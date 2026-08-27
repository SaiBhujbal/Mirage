"""
Two-way Slack — approve/reject model promotions and label captured zero-days from the channel.

WHY SOCKET MODE (not a Request URL): interactive Slack apps normally need a PUBLIC HTTPS
endpoint for Slack to POST button clicks to. A WAF often sits on-prem or in a private VPC,
and punching an inbound hole through the perimeter *into the security control plane* is
exactly the wrong trade. Socket Mode instead opens an OUTBOUND WebSocket to Slack — no
inbound firewall rule, no public endpoint, no reverse tunnel.

Requires (all optional — the module degrades to one-way if absent):
    pip install slack_sdk
    SLACK_BOT_TOKEN=xoxb-...    # scopes: chat:write, commands
    SLACK_APP_TOKEN=xapp-...    # Socket Mode token, scope: connections:write

SECURITY MODEL — this is a control-plane surface, so it is deliberately narrow:
  * Actions are ALLOW-LISTED. A button can only: label a capture attack/benign, or
    approve/reject a pending promotion. There is no free-text command execution, no
    "run this", no arbitrary model selection.
  * Every action is authorised against SLACK_APPROVERS (comma-separated Slack user IDs).
    An unlisted user gets a refusal, and the attempt is logged. Empty list = deny all,
    because "anyone in the channel can promote a model" is not an access model.
  * Approving does NOT bypass the safety chain: it only sets a flag the MLOps runner
    reads. The poison guard, the accumulation threshold, the promotion gate and the
    canary all still run. A human cannot click past them.
  * Payloads shown in Slack are truncated and rendered in a code block; the label action
    records a decision, it never re-executes the payload.
"""
from __future__ import annotations
import json, os, time, logging, threading
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("waf.slack.interactive")
ROOT = Path(__file__).resolve().parent.parent
DECISIONS = ROOT / "data" / "corpus" / "slack_decisions.jsonl"
PENDING = ROOT / "data" / "corpus" / "pending_approvals.json"
DECISIONS.parent.mkdir(parents=True, exist_ok=True)

APPROVERS = {u.strip() for u in os.environ.get("SLACK_APPROVERS", "").split(",") if u.strip()}


# ───────────────────────── decision store (what the runner reads) ─────────────────────────
def record(kind: str, target: str, decision: str, user: str, meta: Optional[Dict] = None) -> Dict:
    rec = {"ts": time.time(), "kind": kind, "target": target, "decision": decision,
           "slack_user": user, "meta": meta or {}}
    with DECISIONS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def decisions_for(kind: str) -> List[Dict]:
    if not DECISIONS.exists():
        return []
    out = []
    for line in DECISIONS.read_text(encoding="utf-8").splitlines():
        try:
            d = json.loads(line)
            if d.get("kind") == kind:
                out.append(d)
        except Exception:
            pass
    return out


def promotion_approved(version: str) -> Optional[bool]:
    """True/False if a human decided on this version in Slack; None if undecided."""
    for d in reversed(decisions_for("promotion")):
        if d["target"] == version:
            return d["decision"] == "approve"
    return None


def authorised(user_id: str) -> bool:
    return bool(APPROVERS) and user_id in APPROVERS


# ───────────────────────── message builders (interactive) ─────────────────────────
def zero_day_review_blocks(capture_id: str, category: str, novelty: float,
                           mal_prob: float, src_ip: str, path: str, payload: str) -> List[Dict]:
    return [
        {"type": "header", "text": {"type": "plain_text", "text": f"🔴 Zero-day captured — needs your label"}},
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f"*{category}* from `{src_ip}` on `{path}`\n```{payload[:300]}```"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*novelty*\n{novelty:.1f}"},
            {"type": "mrkdwn", "text": f"*ML prob*\n{mal_prob:.2f}"},
            {"type": "mrkdwn", "text": f"*action taken*\ndeceived via honeypot"},
            {"type": "mrkdwn", "text": f"*capture*\n`{capture_id}`"}]},
        {"type": "actions", "block_id": f"zd:{capture_id}", "elements": [
            {"type": "button", "action_id": "label_attack", "style": "danger",
             "text": {"type": "plain_text", "text": "Real attack"}, "value": capture_id},
            {"type": "button", "action_id": "label_benign",
             "text": {"type": "plain_text", "text": "False alarm"}, "value": capture_id},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn",
            "text": "Labelling feeds the retrain buffer. Nothing trains until the batch is "
                    "large and diverse enough, and the poison guard screens it first."}]},
    ]


def promotion_approval_blocks(version: str, metrics: Dict, gate: Dict, batch_n: int) -> List[Dict]:
    passed = all(gate.values())
    return [
        {"type": "header", "text": {"type": "plain_text", "text": "⚖️ Model retrain ready — approve?"}},
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f"Challenger `{version}` trained on *{batch_n}* reviewed samples.\n"
                    f"Safety gate: {'*all 5 checks passed*' if passed else '*FAILED*'}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*recall*\n{metrics.get('chal_recall',0):.3f} (champ {metrics.get('champ_recall',0):.3f})"},
            {"type": "mrkdwn", "text": f"*false positives*\n{metrics.get('chal_fp',0):.3f} (champ {metrics.get('champ_fp',0):.3f})"},
        ]},
        {"type": "actions", "block_id": f"promo:{version}", "elements": [
            {"type": "button", "action_id": "promo_approve", "style": "primary",
             "text": {"type": "plain_text", "text": "Approve canary"}, "value": version},
            {"type": "button", "action_id": "promo_reject", "style": "danger",
             "text": {"type": "plain_text", "text": "Reject"}, "value": version},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn",
            "text": "Approving only *starts the canary* (1%→100% with auto-rollback). "
                    "It cannot skip the gate or the rollback checks."}]},
    ]


# ───────────────────────── Socket Mode listener ─────────────────────────
class SlackInteractive:
    """Outbound-only Socket Mode client. Start with .start() (non-blocking thread)."""

    def __init__(self, bot_token: Optional[str] = None, app_token: Optional[str] = None):
        self.bot_token = bot_token or os.environ.get("SLACK_BOT_TOKEN", "")
        self.app_token = app_token or os.environ.get("SLACK_APP_TOKEN", "")
        self.enabled = False
        self._client = None
        if not (self.bot_token and self.app_token):
            log.info("slack interactive: disabled (SLACK_BOT_TOKEN / SLACK_APP_TOKEN unset) "
                     "— alerts remain one-way via webhook")
            return
        try:
            from slack_sdk.web import WebClient
            from slack_sdk.socket_mode import SocketModeClient
            from slack_sdk.socket_mode.response import SocketModeResponse
            self._WebClient, self._SocketModeClient = WebClient, SocketModeClient
            self._Response = SocketModeResponse
            self.enabled = True
        except ImportError:
            log.warning("slack interactive: slack_sdk not installed "
                        "(pip install slack_sdk) — falling back to one-way alerts")

    def _handle(self, client, req):
        """Dispatch a button click. Allow-listed actions only."""
        resp = self._Response(envelope_id=req.envelope_id)
        client.send_socket_mode_response(resp)
        if req.type != "interactive":
            return
        p = req.payload
        user = (p.get("user") or {}).get("id", "?")
        actions = p.get("actions") or []
        if not actions:
            return
        a = actions[0]
        action_id, value = a.get("action_id"), a.get("value", "")
        channel = ((p.get("channel") or {}).get("id")) or ""
        ts = ((p.get("message") or {}).get("ts")) or ""

        ALLOWED = {"label_attack", "label_benign", "promo_approve", "promo_reject"}
        if action_id not in ALLOWED:
            log.warning("slack interactive: rejected unknown action_id=%r from %s", action_id, user)
            return
        if not authorised(user):
            self._say(channel, ts, f"<@{user}> is not an authorised approver. "
                                   "Add their Slack user ID to `SLACK_APPROVERS`.")
            log.warning("slack interactive: UNAUTHORISED %s attempted %s on %r", user, action_id, value)
            return

        if action_id in ("label_attack", "label_benign"):
            label = 1 if action_id == "label_attack" else 0
            record("capture_label", value, "attack" if label else "benign", user, {"label": label})
            self._say(channel, ts, f"<@{user}> labelled `{value}` as "
                                   f"*{'real attack' if label else 'false alarm'}* — added to the "
                                   f"retrain buffer (poison guard still screens it).")
        else:
            approve = action_id == "promo_approve"
            record("promotion", value, "approve" if approve else "reject", user)
            self._say(channel, ts, f"<@{user}> {'*approved*' if approve else '*rejected*'} "
                                   f"model `{value}`."
                                   + (" Canary will start at 1% traffic." if approve
                                      else " Champion stays live."))

    def _say(self, channel: str, thread_ts: str, text: str):
        try:
            self._client.web_client.chat_postMessage(channel=channel, thread_ts=thread_ts or None, text=text)
        except Exception as e:
            log.error("slack interactive: reply failed: %s", e)

    def post(self, channel: str, blocks: List[Dict], text: str = "MIRAGE-WAF") -> Optional[str]:
        if not self.enabled or not self._client:
            return None
        try:
            r = self._client.web_client.chat_postMessage(channel=channel, blocks=blocks, text=text)
            return r.get("ts")
        except Exception as e:
            log.error("slack interactive: post failed: %s", e)
            return None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._client = self._SocketModeClient(
                app_token=self.app_token, web_client=self._WebClient(token=self.bot_token))
            self._client.socket_mode_request_listeners.append(self._handle)
            threading.Thread(target=self._client.connect, daemon=True).start()
            log.info("slack interactive: Socket Mode connected (outbound only); "
                     "%d authorised approver(s)", len(APPROVERS))
            if not APPROVERS:
                log.warning("slack interactive: SLACK_APPROVERS is EMPTY — every button click "
                            "will be refused. Set it to the Slack user IDs allowed to approve.")
            return True
        except Exception as e:
            log.error("slack interactive: could not start Socket Mode (%s) — one-way alerts only", e)
            return False


interactive = SlackInteractive()
