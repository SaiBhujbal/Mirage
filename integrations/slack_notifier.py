"""
Slack notifier for DECEPTICON-WAF — alerts to a channel via an Incoming Webhook.

Why webhook (not the bot API / MCP): incoming webhooks are the standard alerting primitive —
a single POST to a secret URL, no broad OAuth scopes, exactly what a monitoring system needs.

Two properties a WAF notifier MUST have or it destroys the channel it posts to:
  - THROTTLING: under an attack a WAF can produce thousands of events/sec. We cap posts per
    alert-type and never busy-post.
  - AGGREGATION: identical/similar events inside a window collapse into one message with a
    count ("247 SQLi attempts from 12 IPs in 60s"), not 247 pings.

Config (never hardcode the URL — it is a secret):
    export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxxx"
No URL set  -> dry-run mode: the notifier builds the payload and returns it (and logs it),
but posts nothing. Safe by default; wire the env var to go live.
"""
from __future__ import annotations
import os, json, time, ssl, hashlib, threading, urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SEV_COLOR = {"info": "#36a64f", "low": "#2eb67d", "medium": "#ecb22e",
             "high": "#e01e5a", "critical": "#8b0000"}
SEV_EMOJI = {"info": "🛈", "low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🚨"}


@dataclass
class _Bucket:
    count: int = 0
    first_ts: float = 0.0
    last_posted: float = 0.0
    sample: dict = field(default_factory=dict)


class SlackNotifier:
    def __init__(self, webhook_url: Optional[str] = None,
                 min_interval_s: float = 30.0, window_s: float = 60.0):
        self.webhook = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        self.dry_run = not self.webhook
        self.min_interval = min_interval_s      # min seconds between posts of the SAME alert key
        self.window = window_s                  # aggregation window
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    # ---- public API -------------------------------------------------------
    def notify(self, key: str, title: str, severity: str = "medium",
               fields: Optional[Dict[str, str]] = None, text: str = "",
               force: bool = False) -> Optional[dict]:
        """
        key      : dedup/throttle key (e.g. 'attack:sqli', 'promo', 'zero_day').
        Returns the posted payload, or None if suppressed by throttle/aggregation.
        Aggregated events add a '(xN in last {window}s)' count to the title.
        """
        now = time.time()
        with self._lock:
            b = self._buckets.setdefault(key, _Bucket(first_ts=now))
            b.count += 1
            b.sample = {"title": title, "severity": severity, "fields": fields or {}, "text": text}
            # window reset
            if now - b.first_ts > self.window:
                b.first_ts = now; b.count = 1
            # throttle: only post if enough time passed since last post for this key
            if not force and (now - b.last_posted) < self.min_interval and b.last_posted > 0:
                return None
            b.last_posted = now
            n = b.count
            b.count = 0
        agg = f"  _(×{n} in {int(self.window)}s)_" if n > 1 else ""
        return self._post(self._payload(title + agg, severity, fields or {}, text))

    def _payload(self, title: str, severity: str, fields: Dict[str, str], text: str) -> dict:
        blocks = [{"type": "header", "text": {"type": "plain_text",
                   "text": f"{SEV_EMOJI.get(severity,'•')} {title}"[:150]}}]
        if text:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}})
        if fields:
            blocks.append({"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*{k}*\n{v}"[:2000]} for k, v in list(fields.items())[:10]]})
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"DECEPTICON-WAF · {time.strftime('%Y-%m-%d %H:%M:%S %Z')}"}]})
        return {"attachments": [{"color": SEV_COLOR.get(severity, "#666"), "blocks": blocks}]}

    def _post(self, payload: dict) -> dict:
        if self.dry_run:
            print("[slack:dry-run] would POST:\n" + json.dumps(payload, indent=2)[:1200])
            return payload
        try:
            req = urllib.request.Request(
                self.webhook, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=8, context=ssl.create_default_context()) as r:
                r.read()
        except Exception as e:
            print(f"[slack] post failed (non-fatal): {e}")
        return payload

    # ---- typed helpers for the WAF's key events ---------------------------
    def zero_day_captured(self, category: str, novelty: float, mal_prob: float,
                          client_ip: str, path: str, payload: str) -> Optional[dict]:
        return self.notify(
            key=f"zero_day:{category}", severity="high",
            title=f"Zero-day captured → honeypot ({category})",
            fields={"source IP": client_ip, "endpoint": path,
                    "novelty": f"{novelty:.1f}", "ML prob": f"{mal_prob:.2f}",
                    "action": "deceived + captured for retrain"},
            text=f"Novel/ML-caught attack (no signature). Payload:\n```{payload[:300]}```\n"
                 f"Queued for human review → retrain loop.")

    def promotion_decision(self, promote: bool, checks: Dict[str, bool],
                           metrics: Dict[str, float]) -> Optional[dict]:
        failed = [k for k, ok in checks.items() if not ok]
        return self.notify(
            key="promo", severity=("low" if promote else "critical"), force=True,
            title=("Model PROMOTED" if promote else "Model retrain REJECTED"),
            fields={"recall": f"{metrics.get('chal_recall',0):.3f} (champ {metrics.get('champ_recall',0):.3f})",
                    "FP": f"{metrics.get('chal_fp',0):.3f} (champ {metrics.get('champ_fp',0):.3f})",
                    "failed gates": ", ".join(failed) or "none"},
            text=("New model passed all safety gates and is now live."
                  if promote else
                  f"Challenger blocked from shipping — failed: *{', '.join(failed)}*. "
                  "Possible poisoning or regression; champion kept."))

    def attack_spike(self, category: str, count: int, unique_ips: int,
                     top_ip: str) -> Optional[dict]:
        return self.notify(
            key=f"attack:{category}", severity="medium",
            title=f"Attack spike: {category}",
            fields={"count (window)": str(count), "unique IPs": str(unique_ips),
                    "top source": top_ip, "status": "blocked at edge"})

    def fp_rate_alert(self, rate: float, threshold: float) -> Optional[dict]:
        return self.notify(
            key="fp_rate", severity="high", force=True,
            title="False-positive rate above budget",
            fields={"current FP": f"{rate*100:.2f}%", "budget": f"{threshold*100:.2f}%",
                    "action": "review threshold / retrain — legit users may be blocked"})


# module singleton — honors SLACK_MIN_INTERVAL_S / SLACK_WINDOW_S if set
notifier = SlackNotifier(
    min_interval_s=float(os.environ.get("SLACK_MIN_INTERVAL_S", "30")),
    window_s=float(os.environ.get("SLACK_WINDOW_S", "60")),
)
