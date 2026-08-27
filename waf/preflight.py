"""
Preflight — validate deployment config before (and during) serving.

Rationale: the most damaging WAF failures in this project were CONFIGURATION failures, not
code failures — a leftmost X-Forwarded-For read that voided rate limiting, host-header
detection silently off, ML enforcing without calibration. Documentation does not prevent
those; a loud startup check does.

Two entry points:
  * check() / print_report()  — run at boot and as a standalone pre-deploy gate:
        python -m waf.preflight        (exit 1 if any CRITICAL finding)
  * runtime_xff_warning()     — one-shot runtime detector for the single misconfiguration
        that static checks cannot see: requests arriving WITH X-Forwarded-For while
        TRUSTED_PROXIES is unset. That means you are behind a proxy but not configured for
        it, so every client shares one rate-limit bucket.

Severities:
  CRITICAL — a security control is silently disabled or defeated. Fix before serving traffic.
  WARN     — a real gap, but a defensible choice for some topologies.
  INFO     — state worth confirming.
"""
from __future__ import annotations
import os, sys, logging
from pathlib import Path
from typing import List, Tuple

log = logging.getLogger("waf.preflight")
ROOT = Path(__file__).resolve().parent.parent

CRITICAL, WARN, INFO, OK = "CRITICAL", "WARN", "INFO", "OK"


def _env(k, default=""):
    return os.environ.get(k, default).strip()


def _truthy(v: str) -> bool:
    return v.lower() in ("1", "true", "on", "yes")


def check() -> List[Tuple[str, str, str]]:
    """Returns [(severity, title, detail)]."""
    f: List[Tuple[str, str, str]] = []
    mode = _env("WAF_MODE", "block").lower()
    upstream = _env("UPSTREAM_URL")
    trusted = _env("TRUSTED_PROXIES")
    hosts = _env("EXPECTED_HOSTS")
    redis_url = _env("REDIS_URL")
    ml_enforce = _truthy(_env("WAF_ML_ENFORCE"))
    workers = _env("WORKERS", "1")

    # ── 1. client-IP trust boundary (the measured bypass) ──
    if not trusted:
        f.append((WARN, "TRUSTED_PROXIES is unset",
                  "X-Forwarded-For will be IGNORED and the TCP peer used. Correct ONLY if the "
                  "WAF is directly internet-facing. If you are behind a load balancer, ingress "
                  "or CDN, every client collapses into ONE rate-limit bucket — set it to your "
                  "proxy egress CIDRs (e.g. 10.0.0.0/8)."))
    else:
        from waf.client_ip import parse_networks
        nets = parse_networks(trusted)
        if not nets:
            f.append((CRITICAL, "TRUSTED_PROXIES is set but parsed to nothing",
                      f"No valid CIDR in {trusted[:60]!r}. XFF is being ignored — verify the syntax."))
        else:
            wide = [str(n) for n in nets if n.prefixlen <= 8 and not n.is_private]
            if wide:
                f.append((CRITICAL, "TRUSTED_PROXIES contains a huge PUBLIC range",
                          f"{', '.join(wide)} — any host in that range can forge X-Forwarded-For "
                          "and impersonate any client. Narrow it to your proxy egress IPs."))
            else:
                f.append((OK, "Client-IP trust boundary configured",
                          f"{len(nets)} trusted proxy network(s); XFF read rightmost-untrusted."))

    # ── 2. host-header detection ──
    if not hosts:
        f.append((WARN, "EXPECTED_HOSTS is unset",
                  "Host-header injection / cache-poisoning detection is OFF (any Host accepted). "
                  "Set it to the hostnames you serve, e.g. EXPECTED_HOSTS=app.example.com"))
    else:
        f.append((OK, "Host-header detection active", f"{len(hosts.split(','))} expected host(s)."))

    # ── 3. multi-replica rate limiting ──
    try:
        nworkers = int(workers)
    except ValueError:
        nworkers = 1
    if not redis_url and nworkers > 1:
        f.append((CRITICAL, "Rate limiting is PER-PROCESS with multiple workers",
                  f"WORKERS={nworkers} and REDIS_URL unset: an attacker gets {nworkers}x the "
                  "intended budget (more still across pods). Set REDIS_URL for a shared window."))
    elif not redis_url:
        f.append((WARN, "Rate limiting is per-process",
                  "Fine for a single instance. Set REDIS_URL before scaling to multiple "
                  "workers/replicas or limits multiply by replica count."))
    else:
        f.append((OK, "Shared rate limiting configured", "Redis sliding window across replicas."))

    # ── 4. ML enforcement without calibration evidence ──
    if ml_enforce:
        reg = ROOT / "models_v2" / "registry.json"
        f.append((CRITICAL if not reg.exists() else WARN,
                  "ML layer is ENFORCING",
                  "A model trained on someone else's benign traffic flags up to 99.8% of yours "
                  "as attacks. Only enable after >=2 weeks of shadow mode on YOUR traffic and a "
                  "measured false-positive rate you can accept."))
    else:
        f.append((OK, "ML layer in shadow (safe default)",
                  "Records would-blocks without enforcing. Signatures still enforce."))

    # ── 5. mode / upstream sanity ──
    if mode not in ("block", "shadow", "monitor"):
        f.append((CRITICAL, "Unknown WAF_MODE", f"{mode!r} is not block|shadow|monitor."))
    elif mode == "block":
        f.append((INFO, "Mode: BLOCK (enforcing)",
                  "First deployment should be WAF_MODE=shadow for >=2 weeks to measure FP."))
    else:
        f.append((OK, "Mode: SHADOW (log-only)", "Nothing is blocked; would-blocks recorded."))
    if not upstream:
        f.append((WARN, "UPSTREAM_URL unset",
                  "Serving the built-in echo app — fine for testing, not for protecting anything."))

    # ── 6. serving stack ──
    if not _truthy(_env("WAF_UNDER_WSGI")) and "gunicorn" not in " ".join(sys.argv).lower():
        f.append((WARN, "Not running under a production WSGI server",
                  "python -m waf.server uses the Flask development server (single process, no "
                  "request queueing). In production run: gunicorn waf.server:app --preload "
                  "(the bundled Dockerfile already does)."))

    # ── 7. alerting ──
    if not _env("SLACK_WEBHOOK_URL"):
        f.append((WARN, "Slack alerting is in dry-run",
                  "SLACK_WEBHOOK_URL unset: 0-day captures and promotion decisions are logged "
                  "but nobody is notified."))
    if _env("SLACK_BOT_TOKEN") and not _env("SLACK_APPROVERS"):
        f.append((CRITICAL, "Two-way Slack enabled with NO approvers",
                  "SLACK_APPROVERS is empty, so every button click will be refused. Set it to "
                  "the Slack user IDs allowed to approve."))

    # ── 8. models present ──
    if not (ROOT / "models_v2").exists():
        f.append((WARN, "models_v2/ missing",
                  "The ML layer will be unavailable; the WAF degrades to rules-only "
                  "(signatures still enforce)."))
    return f


def print_report(findings=None, stream=sys.stderr) -> int:
    findings = findings if findings is not None else check()
    order = {CRITICAL: 0, WARN: 1, INFO: 2, OK: 3}
    findings = sorted(findings, key=lambda x: order.get(x[0], 9))
    ncrit = sum(1 for s, *_ in findings if s == CRITICAL)
    nwarn = sum(1 for s, *_ in findings if s == WARN)
    w = stream.write
    w("\n" + "=" * 78 + "\n  MIRAGE WAF — preflight\n" + "=" * 78 + "\n")
    for sev, title, detail in findings:
        tag = {CRITICAL: "[CRITICAL]", WARN: "[WARN]    ", INFO: "[info]    ", OK: "[ok]      "}[sev]
        w(f"{tag} {title}\n")
        if sev in (CRITICAL, WARN):
            for line in _wrap(detail, 70):
                w(f"           {line}\n")
    w("-" * 78 + "\n")
    w(f"  {ncrit} critical, {nwarn} warning(s). "
      f"{'FIX CRITICAL ITEMS BEFORE SERVING TRAFFIC.' if ncrit else 'No critical findings.'}\n")
    w("=" * 78 + "\n\n")
    stream.flush()
    return ncrit


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line); line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


_warned_xff = False


def runtime_xff_warning(has_xff: bool, trusted_configured: bool):
    """Fires once if XFF headers are arriving but no trusted proxies are configured."""
    global _warned_xff
    if _warned_xff or trusted_configured or not has_xff:
        return
    _warned_xff = True
    log.warning(
        "MISCONFIGURATION: requests carry X-Forwarded-For but TRUSTED_PROXIES is unset. "
        "The header is being ignored (correct, it is unauthenticated) — but that means every "
        "client behind your proxy shares ONE rate-limit bucket and reputation identity. "
        "Set TRUSTED_PROXIES to your load-balancer egress CIDRs.")


if __name__ == "__main__":
    sys.exit(1 if print_report(stream=sys.stdout) else 0)
