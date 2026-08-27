"""
Standalone layered WAF — a reverse proxy that enforces the LayeredWAF in front of any app.

Run:
    UPSTREAM_URL=http://127.0.0.1:8000 WAF_MODE=block python -m waf.server
    # then send traffic to the WAF port (default 8080); it proxies clean traffic to UPSTREAM_URL.

Modes (WAF_MODE):
    block   - enforce: malicious -> 403 / honeypot, clean -> forwarded upstream   (default)
    shadow  - log-only: nothing is blocked, would-block decisions are recorded     (SAFE first deploy)
    monitor - alias for shadow

Env:
    WAF_PORT=8080                listen port
    UPSTREAM_URL=...             backend to protect; if unset, a built-in echo app is served
    WAF_ML_ENFORCE=false         let the ML layer BLOCK (default: ML is shadow — calibrate first!)
    SLACK_WEBHOOK_URL=...        alerts (dry-run if unset)

Endpoints (not proxied): /waf/health, /waf/stats
"""
from __future__ import annotations
import os, sys, json, time, uuid
from pathlib import Path
from flask import Flask, request, Response, jsonify
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from waf.engine import LayeredWAF, BLOCK, HONEYPOT, THROTTLE, ALLOW

MODE = os.environ.get("WAF_MODE", "block").lower()
UPSTREAM = os.environ.get("UPSTREAM_URL", "").rstrip("/")
PORT = int(os.environ.get("WAF_PORT", "8080"))
ML_ENFORCE = os.environ.get("WAF_ML_ENFORCE", "false").lower() in ("1", "true", "on")
CAPTURE = Path(__file__).resolve().parent.parent / "data" / "corpus" / "captured_zero_days.jsonl"
CAPTURE.parent.mkdir(parents=True, exist_ok=True)

# EXPECTED_HOSTS: comma-separated hostnames this deployment legitimately serves.
# Required to detect host-header injection / cache-poisoning (an attacker sends
# `Host: evil.com` so generated links and cached entries point at their domain).
# Unset = any Host accepted, and that detection is OFF — a real gap, so we say so at boot.
EXPECTED_HOSTS = {h.strip().lower() for h in os.environ.get("EXPECTED_HOSTS", "").split(",") if h.strip()}
waf = LayeredWAF(ml_enforce=ML_ENFORCE, expected_hosts=EXPECTED_HOSTS or None)
app = Flask(__name__)

# Run preflight at IMPORT time so it also fires under gunicorn, where __main__ never executes.
# It reports and continues — a config warning must not take the WAF down.
if os.environ.get("WAF_SKIP_PREFLIGHT", "").lower() not in ("1", "true", "on"):
    try:
        from waf.preflight import print_report as _preflight
        _preflight()
    except Exception as _e:  # never let a diagnostic break serving
        print(f"[waf] preflight skipped: {_e}")

try:
    from integrations.slack_notifier import notifier as slack
except Exception:
    slack = None
try:
    from deception.comprehensive_honeypot import comprehensive_honeypot
    from core.models import RequestContext
    HONEYPOT_OK = True
except Exception:
    HONEYPOT_OK = False

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host"}


from waf.client_ip import ClientIPResolver
from waf.preflight import print_report, runtime_xff_warning

# X-Forwarded-For is attacker-controlled. Only honoured when the TCP peer is a configured
# trusted proxy, and then read RIGHT-to-left. See waf/client_ip.py for the measured
# bypass this prevents (rotating XFF defeated rate limiting 150/150 before the fix).
_ipresolver = ClientIPResolver()


def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    # One-shot warning if XFF is arriving but no trusted proxies are configured — the one
    # misconfiguration a static check can't see (it depends on real traffic).
    runtime_xff_warning(bool(xff), bool(_ipresolver.networks))
    return _ipresolver.resolve(request.remote_addr or "", xff,
                               request.headers.get("X-Real-IP", ""))


def _honeypot_response(method, path, query, body, category):
    if HONEYPOT_OK:
        try:
            ctx = RequestContext(request_id=uuid.uuid4().hex[:12], timestamp=time.time(),
                                 client_ip=_client_ip(), client_port=0, server_ip="0.0.0.0",
                                 server_port=PORT, method=method, path=path, query_string=query,
                                 headers=dict(request.headers), body=body.encode())
            hp = comprehensive_honeypot.generate_response(ctx, attack_type=category, result=None)
            return Response(hp.get("body", "OK"), status=hp.get("status", 200),
                            headers=hp.get("headers", {}))
        except Exception:
            pass
    return Response('{"status":"ok"}', status=200, mimetype="application/json")


def _capture(method, path, query, body, d):
    with open(CAPTURE, "a") as f:
        f.write(json.dumps({"ts": time.time(), "method": method, "path": path, "query": query,
                            "body": body[:500], "category": d.category, "novelty": d.novelty,
                            "mal_prob": d.ml_prob, "source_ip": _client_ip(),
                            "label": None, "reviewed": False}) + "\n")   # label=None -> needs human review


def _proxy_upstream(method, path, query, body):
    if not UPSTREAM:
        # built-in echo app so the WAF is runnable/testable with no backend
        return Response(json.dumps({"upstream": "builtin-echo", "method": method,
                                    "path": path, "query": query, "seen_by": "app"}),
                        status=200, mimetype="application/json")
    url = f"{UPSTREAM}{path}" + (f"?{query}" if query else "")
    fwd = {k: v for k, v in request.headers if k.lower() not in HOP}
    r = requests.request(method, url, headers=fwd, data=body, timeout=15, allow_redirects=False)
    resp_headers = [(k, v) for k, v in r.headers.items() if k.lower() not in HOP]
    return Response(r.content, status=r.status_code, headers=resp_headers)


@app.route("/waf/health")
def health():
    return jsonify({"status": "healthy", "mode": MODE, "upstream": UPSTREAM or "builtin-echo",
                    "ml_enforcing": ML_ENFORCE})


@app.route("/waf/stats")
def stats():
    return jsonify({"mode": MODE, **waf.stats()})


@app.route("/metrics")
def metrics():
    """Prometheus exposition — scrape target for the bundled Grafana dashboards."""
    s = waf.stats()
    c = s["counters"]; lat = s["latency_ms"]
    lines = [
        "# HELP waf_requests_total Total requests seen by the WAF, by action",
        "# TYPE waf_requests_total counter",
    ]
    for action in ("allow", "block", "honeypot", "throttle"):
        lines.append(f'waf_requests_total{{action="{action}"}} {c.get(action, 0)}')
    lines += ["# HELP waf_shadow_would_block_total ML would-block events (shadow mode)",
              "# TYPE waf_shadow_would_block_total counter",
              f'waf_shadow_would_block_total {c.get("shadow_would_block", 0)}']
    lines += ["# HELP waf_attacks_by_category_total Blocked/honeypotted by category",
              "# TYPE waf_attacks_by_category_total counter"]
    for cat, n in s["by_category"].items():
        safe = str(cat).replace('"', "")
        lines.append(f'waf_attacks_by_category_total{{category="{safe}"}} {n}')
    lines += ["# HELP waf_latency_ms Decision latency (ms)",
              "# TYPE waf_latency_ms gauge",
              f'waf_latency_ms{{quantile="mean"}} {lat["mean"]}',
              f'waf_latency_ms{{quantile="0.95"}} {lat["p95"]}',
              f'waf_latency_ms{{quantile="0.99"}} {lat["p99"]}']
    lines += ['# HELP waf_ml_enforcing Whether the ML layer is enforcing (1) or shadow (0)',
              '# TYPE waf_ml_enforcing gauge',
              f'waf_ml_enforcing {1 if s["ml_enforcing"] else 0}']
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
def gateway(path):
    method = request.method
    full_path = "/" + path
    query = request.query_string.decode("utf-8", "ignore")
    body = request.get_data(as_text=True) or ""
    d = waf.evaluate(method, full_path, query, body, dict(request.headers), _client_ip())

    enforcing = MODE == "block"
    hdr = {"X-WAF": "DECEPTICON", "X-WAF-Mode": MODE, "X-WAF-Latency-ms": str(d.latency_ms),
           "X-WAF-Decision": d.action, "X-WAF-Layer": d.layer}

    # HONEYPOT: deceive + capture + alert (only when enforcing)
    if d.action == HONEYPOT and enforcing:
        _capture(method, full_path, query, body, d)
        if slack:
            slack.zero_day_captured(d.category, d.novelty, d.ml_prob, _client_ip(), full_path, query or body)
        resp = _honeypot_response(method, full_path, query, body, d.category)
        for k, v in hdr.items():
            resp.headers[k] = v
        return resp

    # BLOCK / THROTTLE
    if d.action in (BLOCK, THROTTLE) and enforcing:
        if slack and d.action == BLOCK:
            slack.attack_spike(d.category, 1, 1, _client_ip())
        code = 429 if d.action == THROTTLE else 403
        return Response(json.dumps({"error": "blocked by WAF", "category": d.category,
                                    "layer": d.layer}), status=code, mimetype="application/json",
                        headers=hdr)

    # ALLOW (or shadow mode: nothing blocked, but record would-blocks)
    resp = _proxy_upstream(method, full_path, query, body)
    for k, v in hdr.items():
        resp.headers[k] = v
    if d.shadow_would_block or (not enforcing and d.action in (BLOCK, HONEYPOT)):
        resp.headers["X-WAF-Shadow-WouldBlock"] = f"{d.layer}:{d.category}"
    return resp


if __name__ == "__main__":
    print(f"""
  DECEPTICON Standalone Layered WAF
  mode={MODE}  port={PORT}  upstream={UPSTREAM or 'builtin-echo'}  ml_enforce={ML_ENFORCE}
  layers: rate-limit -> signatures -> advanced -> ML({'enforce' if ML_ENFORCE else 'shadow'}) -> honeypot
  health: http://127.0.0.1:{PORT}/waf/health   stats: http://127.0.0.1:{PORT}/waf/stats
""")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
