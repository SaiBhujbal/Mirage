"""
LayeredWAF — the standalone layered decision engine.

Defense in depth, in order, cheapest first. Each layer can BLOCK, or escalate. The ML
layer is SHADOW by default (logs a would-block, does not enforce) because — per the whole
project's finding — ML must be calibrated on YOUR traffic before it enforces, or it will
false-positive. Signatures always enforce; they are precise.

  L1 rate limit        -> THROTTLE
  L2 signatures        -> BLOCK (pattern engine + 185-pattern scanner; precise, sub-ms)
  L3 advanced heuristics (XXE/SSTI/SSRF/JWT/encoded)  -> BLOCK on CRITICAL
  L4 ML ensemble       -> BLOCK (enforce) or SHADOW (log would-block)
  L5 open-set novelty  -> HONEYPOT (deceive + capture the 0-day) when ML unsure but anomalous

evaluate() is pure/fast; the server wraps it with proxying, honeypot responses, capture,
Slack, and metrics.
"""
from __future__ import annotations
import re, time, threading, urllib.parse
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pattern_engine import pattern_engine
from core.comprehensive_scanner import comprehensive_scanner
try:
    from core.advanced_protection import advanced_protection, ThreatLevel
    ADV = True
except Exception:
    ADV = False

ALLOW, THROTTLE, BLOCK, HONEYPOT = "ALLOW", "THROTTLE", "BLOCK", "HONEYPOT"

# ── Inspection size cap (resource-exhaustion defence) ────────────────────────────
# MEASURED: scanning a 1 MB body cost ~1,569 ms in the 185-pattern scanner alone
# (~2.3 s across all layers). Uncapped, an attacker exhausts the WAF's own CPU by
# posting large bodies — a DoS on the security control itself. Every serious WAF caps
# this (cf. ModSecurity SecRequestBodyLimit).
#
# We inspect the first N bytes and RECORD that truncation happened. Real injection
# payloads live in the first few KB; the tradeoff is explicit rather than silent.
# Tune with WAF_MAX_INSPECT_BYTES.
MAX_INSPECT_BYTES = int(os.environ.get("WAF_MAX_INSPECT_BYTES", "262144"))  # 256 KB


def _cap(s: str):
    """Return (inspected_slice, was_truncated)."""
    if s and len(s) > MAX_INSPECT_BYTES:
        return s[:MAX_INSPECT_BYTES], True
    return s, False


# ── input hygiene applied before the regex/scanner tier (ReDoS + fail-open fixes) ──
# 64+ identical chars collapse to 64: real injection payloads never need long identical
# runs, and shortening them only makes an attack MORE visible while defusing catastrophic
# backtracking regardless of which pattern is vulnerable.
_RUN64 = re.compile(r'(.)\1{63,}', re.DOTALL)


def _sanitize(s: str) -> str:
    """Coerce to valid UTF-8 and defang long identical-char runs. A lone UTF-16 surrogate
    used to raise UnicodeEncodeError inside the scanner, which the single try/except then
    swallowed — silently disabling the entire signature tier (fail-open). Encoding with
    errors='replace' removes surrogates before any scanner sees the string."""
    if not s:
        return s
    s = s.encode('utf-8', 'replace').decode('utf-8', 'replace')
    if len(s) > 64:
        s = _RUN64.sub(lambda m: m.group(1) * 64, s)
    return s


# Headers that carry ATTACKER-CONTROLLED data and must be injection-scanned. They live in
# _SKIP_HEADERS (below) to keep them out of the broad name-keyed scan that false-positives
# on infra headers, but their VALUES are scanned explicitly in evaluate(). This closes the
# header blind spot without reintroducing the Host=127.0.0.1 / Accept:*/* false positives.
_USER_DATA_HEADERS = {"referer", "origin", "authorization",
                      "x-forwarded-for", "x-real-ip", "x-request-id"}

# When scanning header VALUES, honor only UNAMBIGUOUS injection categories. Scanning the
# full ruleset here false-positives: a normal Referer/Origin `//host` matches the
# open-redirect rule, and a normal Bearer token IS a JWT. Real header injection (SQLi/XSS/
# RCE/traversal/etc.) still fires through these categories.
_HEADER_INJECTION_CATS = {
    "sql_injection", "cross_site_scripting", "remote_code_execution", "command_injection",
    "path_traversal", "server_side_template_injection", "ldap_injection",
    "nosql_injection", "xxe", "xml_external_entity",
}

# Standard browser/proxy headers set by the transport or content negotiation — NOT
# attacker-controlled injection vectors. Scanning them causes false positives: the WAF's own
# Host (127.0.0.1) matches the SSRF localhost rule, and `Accept: */*` matches the SQL
# inline-comment pattern `/*` — either one blocks every legitimate request. We scan only
# headers that actually carry user/app data (Cookie, Referer, and non-standard custom headers).
_SKIP_HEADERS = {
    "host", "connection", "keep-alive", "content-length", "content-type", "te", "trailer",
    "transfer-encoding", "upgrade", "upgrade-insecure-requests", "via", "dnt",
    "accept", "accept-encoding", "accept-language", "accept-charset", "accept-datetime",
    "user-agent", "cache-control", "pragma", "expect", "range", "if-modified-since",
    "if-none-match", "if-match", "if-range", "max-forwards", "from", "date",
    "origin", "referer",  # URLs — prone to FP; block via path/query/body instead
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "x-request-id",
    "proxy-authorization", "proxy-connection", "authorization",
} | {f"sec-fetch-{x}" for x in ("dest", "mode", "site", "user")} \
  | {f"sec-ch-ua{x}" for x in ("", "-mobile", "-platform", "-arch", "-model")}


def _scan_headers(headers):
    return {k: v for k, v in (headers or {}).items() if k.lower() not in _SKIP_HEADERS}


# Headers excluded from *injection* scanning above still carry real attack signal for
# SPECIFIC classes. Blanket-skipping them silently disabled scanner and host-header
# detection (measured: 0/6 and 0/2). So scan them against narrow, purpose-built patterns
# instead of the full injection ruleset — precision without losing coverage.
# UNAMBIGUOUS attack tooling only.
#
# Deliberately EXCLUDES generic HTTP clients (curl, python-requests, go-http-client, wget,
# libwww-perl, scrapy). Those are dual-use: they are what legitimate API consumers, health
# checks, CI pipelines and monitoring use. An earlier version included `curl` and consequently
# 403'd every API client and every curl-based health probe — caught by end-to-end testing, not
# by unit tests. UA is also trivially spoofed, so this is a weak signal by design: it is
# corroborating evidence, never the sole basis for a block in a tuned deployment.
_SCANNER_UA = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap\s+scripting\s+engine|masscan|nessus|acunetix|burpsuite|"
    r"owasp\s+zap|w3af|havij|dirbuster|gobuster|ffuf|wpscan|joomscan|metasploit|"
    r"hydra|arachni|skipfish|whatweb|nuclei|xsser|commix)\b")
_HOST_BAD = re.compile(r"(?i)^(?!$)(?:[^\s]*(?:\.\.|[<>'\"();]|%0d|%0a|\r|\n)|(?:https?://))")

# Recon probes for sensitive files/paths. Extremely common as a precursor to exploitation
# (/.env and /.git/config leak credentials outright), and invisible to injection rules
# because the path contains no attack syntax at all.
_RECON_PATH = re.compile(
    r"(?i)(?:^|/)(?:\.git(?:/|$)|\.svn(?:/|$)|\.hg(?:/|$)|\.env(?:\.|$)|\.aws(?:/|$)|"
    r"\.ssh(?:/|$)|id_rsa|\.htpasswd|\.htaccess|web\.config|"
    r"wp-config\.php|configuration\.php|settings\.py|secrets?\.(?:ya?ml|json|txt)|"
    r"docker-compose\.ya?ml|\.dockerenv|\.npmrc|\.pypirc|"
    r"phpinfo\.php|server-status|actuator/env|actuator/heapdump|"
    r"[^/]+\.(?:bak|old|orig|save|swp|sql|dump|log|pem|key|p12|pfx)(?:$|\?))")


def _path_signals(path: str):
    m = _RECON_PATH.search(path or "")
    return [("sensitive_file_probe", 0.70, m.group(0)[:60])] if m else []


# ── gaps closed after the coverage matrix measured them as misses ──
# Prototype pollution via QUERY-STRING parameter names (`?__proto__[isAdmin]=true`,
# `?constructor[prototype][x]=1`). The body form was caught by the JSON rules; the query
# form has no JSON to match, so it needs a parameter-NAME rule.
_PROTO_POLLUTION = re.compile(
    r"(?i)(?:^|[?&;])\s*(?:__proto__|constructor\s*\[\s*[\"']?prototype[\"']?\s*\]|prototype)"
    r"\s*(?:[\[\].=]|%5b)")

# Open-redirect backslash bypass: browsers normalise `\` to `/` in the authority, so
# `/\evil.com`, `\/evil.com` and `/\/evil.com` all redirect off-site while looking like a
# relative path. A leading `/` may precede the backslash — allow it.
_REDIRECT_BYPASS = re.compile(
    r"(?i)(?:^|=)\s*(?:https?:)?(?:/|%2f)?(?:\\|%5c){1,2}(?:/|\\|%2f|%5c)?"
    r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}")


# CRLF in a QUERY STRING only. A newline in a URL query is essentially never legitimate,
# so here we can catch what the signature tier deliberately will not: injection of an
# ARBITRARY header ("\r\nX-Injected: true" — response splitting with any header name) and
# bare newline log forging ("\nFAKE LOG ENTRY"). This is scoped to the query on purpose:
# request BODIES legitimately contain multi-line text, where the same rule would false-
# positive on ordinary prose. Both forms (percent-encoded and raw) are matched; bounded
# quantifiers keep it linear.
_CRLF_QUERY_HEADER = re.compile(r"(?i)(?:%0d%0a|%0d|%0a|\r\n|\r|\n)\s{0,8}[A-Za-z][A-Za-z0-9-]{0,40}\s{0,8}:")
_CRLF_QUERY_BARE = re.compile(r"(?i)(?:%0d%0a|%0d|%0a|\r\n|\r|\n)\s{0,8}\S")


# Redirect-target parameters, and an absolute URL's host. An open redirect to an ARBITRARY
# host cannot be told apart from a legitimate one by shape alone (next=https://evil.com and
# next=https://myapp.com are identical in form) — it needs to know which hosts are yours.
# So this check activates ONLY when WAF_ALLOWED_REDIRECT_HOSTS (or EXPECTED_HOSTS) is set;
# unset means the check is off and behaviour is unchanged (no false positives by default).
_REDIR_PARAM = re.compile(r"(?i)(?:^|[?&])(?:next|url|redirect|redirect_uri|return|return_to|returnurl|dest|destination|continue|goto|target|rurl)=([^&]+)")


def _redirect_host_signals(query: str, body: str, allowed_hosts):
    if not allowed_hosts:
        return []
    out = []
    for src in (query or "", body or ""):
        for m in _REDIR_PARAM.finditer(src or ""):
            raw = urllib.parse.unquote(m.group(1))
            if not re.match(r"(?i)^(?:https?:)?//", raw):
                continue                      # relative target: same-origin, fine
            host = urllib.parse.urlsplit(raw if "://" in raw else "http:" + raw).hostname
            if host and host.lower() not in allowed_hosts:
                out.append(("open_redirect", 0.85, raw[:60]))
    return out


def _payload_signals(query: str, body: str):
    out = []
    for src in (query or "", body or ""):
        if not src:
            continue
        if _PROTO_POLLUTION.search(src):
            out.append(("prototype_pollution", 0.80, src[:60]))
        if _REDIRECT_BYPASS.search(src):
            out.append(("open_redirect", 0.75, src[:60]))
    q = query or ""
    if q:
        if _CRLF_QUERY_HEADER.search(q):
            out.append(("crlf_injection", 0.85, q[:60]))
        elif _CRLF_QUERY_BARE.search(q):
            # No header name — log forging / response manipulation rather than header
            # injection. Still not legitimate in a query string.
            out.append(("crlf_injection", 0.70, q[:60]))
    return out


def _header_signals(headers, expected_hosts=None):
    """Return [(category, severity, evidence)] for header-specific attack classes."""
    out = []
    for k, v in (headers or {}).items():
        kl, val = k.lower(), str(v)
        if kl == "user-agent":
            m = _SCANNER_UA.search(val)
            if m:
                out.append(("scanner_tool", 0.75, m.group(0)[:60]))
        elif kl in ("host", "x-forwarded-host"):
            if _HOST_BAD.search(val):
                out.append(("host_header_injection", 0.80, val[:60]))
            elif expected_hosts and val.split(":")[0].lower() not in expected_hosts:
                out.append(("host_header_injection", 0.60, val[:60]))
    return out


@dataclass
class Decision:
    action: str = ALLOW
    layer: str = "-"
    category: str = "-"
    severity: float = 0.0
    matched: str = "-"
    latency_ms: float = 0.0
    ml_prob: float = 0.0
    novelty: float = 0.0
    is_zero_day: bool = False
    shadow_would_block: bool = False   # ML in shadow mode flagged it but didn't enforce
    reasons: List[str] = field(default_factory=list)


# Kept as the single-instance implementation and re-exported for tests; multi-replica
# deployments get the shared Redis window via build_rate_limiter (set REDIS_URL).
from waf.ratelimit import MemoryRateLimiter as RateLimiter, build_rate_limiter


class LayeredWAF:
    def __init__(self, ml_enforce: bool = None, rate_capacity: int = 120,
                 expected_hosts: Optional[set] = None):
        # expected_hosts: set of hostnames this deployment legitimately serves. When provided,
        # a Host header outside the set is flagged (cache-poisoning / password-reset poisoning).
        # Left None in the demo because any host is "valid" for a local test.
        self.expected_hosts = {h.lower() for h in expected_hosts} if expected_hosts else None
        # ML enforcement posture, controlled by WAF_ML_ENFORCE. Moving ML out of shadow is a
        # first-class one-line switch (WAF_ML_ENFORCE=true) with HIGH-PRECISION enforcement:
        # it blocks only verdicts clearing WAF_ML_ENFORCE_THRESHOLD (default 0.9), so a
        # small-but-real false-positive rate on un-calibrated traffic is bounded.
        # Ships DEFAULT-OFF (shadow) deliberately: enabling an un-calibrated model by default
        # would false-positive legitimate traffic and break a fresh deployment. Enable it after
        # you have MEASURED the real false-positive rate on your own production benign traffic.
        if ml_enforce is None:
            ml_enforce = os.environ.get("WAF_ML_ENFORCE", "false").strip().lower() in ("1", "true", "yes", "on")
        self.ml_enforce = ml_enforce
        self.ml_threshold = float(os.environ.get("WAF_ML_ENFORCE_THRESHOLD", "0.9"))
        # Content-type boundary: routes that LEGITIMATELY carry code/SQL/markup (an admin query
        # console, a paste service, a GraphQL/DSL endpoint) would otherwise be false-positived by
        # the injection signatures + GCID. On these path prefixes the WAF still SCANS and LOGS
        # every hit (a would-block is recorded as shadow_would_block for visibility) but does NOT
        # 403 — detection without enforcement. Safety-critical blocks (rate limit, fail-closed
        # truncation/scan-error) are NOT exempted. Empty = enforce everywhere.
        self.shadow_routes = tuple(
            p.strip() for p in os.environ.get("WAF_SHADOW_ROUTES", "").split(",") if p.strip()
        )
        # Hosts a redirect parameter may legitimately point at. Falls back to EXPECTED_HOSTS
        # (the hostnames this deployment serves) so one setting covers both. Unset => the
        # arbitrary-host open-redirect check is OFF (shape alone cannot decide it).
        _redir = os.environ.get("WAF_ALLOWED_REDIRECT_HOSTS") or os.environ.get("EXPECTED_HOSTS", "")
        self.allowed_redirect_hosts = {h.strip().lower() for h in _redir.split(",") if h.strip()}
        if not self.allowed_redirect_hosts and expected_hosts:
            self.allowed_redirect_hosts = {h.lower() for h in expected_hosts}
        # Shared window when REDIS_URL is set (multi-replica correctness), else per-process.
        self.rate = build_rate_limiter(capacity=rate_capacity)
        self.metrics = Counter()
        self.by_category = Counter()
        self.latencies: deque = deque(maxlen=5000)
        self.lock = threading.Lock()
        # ML layer (optional — engine runs rules-only if it fails to load)
        try:
            from ml.detector_v2 import get_detector
            self.ml = get_detector()
        except Exception as e:
            self.ml = None
            print(f"[waf] ML layer unavailable, running rules-only: {e}")

    def evaluate(self, method: str, path: str, query: str, body: str,
                 headers: Dict[str, str], client_ip: str) -> Decision:
        t0 = time.perf_counter()
        d = Decision()

        # L1 rate limit
        if not self.rate.allow(client_ip):
            d.action, d.layer, d.category = THROTTLE, "rate_limit", "RATE_LIMIT"
            d.reasons.append("rate_limit")
            return self._finish(d, t0)

        # Sanitize every field BEFORE the regex tier: coerce to valid UTF-8 (a lone
        # surrogate previously raised UnicodeEncodeError and silently disabled the whole
        # signature tier) and defang identical-char runs (ReDoS defence-in-depth).
        path = _sanitize(path)
        query = _sanitize(query)
        body = _sanitize(body)
        headers = {k: _sanitize(str(v)) for k, v in (headers or {}).items()}

        # Cap what the expensive regex/ML layers inspect. If the input exceeds the cap we
        # cannot vouch for the uninspected remainder (which is still proxied upstream), so
        # we FAIL CLOSED at decision time rather than allow a truncation bypass.
        full_len = len(query or "") + len(body or "")
        query, q_trunc = _cap(query)
        body, b_trunc = _cap(body)
        truncated = q_trunc or b_trunc
        if truncated:
            d.reasons.append(f"oversized_uninspectable:{full_len}b>{MAX_INSPECT_BYTES}b")

        best_sev = 0.0
        scan_hdrs = _scan_headers(headers)   # exclude infra headers (Host etc.) to avoid FPs

        # Per-scanner guards that FAIL CLOSED: an exception in one scanner must not silently
        # skip detection (the old single try/except swallowed everything and continued).
        scan_err = False
        try:
            for rule, m, loc in pattern_engine.scan_request(path, query, body, scan_hdrs):
                d.reasons.append(f"rules:{rule.category}")
                if rule.severity > best_sev:
                    best_sev, d.category, d.matched, d.layer = rule.severity, rule.category, m.group(0)[:80], "signatures"
        except Exception as e:
            scan_err = True
            d.reasons.append(f"sig_err:pattern_engine:{e}")
        try:
            for r in comprehensive_scanner.scan_request(path=path, query=query, body=body, headers=scan_hdrs):
                sev = r.severity.value / 4.0
                d.reasons.append(f"scanner:{r.category.value}")
                if sev > best_sev:
                    best_sev, d.category, d.matched, d.layer = sev, r.category.value, r.matched_text[:80], "scanner"
        except Exception as e:
            scan_err = True
            d.reasons.append(f"sig_err:scanner:{e}")

        # Close the header blind spot: scan attacker-controlled header VALUES, but honor only
        # unambiguous injection categories so legitimate URLs (Referer/Origin) and Bearer
        # tokens do not false-positive.
        for hk in _USER_DATA_HEADERS:
            hv = headers.get(hk) or headers.get(hk.title()) or headers.get(hk.upper()) or ""
            if not hv:
                continue
            try:
                for r in comprehensive_scanner.scan_payload(hv):
                    if r.category.value not in _HEADER_INJECTION_CATS:
                        continue
                    sev = r.severity.value / 4.0
                    d.reasons.append(f"header_inj:{hk}:{r.category.value}")
                    if sev > best_sev:
                        best_sev, d.category, d.matched, d.layer = sev, r.category.value, r.matched_text[:80], f"header:{hk}"
            except Exception as e:
                scan_err = True
                d.reasons.append(f"hdr_scan_err:{hk}:{e}")

        # L2b: header-specific signals (scanner tools, host-header injection).
        # Narrow patterns only — these headers are excluded from the broad injection scan
        # because standard values like `Accept: */*` false-positive on SQL comment rules.
        try:
            for cat, sev, ev in (_header_signals(headers, self.expected_hosts)
                                 + _path_signals(path) + _payload_signals(query, body)
                                 + _redirect_host_signals(query, body,
                                                          getattr(self, "allowed_redirect_hosts", None))):
                d.reasons.append(f"header:{cat}")
                if sev > best_sev:
                    best_sev, d.category, d.matched, d.layer = sev, cat, ev, "headers"
        except Exception as e:
            d.reasons.append(f"hdr_err:{e}")

        # L3 advanced heuristics
        if ADV:
            try:
                for det in advanced_protection.analyze(path=path, query=query, body=body,
                                                        headers=headers, client_ip=client_ip, ml_score=0.0):
                    sev = getattr(det, "confidence", 0.6)
                    d.reasons.append(f"advanced:{det.category}")
                    if sev > best_sev:
                        best_sev, d.category, d.matched, d.layer = sev, det.category, (getattr(det, "raw_evidence", "") or "")[:80], "advanced"
            except Exception as e:
                d.reasons.append(f"adv_err:{e}")

        sig_block = best_sev >= 0.5    # signatures/advanced are precise -> enforce

        # L4/L5 ML + open-set novelty
        if self.ml is not None:
            try:
                r = self.ml.predict(method, path, query, body, headers)
                d.ml_prob, d.novelty, d.is_zero_day = r.mal_prob, r.novelty, r.is_zero_day
                d.reasons.append(f"ml:{r.category}:{r.route}:p={r.mal_prob}")
                # MLResult.enforce is the authoritative "safe to ACT" signal: it is True only
                # when the train/serve feature contract is VERIFIED and the verdict clears the
                # model's high-confidence threshold. Gate every ML action on it — NEVER on a raw
                # probability: a skewed/uncalibrated model reports mal_prob≈1.0 for ALL traffic
                # (benign included), so probability-gating would block the whole site. When the
                # contract is unverified the skew guard sets enforce=False and ML only observes.
                ml_act = self.ml_enforce and bool(getattr(r, "enforce", False))
                if ml_act and r.is_zero_day and not sig_block:
                    # novel + signatures missed it -> honeypot to deceive & capture
                    d.action, d.layer, d.category = HONEYPOT, "ml:novelty", r.category
                    best_sev = max(best_sev, 0.6)
                elif ml_act and r.is_malicious and r.mal_prob >= self.ml_threshold:
                    if r.mal_prob > best_sev:
                        best_sev, d.category, d.layer = r.mal_prob, r.category, "ml"
                elif r.is_malicious or r.is_zero_day:
                    # Enforcement off, contract unverified, or below threshold -> observe (shadow).
                    d.shadow_would_block = True
            except Exception as e:
                d.reasons.append(f"ml_err:{e}")

        d.severity = round(best_sev, 3)
        if d.action == ALLOW:
            if truncated or scan_err:
                # Fail closed: input we could not fully inspect, or a scanner that errored,
                # must not pass as ALLOW (truncation-bypass and fail-open fixes).
                d.action = BLOCK
                if d.layer == "-":
                    d.layer = "failsafe"
                if d.category == "-":
                    d.category = "oversized_uninspectable" if truncated else "scan_error"
            elif sig_block or (self.ml_enforce and best_sev >= 0.5):
                if self.shadow_routes and path.startswith(self.shadow_routes):
                    # Route legitimately expects code/SQL/markup: detect + log, do not block.
                    d.shadow_would_block = True
                    d.reasons.append(f"shadow_route:{d.category}")
                else:
                    d.action = BLOCK
        return self._finish(d, t0)

    def _finish(self, d: Decision, t0: float) -> Decision:
        d.latency_ms = round((time.perf_counter() - t0) * 1000, 4)
        with self.lock:
            self.metrics["total"] += 1
            self.metrics[d.action.lower()] += 1
            if d.shadow_would_block:
                self.metrics["shadow_would_block"] += 1
            if d.action in (BLOCK, HONEYPOT):
                self.by_category[d.category] += 1
            self.latencies.append(d.latency_ms)
        return d

    def stats(self) -> Dict:
        with self.lock:
            lat = sorted(self.latencies)
            p = lambda q: lat[min(len(lat) - 1, int(len(lat) * q))] if lat else 0.0
            return {
                "counters": dict(self.metrics),
                "by_category": dict(self.by_category.most_common(10)),
                "latency_ms": {"mean": round(sum(lat) / len(lat), 3) if lat else 0.0,
                               "p95": round(p(0.95), 3), "p99": round(p(0.99), 3)},
                "ml_enforcing": self.ml_enforce, "ml_loaded": self.ml is not None,
            }
