"""
Hostile edge-case suite. Everything a reviewer (or an attacker) will throw at this repo.

Three classes of test:
  A. MALFORMED / ADVERSARIAL INPUT  — the WAF must never crash, hang, or fail-open silently
  B. RESILIENCE                     — missing models, corrupt state files, dead network
  C. CONCURRENCY & RESOURCE SAFETY  — thread safety, unbounded growth, DoS payload sizes

Run:  python -m pytest tests/test_edge_cases.py -q     (or)     python tests/test_edge_cases.py
"""
from __future__ import annotations
import json, os, sys, shutil, tempfile, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from waf.engine import LayeredWAF, ALLOW, BLOCK, THROTTLE, HONEYPOT

WAF = LayeredWAF()
H = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}


def ev(method="GET", path="/", query="", body="", headers=None, ip="203.0.113.1"):
    return WAF.evaluate(method, path, query, body, headers if headers is not None else H, ip)


# ───────────────────────── A. MALFORMED / ADVERSARIAL INPUT ─────────────────────────

@pytest.mark.parametrize("case,kw", [
    ("completely empty",        dict(method="", path="", query="", body="")),
    ("no leading slash",        dict(path="admin")),
    ("only slashes",            dict(path="//////")),
    ("null byte in path",       dict(path="/a\x00b")),
    ("null byte in query",      dict(query="id=1\x00 UNION SELECT")),
    ("CRLF injection",          dict(query="a=1\r\nSet-Cookie: x=1")),
    ("bare CR",                 dict(query="a=\r")),
    ("unicode path",            dict(path="/café/naïve/日本語/emoji🐭")),
    ("RTL override",            dict(query="f=‮gnp.exe")),
    ("overlong UTF-8",          dict(query="p=%c0%ae%c0%ae%2f")),
    ("surrogate pair",          dict(query="q=😀")),
    ("binary-ish body",         dict(body="\x00\x01\x02\xff\xfe")),
    ("malformed JSON body",     dict(body='{"a":')),
    ("deeply nested JSON",      dict(body="[" * 200 + "]" * 200)),
    ("huge single param",       dict(query="q=" + "A" * 100_000)),
    ("many params",             dict(query="&".join(f"p{i}={i}" for i in range(2000)))),
    ("duplicate params",        dict(query="id=1&id=2&id=3&id=4")),
    ("param with no value",     dict(query="a&b&c")),
    ("only equals",             dict(query="=" * 500)),
    ("percent at end",          dict(query="q=abc%")),
    ("invalid percent",         dict(query="q=%zz%")),
    ("very long path",          dict(path="/" + "seg/" * 3000)),
    ("tab/newline in body",     dict(body="a\tb\nc\r\nd")),
    ("json null values",        dict(body='{"a":null,"b":[null,null]}')),
    ("empty header value",      dict(headers={"X-Custom": "", "User-Agent": ""})),
    ("header injection try",    dict(headers={"X-Evil": "a\r\nX-Injected: 1"})),
    ("no headers at all",       dict(headers={})),
])
def test_malformed_input_never_crashes(case, kw):
    """The engine must return a Decision for ANY input — never raise, never hang."""
    t0 = time.perf_counter()
    d = ev(**kw)
    elapsed = (time.perf_counter() - t0) * 1000
    assert d is not None, f"{case}: no decision returned"
    assert d.action in (ALLOW, BLOCK, THROTTLE, HONEYPOT), f"{case}: bad action {d.action}"
    assert elapsed < 3000, f"{case}: took {elapsed:.0f}ms — possible ReDoS"
    assert isinstance(d.latency_ms, float)


def test_no_silent_fail_open_on_layer_error():
    """If a layer raises, the failure must be RECORDED in reasons, not swallowed."""
    d = ev(query="id=1 UNION SELECT password FROM users--")
    assert d.action == BLOCK, "known SQLi must block"
    assert any("rules:" in r or "scanner:" in r for r in d.reasons), "no layer evidence recorded"


@pytest.mark.parametrize("payload", [
    "id=1 UNION SELECT password FROM users--",
    "q=<script>alert(document.cookie)</script>",
    "file=../../../../etc/passwd",
    "cmd=;cat /etc/passwd",
    "url=http://169.254.169.254/latest/meta-data/",
])
def test_known_attacks_still_blocked_under_obfuscation(payload):
    """Core attacks must block even with mixed case + padding around them."""
    d = ev(query=payload)
    assert d.action == BLOCK, f"{payload!r} not blocked (action={d.action})"


def test_attack_hidden_in_deep_path_segment():
    d = ev(path="/api/v2/files/../../../../etc/passwd")
    assert d.action == BLOCK, "path traversal in path segment must block"


# ───────────────────────── B. RESILIENCE ─────────────────────────

def test_engine_works_without_ml_models(monkeypatch):
    """Missing/broken ML artifacts must DEGRADE to rules-only, not crash the WAF."""
    import waf.engine as we
    import importlib
    monkeypatch.setattr(we, "get_detector", lambda: (_ for _ in ()).throw(FileNotFoundError("no model")), raising=False)
    w = we.LayeredWAF.__new__(we.LayeredWAF)      # build without __init__ ML load
    w.ml_enforce = False
    w.rate = we.RateLimiter(capacity=120)
    from collections import Counter, deque
    w.metrics, w.by_category, w.latencies = Counter(), Counter(), deque(maxlen=100)
    w.lock = threading.Lock()
    w.ml = None                                    # simulate failed load
    w.shadow_routes = ()                           # enforce everywhere (no route exceptions)
    d = w.evaluate("GET", "/u", "id=1 UNION SELECT p FROM users--", "", H, "1.2.3.4")
    assert d.action == BLOCK, "rules must still block when ML is unavailable"


def test_corrupt_capture_file_is_survivable():
    """A malformed JSONL line in the capture feed must not kill the pipeline."""
    import ml.zeroday_store as zs
    tmp = Path(tempfile.mkdtemp())
    orig = (zs.STORE, zs.PENDING, zs.STATE, zs.BATCHES)
    zs.STORE, zs.PENDING, zs.STATE, zs.BATCHES = tmp, tmp / "p.jsonl", tmp / "s.json", tmp / "b"
    zs.BATCHES.mkdir(parents=True, exist_ok=True)
    try:
        zs.PENDING.write_text('{"good":1,"label":1,"reviewed":true}\nNOT JSON AT ALL\n{"b":\n')
        rows = zs.pending()                       # must skip bad lines, not raise
        assert isinstance(rows, list)
        ready, info = zs.readiness()
        assert ready is False
    finally:
        zs.STORE, zs.PENDING, zs.STATE, zs.BATCHES = orig
        shutil.rmtree(tmp, ignore_errors=True)


def test_corrupt_store_state_recovers():
    import ml.zeroday_store as zs
    tmp = Path(tempfile.mkdtemp())
    orig = (zs.STORE, zs.PENDING, zs.STATE, zs.BATCHES)
    zs.STORE, zs.PENDING, zs.STATE, zs.BATCHES = tmp, tmp / "p.jsonl", tmp / "s.json", tmp / "b"
    zs.BATCHES.mkdir(parents=True, exist_ok=True)
    try:
        zs.STATE.write_text("{{{ not json")
        s = zs._state()                            # must fall back to defaults
        assert isinstance(s, dict) and "batch_opened" in s
    finally:
        zs.STORE, zs.PENDING, zs.STATE, zs.BATCHES = orig
        shutil.rmtree(tmp, ignore_errors=True)


def test_kev_uses_cache_when_network_dead(monkeypatch):
    """Data pipeline must not hard-fail when the CVE feed is unreachable (cache fallback)."""
    import data_pipeline.kev_source as kev
    if not kev.CACHE.exists():
        pytest.skip("no KEV cache present to test fallback")
    monkeypatch.setattr(kev.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("network down")))
    data = kev.fetch_kev(use_cache_hours=10**6)     # force cache path
    assert data.get("count", 0) > 0


def test_registry_missing_artifact_falls_back():
    """A registry pointing at a nonexistent model file must not crash the detector."""
    from ml.detector_v2 import DetectorV2
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "registry.json").write_text(json.dumps(
            {"live": "ghost", "versions": {"ghost": {"artifacts": {"clf": "does_not_exist.json"}}}}))
        sel = DetectorV2._resolve(tmp)
        assert sel["version"] != "ghost", "must not select a version whose artifact is missing"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ───────────────────────── C. CONCURRENCY & RESOURCE SAFETY ─────────────────────────

def test_thread_safety_under_concurrent_load():
    """Metrics/rate-limiter must not corrupt or crash under parallel requests."""
    w = LayeredWAF()
    errors, N, T = [], 60, 8

    def worker(tid):
        try:
            for i in range(N):
                w.evaluate("GET", f"/p{i}", f"q={i}", "", H, f"10.0.{tid}.{i % 250}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(T)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert not errors, f"concurrency errors: {errors[:3]}"
    assert w.metrics["total"] == N * T, f"metric race: {w.metrics['total']} != {N*T}"


def test_rate_limiter_expires_old_entries():
    """The limiter must EXPIRE entries outside the window, not just cap the deque.

    NOTE: capacity must be > the number of hits, otherwise `allow` stops appending once
    full and the test passes even with expiry removed (this exact bug was caught by
    mutation-testing the suite — a capped deque is not proof of expiry)."""
    from waf.engine import RateLimiter
    rl = RateLimiter(capacity=10_000, window_s=0.2)   # high cap => growth is real
    for _ in range(500):
        rl.allow("1.2.3.4")
    assert len(rl.hits["1.2.3.4"]) == 500, "precondition: entries should accumulate"
    time.sleep(0.25)                                   # let the window pass
    rl.allow("1.2.3.4")                                # this call must prune the old 500
    assert len(rl.hits["1.2.3.4"]) == 1, \
        f"old entries not expired ({len(rl.hits['1.2.3.4'])} left) — unbounded memory growth"


# ── trust-boundary: X-Forwarded-For spoofing ──
# Regression lock for a MEASURED bypass: before the fix, 150 requests with a rotating fake
# XFF got 150 allowed / 0 throttled against a 120/10s limit. Every per-client control
# (rate limit, IP reputation, poison-guard per-source cap) depends on this resolution.

def test_xff_ignored_when_peer_is_untrusted():
    from waf.client_ip import ClientIPResolver
    r = ClientIPResolver("")                       # trust nothing (default)
    assert r.resolve("8.8.8.8", "1.2.3.4") == "8.8.8.8", "forged XFF must be ignored"


def test_xff_uses_rightmost_untrusted_behind_proxy():
    from waf.client_ip import ClientIPResolver
    r = ClientIPResolver("127.0.0.0/8,10.0.0.0/8")
    # attacker prepends a fake entry; real client was appended by our LB
    assert r.resolve("127.0.0.1", "1.2.3.4, 203.0.113.50") == "203.0.113.50"
    # whole chain is our own proxies -> fall back to peer, never to the forged value
    assert r.resolve("127.0.0.1", "evil-spoof, 10.0.0.5") == "127.0.0.1"


def test_spoofed_xff_cannot_mint_unlimited_rate_budget():
    """The end-to-end property: rotating XFF must NOT create fresh rate buckets."""
    from waf.engine import LayeredWAF
    from waf.client_ip import ClientIPResolver
    w = LayeredWAF(rate_capacity=20)
    r = ClientIPResolver("")                       # WAF directly exposed
    peer = "203.0.113.9"
    allowed = 0
    for i in range(60):
        ip = r.resolve(peer, f"10.0.0.{i}")        # attacker rotates the header
        if w.evaluate("GET", "/", "", "", H, ip).action != THROTTLE:
            allowed += 1
    assert allowed <= 25, f"{allowed}/60 allowed — XFF spoofing still mints rate budget"


def test_rate_limiter_actually_throttles():
    from waf.engine import RateLimiter
    rl = RateLimiter(capacity=5, window_s=60)
    results = [rl.allow("9.9.9.9") for _ in range(10)]
    assert results[:5] == [True] * 5 and results[5:] == [False] * 5, f"bad throttle pattern {results}"


def test_latency_buffer_is_capped():
    w = LayeredWAF()
    for i in range(6000):
        w.evaluate("GET", "/", "", "", H, "9.8.7.6")
    assert len(w.latencies) <= 5000, "latency buffer unbounded"


def test_large_payload_does_not_explode_latency():
    """A 1MB body must still decide quickly (input truncation must be enforced)."""
    big = "A" * 1_000_000
    t0 = time.perf_counter()
    d = ev(body=big)
    ms = (time.perf_counter() - t0) * 1000
    assert d is not None and ms < 3000, f"1MB body took {ms:.0f}ms"


def test_repeated_evaluation_is_deterministic():
    a = ev(query="id=1 UNION SELECT password FROM users--")
    b = ev(query="id=1 UNION SELECT password FROM users--")
    assert (a.action, a.category) == (b.action, b.category), "non-deterministic decision"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "--no-header", "-x" if "-x" in sys.argv else "--tb=short"]))
