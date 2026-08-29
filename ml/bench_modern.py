"""
Modern API-traffic benchmark — the evidence the CSIC/PKDD numbers cannot provide.

BACKGROUND. CSIC-2010 and ECML/PKDD-2007 are the standard public HTTP-attack corpora and this
project reports on them, but they are 15+ years old: form-encoded requests to a server-rendered
Spanish e-commerce app. They contain no JSON APIs, no GraphQL, no JWTs, no base64 payloads, no
SPA-shaped traffic. A detector can score perfectly on them and still false-positive on
everything a 2020s API serves — which is exactly the failure mode measured in this project for
the lexical/statistical models (52-100% FP on modern benign).

So this benchmark evaluates the SAME detector on generated modern traffic — JSON API bodies,
GraphQL queries, JWT bearer tokens, base64 blobs, UUIDs, i18n text, webhook payloads — plus
modern attack shapes, and reports false positives and recall separately with confidence
intervals. Generated traffic is weaker evidence than production traffic (it comes from a
generator whose assumptions are ours), which is stated rather than glossed: this closes the
"no modern traffic in the evaluation" gap, not the "no production traffic" one.

Run:  python -m ml.bench_modern
      WAF_ML_MODEL=gcid python -m ml.bench_modern     # the enforcement-ready detector
"""
from __future__ import annotations

import math

from data_pipeline.modern_attacks import generate as gen_attacks
from data_pipeline.modern_benign import generate as gen_benign
from waf.engine import LayeredWAF

SEED_BENIGN, SEED_ATTACK, N = 7, 11, 4000


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _norm(rec):
    """Generators emit 4- or 5-tuples; normalise to (method, path, query, body)."""
    if isinstance(rec, dict):
        return (rec.get("method", "GET"), rec.get("path", "/"),
                rec.get("query", ""), rec.get("body", ""))
    return tuple(rec[:4])


def _run(waf, records, tag):
    blocked = 0
    for i, rec in enumerate(records):
        m, p, q, b = _norm(rec)
        ip = f"203.0.{i // 250 % 250}.{i % 250}"       # unique IP: don't measure reputation state
        if waf.evaluate(m, p, q, b, {"user-agent": "Mozilla/5.0"}, ip).action != "ALLOW":
            blocked += 1
    lo, hi = wilson(blocked, len(records))
    rate = blocked / len(records) * 100 if records else 0.0
    print(f"    {tag:<34}{blocked:>5}/{len(records):<7}{rate:6.2f}%  [{lo*100:.2f}, {hi*100:.2f}]")
    return blocked


def main() -> int:
    benign = gen_benign(N, seed=SEED_BENIGN)
    attacks = gen_attacks(N, seed=SEED_ATTACK)
    print(f"Modern API traffic benchmark — {len(benign)} benign, {len(attacks)} attacks\n")
    print("  Benign shapes: JSON API bodies, GraphQL queries, JWT bearer tokens, base64 blobs,")
    print("  UUIDs, i18n text, OAuth callbacks, webhooks — none of which exist in CSIC/PKDD.\n")

    waf = LayeredWAF(ml_enforce=False)
    print(f"    {'measurement':<34}{'count':<13}{'rate':<9}[95% CI]")
    fp = _run(waf, benign, "false positives (benign blocked)")
    tp = _run(waf, attacks, "recall (attacks blocked)")

    print("\nInterpretation:")
    print(f"  - False-positive rate on modern benign: {fp/len(benign)*100:.2f}%. This is the number")
    print("    the CSIC/PKDD evaluation cannot tell you, and the one that decides whether")
    print("    enforcement is survivable on an API-shaped workload.")
    print(f"  - Recall on modern attack shapes: {tp/len(attacks)*100:.2f}%.")
    print("  - Caveat, stated plainly: this is GENERATED traffic. It closes the 'no modern")
    print("    traffic in the evaluation' gap, not the 'no production traffic' gap. Calibrate")
    print("    on your own logs before enforcing: python -m waf.calibrate <traffic>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
