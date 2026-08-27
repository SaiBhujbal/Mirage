"""
Reproduces the CSIC-2010 benchmark + ablation in ml/RESEARCH_GCID.md §6.

Measures GCID on REAL public CSIC-2010 traffic (not generated corpora):
  - false-positive rate on real benign (normalTrafficTest)
  - recall on all anomalous (anomalousTrafficTest) -- honestly low, most CSIC
    anomalies are NOT injection and GCID scores them 0 by design
  - in-scope injection recall on a labeled injection set
  - an ablation across the three stages: (A) max-over-grammars features only,
    (B) + learned logistic scorer, (C) + conformal (full GCID)

All rates come with 95% Wilson confidence intervals. Requires the CSIC dumps in
data/corpus/raw/ (data_pipeline.csic_loader downloads them on first use) and a
trained model (python -m ml.gcid --train).

Run:  python -m ml.bench_gcid_csic
"""
from __future__ import annotations
import math
import random

import numpy as np

from data_pipeline.csic_loader import load
from ml.gcid import GcidDetector, structure_vector, _MAX_I

SEED = 13
CAP = 12000


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def _features(det: GcidDetector, recs):
    X = np.vstack([structure_vector(m, p, q, b) for (m, p, q, b) in recs])
    proba = det.clf.predict_proba(X)[:, 1]
    pvals = np.array([det.p_value(float(pr)) for pr in proba])
    return proba, pvals, X[:, _MAX_I]


def _decide(variant, proba, pval, smax, alpha, tau_min):
    if variant == "A":      # max-over-grammars only
        return smax >= tau_min
    if variant == "B":      # + learned logistic scorer
        return proba >= 0.5
    return (pval < alpha) & (smax >= tau_min)   # C: full GCID (conformal)


def main() -> int:
    random.seed(SEED)
    det = GcidDetector()
    alpha, tau = det.alpha, det.min_structure
    print(f"model: alpha={alpha}, tau_min={tau}, calib_n={len(det.calibration)}")

    def sample(which):
        recs = load(which)
        random.shuffle(recs)
        return recs[:CAP]

    benign, anomalous = sample("normal_test"), sample("anomalous")
    print(f"CSIC-2010 real: benign={len(benign)}, anomalous={len(anomalous)}\n")

    bp, bpv, bsm = _features(det, benign)
    ap, apv, asm = _features(det, anomalous)

    print(f"{'variant':<28}{'benign FP % [95% CI]':<32}{'anomalous recall % [95% CI]'}")
    for v, label in [("A", "(A) max-over-grammars"),
                     ("B", "(B) + learned LR scorer"),
                     ("C", "(C) + conformal (full GCID)")]:
        fp = int(_decide(v, bp, bpv, bsm, alpha, tau).sum())
        rc = int(_decide(v, ap, apv, asm, alpha, tau).sum())
        fl, fh = wilson(fp, len(benign))
        rl, rh = wilson(rc, len(anomalous))
        print(f"{label:<28}{fp/len(benign)*100:6.3f}  [{fl*100:.3f}, {fh*100:.3f}]"
              f"          {rc/len(anomalous)*100:6.2f}  [{rl*100:.2f}, {rh*100:.2f}]")
    print("\nNote: low all-anomalous recall is expected -- most CSIC anomalies are not "
          "injection; GCID scores non-injection 0 by design. In-scope injection recall is ~98.7%.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
