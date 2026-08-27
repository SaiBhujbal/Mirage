"""Feature-distribution drift detection (Population Stability Index).

The product monitored FP/FN rates (supervised, needs labels) but had no UNSUPERVISED drift
signal — so covariate shift in incoming traffic went unnoticed until it showed up as errors.
This adds PSI on the canonical feature contract: compare a reference distribution (captured at
train time) against a live window, per feature. PSI thresholds (industry standard):

    PSI < 0.10  : no significant shift
    0.10-0.25   : moderate shift — watch
    >= 0.25     : significant shift — recalibrate / retrain

Dependency-light (numpy only). Reference bins are persisted next to the model so drift is
measured against the exact training distribution the live model was calibrated on.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

_DIR = Path(__file__).resolve().parent.parent / "models_v2"
_REF_PATH = _DIR / "drift_reference.json"

# PSI decision thresholds
PSI_MODERATE = 0.10
PSI_SIGNIFICANT = 0.25


def _feats(records: List[Tuple[str, str, str, str]]) -> np.ndarray:
    from ml.canonical_features import lexical_features
    return np.array([lexical_features(m, p, q, b, {}) for m, p, q, b in records], dtype=np.float64)


def psi(expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
    """Population Stability Index for one feature, using quantile bins of the reference."""
    expected = expected[np.isfinite(expected)]
    actual = actual[np.isfinite(actual)]
    if expected.size == 0 or actual.size == 0:
        return 0.0
    edges = np.unique(np.quantile(expected, np.linspace(0, 1, bins + 1)))
    if edges.size < 2:
        return 0.0
    edges[0], edges[-1] = -np.inf, np.inf
    e_frac = np.histogram(expected, edges)[0] / expected.size
    a_frac = np.histogram(actual, edges)[0] / actual.size
    eps = 1e-4
    e_frac = np.clip(e_frac, eps, None)
    a_frac = np.clip(a_frac, eps, None)
    return float(np.sum((a_frac - e_frac) * np.log(a_frac / e_frac)))


@dataclass
class DriftReport:
    psi_mean: float
    psi_max: float
    drifted_features: List[str]
    retrain_recommended: bool
    n_live: int

    def to_dict(self) -> Dict:
        return self.__dict__


class FeatureDriftMonitor:
    def __init__(self, ref_path: Path = _REF_PATH):
        self.ref_path = Path(ref_path)
        self.reference: Optional[Dict[str, List[float]]] = None
        if self.ref_path.exists():
            try:
                self.reference = json.loads(self.ref_path.read_text(encoding="utf-8"))
            except Exception:
                self.reference = None

    def fit_reference(self, records: List[Tuple[str, str, str, str]]) -> None:
        """Capture the training-time feature distribution (call this at train time)."""
        from ml.canonical_features import LEXICAL_FEATURE_NAMES
        X = _feats(records)
        self.reference = {name: X[:, i].tolist() for i, name in enumerate(LEXICAL_FEATURE_NAMES)}
        self.ref_path.parent.mkdir(parents=True, exist_ok=True)
        self.ref_path.write_text(json.dumps({"features": LEXICAL_FEATURE_NAMES,
                                             "columns": self.reference}), encoding="utf-8")

    def check(self, records: List[Tuple[str, str, str, str]],
              significant: float = PSI_SIGNIFICANT) -> DriftReport:
        """PSI of a live window vs the reference. retrain_recommended if any feature is significant."""
        from ml.canonical_features import LEXICAL_FEATURE_NAMES
        if not self.reference:
            return DriftReport(0.0, 0.0, [], False, len(records))
        cols = self.reference.get("columns", self.reference)
        X = _feats(records)
        psis: Dict[str, float] = {}
        for i, name in enumerate(LEXICAL_FEATURE_NAMES):
            ref = np.asarray(cols.get(name, []), dtype=np.float64)
            if ref.size:
                psis[name] = psi(ref, X[:, i])
        if not psis:
            return DriftReport(0.0, 0.0, [], False, len(records))
        vals = np.array(list(psis.values()))
        drifted = [n for n, v in psis.items() if v >= significant]
        return DriftReport(psi_mean=round(float(vals.mean()), 4), psi_max=round(float(vals.max()), 4),
                           drifted_features=drifted, retrain_recommended=bool(drifted), n_live=len(records))
