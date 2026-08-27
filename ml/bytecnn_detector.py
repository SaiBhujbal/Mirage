"""Byte-CNN serving detector — the research DualBranchNet as a selectable live model.

Wraps ml/deep_model.DualBranchNet (byte-CNN + lexical fusion + energy novelty head) behind the
same MLResult contract as detector_v2.DetectorV2, so the engine and the harness `ml_model` target
can score it interchangeably. Selected with WAF_ML_MODEL=bytecnn.

SHADOW ONLY by design: on measured data this model still has ~7% false positives on diverse
benign — better than the lexical XGBoost (100% on modern) but not yet under an enforce budget — so
`enforce` is always False (it detects and shadow-logs, never blocks) until it clears the harness
`--gate-ml` on production-shaped traffic. Requires torch; if torch is unavailable (e.g. Windows
Application Control blocks it), loading raises and get_detector() falls back to the XGBoost model.
"""
from __future__ import annotations

import os
import json
import logging
from pathlib import Path
from typing import Dict, Optional

import numpy as np

from ml.detector_v2 import MLResult, serving_contract_hash
from ml.canonical_features import lexical_features, byte_sequence

logger = logging.getLogger("decepticon.ml.bytecnn")
_DIR = Path(__file__).resolve().parent.parent / "models_v2"


class ByteCNNDetector:
    model_kind = "bytecnn (DualBranchNet: byte-CNN + lexical fusion, energy novelty)"

    def __init__(self, models_dir: Path = _DIR):
        import torch  # raises if torch is unavailable -> caller falls back
        from ml.deep_model import DualBranchNet

        meta_path = models_dir / "deep_meta.json"
        weights = models_dir / "dualbranch.pt"
        if not (meta_path.exists() and weights.exists()):
            raise FileNotFoundError(f"byte-CNN artifacts missing in {models_dir} "
                                    "(train with: python -m ml.deep_model)")
        self._torch = torch
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.class_names = meta["class_names"]
        self.model_version = f"bytecnn:{meta.get('epochs','?')}ep"
        # novelty (energy) threshold: high energy = novel. Use meta if present, else a default.
        self.nov_t = float(meta.get("energy_novelty_threshold", 0.0))
        self.mal_t = 0.5
        # The byte-CNN uses a DIFFERENT feature contract (bytes + lexical), so the lexical-only
        # skew guard does not apply; keep it shadow (contract_verified stays False -> enforce False).
        self.contract_verified = False
        self.serving_contract = serving_contract_hash()

        self.net = DualBranchNet(len(self.class_names))
        self.net.load_state_dict(torch.load(str(weights), map_location="cpu"))
        self.net.eval()
        self.loaded = True
        logger.info("byte-CNN serving model loaded (%s, %d classes) — SHADOW only",
                    self.model_version, len(self.class_names))

    def predict(self, method: str = "GET", path: str = "", query: str = "",
                body: str = "", headers: Optional[Dict[str, str]] = None) -> MLResult:
        torch = self._torch
        B = torch.tensor(np.array([byte_sequence(method, path, query, body, {})]), dtype=torch.long)
        L = torch.tensor(np.array([lexical_features(method, path, query, body, {})]), dtype=torch.float32)
        with torch.no_grad():
            logits = self.net(B, L)
            probs = torch.softmax(logits, dim=1)[0]
            energy = float(self.net.energy(logits)[0].item())
            benign_p = float(probs[0].item())
            top_i = int(torch.argmax(logits[0]).item())
        mal_prob = 1.0 - benign_p
        category = self.class_names[top_i] if top_i < len(self.class_names) else "attack"
        clf_hit = mal_prob >= self.mal_t
        nov_hit = self.nov_t > 0 and energy >= self.nov_t
        is_zero_day = nov_hit and not clf_hit
        route = "classifier" if clf_hit else ("novelty" if nov_hit else "none")
        return MLResult(
            is_malicious=bool(clf_hit or nov_hit), mal_prob=mal_prob, novelty=energy,
            category=(category if category != "benign" else "attack"), is_zero_day=is_zero_day,
            route=route, enforce=False,  # SHADOW: never enforce until it clears --gate-ml
            enforce_reason="byte-CNN shadow (representation prototype; not enforce-gated yet)",
            contract_verified=False, model_version=self.model_version)
