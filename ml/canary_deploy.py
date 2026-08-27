"""
Canary deployment + model registry — progressive rollout with automatic rollback.

The promotion gate (champion_challenger) answers "is this model allowed to ship?".
It does NOT answer "is it safe on live traffic?". Canary does: the challenger takes a
small, growing share of REAL requests while the champion still serves the rest, and we
watch live health at every stage. Any breach → instant rollback to the champion.

Stages: 1% → 5% → 25% → 50% → 100%, each held for a soak window.
Abort conditions (checked at every stage, evaluated on canary traffic only):
  - benign false-positive rate > champion FP + FP_TOLERANCE
  - attack recall < champion recall - REC_TOLERANCE
  - error rate > ERR_MAX (inference exceptions)
  - p99 latency > LAT_MAX_MS
Rollback is the default action on ANY breach — deployment is not "brave".

The registry keeps every version with its metrics + a pointer to the live one, so a
rollback is a pointer swap, not a retrain.
"""
from __future__ import annotations
import json, time, hashlib, random
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
REG_DIR = ROOT / "models_v2"
REGISTRY = REG_DIR / "registry.json"

STAGES = [0.01, 0.05, 0.25, 0.50, 1.00]
FP_TOLERANCE = 0.01      # canary may not exceed champion FP by more than 1pt
REC_TOLERANCE = 0.03     # nor lose more than 3pts recall
ERR_MAX = 0.005
LAT_MAX_MS = 25.0


# ---------------- registry ----------------
def _load_registry() -> Dict:
    if REGISTRY.exists():
        try:
            return json.loads(REGISTRY.read_text())
        except Exception:
            pass
    return {"live": None, "previous": None, "versions": {}}


def register(version: str, artifacts: Dict[str, str], metrics: Dict, notes: str = "") -> Dict:
    reg = _load_registry()
    reg["versions"][version] = {"version": version, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "artifacts": artifacts, "metrics": metrics, "notes": notes,
                                "status": "registered"}
    REGISTRY.write_text(json.dumps(reg, indent=2))
    return reg["versions"][version]


def set_live(version: str) -> Dict:
    reg = _load_registry()
    if version not in reg["versions"]:
        raise KeyError(f"unknown version {version}")
    reg["previous"] = reg.get("live")
    reg["live"] = version
    reg["versions"][version]["status"] = "live"
    if reg["previous"] and reg["previous"] in reg["versions"]:
        reg["versions"][reg["previous"]]["status"] = "previous"
    REGISTRY.write_text(json.dumps(reg, indent=2))
    return reg


def rollback() -> Optional[str]:
    """Pointer swap back to the previous live version. No retrain, no downtime."""
    reg = _load_registry()
    prev = reg.get("previous")
    if not prev:
        return None
    reg["versions"][reg["live"]]["status"] = "rolled_back"
    reg["live"], reg["previous"] = prev, None
    reg["versions"][prev]["status"] = "live"
    REGISTRY.write_text(json.dumps(reg, indent=2))
    return prev


def live_version() -> Optional[str]:
    return _load_registry().get("live")


# ---------------- canary ----------------
class CanaryRun:
    """
    score_champ / score_chal: fn(sample_dict) -> malicious probability.
    traffic: list of dicts with keys {method,path,query,body,label(0/1)} — a live sample.
    """
    def __init__(self, score_champ: Callable, score_chal: Callable, threshold: float = 0.5):
        self.sc, self.sh, self.thr = score_champ, score_chal, threshold
        self.log: List[Dict] = []

    def _measure(self, scorer, traffic) -> Dict:
        t0 = time.perf_counter(); errs = 0
        fp = fn = tp = tn = 0
        lat = []
        for s in traffic:
            t1 = time.perf_counter()
            try:
                p = scorer(s)
            except Exception:
                errs += 1
                continue
            lat.append((time.perf_counter() - t1) * 1000)
            hit = p >= self.thr
            if s["label"] == 1:
                tp += hit; fn += (not hit)
            else:
                fp += hit; tn += (not hit)
        lat.sort()
        p99 = lat[int(len(lat) * 0.99)] if lat else 0.0
        return {"fp_rate": fp / max(fp + tn, 1), "recall": tp / max(tp + fn, 1),
                "err_rate": errs / max(len(traffic), 1), "p99_ms": round(p99, 3), "n": len(traffic)}

    def run(self, traffic: List[Dict], seed: int = 0) -> Dict:
        random.seed(seed)
        champ_base = self._measure(self.sc, traffic)
        stages_out, aborted, abort_reason = [], False, None
        for pct in STAGES:
            k = max(30, int(len(traffic) * pct))
            canary_traffic = random.sample(traffic, min(k, len(traffic)))
            m = self._measure(self.sh, canary_traffic)
            breaches = []
            if m["fp_rate"] > champ_base["fp_rate"] + FP_TOLERANCE:
                breaches.append(f"FP {m['fp_rate']:.3f} > champ {champ_base['fp_rate']:.3f}+{FP_TOLERANCE}")
            if m["recall"] < champ_base["recall"] - REC_TOLERANCE:
                breaches.append(f"recall {m['recall']:.3f} < champ {champ_base['recall']:.3f}-{REC_TOLERANCE}")
            if m["err_rate"] > ERR_MAX:
                breaches.append(f"errors {m['err_rate']:.4f} > {ERR_MAX}")
            if m["p99_ms"] > LAT_MAX_MS:
                breaches.append(f"p99 {m['p99_ms']}ms > {LAT_MAX_MS}ms")
            stages_out.append({"traffic_pct": pct, "metrics": m, "breaches": breaches,
                               "action": "ROLLBACK" if breaches else "advance"})
            if breaches:
                aborted, abort_reason = True, breaches[0]
                break
        return {"champion_baseline": champ_base, "stages": stages_out,
                "outcome": "ROLLED_BACK" if aborted else "FULLY_PROMOTED",
                "abort_reason": abort_reason}


def format_run(res: Dict) -> str:
    b = res["champion_baseline"]
    out = [f"champion baseline: FP={b['fp_rate']:.3f} recall={b['recall']:.3f} p99={b['p99_ms']}ms"]
    for s in res["stages"]:
        m = s["metrics"]
        out.append(f"  stage {int(s['traffic_pct']*100):>3}% traffic  FP={m['fp_rate']:.3f} "
                   f"recall={m['recall']:.3f} p99={m['p99_ms']:>5}ms  -> {s['action']}"
                   + (f"   [{s['breaches'][0]}]" if s["breaches"] else ""))
    out.append(f"  OUTCOME: {res['outcome']}" + (f" ({res['abort_reason']})" if res["abort_reason"] else ""))
    return "\n".join(out)
