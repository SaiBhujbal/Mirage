"""
Zero-day data store — accumulate first, retrain only when there is ENOUGH signal.

THE RULE (and the bug this fixes): never retrain from a single captured data point.
One sample cannot move a decision boundary responsibly — it can only overfit, destabilise
calibration, or hand an attacker a one-shot lever over the model. Captures are therefore
BUFFERED in a durable store and a retrain is released only when the batch satisfies every
readiness condition below.

Readiness gate (ALL must hold):
  1. MIN_TOTAL          >= 150 reviewed samples accumulated
  2. MIN_PER_CLASS      >= 40 attack AND >= 40 benign (a one-sided batch skews the prior)
  3. MIN_DISTINCT_SHAPES>= 25 distinct payload shapes (not 150 copies of one flood)
  4. MIN_SOURCES        >= 10 distinct source IPs (not one attacker steering the model)
  5. MIN_AGE_HOURS      >= 6h since the batch opened (resist a fast poisoning burst)
  6. cooldown           >= 24h since the last released batch

Anything short of that: the store keeps accumulating and reports WHY it is not ready.
Released batches are archived with a batch id so a retrain is reproducible and auditable.
"""
from __future__ import annotations
import json, hashlib, re, time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "data" / "corpus" / "zeroday_store"
PENDING = STORE / "pending.jsonl"
STATE = STORE / "state.json"
BATCHES = STORE / "batches"
for d in (STORE, BATCHES):
    d.mkdir(parents=True, exist_ok=True)

MIN_TOTAL = 150
MIN_PER_CLASS = 40
MIN_DISTINCT_SHAPES = 25
MIN_SOURCES = 10
MIN_AGE_HOURS = 6.0
COOLDOWN_HOURS = 24.0


def _shape(payload: str) -> str:
    s = (payload or "").lower()
    s = re.sub(r"\d+", "#", s)
    s = re.sub(r"[a-f0-9]{6,}", "H", s)
    s = re.sub(r"\s+", " ", s).strip()
    return hashlib.sha1(s.encode()).hexdigest()[:12]


def _state() -> Dict:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except Exception:
            pass
    return {"batch_opened": time.time(), "last_release": 0.0, "released_batches": 0}


def _save_state(s: Dict):
    STATE.write_text(json.dumps(s, indent=2))


def add(sample: Dict) -> None:
    """Append one captured/reviewed sample to the pending buffer. Never trains directly."""
    sample = dict(sample)
    sample.setdefault("ts", time.time())
    sample["shape"] = _shape(f"{sample.get('query','')} {sample.get('body','')}")
    st = _state()
    if not PENDING.exists() or PENDING.stat().st_size == 0:
        st["batch_opened"] = time.time()
        _save_state(st)
    with PENDING.open("a") as f:
        f.write(json.dumps(sample) + "\n")


def pending() -> List[Dict]:
    if not PENDING.exists():
        return []
    out = []
    for line in PENDING.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def readiness() -> Tuple[bool, Dict]:
    """Is the accumulated batch big/diverse/old enough to justify a retrain?"""
    s = pending()
    st = _state()
    reviewed = [x for x in s if x.get("reviewed") and x.get("label") in (0, 1)]
    n_atk = sum(1 for x in reviewed if x["label"] == 1)
    n_ben = sum(1 for x in reviewed if x["label"] == 0)
    shapes = len({x.get("shape") for x in reviewed})
    sources = len({x.get("source_ip", "?") for x in reviewed})
    age_h = (time.time() - st.get("batch_opened", time.time())) / 3600
    cool_h = (time.time() - st.get("last_release", 0)) / 3600

    checks = {
        "total_reviewed":  (len(reviewed) >= MIN_TOTAL,        f"{len(reviewed)}/{MIN_TOTAL}"),
        "attack_samples":  (n_atk >= MIN_PER_CLASS,            f"{n_atk}/{MIN_PER_CLASS}"),
        "benign_samples":  (n_ben >= MIN_PER_CLASS,            f"{n_ben}/{MIN_PER_CLASS}"),
        "distinct_shapes": (shapes >= MIN_DISTINCT_SHAPES,     f"{shapes}/{MIN_DISTINCT_SHAPES}"),
        "distinct_sources":(sources >= MIN_SOURCES,            f"{sources}/{MIN_SOURCES}"),
        "batch_age_h":     (age_h >= MIN_AGE_HOURS,            f"{age_h:.1f}h/{MIN_AGE_HOURS}h"),
        "cooldown_h":      (cool_h >= COOLDOWN_HOURS or st.get("released_batches", 0) == 0,
                            f"{cool_h:.1f}h/{COOLDOWN_HOURS}h"),
    }
    ready = all(ok for ok, _ in checks.values())
    blockers = [k for k, (ok, _) in checks.items() if not ok]
    return ready, {"ready": ready, "checks": {k: {"pass": ok, "value": v} for k, (ok, v) in checks.items()},
                   "blockers": blockers, "pending_total": len(s), "reviewed": len(reviewed),
                   "attack": n_atk, "benign": n_ben, "shapes": shapes, "sources": sources}


def release() -> Optional[Dict]:
    """If ready, archive the batch and return it for training. Otherwise return None."""
    ready, info = readiness()
    if not ready:
        return None
    samples = [x for x in pending() if x.get("reviewed") and x.get("label") in (0, 1)]
    bid = time.strftime("batch_%Y%m%d_%H%M%S")
    (BATCHES / f"{bid}.jsonl").write_text("\n".join(json.dumps(x) for x in samples))
    PENDING.write_text("")
    st = _state()
    st["last_release"] = time.time()
    st["batch_opened"] = time.time()
    st["released_batches"] = st.get("released_batches", 0) + 1
    _save_state(st)
    return {"batch_id": bid, "samples": samples, "n": len(samples), "info": info}


def summary() -> str:
    ready, info = readiness()
    lines = [f"zero-day store: {info['pending_total']} pending ({info['reviewed']} reviewed: "
             f"{info['attack']} attack / {info['benign']} benign, {info['shapes']} shapes, "
             f"{info['sources']} sources)"]
    lines.append(f"  RETRAIN {'RELEASED' if ready else 'HELD'}"
                 + ("" if ready else f" — waiting on: {', '.join(info['blockers'])}"))
    for k, v in info["checks"].items():
        lines.append(f"    [{'ok ' if v['pass'] else 'no '}] {k:<17} {v['value']}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(summary())
