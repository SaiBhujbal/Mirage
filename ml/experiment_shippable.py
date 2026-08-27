"""
Shippable configuration search: combine the v3 ensemble with per-parameter-value
max-aggregation (dilution-proof) and calibrate on REAL benign, to find a config that is
low-FP AND low-ASR AND high-recall at once — or prove that tradeoff honestly.

Scoring modes compared on pooled real CSIC+PKDD:
  whole   : ensemble on the whole request (dilution-vulnerable, from train_v3)
  perval  : ensemble on each param-value / body, take MAX (dilution-proof: adding benign
            fields cannot lower the max malicious field). Threshold calibrated on real
            benign field-values.

Reports FP, recall, and adaptive-attacker ASR for each, and the recommended shipped config.
"""
from __future__ import annotations
import os, sys, json, time, random
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import lexical_features
from data_pipeline.csic_loader import load as csic_load
from data_pipeline.pkdd_loader import load as pkdd_load
from sklearn.feature_extraction.text import HashingVectorizer
import joblib, xgboost as xgb

random.seed(7); np.random.seed(7)
M = Path(__file__).resolve().parent.parent / "models_v2"
N_HASH = 2 ** 18
W = 0.65

hv = HashingVectorizer(analyzer="char_wb", ngram_range=(2, 4), n_features=N_HASH,
                       alternate_sign=False, norm="l2")
lr = joblib.load(M / "v3_charlr.joblib")
scaler = joblib.load(M / "v3_scaler.joblib")
xgbm = xgb.XGBClassifier(); xgbm.load_model(str(M / "v3_lexxgb.json"))


def ens_score_str(s):
    xc = hv.transform([s.lower()])
    xl = scaler.transform(lexical_features("GET", "/x", s, "", {}).reshape(1, -1)).astype(np.float32)
    return float(W * lr.predict_proba(xc)[0, 1] + (1 - W) * xgbm.predict_proba(xl)[0, 1])


def fields(m, p, q, b):
    out = []
    for kv in (q or "").split("&"):
        if "=" in kv:
            out.append(kv.split("=", 1)[1])
        elif kv:
            out.append(kv)
    if b:
        out.append(b)
    for seg in (p or "").split("/"):
        if len(seg) >= 4:
            out.append(seg)
    return out or [q or b or p]


def perval_score(m, p, q, b):
    return max((ens_score_str(f) for f in fields(m, p, q, b)), default=0.0)


def whole_score(m, p, q, b):
    return ens_score_str(f"{p}?{q} {b}")


def main():
    t0 = time.time()
    recs, y = [], []
    for m, p, q, b in csic_load("normal_train"):
        recs.append((m, p, q, b)); y.append(0)
    for m, p, q, b in csic_load("anomalous"):
        recs.append((m, p, q, b)); y.append(1)
    for m, p, q, b, lab in pkdd_load("test"):
        recs.append((m, p, q, b)); y.append(0 if lab.lower() == "valid" else 1)
    y = np.array(y)
    idx = np.random.permutation(len(y))[:16000]     # sample for speed (perval is ~8x calls)
    recs = [recs[i] for i in idx]; y = y[idx]
    ben = [r for r, t in zip(recs, y) if t == 0]
    atk = [r for r, t in zip(recs, y) if t == 1]
    print(f"[data] sample: {len(ben)} benign, {len(atk)} attack")

    results = {}
    from ml.adaptive_attacker import attack_success_rate, HELDOUT_OPS
    for name, fn in [("whole", whole_score), ("perval", perval_score)]:
        bs = np.array([fn(*r) for r in ben])
        as_ = np.array([fn(*r) for r in atk])
        # threshold for 0.5% FP calibrated on real benign
        t = float(np.quantile(bs, 0.995))
        rec = float(np.mean(as_ >= t)); fp = float(np.mean(bs >= t))
        # adaptive attacker at this threshold
        atk_strings = [(q or b) for (m, p, q, b) in atk if (q or b)][:40]
        def sfn(payload, _fn=fn):
            return _fn("GET", "/x", payload, "")
        asr, _, _ = attack_success_rate(atk_strings, sfn, block_threshold=t, budget=35, ops=HELDOUT_OPS)
        results[name] = {"threshold": round(t, 4), "benign_fp": round(fp, 4),
                         "recall": round(rec, 4), "adaptive_ASR": round(asr, 3)}
        print(f"  {name:<8} FP={fp*100:5.2f}%  recall={rec*100:5.1f}%  adaptive_ASR={asr*100:5.1f}%  (thr {t:.3f})")

    (M / "shippable_experiment.json").write_text(json.dumps(results, indent=2, default=float))
    better = "perval" if results["perval"]["adaptive_ASR"] < results["whole"]["adaptive_ASR"] else "whole"
    print(f"\n  recommended shipped scoring: {better}")
    print(f"  (perval trades some FP for dilution-robustness; whole is faster)")
    print(f"  ({round(time.time()-t0,1)}s)  wrote models_v2/shippable_experiment.json")


if __name__ == "__main__":
    main()
