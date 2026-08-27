"""
Real-data training + evaluation on CSIC-2010 (the Q1-credible numbers).

Why this exists: the synthetic-trained detector scored 0.98 recall on its own test
set but only 8.7% on real CSIC attacks, and the span detector false-positived on 100%
of real benign. Synthetic evaluation is a fantasy. This trains and evaluates on REAL
labeled HTTP traffic and reports honest numbers.

Binary detector (benign vs attack) on the canonical feature contract, trained and
tested on disjoint CSIC splits, plus a Mahalanobis open-set (zero-day) score and an
adaptive-attacker robustness measurement on real attack payloads.
"""
from __future__ import annotations
import os, sys, json, time, random
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import lexical_features, LEXICAL_FEATURE_NAMES
from ml.detector_v2 import serving_contract_hash  # single source of the train/serve contract hash
from data_pipeline.csic_loader import load
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
import xgboost as xgb
import joblib

random.seed(42); np.random.seed(42)
OUT = Path(__file__).resolve().parent.parent / "models_v2"; OUT.mkdir(exist_ok=True)


def feats(recs):
    return np.array([lexical_features(m, p, q, b, {}) for m, p, q, b in recs], np.float32)


def main():
    t0 = time.time()
    # REAL data: train benign from normal_train, attacks from anomalous.
    # Hold out normal_test entirely (never seen) for the honest benign FP.
    benign_tr = load("normal_train")
    benign_ind = load("normal_test")          # independent benign, never trained
    attacks = load("anomalous")
    random.shuffle(attacks)
    a_split = int(0.8 * len(attacks))
    atk_tr, atk_te = attacks[:a_split], attacks[a_split:]
    random.shuffle(benign_tr)
    b_split = int(0.8 * len(benign_tr))
    ben_tr, ben_te = benign_tr[:b_split], benign_tr[b_split:]

    # Modern benign: teach the model that JSON APIs / SPAs / JWTs / markdown / base64 uploads are
    # benign, so it stops false-positiving on out-of-distribution modern traffic (the reason ML
    # enforcement blocked 100% of modern benign). Randomized values, DISTINCT from the frozen
    # harness eval corpus, so the held-out harness still tests generalization, not memorization.
    # Default OFF (0): an experiment adding 4000 SYNTHETIC modern-benign samples barely moved the
    # false-positive rate and made adaptive evasion ~3x easier (ASR 25%->75%) — a net loss. The
    # right input here is REAL production benign traffic, not synthetic; point MODERN_BENIGN_N at
    # a generator seeded from your access logs once you have them. See DEPLOYMENT_READINESS.md.
    # The CSIC-only model treats ALL modern traffic (benign AND attack) as out-of-distribution.
    # Adding modern benign alone made evasion easier; the fix is to teach BOTH classes in the
    # modern manifold. Randomized + DISTINCT from the frozen harness eval corpus (held-out).
    from data_pipeline.modern_benign import generate as _gen_modern
    from data_pipeline.modern_attacks import generate as _gen_matk
    _mb_n = int(os.environ.get("MODERN_BENIGN_N", "0"))
    _ma_n = int(os.environ.get("MODERN_ATTACK_N", "0"))
    modern = _gen_modern(_mb_n) if _mb_n > 0 else []
    matk = _gen_matk(_ma_n) if _ma_n > 0 else []

    _ben_parts = [feats(ben_tr)] + ([feats(modern)] if modern else [])
    _atk_parts = [feats(atk_tr)] + ([feats(matk)] if matk else [])
    Xtr = np.vstack(_ben_parts + _atk_parts)
    ytr = np.r_[np.zeros(len(ben_tr) + len(modern)), np.ones(len(atk_tr) + len(matk))].astype(int)
    Xte = np.vstack([feats(ben_te), feats(atk_te)])
    yte = np.r_[np.zeros(len(ben_te)), np.ones(len(atk_te))].astype(int)
    print(f"[data] REAL CSIC-2010 + {len(modern)} modern benign: train={len(ytr)} "
          f"(benign {len(ben_tr)}+{len(modern)}, attack {len(atk_tr)}), test={len(yte)}")

    scaler = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)
    clf = xgb.XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.07,
                            subsample=0.85, colsample_bytree=0.85, reg_lambda=1.0,
                            n_jobs=4, eval_metric="logloss", tree_method="hist")
    clf.fit(Xtr_s, ytr)

    proba = clf.predict_proba(Xte_s)[:, 1]
    pred = (proba >= 0.5).astype(int)
    prec = precision_score(yte, pred); rec = recall_score(yte, pred)
    f1 = f1_score(yte, pred); auc = roc_auc_score(yte, proba)

    # honest independent benign FP (normal_test, never trained)
    Xind = scaler.transform(feats(benign_ind[:8000]))
    ind_fp = float(np.mean(clf.predict_proba(Xind)[:, 1] >= 0.5))

    # Mahalanobis open-set (zero-day) scorer on benign
    Xb = Xtr_s[ytr == 0]
    mu = Xb.mean(0); cov = np.cov(Xb, rowvar=False) + 1e-3 * np.eye(Xb.shape[1])
    prec_m = np.linalg.inv(cov).astype(np.float32); mu = mu.astype(np.float32)
    def maha(X):
        d = X.astype(np.float32) - mu
        return np.sqrt(np.einsum("ij,jk,ik->i", d, prec_m, d).clip(min=0))
    nov_t = float(np.quantile(maha(Xind), 0.99))

    # adaptive attacker on REAL attack payloads
    from ml.adaptive_attacker import attack_success_rate, HELDOUT_OPS
    def score_fn(pl):
        x = scaler.transform(lexical_features("GET", "/x", pl, "", {}).reshape(1, -1)).astype(np.float32)
        return float(clf.predict_proba(x)[0, 1])
    real_atk_strings = [(q or b) for (m, p, q, b) in atk_te if (q or b) and len(q or b) >= 4][:60]
    asr, q_avg, _ = attack_success_rate(real_atk_strings, score_fn, block_threshold=0.5, budget=40, ops=HELDOUT_OPS)

    clf.save_model(str(OUT / "csic_classifier.json"))
    joblib.dump(scaler, OUT / "csic_scaler.joblib")
    np.savez(OUT / "csic_maha.npz", mu=mu, prec=prec_m, nov_t=nov_t)
    meta = {
        "dataset": "CSIC-2010 (real HTTP traffic)", "trained": time.strftime("%Y-%m-%d %H:%M:%S"),
        "n_train": int(len(ytr)), "n_test": int(len(yte)),
        "real_test": {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                      "roc_auc": round(auc, 4)},
        "independent_benign_fp": round(ind_fp, 4),
        "adaptive_attacker_ASR_on_real": round(asr, 3), "attacker_avg_queries": round(q_avg, 1),
        "novelty_threshold": nov_t, "train_seconds": round(time.time() - t0, 1),
        # Train/serve skew guard: persist the SAME feature-contract hash the detector
        # computes at serving. Without this the guard stays unsatisfied and the model can
        # only shadow-log (MLResult.enforce=False on every verdict).
        "contract_hash": serving_contract_hash(),
        "malicious_threshold": 0.5,
        "modern_benign_n": int(len(modern)),
    }
    (OUT / "csic_meta.json").write_text(json.dumps(meta, indent=2, default=float))

    print("\n=== REAL-DATA RESULTS (CSIC-2010, honest) ===")
    print(f"  held-out test: precision={prec:.3f}  recall={rec:.3f}  F1={f1:.3f}  ROC-AUC={auc:.3f}")
    print(f"  INDEPENDENT benign FP (normal_test, never trained): {ind_fp*100:.2f}%")
    print(f"  adaptive attacker ASR on REAL attacks: {asr*100:.1f}%  (avg {q_avg:.0f} queries)")
    print(f"  ({meta['train_seconds']}s)  wrote models_v2/csic_*")


if __name__ == "__main__":
    main()
