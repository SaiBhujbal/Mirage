"""
Cross-dataset generalisation — the Q1 experiment.

The whole project's recurring finding is that WAF-ML is dominated by benign-distribution
match. This tests it rigorously across TWO real datasets (CSIC-2010, ECML/PKDD-2007):
train on one, test on the other. If a model trained on dataset A collapses on dataset B's
benign (high FP) or attacks (low recall), the generalisation claim any WAF-ML paper implies
is false — and that is the honest, publishable result.

Reports a 2x2 train/test matrix of benign-FP and attack-recall, plus a pooled model.
All on the shared canonical feature contract; per-source StandardScaler refit per training set.
"""
from __future__ import annotations
import os, sys, json, time, random
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import lexical_features
from data_pipeline.csic_loader import load as csic_load
from data_pipeline.pkdd_loader import load as pkdd_load
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

random.seed(42); np.random.seed(42)
OUT = Path(__file__).resolve().parent.parent / "models_v2"


def feats(recs):
    return np.array([lexical_features(m, p, q, b, {}) for (m, p, q, b) in recs], np.float32)


def csic_dataset(n_benign=12000, n_attack=12000):
    ben = [(m, p, q, b) for (m, p, q, b) in csic_load("normal_train")]
    atk = [(m, p, q, b) for (m, p, q, b) in csic_load("anomalous")]
    random.shuffle(ben); random.shuffle(atk)
    return ben[:n_benign], atk[:n_attack]


def pkdd_dataset(n_benign=10000, n_attack=12000):
    recs = pkdd_load("test")
    ben = [(m, p, q, b) for (m, p, q, b, lab) in recs if lab.lower() == "valid"]
    atk = [(m, p, q, b) for (m, p, q, b, lab) in recs if lab.lower() != "valid"]
    random.shuffle(ben); random.shuffle(atk)
    return ben[:n_benign], atk[:n_attack]


def split(ben, atk, frac=0.7):
    bi, ai = int(len(ben) * frac), int(len(atk) * frac)
    return (ben[:bi], atk[:ai]), (ben[bi:], atk[ai:])


def train_model(ben, atk):
    X = np.vstack([feats(ben), feats(atk)])
    y = np.r_[np.zeros(len(ben)), np.ones(len(atk))].astype(int)
    sc = StandardScaler().fit(X)
    clf = xgb.XGBClassifier(n_estimators=350, max_depth=7, learning_rate=0.08,
                            subsample=0.85, colsample_bytree=0.85, reg_lambda=1.0,
                            n_jobs=4, eval_metric="logloss", tree_method="hist")
    clf.fit(sc.transform(X), y)
    return sc, clf


def evaluate(model, ben, atk):
    sc, clf = model
    fp = float(np.mean(clf.predict_proba(sc.transform(feats(ben)))[:, 1] >= 0.5)) if ben else 0.0
    rec = float(np.mean(clf.predict_proba(sc.transform(feats(atk)))[:, 1] >= 0.5)) if atk else 0.0
    return fp, rec


def main():
    t0 = time.time()
    print("[data] loading CSIC-2010 and PKDD-2007 (real)...")
    c_ben, c_atk = csic_dataset(); p_ben, p_atk = pkdd_dataset()
    (c_ben_tr, c_atk_tr), (c_ben_te, c_atk_te) = split(c_ben, c_atk)
    (p_ben_tr, p_atk_tr), (p_ben_te, p_atk_te) = split(p_ben, p_atk)
    print(f"[data] CSIC benign {len(c_ben)} attack {len(c_atk)} | PKDD benign {len(p_ben)} attack {len(p_atk)}")

    print("[train] CSIC model, PKDD model, POOLED model...")
    m_csic = train_model(c_ben_tr, c_atk_tr)
    m_pkdd = train_model(p_ben_tr, p_atk_tr)
    m_pool = train_model(c_ben_tr + p_ben_tr, c_atk_tr + p_atk_tr)

    tests = {"CSIC": (c_ben_te, c_atk_te), "PKDD": (p_ben_te, p_atk_te)}
    rows = {}
    for mname, model in [("trained_CSIC", m_csic), ("trained_PKDD", m_pkdd), ("trained_POOLED", m_pool)]:
        rows[mname] = {}
        for tname, (tb, ta) in tests.items():
            fp, rec = evaluate(model, tb, ta)
            rows[mname][tname] = {"benign_fp": round(fp, 4), "attack_recall": round(rec, 4)}

    res = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
           "datasets": {"CSIC": {"benign": len(c_ben), "attack": len(c_atk)},
                        "PKDD": {"benign": len(p_ben), "attack": len(p_atk)}},
           "matrix": rows, "train_seconds": round(time.time() - t0, 1)}
    (OUT / "cross_dataset.json").write_text(json.dumps(res, indent=2))

    print("\n=== CROSS-DATASET GENERALISATION (real CSIC-2010 x PKDD-2007) ===")
    print(f"{'':<16}{'test CSIC (FP/rec)':>22}{'test PKDD (FP/rec)':>22}")
    for mname in rows:
        c = rows[mname]["CSIC"]; p = rows[mname]["PKDD"]
        print(f"{mname:<16}{c['benign_fp']*100:>7.1f}% /{c['attack_recall']*100:>6.1f}%"
              f"{p['benign_fp']*100:>12.1f}% /{p['attack_recall']*100:>6.1f}%")
    # honest verdict
    xrec = rows["trained_CSIC"]["PKDD"]["attack_recall"]
    xfp = rows["trained_CSIC"]["PKDD"]["benign_fp"]
    print(f"\nCSIC-trained on PKDD: recall {xrec*100:.0f}%, benign FP {xfp*100:.0f}%")
    print("If cross-dataset recall/FP is much worse than in-domain -> generalisation fails")
    print("(benign-distribution-match finding confirmed on a 2nd real dataset). Pooled row")
    print("shows whether simply training on both recovers performance.")
    print(f"({res['train_seconds']}s)  wrote models_v2/cross_dataset.json")


if __name__ == "__main__":
    main()
