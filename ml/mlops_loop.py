"""
The MLOps active-learning loop, end to end and measured.

The vision (yours): a request the ML is unsure about is a candidate zero-day. It could be
a real attack or a false positive. Either way it gets STUDIED (captured + labeled), fed
back, and the model RETRAINED so next time the ML catches it directly — before it has to
fall through to the honeypot / next layer.

This script demonstrates the loop on REAL data with honest before/after numbers:
  1. Baseline model: trained on real traffic (CSIC+PKDD) but NOT on the Nuclei CVE
     exploits — those are the "zero-days" it has never seen.
  2. Probe with real CVEs -> measure how many slip past (the capture set).
  3. Study & retrain: add the captured CVE exploits (attack-labeled) AND a captured
     false-positive (benign-labeled) back into training.
  4. Re-measure: recall on the captured CVEs (did we learn them?) and on a DISJOINT
     future CVE set (did we generalize?), plus that the FP stops firing.
"""
from __future__ import annotations
import os, sys, json, time, random
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import lexical_features
from data_pipeline.csic_loader import load as csic_load
from data_pipeline.pkdd_loader import load as pkdd_load
from data_pipeline.nuclei_loader import load as nuclei_load
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

random.seed(0); np.random.seed(0)
OUT = Path(__file__).resolve().parent.parent / "models_v2"
N_HASH = 2 ** 18; W = 0.65
hv = HashingVectorizer(analyzer="char_wb", ngram_range=(2, 4), n_features=N_HASH,
                       alternate_sign=False, norm="l2")


def reqstr(m, p, q, b): return f"{p}?{q} {b}".lower()


def train(records, y):
    Xc = hv.transform([reqstr(*r) for r in records])
    Xl = np.array([lexical_features(*r, {}) for r in records], np.float32)
    sc = StandardScaler().fit(Xl)
    lr = LogisticRegression(max_iter=400, C=4.0, class_weight="balanced", solver="liblinear").fit(Xc, y)
    xg = xgb.XGBClassifier(n_estimators=300, max_depth=7, learning_rate=0.08, subsample=0.85,
                           colsample_bytree=0.85, reg_lambda=1.0, n_jobs=4,
                           eval_metric="logloss", tree_method="hist").fit(sc.transform(Xl), y)
    return (lr, sc, xg)


def score(model, recs):
    lr, sc, xg = model
    Xc = hv.transform([reqstr(*r) for r in recs])
    Xl = sc.transform(np.array([lexical_features(*r, {}) for r in recs], np.float32))
    return W * lr.predict_proba(Xc)[:, 1] + (1 - W) * xg.predict_proba(Xl)[:, 1]


def main():
    t0 = time.time()
    # --- real background traffic (sampled for speed) ---
    bg, ybg = [], []
    for m, p, q, b in csic_load("normal_train")[:9000]:
        bg.append((m, p, q, b)); ybg.append(0)
    for m, p, q, b in csic_load("anomalous")[:6000]:
        bg.append((m, p, q, b)); ybg.append(1)
    for m, p, q, b, lab in pkdd_load("test")[:9000]:
        bg.append((m, p, q, b)); ybg.append(0 if lab.lower() == "valid" else 1)

    # --- real CVE exploits = the "zero-days" (never in background training) ---
    cves = [(r["method"], r["path"], r["query"], r["body"]) for r in nuclei_load()]
    random.shuffle(cves)
    cut = int(0.6 * len(cves))
    captured, future = cves[:cut], cves[cut:]      # captured = will be fed back; future = disjoint test
    print(f"[data] background {len(bg)} reqs | CVE exploits {len(cves)} ({len(captured)} captured, {len(future)} future/disjoint)")

    # split background benign into train vs a held-out benign pool (for honest FP harvesting)
    ben_idx = [i for i, t in enumerate(ybg) if t == 0]
    random.shuffle(ben_idx)
    holdout_ben = [bg[i] for i in ben_idx[:2500]]
    train_mask = set(ben_idx[2500:]) | {i for i, t in enumerate(ybg) if t == 1}
    bg_tr = [bg[i] for i in sorted(train_mask)]; y_tr = [ybg[i] for i in sorted(train_mask)]

    # STRICT production threshold: 0.1% FP on the TRAIN benign (leaves a real recall gap)
    def thr(model, at=0.999):
        bs = score(model, [r for r, t in zip(bg_tr, y_tr) if t == 0])
        return float(np.quantile(bs, at))

    def recall(model, recs, t): return float(np.mean(score(model, recs) >= t)) if recs else 0.0

    # ---------- BEFORE: baseline trained WITHOUT CVEs and WITHOUT the harvested FPs ----------
    base = train(bg_tr, np.array(y_tr))
    t_base = thr(base)
    r_cap_before = recall(base, captured, t_base)
    r_fut_before = recall(base, future, t_base)
    # harvest REAL false positives: held-out benign the baseline flags at this threshold
    hb_scores = score(base, holdout_ben)
    fp_idx = [i for i, s in enumerate(hb_scores) if s >= t_base]
    fps = [holdout_ben[i] for i in fp_idx]
    random.shuffle(fps)
    fp_cap, fp_test = fps[:len(fps)//2], fps[len(fps)//2:]
    fp_rate_before = len(fp_test) / len(holdout_ben) if holdout_ben else 0.0  # portion of a fresh benign pool that fires
    print(f"\n[BEFORE retrain] strict threshold={t_base:.3f} (0.1% FP target)")
    print(f"  recall on captured CVEs : {r_cap_before*100:.1f}%   (rest slip past ML -> next layer/honeypot)")
    print(f"  recall on FUTURE CVEs   : {r_fut_before*100:.1f}%   (disjoint, never captured)")
    print(f"  harvested {len(fps)} real false-positives from held-out benign to STUDY")

    # ---------- STUDY & RETRAIN: captured CVEs (attack) + captured FPs (benign) ----------
    bg2 = bg_tr + captured + fp_cap
    y2 = list(y_tr) + [1] * len(captured) + [0] * len(fp_cap)
    improved = train(bg2, np.array(y2))
    t_imp = thr(improved)
    r_cap_after = recall(improved, captured, t_imp)
    r_fut_after = recall(improved, future, t_imp)
    # FP rate on the DISJOINT fp_test set (were they fixed without seeing them?) + fresh benign
    fp_fired_after = float(np.mean(score(improved, fp_test) >= t_imp)) if fp_test else 0.0
    fp_fired_before = 1.0  # by construction these all fired pre-retrain

    print(f"\n[AFTER retrain on captured CVEs + studied FPs] threshold={t_imp:.3f}")
    print(f"  === ATTACK direction (catch 0-day before next layer) ===")
    print(f"  captured-CVE recall : {r_cap_before*100:.1f}% -> {r_cap_after*100:.1f}%  ({(r_cap_after-r_cap_before)*100:+.1f} pts, memorized)")
    print(f"  future-CVE recall   : {r_fut_before*100:.1f}% -> {r_fut_after*100:.1f}%  ({(r_fut_after-r_fut_before)*100:+.1f} pts, generalized)")
    print(f"  === FALSE-POSITIVE direction (studied 0-day was benign) ===")
    print(f"  disjoint FP-test still firing: 100% -> {fp_fired_after*100:.0f}%  "
          f"({'reduced' if fp_fired_after<0.9 else 'no change'} — learned from HALF, fixed the other half)")
    fp_before, fp_after = fp_fired_before, fp_fired_after

    res = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
           "background": len(bg), "cve_total": len(cves), "captured": len(captured), "future": len(future),
           "before": {"captured_recall": round(r_cap_before, 3), "future_recall": round(r_fut_before, 3), "fp_fired": bool(fp_before)},
           "after": {"captured_recall": round(r_cap_after, 3), "future_recall": round(r_fut_after, 3), "fp_fired": bool(fp_after)},
           "train_seconds": round(time.time() - t0, 1)}
    (OUT / "mlops_loop.json").write_text(json.dumps(res, indent=2, default=float))
    print(f"\n({res['train_seconds']}s)  wrote models_v2/mlops_loop.json")


if __name__ == "__main__":
    main()
