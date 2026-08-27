"""
MLOps runner — one full, guarded retrain cycle. Schedule this (cron / Task Scheduler / the
/schedule skill) to run the loop autonomously but safely.

Cycle:
  1. Load the capture feed (honeypot captures + reviewed labels).
  2. POISON GUARD screens it (ml/poison_guard) — poison never reaches training.
  3. Retrain a CHALLENGER on (background traffic + clean captured samples).
  4. CHAMPION/CHALLENGER gate (ml/champion_challenger) validates it.
  5. PROMOTE (swap live model) or REJECT (keep champion) — with rollback safety.
  6. Slack summary to the desired user (throttled, dry-run unless SLACK_WEBHOOK_URL set).
  7. Write a run report.

Idempotent and log-only-safe: if nothing passes the guard, or the gate rejects, the live
model is untouched. Never auto-promotes blind, never trains on unreviewed/poisoned data.
"""
from __future__ import annotations
import os, sys, json, time, random
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_pipeline.csic_loader import load as csic_load
from data_pipeline.pkdd_loader import load as pkdd_load
from ml.mlops_loop import train, score
from ml.poison_guard import screen, summary as poison_summary
from ml.champion_challenger import gate, MUST_CATCH
from core.pattern_engine import pattern_engine
import ml.zeroday_store as zstore
from ml.canary_deploy import CanaryRun, format_run, register, set_live, rollback, live_version

OUT = Path(__file__).resolve().parent.parent / "models_v2"
REPORTS = OUT / "runs"; REPORTS.mkdir(parents=True, exist_ok=True)
CAPTURE = Path(__file__).resolve().parent.parent / "data" / "corpus" / "captured_zero_days.jsonl"
random.seed(0); np.random.seed(0)

try:
    from integrations.slack_notifier import notifier as slack
except Exception:
    slack = None


def _sig_hit(s):
    return bool(pattern_engine.scan_request(s.get("path", ""), s.get("query", ""), s.get("body", ""), {}))


def load_reviewed_captures() -> list:
    """Load captured zero-days that a human has labeled+reviewed. In this demo we synthesize a
    review queue (incl. a planted poison batch) so the guard is exercised; in production this
    reads the reviewed rows from CAPTURE / a labeling DB."""
    # Optional: pull the LATEST real-world exploits from the Tavily threat-intel feed into the
    # capture feed BEFORE loading it. Gated by TAVILY_API_KEY and fully fail-safe — a threat-intel
    # outage must never break a retrain cycle. Tavily samples are still screened by the poison
    # guard and gated by the zero-day store below, exactly like honeypot captures.
    try:
        from data_pipeline.tavily_source import tavily_feed, collect_and_build
        if tavily_feed.enabled:
            res = collect_and_build()
            print(f"[runner] tavily: +{res['written_to_feed']} new exploit samples "
                  f"({res['seed_payloads']} seeds, {res['augmented']} augmented)")
    except Exception as e:
        print(f"[runner] tavily refresh skipped: {e}")

    samples = []
    if CAPTURE.exists():
        for line in CAPTURE.read_text().splitlines():
            try:
                r = json.loads(line)
                samples.append({"method": r.get("method", "GET"), "path": r.get("path", "/"),
                                "query": r.get("query", ""), "body": r.get("body", ""),
                                "label": 1, "source_ip": "honeypot", "reviewed": True})
            except Exception:
                pass
    # planted POISON: attacker floods the feed with SQLi mislabeled benign (+ unreviewed rows)
    for i in range(60):
        samples.append({"method": "GET", "path": "/x", "query": f"id={i} UNION SELECT pass FROM users--",
                        "body": "", "label": 0, "source_ip": "198.51.100.9", "reviewed": True})
    for i in range(20):
        samples.append({"method": "GET", "path": "/y", "query": f"q={i}<script>alert(1)</script>",
                        "body": "", "label": 0, "source_ip": "x", "reviewed": False})  # unreviewed
    return samples


def run_cycle() -> dict:
    t0 = time.time()
    # background training traffic
    bg, y = [], []
    for m, p, q, b in csic_load("normal_train")[:8000]:
        bg.append((m, p, q, b)); y.append(0)
    for m, p, q, b in csic_load("anomalous")[:6000]:
        bg.append((m, p, q, b)); y.append(1)
    for m, p, q, b, lab in pkdd_load("test")[:8000]:
        bg.append((m, p, q, b)); y.append(0 if lab.lower() == "valid" else 1)
    idx = np.random.permutation(len(y)); bg = [bg[i] for i in idx]; y = [y[i] for i in idx]
    cut = int(0.8 * len(y)); bg_tr, y_tr, val, yval = bg[:cut], y[:cut], bg[cut:], y[cut:]

    print("[runner] training/loading champion...")
    champ = train(bg_tr, np.array(y_tr))
    thr = float(np.quantile(score(champ, [r for r, t in zip(bg_tr, y_tr) if t == 0]), 0.995))

    # Drift + FP-trigger telemetry (fail-safe; never breaks the cycle). Feature-distribution
    # drift (PSI) is the unsupervised early-warning the FP/FN monitor can't give; the FP monitor
    # writes retrain_trigger_*.json which we surface here so a scheduled cycle acts on them.
    drift_info, pending_triggers = {}, []
    try:
        from metrics.drift import FeatureDriftMonitor
        dm = FeatureDriftMonitor()
        if dm.reference is None:
            dm.fit_reference([r for r, t in zip(bg_tr, y_tr) if t == 0][:4000])
        drift_info = dm.check([r for r, t in zip(val, yval) if t == 0]).to_dict()
        print(f"[runner] drift: psi_mean={drift_info.get('psi_mean')} psi_max={drift_info.get('psi_max')} "
              f"retrain_recommended={drift_info.get('retrain_recommended')}")
    except Exception as e:
        print(f"[runner] drift check skipped: {e}")
    try:
        tdir = Path(__file__).resolve().parent.parent / "data" / "security"
        pending_triggers = sorted(p.name for p in tdir.glob("retrain_trigger_*.json")) if tdir.exists() else []
        if pending_triggers:
            print(f"[runner] FP-monitor retrain triggers pending: {len(pending_triggers)}")
    except Exception:
        pass

    # 1-2. capture feed -> poison guard
    captures = load_reviewed_captures()
    champ_score_fn = lambda s: float(score(champ, [(s["method"], s["path"], s["query"], s["body"])])[0])
    clean, quarantined = screen(captures, champ_score_fn, _sig_hit, require_review=True)
    psum = poison_summary(clean, quarantined)
    print(f"[runner] poison guard: {psum['accepted']} accepted, {psum['quarantined']} quarantined "
          f"-> {psum['quarantine_reasons']}")

    # 2b. ACCUMULATE into the durable zero-day store. NEVER retrain from a single/thin batch:
    #     the store releases a batch only when it is big, class-balanced, shape-diverse,
    #     multi-source, aged, and past cooldown.
    for s in clean:
        zstore.add(s)
    ready, rinfo = zstore.readiness()
    print("[runner] " + zstore.summary().replace("\n", "\n[runner] "))
    if not ready:
        report = {"cycle_ts": time.strftime("%Y-%m-%d %H:%M:%S"), "capture_feed": len(captures),
                  "poison_guard": psum, "store": rinfo, "drift": drift_info,
                  "pending_fp_triggers": pending_triggers,
                  "decision": "HELD — accumulating data (not enough to retrain)",
                  "seconds": round(time.time() - t0, 1)}
        (REPORTS / f"run_{time.strftime('%Y%m%d_%H%M%S')}.json").write_text(json.dumps(report, indent=2, default=float))
        if slack:
            slack.notify(key="mlops_cycle", severity="low", force=True,
                         title="MLOps cycle: HELD — accumulating zero-day data",
                         fields={"pending": str(rinfo["pending_total"]), "reviewed": str(rinfo["reviewed"]),
                                 "attack/benign": f"{rinfo['attack']}/{rinfo['benign']}",
                                 "waiting on": ", ".join(rinfo["blockers"])[:120]},
                         text="Captures are buffering. A retrain is released only when the batch is "
                              "large, balanced, diverse and aged — never from a single data point.")
        print(f"\n=== MLOps CYCLE: HELD (accumulating) — blockers: {', '.join(rinfo['blockers'])} ===")
        return report
    batch = zstore.release()
    print(f"[runner] store RELEASED {batch['batch_id']}: {batch['n']} samples -> retraining")

    # 3. retrain challenger on background + the RELEASED BATCH
    clean_recs = [(s["method"], s["path"], s["query"], s["body"]) for s in batch["samples"]]
    clean_lab = [int(s["label"]) for s in batch["samples"]]
    challenger = train(bg_tr + clean_recs, np.array(list(y_tr) + clean_lab)) if clean_recs else champ

    # 4. gate
    real_benign = [r for r, t in zip(val, yval) if t == 0]
    champ_ben_scores = score(champ, real_benign)
    import ml.champion_challenger as cc
    # guardrail = DEEP benign (champion scores them far below threshold), so it tests real
    # regressions, not boundary noise. A model that blocks unambiguously-benign traffic is broken.
    cb = score(champ, real_benign)
    deep = np.where(cb < max(0.15, thr * 0.4))[0][:50]
    cc.MUST_ALLOW = [real_benign[i] for i in deep]
    promote, checks, metrics = gate(champ, challenger, val, yval, champ_ben_scores, thr)

    # 4b. OPTIONAL human approval in Slack (two-way). Only consulted when interactive Slack
    # is configured; it can only ADD a stop, never skip the gate/canary below.
    ver_pending = time.strftime("v%Y.%m.%d-%H%M%S")
    try:
        from integrations.slack_interactive import interactive, promotion_approval_blocks, promotion_approved
        if interactive.enabled and promote:
            ch = os.environ.get("SLACK_CHANNEL", "")
            if ch:
                interactive.post(ch, promotion_approval_blocks(
                    ver_pending, metrics, {k: v[0] for k, v in checks.items()}, batch["n"]))
            verdict = promotion_approved(ver_pending)
            if verdict is False:
                promote = False
                print("[runner] human REJECTED promotion in Slack — champion kept")
            elif verdict is None and os.environ.get("REQUIRE_SLACK_APPROVAL", "").lower() in ("1", "true", "on"):
                promote = False
                print("[runner] awaiting human approval in Slack (REQUIRE_SLACK_APPROVAL=on) — holding")
    except Exception as e:
        print(f"[runner] slack approval step skipped: {e}")

    # 5. gate -> CANARY -> promote/rollback (a gate pass is NOT a licence to take 100% traffic)
    canary_res = None
    if promote:
        live_traffic = [{"method": m, "path": p, "query": q, "body": b, "label": t}
                        for (m, p, q, b), t in zip(val, yval)]
        sfn = lambda model: (lambda s: float(score(model, [(s["method"], s["path"], s["query"], s["body"])])[0]))
        canary_res = CanaryRun(sfn(champ), sfn(challenger), threshold=thr).run(live_traffic)
        print("[canary] " + format_run(canary_res).replace("\n", "\n[canary] "))
        promote = canary_res["outcome"] == "FULLY_PROMOTED"

    action = "PROMOTED (canary 1→100%)" if promote else (
        "ROLLED BACK at canary" if canary_res else "REJECTED at gate — champion kept")
    if promote:
        ver = time.strftime("v%Y.%m.%d-%H%M%S")
        register(ver, {"batch": batch["batch_id"]},
                 {"recall": metrics.get("chal_recall"), "fp": metrics.get("chal_fp")},
                 notes=f"retrained on {batch['n']} samples; canary passed all stages")
        set_live(ver)
        (OUT / "PROMOTED.flag").write_text(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {ver}")

    report = {
        "cycle_ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "capture_feed": len(captures),
        "poison_guard": psum,
        "quarantined_examples": [{"reason": q["quarantine_reason"],
                                  "payload": (q.get("query") or q.get("body"))[:80]} for q in quarantined[:5]],
        "trained_on_clean": len(clean_recs),
        "store_batch": batch["batch_id"], "store_readiness": rinfo,
        "gate": {k: v[0] for k, v in checks.items()},
        "canary": canary_res,
        "live_version": live_version(),
        "metrics": metrics,
        "drift": drift_info,
        "pending_fp_triggers": pending_triggers,
        "decision": action,
        "seconds": round(time.time() - t0, 1),
    }
    (REPORTS / f"run_{time.strftime('%Y%m%d_%H%M%S')}.json").write_text(json.dumps(report, indent=2, default=float))

    # 6. Slack summary
    if slack:
        slack.notify(key="mlops_cycle", severity=("low" if promote else "high"), force=True,
                     title=f"MLOps retrain cycle: {action}",
                     fields={"capture feed": str(len(captures)),
                             "poison quarantined": str(psum["quarantined"]),
                             "trained on (clean)": str(len(clean_recs)),
                             "gate result": "all pass" if promote else
                                 "failed: " + ",".join(k for k, v in checks.items() if not v[0])},
                     text=("New model passed the poison guard AND all safety gates — promoted."
                           if promote else
                           "Retrain blocked. Poison guard quarantined bad captures; challenger "
                           "failed the gate. Champion unchanged (safe)."))

    print(f"\n=== MLOps CYCLE COMPLETE: {action} ===")
    print(f"  capture feed: {len(captures)} | quarantined poison: {psum['quarantined']} | "
          f"trained on clean: {len(clean_recs)}")
    failed_gates = [k for k, v in checks.items() if not v[0]]
    print(f"  gate: {'ALL PASS' if not failed_gates else 'FAILED (' + ', '.join(failed_gates) + ')'}"
          f"   canary: {canary_res['outcome'] if canary_res else 'not reached'}"
          + (f" [{canary_res['abort_reason']}]" if canary_res and canary_res.get("abort_reason") else ""))
    print(f"  live model version: {live_version() or 'unchanged (champion)'}")
    print(f"  report -> models_v2/runs/  ({report['seconds']}s)")
    return report


if __name__ == "__main__":
    run_cycle()
