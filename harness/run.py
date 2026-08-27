"""Harness CLI — run the four WAF gates across rules + ML targets; exit non-zero on failure.

    python -m harness.run                 # rules + ml_waf + ml_model targets, human report
    python -m harness.run --json          # machine report (also -> models_v2/harness_report.json)
    python -m harness.run --targets rules # rules-tier only (CI without model artifacts)
    python -m harness.run --gate-ml       # ALSO hard-fail unless ML enforcement is ready
    python -m harness.run --ml-native     # print honest ML metrics on the model's native (CSIC) data

The rules target is the deterministic hard gate (CI-safe). The ML targets (full ml_enforce=True
WAF, and the raw model) are evaluated and drive an "ML enforcement ready?" verdict — they gate the
build only with --gate-ml, since ML enforcement readiness is a deliberate go-live decision.
"""
from __future__ import annotations

import sys
import json
import argparse
from pathlib import Path

from harness.corpus import load_corpus
from harness.gates import run_gates, DEFAULTS


def _ml_native_readout(sample: int = 800) -> str:
    """Honest ML metrics on the model's NATIVE distribution (real CSIC-2010), not the curated
    corpus. This is the recall/FP a reviewer should trust for the model itself."""
    try:
        from ml.detector_v2 import get_detector
        from data_pipeline.csic_loader import load
        det = get_detector()
        benign = load("normal_test")[:sample]
        attacks = load("anomalous")[:sample]
        def rate(recs, want):
            return sum(1 for m, p, q, b in recs if det.predict(m, p, q, b, {}).is_malicious == want) / max(1, len(recs))
        ben_ok = rate(benign, False)
        atk_ok = rate(attacks, True)
        return (f"  ML native (real CSIC-2010, n={sample}/class): "
                f"attack recall {atk_ok*100:.1f}%  |  benign FP {(1-ben_ok)*100:.1f}%")
    except Exception as e:
        return f"  ML native readout unavailable: {type(e).__name__}: {e}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="WAF harness gate runner (rules + ML)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--targets", default="rules,ml_waf,ml_model",
                    help="comma list: rules,ml_waf,ml_model")
    ap.add_argument("--gate-ml", action="store_true", help="hard-fail unless ML enforcement is ready")
    ap.add_argument("--ml-native", action="store_true", help="print ML metrics on native CSIC data")
    ap.add_argument("--recall-min", type=float, default=DEFAULTS["recall_min"])
    ap.add_argument("--fp-max", type=float, default=DEFAULTS["fp_max"])
    ap.add_argument("--latency-p99-ms", type=float, default=DEFAULTS["latency_p99_ms"])
    ap.add_argument("--redos-max-ms", type=float, default=DEFAULTS["redos_max_ms"])
    ap.add_argument("--out", default="models_v2/harness_report.json")
    args = ap.parse_args(argv)

    corpus = load_corpus()
    report = run_gates(corpus, targets=[t.strip() for t in args.targets.split(",") if t.strip()],
                       budgets=dict(recall_min=args.recall_min, fp_max=args.fp_max,
                                    latency_p99_ms=args.latency_p99_ms, redos_max_ms=args.redos_max_ms))

    try:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    except Exception:
        pass

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.format())
        if args.ml_native:
            print(_ml_native_readout())

    ok = report.passed and (report.enforcement_ready is not False or not args.gate_ml)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
