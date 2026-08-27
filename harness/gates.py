"""The four WAF harness gates -> one pass/fail report, across multiple TARGETS.

Targets (an ML WAF must be gated as an ML WAF, not just its regex tier):
  * rules     — LayeredWAF(ml_enforce=False): the signature/heuristic enforcing surface.
  * ml_waf    — LayeredWAF(ml_enforce=True): the FULL stack as it would enforce in production.
  * ml_model  — the raw detector in isolation: would it BLOCK (enforce + high prob)? Isolates
                the model's own contribution and its false-positive behavior.

Gates: recall (with per-family + must-catch), false_pos (load-bearing for enforcement),
latency p99, redos. Per-family recall is reported so a corpus flooded with one family can't
hide rot in another. Unique client IP per case so the per-IP accumulator can't skew results.

ML targets need the ML deps + a loadable model; when unavailable they are reported as SKIPPED,
never a hard failure (so CI without model artifacts still runs the rules gate).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Tuple

from harness.corpus import Corpus, Record

DEFAULTS = dict(recall_min=0.95, fp_max=0.02, latency_p99_ms=50.0, redos_max_ms=500.0)

_REDOS_PROBES = [
    "{{" + " " * 8192, "<" + "a" * 8192, "${" + " " * 8192,
    "A" * 70000, "(" * 4096 + ")" * 4096, " \t" * 8192,
]


@dataclass
class GateResult:
    name: str
    passed: bool
    value: float
    budget: float
    detail: str = ""


@dataclass
class TargetReport:
    target: str
    available: bool
    passed: bool
    gates: List[GateResult] = field(default_factory=list)
    per_family_recall: Dict[str, float] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["gates"] = [asdict(g) for g in self.gates]
        return d


@dataclass
class GateReport:
    corpus_version: str
    corpus_hash: str
    passed: bool                       # overall: hard-gated targets all pass
    targets: List[TargetReport] = field(default_factory=list)
    n_attacks: int = 0
    n_benign: int = 0
    enforcement_ready: Optional[bool] = None   # can WAF_ML_ENFORCE=true ship safely?
    seconds: float = 0.0

    # back-compat: expose the rules target's gates at the top level
    @property
    def gates(self) -> List[GateResult]:
        for t in self.targets:
            if t.target == "rules":
                return t.gates
        return self.targets[0].gates if self.targets else []

    @property
    def per_family_recall(self) -> Dict[str, float]:
        for t in self.targets:
            if t.target == "rules":
                return t.per_family_recall
        return {}

    def to_dict(self) -> Dict:
        return {"corpus_version": self.corpus_version, "corpus_hash": self.corpus_hash,
                "passed": self.passed, "enforcement_ready": self.enforcement_ready,
                "n_attacks": self.n_attacks, "n_benign": self.n_benign,
                "seconds": self.seconds, "targets": [t.to_dict() for t in self.targets]}

    def format(self) -> str:
        lines = [f"WAF harness gate report  (corpus v{self.corpus_version} #{self.corpus_hash})",
                 f"  attacks={self.n_attacks}  benign={self.n_benign}  ({self.seconds:.2f}s)"]
        for t in self.targets:
            lines.append("")
            if not t.available:
                lines.append(f"  == target: {t.target} ==  SKIPPED ({t.note})")
                continue
            lines.append(f"  == target: {t.target} ==  {'PASS' if t.passed else 'FAIL'}")
            for g in t.gates:
                mark = "PASS" if g.passed else "FAIL"
                lines.append(f"    [{mark}] {g.name:10s} {g.value:8.3f}  (budget {g.budget})  {g.detail}")
            lines.append("    per-family recall: " + ", ".join(
                f"{k}={v:.2f}" for k, v in sorted(t.per_family_recall.items())))
        lines.append("")
        if self.enforcement_ready is not None:
            lines.append(f"  ML ENFORCEMENT READY (WAF_ML_ENFORCE=true safe?): "
                         f"{'YES' if self.enforcement_ready else 'NO'}")
        lines.append(f"  RESULT: {'ALL HARD GATES PASS' if self.passed else 'HARD GATES FAILED'}")
        return "\n".join(lines)


# decide_fn: record -> (blocked: bool, latency_ms: float)
DecideFn = Callable[[Record], Tuple[bool, float]]


def _rules_decider(waf):
    def f(r: Record) -> Tuple[bool, float]:
        headers = {"user-agent": "Mozilla/5.0", **(r.headers or {})}
        s = time.perf_counter()
        d = waf.evaluate(r.method, r.path, r.query, r.body, headers, _next_ip())
        return d.action != "ALLOW", (time.perf_counter() - s) * 1000
    return f


def _model_decider(detector, threshold: float):
    def f(r: Record) -> Tuple[bool, float]:
        s = time.perf_counter()
        pred = detector.predict(r.method, r.path, r.query, r.body, r.headers or {})
        ms = (time.perf_counter() - s) * 1000
        # ml_model measures the model's DETECTION quality (is_malicious) — independent of the
        # enforce gate — so a shadow model (enforce=False) still shows its real recall/FP. The
        # ml_waf target separately measures what the deployed stack actually ENFORCES.
        blocked = bool(getattr(pred, "is_malicious", False))
        return blocked, ms
    return f


_ipn = [0]


def _next_ip() -> str:
    _ipn[0] += 1
    return f"198.51.{_ipn[0] // 256 % 256}.{_ipn[0] % 256}"


def _measure(corpus: Corpus, decide: DecideFn, budgets: Dict, target: str) -> TargetReport:
    fam_total: Dict[str, int] = {}
    fam_caught: Dict[str, int] = {}
    latencies: List[float] = []
    for r in corpus.attacks:
        blocked, ms = decide(r)
        latencies.append(ms)
        fam_total[r.family] = fam_total.get(r.family, 0) + 1
        if blocked:
            fam_caught[r.family] = fam_caught.get(r.family, 0) + 1
    recall = sum(fam_caught.values()) / max(1, len(corpus.attacks))
    per_family = {fam: fam_caught.get(fam, 0) / fam_total[fam] for fam in fam_total}

    fp = 0
    for r in corpus.benign:
        blocked, ms = decide(r)
        latencies.append(ms)
        if blocked:
            fp += 1
    fp_rate = fp / max(1, len(corpus.benign))

    lat = sorted(latencies)
    p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))] if lat else 0.0

    worst = 0.0
    for probe in _REDOS_PROBES:
        blocked, ms = decide(Record(id="redos", label="attack", family="redos",
                                    method="POST", path="/", query="", body="x=" + probe))
        worst = max(worst, ms)

    mc_fail = [f for f in corpus.must_catch_families if per_family.get(f, 0.0) < 1.0]
    gates = [
        GateResult("recall", recall >= budgets["recall_min"] and not mc_fail, round(recall, 3),
                   budgets["recall_min"], "must-catch OK" if not mc_fail else f"MUST-CATCH MISS: {','.join(mc_fail)}"),
        GateResult("false_pos", fp_rate <= budgets["fp_max"], round(fp_rate, 3), budgets["fp_max"],
                   f"{fp}/{len(corpus.benign)} benign blocked"),
        GateResult("latency", p99 <= budgets["latency_p99_ms"], round(p99, 3), budgets["latency_p99_ms"], "p99 ms"),
        GateResult("redos", worst <= budgets["redos_max_ms"], round(worst, 3), budgets["redos_max_ms"], "worst ms"),
    ]
    return TargetReport(target=target, available=True, passed=all(g.passed for g in gates),
                        gates=gates, per_family_recall={k: round(v, 3) for k, v in per_family.items()})


def _try_load_detector():
    try:
        from ml.detector_v2 import get_detector
        det = get_detector()
        thr = float(getattr(det, "enforce_threshold", 0.9) or 0.9)
        return det, thr, ""
    except Exception as e:  # deps or model artifacts absent
        return None, 0.9, f"{type(e).__name__}: {e}"


def run_gates(corpus: Corpus, waf=None, budgets: Optional[Dict] = None,
              targets: Optional[List[str]] = None) -> GateReport:
    """Run the gates across the requested targets. Default: rules + (ml_waf, ml_model if loadable).
    Only the 'rules' target hard-gates the overall pass (CI-safe); ML targets are reported and
    drive the enforcement-readiness verdict."""
    b = {**DEFAULTS, **(budgets or {})}
    targets = targets or ["rules", "ml_waf", "ml_model"]
    t0 = time.perf_counter()
    reports: List[TargetReport] = []

    if "rules" in targets:
        w = waf
        if w is None:
            from waf.engine import LayeredWAF
            w = LayeredWAF(ml_enforce=False)
        reports.append(_measure(corpus, _rules_decider(w), b, "rules"))

    det, thr, err = (None, 0.9, "")
    if "ml_waf" in targets or "ml_model" in targets:
        det, thr, err = _try_load_detector()

    if "ml_waf" in targets:
        if det is not None:
            from waf.engine import LayeredWAF
            reports.append(_measure(corpus, _rules_decider(LayeredWAF(ml_enforce=True)), b, "ml_waf"))
        else:
            reports.append(TargetReport("ml_waf", available=False, passed=True, note="ML model unavailable: " + err))

    if "ml_model" in targets:
        if det is not None:
            tr = _measure(corpus, _model_decider(det, thr), b, "ml_model")
            tr.note = f"raw detector, enforce_threshold={thr}"
            reports.append(tr)
        else:
            reports.append(TargetReport("ml_model", available=False, passed=True, note="ML model unavailable: " + err))

    # overall hard-gate = the rules target (deterministic, CI-safe)
    rules_ok = all(t.passed for t in reports if t.target == "rules")
    # enforcement readiness = the ml_waf target's gates all pass (recall high AND FP under budget)
    mlw = next((t for t in reports if t.target == "ml_waf" and t.available), None)
    ready = mlw.passed if mlw else None

    return GateReport(corpus_version=corpus.version, corpus_hash=corpus.hash, passed=rules_ok,
                      targets=reports, n_attacks=len(corpus.attacks), n_benign=len(corpus.benign),
                      enforcement_ready=ready, seconds=round(time.perf_counter() - t0, 2))
