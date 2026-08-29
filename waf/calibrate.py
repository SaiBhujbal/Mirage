"""
Calibrate enforcement against YOUR benign traffic — the missing step between "shadow" and
"WAF_ML_ENFORCE=true".

Every rollout document in this repo says the same thing: measure the false-positive rate on
your own traffic before you enforce. Nothing actually measured it for you. This does.

Feed it a sample of REAL BENIGN requests (an access log, or JSONL you export from your app)
and it replays them through the real decision path in every posture, then reports:

  - the false-positive rate per posture (rules only / + ML shadow-as-if-enforcing)
  - WHICH rules and layers caused them, ranked — the top offenders are usually one or two
    rules over-matching one endpoint, not a broad problem
  - which PATHS concentrate the failures, so you can scope them with WAF_SHADOW_ROUTES
  - a verdict against your budget, with the exact env vars to set

It never needs attack traffic: enforcement risk is a false-positive question. Recall is
already gated by the frozen harness corpus (`python -m harness.run`).

INPUT FORMATS (auto-detected)
  .jsonl  one object per line, keys: method, path, query, body, headers (all optional but
          `path`; `url` is accepted instead of path+query)
  .log    Common/Combined access log — the request line is parsed, bodies are unavailable
          (GET-heavy logs still catch the majority of query-string false positives)

USAGE
    python -m waf.calibrate access.log
    python -m waf.calibrate traffic.jsonl --budget 0.001 --top 15
    python -m waf.calibrate traffic.jsonl --json report.json

EXIT CODE
    0 = false-positive rate within budget (safe to proceed to the next rollout phase)
    1 = over budget (do not enforce yet; the report names what to fix)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

# Common/Combined log format: host ident user [time] "METHOD path HTTP/x" status size ...
_ACCESS_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/[\d.]+"')


def _from_jsonl(path: Path) -> Iterator[Tuple[str, str, str, str, Dict[str, str]]]:
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict):
                continue
            if "url" in r and "path" not in r:
                sp = urlsplit(r["url"])
                p, q = sp.path, sp.query
            else:
                p, q = r.get("path", "/"), r.get("query", "")
            body = r.get("body", "")
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            headers = r.get("headers") or {}
            if not isinstance(headers, dict):
                headers = {}
            yield (r.get("method", "GET").upper(), p or "/", q or "",
                   body or "", {str(k): str(v) for k, v in headers.items()})


def _from_access_log(path: Path) -> Iterator[Tuple[str, str, str, str, Dict[str, str]]]:
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = _ACCESS_RE.search(line)
            if not m:
                continue
            sp = urlsplit(m.group("url"))
            yield (m.group("method"), sp.path or "/", sp.query or "", "", {})


def load_requests(path: Path, limit: Optional[int]) -> List[Tuple]:
    src = _from_jsonl(path) if path.suffix.lower() in (".jsonl", ".json") else _from_access_log(path)
    out = []
    for rec in src:
        out.append(rec)
        if limit and len(out) >= limit:
            break
    return out


def _evaluate(requests: List[Tuple], ml_enforce: bool) -> dict:
    """Replay traffic through the real engine. Returns FP stats for this posture."""
    from waf.engine import LayeredWAF

    waf = LayeredWAF(ml_enforce=ml_enforce)
    blocked, by_layer, by_cat, by_path, examples = 0, Counter(), Counter(), Counter(), []
    for i, (m, p, q, b, h) in enumerate(requests):
        # A unique client IP per request: the per-IP reputation/rate state is not what we are
        # measuring, and reusing one IP would manufacture blocks that real users never see.
        ip = f"198.51.{i // 250 % 250}.{i % 250}"
        d = waf.evaluate(m, p, q, b, h or {"user-agent": "Mozilla/5.0"}, ip)
        if d.action != "ALLOW":
            blocked += 1
            by_layer[d.layer] += 1
            by_cat[d.category] += 1
            by_path[p] += 1
            if len(examples) < 25:
                examples.append({"method": m, "path": p, "query": q[:120], "body": (b or "")[:120],
                                 "action": d.action, "layer": d.layer, "category": d.category,
                                 "reasons": list(d.reasons)[:4]})
    n = len(requests) or 1
    return {"requests": len(requests), "false_positives": blocked, "fp_rate": blocked / n,
            "by_layer": by_layer.most_common(), "by_category": by_cat.most_common(),
            "by_path": by_path.most_common(), "examples": examples}


def _pct(x: float) -> str:
    return f"{x * 100:.3f}%"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Calibrate WAF enforcement on your own benign traffic")
    ap.add_argument("traffic", help="access log (.log) or JSONL (.jsonl) of REAL BENIGN requests")
    ap.add_argument("--budget", type=float, default=0.001,
                    help="max acceptable false-positive rate (default 0.001 = 0.1%%)")
    ap.add_argument("--limit", type=int, default=50000, help="max requests to replay")
    ap.add_argument("--top", type=int, default=10, help="how many offenders to list")
    ap.add_argument("--json", dest="json_out", help="write the full report to this path")
    args = ap.parse_args(argv)

    path = Path(args.traffic)
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 2

    requests = load_requests(path, args.limit)
    if not requests:
        print(f"error: no requests parsed from {path}. Expected an access log or JSONL.",
              file=sys.stderr)
        return 2

    print(f"Calibrating on {len(requests)} requests from {path.name}")
    print("These MUST be benign traffic — any real attack in the sample counts as a false positive.")

    # Which model is serving decides the answer entirely: measured on the same 3,000 real
    # requests, the legacy lexical detector false-positives on 94.7% of them (it routes benign
    # traffic to the honeypot as "novel"), the grammar-conformance detector on 0.0%. Name the
    # model, so a result is never misread as being about a model that was not measured.
    model = os.environ.get("WAF_ML_MODEL", "(unset -> default lexical detector_v2)")
    try:
        from ml.detector_v2 import get_detector
        det = get_detector()
        kind = getattr(det, "model_kind", type(det).__name__)
    except Exception as e:
        kind = f"unavailable ({type(e).__name__})"
    print(f"Serving model: WAF_ML_MODEL={model}")
    print(f"               {kind}")
    if "gcid" not in str(model).lower():
        print("               NOTE: set WAF_ML_MODEL=gcid to calibrate the enforcement-ready detector.")
    print()

    postures = {}
    for label, ml in (("rules only (WAF_ML_ENFORCE=false)", False),
                      ("rules + ML enforcing (WAF_ML_ENFORCE=true)", True)):
        # WAF_GCID_ENFORCE is read at detector load, so surface it for the ML posture.
        prev = os.environ.get("WAF_GCID_ENFORCE")
        if ml:
            os.environ["WAF_GCID_ENFORCE"] = "true"
        try:
            postures[label] = _evaluate(requests, ml)
        finally:
            if prev is None:
                os.environ.pop("WAF_GCID_ENFORCE", None)
            else:
                os.environ["WAF_GCID_ENFORCE"] = prev

    print(f"{'posture':<46}{'false positives':<20}{'rate':<12}verdict")
    verdicts = {}
    for label, r in postures.items():
        ok = r["fp_rate"] <= args.budget
        verdicts[label] = ok
        print(f"  {label:<44}{r['false_positives']:>5} / {r['requests']:<12}"
              f"{_pct(r['fp_rate']):<12}{'OK' if ok else 'OVER BUDGET'}")

    # The detail that makes this actionable: what actually caused the blocks.
    worst = postures["rules + ML enforcing (WAF_ML_ENFORCE=true)"]
    if worst["false_positives"]:
        print(f"\nTop causes (ML-enforcing posture), budget {_pct(args.budget)}:")
        print("  by layer:    " + ", ".join(f"{k}={v}" for k, v in worst["by_layer"][:args.top]))
        print("  by category: " + ", ".join(f"{k}={v}" for k, v in worst["by_category"][:args.top]))
        print("  by path:     " + ", ".join(f"{k}={v}" for k, v in worst["by_path"][:args.top]))
        print("\n  Sample false positives:")
        for ex in worst["examples"][:5]:
            eviden = ex["query"] or ex["body"]
            print(f"    {ex['action']:<9} {ex['layer']:<12} {ex['category']:<22} "
                  f"{ex['method']} {ex['path']} {eviden[:60]}")

        # Concentrated failures are a scoping problem, not a tuning problem.
        top_paths = [p for p, c in worst["by_path"]
                     if c >= max(2, 0.25 * worst["false_positives"])]
        if top_paths:
            print("\n  These paths concentrate the false positives. If they legitimately carry"
                  "\n  code/SQL/markup (admin console, paste, GraphQL), scope them instead of"
                  "\n  weakening rules globally:")
            print(f"    WAF_SHADOW_ROUTES={','.join(top_paths[:8])}")

    print("\nVerdict:")
    if verdicts["rules only (WAF_ML_ENFORCE=false)"]:
        print("  - Signature enforcement is within budget on this traffic: WAF_MODE=block is safe.")
    else:
        print("  - Signatures alone exceed your budget. Do NOT enforce yet; scope the paths above")
        print("    (WAF_SHADOW_ROUTES) or tune the named rules, then re-run.")
    if verdicts["rules + ML enforcing (WAF_ML_ENFORCE=true)"]:
        print("  - ML enforcement is within budget: WAF_ML_ENFORCE=true WAF_GCID_ENFORCE=true")
        print("    Roll it out to a canary slice first and watch /waf/stats.")
    else:
        print("  - ML enforcement is over budget on this traffic. Keep it in shadow.")

    print("\n  This measures FALSE POSITIVES only. Detection is gated separately by the frozen")
    print("  corpus: python -m harness.run --gate-ml")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(postures, indent=2), encoding="utf-8")
        print(f"\n  full report -> {args.json_out}")

    return 0 if all(verdicts.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
