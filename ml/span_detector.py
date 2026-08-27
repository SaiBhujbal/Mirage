"""
Span-localized detector — the reframed defense the negative result (RESEARCH_DESIGN §3d)
pointed to.

Insight: benign-dilution evades whole-request scoring because it lowers the *global*
malicious probability by adding legitimate context. But an injected attack lives in a
single field/span. If we score each span INDEPENDENTLY and take the max, adding benign
padding elsewhere cannot lower the malicious span's score => dilution-invariant by
construction (this time the "by construction" is honest: max over spans is provably
non-decreasing when you add spans).

  score(request) = max over spans s of  base_detector(s)

Spans = individual query-param values, path segments, and body (whole + JSON values).
base_detector = the deployed lexical detector_v2 applied to a single span.
"""
from __future__ import annotations
import os, sys, re, json
from typing import List
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.detector_v2 import get_detector


def extract_spans(method: str, path: str, query: str, body: str) -> List[str]:
    spans = []
    # query params -> each value (and each key=value) is a span
    for kv in (query or "").split("&"):
        if not kv:
            continue
        if "=" in kv:
            spans.append(kv.split("=", 1)[1])
        spans.append(kv)
    # path segments
    for seg in (path or "").split("/"):
        if seg:
            spans.append(seg)
    # body: whole, plus JSON leaf values if parseable
    if body:
        spans.append(body)
        try:
            obj = json.loads(body)
            def leaves(o):
                if isinstance(o, dict):
                    for v in o.values(): yield from leaves(v)
                    for k in o.keys(): yield str(k)
                elif isinstance(o, list):
                    for v in o: yield from leaves(v)
                else:
                    yield str(o)
            spans.extend(list(leaves(obj)))
        except Exception:
            pass
    # de-dup, keep non-trivial
    seen, out = set(), []
    for s in spans:
        s = s.strip()
        if len(s) >= 3 and s not in seen:
            seen.add(s); out.append(s)
    return out or [(query or body or path or "")]


class SpanDetector:
    def __init__(self):
        self.det = get_detector()

    def score(self, method: str = "GET", path: str = "", query: str = "",
              body: str = "") -> float:
        spans = extract_spans(method, path, query, body)
        best = 0.0
        for s in spans:
            # score the span alone as an isolated query value
            p = self.det.predict("GET", "/x", f"p={s}", "", {}).mal_prob
            if p > best:
                best = p
        return best

    def score_payload(self, payload: str) -> float:
        """For the attacker: treat the raw (possibly dilution-padded) string as a query."""
        return self.score("GET", "/search", payload, "")


_span = None
def get_span_detector():
    global _span
    if _span is None:
        _span = SpanDetector()
    return _span
