"""
WAF Gate — the honest, WORKING enforcement layer for the demo.

This deliberately combines only the layers that were verified to function
correctly against real CVE payloads:
  1. core.pattern_engine       (fast signature rules, sync/blocking path)
  2. core.advanced_protection  (XXE/SSTI/SSRF/JWT/encoded-attack heuristics)
  3. core.comprehensive_scanner (185 OWASP-mapped regex patterns)

The two ML inference paths (ml.secure_inference, ml.performance_optimizer)
are intentionally NOT used here: at the time of building this demo one
crashes (30-vs-50 feature mismatch) and the other returns "malicious xss
0.992" for every input including benign traffic. Wiring them in would block
100% of legitimate users, so the demo runs on the rule-based layers that
actually work. This is called out honestly in the write-up.

evaluate() returns a Decision the demo app uses to allow or block.
"""
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pattern_engine import pattern_engine
from core.comprehensive_scanner import comprehensive_scanner
try:
    from core.advanced_protection import advanced_protection, ThreatLevel
    ADV = True
except Exception:
    ADV = False

# Fixed ML layer (models_v2). Loaded lazily; if artifacts are missing the gate
# still runs rule-only rather than crashing.
try:
    from ml.detector_v2 import get_detector
    _ml = get_detector()
    ML = True
except Exception as _e:
    _ml = None
    ML = False
    _ML_ERR = str(_e)


@dataclass
class Decision:
    blocked: bool
    category: str = "-"
    severity: float = 0.0
    matched: str = "-"
    layer: str = "-"
    latency_ms: float = 0.0
    is_zero_day: bool = False
    ml_prob: float = 0.0
    ml_novelty: float = 0.0
    details: List[str] = field(default_factory=list)


def evaluate(method: str, path: str, query: str, body: str,
             headers: Optional[Dict[str, str]] = None) -> Decision:
    headers = headers or {}
    t0 = time.perf_counter()
    best_sev = 0.0
    cat = "-"
    matched = "-"
    layer = "-"
    details: List[str] = []

    # Layer 1: fast pattern engine (signature rules)
    try:
        matches = pattern_engine.scan_request(path, query, body, headers)
        for rule, m, loc in matches:
            details.append(f"rules:{rule.category}:{rule.rule_id}")
            if rule.severity > best_sev:
                best_sev, cat, matched, layer = rule.severity, rule.category, m.group(0)[:80], "rules"
    except Exception as e:
        details.append(f"rules_err:{e}")

    # Layer 2: comprehensive 185-pattern scanner
    try:
        results = comprehensive_scanner.scan_request(path=path, query=query, body=body, headers=headers)
        for r in results:
            sev = r.severity.value / 4.0  # Severity enum -> 0..1-ish
            details.append(f"scanner:{r.category.value}:{r.pattern_id}")
            if sev > best_sev:
                best_sev, cat, matched, layer = sev, r.category.value, r.matched_text[:80], "scanner"
    except Exception as e:
        details.append(f"scanner_err:{e}")

    # Layer 3: advanced protection heuristics
    if ADV:
        try:
            dets = advanced_protection.analyze(path=path, query=query, body=body,
                                               headers=headers, client_ip="demo", ml_score=0.0)
            for d in dets:
                sev = getattr(d, "confidence", 0.6)
                details.append(f"advanced:{d.category}")
                if sev > best_sev:
                    best_sev, cat, matched, layer = sev, d.category, (getattr(d, "raw_evidence", "") or "")[:80], "advanced"
        except Exception as e:
            details.append(f"advanced_err:{e}")

    # Layer 4: fixed ML (classifier + energy/novelty open-set route)
    is_zero_day = False
    ml_prob = ml_novelty = 0.0
    if ML and _ml is not None:
        try:
            r = _ml.predict(method, path, query, body, headers)
            ml_prob, ml_novelty = r.mal_prob, r.novelty
            details.append(f"ml:{r.category}:{r.route}:p={r.mal_prob}")
            if r.is_malicious:
                sev = max(r.mal_prob, 0.6 if r.is_zero_day else r.mal_prob)
                if sev > best_sev:
                    best_sev, cat, matched, layer = sev, r.category, f"ml:{r.route}", "ml"
                if r.is_zero_day:
                    is_zero_day = True
        except Exception as e:
            details.append(f"ml_err:{e}")

    latency = (time.perf_counter() - t0) * 1000
    # Block threshold: any layer with severity >= 0.5 blocks
    blocked = best_sev >= 0.5
    return Decision(blocked=blocked, category=cat, severity=round(best_sev, 3),
                    matched=matched, layer=layer if blocked else "-",
                    latency_ms=round(latency, 4), is_zero_day=is_zero_day,
                    ml_prob=ml_prob, ml_novelty=ml_novelty, details=details)
