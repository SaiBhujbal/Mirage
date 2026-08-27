"""
CISA Known Exploited Vulnerabilities (KEV) connector.

KEV is CISA's authoritative list of vulnerabilities being *actively exploited in
the wild*. It's a single public JSON feed, no auth, updated ~daily.

Why this matters for "one step ahead": KEV does not give us payloads, but it tells
us which attack CATEGORIES adversaries are exploiting RIGHT NOW. We use that to
weight the training corpus toward in-the-wild threats instead of a flat class prior.
That is a real, defensible signal — the model spends capacity where attackers are.
"""
from __future__ import annotations
import json, time, urllib.request, ssl
from collections import Counter
from pathlib import Path
from typing import Dict
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_pipeline.cwe_map import map_cwes

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE = Path(__file__).resolve().parent.parent / "data" / "corpus" / "kev_raw.json"


def fetch_kev(use_cache_hours: float = 24.0) -> dict:
    if CACHE.exists() and (time.time() - CACHE.stat().st_mtime) < use_cache_hours * 3600:
        return json.loads(CACHE.read_text())
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "decepticon-pipeline/1.0"})
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
        data = json.load(r)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(data))
    return data


def category_threat_weights(recency_days: int = 365) -> Dict:
    """
    Returns per-category exploitation stats from KEV:
      counts        — total KEV entries mapping to each category
      recent_counts — entries added in the last `recency_days`
      weight        — normalized multiplier (>=1.0) for oversampling training data,
                      emphasising actively- and recently-exploited categories.
    """
    data = fetch_kev()
    counts, recent = Counter(), Counter()
    now = time.time()
    mapped = unmapped = 0
    for v in data.get("vulnerabilities", []):
        cats = map_cwes(v.get("cwes", []))
        if not cats:
            unmapped += 1
            continue
        mapped += 1
        added = v.get("dateAdded", "")
        is_recent = False
        try:
            t = time.mktime(time.strptime(added, "%Y-%m-%d"))
            is_recent = (now - t) <= recency_days * 86400
        except Exception:
            pass
        for c in cats:
            counts[c] += 1
            if is_recent:
                recent[c] += 1

    total = sum(counts.values()) or 1
    # weight = 1 + share-of-KEV + extra for recency. Bounded so no class dominates.
    weights = {}
    for c in counts:
        share = counts[c] / total
        rec_share = recent[c] / (sum(recent.values()) or 1)
        weights[c] = round(min(3.0, 1.0 + 4.0 * share + 2.0 * rec_share), 3)
    return {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "kev_version": data.get("catalogVersion"),
        "kev_total": data.get("count"),
        "mapped_to_web_categories": mapped,
        "unmapped_non_web": unmapped,
        "counts": dict(counts.most_common()),
        "recent_counts": dict(recent.most_common()),
        "weights": weights,
    }


if __name__ == "__main__":
    import json as _j
    stats = category_threat_weights()
    print(_j.dumps(stats, indent=2))
