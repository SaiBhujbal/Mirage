"""
Corpus builder — the data pipeline's orchestrator.

Flow:
  live CISA KEV feed  ─► category threat weights (what's exploited NOW)
  real payload sources ─► per-category payloads (embedded PayloadsAllTheThings-style
                          corpus in the repo; extensible to Nuclei/ExploitDB — see
                          data_pipeline/README for the connector contract)
  ─► canonical feature extraction (same contract as train/serve)
  ─► versioned manifest with provenance + licensing + KEV-derived sample weights

Output (dated, reproducible):
  data/corpus/manifest_<YYYYMMDD>.json   provenance + counts + threat weights
  data/corpus/kev_weights.json           category -> sample-weight multiplier
train_v2.py reads kev_weights.json and applies per-sample weights so the model
spends capacity on in-the-wild threats.
"""
from __future__ import annotations
import json, time, hashlib, sys, os
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_pipeline.kev_source import category_threat_weights
from ml.real_payload_loader import EmbeddedPayloads
from ml.canonical_features import LEXICAL_FEATURE_NAMES

CORPUS = Path(__file__).resolve().parent.parent / "data" / "corpus"
CORPUS.mkdir(parents=True, exist_ok=True)

SOURCES = [
    {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "role": "threat-prioritisation (metadata, not payloads)", "license": "US Gov public domain", "live": True},
    {"name": "Embedded PayloadsAllTheThings/SecLists corpus", "url": "ml/real_payload_loader.py",
     "role": "actual attack payloads", "license": "MIT / source-repo terms", "live": False},
    {"name": "NVD CVE 2.0 API", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
     "role": "CWE labels + descriptions (metadata; optional, rate-limited)", "license": "US Gov public domain", "live": False},
    {"name": "Nuclei templates (extension point)", "url": "https://github.com/projectdiscovery/nuclei-templates",
     "role": "real HTTP attack payloads in YAML (not yet ingested)", "license": "MIT", "live": False},
]


def build():
    kev = category_threat_weights()
    emb = EmbeddedPayloads.get_all()
    payload_counts = {cat: len(pls) for cat, pls in emb.items()}

    # KEV weights are per web-category; map onto the payload categories we actually have.
    # Categories with no KEV signal default to 1.0 (neutral).
    weights = {cat: round(kev["weights"].get(cat, 1.0), 3) for cat in payload_counts}
    weights["benign"] = 1.0

    manifest = {
        "corpus_version": time.strftime("%Y%m%d"),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "feature_contract": LEXICAL_FEATURE_NAMES,
        "sources": SOURCES,
        "kev": {"version": kev["kev_version"], "total": kev["kev_total"],
                "web_mapped": kev["mapped_to_web_categories"],
                "counts": kev["counts"], "recent_counts": kev["recent_counts"]},
        "payload_counts": payload_counts,
        "sample_weights": weights,
        "licensing_note": "KEV/NVD are US-Gov public domain (metadata only). Payloads derive "
                          "from MIT-licensed public security corpora. Verify per-source terms "
                          "before redistribution of any bundled payloads.",
        "honesty_note": "KEV/NVD provide CVE METADATA, not payloads. Their contribution here is "
                        "threat prioritisation (sample weights), not raw training strings. Raw "
                        "attack strings come from the payload corpora.",
    }
    ver = manifest["corpus_version"]
    (CORPUS / f"manifest_{ver}.json").write_text(json.dumps(manifest, indent=2))
    (CORPUS / "kev_weights.json").write_text(json.dumps(weights, indent=2))

    print(f"[corpus] KEV {kev['kev_version']}: {kev['mapped_to_web_categories']}/{kev['kev_total']} web-mapped")
    print(f"[corpus] top exploited categories (KEV): "
          + ", ".join(f"{k}={v}" for k, v in list(kev['counts'].items())[:5]))
    print(f"[corpus] sample-weight multipliers written -> data/corpus/kev_weights.json")
    print(f"[corpus] highest-weighted (train emphasis): "
          + ", ".join(f"{k}={v}" for k, v in sorted(weights.items(), key=lambda x: -x[1])[:5]))
    print(f"[corpus] manifest -> data/corpus/manifest_{ver}.json")
    return manifest


if __name__ == "__main__":
    build()
