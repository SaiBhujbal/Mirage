"""
Nuclei CVE-template loader — REAL, CVE-tagged HTTP exploit payloads.

Each nuclei template carries cve-id + cwe-id AND the actual HTTP request that exploits
the CVE. This is the one source that ties a real exploit payload to a real CVE label —
exactly what "train on known exploits, probe with known CVEs" needs.

Fetches a bounded sample across CVE years, caches raw YAML to data/corpus/raw/nuclei/,
and extracts (payload_string, cve_id, cwe_id, category) by parsing the request path/body.
License: MIT (projectdiscovery/nuclei-templates).
"""
from __future__ import annotations
import os, sys, re, ssl, json, time, urllib.request
from pathlib import Path
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_pipeline.cwe_map import CWE_TO_CATEGORY

RAW = Path(__file__).resolve().parent.parent / "data" / "corpus" / "raw" / "nuclei"
RAW.mkdir(parents=True, exist_ok=True)
CTX = ssl.create_default_context()
UA = {"User-Agent": "decepticon-pipeline/1.0"}


def _get(url, timeout=30):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout, context=CTX).read()


def fetch(years=("2024", "2023", "2022", "2021"), per_year=60) -> int:
    """Download up to per_year templates for each year into the cache. Returns count cached."""
    n = 0
    for y in years:
        try:
            listing = json.loads(_get(f"https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves/{y}"))
        except Exception as e:
            print(f"  [nuclei] {y}: listing failed ({e})"); continue
        yamls = [x for x in listing if x["name"].endswith(".yaml")][:per_year]
        for x in yamls:
            dst = RAW / x["name"]
            if dst.exists():
                n += 1; continue
            try:
                dst.write_bytes(_get(x["download_url"]))
                n += 1
                time.sleep(0.05)
            except Exception:
                pass
    return n


# extract payload-bearing strings from a template's raw request section
_path_re = re.compile(r'^\s*-\s*["\']?(?:\{\{BaseURL\}\}|\{\{RootURL\}\})?(/[^"\'\n]{3,400})', re.M)
_cve_re = re.compile(r'cve-id:\s*(CVE-\d{4}-\d+)', re.I)
_cwe_re = re.compile(r'cwe-id:\s*(CWE-\d+)', re.I)
_body_re = re.compile(r'body:\s*["\']?([^\n"\']{6,400})', re.I)


def parse_template(text: str) -> List[Dict]:
    cve = (_cve_re.search(text) or [None, None])[1] if _cve_re.search(text) else None
    cwe_m = _cwe_re.search(text)
    cwe = cwe_m.group(1).upper() if cwe_m else None
    category = CWE_TO_CATEGORY.get(cwe, "generic_injection") if cwe else "generic_injection"
    payloads = []
    for m in _path_re.finditer(text):
        payloads.append(("GET", m.group(1)))
    for m in _body_re.finditer(text):
        payloads.append(("POST", m.group(1)))
    out = []
    for method, raw in payloads:
        # split path?query
        if "?" in raw:
            path, query = raw.split("?", 1)
        else:
            path, query = raw, ""
        out.append({"method": method, "path": path[:300], "query": query[:400],
                    "body": raw[:400] if method == "POST" else "",
                    "cve": cve, "cwe": cwe, "category": category})
    return out


def load(fetch_if_empty=True) -> List[Dict]:
    files = list(RAW.glob("*.yaml"))
    if not files and fetch_if_empty:
        print("[nuclei] cache empty — fetching sample...")
        fetch()
        files = list(RAW.glob("*.yaml"))
    recs = []
    for f in files:
        try:
            recs.extend(parse_template(f.read_text(encoding="utf-8", errors="ignore")))
        except Exception:
            pass
    # keep only payloads with some attack-ish content or a query (drop bare paths)
    recs = [r for r in recs if r["query"] or r["body"] or any(
        c in r["path"].lower() for c in ("'", "..", "<", "%", "select", "etc/passwd", "="))]
    return recs


if __name__ == "__main__":
    from collections import Counter
    recs = load()
    print(f"Nuclei CVE payloads: {len(recs)} from {len(list(RAW.glob('*.yaml')))} templates")
    print("by category:", dict(Counter(r["category"] for r in recs).most_common()))
    print("distinct CVEs:", len({r["cve"] for r in recs if r["cve"]}))
    for r in recs[:4]:
        print(f"  [{r['cve']} {r['category']}] {r['method']} {r['path']}?{r['query']}"[:110])
