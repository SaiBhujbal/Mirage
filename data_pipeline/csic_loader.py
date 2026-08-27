"""
CSIC-2010 loader — REAL labeled HTTP traffic (replaces synthetic benign for Q1 credibility).

Source: msudol/Web-Application-Attack-Datasets mirror of the CSIC 2010 HTTP dataset
(Torrano-Gimenez et al., CSIC 2010). ~36k normal + ~25k anomalous requests to an
e-commerce app. Research-use; cite the CSIC dataset.

We pull the RAW request dumps (not the pre-computed Weka feature CSV) so we can extract
the SAME canonical features used by train/serve — no skew, no borrowed feature set.

Parses the CSIC block format:
    GET http://host/path?query HTTP/1.1
    Header: value
    ...
    <blank line>
    <optional body>
into (method, path, query, body) records.
"""
from __future__ import annotations
import os, sys, ssl, urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from typing import List, Tuple

RAW = Path(__file__).resolve().parent.parent / "data" / "corpus" / "raw"
RAW.mkdir(parents=True, exist_ok=True)
BASE = "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010/"
FILES = {
    "normal_train": "normalTrafficTraining.txt",
    "normal_test": "normalTrafficTest.txt",
    "anomalous": "anomalousTrafficTest.txt",
}


def _download(name: str) -> Path:
    dst = RAW / FILES[name]
    if dst.exists() and dst.stat().st_size > 1000:
        return dst
    req = urllib.request.Request(BASE + FILES[name], headers={"User-Agent": "mirage/1.0"})
    with urllib.request.urlopen(req, timeout=120, context=ssl.create_default_context()) as r:
        data = r.read()
    dst.write_bytes(data)
    return dst


def _parse(path: Path) -> List[Tuple[str, str, str, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.split("\n")
    recs = []
    i, n = 0, len(lines)
    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")
    while i < n:
        line = lines[i].strip()
        if line.startswith(methods):
            parts = line.split(" ")
            method, url = parts[0], parts[1]
            sp = urlsplit(url)
            reqpath, query = sp.path, sp.query
            # consume headers until blank line
            i += 1
            content_len = 0
            while i < n and lines[i].strip() != "":
                h = lines[i].strip()
                if h.lower().startswith("content-length:"):
                    try:
                        content_len = int(h.split(":", 1)[1].strip())
                    except Exception:
                        content_len = 0
                i += 1
            body = ""
            # blank line then body (for POST); CSIC puts body on the next non-empty line(s)
            i += 1
            if content_len > 0 and i < n:
                body = lines[i].strip()
                i += 1
            recs.append((method, reqpath, query, body))
        else:
            i += 1
    return recs


def load(which: str) -> List[Tuple[str, str, str, str]]:
    """which in {normal_train, normal_test, anomalous}. Returns (method,path,query,body) records."""
    return _parse(_download(which))


def attack_payload_strings(max_n: int = 4000) -> List[str]:
    """Extract raw attack strings (query or body) from CSIC anomalous requests, for the attacker."""
    recs = load("anomalous")
    out = []
    for m, p, q, b in recs:
        s = q or b
        if s and len(s) >= 4:
            out.append(s)
        if len(out) >= max_n:
            break
    return out


if __name__ == "__main__":
    for k in FILES:
        recs = load(k)
        ex = recs[0] if recs else None
        print(f"{k:<14} {len(recs):>6} requests   e.g. {str(ex)[:90]}")
