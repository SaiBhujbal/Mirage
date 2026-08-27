"""
ECML/PKDD-2007 loader — a SECOND real, multi-class HTTP-attack corpus.

Despite the .txt/xml name, the file is a block format:
    Start - Id: <n>
    class: <Valid | SQL Injection | XSS | LDAP Injection | XPath Injection |
            Path Traversal | Command Execution | SSI>
    <METHOD> <uri> HTTP/1.1
    <headers...>
    <blank line>
    <body or 'null'>
    End - Id: <n>

Used for cross-dataset generalisation (train on CSIC, test on PKDD and vice-versa) —
the Q1 experiment that tests whether a WAF model survives a benign distribution it was
not trained on.
"""
from __future__ import annotations
import os, sys, ssl, urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from typing import List, Tuple

RAW = Path(__file__).resolve().parent.parent / "data" / "corpus" / "raw"
RAW.mkdir(parents=True, exist_ok=True)
BASE = ("https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/"
        "OriginalDataSets/ecml_pkdd/dataset_ecml_pkdd_train_test/")
# The TEST split carries both benign (Valid) and the 7 attack classes; train is benign-only.
FILES = {"test": "xml_test.txt", "train": "xml_train.txt"}


def _download(which: str = "test") -> Path:
    dst = RAW / f"pkdd2007_{which}.txt"
    if dst.exists() and dst.stat().st_size > 1000:
        return dst
    req = urllib.request.Request(BASE + FILES[which], headers={"User-Agent": "decepticon/1.0"})
    with urllib.request.urlopen(req, timeout=180, context=ssl.create_default_context()) as r:
        dst.write_bytes(r.read())
    return dst


def load(which: str = "test") -> List[Tuple[str, str, str, str, str]]:
    """Returns (method, path, query, body, label) records. label='Valid' == benign.
    which='test' has benign + 7 attack classes; 'train' is benign-only."""
    text = _download(which).read_text(encoding="utf-8", errors="ignore")
    blocks = text.split("Start - Id:")
    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT ")
    recs = []
    for blk in blocks:
        lines = blk.split("\n")
        label, req_i = None, None
        for i, ln in enumerate(lines):
            s = ln.strip()
            if s.lower().startswith("class:"):
                label = s.split(":", 1)[1].strip()
            # NOTE: PKDD mixes HTTP/1.0 and HTTP/1.1 request lines. Matching only "HTTP/1.1"
            # silently dropped ~half the corpus (12,751 of 25,613 blocks — mostly POST attacks).
            elif s.startswith(methods) and "HTTP/1." in s:
                req_i = i
                break
        if label is None or req_i is None:
            continue
        rl = lines[req_i].strip().split(" ")
        method, url = rl[0], rl[1]
        sp = urlsplit(url)
        # body: find blank line after headers, take next non-'null' line before End
        body = ""
        j = req_i + 1
        while j < len(lines) and lines[j].strip() != "":
            j += 1
        j += 1
        if j < len(lines):
            cand = lines[j].strip()
            if cand and cand.lower() != "null" and not cand.startswith("End - Id"):
                body = cand
        recs.append((method, sp.path, sp.query, body, label))
    return recs


def as_binary(recs):
    """-> list of ((method,path,query,body), label01) with Valid=0, attack=1."""
    return [((m, p, q, b), 0 if lab.lower() == "valid" else 1) for (m, p, q, b, lab) in recs]


if __name__ == "__main__":
    from collections import Counter
    recs = load()
    c = Counter(lab for *_, lab in recs)
    print(f"PKDD-2007: {len(recs)} requests")
    for k, v in c.most_common():
        print(f"  {k:<20} {v}")
