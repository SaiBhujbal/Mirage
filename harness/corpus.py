"""Frozen, content-hashed evaluation corpus for the WAF harness.

The corpus is loaded from harness/eval_corpus.json — a human-reviewed set kept SEPARATE from
the auto-accumulated training feed so a gate is never evaluated on auto-labeled data. Every
load is content-hashed so a report is traceable to the exact corpus version (dataset lineage
without a heavyweight tool)."""
from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

_CORPUS_PATH = Path(__file__).resolve().parent / "eval_corpus.json"


@dataclass
class Record:
    id: str
    label: str            # "attack" | "benign"
    family: str
    method: str = "GET"
    path: str = "/"
    query: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"


@dataclass
class Corpus:
    version: str
    hash: str
    must_catch_families: List[str]
    records: List[Record]

    @property
    def attacks(self) -> List[Record]:
        return [r for r in self.records if r.is_attack]

    @property
    def benign(self) -> List[Record]:
        return [r for r in self.records if not r.is_attack]

    def families(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in self.attacks:
            out[r.family] = out.get(r.family, 0) + 1
        return out


def corpus_hash(raw: str) -> str:
    """SHA-256 (16 hex) of the raw corpus text — the dataset-lineage fingerprint."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_corpus(path: Path = _CORPUS_PATH) -> Corpus:
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    records = []
    seen = set()
    for d in data["records"]:
        if d["id"] in seen:
            raise ValueError(f"duplicate record id in corpus: {d['id']}")
        seen.add(d["id"])
        records.append(Record(
            id=d["id"], label=d["label"], family=d.get("family", "unknown"),
            method=d.get("method", "GET"), path=d.get("path", "/"),
            query=d.get("query", ""), body=d.get("body", ""),
            headers=d.get("headers", {}) or {}))
    if not any(r.is_attack for r in records) or not any(not r.is_attack for r in records):
        raise ValueError("corpus must contain both attack and benign records")
    return Corpus(version=data.get("version", "?"), hash=corpus_hash(raw),
                  must_catch_families=data.get("must_catch_families", []), records=records)
