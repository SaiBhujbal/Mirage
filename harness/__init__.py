"""WAF evaluation harness: one versioned labeled corpus + four gates (recall, false-positive,
latency, ReDoS) with a single pass/fail report, for CI (rules tier) and MLOps promotion."""
from harness.corpus import load_corpus, corpus_hash, Record
from harness.gates import run_gates, GateReport

__all__ = ["load_corpus", "corpus_hash", "Record", "run_gates", "GateReport"]
