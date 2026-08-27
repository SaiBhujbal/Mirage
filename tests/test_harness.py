"""Harness self-tests: corpus integrity + multi-target gate behavior (rules + ML)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness.corpus import load_corpus, corpus_hash
from harness.gates import run_gates


def test_corpus_loads_and_hashes():
    c = load_corpus()
    assert c.attacks and c.benign
    assert c.hash and len(c.hash) == 16
    import pathlib
    raw = (pathlib.Path(__file__).resolve().parent.parent / "harness" / "eval_corpus.json").read_text(encoding="utf-8")
    assert corpus_hash(raw) == c.hash


def test_must_catch_families_present():
    c = load_corpus()
    fams = c.families()
    for mc in c.must_catch_families:
        assert fams.get(mc, 0) >= 1, f"must-catch family {mc} has no attack records"


def test_rules_gate_passes():
    # rules-only target is deterministic and ML-free (CI-safe).
    rep = run_gates(load_corpus(), targets=["rules"])
    assert rep.passed, "rules gates should pass on the hardened WAF:\n" + rep.format()
    for g in rep.gates:
        assert g.passed, f"gate {g.name} failed: {g.value} vs {g.budget}"


def test_per_family_recall_reported():
    rep = run_gates(load_corpus(), targets=["rules"])
    for mc in load_corpus().must_catch_families:
        assert rep.per_family_recall.get(mc, 0.0) == 1.0


def test_fp_gate_catches_a_broken_waf():
    """A WAF that blocks everything must FAIL the false_pos gate (the gate actually gates)."""
    class BlockAll:
        def evaluate(self, *a, **k):
            class D:
                action = "BLOCK"
            return D()
    rep = run_gates(load_corpus(), waf=BlockAll(), targets=["rules"])
    fp_gate = next(g for g in rep.gates if g.name == "false_pos")
    assert not fp_gate.passed and not rep.passed


def test_ml_targets_present_and_reported():
    """The harness must evaluate the ML surface, not just rules. ML targets are either
    available (evaluated) or skipped (deps/model absent) — never silently missing."""
    rep = run_gates(load_corpus(), targets=["rules", "ml_waf", "ml_model"])
    names = {t.target for t in rep.targets}
    assert {"rules", "ml_waf", "ml_model"} <= names
    # rules is the hard gate; overall pass tracks it regardless of ML availability
    assert rep.passed is True
    # enforcement_ready is a bool when ml_waf evaluated, else None (model unavailable)
    mlw = next(t for t in rep.targets if t.target == "ml_waf")
    assert (rep.enforcement_ready in (True, False)) if mlw.available else (rep.enforcement_ready is None)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
