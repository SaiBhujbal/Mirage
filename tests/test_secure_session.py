"""
Tests for DECEPTICON Secure Session Manager
"""
import time
import os
import sys
import hashlib
from typing import Dict
from unittest.mock import patch, MagicMock

# Handle missing dependencies by mocking them before importing project modules
if 'orjson' not in sys.modules:
    sys.modules['orjson'] = MagicMock()
if 'requests' not in sys.modules:
    sys.modules['requests'] = MagicMock()
if 'pydantic_settings' not in sys.modules:
    sys.modules['pydantic_settings'] = MagicMock()
if 'mmh3' not in sys.modules:
    sys.modules['mmh3'] = MagicMock()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.secure_session import (
    SecureSessionIDGenerator,
    SessionBinding,
    SecureSession,
    SecureSessionManager,
    AdminSessionAccess
)
from core.models import RequestContext

# ============================================================================
# Helper Objects
# ============================================================================

def create_mock_ctx(
    client_ip: str = "192.168.1.100",
    user_agent: str = "Mozilla/5.0",
    session_id: str = None
) -> RequestContext:
    """Create a test request context"""
    import uuid
    headers = {"user-agent": user_agent, "host": "example.com"}
    if session_id:
        headers["x-session-id"] = session_id

    return RequestContext(
        request_id=str(uuid.uuid4()),
        timestamp=time.time(),
        client_ip=client_ip,
        client_port=12345,
        server_ip="10.0.0.1",
        server_port=8080,
        method="GET",
        path="/",
        query_string="",
        headers=headers,
        body=b"",
    )

# ============================================================================
# Tests
# ============================================================================

class TestSecureSessionIDGenerator:
    def test_generate(self):
        sid = SecureSessionIDGenerator.generate()
        assert len(sid) >= 43
        assert isinstance(sid, str)

    def test_is_valid_format(self):
        sid = SecureSessionIDGenerator.generate()
        assert SecureSessionIDGenerator.is_valid_format(sid)
        assert not SecureSessionIDGenerator.is_valid_format("short")
        assert not SecureSessionIDGenerator.is_valid_format("invalid chars!!!^^")
        assert not SecureSessionIDGenerator.is_valid_format("")

    def test_hash_for_storage(self):
        sid = SecureSessionIDGenerator.generate()
        hashed = SecureSessionIDGenerator.hash_for_storage(sid)
        assert len(hashed) == 64  # SHA-256 length
        assert hashed != sid


class TestSessionBinding:
    def test_create(self):
        binding = SessionBinding.create("1.1.1.1", "fp1", "ua1")
        assert len(binding.ip_hash) == 32
        assert len(binding.fingerprint_hash) == 32
        assert len(binding.ua_hash) == 32

    def test_verify_success(self):
        binding = SessionBinding.create("1.1.1.1", "fp1", "ua1")
        is_valid, msg = binding.verify("1.1.1.1", "fp1", "ua1")
        assert is_valid
        assert msg == ""

    def test_verify_ip_mismatch(self):
        binding = SessionBinding.create("1.1.1.1", "fp1", "ua1")
        is_valid, msg = binding.verify("2.2.2.2", "fp1", "ua1")
        assert not is_valid
        assert "IP" in msg

    def test_verify_multiple_mismatch(self):
        binding = SessionBinding.create("1.1.1.1", "fp1", "ua1")
        is_valid, msg = binding.verify("2.2.2.2", "fp2", "ua1")
        assert not is_valid
        assert "IP" in msg
        assert "fingerprint" in msg

    def test_serialization(self):
        binding = SessionBinding.create("1.1.1.1", "fp1", "ua1")
        data = binding.to_dict()
        binding2 = SessionBinding.from_dict(data)
        assert binding.ip_hash == binding2.ip_hash


class TestSecureSession:
    def test_expiration_idle(self):
        binding = SessionBinding.create("1.1.1.1", "fp", "ua")
        session = SecureSession("hash", binding, time.time() - 4000, time.time() - 3601)
        assert session.is_expired()

    def test_expiration_absolute(self):
        binding = SessionBinding.create("1.1.1.1", "fp", "ua")
        session = SecureSession("hash", binding, time.time() - 86401, time.time())
        assert session.is_expired()

    def test_not_expired(self):
        binding = SessionBinding.create("1.1.1.1", "fp", "ua")
        session = SecureSession("hash", binding, time.time() - 100, time.time())
        assert not session.is_expired()

    def test_touch(self):
        binding = SessionBinding.create("1.1.1.1", "fp", "ua")
        session = SecureSession("hash", binding, time.time(), time.time() - 10)
        old_activity = session.last_activity

        session.touch()
        assert session.last_activity > old_activity
        assert session.request_count == 1


class TestSecureSessionManager:
    def setup_method(self):
        self.manager = SecureSessionManager()

    def test_create_session(self):
        sid, err = self.manager.create_session("1.1.1.1", "fp", "ua")
        assert sid is not None
        assert err == ""

        hashed = SecureSessionIDGenerator.hash_for_storage(sid)
        assert hashed in self.manager.sessions

    @patch('time.sleep')
    def test_validate_session_success(self, mock_sleep):
        sid, _ = self.manager.create_session("1.1.1.1", "fp", "ua")

        is_valid, session, err = self.manager.validate_session(sid, "1.1.1.1", "fp", "ua")
        assert is_valid
        assert session is not None
        mock_sleep.assert_not_called()

    @patch('time.sleep')
    def test_validate_session_not_found_timing(self, mock_sleep):
        sid = SecureSessionIDGenerator.generate()
        is_valid, session, err = self.manager.validate_session(sid, "1.1.1.1", "fp", "ua")
        assert not is_valid
        assert session is None
        mock_sleep.assert_called_once()

    @patch('threading.Thread')
    def test_validate_session_binding_mismatch(self, mock_thread):
        sid, _ = self.manager.create_session("1.1.1.1", "fp", "ua")

        is_valid, session, err = self.manager.validate_session(sid, "2.2.2.2", "fp", "ua")
        assert not is_valid
        mock_thread.assert_called_once()

    def test_get_or_create_session(self):
        ctx = create_mock_ctx()
        session = self.manager.get_or_create_session(ctx)
        assert session is not None

        # Test reuse
        ctx2 = create_mock_ctx(session_id="invalid")
        session2 = self.manager.get_or_create_session(ctx2)
        assert session2.session_id_hash != session.session_id_hash

    def test_session_rotation(self):
        sid, _ = self.manager.create_session("1.1.1.1", "fp", "ua")

        new_sid, err = self.manager.rotate_session(sid, "1.1.1.1", "fp", "ua")
        assert new_sid is not None
        assert new_sid != sid

        # old session should be invalid
        is_valid, _, _ = self.manager.validate_session(sid, "1.1.1.1", "fp", "ua")
        assert not is_valid

        # new session valid
        is_valid, _, _ = self.manager.validate_session(new_sid, "1.1.1.1", "fp", "ua")
        assert is_valid

    def test_get_session_stats_idor_protection(self):
        sid, _ = self.manager.create_session("1.1.1.1", "fp", "ua")

        # correct ip
        stats = self.manager.get_session_stats(sid, "1.1.1.1")
        assert stats is not None

        # wrong ip
        stats2 = self.manager.get_session_stats(sid, "2.2.2.2")
        assert stats2 is None


# ============================================================================
# Run Tests
# ============================================================================

def run_all_tests():
    """Run all tests and print summary"""
    import traceback

    test_classes = [
        TestSecureSessionIDGenerator,
        TestSessionBinding,
        TestSecureSession,
        TestSecureSessionManager,
    ]

    results = {"passed": 0, "failed": 0, "errors": []}

    print("\n" + "="*70)
    print("DECEPTICON Secure Session Test Suite")
    print("="*70 + "\n")

    for test_class in test_classes:
        print(f"\n🔍 Running {test_class.__name__}...")
        print("-" * 50)

        instance = test_class()
        # Some methods need setup
        has_setup = hasattr(instance, 'setup_method')

        methods = [m for m in dir(instance) if m.startswith("test_")]

        for method_name in methods:
            try:
                if has_setup:
                    instance.setup_method()
                method = getattr(instance, method_name)
                method()
                print(f"  ✅ {method_name}")
                results["passed"] += 1
            except AssertionError as e:
                print(f"  ❌ {method_name}: {e}")
                results["failed"] += 1
                results["errors"].append((test_class.__name__, method_name, str(e)))
            except Exception as e:
                print(f"  💥 {method_name}: {e}")
                results["failed"] += 1
                results["errors"].append((test_class.__name__, method_name, traceback.format_exc()))

    # Summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    print(f"  Passed: {results['passed']}")
    print(f"  Failed: {results['failed']}")
    print(f"  Total:  {results['passed'] + results['failed']}")

    if results["errors"]:
        print("\nFailures:")
        for cls, method, error in results["errors"]:
            print(f"  - {cls}.{method}")
            print(error)

    return results["failed"] == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
