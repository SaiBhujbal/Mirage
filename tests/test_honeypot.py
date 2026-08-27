"""
DECEPTICON Honeypot Test Suite
Tests deception, canary tokens, and tarpit components
"""
import time
import asyncio
import sys
import os
import json
import unittest.mock

# Mock missing dependencies
sys.modules['orjson'] = unittest.mock.MagicMock()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deception.honeypot import CanaryFactory, HoneypotRouter, Tarpit
from core.models import RequestContext, WAFResult, Action, RiskLevel, SessionState, Detection, DetectionSource

# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

def create_request_context(
    method: str = "GET",
    path: str = "/",
    query_string: str = "",
    body: str = "",
    headers: dict = None,
    client_ip: str = "192.168.1.100"
) -> RequestContext:
    import uuid
    return RequestContext(
        request_id=str(uuid.uuid4()),
        timestamp=time.time(),
        client_ip=client_ip,
        client_port=12345,
        server_ip="10.0.0.1",
        server_port=8080,
        method=method,
        path=path,
        query_string=query_string,
        headers=headers or {"user-agent": "Mozilla/5.0", "host": "example.com"},
        body=body.encode() if isinstance(body, str) else body,
    )

# ═══════════════════════════════════════════════════════════════════════════════
# CanaryFactory Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCanaryFactory:
    """Test the Canary Token generation and tracking"""

    def test_create_credential_token(self):
        factory = CanaryFactory()
        session_id = "test_session_1"
        username, password = factory.create_credential_token(session_id)

        assert username is not None
        assert password is not None

        token = factory.check_token(f"{username}:{password}")
        assert token is not None
        assert token.token_type == 'credential'
        assert token.created_for_session == session_id
        assert not token.triggered

    def test_create_dns_token(self):
        factory = CanaryFactory()
        session_id = "test_session_2"
        domain = factory.create_dns_token(session_id)

        assert domain.endswith(".canary.decepticon.local")
        token = factory.check_token(domain)
        assert token is not None
        assert token.token_type == 'dns'
        assert not token.triggered

    def test_create_url_token(self):
        factory = CanaryFactory()
        session_id = "test_session_3"
        url = factory.create_url_token(session_id)

        assert url.startswith("http")
        # Extract token_id from URL
        token_id = url.split('/')[-2]
        token = factory.check_token(token_id)
        assert token is not None
        assert token.token_type == 'url'

    def test_create_aws_key_token(self):
        factory = CanaryFactory()
        session_id = "test_session_4"
        access_key, secret_key = factory.create_aws_key_token(session_id)

        assert access_key.startswith("AKIA")
        assert len(access_key) == 20
        assert len(secret_key) == 40

        token = factory.check_token(access_key)
        assert token is not None
        assert token.token_type == 'aws_key'

    def test_trigger_and_get_tokens(self):
        factory = CanaryFactory()
        domain = factory.create_dns_token("session_trigger")
        token = factory.check_token(domain)

        context = {"path": "/trigger"}
        ip = "10.0.0.5"
        factory.trigger_token(token, ip, context)

        assert token.triggered
        assert token.triggered_from_ip == ip
        assert token.triggered_context == context

        triggered = factory.get_triggered_tokens()
        assert len(triggered) == 1
        assert triggered[0].token_value == domain

# ═══════════════════════════════════════════════════════════════════════════════
# HoneypotRouter Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHoneypotRouter:
    """Test the routing of traffic to honeypots and data capture"""

    def test_should_route_to_honeypot(self):
        router = HoneypotRouter()

        # Test High Risk routing
        result_high = WAFResult(request_id="1", action=Action.ALLOW, risk_level=RiskLevel.HIGH, detections=[], start_time=time.time())
        session_normal = SessionState(session_id="1", client_ip="1.1.1.1", first_seen=time.time(), last_seen=time.time())
        assert router.should_route_to_honeypot(result_high, session_normal)

        # Test suspicious session routing
        result_low = WAFResult(request_id="2", action=Action.ALLOW, risk_level=RiskLevel.LOW, detections=[], start_time=time.time())
        session_suspicious = SessionState(session_id="2", client_ip="2.2.2.2", first_seen=time.time(), last_seen=time.time(), blocked_count=3)
        assert router.should_route_to_honeypot(result_low, session_suspicious)

        # Test scanner behavior
        session_scanner = SessionState(session_id="3", client_ip="3.3.3.3", first_seen=time.time(), last_seen=time.time(), unique_paths=set(str(i) for i in range(51)), request_intervals=[0.1]*101, request_count=101)
        assert router.should_route_to_honeypot(result_low, session_scanner)

    def test_route_to_sqli_honeypot(self):
        router = HoneypotRouter()
        ctx = create_request_context(query_string="id=' OR 1=1--", method="GET")
        result = WAFResult(request_id="req_1", action=Action.HONEYPOT, risk_level=RiskLevel.HIGH, detections=[], start_time=time.time())

        response = router.route_to_honeypot(ctx, result, "SQLI")
        assert response['status'] == 200
        assert 'application/json' in response['headers']['Content-Type']
        body = json.loads(response['body'])
        assert body['status'] == 'success'
        assert len(body['results']) == 2

        # Ensure session intel is tracked
        intel = router.get_session_intel(result.honeypot_id)
        assert intel is not None
        assert "id=' OR 1=1--" in intel['payloads'][0]
        assert len(intel['canary_tokens']) > 0

    def test_route_to_xss_honeypot(self):
        router = HoneypotRouter()
        ctx = create_request_context(query_string="<script>alert(1)</script>", method="GET")
        result = WAFResult(request_id="req_2", action=Action.HONEYPOT, risk_level=RiskLevel.HIGH, detections=[], start_time=time.time())

        response = router.route_to_honeypot(ctx, result, "XSS")
        assert response['status'] == 200
        assert '<script src=' in response['body']

        payloads = router.get_captured_payloads(result.honeypot_id)
        assert "<script>alert(1)</script>" in payloads[0]

    def test_route_to_rce_honeypot(self):
        router = HoneypotRouter()
        ctx = create_request_context(query_string="; cat /etc/passwd", method="GET")
        result = WAFResult(request_id="req_3", action=Action.HONEYPOT, risk_level=RiskLevel.HIGH, detections=[], start_time=time.time())

        response = router.route_to_honeypot(ctx, result, "RCE")
        assert response['status'] == 200
        assert 'Command executed.' in response['body']
        assert '[Access Denied]' in response['body']

        intel = router.get_session_intel(result.honeypot_id)
        assert 'cat' in intel['commands'][0]

    def test_route_to_lfi_honeypot(self):
        router = HoneypotRouter()
        ctx = create_request_context(query_string="../../etc/shadow", method="GET")
        result = WAFResult(request_id="req_4", action=Action.HONEYPOT, risk_level=RiskLevel.HIGH, detections=[], start_time=time.time())

        response = router.route_to_honeypot(ctx, result, "LFI")
        assert response['status'] == 200
        assert 'root:x:0:0' in response['body']
        assert 'AWS Keys' in response['body']

        intel = router.get_session_intel(result.honeypot_id)
        assert 'etc/shadow' in intel['files'][0]

    def test_route_to_admin_honeypot(self):
        router = HoneypotRouter()
        ctx = create_request_context(method="POST", body="username=admin&password=Password123!")
        result = WAFResult(request_id="req_5", action=Action.HONEYPOT, risk_level=RiskLevel.HIGH, detections=[], start_time=time.time())

        response = router.route_to_honeypot(ctx, result, "ADMIN")
        assert response['status'] == 200
        body = json.loads(response['body'])
        assert body['message'] == 'Login successful'

        intel = router.get_session_intel(result.honeypot_id)
        assert ('admin', 'Password123!') in intel['credentials']

    def test_get_all_triggered_canaries(self):
        """Test aggregation of triggered canary tokens"""
        router = HoneypotRouter()
        session_id = "test_trigger_session"

        # 1. Create a token
        domain = router.canary_factory.create_dns_token(session_id)
        token = router.canary_factory.check_token(domain)
        assert token is not None

        # 2. Trigger the token
        trigger_ip = "203.0.113.5"
        trigger_context = {"path": "/admin/secret", "method": "GET"}
        router.canary_factory.trigger_token(token, trigger_ip, trigger_context)

        # 3. Retrieve all triggered tokens via router
        triggered_list = router.get_all_triggered_canaries()

        # 4. Verify result
        assert len(triggered_list) == 1
        triggered_data = triggered_list[0]

        assert triggered_data['token_id'] == token.token_id
        assert triggered_data['type'] == 'dns'
        assert triggered_data['created_for'] == session_id
        assert triggered_data['triggered_at'] is not None
        assert triggered_data['triggered_from'] == trigger_ip
        assert triggered_data['context'] == trigger_context

# ═══════════════════════════════════════════════════════════════════════════════
# Tarpit Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTarpit:
    """Test Tarpit functionality"""

    def test_generate_infinite_maze(self):
        response = Tarpit.generate_infinite_maze()
        assert response['status'] == 200
        assert 'application/json' in response['headers']['Content-Type']

        body = json.loads(response['body'])
        assert 'entries' in body
        assert len(body['entries']) > 0
        assert body['total'] == len(body['entries'])

        has_dir = any(e['type'] == 'directory' for e in body['entries'])
        has_file = any(e['type'] == 'file' for e in body['entries'])
        assert has_dir
        assert has_file

    def test_slow_response(self):
        async def run_slow_response():
            gen = Tarpit.slow_response(delay_ms=100) # Fast delay for testing
            chunks = []
            async for chunk in gen:
                chunks.append(chunk)
            return chunks

        chunks = asyncio.run(run_slow_response())
        assert len(chunks) > 100
        assert b"HTTP/1.1 200 OK\r\n" in chunks[0]
        assert b"0\r\n\r\n" in chunks[-1]


# ═══════════════════════════════════════════════════════════════════════════════
# Run Tests
# ═══════════════════════════════════════════════════════════════════════════════

def run_all_tests():
    """Run all tests and print summary"""
    import traceback

    test_classes = [
        TestCanaryFactory,
        TestHoneypotRouter,
        TestTarpit,
    ]

    results = {"passed": 0, "failed": 0, "errors": []}

    print("\n" + "="*70)
    print("DECEPTICON Honeypot Test Suite")
    print("="*70 + "\n")

    for test_class in test_classes:
        print(f"\n🔍 Running {test_class.__name__}...")
        print("-" * 50)

        instance = test_class()
        methods = [m for m in dir(instance) if m.startswith("test_")]

        for method_name in methods:
            try:
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
            print(f"    {error}")

    return results["failed"] == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
