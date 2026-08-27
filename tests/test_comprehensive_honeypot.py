import sys
import os
import time
import json
import unittest
import pytest
pytest.importorskip("orjson")  # legacy suite dep — skip cleanly if not installed

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import RequestContext
from deception.comprehensive_honeypot import ComprehensiveHoneypot, AttackerProfile, CanaryToken

def create_mock_context(client_ip="192.168.1.100", method="POST", path="/api/test",
                 query_string="", body_str="", headers=None) -> RequestContext:
    ctx = RequestContext(
        request_id="test_req_id",
        timestamp=time.time(),
        client_ip=client_ip,
        client_port=12345,
        server_ip="10.0.0.1",
        server_port=8080,
        method=method,
        path=path,
        query_string=query_string,
        headers=headers or {"user-agent": "Mozilla/5.0"},
        body=body_str.encode() if isinstance(body_str, str) else body_str,
    )
    return ctx

class TestComprehensiveHoneypot(unittest.TestCase):

    def setUp(self):
        self.honeypot = ComprehensiveHoneypot(callback_domain="test.canary.local")
        self.ctx = create_mock_context(
            query_string="id=1' OR '1'='1",
            body_str='{"test": "payload"}',
            headers={'user-agent': 'sqlmap/1.6'}
        )

    def test_canary_creation_and_checking(self):
        # Create a canary
        canary_value = self.honeypot._create_canary('sqli', 'session_123', 'credential')

        # Verify it exists and can be checked
        canary = self.honeypot.check_canary(canary_value)
        self.assertIsNotNone(canary)
        self.assertEqual(canary.attack_type, 'sqli')
        self.assertEqual(canary.session_id, 'session_123')
        self.assertEqual(canary.token_type, 'credential')
        self.assertFalse(canary.triggered)

    def test_canary_triggering(self):
        canary_value = self.honeypot._create_canary('xss', 'session_456', 'dns')
        canary = self.honeypot.check_canary(canary_value)

        # Trigger it
        self.honeypot.trigger_canary(canary.token_id, {"source_ip": "10.0.0.5"})

        # Verify
        self.assertTrue(canary.triggered)
        self.assertIsNotNone(canary.triggered_at)
        self.assertEqual(canary.triggered_context, {"source_ip": "10.0.0.5"})

        # Ensure it appears in triggered list
        triggered = self.honeypot.get_triggered_canaries()
        self.assertEqual(len(triggered), 1)
        self.assertEqual(triggered[0].token_id, canary.token_id)

    def test_attacker_profiling(self):
        # Initial request
        self.honeypot.generate_response(self.ctx, 'sqli')

        profile = self.honeypot.get_attacker_profile(self.ctx.client_ip)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.total_requests, 1)
        self.assertIn('sqli', profile.attack_types)
        self.assertIn('sqlmap', profile.tools_detected)  # sqlmap was in user-agent

        # Another request from same IP, different attack
        ctx2 = create_mock_context(client_ip=self.ctx.client_ip, query_string="<script>alert(1)</script>")
        self.honeypot.generate_response(ctx2, 'xss')

        profile = self.honeypot.get_attacker_profile(self.ctx.client_ip)
        self.assertEqual(profile.total_requests, 2)
        self.assertIn('xss', profile.attack_types)
        self.assertTrue(profile.sophistication_score > 0)

    def test_payload_capture(self):
        self.honeypot.generate_response(self.ctx, 'sqli')

        payloads = self.honeypot.get_captured_payloads()
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]['attack_type'], 'sqli')
        self.assertEqual(payloads[0]['client_ip'], self.ctx.client_ip)

        sqli_payloads = self.honeypot.get_captured_payloads(attack_type='sqli')
        self.assertEqual(len(sqli_payloads), 1)

        xss_payloads = self.honeypot.get_captured_payloads(attack_type='xss')
        self.assertEqual(len(xss_payloads), 0)

    def test_sqli_response(self):
        response = self.honeypot.generate_response(self.ctx, 'sqli')
        self.assertEqual(response['status'], 200)
        self.assertIn('application/json', response['headers']['Content-Type'])
        self.assertIn('X-Request-ID', response['headers'])

        body = json.loads(response['body'])
        self.assertEqual(body['status'], 'success')
        self.assertIn('users', body['query'])
        self.assertTrue(len(body['results']) > 0)

    def test_xss_response(self):
        response = self.honeypot.generate_response(self.ctx, 'xss')
        self.assertEqual(response['status'], 200)
        self.assertIn('text/html', response['headers']['Content-Type'])
        self.assertIn('test.canary.local', response['body'])

    def test_rce_response(self):
        ctx = create_mock_context(query_string="cat /etc/passwd")
        response = self.honeypot.generate_response(ctx, 'rce')
        self.assertEqual(response['status'], 200)
        self.assertIn('Command output:', response['body'])
        self.assertIn('DB_HOST=', response['body']) # Result of fake 'cat' command

    def test_lfi_response(self):
        ctx = create_mock_context(query_string="../../../etc/passwd")
        response = self.honeypot.generate_response(ctx, 'lfi')
        self.assertEqual(response['status'], 200)
        self.assertIn('root:x:0:0:', response['body'])

        ctx2 = create_mock_context(query_string=".env")
        response2 = self.honeypot.generate_response(ctx2, 'lfi')
        self.assertIn('AWS_ACCESS_KEY_ID', response2['body'])

    def test_zero_day_unknown_attack(self):
        """Rigorous Zero-Day attack testing for unknown/unmapped attack types"""
        zero_day_payload = "NEW_EXPLOIT_PAYLOAD_0xdeadbeef\x00\x01\x02"
        ctx = create_mock_context(
            client_ip="10.10.10.10",
            query_string=zero_day_payload,
            headers={"user-agent": "UnknownScanner/1.0"}
        )

        # Use an unknown attack type identifier to simulate a zero-day categorization
        # or an entirely new detection by the ML/Anomaly engine
        attack_type = "UNKNOWN_ZERO_DAY_EXPLOIT"

        response = self.honeypot.generate_response(ctx, attack_type)

        # Verify default fallback response is used safely
        self.assertEqual(response['status'], 200)
        body = json.loads(response['body'])
        self.assertEqual(body['status'], 'success')
        self.assertEqual(body['message'], 'Request processed')

        # Verify the attacker profile is created/updated properly
        profile = self.honeypot.get_attacker_profile("10.10.10.10")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.total_requests, 1)
        self.assertIn(attack_type, profile.attack_types)

        # Verify the zero-day payload is captured
        payloads = self.honeypot.get_captured_payloads(attack_type=attack_type)
        self.assertEqual(len(payloads), 1)
        self.assertIn(zero_day_payload[:200], payloads[0]['query'])

    def test_statistics(self):
        self.honeypot.generate_response(self.ctx, 'sqli')
        ctx_xss = create_mock_context(client_ip="192.168.1.101", query_string="<script>")
        self.honeypot.generate_response(ctx_xss, 'xss')

        stats = self.honeypot.get_statistics()
        self.assertEqual(stats['total_attackers'], 2)
        self.assertGreater(stats['total_canaries'], 0)
        self.assertEqual(stats['captured_payloads'], 2)
        self.assertIn('sqli', stats['attack_type_distribution'])
        self.assertIn('xss', stats['attack_type_distribution'])

if __name__ == '__main__':
    unittest.main()
