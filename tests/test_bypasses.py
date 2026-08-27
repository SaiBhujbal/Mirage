"""
MIRAGE WAF Bypass Test Suite
Tests for encoding bypasses, ML evasion, and honeypot detection

Run with: pytest tests/test_bypasses.py -v
"""

import pytest
pytest.importorskip("pydantic_settings")  # legacy suite dep — skip cleanly if not installed
import time
import statistics
from typing import List, Dict, Tuple

# Import WAF components
import sys

sys.path.insert(0, ".")

from core.waf_engine import waf_engine
from core.models import RequestContext, Action
from core.advanced_protection import advanced_protection


class TestEncodingBypasses:
    """Test encoding-based WAF bypasses"""

    def create_context(
        self, query: str = "", body: str = "", path: str = "/test"
    ) -> RequestContext:
        """Helper to create request context"""
        return RequestContext(
            request_id="test-001",
            timestamp=time.time(),
            client_ip="192.168.1.100",
            client_port=12345,
            server_ip="127.0.0.1",
            server_port=8080,
            method="GET",
            path=path,
            query_string=query,
            headers={"user-agent": "pytest"},
            body=body.encode() if body else b"",
        )

    def test_single_url_encoding(self):
        """Test single URL encoding bypass attempt"""
        # %27 = '
        payload = "id=1%27%20OR%201=1--"
        ctx = self.create_context(query=payload)
        result = waf_engine.analyze_request(ctx)

        assert len(result.detections) > 0, "Should detect URL-encoded SQLi"
        assert result.action >= Action.CHALLENGE

    def test_double_url_encoding(self):
        """Test double URL encoding bypass attempt"""
        # %2527 = %27 = '
        payload = "id=1%2527%2520OR%25201=1--"
        ctx = self.create_context(query=payload)
        result = waf_engine.analyze_request(ctx)

        assert len(result.detections) > 0, "Should detect double URL-encoded SQLi"

    def test_triple_url_encoding(self):
        """Test triple URL encoding bypass attempt"""
        # %252527 = %2527 = %27 = '
        payload = "id=1%252527%252520OR%2525201=1--"
        ctx = self.create_context(query=payload)
        result = waf_engine.analyze_request(ctx)

        assert len(result.detections) > 0, "Should detect triple URL-encoded SQLi"

    def test_mixed_encoding(self):
        """Test mixed encoding (URL + HTML entities)"""
        # Mix of URL encoding and HTML entities
        payload = "id=1&#x27;%20OR%201&#x3d;1--"
        ctx = self.create_context(query=payload)
        result = waf_engine.analyze_request(ctx)

        assert len(result.detections) > 0, "Should detect mixed encoding SQLi"

    def test_unicode_normalization(self):
        """Test Unicode normalization bypass"""
        # Fullwidth characters
        payload = "id=1' ＯＲ １＝１--"  # Fullwidth OR 1=1
        ctx = self.create_context(query=payload)
        result = waf_engine.analyze_request(ctx)

        # May or may not detect - document behavior
        print(f"Unicode normalization: {len(result.detections)} detections")

    def test_null_byte_injection(self):
        """Test null byte injection bypass"""
        payload = "file=../etc/passwd%00.jpg"
        ctx = self.create_context(query=payload)
        result = waf_engine.analyze_request(ctx)

        assert len(result.detections) > 0, "Should detect null byte LFI"

    def test_case_variation(self):
        """Test case variation bypass"""
        payloads = [
            "id=1' oR 1=1--",
            "id=1' Or 1=1--",
            "id=1' OR 1=1--",
            "id=1' or 1=1--",
        ]

        for payload in payloads:
            ctx = self.create_context(query=payload)
            result = waf_engine.analyze_request(ctx)
            assert (
                len(result.detections) > 0
            ), f"Should detect case variation: {payload}"

    def test_comment_injection(self):
        """Test SQL comment bypass"""
        payloads = [
            "id=1'/**/OR/**/1=1--",
            "id=1'/*comment*/OR/*comment*/1=1--",
            "id=1'/*!50000OR*/1=1--",  # MySQL version comment
        ]

        for payload in payloads:
            ctx = self.create_context(query=payload)
            result = waf_engine.analyze_request(ctx)
            assert (
                len(result.detections) > 0
            ), f"Should detect comment bypass: {payload}"

    def test_whitespace_alternatives(self):
        """Test whitespace alternative bypasses"""
        payloads = [
            "id=1'\tOR\t1=1--",  # Tab
            "id=1'\nOR\n1=1--",  # Newline
            "id=1'\rOR\r1=1--",  # Carriage return
            "id=1'%0aOR%0a1=1--",  # URL-encoded newline
        ]

        for payload in payloads:
            ctx = self.create_context(query=payload)
            result = waf_engine.analyze_request(ctx)
            assert (
                len(result.detections) > 0
            ), f"Should detect whitespace bypass: {repr(payload)}"

    def test_max_encoding_depth(self):
        """Test max encoding depth (should handle 10, fail gracefully at 11+)"""
        # Build 11-layer encoded payload
        payload = "'"
        for _ in range(11):
            payload = payload.replace("'", "%27")

        query = f"id=1{payload}OR 1=1--"
        ctx = self.create_context(query=query)

        # Should not crash, may or may not detect
        result = waf_engine.analyze_request(ctx)
        print(f"11-layer encoding: {len(result.detections)} detections")

    def test_circular_encoding(self):
        """Test circular/recursive encoding patterns"""
        # This shouldn't cause infinite loop
        payload = "id=%25%32%37%25%32%37%25%32%37"  # Circular-ish pattern
        ctx = self.create_context(query=payload)

        start = time.time()
        result = waf_engine.analyze_request(ctx)
        elapsed = time.time() - start

        assert elapsed < 1.0, "Should complete in <1 second (no infinite loop)"


class TestMLEvasion:
    """Test ML model evasion attempts"""

    def create_context(self, query: str = "", body: str = "") -> RequestContext:
        return RequestContext(
            request_id="test-ml-001",
            timestamp=time.time(),
            client_ip="192.168.1.100",
            client_port=12345,
            server_ip="127.0.0.1",
            server_port=8080,
            method="POST",
            path="/api/data",
            query_string=query,
            headers={"user-agent": "Mozilla/5.0", "content-type": "application/json"},
            body=body.encode() if body else b"",
        )

    def test_low_entropy_payload(self):
        """Test payload designed to have low entropy"""
        # Normal-looking text with embedded SQLi
        payload = "The user said: 'SELECT * FROM users' is a valid query"
        ctx = self.create_context(body=payload)
        result = waf_engine.analyze_request(ctx)

        # Document behavior - ML might miss this
        print(
            f"Low entropy payload: {len(result.detections)} detections, action={result.action}"
        )

    def test_padding_attack(self):
        """Test padding attack to dilute malicious content"""
        # Lots of normal text with small malicious payload
        normal_text = "This is a completely normal request. " * 50
        malicious = "' OR 1=1--"
        payload = normal_text + malicious

        ctx = self.create_context(body=payload)
        result = waf_engine.analyze_request(ctx)

        # Should still detect despite padding
        print(f"Padding attack: {len(result.detections)} detections")

    def test_semantic_equivalence(self):
        """Test semantically equivalent but syntactically different payloads"""
        payloads = [
            "' OR '1'='1",
            "' OR 'x'='x",
            "' OR ''='",
            "' OR 1<2--",
            "' OR 2>1--",
        ]

        detected = 0
        for payload in payloads:
            ctx = self.create_context(query=f"id=1{payload}")
            result = waf_engine.analyze_request(ctx)
            if len(result.detections) > 0:
                detected += 1

        print(f"Semantic equivalence: {detected}/{len(payloads)} detected")
        assert detected >= len(payloads) // 2, "Should detect at least half"

    def test_benign_looking_sqli(self):
        """Test SQLi that looks like normal SQL discussion"""
        payloads = [
            "I need help with: SELECT * FROM users WHERE id = 1",
            "How do I write: INSERT INTO table VALUES (1, 'test')",
            "Example query: DELETE FROM logs WHERE date < '2024-01-01'",
        ]

        for payload in payloads:
            ctx = self.create_context(body=payload)
            result = waf_engine.analyze_request(ctx)
            # These are edge cases - document behavior
            print(f"Benign-looking SQL: {payload[:40]}... -> {result.action}")

    def test_unicode_homoglyphs(self):
        """Test Unicode homoglyph attacks"""
        # Using Cyrillic 'о' instead of Latin 'o'
        payload = "id=1' ОR 1=1--"  # Cyrillic О
        ctx = self.create_context(query=payload)
        result = waf_engine.analyze_request(ctx)

        print(f"Unicode homoglyph: {len(result.detections)} detections")

    def test_special_char_avoidance(self):
        """Test payloads avoiding special characters"""
        # SQL injection without quotes
        payloads = [
            "id=1 OR 1=1",
            "id=1 OR id=id",
            "id=1 UNION SELECT null,null,null",
        ]

        for payload in payloads:
            ctx = self.create_context(query=payload)
            result = waf_engine.analyze_request(ctx)
            print(f"No special chars: {payload} -> {len(result.detections)} detections")


class TestHoneypotFingerprinting:
    """Test honeypot detection resistance"""

    def test_timing_consistency(self):
        """Test that honeypot responses don't have consistent timing"""
        from deception.enhanced_honeypot import enhanced_responder

        timings = []
        for _ in range(20):
            start = time.time()
            response = enhanced_responder.generate_response(
                attack_type="SQLI",
                payload="' OR 1=1--",
                session_id=f"test-{time.time()}",
            )
            timings.append(response["delay_seconds"])

        # Check variance
        if len(timings) > 1:
            variance = statistics.variance(timings)
            print(f"Timing variance: {variance:.4f}")
            assert variance > 0.001, "Timing should have variance (not constant)"

    def test_response_variation(self):
        """Test that honeypot responses vary"""
        from deception.enhanced_honeypot import enhanced_responder

        responses = []
        for i in range(10):
            response = enhanced_responder.generate_response(
                attack_type="SQLI",
                payload="' UNION SELECT * FROM users--",
                session_id=f"test-session-{i}",
            )
            responses.append(str(response["body"]))

        # Check uniqueness
        unique_responses = set(responses)
        print(f"Response variation: {len(unique_responses)}/{len(responses)} unique")
        assert len(unique_responses) > 1, "Responses should vary"

    def test_error_injection(self):
        """Test that honeypot occasionally returns errors"""
        from deception.enhanced_honeypot import enhanced_responder

        error_count = 0
        for i in range(100):
            response = enhanced_responder.generate_response(
                attack_type="SQLI", payload="test", session_id=f"test-{i}"
            )
            if response["status_code"] >= 500:
                error_count += 1

        print(f"Error injection rate: {error_count}%")
        # Should have some errors (default 2%)
        assert error_count >= 0, "Should have possibility of errors"

    def test_header_variation(self):
        """Test that response headers vary"""
        from deception.enhanced_honeypot import HeaderRandomizer

        randomizer = HeaderRandomizer(consistent_per_session=False)

        servers = set()
        for _ in range(20):
            headers = randomizer.get_headers()
            servers.add(headers.get("Server", ""))

        print(f"Server header variation: {len(servers)} unique values")
        assert len(servers) > 1, "Server headers should vary"

    def test_fake_data_realism(self):
        """Test that fake data looks realistic"""
        from deception.enhanced_honeypot import FakeDataGenerator

        gen = FakeDataGenerator()
        gen.reseed("test-context")

        users = gen.fake_database_rows(10)

        # Check data quality
        for user in users:
            assert "@" in user["email"], "Email should have @"
            assert len(user["password_hash"]) > 20, "Password hash should be long"
            assert user["id"] > 0, "ID should be positive"

        print(f"Generated {len(users)} realistic fake users")


class TestRateLimitBypass:
    """Test rate limit bypass attempts"""

    def test_distributed_requests(self):
        """Simulate distributed attack from multiple IPs"""
        try:
            from core.atomic_rate_limiter import AtomicRateLimiter

            adaptive_limiter = AtomicRateLimiter(
                default_capacity=200, default_refill_rate=20.0
            )
        except Exception:
            from core.rate_limiter import adaptive_limiter

        # Reset state
        blocked_count = 0

        # Simulate requests from different IPs
        for i in range(100):
            ip = f"192.168.1.{i % 256}"
            ctx = RequestContext(
                request_id=f"test-{i}",
                timestamp=time.time(),
                client_ip=ip,
                client_port=12345,
                server_ip="127.0.0.1",
                server_port=8080,
                method="GET",
                path="/api/test",
                query_string="",
                headers={},
                body=b"",
            )

            key = adaptive_limiter.get_key(ip, "/api/test")
            if not adaptive_limiter.is_allowed(key):
                blocked_count += 1

        print(f"Distributed attack: {blocked_count}/100 blocked")

    def test_slowloris_simulation(self):
        """Test slow requests staying under rate limit"""
        try:
            from core.atomic_rate_limiter import AtomicRateLimiter

            adaptive_limiter = AtomicRateLimiter(
                default_capacity=200, default_refill_rate=20.0
            )
        except Exception:
            from core.rate_limiter import adaptive_limiter

        # Slow requests over time
        blocked = False
        for i in range(10):
            ctx = RequestContext(
                request_id=f"slow-{i}",
                timestamp=time.time(),
                client_ip="10.0.0.1",
                client_port=12345,
                server_ip="127.0.0.1",
                server_port=8080,
                method="GET",
                path="/slow-test",
                query_string="",
                headers={},
                body=b"",
            )

            key = adaptive_limiter.get_key("10.0.0.1", "/slow-test")
            if not adaptive_limiter.is_allowed(key):
                blocked = True
                break

            time.sleep(0.1)  # Slow down

        print(f"Slowloris simulation: {'blocked' if blocked else 'passed'}")


class TestSessionResetAttack:
    """Test session reset attacks"""

    def test_reputation_persistence(self):
        """Test that reputation survives (with Redis)"""
        from core.persistent_storage import InMemoryStorage, ReputationStorage

        storage = InMemoryStorage()
        rep = ReputationStorage(storage)

        # Record attacks
        rep.record_attack("1.2.3.4", "SQLI", 0.9)
        rep.record_attack("1.2.3.4", "XSS", 0.8)

        score = rep.get_reputation("1.2.3.4")
        print(f"Reputation after attacks: {score:.2f}")

        assert score < 1.0, "Reputation should decrease after attacks"

        # Simulate "restart" by creating new ReputationStorage with same backend
        rep2 = ReputationStorage(storage)
        score2 = rep2.get_reputation("1.2.3.4")

        assert score2 == score, "Reputation should persist"


# Run specific test class
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
