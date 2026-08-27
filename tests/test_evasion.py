"""
MIRAGE ML Evasion Test Suite
Tests for adversarial ML attacks

Run with: pytest tests/test_evasion.py -v
"""
import pytest
pytest.importorskip("pydantic_settings")  # legacy suite dep — skip cleanly if not installed
import time
import random
import string
from typing import List

import sys
sys.path.insert(0, '.')

from core.waf_engine import waf_engine
from core.models import RequestContext, Action


class TestAdversarialML:
    """Test adversarial attacks against ML model"""
    
    def create_context(self, payload: str, method: str = "POST") -> RequestContext:
        return RequestContext(
            request_id=f"test-{time.time()}",
            timestamp=time.time(),
            client_ip="192.168.1.100",
            client_port=12345,
            server_ip="127.0.0.1",
            server_port=8080,
            method=method,
            path="/api/data",
            query_string="" if method == "POST" else payload,
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "content-type": "application/json",
            },
            body=payload.encode() if method == "POST" else b"",
        )
    
    def test_payload_with_normal_prefix(self):
        """Test malicious payload with normal-looking prefix"""
        prefixes = [
            "Thank you for your inquiry about our products. ",
            "Please find the requested information below: ",
            "Here is the data you requested: ",
        ]
        
        malicious = "'; DROP TABLE users;--"
        
        for prefix in prefixes:
            payload = prefix + malicious
            ctx = self.create_context(payload)
            result = waf_engine.analyze_request(ctx)
            
            print(f"Prefix attack: {len(result.detections)} detections")
    
    def test_payload_in_json_structure(self):
        """Test malicious payload hidden in JSON"""
        import json
        
        # Normal-looking JSON with malicious values
        payloads = [
            {"name": "John", "query": "' OR 1=1--"},
            {"data": "normal", "filter": "id=1; DROP TABLE users;"},
            {"search": "<script>alert(1)</script>"},
        ]
        
        for payload in payloads:
            json_payload = json.dumps(payload)
            ctx = self.create_context(json_payload)
            result = waf_engine.analyze_request(ctx)
            
            print(f"JSON hidden payload: {len(result.detections)} detections")
            assert len(result.detections) > 0, f"Should detect malicious JSON: {payload}"
    
    def test_gradual_probing(self):
        """Test gradual probing to find detection threshold"""
        # Gradually increase maliciousness
        probes = [
            "SELECT",
            "SELECT *",
            "SELECT * FROM",
            "SELECT * FROM users",
            "' SELECT * FROM users",
            "' OR SELECT * FROM users",
            "' OR 1=1; SELECT * FROM users--",
        ]
        
        detection_threshold = None
        for i, probe in enumerate(probes):
            ctx = self.create_context(f"query={probe}", method="GET")
            result = waf_engine.analyze_request(ctx)
            
            if len(result.detections) > 0:
                detection_threshold = i
                break
        
        print(f"Detection threshold at probe {detection_threshold}: {probes[detection_threshold] if detection_threshold else 'none'}")
    
    def test_feature_flooding(self):
        """Test flooding with many features to overwhelm analysis"""
        # Many parameters to analyze
        params = "&".join([f"param{i}=value{i}" for i in range(100)])
        params += "&evil=' OR 1=1--"
        
        ctx = self.create_context(params, method="GET")
        result = waf_engine.analyze_request(ctx)
        
        print(f"Feature flooding: {len(result.detections)} detections")
        assert len(result.detections) > 0, "Should detect despite many parameters"
    
    def test_entropy_manipulation(self):
        """Test payload designed to have normal entropy"""
        # High entropy (random) payload
        random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
        
        # Low entropy payload with attack
        low_entropy = "aaaaaa' OR 1=1--aaaaa"
        
        # Mix of both
        mixed = random_chars[:50] + "' OR 1=1--" + random_chars[50:]
        
        for name, payload in [("random", random_chars), ("low", low_entropy), ("mixed", mixed)]:
            ctx = self.create_context(payload)
            result = waf_engine.analyze_request(ctx)
            print(f"Entropy {name}: {len(result.detections)} detections")
    
    def test_polymorphic_payload(self):
        """Test polymorphic payloads that change each time"""
        def generate_sqli():
            variants = [
                "' OR {}={}--",
                "' OR '{}'='{}'",
                "' OR {} LIKE {}--",
            ]
            numbers = ['1', '2', '0', 'true', '1']
            template = random.choice(variants)
            n = random.choice(numbers)
            return template.format(n, n)
        
        detected = 0
        for _ in range(10):
            payload = generate_sqli()
            ctx = self.create_context(f"id={payload}", method="GET")
            result = waf_engine.analyze_request(ctx)
            if len(result.detections) > 0:
                detected += 1
        
        print(f"Polymorphic detection: {detected}/10")
        assert detected >= 5, "Should detect at least half of polymorphic payloads"
    
    def test_time_based_evasion(self):
        """Test if timing affects detection (it shouldn't)"""
        payload = "' OR 1=1--"
        
        # Fast sequence
        fast_results = []
        for _ in range(5):
            ctx = self.create_context(f"id={payload}", method="GET")
            result = waf_engine.analyze_request(ctx)
            fast_results.append(len(result.detections) > 0)
        
        time.sleep(1)
        
        # Slow sequence
        slow_results = []
        for _ in range(5):
            ctx = self.create_context(f"id={payload}", method="GET")
            result = waf_engine.analyze_request(ctx)
            slow_results.append(len(result.detections) > 0)
            time.sleep(0.5)
        
        assert fast_results == slow_results, "Detection should be consistent regardless of timing"


class TestAutoRulePoisoning:
    """Test auto-rule poisoning attacks"""
    
    def test_false_positive_injection(self):
        """Test if attacker can trigger rules that cause FPs"""
        from core.rule_generator import rule_generator
        
        # Simulate ML detecting a benign-looking pattern
        benign_patterns = [
            "SELECT",
            "password",
            "admin",
            "login",
        ]
        
        # These shouldn't generate blocking rules
        for pattern in benign_patterns:
            ctx = RequestContext(
                request_id="fp-test",
                timestamp=time.time(),
                client_ip="10.0.0.1",
                client_port=12345,
            server_ip="127.0.0.1",
            server_port=8080,
                method="GET",
                path="/search",
                query_string=f"q={pattern}",
                headers={},
                body=b"",
            )
            
            result = waf_engine.analyze_request(ctx)
            
            # Should NOT block benign patterns
            assert result.action <= Action.MONITOR, f"Should not block benign: {pattern}"
    
    def test_rule_staging(self):
        """Test that rules go through staging"""
        from core.security_hardening import model_protection
        
        # Stage a rule
        model_protection.stage_rule(
            rule_id="TEST-001",
            pattern="test_pattern",
            category="SQLI",
            source="ml",
            confidence=0.8
        )
        
        # Should not be in production yet
        prod_rules = model_protection.get_production_rules()
        assert not any(r["rule_id"] == "TEST-001" for r in prod_rules), \
            "Rule should not be in production immediately"
        
        # Approve rule
        model_protection.approve_rule("TEST-001", "admin")
        
        # Now should be in production
        prod_rules = model_protection.get_production_rules()
        assert any(r["rule_id"] == "TEST-001" for r in prod_rules), \
            "Approved rule should be in production"


class TestFeatureExtraction:
    """Test feature extraction robustness"""
    
    def test_unicode_handling(self):
        """Test that Unicode doesn't break feature extraction"""
        payloads = [
            "测试' OR 1=1--",  # Chinese
            "тест' OR 1=1--",  # Russian
            "🎯' OR 1=1--",    # Emoji
            "café' OR 1=1--",  # Accented
        ]
        
        for payload in payloads:
            ctx = RequestContext(
                request_id="unicode-test",
                timestamp=time.time(),
                client_ip="10.0.0.1",
                client_port=12345,
            server_ip="127.0.0.1",
            server_port=8080,
                method="GET",
                path="/test",
                query_string=f"q={payload}",
                headers={},
                body=b"",
            )
            
            # Should not crash
            try:
                result = waf_engine.analyze_request(ctx)
                print(f"Unicode payload: {len(result.detections)} detections")
            except Exception as e:
                pytest.fail(f"Unicode handling failed: {e}")
    
    def test_large_payload_handling(self):
        """Test handling of large payloads"""
        # 100KB payload
        large_payload = "A" * 100000 + "' OR 1=1--"
        
        ctx = RequestContext(
            request_id="large-test",
            timestamp=time.time(),
            client_ip="10.0.0.1",
            client_port=12345,
            server_ip="127.0.0.1",
            server_port=8080,
            method="POST",
            path="/upload",
            query_string="",
            headers={"content-type": "text/plain"},
            body=large_payload.encode(),
        )
        
        start = time.time()
        result = waf_engine.analyze_request(ctx)
        elapsed = time.time() - start
        
        print(f"Large payload: {elapsed:.3f}s, {len(result.detections)} detections")
        assert elapsed < 5.0, "Should process large payload in <5 seconds"
    
    def test_binary_payload(self):
        """Test handling of binary data"""
        # Binary with embedded attack
        binary = b"\x00\x01\x02" + b"' OR 1=1--" + b"\x03\x04\x05"
        
        ctx = RequestContext(
            request_id="binary-test",
            timestamp=time.time(),
            client_ip="10.0.0.1",
            client_port=12345,
            server_ip="127.0.0.1",
            server_port=8080,
            method="POST",
            path="/upload",
            query_string="",
            headers={"content-type": "application/octet-stream"},
            body=binary,
        )
        
        # Should not crash
        try:
            result = waf_engine.analyze_request(ctx)
            print(f"Binary payload: {len(result.detections)} detections")
        except Exception as e:
            pytest.fail(f"Binary handling failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
