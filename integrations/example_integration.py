#!/usr/bin/env python3
"""
Example Integration: MIRAGE ML with Custom WAF
Demonstrates how to integrate MIRAGE ML module with any WAF
"""

import requests
import time
from typing import Dict, Tuple

class MirageMLClient:
    """
    Client for integrating with MIRAGE ML API

    Usage:
        client = MirageMLClient(api_url="http://localhost:5000")
        action, details = client.analyze_request(
            method="GET",
            path="/api/users",
            query="?id=1 OR 1=1--",
            headers={"user-agent": "Mozilla/5.0"},
            source_ip="192.168.1.100"
        )

        if action == "block":
            return 403, f"Attack detected: {details['category']}"
    """

    def __init__(self, api_url: str = "http://localhost:5000", timeout: float = 0.1):
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()  # Connection pooling

    def analyze_request(self, method: str, path: str, query: str = "",
                       body: str = "", headers: Dict = None,
                       source_ip: str = "unknown") -> Tuple[str, Dict]:
        """
        Analyze HTTP request with MIRAGE ML

        Returns:
            (action, details) where action is "allow", "block", or "challenge"
        """

        if headers is None:
            headers = {}

        try:
            payload = {
                "method": method,
                "path": path,
                "query": query,
                "body": body,
                "headers": headers,
                "source_ip": source_ip
            }

            response = self.session.post(
                f"{self.api_url}/api/waf/analyze",
                json=payload,
                timeout=self.timeout
            )

            if response.status_code != 200:
                # Fail open on API error
                return "allow", {"error": "API error", "fail_open": True}

            result = response.json()

            return result.get("recommended_action", "allow"), result

        except requests.exceptions.Timeout:
            # Fail open on timeout
            return "allow", {"error": "timeout", "fail_open": True}

        except Exception as e:
            # Fail open on any error
            return "allow", {"error": str(e), "fail_open": True}

    def analyze_batch(self, requests_list: list) -> Dict:
        """Analyze multiple requests in batch"""

        try:
            response = self.session.post(
                f"{self.api_url}/api/waf/analyze/batch",
                json={"requests": requests_list},
                timeout=1.0  # Longer timeout for batch
            )

            return response.json()

        except Exception as e:
            return {"error": str(e), "results": []}

    def report_false_positive(self, payload: str, detected_category: str,
                             actual_category: str = "benign", notes: str = ""):
        """Report a false positive"""

        try:
            response = self.session.post(
                f"{self.api_url}/api/v1/feedback",
                json={
                    "payload": payload,
                    "detected_category": detected_category,
                    "actual_category": actual_category,
                    "feedback_type": "false_positive",
                    "notes": notes
                },
                timeout=1.0
            )

            return response.json()

        except Exception as e:
            return {"error": str(e)}

    def get_baseline(self) -> Dict:
        """Get baseline statistics"""

        try:
            response = self.session.get(
                f"{self.api_url}/api/v1/baseline",
                timeout=1.0
            )

            return response.json()

        except Exception as e:
            return {"error": str(e)}

    def health_check(self) -> bool:
        """Check if API is healthy"""

        try:
            response = self.session.get(
                f"{self.api_url}/api/v1/health",
                timeout=1.0
            )

            return response.json().get("status") == "healthy"

        except:
            return False


# ============================================================================
# Example WAF Integration
# ============================================================================

class CustomWAF:
    """
    Example custom WAF using MIRAGE ML
    This demonstrates how to integrate ML into your WAF
    """

    def __init__(self):
        self.ml_client = MirageMLClient()
        self.blocked_count = 0
        self.allowed_count = 0

        # Check ML API health
        if not self.ml_client.health_check():
            print("⚠️ WARNING: MIRAGE ML API is not responding")
            print("   Falling back to rule-based detection only")

    def process_request(self, method: str, path: str, query: str = "",
                       headers: Dict = None, source_ip: str = "unknown") -> Tuple[int, str]:
        """
        Process HTTP request

        Returns:
            (status_code, message)
        """

        # 1. Call MIRAGE ML
        action, details = self.ml_client.analyze_request(
            method=method,
            path=path,
            query=query,
            headers=headers or {},
            source_ip=source_ip
        )

        # 2. Make decision
        if action == "block":
            self.blocked_count += 1
            category = details.get('category', 'unknown')
            confidence = details.get('confidence', 0)

            return 403, f"❌ BLOCKED: {category.upper()} attack detected (confidence: {confidence:.0%})"

        elif action == "challenge":
            return 429, "⚠️ CHALLENGE: Please complete CAPTCHA verification"

        else:  # allow
            self.allowed_count += 1

            # Check if fail-open (API error)
            if details.get('fail_open'):
                return 200, f"✅ ALLOWED (fail-open: {details.get('error')})"

            return 200, "✅ ALLOWED"

    def get_statistics(self) -> Dict:
        """Get WAF statistics"""

        baseline = self.ml_client.get_baseline()

        return {
            "requests_blocked": self.blocked_count,
            "requests_allowed": self.allowed_count,
            "total_requests": self.blocked_count + self.allowed_count,
            "block_rate": self.blocked_count / (self.blocked_count + self.allowed_count)
                         if (self.blocked_count + self.allowed_count) > 0 else 0,
            "ml_baseline": baseline
        }


# ============================================================================
# Test Cases
# ============================================================================

def test_integration():
    """Test MIRAGE ML integration"""

    print("="*70)
    print("MIRAGE ML Integration Test")
    print("="*70)
    print()

    # Initialize WAF
    waf = CustomWAF()

    # Test cases
    test_cases = [
        # (name, method, path, query, expected_action)
        ("Benign Request", "GET", "/api/users", "?page=1", "allow"),
        ("SQLi Attack", "GET", "/api/users", "?id=1 OR 1=1--", "block"),
        ("XSS Attack", "POST", "/comment", "", "block"),  # body would contain <script>
        ("Path Traversal", "GET", "/files", "?path=../../../etc/passwd", "block"),
        ("Normal Login", "POST", "/api/login", "", "allow"),
        ("RCE Attempt", "GET", "/api/exec", "?cmd=; cat /etc/passwd", "block"),
    ]

    print("Running test cases...\n")

    for name, method, path, query, expected in test_cases:
        status, message = waf.process_request(
            method=method,
            path=path,
            query=query,
            headers={"user-agent": "Mozilla/5.0"},
            source_ip="192.168.1.100"
        )

        # Determine actual action
        if status == 403:
            actual = "block"
        elif status == 429:
            actual = "challenge"
        else:
            actual = "allow"

        # Check if expected
        result = "✓" if actual == expected else "✗"

        print(f"{result} {name:20s}: {message}")

    print()
    print("="*70)
    print("Statistics")
    print("="*70)

    stats = waf.get_statistics()
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Blocked: {stats['requests_blocked']}")
    print(f"Allowed: {stats['requests_allowed']}")
    print(f"Block Rate: {stats['block_rate']:.1%}")

    print()
    print("ML Baseline:")
    baseline = stats.get('ml_baseline', {})
    if 'baseline' in baseline:
        print(f"  Normal Requests/Hour: {baseline['baseline'].get('normal_requests_per_hour', 'N/A')}")
        print(f"  Anomalies (Last Hour): {baseline['anomalies'].get('last_hour', 'N/A')}")

    print()
    print("="*70)
    print("Integration Test Complete!")
    print("="*70)


# ============================================================================
# Middleware Examples
# ============================================================================

def flask_middleware_example():
    """Example Flask middleware using MIRAGE ML"""

    from flask import Flask, request, jsonify

    app = Flask(__name__)
    ml_client = MirageMLClient()

    @app.before_request
    def check_with_ml():
        """Check every request with MIRAGE ML"""

        action, details = ml_client.analyze_request(
            method=request.method,
            path=request.path,
            query=request.query_string.decode(),
            headers=dict(request.headers),
            source_ip=request.remote_addr
        )

        if action == "block":
            return jsonify({
                "error": "Request blocked",
                "category": details.get('category'),
                "confidence": details.get('confidence')
            }), 403

    @app.route('/api/users')
    def get_users():
        return jsonify({"users": ["alice", "bob"]})

    return app


def nginx_lua_example():
    """Example Nginx Lua code (for reference)"""

    lua_code = '''
    -- MIRAGE ML Integration (Nginx Lua)
    local http = require "resty.http"
    local cjson = require "cjson"

    local function check_with_mirage()
        local httpc = http.new()

        local payload = cjson.encode({
            method = ngx.var.request_method,
            path = ngx.var.uri,
            query = ngx.var.args or "",
            headers = ngx.req.get_headers(),
            source_ip = ngx.var.remote_addr
        })

        local res, err = httpc:request_uri(
            "http://localhost:5000/api/waf/analyze",
            {
                method = "POST",
                body = payload,
                headers = { ["Content-Type"] = "application/json" },
                timeout = 100
            }
        )

        if res then
            local result = cjson.decode(res.body)

            if result.is_malicious and result.recommended_action == "block" then
                ngx.status = 403
                ngx.say("Attack detected: " .. result.category)
                ngx.exit(403)
            end
        end
    end

    -- Call in access_by_lua_block
    check_with_mirage()
    '''

    print("Nginx Lua Example:")
    print(lua_code)


if __name__ == "__main__":
    print("\n" + "="*70)
    print("MIRAGE ML Integration Examples")
    print("="*70 + "\n")

    print("1. Running integration tests...")
    test_integration()

    print("\n2. Flask middleware example:")
    print("   See flask_middleware_example() function above")

    print("\n3. Nginx Lua example:")
    nginx_lua_example()

    print("\n" + "="*70)
    print("For full integration guide, see:")
    print("  integrations/INTEGRATION_GUIDE.md")
    print("="*70 + "\n")
