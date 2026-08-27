import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.comprehensive_scanner import ComprehensiveScanner, Severity, ScanResult
from core.comprehensive_patterns import AttackCategory

@pytest.fixture
def scanner():
    return ComprehensiveScanner()

class TestComprehensiveScanner:
    """Test suite for ComprehensiveScanner"""

    def test_decode_input(self, scanner):
        """Test URL and double URL decoding"""
        assert scanner._decode_input("hello%20world") == "hello world"
        assert scanner._decode_input("hello%2520world") == "hello world"
        assert scanner._decode_input(None) == ""
        assert scanner._decode_input("") == ""

    def test_scan_payload_sqli(self, scanner):
        """Test SQL injection detection"""
        payload = "' OR '1'='1"
        results = scanner.scan_payload(payload)
        assert len(results) > 0
        assert any(r.category == AttackCategory.SQLI for r in results)
        assert any(r.severity == Severity.CRITICAL for r in results)

    def test_scan_payload_xss(self, scanner):
        """Test XSS detection"""
        payload = "<script>alert(1)</script>"
        results = scanner.scan_payload(payload)
        assert len(results) > 0
        assert any(r.category == AttackCategory.XSS for r in results)
        assert any(r.severity == Severity.HIGH for r in results)

    def test_scan_payload_benign(self, scanner):
        """Test benign payload"""
        payload = "Hello, how are you today?"
        results = scanner.scan_payload(payload)
        assert len(results) == 0

    def test_scan_request_path(self, scanner):
        """Test scanning request path"""
        results = scanner.scan_request(path="/etc/passwd")
        assert any(r.category == AttackCategory.PATH_TRAVERSAL for r in results)
        assert any(r.location == "path" for r in results)

    def test_scan_request_query(self, scanner):
        """Test scanning query parameters"""
        results = scanner.scan_request(query="id=' OR 1=1")
        assert any(r.category == AttackCategory.SQLI for r in results)
        # Should detect in query and query_param
        locations = [r.location for r in results]
        assert "query" in locations
        assert "query_param" in locations

    def test_scan_request_body(self, scanner):
        """Test scanning request body"""
        results = scanner.scan_request(body='{"username": {"$ne": null}}')
        assert any(r.category == AttackCategory.NOSQL for r in results)
        assert any(r.location == "body" for r in results)

    def test_scan_request_headers(self, scanner):
        """Test scanning request headers"""
        headers = {
            "User-Agent": "sqlmap/1.4.7",
            "Referer": "javascript:alert(1)"
        }
        results = scanner.scan_request(headers=headers)

        ua_results = [r for r in results if r.location == "header:User-Agent"]
        assert any(r.category == AttackCategory.SCANNER for r in ua_results)

        referer_results = [r for r in results if r.location == "header:Referer"]
        assert any(r.category == AttackCategory.XSS for r in referer_results)

    def test_is_malicious(self, scanner):
        """Test is_malicious check with thresholds"""
        # A payload that is known to be at least HIGH but not necessarily CRITICAL
        # However, "<script>alert(1)</script>" matched CRITICAL in some patterns
        # Let's use a lower severity one like a scanner pattern
        payload = "Nikto"

        assert scanner.is_malicious(payload, threshold=Severity.INFO) is True
        assert scanner.is_malicious(payload, threshold=Severity.LOW) is True
        assert scanner.is_malicious(payload, threshold=Severity.MEDIUM) is False

    def test_get_highest_severity(self, scanner):
        """Test highest severity calculation"""
        results = [
            ScanResult(AttackCategory.SQLI, "1", Severity.CRITICAL, "", "", "", ""),
            ScanResult(AttackCategory.XSS, "2", Severity.HIGH, "", "", "", "")
        ]
        assert scanner.get_highest_severity(results) == Severity.CRITICAL

        assert scanner.get_highest_severity([]) is None

        low_results = [ScanResult(AttackCategory.SCANNER, "3", Severity.LOW, "", "", "", "")]
        assert scanner.get_highest_severity(low_results) == Severity.LOW

    def test_utility_methods(self, scanner):
        """Test utility methods for pattern info"""
        categories = scanner.get_attack_categories()
        assert "sql_injection" in categories
        assert "cross_site_scripting" in categories

        counts = scanner.get_pattern_count()
        assert counts["sql_injection"] > 0
        assert counts["cross_site_scripting"] > 0
        assert sum(counts.values()) == scanner.total_patterns

if __name__ == "__main__":
    pytest.main([__file__])
