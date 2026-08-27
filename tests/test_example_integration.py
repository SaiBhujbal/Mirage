import pytest
import sys
import os
from unittest.mock import MagicMock, patch
import requests

# Add root directory to path to import from integrations
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.example_integration import DecepticonMLClient, CustomWAF

@pytest.fixture
def ml_client():
    return DecepticonMLClient(api_url="http://test-api")

@pytest.fixture
def custom_waf():
    with patch('integrations.example_integration.DecepticonMLClient.health_check', return_value=True):
        return CustomWAF()

# DecepticonMLClient tests
def test_analyze_request_success(ml_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"recommended_action": "block", "category": "sqli", "confidence": 0.95}

    with patch.object(ml_client.session, 'post', return_value=mock_response) as mock_post:
        action, details = ml_client.analyze_request("GET", "/api/users", "?id=1")
        assert action == "block"
        assert details["category"] == "sqli"
        mock_post.assert_called_once()

def test_analyze_request_fail_open_status(ml_client):
    mock_response = MagicMock()
    mock_response.status_code = 500

    with patch.object(ml_client.session, 'post', return_value=mock_response):
        action, details = ml_client.analyze_request("GET", "/api/users", "?id=1")
        assert action == "allow"
        assert details["fail_open"] is True

def test_analyze_request_timeout(ml_client):
    with patch.object(ml_client.session, 'post', side_effect=requests.exceptions.Timeout):
        action, details = ml_client.analyze_request("GET", "/api/users", "?id=1")
        assert action == "allow"
        assert details["error"] == "timeout"

def test_analyze_batch(ml_client):
    mock_response = MagicMock()
    mock_response.json.return_value = {"results": [{"action": "allow"}]}

    with patch.object(ml_client.session, 'post', return_value=mock_response):
        result = ml_client.analyze_batch([{"method": "GET", "path": "/"}])
        assert result["results"][0]["action"] == "allow"

def test_analyze_batch_error(ml_client):
    with patch.object(ml_client.session, 'post', side_effect=Exception("Connection error")):
        result = ml_client.analyze_batch([{"method": "GET", "path": "/"}])
        assert "error" in result
        assert result["results"] == []

def test_report_false_positive(ml_client):
    mock_response = MagicMock()
    mock_response.json.return_value = {"status": "received"}

    with patch.object(ml_client.session, 'post', return_value=mock_response):
        result = ml_client.report_false_positive("payload", "sqli")
        assert result["status"] == "received"

def test_get_baseline(ml_client):
    mock_response = MagicMock()
    mock_response.json.return_value = {"baseline": "data"}

    with patch.object(ml_client.session, 'get', return_value=mock_response):
        result = ml_client.get_baseline()
        assert result["baseline"] == "data"

def test_health_check_healthy(ml_client):
    mock_response = MagicMock()
    mock_response.json.return_value = {"status": "healthy"}

    with patch.object(ml_client.session, 'get', return_value=mock_response):
        assert ml_client.health_check() is True

def test_health_check_unhealthy(ml_client):
    mock_response = MagicMock()
    mock_response.json.return_value = {"status": "unhealthy"}

    with patch.object(ml_client.session, 'get', return_value=mock_response):
        assert ml_client.health_check() is False

def test_health_check_exception(ml_client):
    with patch.object(ml_client.session, 'get', side_effect=Exception()):
        assert ml_client.health_check() is False

# CustomWAF tests
def test_custom_waf_process_request_block(custom_waf):
    with patch.object(custom_waf.ml_client, 'analyze_request', return_value=("block", {"category": "sqli", "confidence": 0.9})):
        status, message = custom_waf.process_request("GET", "/test")
        assert status == 403
        assert "BLOCKED" in message
        assert custom_waf.blocked_count == 1

def test_custom_waf_process_request_challenge(custom_waf):
    with patch.object(custom_waf.ml_client, 'analyze_request', return_value=("challenge", {})):
        status, message = custom_waf.process_request("GET", "/test")
        assert status == 429
        assert "CHALLENGE" in message

def test_custom_waf_process_request_allow(custom_waf):
    with patch.object(custom_waf.ml_client, 'analyze_request', return_value=("allow", {})):
        status, message = custom_waf.process_request("GET", "/test")
        assert status == 200
        assert "ALLOWED" in message
        assert custom_waf.allowed_count == 1

def test_custom_waf_process_request_fail_open(custom_waf):
    with patch.object(custom_waf.ml_client, 'analyze_request', return_value=("allow", {"fail_open": True, "error": "api error"})):
        status, message = custom_waf.process_request("GET", "/test")
        assert status == 200
        assert "fail-open" in message

def test_custom_waf_statistics(custom_waf):
    with patch.object(custom_waf.ml_client, 'analyze_request', side_effect=[
        ("block", {"category": "sqli", "confidence": 0.9}),
        ("allow", {}),
        ("allow", {})
    ]):
        with patch.object(custom_waf.ml_client, 'get_baseline', return_value={"baseline": "info"}):
            custom_waf.process_request("GET", "/1")
            custom_waf.process_request("GET", "/2")
            custom_waf.process_request("GET", "/3")

            stats = custom_waf.get_statistics()
            assert stats["requests_blocked"] == 1
            assert stats["requests_allowed"] == 2
            assert stats["total_requests"] == 3
            assert stats["block_rate"] == 1/3
            assert stats["ml_baseline"] == {"baseline": "info"}

def test_custom_waf_init_health_check_failure():
    with patch('integrations.example_integration.DecepticonMLClient.health_check', return_value=False):
        with patch('builtins.print') as mock_print:
            waf = CustomWAF()
            mock_print.assert_any_call("⚠️ WARNING: DECEPTICON ML API is not responding")
