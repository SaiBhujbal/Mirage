import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.response_sanitizer import ResponseSanitizer, HeaderSanitizer, ErrorSanitizer

class TestResponseSanitizer:
    """Test response sanitization"""

    def test_credit_card_redaction(self):
        """Test credit card number redaction"""
        sanitizer = ResponseSanitizer()

        content = b'{"card": "4111111111111111", "name": "John"}'
        result = sanitizer.sanitize(content, "application/json")

        assert b"4111111111111111" not in result.content
        assert result.was_modified

    def test_api_key_redaction(self):
        """Test API key redaction"""
        sanitizer = ResponseSanitizer()

        # fake, test-only key built from parts so secret scanners don't flag the literal
        _fake_key = "sk_live_" + ("abcdef1234567890" * 2)
        content = ('{"api_key": "%s"}' % _fake_key).encode()
        result = sanitizer.sanitize(content, "application/json", strict_mode=True)

        assert result.was_modified

    def test_password_redaction(self):
        """Test password redaction in JSON"""
        sanitizer = ResponseSanitizer()

        content = b'{"username": "admin", "password": "secret123"}'
        result = sanitizer.sanitize(content, "application/json")

        assert b"secret123" not in result.content

    def test_stack_trace_detection(self):
        """Test stack trace detection"""
        sanitizer = ResponseSanitizer()

        content = b'''
        Error: Something went wrong
        Traceback (most recent call last):
          File "/app/views.py", line 42, in handle_request
            result = process_data(data)
        '''

        result = sanitizer.sanitize(content, "text/plain")
        assert "stack_trace" in result.patterns_found

    def test_aws_keys_redaction(self):
        """Test AWS keys redaction"""
        sanitizer = ResponseSanitizer()

        # AWS secret keys are always redacted (critical pattern)
        content = b'{"aws_secret": "AWS_SECRET_KEY=abcxyz123/+=4567890abcxyz123/+=4567890"}'
        result = sanitizer.sanitize(content, "text/plain")
        assert b"abcxyz123/+=4567890abcxyz123/+=4567890" not in result.content
        assert result.was_modified

    def test_internal_ip_redaction(self):
        """Test Internal IP detection and redaction in strict mode"""
        sanitizer = ResponseSanitizer()

        content = b'Server IP is 192.168.1.100'
        # Internal IP is not critical, so without strict mode it just detects it
        result_normal = sanitizer.sanitize(content, "text/plain")
        assert "internal_ip" in result_normal.patterns_found
        assert result_normal.was_modified == False

        # With strict mode, it should be redacted
        result_strict = sanitizer.sanitize(content, "text/plain", strict_mode=True)
        assert b"192.168.1.100" not in result_strict.content
        assert result_strict.was_modified

    def test_html_sanitization(self):
        """Test HTML specific sanitization"""
        sanitizer = ResponseSanitizer()

        content = b'''
        <html>
        <body>
            <!-- This is a very long comment that contains some sensitive internal debug information that should definitely be redacted by the sanitizer -->
            <div id="error-trace" class="debug">Exception: Database connection failed at line 42</div>
        </body>
        </html>
        '''
        result = sanitizer.sanitize(content, "text/html")
        assert b"This is a very long comment" not in result.content
        assert b"Exception: Database connection failed" not in result.content
        assert result.was_modified

    def test_json_nested_redaction(self):
        """Test nested JSON redaction"""
        sanitizer = ResponseSanitizer()

        content = b'''
        {
            "user": {
                "profile": {
                    "api_key": "my_super_secret_key"
                }
            },
            "tokens": [
                {"access_token": "token123"}
            ]
        }
        '''
        result = sanitizer.sanitize(content, "application/json")
        assert b"my_super_secret_key" not in result.content
        assert b"token123" not in result.content
        assert result.was_modified

    def test_binary_content_handling(self):
        """Test handling of binary content"""
        sanitizer = ResponseSanitizer()

        content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
        result = sanitizer.sanitize(content, "image/png")
        assert result.content == content
        assert not result.was_modified

    def test_whitelist_functionality(self):
        """Test whitelist functionality"""
        sanitizer = ResponseSanitizer()
        safe_ip = "10.0.0.1"
        sanitizer.add_to_whitelist(safe_ip)

        content = f'Public IP is {safe_ip}'.encode('utf-8')
        result = sanitizer.sanitize(content, "text/plain", strict_mode=True)

        assert safe_ip.encode('utf-8') in result.content
        assert not result.was_modified

    def test_get_stats(self):
        """Test statistics collection"""
        sanitizer = ResponseSanitizer()
        content = b'{"password": "secret123", "ssn": "123-45-6789"}'
        sanitizer.sanitize(content, "application/json")

        stats = sanitizer.get_stats()
        assert stats['responses_scanned'] == 1
        assert stats['responses_modified'] == 1
        assert 'password' in stats['patterns_found']
        assert 'ssn' in stats['patterns_found']

class TestHeaderSanitizer:
    """Test header sanitization"""

    def test_header_sanitization(self):
        headers = {
            'X-Powered-By': 'Express',
            'Server': 'Apache/2.4.41',
            'X-AspNet-Version': '4.0.30319',
            'Content-Type': 'application/json',
            'Custom-Header': 'CustomValue'
        }

        sanitized = HeaderSanitizer.sanitize(headers)

        # Check removed headers
        assert 'X-AspNet-Version' not in sanitized

        # Check that 'Server' was removed (it is in REMOVE_HEADERS so it gets stripped entirely)
        assert 'Server' not in sanitized

        # 'X-Powered-By' is in REMOVE_HEADERS but is added back explicitly
        assert sanitized.get('X-Powered-By') == 'MIRAGE-WAF'

        # Check kept headers
        assert sanitized.get('Content-Type') == 'application/json'
        assert sanitized.get('Custom-Header') == 'CustomValue'

        # Check added security headers
        assert sanitized.get('X-Content-Type-Options') == 'nosniff'
        assert sanitized.get('X-Frame-Options') == 'DENY'
        assert sanitized.get('X-XSS-Protection') == '1; mode=block'

class TestErrorSanitizer:
    """Test error sanitization"""

    def test_error_sanitization(self):
        # Without request ID
        result = ErrorSanitizer.sanitize_error(500, "Database connection timeout: mysql://root:pass@localhost")
        assert result['status'] == 500
        assert result['error'] == "Internal Server Error"
        assert "mysql" not in result.get('error', '')

        # With request ID
        result_with_id = ErrorSanitizer.sanitize_error(404, "File /etc/passwd not found", include_request_id=True, request_id="req-123")
        assert result_with_id['status'] == 404
        assert result_with_id['error'] == "Not Found"
        assert result_with_id['request_id'] == "req-123"
        assert "passwd" not in result_with_id.get('error', '')
