"""
MIRAGE Response Sanitizer
Prevent sensitive data leakage even if attacker bypasses WAF
Last line of defense for data protection
"""
import re
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
import json

@dataclass
class SanitizationResult:
    """Result of response sanitization"""
    content: bytes
    was_modified: bool
    patterns_found: List[str]
    redacted_count: int

class SensitiveDataPatterns:
    """
    Patterns for detecting sensitive data in responses
    """
    
    # Credit card numbers (with common formats)
    CREDIT_CARD = re.compile(
        r'\b(?:'
        r'4[0-9]{12}(?:[0-9]{3})?|'  # Visa
        r'5[1-5][0-9]{14}|'           # MasterCard
        r'3[47][0-9]{13}|'            # Amex
        r'6(?:011|5[0-9]{2})[0-9]{12}|'  # Discover
        r'(?:2131|1800|35\d{3})\d{11}'   # JCB
        r')\b'
    )
    
    # SSN (US Social Security Number)
    SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    
    # API Keys (various formats)
    API_KEY = re.compile(
        r'(?i)(?:'
        r'api[_-]?key|apikey|access[_-]?token|auth[_-]?token|'
        r'bearer|secret[_-]?key|private[_-]?key'
        r')["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'
    )
    
    # AWS Keys
    AWS_ACCESS_KEY = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')
    AWS_SECRET_KEY = re.compile(r'(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?')
    
    # Private keys
    PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')
    
    # Passwords in various formats
    PASSWORD = re.compile(
        r'(?i)(?:'
        r'password|passwd|pwd|pass|secret'
        r')["\']?\s*[:=]\s*["\']?([^\s"\'<>&]{4,})["\']?'
    )
    
    # Email addresses
    EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    # Phone numbers (various formats)
    PHONE = re.compile(
        r'\b(?:'
        r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}|'
        r'\+91[-.\s]?[0-9]{10}'  # Indian format
        r')\b'
    )
    
    # JWT tokens
    JWT = re.compile(r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b')
    
    # Database connection strings
    DB_CONNECTION = re.compile(
        r'(?i)(?:'
        r'mongodb(?:\+srv)?://[^\s<>"]+|'
        r'postgres(?:ql)?://[^\s<>"]+|'
        r'mysql://[^\s<>"]+|'
        r'redis://[^\s<>"]+|'
        r'Server=[^;]+;.*(?:Password|Pwd)=[^;]+'
        r')'
    )
    
    # Internal IPs (should not leak)

    # Added patterns
    GITHUB_TOKEN = re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36})\b')
    SLACK_TOKEN = re.compile(r'\bxox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b')
    STRIPE_KEY = re.compile(r'\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24}\b')

    INTERNAL_IP = re.compile(
        r'\b(?:'
        r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
        r'192\.168\.\d{1,3}\.\d{1,3}'
        r')\b'
    )
    
    # Stack traces (can reveal internal structure)
    STACK_TRACE = re.compile(
        r'(?:'
        r'Traceback \(most recent call last\):|'
        r'at [\w.$]+\([\w.]+:\d+\)|'
        r'File "[^"]+", line \d+|'
        r'Exception in thread|'
        r'\.java:\d+\)'
        r')'
    )
    
    # SQL errors (can reveal DB structure)
    SQL_ERROR = re.compile(
        r'(?i)(?:'
        r'sql syntax|mysql_fetch|ORA-\d+|'
        r'postgresql|sqlite3?\.|'
        r'SQLSTATE\[|'
        r'syntax error at or near|'
        r'unterminated quoted string'
        r')'
    )

class ResponseSanitizer:
    """
    Sanitize response content to prevent data leakage
    Works on both JSON and HTML responses
    """
    
    # Redaction placeholder
    REDACTED = "[REDACTED]"
    REDACTED_BYTES = b"[REDACTED]"
    
    def __init__(self):
        # Compile all patterns
        self.patterns: Dict[str, re.Pattern] = {
            'credit_card': SensitiveDataPatterns.CREDIT_CARD,
            'ssn': SensitiveDataPatterns.SSN,
            'api_key': SensitiveDataPatterns.API_KEY,
            'aws_access_key': SensitiveDataPatterns.AWS_ACCESS_KEY,
            'aws_secret_key': SensitiveDataPatterns.AWS_SECRET_KEY,
            'private_key': SensitiveDataPatterns.PRIVATE_KEY,
            'password': SensitiveDataPatterns.PASSWORD,
            'email': SensitiveDataPatterns.EMAIL,
            'phone': SensitiveDataPatterns.PHONE,
            'jwt': SensitiveDataPatterns.JWT,
            'db_connection': SensitiveDataPatterns.DB_CONNECTION,
            'internal_ip': SensitiveDataPatterns.INTERNAL_IP,
            'stack_trace': SensitiveDataPatterns.STACK_TRACE,
            'sql_error': SensitiveDataPatterns.SQL_ERROR,
            'github_token': SensitiveDataPatterns.GITHUB_TOKEN,
            'slack_token': SensitiveDataPatterns.SLACK_TOKEN,
            'stripe_key': SensitiveDataPatterns.STRIPE_KEY,
        }
        
        # Patterns to always block (high severity)
        self.critical_patterns = {
            'private_key', 'aws_secret_key', 'db_connection', 'github_token', 'slack_token', 'stripe_key', 'internal_ip'
        }
        
        # Whitelist for known safe values
        self.whitelist: Set[str] = set()
        
        # Statistics
        self.stats = {
            'responses_scanned': 0,
            'responses_modified': 0,
            'patterns_found': {},
        }
    
    def sanitize(self, content: bytes, content_type: str = "",
                 strict_mode: bool = False) -> SanitizationResult:
        """
        Sanitize response content
        
        Args:
            content: Response body bytes
            content_type: Content-Type header
            strict_mode: If True, redact everything suspicious
        
        Returns:
            SanitizationResult with sanitized content
        """
        self.stats['responses_scanned'] += 1
        
        if not content:
            return SanitizationResult(
                content=content,
                was_modified=False,
                patterns_found=[],
                redacted_count=0
            )
        
        # Try to decode content
        try:
            text = content.decode('utf-8')
        except:
            # Binary content - skip
            return SanitizationResult(
                content=content,
                was_modified=False,
                patterns_found=[],
                redacted_count=0
            )
        
        patterns_found = []
        redacted_count = 0
        modified = False
        
        # Check each pattern
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(text)
            
            if matches:
                patterns_found.append(pattern_name)
                
                # Track stats
                self.stats['patterns_found'][pattern_name] = \
                    self.stats['patterns_found'].get(pattern_name, 0) + len(matches)
                
                # Determine if we should redact
                should_redact = (
                    strict_mode or
                    pattern_name in self.critical_patterns or
                    pattern_name in ['credit_card', 'ssn', 'password', 'jwt']
                )
                
                if should_redact:
                    # Redact all matches
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]  # Get first group
                        
                        if match not in self.whitelist:
                            text = text.replace(match, self.REDACTED)
                            redacted_count += 1
                            modified = True
        
        # Additional JSON-specific sanitization
        if 'json' in content_type.lower():
            text, json_redactions = self._sanitize_json(text)
            redacted_count += json_redactions
            if json_redactions > 0:
                modified = True
        
        # Additional HTML-specific sanitization
        if 'html' in content_type.lower():
            text, html_redactions = self._sanitize_html(text)
            redacted_count += html_redactions
            if html_redactions > 0:
                modified = True
        
        if modified:
            self.stats['responses_modified'] += 1
        
        return SanitizationResult(
            content=text.encode('utf-8'),
            was_modified=modified,
            patterns_found=patterns_found,
            redacted_count=redacted_count
        )
    
    def _sanitize_json(self, text: str) -> Tuple[str, int]:
        """
        Sanitize JSON content
        Look for sensitive keys and redact their values
        """
        redactions = 0
        
        sensitive_keys = [
            'password', 'passwd', 'pwd', 'secret', 'token',
            'api_key', 'apikey', 'access_token', 'refresh_token',
            'private_key', 'credit_card', 'ssn', 'cvv', 'pin'
        ]
        
        try:
            data = json.loads(text)
            modified, redactions = self._redact_dict(data, sensitive_keys)
            if modified:
                text = json.dumps(data, indent=2)
        except:
            # Not valid JSON, skip
            pass
        
        return text, redactions
    
    def _redact_dict(self, obj, sensitive_keys: List[str]) -> Tuple[bool, int]:
        """
        Recursively redact sensitive keys in dict/list
        """
        modified = False
        redactions = 0
        
        if isinstance(obj, dict):
            for key in obj:
                key_lower = key.lower()
                
                # Check if key is sensitive
                if any(sk in key_lower for sk in sensitive_keys):
                    if obj[key] and obj[key] != self.REDACTED:
                        obj[key] = self.REDACTED
                        modified = True
                        redactions += 1
                
                # Recurse into nested objects
                elif isinstance(obj[key], (dict, list)):
                    m, r = self._redact_dict(obj[key], sensitive_keys)
                    modified = modified or m
                    redactions += r
        
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    m, r = self._redact_dict(item, sensitive_keys)
                    modified = modified or m
                    redactions += r
        
        return modified, redactions
    
    def _sanitize_html(self, text: str) -> Tuple[str, int]:
        """
        Sanitize HTML content
        Remove comments, error messages, debug info
        """
        redactions = 0
        
        # Remove HTML comments (can contain debug info)
        comment_pattern = re.compile(r'<!--.*?-->', re.DOTALL)
        matches = comment_pattern.findall(text)
        for match in matches:
            if len(match) > 50:  # Only remove long comments
                text = text.replace(match, '<!-- [REDACTED] -->')
                redactions += 1
        
        # Remove debug/error divs
        debug_pattern = re.compile(
            r'<(?:div|pre|code)[^>]*(?:class|id)=["\'][^"\']*(?:debug|error|trace|exception)[^"\']*["\'][^>]*>.*?</(?:div|pre|code)>',
            re.DOTALL | re.IGNORECASE
        )
        text = debug_pattern.sub('<!-- [DEBUG INFO REDACTED] -->', text)
        
        return text, redactions
    
    def add_to_whitelist(self, value: str):
        """Add value to whitelist (won't be redacted)"""
        self.whitelist.add(value)
    
    def get_stats(self) -> Dict:
        """Get sanitization statistics"""
        return self.stats.copy()

class HeaderSanitizer:
    """
    Sanitize response headers to prevent info leakage
    """
    
    # Headers to remove
    REMOVE_HEADERS = {
        'x-powered-by',
        'server',
        'x-aspnet-version',
        'x-aspnetmvc-version',
        'x-runtime',
        'x-version',
    }
    
    # Headers to modify
    MODIFY_HEADERS = {
        'server': 'MIRAGE',
    }
    
    @classmethod
    def sanitize(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize response headers
        """
        sanitized = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            # Skip headers to remove
            if key_lower in cls.REMOVE_HEADERS:
                continue
            
            # Modify certain headers
            if key_lower in cls.MODIFY_HEADERS:
                sanitized[key] = cls.MODIFY_HEADERS[key_lower]
            else:
                sanitized[key] = value
        
        # Add security headers
        sanitized['X-Content-Type-Options'] = 'nosniff'
        sanitized['X-Frame-Options'] = 'DENY'
        sanitized['X-XSS-Protection'] = '1; mode=block'
        sanitized['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        sanitized['X-Powered-By'] = 'MIRAGE-WAF'
        
        return sanitized

class ErrorSanitizer:
    """
    Sanitize error responses to prevent information disclosure
    """
    
    # Generic error messages by status code
    GENERIC_ERRORS = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }
    
    @classmethod
    def sanitize_error(cls, status_code: int, original_message: str,
                       include_request_id: bool = True,
                       request_id: str = "") -> Dict:
        """
        Return sanitized error response
        """
        generic_message = cls.GENERIC_ERRORS.get(status_code, "Error")
        
        response = {
            "error": generic_message,
            "status": status_code,
        }
        
        if include_request_id and request_id:
            response["request_id"] = request_id
        
        # Don't include original message (might leak info)
        # But log it server-side
        
        return response

# Global instances
response_sanitizer = ResponseSanitizer()
header_sanitizer = HeaderSanitizer()
error_sanitizer = ErrorSanitizer()
