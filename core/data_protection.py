"""
DECEPTICON Sensitive Data Protection
Last line of defense - ensures attackers NEVER get sensitive data
Even if WAF is bypassed, this layer protects the crown jewels
"""
import re
import hashlib
import time
from typing import Dict, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import threading

class DataCategory(Enum):
    """Categories of sensitive data"""
    PII = "pii"                    # Personal identifiable info
    CREDENTIALS = "credentials"    # Passwords, keys, tokens
    FINANCIAL = "financial"        # Credit cards, bank accounts
    HEALTH = "health"              # Medical records
    CLASSIFIED = "classified"      # Military/government
    INTERNAL = "internal"          # Internal system data

@dataclass
class SensitivePattern:
    """Pattern for detecting sensitive data"""
    pattern_id: str
    category: DataCategory
    regex: re.Pattern
    description: str
    redaction_strategy: str  # mask, remove, tokenize, encrypt
    severity: float = 1.0

@dataclass
class DataLeakAttempt:
    """Record of data leak attempt"""
    timestamp: float
    request_id: str
    client_ip: str
    category: DataCategory
    pattern_matched: str
    data_sample: str  # Redacted sample
    blocked: bool
    path: str

class SensitiveDataProtector:
    """
    Multi-layer sensitive data protection
    
    Strategies:
    1. Request inspection - block requests targeting sensitive paths
    2. Response inspection - redact/block sensitive data in responses
    3. Tokenization - replace sensitive data with tokens
    4. Encryption - encrypt sensitive fields
    5. Access logging - log all access attempts
    """
    
    def __init__(self):
        self.patterns: Dict[str, SensitivePattern] = {}
        self.sensitive_paths: Set[str] = set()
        self.sensitive_headers: Set[str] = set()
        self.leak_attempts: List[DataLeakAttempt] = []
        self.tokenization_map: Dict[str, str] = {}
        self.lock = threading.Lock()
        
        # Initialize patterns
        self._init_patterns()
        self._init_sensitive_paths()
        self._init_sensitive_headers()
        
        # Statistics
        self.stats = {
            'requests_scanned': 0,
            'responses_scanned': 0,
            'leaks_blocked': 0,
            'data_redacted': 0,
        }
    
    def _init_patterns(self):
        """Initialize sensitive data patterns"""
        
        patterns = [
            # Credentials
            SensitivePattern(
                pattern_id="CRED-001",
                category=DataCategory.CREDENTIALS,
                regex=re.compile(
                    r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^"\'&\s]{4,50})',
                    re.I
                ),
                description="Password in plaintext",
                redaction_strategy="remove",
                severity=1.0
            ),
            SensitivePattern(
                pattern_id="CRED-002",
                category=DataCategory.CREDENTIALS,
                regex=re.compile(
                    r'(?:api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,100})',
                    re.I
                ),
                description="API key",
                redaction_strategy="mask",
                severity=1.0
            ),
            SensitivePattern(
                pattern_id="CRED-003",
                category=DataCategory.CREDENTIALS,
                regex=re.compile(
                    r'(?:secret|token|auth)\s*[=:]\s*["\']?([a-zA-Z0-9_\-+/]{20,200})',
                    re.I
                ),
                description="Secret/Token",
                redaction_strategy="mask",
                severity=0.9
            ),
            SensitivePattern(
                pattern_id="CRED-004",
                category=DataCategory.CREDENTIALS,
                regex=re.compile(
                    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                    re.I
                ),
                description="Private key",
                redaction_strategy="remove",
                severity=1.0
            ),
            SensitivePattern(
                pattern_id="CRED-005",
                category=DataCategory.CREDENTIALS,
                regex=re.compile(
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                ),
                description="AWS Access Key",
                redaction_strategy="mask",
                severity=1.0
            ),
            SensitivePattern(
                pattern_id="CRED-006",
                category=DataCategory.CREDENTIALS,
                regex=re.compile(
                    r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',  # GitHub token
                ),
                description="GitHub Token",
                redaction_strategy="mask",
                severity=1.0
            ),
            
            # PII
            SensitivePattern(
                pattern_id="PII-001",
                category=DataCategory.PII,
                regex=re.compile(
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                ),
                description="Email address",
                redaction_strategy="mask",
                severity=0.6
            ),
            SensitivePattern(
                pattern_id="PII-002",
                category=DataCategory.PII,
                regex=re.compile(
                    r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'  # SSN
                ),
                description="Social Security Number",
                redaction_strategy="remove",
                severity=1.0
            ),
            SensitivePattern(
                pattern_id="PII-003",
                category=DataCategory.PII,
                regex=re.compile(
                    r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'
                ),
                description="Phone number",
                redaction_strategy="mask",
                severity=0.5
            ),
            SensitivePattern(
                pattern_id="PII-004",
                category=DataCategory.PII,
                regex=re.compile(
                    r'(?i)(?:aadhaar|aadhar)\s*[:#]?\s*\d{4}[\s-]?\d{4}[\s-]?\d{4}'
                ),
                description="Aadhaar Number",
                redaction_strategy="remove",
                severity=1.0
            ),
            
            # Financial
            SensitivePattern(
                pattern_id="FIN-001",
                category=DataCategory.FINANCIAL,
                regex=re.compile(
                    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
                ),
                description="Credit card number",
                redaction_strategy="mask",
                severity=1.0
            ),
            SensitivePattern(
                pattern_id="FIN-002",
                category=DataCategory.FINANCIAL,
                regex=re.compile(
                    r'\b[0-9]{9,18}\b.*?(?:account|acct)',
                    re.I
                ),
                description="Bank account number",
                redaction_strategy="mask",
                severity=0.9
            ),
            SensitivePattern(
                pattern_id="FIN-003",
                category=DataCategory.FINANCIAL,
                regex=re.compile(
                    r'\b[A-Z]{4}0[A-Z0-9]{6}\b'  # IFSC Code
                ),
                description="IFSC Code",
                redaction_strategy="mask",
                severity=0.5
            ),
            
            # Classified
            SensitivePattern(
                pattern_id="CLASS-001",
                category=DataCategory.CLASSIFIED,
                regex=re.compile(
                    r'(?i)\b(?:top\s*secret|classified|confidential|restricted)\b'
                ),
                description="Classification marker",
                redaction_strategy="remove",
                severity=1.0
            ),
            SensitivePattern(
                pattern_id="CLASS-002",
                category=DataCategory.CLASSIFIED,
                regex=re.compile(
                    r'(?i)(?:coordinates?|coords?)\s*[=:]\s*[-\d.]+\s*,\s*[-\d.]+'
                ),
                description="Geographic coordinates",
                redaction_strategy="remove",
                severity=0.8
            ),
            
            # Internal
            SensitivePattern(
                pattern_id="INT-001",
                category=DataCategory.INTERNAL,
                regex=re.compile(
                    r'(?i)(?:internal[_-]?ip|private[_-]?ip)\s*[=:]\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                ),
                description="Internal IP address",
                redaction_strategy="remove",
                severity=0.7
            ),
            SensitivePattern(
                pattern_id="INT-002",
                category=DataCategory.INTERNAL,
                regex=re.compile(
                    r'(?i)(?:db|database)[_-]?(?:host|server|connection)\s*[=:]\s*[^\s]+',
                ),
                description="Database connection string",
                redaction_strategy="remove",
                severity=0.9
            ),
        ]
        
        for pattern in patterns:
            self.patterns[pattern.pattern_id] = pattern
    
    def _init_sensitive_paths(self):
        """Initialize sensitive paths that require extra protection"""
        self.sensitive_paths = {
            "/api/admin",
            "/api/users",
            "/api/auth",
            "/api/secrets",
            "/api/config",
            "/api/keys",
            "/api/tokens",
            "/internal",
            "/admin",
            "/management",
            "/actuator",
            "/.env",
            "/config",
            "/backup",
            "/dump",
            "/export",
        }
    
    def _init_sensitive_headers(self):
        """Headers that should never be exposed"""
        self.sensitive_headers = {
            "authorization",
            "x-api-key",
            "x-auth-token",
            "cookie",
            "set-cookie",
            "x-csrf-token",
            "x-forwarded-for",
            "x-real-ip",
        }
    
    def is_sensitive_path(self, path: str) -> bool:
        """Check if path accesses sensitive resources"""
        path_lower = path.lower()
        
        for sensitive in self.sensitive_paths:
            if path_lower.startswith(sensitive):
                return True
        
        # Check for common sensitive file patterns
        sensitive_extensions = {'.env', '.key', '.pem', '.crt', '.pfx', '.p12', 
                               '.bak', '.sql', '.dump', '.conf', '.config'}
        
        for ext in sensitive_extensions:
            if path_lower.endswith(ext):
                return True
        
        return False
    
    def scan_request(self, path: str, query: str, body: str, 
                     headers: Dict[str, str], client_ip: str,
                     request_id: str) -> Tuple[bool, List[str]]:
        """
        Scan request for sensitive data access attempts
        Returns (should_block, reasons)
        """
        self.stats['requests_scanned'] += 1
        should_block = False
        reasons = []
        
        # Check path sensitivity
        if self.is_sensitive_path(path):
            reasons.append(f"Accessing sensitive path: {path}")
            # Don't auto-block, but flag
        
        # Check for data exfiltration patterns in query/body
        combined = f"{query} {body}"
        
        # Look for bulk data requests
        if re.search(r'(?i)limit\s*=?\s*(?:all|1000+|\*)', combined):
            reasons.append("Bulk data request detected")
            should_block = True
        
        # Look for export/dump requests
        if re.search(r'(?i)(?:export|dump|backup|download)\s*=?\s*(?:all|true|1)', combined):
            reasons.append("Data export attempt detected")
            should_block = True
        
        # Check for SQL injection targeting sensitive tables
        sensitive_tables = ['users', 'passwords', 'credentials', 'secrets', 'keys', 'tokens']
        for table in sensitive_tables:
            if re.search(rf'(?i)(?:from|into|update|join)\s+[`"\']?{table}', combined):
                reasons.append(f"SQL targeting sensitive table: {table}")
                should_block = True
        
        if should_block:
            self._record_leak_attempt(
                request_id=request_id,
                client_ip=client_ip,
                category=DataCategory.INTERNAL,
                pattern_matched="request_scan",
                data_sample=path[:50],
                blocked=True,
                path=path
            )
            self.stats['leaks_blocked'] += 1
        
        return should_block, reasons
    
    def scan_response(self, response_body: str, content_type: str,
                      path: str, client_ip: str, request_id: str) -> Tuple[str, List[str]]:
        """
        Scan and sanitize response body
        Returns (sanitized_body, redacted_patterns)
        """
        self.stats['responses_scanned'] += 1
        redacted = []
        sanitized = response_body
        
        # Skip binary content
        if 'application/octet-stream' in content_type or 'image/' in content_type:
            return response_body, []
        
        # Scan for sensitive patterns
        for pattern_id, pattern in self.patterns.items():
            matches = pattern.regex.findall(sanitized)
            
            if matches:
                for match in matches:
                    match_str = match if isinstance(match, str) else match[0]
                    
                    # Apply redaction strategy
                    if pattern.redaction_strategy == "remove":
                        sanitized = pattern.regex.sub("[REDACTED]", sanitized)
                    elif pattern.redaction_strategy == "mask":
                        # Keep first and last 2 chars
                        def mask_match(m):
                            text = m.group(0)
                            if len(text) > 8:
                                return text[:2] + '*' * (len(text) - 4) + text[-2:]
                            return '*' * len(text)
                        sanitized = pattern.regex.sub(mask_match, sanitized)
                    elif pattern.redaction_strategy == "tokenize":
                        token = self._tokenize(match_str)
                        sanitized = sanitized.replace(match_str, token)
                    
                    redacted.append(pattern_id)
                    self.stats['data_redacted'] += 1
                    
                    # Record attempt
                    self._record_leak_attempt(
                        request_id=request_id,
                        client_ip=client_ip,
                        category=pattern.category,
                        pattern_matched=pattern_id,
                        data_sample=f"{pattern.description}: {match_str[:10]}...",
                        blocked=False,  # Redacted, not blocked
                        path=path
                    )
        
        return sanitized, redacted
    
    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Remove or mask sensitive headers from response
        """
        sanitized = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            if key_lower in self.sensitive_headers:
                continue  # Remove entirely
            
            # Check for sensitive values
            skip = False
            for pattern in self.patterns.values():
                if pattern.category == DataCategory.CREDENTIALS:
                    if pattern.regex.search(value):
                        skip = True
                        break
            
            if not skip:
                sanitized[key] = value
        
        return sanitized
    
    def sanitize_error_response(self, error: Exception, 
                                  include_trace: bool = False) -> Dict:
        """
        Sanitize error responses to prevent information leakage
        """
        # Never expose internal paths, stack traces, or sensitive info
        error_str = str(error)
        
        # Remove file paths
        error_str = re.sub(r'(?:/[\w./]+)+\.py', '[path]', error_str)
        error_str = re.sub(r'(?:[A-Z]:\\[\w\\]+)+\.py', '[path]', error_str)
        
        # Remove line numbers
        error_str = re.sub(r'line \d+', 'line [N]', error_str)
        
        # Remove internal IPs
        error_str = re.sub(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b', 
                          '[internal-ip]', error_str)
        
        # Remove database connection strings
        error_str = re.sub(r'(?:mysql|postgresql|mongodb)://[^\s]+', 
                          '[db-connection]', error_str)
        
        response = {
            'error': 'An error occurred',
            'code': 'INTERNAL_ERROR'
        }
        
        if include_trace:
            response['detail'] = error_str[:200]  # Limited length
        
        return response
    
    def _tokenize(self, value: str) -> str:
        """
        Replace sensitive value with a reversible token
        Only reversible with server-side lookup
        """
        token = f"TOK_{hashlib.sha256(value.encode()).hexdigest()[:16]}"
        
        with self.lock:
            self.tokenization_map[token] = value
        
        return token
    
    def _record_leak_attempt(self, **kwargs):
        """Record a data leak attempt"""
        attempt = DataLeakAttempt(
            timestamp=time.time(),
            **kwargs
        )
        
        with self.lock:
            self.leak_attempts.append(attempt)
            
            # Keep only last 10000
            if len(self.leak_attempts) > 10000:
                self.leak_attempts = self.leak_attempts[-10000:]
    
    def get_leak_attempts(self, 
                           client_ip: Optional[str] = None,
                           category: Optional[DataCategory] = None,
                           limit: int = 100) -> List[Dict]:
        """Get recent leak attempts"""
        attempts = self.leak_attempts.copy()
        
        if client_ip:
            attempts = [a for a in attempts if a.client_ip == client_ip]
        
        if category:
            attempts = [a for a in attempts if a.category == category]
        
        return [
            {
                'timestamp': a.timestamp,
                'client_ip': a.client_ip,
                'category': a.category.value,
                'pattern': a.pattern_matched,
                'blocked': a.blocked,
                'path': a.path,
            }
            for a in attempts[-limit:]
        ]
    
    def get_stats(self) -> Dict:
        """Get protection statistics"""
        return {
            **self.stats,
            'patterns_loaded': len(self.patterns),
            'sensitive_paths': len(self.sensitive_paths),
            'leak_attempts_recorded': len(self.leak_attempts),
        }

# Global instance
data_protector = SensitiveDataProtector()


class ResponseSanitizer:
    """
    Sanitize all outgoing responses
    This is the FINAL gate before data leaves the system
    """
    
    def __init__(self, protector: SensitiveDataProtector):
        self.protector = protector
    
    def sanitize(self, 
                 body: bytes,
                 headers: Dict[str, str],
                 status_code: int,
                 content_type: str,
                 request_id: str,
                 client_ip: str,
                 path: str) -> Tuple[bytes, Dict[str, str]]:
        """
        Sanitize response before sending to client
        """
        # Sanitize headers
        clean_headers = self.protector.sanitize_headers(headers)
        
        # Skip binary content
        if self._is_binary(content_type):
            return body, clean_headers
        
        # Decode body
        try:
            body_str = body.decode('utf-8')
        except:
            return body, clean_headers
        
        # Scan and sanitize body
        sanitized_str, redacted = self.protector.scan_response(
            body_str, content_type, path, client_ip, request_id
        )
        
        # Add security headers
        clean_headers['X-Content-Type-Options'] = 'nosniff'
        clean_headers['X-Frame-Options'] = 'DENY'
        clean_headers['X-XSS-Protection'] = '1; mode=block'
        clean_headers['Content-Security-Policy'] = "default-src 'self'"
        
        # Remove server info
        clean_headers.pop('Server', None)
        clean_headers.pop('X-Powered-By', None)
        
        return sanitized_str.encode('utf-8'), clean_headers
    
    def _is_binary(self, content_type: str) -> bool:
        """Check if content type is binary"""
        binary_types = [
            'image/', 'video/', 'audio/', 'application/octet-stream',
            'application/zip', 'application/pdf', 'application/gzip'
        ]
        return any(bt in content_type for bt in binary_types)

# Global sanitizer
response_sanitizer = ResponseSanitizer(data_protector)
