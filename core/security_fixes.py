"""
DECEPTICON Security Fixes Module
Addresses all remaining security gaps from pentester assessment
"""
import os
import sys
import time
import json
import hmac
import hashlib
import logging
import threading
import re
from pathlib import Path
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("decepticon.security")


# ============================================================================
# 1. AUTO-DELETE ADMIN KEY FILE
# ============================================================================

class AdminKeyCleanup:
    """
    Auto-delete ADMIN_KEY.txt after 24 hours
    Prevents key file from lingering on filesystem
    """
    
    KEY_MAX_AGE_SECONDS = 86400  # 24 hours
    
    @classmethod
    def cleanup_expired_key(cls, key_path: str = "./data/security/ADMIN_KEY.txt"):
        """Delete admin key file if older than 24 hours"""
        key_file = Path(key_path)
        
        if key_file.exists():
            try:
                age = time.time() - key_file.stat().st_mtime
                
                if age > cls.KEY_MAX_AGE_SECONDS:
                    key_file.unlink()
                    logger.warning(
                        f"Auto-deleted expired ADMIN_KEY.txt (age: {age/3600:.1f} hours). "
                        "If you haven't saved the key, generate a new one."
                    )
                    return True
                else:
                    remaining = (cls.KEY_MAX_AGE_SECONDS - age) / 3600
                    logger.warning(
                        f"⚠️  ADMIN_KEY.txt still exists! "
                        f"Save the key and delete the file. Auto-delete in {remaining:.1f} hours."
                    )
            except Exception as e:
                logger.error(f"Failed to cleanup admin key: {e}")
        
        return False
    
    @classmethod
    def schedule_cleanup(cls, key_path: str = "./data/security/ADMIN_KEY.txt"):
        """Schedule periodic cleanup check"""
        def cleanup_loop():
            while True:
                cls.cleanup_expired_key(key_path)
                time.sleep(3600)  # Check every hour
        
        thread = threading.Thread(target=cleanup_loop, daemon=True)
        thread.start()


# ============================================================================
# 2. REQUEST SIZE LIMIT MIDDLEWARE
# ============================================================================

class RequestSizeLimiter:
    """
    Limit request body size to prevent DoS attacks
    """
    
    def __init__(self, max_size: int = 1024 * 1024):
        self.max_size = max_size
    
    def check_size(self, content_length: Optional[str]) -> tuple[bool, str]:
        """
        Check if content length is within limits
        Returns: (is_allowed, error_message)
        """
        if content_length is None:
            return True, ""
        
        try:
            size = int(content_length)
            if size > self.max_size:
                return False, f"Request body too large. Max: {self.max_size} bytes"
            return True, ""
        except ValueError:
            return False, "Invalid Content-Length header"


# For FastAPI middleware
def create_size_limit_middleware(max_size: int = 1024 * 1024):
    """Create FastAPI middleware for request size limiting"""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
    
    limiter = RequestSizeLimiter(max_size)
    
    class SizeLimitMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            content_length = request.headers.get("content-length")
            
            is_allowed, error = limiter.check_size(content_length)
            if not is_allowed:
                return JSONResponse(
                    {"error": error},
                    status_code=413
                )
            
            return await call_next(request)
    
    return SizeLimitMiddleware


# ============================================================================
# 3. SANITIZING LOG FORMATTER
# ============================================================================

class SanitizingFormatter(logging.Formatter):
    """
    Log formatter that redacts sensitive data
    Prevents credential leakage in logs
    """
    
    REDACT_PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']?[^"\'&\s]+', 'password=***REDACTED***'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\'&\s]+', 'api_key=***REDACTED***'),
        (r'secret["\']?\s*[:=]\s*["\']?[^"\'&\s]+', 'secret=***REDACTED***'),
        (r'token["\']?\s*[:=]\s*["\']?[^"\'&\s]+', 'token=***REDACTED***'),
        (r'authorization:\s*bearer\s+\S+', 'Authorization: Bearer ***REDACTED***'),
        (r'x-api-key:\s*\S+', 'X-API-Key: ***REDACTED***'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***EMAIL***'),
        (r'\b\d{3}-\d{2}-\d{4}\b', '***SSN***'),
        (r'\b\d{13,16}\b', '***CARD***'),
        (r'/home/\w+', '/home/***'),
        (r'-----BEGIN.*PRIVATE KEY-----', '***PRIVATE_KEY***'),
    ]
    
    def __init__(self, fmt=None, datefmt=None, style='%'):
        super().__init__(fmt, datefmt, style)
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self.REDACT_PATTERNS
        ]
    
    def format(self, record):
        # Create a copy of the record to avoid modifying the original
        record = logging.makeLogRecord(record.__dict__)
        
        # Redact message
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        
        # Redact args if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._redact(str(arg)) for arg in record.args)
        
        return super().format(record)
    
    def _redact(self, text: str) -> str:
        for pattern, replacement in self._compiled_patterns:
            text = pattern.sub(replacement, text)
        return text


def configure_secure_logging(env: str = "development"):
    """Configure logging with sanitization and appropriate level"""
    
    # Determine log level based on environment
    if env == "production":
        level = logging.WARNING
    elif env == "staging":
        level = logging.INFO
    else:
        level = logging.DEBUG
    
    # Create sanitizing formatter
    formatter = SanitizingFormatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Add console handler with sanitizing formatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    return root_logger


# ============================================================================
# 4. SESSION ENCRYPTION
# ============================================================================

class SessionEncryption:
    """
    Encrypt sensitive session data at rest in Redis
    """
    
    def __init__(self, key: Optional[str] = None):
        self.enabled = False
        self.cipher = None
        
        if key:
            try:
                from cryptography.fernet import Fernet
                # Key should be 32 bytes, URL-safe base64-encoded
                self.cipher = Fernet(key.encode() if isinstance(key, str) else key)
                self.enabled = True
                logger.info("Session encryption enabled")
            except ImportError:
                logger.warning("cryptography not installed. Session encryption disabled.")
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {e}")
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not self.enabled or not self.cipher:
            return data
        
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return data
    
    def decrypt(self, data: str) -> str:
        """Decrypt string data"""
        if not self.enabled or not self.cipher:
            return data
        
        try:
            return self.cipher.decrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return data
    
    def encrypt_dict(self, data: Dict, sensitive_keys: List[str] = None) -> Dict:
        """Encrypt sensitive fields in a dictionary"""
        if not self.enabled:
            return data
        
        sensitive_keys = sensitive_keys or [
            "fingerprint", "ja4_fingerprint", "behavioral_fingerprint",
            "user_agent", "payloads", "credentials"
        ]
        
        result = data.copy()
        for key in sensitive_keys:
            if key in result and isinstance(result[key], str):
                result[key] = self.encrypt(result[key])
        
        return result
    
    def decrypt_dict(self, data: Dict, sensitive_keys: List[str] = None) -> Dict:
        """Decrypt sensitive fields in a dictionary"""
        if not self.enabled:
            return data
        
        sensitive_keys = sensitive_keys or [
            "fingerprint", "ja4_fingerprint", "behavioral_fingerprint",
            "user_agent", "payloads", "credentials"
        ]
        
        result = data.copy()
        for key in sensitive_keys:
            if key in result and isinstance(result[key], str):
                result[key] = self.decrypt(result[key])
        
        return result
    
    @staticmethod
    def generate_key() -> str:
        """Generate a new encryption key"""
        try:
            from cryptography.fernet import Fernet
            return Fernet.generate_key().decode()
        except ImportError:
            import base64
            import os
            return base64.urlsafe_b64encode(os.urandom(32)).decode()


# ============================================================================
# 5. MULTI-FACTOR AUTHENTICATION (TOTP)
# ============================================================================

class TOTPManager:
    """
    Time-based One-Time Password for admin API keys
    """
    
    def __init__(self):
        self.totp_available = False
        try:
            import pyotp
            self.pyotp = pyotp
            self.totp_available = True
        except ImportError:
            logger.warning("pyotp not installed. MFA disabled. Install with: pip install pyotp")
    
    def generate_secret(self) -> Optional[str]:
        """Generate a new TOTP secret"""
        if not self.totp_available:
            return None
        return self.pyotp.random_base32()
    
    def get_provisioning_uri(self, secret: str, account_name: str, 
                             issuer: str = "DECEPTICON-WAF") -> Optional[str]:
        """Generate QR code URI for authenticator apps"""
        if not self.totp_available:
            return None
        
        totp = self.pyotp.TOTP(secret)
        return totp.provisioning_uri(name=account_name, issuer_name=issuer)
    
    def verify(self, secret: str, token: str, valid_window: int = 1) -> bool:
        """
        Verify TOTP token
        valid_window: Number of 30-second windows to accept (1 = ±30 seconds)
        """
        if not self.totp_available:
            return True  # MFA not available, allow
        
        if not secret:
            return True  # MFA not enabled for this key
        
        try:
            totp = self.pyotp.TOTP(secret)
            return totp.verify(token, valid_window=valid_window)
        except Exception as e:
            logger.error(f"TOTP verification failed: {e}")
            return False
    
    def get_current_token(self, secret: str) -> Optional[str]:
        """Get current TOTP token (for testing)"""
        if not self.totp_available:
            return None
        
        totp = self.pyotp.TOTP(secret)
        return totp.now()


# ============================================================================
# 6. IMMUTABLE AUDIT LOGGING
# ============================================================================

@dataclass
class AuditEntry:
    """Single audit log entry"""
    timestamp: float
    action: str
    actor: str  # API key ID, IP, or system
    resource: str
    details: Dict
    signature: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "details": self.details,
            "signature": self.signature,
        }


class AuditLogger:
    """
    Immutable audit log with cryptographic signatures
    Write-only, append-only for tamper detection
    """
    
    # Actions to audit
    ACTIONS = {
        "API_KEY_CREATED": "high",
        "API_KEY_REVOKED": "high",
        "RULE_CREATED": "medium",
        "RULE_APPROVED": "high",
        "RULE_REJECTED": "medium",
        "CONFIG_CHANGED": "high",
        "ATTACK_BLOCKED": "low",
        "HONEYPOT_ACCESS": "medium",
        "AUTH_FAILURE": "high",
        "AUTH_SUCCESS": "low",
        "ADMIN_ACCESS": "high",
        "DATA_EXPORT": "high",
        "SESSION_CLEARED": "high",
        "ML_FEEDBACK_SUBMITTED": "medium",
    }
    
    def __init__(self, 
                 log_path: str = "./data/audit/audit.log",
                 signing_key: Optional[bytes] = None):
        
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # SECURITY FIX: Get signing key from environment, NEVER store on disk
        if signing_key:
            self.signing_key = signing_key
        else:
            # Try environment variable first (preferred)
            env_key = os.environ.get('AUDIT_SIGNING_KEY')
            if env_key:
                import base64
                try:
                    self.signing_key = base64.b64decode(env_key)
                    logger.info("Audit signing key loaded from environment")
                except Exception:
                    logger.error("Invalid AUDIT_SIGNING_KEY format (expected base64)")
                    self.signing_key = os.urandom(32)
            else:
                # Generate key and WARN user to save it
                self.signing_key = os.urandom(32)
                import base64
                key_b64 = base64.b64encode(self.signing_key).decode()
                
                # SECURITY: Print key ONCE and require user to save it
                logger.warning(
                    f"\n{'='*60}\n"
                    f"⚠️  AUDIT SIGNING KEY NOT CONFIGURED!\n"
                    f"Add this to your environment:\n"
                    f"  export AUDIT_SIGNING_KEY={key_b64}\n"
                    f"{'='*60}\n"
                    f"Key shown ONCE. Audit integrity requires same key on restart.\n"
                )
                
                # SECURITY FIX: NEVER write key to disk
                # Old vulnerable code (REMOVED):
                # key_path = self.log_path.parent / ".audit_key"
                # with open(key_path, 'wb') as f:
                #     f.write(self.signing_key)
        
        self.lock = threading.Lock()
        self._last_signature = self._get_last_signature()
    
    def log(self, action: str, actor: str, resource: str, details: Dict = None):
        """
        Log an audit entry
        
        action: One of ACTIONS keys
        actor: Who performed the action (API key ID, IP, "system")
        resource: What was affected (rule ID, session ID, etc.)
        details: Additional context
        """
        if action not in self.ACTIONS:
            logger.warning(f"Unknown audit action: {action}")
        
        entry = AuditEntry(
            timestamp=time.time(),
            action=action,
            actor=actor,
            resource=resource,
            details=details or {},
        )
        
        # Create chain signature (includes previous signature for integrity)
        entry.signature = self._sign_entry(entry)
        
        with self.lock:
            self._append_entry(entry)
            self._last_signature = entry.signature
    
    def _sign_entry(self, entry: AuditEntry) -> str:
        """Create HMAC signature for entry"""
        data = json.dumps({
            "timestamp": entry.timestamp,
            "action": entry.action,
            "actor": entry.actor,
            "resource": entry.resource,
            "details": entry.details,
            "previous": self._last_signature,
        }, sort_keys=True)
        
        signature = hmac.new(
            self.signing_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _append_entry(self, entry: AuditEntry):
        """Append entry to log file"""
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def _get_last_signature(self) -> str:
        """Get signature of last entry for chaining"""
        if not self.log_path.exists():
            return "GENESIS"
        
        try:
            with open(self.log_path, 'rb') as f:
                # Read last line
                f.seek(0, 2)  # End
                size = f.tell()
                if size == 0:
                    return "GENESIS"
                
                # Find last newline
                pos = size - 1
                while pos > 0:
                    f.seek(pos)
                    if f.read(1) == b'\n':
                        break
                    pos -= 1
                
                f.seek(pos + 1 if pos > 0 else 0)
                last_line = f.read().decode().strip()
                
                if last_line:
                    entry = json.loads(last_line)
                    return entry.get("signature", "GENESIS")
        except Exception as e:
            logger.error(f"Failed to read last audit signature: {e}")
        
        return "GENESIS"
    
    def verify_integrity(self) -> tuple[bool, List[str]]:
        """
        Verify audit log integrity
        Returns: (is_valid, list of issues)
        """
        issues = []
        
        if not self.log_path.exists():
            return True, []
        
        try:
            previous_sig = "GENESIS"
            
            with open(self.log_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        entry_dict = json.loads(line.strip())
                        
                        # Recreate entry
                        entry = AuditEntry(
                            timestamp=entry_dict["timestamp"],
                            action=entry_dict["action"],
                            actor=entry_dict["actor"],
                            resource=entry_dict["resource"],
                            details=entry_dict["details"],
                        )
                        
                        # Temporarily set last signature for verification
                        saved_last = self._last_signature
                        self._last_signature = previous_sig
                        
                        expected_sig = self._sign_entry(entry)
                        
                        self._last_signature = saved_last
                        
                        if entry_dict["signature"] != expected_sig:
                            issues.append(f"Line {line_num}: Signature mismatch (possible tampering)")
                        
                        previous_sig = entry_dict["signature"]
                        
                    except json.JSONDecodeError:
                        issues.append(f"Line {line_num}: Invalid JSON")
                    except KeyError as e:
                        issues.append(f"Line {line_num}: Missing field {e}")
        
        except Exception as e:
            issues.append(f"Failed to read audit log: {e}")
        
        return len(issues) == 0, issues
    
    def get_entries(self, 
                    start_time: Optional[float] = None,
                    end_time: Optional[float] = None,
                    action: Optional[str] = None,
                    actor: Optional[str] = None,
                    limit: int = 100) -> List[Dict]:
        """Query audit entries with filters"""
        entries = []
        
        if not self.log_path.exists():
            return entries
        
        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Apply filters
                        if start_time and entry["timestamp"] < start_time:
                            continue
                        if end_time and entry["timestamp"] > end_time:
                            continue
                        if action and entry["action"] != action:
                            continue
                        if actor and entry["actor"] != actor:
                            continue
                        
                        entries.append(entry)
                        
                        if len(entries) >= limit:
                            break
                    except:
                        continue
        except Exception as e:
            logger.error(f"Failed to query audit log: {e}")
        
        return entries


# ============================================================================
# 7. GITIGNORE GENERATOR
# ============================================================================

GITIGNORE_CONTENT = """
# DECEPTICON Security - DO NOT COMMIT
data/security/
data/audit/
*.key
*.pem
ADMIN_KEY.txt

# Environment
.env
.env.local
.env.production

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
venv/
.venv/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Logs
*.log
logs/

# Models (large files)
# models/*.joblib
# models/*.pkl

# Testing
.coverage
htmlcov/
.pytest_cache/

# OS
.DS_Store
Thumbs.db
"""


def create_gitignore(path: str = "./.gitignore"):
    """Create .gitignore with security rules"""
    gitignore_path = Path(path)
    
    if gitignore_path.exists():
        # Append security rules if not present
        with open(gitignore_path, 'r') as f:
            content = f.read()
        
        if "data/security/" not in content:
            with open(gitignore_path, 'a') as f:
                f.write("\n# DECEPTICON Security\n")
                f.write("data/security/\n")
                f.write("data/audit/\n")
                f.write("ADMIN_KEY.txt\n")
            logger.info("Added security rules to existing .gitignore")
    else:
        with open(gitignore_path, 'w') as f:
            f.write(GITIGNORE_CONTENT)
        logger.info("Created .gitignore with security rules")


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

# Initialize on import
admin_key_cleanup = AdminKeyCleanup()
request_size_limiter = RequestSizeLimiter()
totp_manager = TOTPManager()
audit_logger = AuditLogger()
session_encryption = SessionEncryption()


def initialize_security(settings):
    """Initialize all security components based on settings"""
    global session_encryption
    
    # Configure secure logging
    configure_secure_logging(settings.ENV.value if hasattr(settings.ENV, 'value') else str(settings.ENV))
    
    # Start admin key cleanup
    admin_key_cleanup.schedule_cleanup(
        os.path.join(settings.API_KEY_STORAGE_PATH, "ADMIN_KEY.txt")
    )
    
    # Initialize session encryption if configured
    if settings.ENCRYPT_SESSION_DATA and settings.SESSION_ENCRYPTION_KEY:
        session_encryption = SessionEncryption(settings.SESSION_ENCRYPTION_KEY)
    
    # Create .gitignore
    create_gitignore()
    
    logger.info("Security components initialized")
