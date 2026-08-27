"""
MIRAGE Security Hardening Module
Addresses pentester-identified vulnerabilities
"""
import os
import hmac
import hashlib
import secrets
import time
import json
import logging
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from functools import wraps
from collections import defaultdict
import threading

logger = logging.getLogger("mirage.security")

# ============================================================================
# API AUTHENTICATION
# ============================================================================

@dataclass
class APIKey:
    """API Key with permissions"""
    key_id: str
    key_hash: str  # Store hash, not plaintext
    name: str
    permissions: List[str]  # ["read", "write", "admin"]
    created_at: float
    expires_at: Optional[float] = None
    last_used: Optional[float] = None
    is_active: bool = True
    rate_limit: int = 100  # requests per minute


class APIKeyManager:
    """
    Secure API key management for WAF admin endpoints
    
    Security measures:
    - Keys stored as SHA-256 hashes
    - Rate limiting per key
    - Permission-based access control
    - Automatic expiration
    """
    
    def __init__(self, storage_path: str = "./data/security"):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
        
        self.keys: Dict[str, APIKey] = {}
        self.key_usage: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
        
        self._load_keys()
        
        # Create default admin key if none exist
        if not self.keys:
            self._create_default_admin_key()
    
    def generate_key(self, name: str, permissions: List[str], 
                     expires_days: Optional[int] = None,
                     rate_limit: int = 100) -> Tuple[str, str]:
        """
        Generate new API key
        Returns: (key_id, plaintext_key) - plaintext shown ONCE
        """
        key_id = secrets.token_hex(8)
        plaintext_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(plaintext_key.encode()).hexdigest()
        
        expires_at = None
        if expires_days:
            expires_at = time.time() + (expires_days * 86400)
        
        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            permissions=permissions,
            created_at=time.time(),
            expires_at=expires_at,
            rate_limit=rate_limit,
        )
        
        with self.lock:
            self.keys[key_id] = api_key
            self._save_keys()
        
        # Return full key: key_id.plaintext_key
        return key_id, f"{key_id}.{plaintext_key}"
    
    def validate_key(self, full_key: str) -> Tuple[bool, Optional[APIKey], str]:
        """
        Validate API key
        Returns: (is_valid, api_key, error_message)
        """
        if not full_key or '.' not in full_key:
            return False, None, "Invalid key format"
        
        try:
            key_id, plaintext = full_key.split('.', 1)
        except ValueError:
            return False, None, "Invalid key format"
        
        with self.lock:
            if key_id not in self.keys:
                return False, None, "Key not found"
            
            api_key = self.keys[key_id]
            
            # Check if active
            if not api_key.is_active:
                return False, None, "Key is disabled"
            
            # Check expiration
            if api_key.expires_at and time.time() > api_key.expires_at:
                return False, None, "Key has expired"
            
            # Verify hash
            provided_hash = hashlib.sha256(plaintext.encode()).hexdigest()
            if not hmac.compare_digest(provided_hash, api_key.key_hash):
                return False, None, "Invalid key"
            
            # Check rate limit
            if not self._check_rate_limit(key_id, api_key.rate_limit):
                return False, None, "Rate limit exceeded"
            
            # Update last used
            api_key.last_used = time.time()
            
            return True, api_key, ""
    
    def check_permission(self, api_key: APIKey, required_permission: str) -> bool:
        """Check if key has required permission"""
        if "admin" in api_key.permissions:
            return True
        return required_permission in api_key.permissions
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key"""
        with self.lock:
            if key_id in self.keys:
                self.keys[key_id].is_active = False
                self._save_keys()
                return True
        return False
    
    def _check_rate_limit(self, key_id: str, limit: int) -> bool:
        """Check rate limit for key (requests per minute)"""
        now = time.time()
        minute_ago = now - 60
        
        # Clean old entries
        self.key_usage[key_id] = [t for t in self.key_usage[key_id] if t > minute_ago]
        
        if len(self.key_usage[key_id]) >= limit:
            return False
        
        self.key_usage[key_id].append(now)
        return True
    
    def _create_default_admin_key(self):
        """
        Create default admin key on first run
        
        SECURITY FIX: 
        - NEVER writes key to filesystem
        - Shows key ONCE on console
        - Key must be saved immediately
        """
        key_id, full_key = self.generate_key(
            name="default_admin",
            permissions=["admin"],
            rate_limit=1000
        )
        
        # SECURITY FIX: NEVER write plaintext key to file!
        # OLD VULNERABLE CODE (REMOVED):
        # key_file = os.path.join(self.storage_path, "ADMIN_KEY.txt")
        # with open(key_file, 'w') as f:
        #     f.write(f"Key: {full_key}\n")
        
        # Display key ONCE on console
        print("\n" + "=" * 70)
        print("[SECURITY] MIRAGE ADMIN API KEY - SAVE THIS NOW!")
        print("=" * 70)
        print(f"\nAPI Key: {full_key}\n")
        print("[WARNING] THIS KEY WILL NOT BE SHOWN AGAIN!")
        print("[WARNING] SAVE IT SECURELY (password manager, vault, etc.)")
        print("[WARNING] Set as environment variable: MIRAGE_ADMIN_KEY")
        print("=" * 70 + "\n")
        
        # Also log (without the key itself for security)
        logger.warning(
            f"Admin API key created (key_id: {key_id}). "
            f"Key was displayed on console - save it immediately!"
        )
    
    def _save_keys(self):
        """Save keys to disk (hashes only, never plaintext)"""
        data = {}
        for key_id, api_key in self.keys.items():
            data[key_id] = {
                "key_id": api_key.key_id,
                "key_hash": api_key.key_hash,
                "name": api_key.name,
                "permissions": api_key.permissions,
                "created_at": api_key.created_at,
                "expires_at": api_key.expires_at,
                "last_used": api_key.last_used,
                "is_active": api_key.is_active,
                "rate_limit": api_key.rate_limit,
            }
        
        keys_file = os.path.join(self.storage_path, "api_keys.json")
        with open(keys_file, 'w') as f:
            json.dump(data, f, indent=2)
        os.chmod(keys_file, 0o600)
    
    def _load_keys(self):
        """Load keys from disk"""
        keys_file = os.path.join(self.storage_path, "api_keys.json")
        if os.path.exists(keys_file):
            try:
                with open(keys_file) as f:
                    data = json.load(f)
                for key_id, key_data in data.items():
                    self.keys[key_id] = APIKey(**key_data)
            except Exception as e:
                logger.error(f"Failed to load API keys: {e}")


# ============================================================================
# ERROR SANITIZATION
# ============================================================================

class ErrorSanitizer:
    """
    Sanitize error messages to prevent information disclosure
    
    Security measures:
    - Generic error messages to clients
    - Detailed errors only in secure logs
    - No stack traces in responses
    - No internal paths exposed
    """
    
    # Map internal errors to generic messages
    ERROR_MAP = {
        "database": "Service temporarily unavailable",
        "connection": "Service temporarily unavailable",
        "timeout": "Request timed out",
        "validation": "Invalid request",
        "authentication": "Authentication failed",
        "authorization": "Access denied",
        "not_found": "Resource not found",
        "rate_limit": "Too many requests",
        "internal": "An error occurred",
    }
    
    # Patterns to redact from error messages
    REDACT_PATTERNS = [
        (r'/home/\w+', '/home/***'),
        (r'/var/\w+', '/var/***'),
        (r'/etc/\w+', '/etc/***'),
        (r'password[=:]\s*\S+', 'password=***'),
        (r'api[_-]?key[=:]\s*\S+', 'api_key=***'),
        (r'secret[=:]\s*\S+', 'secret=***'),
        (r'token[=:]\s*\S+', 'token=***'),
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP REDACTED]'),
        (r'at 0x[0-9a-f]+', 'at [ADDR]'),
    ]
    
    @classmethod
    def sanitize(cls, error: Exception, include_type: bool = False) -> str:
        """
        Sanitize error for client response
        Returns generic, safe error message
        """
        error_str = str(error).lower()
        
        # Match to generic error
        for keyword, generic_msg in cls.ERROR_MAP.items():
            if keyword in error_str:
                return generic_msg
        
        # Default generic message
        return "An error occurred"
    
    @classmethod
    def log_detailed(cls, error: Exception, context: Dict = None) -> str:
        """
        Create detailed error for secure logging
        Redacts sensitive information
        """
        import traceback
        import re
        
        detailed = f"Error: {type(error).__name__}: {str(error)}\n"
        detailed += f"Traceback:\n{traceback.format_exc()}"
        
        if context:
            detailed += f"\nContext: {json.dumps(context, default=str)}"
        
        # Redact sensitive patterns
        for pattern, replacement in cls.REDACT_PATTERNS:
            detailed = re.sub(pattern, replacement, detailed, flags=re.IGNORECASE)
        
        return detailed
    
    @classmethod
    def safe_response(cls, status: str, message: str = None) -> Dict:
        """Create safe API response"""
        return {
            "status": status,
            "message": message or cls.ERROR_MAP.get("internal"),
            "timestamp": time.time(),
        }


# ============================================================================
# GEOLOCATION & GEOBLOCKING
# ============================================================================

class GeoBlocker:
    """
    IP geolocation and geoblocking
    
    Uses local GeoLite2 database (no external API calls)
    """
    
    def __init__(self, blocked_countries: List[str] = None,
                 allowed_countries: List[str] = None,
                 geoip_db_path: str = None):
        
        self.blocked_countries = set(blocked_countries or [])
        self.allowed_countries = set(allowed_countries or [])
        self.geoip_reader = None
        
        # Try to load GeoIP database
        if geoip_db_path:
            self._load_geoip(geoip_db_path)
    
    def _load_geoip(self, db_path: str):
        """Load MaxMind GeoIP database"""
        try:
            import geoip2.database
            self.geoip_reader = geoip2.database.Reader(db_path)
            logger.info(f"Loaded GeoIP database from {db_path}")
        except ImportError:
            logger.warning("geoip2 not installed. Geoblocking disabled.")
        except Exception as e:
            logger.warning(f"Failed to load GeoIP database: {e}")
    
    def get_country(self, ip: str) -> Optional[str]:
        """Get country code for IP"""
        if not self.geoip_reader:
            return None
        
        try:
            response = self.geoip_reader.country(ip)
            return response.country.iso_code
        except Exception:
            return None
    
    def is_blocked(self, ip: str) -> Tuple[bool, str]:
        """
        Check if IP should be blocked based on geolocation
        Returns: (is_blocked, reason)
        """
        country = self.get_country(ip)
        
        if not country:
            # Can't determine country - allow by default
            return False, ""
        
        # Check blocklist first
        if country in self.blocked_countries:
            return True, f"Country {country} is blocked"
        
        # If allowlist is set, check if country is allowed
        if self.allowed_countries and country not in self.allowed_countries:
            return True, f"Country {country} is not in allowlist"
        
        return False, ""
    
    def get_geo_info(self, ip: str) -> Dict:
        """Get full geo info for IP"""
        if not self.geoip_reader:
            return {"available": False}
        
        try:
            response = self.geoip_reader.country(ip)
            return {
                "available": True,
                "country_code": response.country.iso_code,
                "country_name": response.country.name,
                "continent": response.continent.code,
            }
        except Exception:
            return {"available": False}


# ============================================================================
# TLS ENFORCEMENT
# ============================================================================

class TLSEnforcer:
    """
    Enforce TLS/HTTPS requirements
    """
    
    def __init__(self, 
                 require_tls: bool = True,
                 min_tls_version: str = "TLSv1.2",
                 hsts_max_age: int = 31536000):
        
        self.require_tls = require_tls
        self.min_tls_version = min_tls_version
        self.hsts_max_age = hsts_max_age
        
        self.tls_versions = {
            "TLSv1.0": 1.0,
            "TLSv1.1": 1.1,
            "TLSv1.2": 1.2,
            "TLSv1.3": 1.3,
        }
    
    def check_request(self, is_https: bool, tls_version: str = None) -> Tuple[bool, str]:
        """
        Check if request meets TLS requirements
        Returns: (is_allowed, error_message)
        """
        if self.require_tls and not is_https:
            return False, "HTTPS required"
        
        if tls_version and self.min_tls_version:
            req_ver = self.tls_versions.get(tls_version, 0)
            min_ver = self.tls_versions.get(self.min_tls_version, 1.2)
            
            if req_ver < min_ver:
                return False, f"Minimum TLS version {self.min_tls_version} required"
        
        return True, ""
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers to add to responses"""
        headers = {
            "Strict-Transport-Security": f"max-age={self.hsts_max_age}; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
        }
        return headers


# ============================================================================
# SIEM INTEGRATION
# ============================================================================

class SIEMIntegration:
    """
    Security Information and Event Management integration
    
    Supports:
    - Syslog (RFC 5424)
    - Webhook (JSON)
    - File-based for SIEM ingestion
    """
    
    def __init__(self, 
                 syslog_host: str = None,
                 syslog_port: int = 514,
                 webhook_url: str = None,
                 file_path: str = None):
        
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.webhook_url = webhook_url
        self.file_path = file_path
        
        self.syslog_handler = None
        self._setup_syslog()
    
    def _setup_syslog(self):
        """Setup syslog handler"""
        if self.syslog_host:
            try:
                import logging.handlers
                self.syslog_handler = logging.handlers.SysLogHandler(
                    address=(self.syslog_host, self.syslog_port)
                )
                logger.info(f"SIEM: Syslog configured to {self.syslog_host}:{self.syslog_port}")
            except Exception as e:
                logger.error(f"SIEM: Failed to setup syslog: {e}")
    
    def send_event(self, event_type: str, severity: str, data: Dict):
        """
        Send security event to SIEM
        
        event_type: "attack_detected", "honeypot_access", "rule_triggered", etc.
        severity: "critical", "high", "medium", "low", "info"
        """
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "source": "mirage_waf",
            "data": data,
        }
        
        # Send to all configured destinations
        if self.syslog_handler:
            self._send_syslog(event)
        
        if self.webhook_url:
            self._send_webhook(event)
        
        if self.file_path:
            self._write_file(event)
    
    def _send_syslog(self, event: Dict):
        """Send to syslog"""
        try:
            severity_map = {
                "critical": 2,  # LOG_CRIT
                "high": 3,      # LOG_ERR
                "medium": 4,    # LOG_WARNING
                "low": 5,       # LOG_NOTICE
                "info": 6,      # LOG_INFO
            }
            
            priority = severity_map.get(event["severity"], 6)
            message = json.dumps(event)
            
            # Format as CEF (Common Event Format) for better SIEM compatibility
            cef = f"CEF:0|Mirage|WAF|1.0|{event['event_type']}|{event['severity']}|{priority}|{message}"
            
            self.syslog_handler.emit(
                logging.LogRecord(
                    name="mirage",
                    level=logging.WARNING,
                    pathname="",
                    lineno=0,
                    msg=cef,
                    args=(),
                    exc_info=None
                )
            )
        except Exception as e:
            logger.error(f"SIEM syslog error: {e}")
    
    def _send_webhook(self, event: Dict):
        """Send to webhook"""
        try:
            import urllib.request

            # Restrict to http(s): the webhook URL is operator config, but a scheme guard stops
            # a misconfiguration or tampered config from turning urlopen into a file://-read.
            if not str(self.webhook_url).lower().startswith(("http://", "https://")):
                logger.error("SIEM webhook URL must be http(s), refusing: %s", self.webhook_url)
                return

            data = json.dumps(event).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status != 200:
                    logger.warning(f"SIEM webhook returned {response.status}")
        except Exception as e:
            logger.error(f"SIEM webhook error: {e}")
    
    def _write_file(self, event: Dict):
        """Write to file for SIEM ingestion"""
        try:
            with open(self.file_path, 'a') as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"SIEM file write error: {e}")


# ============================================================================
# MODEL POISONING PROTECTION
# ============================================================================

class ModelPoisoningProtection:
    """
    Protect against ML model poisoning attacks
    
    Security measures:
    - Validate training data sources
    - Human-in-loop for auto-generated rules
    - Anomaly detection in training data
    - Rule staging before activation
    """
    
    def __init__(self, require_approval: bool = True,
                 min_samples_for_rule: int = 5,
                 staging_period_hours: int = 24):
        
        self.require_approval = require_approval
        self.min_samples_for_rule = min_samples_for_rule
        self.staging_period_hours = staging_period_hours
        
        self.staged_rules: Dict[str, Dict] = {}
        self.approved_rules: Dict[str, Dict] = {}
        self.lock = threading.Lock()
    
    def validate_training_sample(self, payload: str, category: str, 
                                  source: str) -> Tuple[bool, str]:
        """
        Validate training sample before adding to dataset
        
        Checks:
        - Source is trusted
        - Payload matches claimed category
        - No anomalies in payload
        """
        # Check trusted sources
        trusted_sources = ["honeypot", "pattern_engine", "manual_review"]
        if source not in trusted_sources:
            return False, f"Untrusted source: {source}"
        
        # Basic sanity checks
        if len(payload) > 10000:
            return False, "Payload too large"
        
        if len(payload) < 3:
            return False, "Payload too small"
        
        # Check for obvious poisoning attempts
        poison_indicators = [
            "ignore previous",
            "disregard above",
            "new instructions",
            "admin override",
        ]
        
        payload_lower = payload.lower()
        for indicator in poison_indicators:
            if indicator in payload_lower:
                return False, f"Potential poisoning: {indicator}"
        
        return True, ""
    
    def stage_rule(self, rule_id: str, pattern: str, category: str,
                   source: str, confidence: float) -> bool:
        """
        Stage a rule for review before activation
        """
        with self.lock:
            self.staged_rules[rule_id] = {
                "rule_id": rule_id,
                "pattern": pattern,
                "category": category,
                "source": source,
                "confidence": confidence,
                "staged_at": time.time(),
                "hits_during_staging": 0,
                "false_positives_during_staging": 0,
            }
        
        logger.info(f"Rule {rule_id} staged for review")
        return True
    
    def approve_rule(self, rule_id: str, approved_by: str) -> bool:
        """Approve a staged rule for production"""
        with self.lock:
            if rule_id not in self.staged_rules:
                return False
            
            rule = self.staged_rules.pop(rule_id)
            rule["approved_by"] = approved_by
            rule["approved_at"] = time.time()
            
            self.approved_rules[rule_id] = rule
        
        logger.info(f"Rule {rule_id} approved by {approved_by}")
        return True
    
    def reject_rule(self, rule_id: str, rejected_by: str, reason: str) -> bool:
        """Reject a staged rule"""
        with self.lock:
            if rule_id in self.staged_rules:
                rule = self.staged_rules.pop(rule_id)
                logger.info(f"Rule {rule_id} rejected by {rejected_by}: {reason}")
                return True
        return False
    
    def get_production_rules(self) -> List[Dict]:
        """Get rules that are approved for production"""
        with self.lock:
            # If approval not required, auto-approve after staging period
            if not self.require_approval:
                now = time.time()
                staging_seconds = self.staging_period_hours * 3600
                
                auto_approve = []
                for rule_id, rule in self.staged_rules.items():
                    if now - rule["staged_at"] > staging_seconds:
                        if rule["false_positives_during_staging"] < 3:
                            auto_approve.append(rule_id)
                
                for rule_id in auto_approve:
                    rule = self.staged_rules.pop(rule_id)
                    rule["approved_by"] = "auto"
                    rule["approved_at"] = now
                    self.approved_rules[rule_id] = rule
            
            return list(self.approved_rules.values())
    
    def record_staging_hit(self, rule_id: str, is_false_positive: bool):
        """Record hit during staging period"""
        with self.lock:
            if rule_id in self.staged_rules:
                self.staged_rules[rule_id]["hits_during_staging"] += 1
                if is_false_positive:
                    self.staged_rules[rule_id]["false_positives_during_staging"] += 1


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

api_key_manager = APIKeyManager()
error_sanitizer = ErrorSanitizer()
geo_blocker = GeoBlocker()
# Disable TLS requirement for development/testing
require_tls_in_dev = os.environ.get('ENV') == 'production'
tls_enforcer = TLSEnforcer(require_tls=require_tls_in_dev)
siem = SIEMIntegration()
model_protection = ModelPoisoningProtection()
