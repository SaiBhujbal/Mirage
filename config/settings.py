"""
MIRAGE ML-WAF Configuration
Ultra-low latency settings with defense-in-depth
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Dict, Optional
from enum import Enum
import os

class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class LatencyBudget:
    """Strict latency budgets in milliseconds"""
    BLOOM_FILTER = 0.05      # Instant hash lookup
    FAST_RULES = 0.5         # Compiled regex patterns
    ML_INFERENCE = 2.0       # Lightweight model
    TOTAL_SYNC = 3.0         # Max sync path
    ASYNC_BUDGET = 50.0      # Async processing budget
    
    # Thresholds
    ACCEPTABLE = 5.0         # User won't notice
    NOTICEABLE = 50.0        # User might notice
    UNACCEPTABLE = 200.0     # Must never exceed

class Settings(BaseSettings):
    """Main configuration"""
    
    # Environment
    ENV: Environment = Environment.DEVELOPMENT
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    BLOCK_MODE: bool = True
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    WORKERS: int = 4
    
    # Redis (for caching & pub/sub)
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_POOL_SIZE: int = 20
    
    # Latency Settings
    MAX_SYNC_LATENCY_MS: float = LatencyBudget.TOTAL_SYNC
    ENABLE_ML: bool = True
    ENABLE_ASYNC_ML: bool = True
    ENABLE_ASYNC_LOGGING: bool = True
    
    # ML Model Settings (Real-world trained models)
    ML_MODEL_PATH: str = "./models/http_classifier.onnx"
    ML_ANOMALY_MODEL_PATH: str = "./models/http_isolation_forest.onnx"
    ML_SCALER_PATH: str = "./models/http_scaler.onnx"
    ML_THRESHOLD_BLOCK: float = 0.85
    ML_THRESHOLD_SUSPICIOUS: float = 0.5
    ML_THRESHOLD_HONEYPOT: float = 0.7
    ML_BATCH_SIZE: int = 32
    ML_CACHE_SIZE: int = 10000
    
    # Feature Extraction
    MAX_BODY_SIZE: int = 1024 * 1024  # 1MB
    MAX_URL_LENGTH: int = 8192
    MAX_HEADER_SIZE: int = 16384
    
    # Bloom Filter (known bad signatures)
    BLOOM_FILTER_SIZE: int = 1000000
    BLOOM_FILTER_FP_RATE: float = 0.001
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    RATE_LIMIT_BURST: int = 20
    
    # Fingerprinting
    ENABLE_JA3_FINGERPRINT: bool = True
    ENABLE_BEHAVIORAL_FINGERPRINT: bool = True
    FINGERPRINT_CACHE_TTL: int = 3600
    
    # Deception
    ENABLE_HONEYPOT: bool = True
    HONEYPOT_ENGAGEMENT_RATE: float = 0.3
    TARPIT_DELAY_MS: int = 5000
    
    # Zero-Day Protection
    ENABLE_ZERO_DAY_DETECTION: bool = True
    ANOMALY_THRESHOLD: float = 3.0  # Standard deviations
    AUTO_RULE_GENERATION: bool = True
    SHADOW_MODE_SAMPLING: float = 0.1  # 10% of traffic
    
    # Sensitive Data Protection
    SENSITIVE_PATHS: List[str] = [
        "/api/admin",
        "/api/users",
        "/api/auth",
        "/api/secrets",
        "/internal",
    ]
    
    # Protected response patterns (never leak)
    SENSITIVE_PATTERNS: List[str] = [
        r"password[\"']?\s*[:=]",
        r"api[_-]?key[\"']?\s*[:=]",
        r"secret[\"']?\s*[:=]",
        r"token[\"']?\s*[:=]",
        r"-----BEGIN.*PRIVATE KEY-----",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
        r"\b\d{16}\b",  # Credit card
    ]
    
    # Canary Tokens
    ENABLE_CANARY_TOKENS: bool = True
    CANARY_CALLBACK_URL: str = "http://localhost:8080/api/canary/callback"
    
    # Logging
    LOG_REQUESTS: bool = True
    LOG_ASYNC: bool = True
    LOG_RETENTION_DAYS: int = 30
    
    # Metrics
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY HARDENING SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════
    
    # API Authentication
    REQUIRE_API_AUTH: bool = True
    API_KEY_STORAGE_PATH: str = "./data/security"
    ADMIN_API_RATE_LIMIT: int = 100  # per minute
    
    # TLS/HTTPS - AUTO-ENABLED FOR PRODUCTION
    # Will be overridden to True if ENV=production
    REQUIRE_TLS: bool = False
    MIN_TLS_VERSION: str = "TLSv1.2"
    HSTS_MAX_AGE: int = 31536000  # 1 year
    
    # Geoblocking
    ENABLE_GEOBLOCKING: bool = False
    GEOIP_DB_PATH: Optional[str] = None  # Path to MaxMind GeoLite2 database
    BLOCKED_COUNTRIES: List[str] = []  # ISO country codes
    ALLOWED_COUNTRIES: List[str] = []  # If set, only these countries allowed
    
    # Session Storage
    SESSION_STORAGE_TYPE: str = "memory"  # "memory" or "redis"
    SESSION_TTL_SECONDS: int = 86400  # 24 hours
    
    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None  # REQUIRED for production!
    REDIS_DB: int = 0
    REDIS_USE_SSL: bool = False
    
    # SIEM Integration
    ENABLE_SIEM: bool = False
    SIEM_SYSLOG_HOST: Optional[str] = None
    SIEM_SYSLOG_PORT: int = 514
    SIEM_WEBHOOK_URL: Optional[str] = None
    SIEM_LOG_FILE: Optional[str] = None
    
    # Model Poisoning Protection
    REQUIRE_RULE_APPROVAL: bool = True  # Human-in-loop for auto rules
    RULE_STAGING_HOURS: int = 24  # Staging period before activation
    MIN_SAMPLES_FOR_RULE: int = 5  # Minimum detections before rule creation
    
    # Request Size Limits
    MAX_REQUEST_BODY_SIZE: int = 1024 * 1024  # 1MB default
    MAX_URL_LENGTH: int = 8192
    MAX_HEADER_SIZE: int = 16384
    
    # Session Encryption
    ENCRYPT_SESSION_DATA: bool = False  # Enable for sensitive deployments
    SESSION_ENCRYPTION_KEY: Optional[str] = None  # 32-byte Fernet key
    
    # Multi-Factor Authentication
    ENABLE_MFA_FOR_ADMIN: bool = False  # TOTP for admin API keys
    
    # Audit Logging
    ENABLE_AUDIT_LOG: bool = True
    AUDIT_LOG_PATH: str = "./data/audit/audit.log"
    
    # Allowed Origins (for CORS in production)
    ALLOWED_ORIGINS: List[str] = ["https://yourdomain.com"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        validate_assignment = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._apply_production_defaults()
    
    def _apply_production_defaults(self):
        """Auto-apply secure defaults for production"""
        import logging
        import sys
        
        if self.ENV == Environment.PRODUCTION:
            # Force TLS in production
            if not self.REQUIRE_TLS:
                logging.critical(
                    "⚠️  SECURITY WARNING: TLS disabled in production! "
                    "Set REQUIRE_TLS=true or this will fail on next startup."
                )
                # Give one startup grace period, then enforce
                object.__setattr__(self, 'REQUIRE_TLS', True)
            
            # Warn about Redis password
            if self.SESSION_STORAGE_TYPE == "redis" and not self.REDIS_PASSWORD:
                logging.critical(
                    "⚠️  SECURITY WARNING: Redis password not set in production! "
                    "Set REDIS_PASSWORD environment variable."
                )
            
            # Force secure defaults
            object.__setattr__(self, 'DEBUG', False)
            object.__setattr__(self, 'REQUIRE_API_AUTH', True)

            if not self.BLOCK_MODE:
                logging.critical("⚠️  SECURITY WARNING: Block mode disabled in production! Enforcing BLOCK_MODE=true.")
                object.__setattr__(self, 'BLOCK_MODE', True)

# Singleton
settings = Settings()

# Attack Categories
ATTACK_CATEGORIES = {
    "SQLI": {"id": 1, "severity": "critical", "block": True},
    "XSS": {"id": 2, "severity": "high", "block": True},
    "RCE": {"id": 3, "severity": "critical", "block": True},
    "LFI": {"id": 4, "severity": "high", "block": True},
    "RFI": {"id": 5, "severity": "high", "block": True},
    "SSRF": {"id": 6, "severity": "high", "block": True},
    "XXE": {"id": 7, "severity": "high", "block": True},
    "CSRF": {"id": 8, "severity": "medium", "block": False},
    "IDOR": {"id": 9, "severity": "medium", "block": False},
    "BOT": {"id": 10, "severity": "low", "block": False},
    "DDOS": {"id": 11, "severity": "high", "block": True},
    "SCANNER": {"id": 12, "severity": "low", "block": False},
    "ZERO_DAY": {"id": 99, "severity": "critical", "block": True},
}

# MITRE ATT&CK Mapping
MITRE_MAPPING = {
    "SQLI": {"tactic": "Initial Access", "technique": "T1190"},
    "XSS": {"tactic": "Initial Access", "technique": "T1189"},
    "RCE": {"tactic": "Execution", "technique": "T1059"},
    "LFI": {"tactic": "Collection", "technique": "T1005"},
    "RFI": {"tactic": "Execution", "technique": "T1105"},
    "SSRF": {"tactic": "Initial Access", "technique": "T1190"},
    "XXE": {"tactic": "Initial Access", "technique": "T1190"},
    "BOT": {"tactic": "Reconnaissance", "technique": "T1595"},
    "DDOS": {"tactic": "Impact", "technique": "T1498"},
}
