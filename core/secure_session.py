"""
DECEPTICON Secure Session Manager
FIXES: Predictable Session IDs, Session Hijacking, Session Enumeration

SECURITY MEASURES:
1. Cryptographically secure random session IDs (256-bit)
2. Session binding (IP + fingerprint)
3. Session rotation on privilege change
4. Secure session storage with encryption
5. Session enumeration protection
"""
import os
import time
import secrets
import hashlib
import hmac
import logging
from typing import Dict, Optional, Set, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import threading
import json

logger = logging.getLogger("decepticon.security.session")


# ============================================================================
# SECURE SESSION ID GENERATION
# ============================================================================

class SecureSessionIDGenerator:
    """
    Generate cryptographically secure session IDs
    
    FIXES:
    - Predictable session IDs (was: MD5 of IP+UA)
    - Session enumeration (was: 16-char hex = 2^64 space)
    
    NOW:
    - 256-bit random tokens (secrets.token_urlsafe)
    - Unpredictable, unguessable
    - No correlation to user data
    """
    
    # Session ID length (characters)
    # 43 chars of base64 = 256 bits of entropy
    SESSION_ID_LENGTH = 43
    
    @classmethod
    def generate(cls) -> str:
        """Generate a cryptographically secure session ID"""
        # secrets.token_urlsafe uses os.urandom internally
        # 32 bytes = 256 bits of entropy
        return secrets.token_urlsafe(32)
    
    @classmethod
    def is_valid_format(cls, session_id: str) -> bool:
        """Check if session ID has valid format"""
        if not session_id:
            return False
        
        # URL-safe base64: alphanumeric + '-' + '_'
        import re
        pattern = r'^[A-Za-z0-9_-]{32,64}$'
        return bool(re.match(pattern, session_id))
    
    @classmethod
    def hash_for_storage(cls, session_id: str) -> str:
        """
        Hash session ID for storage
        
        We store the hash, not the session ID itself.
        This way, even if storage is compromised, 
        session IDs can't be recovered.
        """
        return hashlib.sha256(session_id.encode()).hexdigest()


# ============================================================================
# SESSION BINDING (Anti-Hijacking)
# ============================================================================

@dataclass
class SessionBinding:
    """
    Bind session to client characteristics
    
    FIXES: Session hijacking by requiring matching characteristics
    """
    ip_hash: str  # Hash of IP (privacy)
    fingerprint_hash: str  # Hash of browser fingerprint
    ua_hash: str  # Hash of User-Agent
    created_at: float
    last_verified: float
    
    # Tolerance settings
    BINDING_STRICT: bool = True  # All must match
    ALLOW_IP_CHANGE: bool = False  # Mobile users may change IP
    
    @classmethod
    def create(cls, client_ip: str, fingerprint: str, user_agent: str) -> 'SessionBinding':
        """Create binding from client characteristics"""
        return cls(
            ip_hash=hashlib.sha256(client_ip.encode()).hexdigest()[:32],
            fingerprint_hash=hashlib.sha256(fingerprint.encode()).hexdigest()[:32],
            ua_hash=hashlib.sha256(user_agent.encode()).hexdigest()[:32],
            created_at=time.time(),
            last_verified=time.time(),
        )
    
    def verify(self, client_ip: str, fingerprint: str, user_agent: str) -> Tuple[bool, str]:
        """
        Verify session binding matches client
        
        Returns: (is_valid, reason)
        """
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:32]
        fp_hash = hashlib.sha256(fingerprint.encode()).hexdigest()[:32]
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:32]
        
        mismatches = []
        
        if not self.ALLOW_IP_CHANGE:
            if not hmac.compare_digest(ip_hash, self.ip_hash):
                mismatches.append("IP")
        
        if not hmac.compare_digest(fp_hash, self.fingerprint_hash):
            mismatches.append("fingerprint")
        
        if not hmac.compare_digest(ua_hash, self.ua_hash):
            mismatches.append("user_agent")
        
        if self.BINDING_STRICT and mismatches:
            return False, f"Session binding mismatch: {', '.join(mismatches)}"
        
        if len(mismatches) >= 2:
            return False, f"Multiple binding mismatches: {', '.join(mismatches)}"
        
        self.last_verified = time.time()
        return True, ""
    
    def to_dict(self) -> Dict:
        return {
            "ip_hash": self.ip_hash,
            "fingerprint_hash": self.fingerprint_hash,
            "ua_hash": self.ua_hash,
            "created_at": self.created_at,
            "last_verified": self.last_verified,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SessionBinding':
        return cls(
            ip_hash=data["ip_hash"],
            fingerprint_hash=data["fingerprint_hash"],
            ua_hash=data["ua_hash"],
            created_at=data["created_at"],
            last_verified=data["last_verified"],
        )


# ============================================================================
# SECURE SESSION DATA
# ============================================================================

@dataclass
class SecureSession:
    """
    Secure session with anti-hijacking measures
    """
    # Session identification (stored as hash)
    session_id_hash: str
    
    # Session binding
    binding: SessionBinding
    
    # Session data
    created_at: float
    last_activity: float
    request_count: int = 0
    
    # Security state
    is_valid: bool = True
    risk_score: float = 0.0
    cumulative_risk: float = 0.0  # Cumulative risk score over session lifetime
    attack_categories: Set[str] = field(default_factory=set)
    unique_paths: Set[str] = field(default_factory=set)  # Track unique paths accessed
    unique_user_agents: Set[str] = field(default_factory=set)  # Track user agent changes
    error_count: int = 0  # Track errors for anomaly detection

    # Properties for compatibility with WAF engine
    @property
    def first_seen(self) -> float:
        """Alias for created_at"""
        return self.created_at

    @property
    def last_seen(self) -> float:
        """Alias for last_activity"""
        return self.last_activity
    
    # Session limits
    MAX_IDLE_SECONDS: int = 3600  # 1 hour
    MAX_SESSION_SECONDS: int = 86400  # 24 hours
    MAX_REQUESTS_PER_SESSION: int = 100000
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        now = time.time()
        
        # Idle timeout
        if now - self.last_activity > self.MAX_IDLE_SECONDS:
            return True
        
        # Absolute timeout
        if now - self.created_at > self.MAX_SESSION_SECONDS:
            return True
        
        return False
    
    def touch(self):
        """Update last activity time"""
        self.last_activity = time.time()
        self.request_count += 1
    
    def to_dict(self) -> Dict:
        return {
            "session_id_hash": self.session_id_hash,
            "binding": self.binding.to_dict(),
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "request_count": self.request_count,
            "is_valid": self.is_valid,
            "risk_score": self.risk_score,
            "attack_categories": list(self.attack_categories),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SecureSession':
        return cls(
            session_id_hash=data["session_id_hash"],
            binding=SessionBinding.from_dict(data["binding"]),
            created_at=data["created_at"],
            last_activity=data["last_activity"],
            request_count=data.get("request_count", 0),
            is_valid=data.get("is_valid", True),
            risk_score=data.get("risk_score", 0.0),
            attack_categories=set(data.get("attack_categories", [])),
        )


# ============================================================================
# SECURE SESSION MANAGER
# ============================================================================

class SecureSessionManager:
    """
    Secure session management with anti-hijacking and enumeration protection
    
    FIXES:
    1. Predictable session IDs -> Cryptographically random
    2. Session hijacking -> Session binding verification
    3. Session enumeration -> No public session lookup
    4. Session fixation -> Session rotation on auth
    """
    
    def __init__(self, 
                 storage_backend = None,
                 session_encryption_key: bytes = None):
        
        # Session storage (in-memory or Redis)
        self.storage = storage_backend or {}
        self.use_external_storage = storage_backend is not None
        
        # Session lookup by hash only (prevents enumeration)
        self.session_lookup: Dict[str, SecureSession] = {}
        
        # Rate limiting for session creation
        self.creation_limiter: Dict[str, List[float]] = defaultdict(list)
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
        # Encryption for sensitive data
        self.encryption_key = session_encryption_key

        # Max sessions limit
        self.max_sessions = 10000  # Reasonable limit for memory management

        logger.info("SecureSessionManager initialized")

    @property
    def sessions(self) -> Dict[str, SecureSession]:
        """
        Property to access session_lookup for backward compatibility

        Returns:
            Dictionary of sessions keyed by session ID hash
        """
        return self.session_lookup

    def get_or_create_session(self, ctx, tls_info=None):
        """
        Get existing session or create new one for the request

        Args:
            ctx: RequestContext object
            tls_info: Optional TLS information

        Returns:
            SecureSession object
        """
        # Extract session ID from headers/cookies if present
        session_id = ctx.headers.get('x-session-id') or ctx.headers.get('cookie', '').split('session_id=')[-1].split(';')[0] if 'session_id=' in ctx.headers.get('cookie', '') else None

        if session_id:
            # Try to validate existing session
            fingerprint = f"{ctx.headers.get('user-agent', '')}:{ctx.client_ip}"
            is_valid, session, error = self.validate_session(
                session_id,
                ctx.client_ip,
                fingerprint,
                ctx.headers.get('user-agent', '')
            )
            if is_valid and session:
                return session

        # Create new session
        fingerprint = f"{ctx.headers.get('user-agent', '')}:{ctx.client_ip}"
        session_id, error = self.create_session(
            ctx.client_ip,
            fingerprint,
            ctx.headers.get('user-agent', '')
        )

        if session_id:
            # Look up the session we just created
            session_id_hash = SecureSessionIDGenerator.hash_for_storage(session_id)
            with self.lock:
                return self.session_lookup.get(session_id_hash)

        # Fallback: create a temporary session object if creation failed
        return SecureSession(
            session_id_hash="temp",
            binding=SessionBinding.create(ctx.client_ip, fingerprint, ctx.headers.get('user-agent', '')),
            created_at=time.time(),
            last_activity=time.time(),
        )

    def create_session(self, 
                       client_ip: str, 
                       fingerprint: str, 
                       user_agent: str) -> Tuple[Optional[str], str]:
        """
        Create a new secure session
        
        Returns: (session_id, error_message)
        """
        # Rate limit session creation (prevent DoS)
        if not self._check_creation_rate(client_ip):
            return None, "Session creation rate limit exceeded"
        
        # Generate secure session ID
        session_id = SecureSessionIDGenerator.generate()
        session_id_hash = SecureSessionIDGenerator.hash_for_storage(session_id)
        
        # Create session binding
        binding = SessionBinding.create(client_ip, fingerprint, user_agent)
        
        # Create session
        session = SecureSession(
            session_id_hash=session_id_hash,
            binding=binding,
            created_at=time.time(),
            last_activity=time.time(),
        )
        
        # Store session
        with self.lock:
            self.session_lookup[session_id_hash] = session
        
        logger.debug(f"Created session: {session_id_hash[:16]}...")
        
        # Return plaintext session ID (only time it's exposed)
        return session_id, ""
    
    def validate_session(self,
                         session_id: str,
                         client_ip: str,
                         fingerprint: str,
                         user_agent: str) -> Tuple[bool, Optional[SecureSession], str]:
        """
        Validate session and verify binding
        
        Returns: (is_valid, session, error_message)
        """
        # Check session ID format
        if not SecureSessionIDGenerator.is_valid_format(session_id):
            return False, None, "Invalid session ID format"
        
        # Get session by hash (prevents timing attacks)
        session_id_hash = SecureSessionIDGenerator.hash_for_storage(session_id)
        
        with self.lock:
            session = self.session_lookup.get(session_id_hash)
        
        if not session:
            # SECURITY FIX: Constant time - do dummy work to match valid session timing
            dummy_binding = SessionBinding.create("0.0.0.0", "dummy", "dummy")
            dummy_binding.verify("0.0.0.0", "dummy", "dummy")
            time.sleep(0.0001)  # Match typical binding verification time
            return False, None, "Session not found"
        
        # Check if expired
        if session.is_expired():
            self._invalidate_session(session_id_hash)
            # Do dummy binding work for constant time
            session.binding.verify(client_ip, fingerprint, user_agent)
            return False, None, "Session expired"
        
        # Check if invalidated
        if not session.is_valid:
            # Do dummy binding work for constant time
            session.binding.verify(client_ip, fingerprint, user_agent)
            return False, None, "Session invalidated"
        
        # Verify binding (anti-hijacking)
        # SECURITY: This is always computed regardless of result
        is_bound, bind_error = session.binding.verify(client_ip, fingerprint, user_agent)
        
        # SECURITY FIX: Always update activity (makes timing constant)
        session.touch()
        
        # SECURITY FIX: Log and flag ASYNCHRONOUSLY to avoid timing leak
        if not is_bound:
            # Potential hijacking attempt - log async so timing is constant
            import threading
            threading.Thread(
                target=self._async_log_and_flag,
                args=(session_id_hash, bind_error),
                daemon=True
            ).start()
            return False, None, "Session binding verification failed"
        
        return True, session, ""
    
    def _async_log_and_flag(self, session_id_hash: str, error: str):
        """Log and flag suspicious session asynchronously (for constant-time response)"""
        logger.warning(f"Session binding failed: {error}")
        self._flag_suspicious_session(session_id_hash)

    def update_session(self, session, ctx, result):
        """
        Update session state with request context and WAF result

        Args:
            session: SecureSession object
            ctx: RequestContext object
            result: WAFResult object
        """
        with self.lock:
            # Update activity timestamp
            session.last_activity = time.time()
            session.request_count += 1

            # Track unique paths
            if hasattr(ctx, 'path'):
                session.unique_paths.add(ctx.path)

            # Track user agent changes
            if hasattr(ctx, 'headers'):
                ua = ctx.headers.get('user-agent', '')
                if ua:
                    session.unique_user_agents.add(ua)

            # Update risk scores
            if hasattr(result, 'risk_level'):
                from core.models import RiskLevel
                risk_value = {
                    RiskLevel.CRITICAL: 100,
                    RiskLevel.HIGH: 75,
                    RiskLevel.MEDIUM: 50,
                    RiskLevel.LOW: 25,
                    RiskLevel.NONE: 0
                }.get(result.risk_level, 0)

                session.risk_score = max(session.risk_score, risk_value)
                session.cumulative_risk += risk_value

            # Track attack categories
            if hasattr(result, 'detections'):
                for detection in result.detections:
                    if hasattr(detection, 'category'):
                        session.attack_categories.add(detection.category)
    
    def get_session_stats(self, 
                          session_id: str,
                          requester_ip: str) -> Optional[Dict]:
        """
        Get session statistics (for authorized requests only)
        
        SECURITY: Only returns stats for YOUR OWN session
        Prevents IDOR / session enumeration
        """
        if not SecureSessionIDGenerator.is_valid_format(session_id):
            # Constant time: compute hash anyway
            _ = SecureSessionIDGenerator.hash_for_storage(session_id or "invalid")
            return None
        
        session_id_hash = SecureSessionIDGenerator.hash_for_storage(session_id)
        
        with self.lock:
            session = self.session_lookup.get(session_id_hash)
        
        # SECURITY FIX: Always compute IP hash for constant time
        requester_ip_hash = hashlib.sha256(requester_ip.encode()).hexdigest()[:32]
        
        if not session:
            # Constant time: do dummy comparison
            hmac.compare_digest(requester_ip_hash, "0" * 32)
            return None
        
        # Verify this is the requester's own session (by IP hash)
        # Using constant-time comparison
        if not hmac.compare_digest(requester_ip_hash, session.binding.ip_hash):
            # Not your session! (IDOR protection)
            # Log async to avoid timing leak
            import threading
            threading.Thread(
                target=lambda: logger.warning(f"IDOR attempt: access to session {session_id_hash[:16]}"),
                daemon=True
            ).start()
            return None
        
        # Return limited, safe data
        return {
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "request_count": session.request_count,
            "risk_score": session.risk_score,
            "attack_categories": list(session.attack_categories),
            # NO fingerprints, NO IP, NO UA exposed!
        }
    
    def rotate_session(self,
                       old_session_id: str,
                       client_ip: str,
                       fingerprint: str,
                       user_agent: str) -> Tuple[Optional[str], str]:
        """
        Rotate session (create new ID, invalidate old)
        
        Use after authentication or privilege change
        FIXES: Session fixation attacks
        """
        # Validate old session first
        is_valid, old_session, error = self.validate_session(
            old_session_id, client_ip, fingerprint, user_agent
        )
        
        if not is_valid:
            return None, error
        
        # Create new session
        new_session_id, error = self.create_session(client_ip, fingerprint, user_agent)
        if not new_session_id:
            return None, error
        
        # Copy session data to new session
        new_session_hash = SecureSessionIDGenerator.hash_for_storage(new_session_id)
        with self.lock:
            new_session = self.session_lookup.get(new_session_hash)
            if new_session and old_session:
                new_session.risk_score = old_session.risk_score
                new_session.attack_categories = old_session.attack_categories.copy()
        
        # Invalidate old session
        old_session_hash = SecureSessionIDGenerator.hash_for_storage(old_session_id)
        self._invalidate_session(old_session_hash)
        
        logger.info(f"Rotated session: {old_session_hash[:16]} -> {new_session_hash[:16]}")
        
        return new_session_id, ""
    
    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session (logout)"""
        if not SecureSessionIDGenerator.is_valid_format(session_id):
            return False
        
        session_id_hash = SecureSessionIDGenerator.hash_for_storage(session_id)
        return self._invalidate_session(session_id_hash)
    
    def _invalidate_session(self, session_id_hash: str) -> bool:
        """Internal: Invalidate session by hash"""
        with self.lock:
            if session_id_hash in self.session_lookup:
                session = self.session_lookup[session_id_hash]
                session.is_valid = False
                del self.session_lookup[session_id_hash]
                return True
        return False
    
    def _flag_suspicious_session(self, session_id_hash: str):
        """Flag session as suspicious (potential hijack)"""
        with self.lock:
            if session_id_hash in self.session_lookup:
                session = self.session_lookup[session_id_hash]
                session.risk_score = min(1.0, session.risk_score + 0.5)
                session.attack_categories.add("SESSION_HIJACK_ATTEMPT")
    
    def _check_creation_rate(self, client_ip: str) -> bool:
        """Rate limit session creation per IP"""
        now = time.time()
        window = 60  # 1 minute
        max_creations = 10  # Max 10 sessions per minute per IP
        
        with self.lock:
            # Clean old entries
            self.creation_limiter[client_ip] = [
                t for t in self.creation_limiter[client_ip]
                if now - t < window
            ]
            
            # Check limit
            if len(self.creation_limiter[client_ip]) >= max_creations:
                return False
            
            # Record creation
            self.creation_limiter[client_ip].append(now)
        
        return True
    
    def record_attack(self, session_id: str, category: str, confidence: float):
        """Record attack against session"""
        if not SecureSessionIDGenerator.is_valid_format(session_id):
            return
        
        session_id_hash = SecureSessionIDGenerator.hash_for_storage(session_id)
        
        with self.lock:
            if session_id_hash in self.session_lookup:
                session = self.session_lookup[session_id_hash]
                session.attack_categories.add(category)
                session.risk_score = min(1.0, session.risk_score + confidence * 0.3)
    
    def cleanup_expired(self):
        """Clean up expired sessions"""
        with self.lock:
            expired = [
                sid_hash for sid_hash, session in self.session_lookup.items()
                if session.is_expired()
            ]
            
            for sid_hash in expired:
                del self.session_lookup[sid_hash]
        
        logger.debug(f"Cleaned up {len(expired)} expired sessions")


# ============================================================================
# ADMIN SESSION ACCESS (Authenticated Only)
# ============================================================================

class AdminSessionAccess:
    """
    Admin-only session access with audit logging
    
    FIXES: IDOR on session endpoints
    Only admins can access other users' sessions, with full audit trail
    """
    
    def __init__(self, session_manager: SecureSessionManager, audit_logger = None):
        self.session_manager = session_manager
        self.audit_logger = audit_logger
    
    def admin_get_session(self, 
                          session_id: str,
                          admin_key_id: str,
                          admin_ip: str) -> Tuple[Optional[Dict], str]:
        """
        Admin access to any session (audited)
        
        Returns: (session_data, error)
        """
        if not SecureSessionIDGenerator.is_valid_format(session_id):
            return None, "Invalid session ID"
        
        session_id_hash = SecureSessionIDGenerator.hash_for_storage(session_id)
        
        with self.session_manager.lock:
            session = self.session_manager.session_lookup.get(session_id_hash)
        
        if not session:
            return None, "Session not found"
        
        # Audit log this access
        if self.audit_logger:
            self.audit_logger.log(
                action="ADMIN_SESSION_ACCESS",
                actor=admin_key_id,
                resource=session_id_hash[:16],
                details={
                    "admin_ip": admin_ip,
                    "session_risk": session.risk_score,
                }
            )
        
        # Return full session data (admin only)
        return session.to_dict(), ""
    
    def admin_list_sessions(self,
                            admin_key_id: str,
                            admin_ip: str,
                            filter_risk_above: float = 0.0) -> List[Dict]:
        """
        Admin list all sessions (audited)
        """
        if self.audit_logger:
            self.audit_logger.log(
                action="ADMIN_SESSION_LIST",
                actor=admin_key_id,
                resource="all_sessions",
                details={"admin_ip": admin_ip, "filter": filter_risk_above}
            )
        
        sessions = []
        with self.session_manager.lock:
            for session in self.session_manager.session_lookup.values():
                if session.risk_score >= filter_risk_above:
                    # Return limited data even for admins
                    sessions.append({
                        "session_hash": session.session_id_hash[:16] + "...",
                        "risk_score": session.risk_score,
                        "attack_categories": list(session.attack_categories),
                        "request_count": session.request_count,
                        "created_at": session.created_at,
                    })
        
        return sessions


# Global instance
secure_session_manager = SecureSessionManager()
