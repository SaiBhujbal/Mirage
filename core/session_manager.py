"""
⛔ DEPRECATED - DO NOT USE THIS MODULE ⛔

This module contains CRITICAL security vulnerabilities:
- Session IDs are SHA256(IP+UA) - PREDICTABLE (CVSS 9.1)
- Session hijacking is trivial
- No session binding verification

USE INSTEAD: core.secure_session

This module will be REMOVED in the next version.
"""

import warnings
import os

# Block import in production
if os.environ.get("ENV") == "production":
    raise ImportError(
        "⛔ SECURITY ERROR: session_manager.py is DEPRECATED and BLOCKED in production!\n"
        "This module uses SHA256(IP+UA) for session IDs which is predictable.\n"
        "Use 'from core.secure_session import secure_session_manager' instead."
    )

# Warn in development
warnings.warn(
    "\n⚠️  DEPRECATED: core.session_manager is INSECURE!\n"
    "   Session IDs are SHA256(IP+UA) = PREDICTABLE\n"
    "   Use 'from core.secure_session import secure_session_manager' instead.\n"
    "   This import will be BLOCKED in production.\n",
    DeprecationWarning,
    stacklevel=2,
)

import time
import hashlib
import mmh3
from typing import Dict, Optional, Set, Tuple, List
from dataclasses import dataclass, field
from collections import defaultdict, deque
import threading
import re

from core.models import RequestContext, SessionState, AttackerProfile, WAFResult


@dataclass
class Fingerprint:
    """Client fingerprint"""

    fingerprint_id: str
    fingerprint_type: str  # ja4, behavioral, browser
    raw_value: str
    created_at: float
    confidence: float = 1.0


class JA4Fingerprinter:
    """
    JA4+ fingerprinting for TLS client identification
    Works even through Tor/VPN!
    """

    @staticmethod
    def compute(tls_info: Dict) -> Optional[str]:
        """
        Compute JA4 fingerprint from TLS handshake info
        Format: t13d190900_9dc949149365_97f8aa674fd9
        """
        if not tls_info:
            return None

        # Extract components
        tls_version = tls_info.get("version", "TLS1.2")
        cipher_suites = tls_info.get("cipher_suites", [])
        extensions = tls_info.get("extensions", [])
        sni = tls_info.get("sni", "")

        # Build JA4 components
        version_map = {"TLS1.0": "10", "TLS1.1": "11", "TLS1.2": "12", "TLS1.3": "13"}
        version_code = version_map.get(tls_version, "12")

        # Protocol + version + SNI flag
        part1 = f"t{version_code}d"

        # Cipher count + extension count
        cipher_count = len(cipher_suites)
        ext_count = len(extensions)
        part1 += f"{cipher_count:02d}{ext_count:02d}"

        # SNI indicator
        part1 += "1" if sni else "0"
        part1 += "0"  # Reserved

        # Cipher hash
        cipher_str = ",".join(sorted([str(c) for c in cipher_suites]))
        cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

        # Extension hash
        ext_str = ",".join(sorted([str(e) for e in extensions]))
        ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]

        return f"{part1}_{cipher_hash}_{ext_hash}"

    @staticmethod
    def compute_from_headers(headers: Dict[str, str]) -> str:
        """
        Compute pseudo-JA4H from HTTP headers
        Less reliable but works without TLS info
        """
        # Use header order and values
        header_order = list(headers.keys())

        # Key headers for fingerprinting
        ua = headers.get("user-agent", "")
        accept = headers.get("accept", "")
        accept_lang = headers.get("accept-language", "")
        accept_enc = headers.get("accept-encoding", "")

        # Build fingerprint string
        fp_str = (
            f"{ua}|{accept}|{accept_lang}|{accept_enc}|{','.join(header_order[:10])}"
        )

        return hashlib.sha256(fp_str.encode()).hexdigest()


class BehavioralFingerprinter:
    """
    Fingerprint based on behavioral patterns
    Survives IP changes and VPN hops
    """

    @staticmethod
    def compute(session_state: SessionState) -> str:
        """
        Compute behavioral fingerprint from session patterns
        """
        # Timing patterns
        timing_sig = ""
        if session_state.request_intervals:
            avg_interval = sum(session_state.request_intervals) / len(
                session_state.request_intervals
            )
            std_interval = (
                sum((x - avg_interval) ** 2 for x in session_state.request_intervals)
                / len(session_state.request_intervals)
            ) ** 0.5
            timing_sig = f"{avg_interval:.2f}:{std_interval:.2f}"

        # Path patterns
        path_sig = (
            f"{len(session_state.unique_paths)}:{len(session_state.unique_user_agents)}"
        )

        # Error patterns
        error_rate = session_state.error_count / max(session_state.request_count, 1)
        error_sig = f"{error_rate:.2f}"

        # Combine
        fp_str = f"{timing_sig}|{path_sig}|{error_sig}"

        return hashlib.sha256(fp_str.encode()).hexdigest()[:16]


class SessionManager:
    """
    High-performance session management with fingerprinting
    """

    def __init__(self, session_ttl: int = 3600, max_sessions: int = 100000):
        self.session_ttl = session_ttl
        self.max_sessions = max_sessions

        # Active sessions
        self.sessions: Dict[str, SessionState] = {}

        # Fingerprint index (fingerprint -> session_ids)
        self.fingerprint_index: Dict[str, Set[str]] = defaultdict(set)

        # Attacker profiles (fingerprint -> profile)
        self.attacker_profiles: Dict[str, AttackerProfile] = {}

        # Known malicious fingerprints
        self.malicious_fingerprints: Set[str] = set()

        # Lock for thread safety
        self.lock = threading.RLock()

        # Statistics
        self.stats = {
            "sessions_created": 0,
            "sessions_expired": 0,
            "fingerprints_matched": 0,
            "attackers_identified": 0,
        }

    def get_or_create_session(
        self, ctx: RequestContext, tls_info: Optional[Dict] = None
    ) -> SessionState:
        """
        Get existing session or create new one
        Target: < 0.1ms
        """
        session_id = self._generate_session_id(ctx)

        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.last_seen = time.time()
                return session

            # Create new session
            session = SessionState(
                session_id=session_id,
                client_ip=ctx.client_ip,
                first_seen=time.time(),
                last_seen=time.time(),
            )

            # Compute fingerprints
            if tls_info:
                session.ja4_fingerprint = JA4Fingerprinter.compute(tls_info)
            else:
                session.ja4_fingerprint = JA4Fingerprinter.compute_from_headers(
                    ctx.headers
                )

            # Store session
            self.sessions[session_id] = session
            self.stats["sessions_created"] += 1

            # Index by fingerprint
            if session.ja4_fingerprint:
                self.fingerprint_index[session.ja4_fingerprint].add(session_id)

                # Check if known malicious
                if session.ja4_fingerprint in self.malicious_fingerprints:
                    session.cumulative_risk = 5.0  # Start with high risk

            # Cleanup old sessions if needed
            if len(self.sessions) > self.max_sessions:
                self._cleanup_oldest()

            return session

    def update_session(
        self, session: SessionState, ctx: RequestContext, result: WAFResult
    ):
        """
        Update session with new request data
        """
        session.update(ctx, result)

        # Update behavioral fingerprint periodically
        if session.request_count % 10 == 0:
            session.behavioral_fingerprint = BehavioralFingerprinter.compute(session)

            if session.behavioral_fingerprint:
                self.fingerprint_index[session.behavioral_fingerprint].add(
                    session.session_id
                )

    def find_related_sessions(self, session: SessionState) -> List[SessionState]:
        """
        Find sessions with matching fingerprints (same attacker)
        """
        related = []

        with self.lock:
            # Match by JA4
            if session.ja4_fingerprint:
                for sid in self.fingerprint_index.get(session.ja4_fingerprint, set()):
                    if sid != session.session_id and sid in self.sessions:
                        related.append(self.sessions[sid])
                        self.stats["fingerprints_matched"] += 1

            # Match by behavioral
            if session.behavioral_fingerprint:
                for sid in self.fingerprint_index.get(
                    session.behavioral_fingerprint, set()
                ):
                    if sid != session.session_id and sid in self.sessions:
                        if self.sessions[sid] not in related:
                            related.append(self.sessions[sid])

        return related

    def mark_fingerprint_malicious(self, fingerprint: str):
        """
        Mark a fingerprint as known malicious
        """
        self.malicious_fingerprints.add(fingerprint)

    def get_attacker_profile(self, fingerprint: str) -> Optional[AttackerProfile]:
        """
        Get or create attacker profile for fingerprint
        """
        if fingerprint not in self.attacker_profiles:
            return None
        return self.attacker_profiles[fingerprint]

    def create_attacker_profile(self, session: SessionState) -> AttackerProfile:
        """
        Create attacker profile from session data
        """
        fp = session.ja4_fingerprint or session.behavioral_fingerprint
        if not fp:
            fp = hashlib.sha256(session.session_id.encode()).hexdigest()[:16]

        profile = AttackerProfile(
            profile_id=fp,
            first_seen=session.first_seen,
            last_seen=session.last_seen,
        )

        if session.ja4_fingerprint:
            profile.ja4_fingerprints.add(session.ja4_fingerprint)
        if session.behavioral_fingerprint:
            profile.behavioral_fingerprints.add(session.behavioral_fingerprint)

        profile.source_ips.add(session.client_ip)
        profile.attack_categories = session.attack_categories.copy()
        profile.attack_count = session.blocked_count

        # Skill assessment based on attack sophistication
        profile.skill_level = self._assess_skill(session)

        self.attacker_profiles[fp] = profile
        self.stats["attackers_identified"] += 1

        return profile

    def _assess_skill(self, session: SessionState) -> str:
        """Assess attacker skill level"""
        categories = session.attack_categories

        # Multiple sophisticated attack types = higher skill
        sophisticated = {"RCE", "SSRF", "XXE", "ZERO_DAY"}
        if categories & sophisticated:
            if len(categories) >= 3:
                return "advanced"
            return "high"

        if "SQLI" in categories or "XSS" in categories:
            return "medium"

        return "low"

    def _generate_session_id(self, ctx: RequestContext) -> str:
        """Generate session ID from request context"""
        # Use IP + User-Agent + some headers for session grouping
        session_key = f"{ctx.client_ip}:{ctx.user_agent}"
        return hashlib.sha256(session_key.encode()).hexdigest()[:16]

    def _cleanup_oldest(self):
        """Remove oldest sessions to stay under limit"""
        now = time.time()

        # Find expired sessions
        expired = [
            sid
            for sid, s in self.sessions.items()
            if now - s.last_seen > self.session_ttl
        ]

        for sid in expired[:1000]:  # Batch cleanup
            session = self.sessions.pop(sid, None)
            if session:
                # Remove from fingerprint index
                for fp in [session.ja4_fingerprint, session.behavioral_fingerprint]:
                    if fp and fp in self.fingerprint_index:
                        self.fingerprint_index[fp].discard(sid)

                self.stats["sessions_expired"] += 1

    def get_session_stats(self, session_id: str) -> Optional[Dict]:
        """Get session statistics"""
        session = self.sessions.get(session_id)
        if not session:
            return None

        return {
            "session_id": session_id,
            "client_ip": session.client_ip,
            "request_count": session.request_count,
            "blocked_count": session.blocked_count,
            "suspicious_count": session.suspicious_count,
            "unique_paths": len(session.unique_paths),
            "cumulative_risk": session.cumulative_risk,
            "is_suspicious": session.is_suspicious,
            "is_scanner": session.is_scanner,
            "attack_categories": list(session.attack_categories),
            "ja4_fingerprint": session.ja4_fingerprint,
            "session_duration": session.last_seen - session.first_seen,
        }


# Global session manager
session_manager = SessionManager()
