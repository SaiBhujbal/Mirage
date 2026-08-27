"""
⛔ DEPRECATED - DO NOT USE THIS MODULE ⛔

This module contains security vulnerabilities:
- Race condition in check-then-increment (CVSS 7.4)
- Non-atomic operations allow bypass
- Uses MD5 for key hashing

USE INSTEAD: core.atomic_rate_limiter

This module will be REMOVED in the next version.
"""

import warnings
import os

# Block import in production
if os.environ.get("ENV") == "production":
    raise ImportError(
        "⛔ SECURITY ERROR: rate_limiter.py is DEPRECATED and BLOCKED in production!\n"
        "This module has race conditions that allow rate limit bypass.\n"
        "Use 'from core.atomic_rate_limiter import atomic_rate_limiter' instead."
    )

# Warn in development
warnings.warn(
    "\n⚠️  DEPRECATED: core.rate_limiter is INSECURE!\n"
    "   Has race conditions allowing bypass.\n"
    "   Use 'from core.atomic_rate_limiter import atomic_rate_limiter' instead.\n"
    "   This import will be BLOCKED in production.\n",
    DeprecationWarning,
    stacklevel=2,
)

import time
import hashlib
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import threading


@dataclass
class RateLimitResult:
    """Result of rate limit check"""

    allowed: bool
    current_rate: float
    limit: float
    remaining: int
    reset_at: float
    retry_after: Optional[float] = None


@dataclass
class TokenBucket:
    """Token bucket for rate limiting"""

    capacity: float
    tokens: float
    refill_rate: float  # tokens per second
    last_update: float

    def consume(self, tokens: int = 1) -> Tuple[bool, float]:
        """
        Try to consume tokens
        Returns (allowed, current_tokens)
        """
        now = time.time()

        # Refill tokens
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_update = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True, self.tokens

        return False, self.tokens


@dataclass
class SlidingWindow:
    """Sliding window counter"""

    window_size: float  # seconds
    max_requests: int
    requests: list = field(default_factory=list)

    def add_request(self) -> Tuple[bool, int]:
        """
        Add request and check if allowed
        Returns (allowed, current_count)
        """
        now = time.time()
        cutoff = now - self.window_size

        # Remove old requests
        self.requests = [t for t in self.requests if t > cutoff]

        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True, len(self.requests)

        return False, len(self.requests)


class RateLimiter:
    """
    Multi-strategy rate limiter
    Supports per-IP, per-session, per-endpoint limiting
    """

    def __init__(
        self, default_rate: int = 100, default_window: int = 60, burst_limit: int = 20
    ):

        self.default_rate = default_rate
        self.default_window = default_window
        self.burst_limit = burst_limit

        # Per-key token buckets
        self.buckets: Dict[str, TokenBucket] = {}

        # Per-key sliding windows
        self.windows: Dict[str, SlidingWindow] = {}

        # Endpoint-specific limits
        self.endpoint_limits: Dict[str, Tuple[int, int]] = {
            "/api/auth/login": (10, 60),  # 10 requests per minute
            "/api/auth/register": (5, 60),  # 5 per minute
            "/api/admin": (30, 60),  # 30 per minute
            "/api/upload": (20, 60),  # 20 per minute
        }

        # Blocked keys (temporary bans)
        self.blocked: Dict[str, float] = {}

        # Suspicious keys (higher scrutiny)
        self.suspicious: Dict[str, float] = {}

        # Lock for thread safety
        self.lock = threading.Lock()

        # Statistics
        self.total_checks = 0
        self.total_blocked = 0

    def check(self, key: str, endpoint: str = "", cost: int = 1) -> RateLimitResult:
        """
        Check if request is allowed
        Target: < 0.1ms
        """
        now = time.time()

        self.total_checks += 1

        # Check if blocked
        if key in self.blocked:
            if now < self.blocked[key]:
                self.total_blocked += 1
                return RateLimitResult(
                    allowed=False,
                    current_rate=0,
                    limit=0,
                    remaining=0,
                    reset_at=self.blocked[key],
                    retry_after=self.blocked[key] - now,
                )
            else:
                del self.blocked[key]

        # Get rate limit for endpoint
        rate, window = self.endpoint_limits.get(
            endpoint, (self.default_rate, self.default_window)
        )

        # Reduce limit for suspicious keys
        if key in self.suspicious:
            rate = rate // 2

        # Get or create bucket
        with self.lock:
            if key not in self.buckets:
                self.buckets[key] = TokenBucket(
                    capacity=self.burst_limit,
                    tokens=self.burst_limit,
                    refill_rate=rate / window,
                    last_update=now,
                )

            if key not in self.windows:
                self.windows[key] = SlidingWindow(window_size=window, max_requests=rate)

        bucket = self.buckets[key]
        window_counter = self.windows[key]

        # Check burst limit (token bucket)
        burst_ok, tokens_left = bucket.consume(cost)

        # Check sustained rate (sliding window)
        rate_ok, current_count = window_counter.add_request()

        allowed = burst_ok and rate_ok

        if not allowed:
            self.total_blocked += 1

        return RateLimitResult(
            allowed=allowed,
            current_rate=current_count / window * 60,  # requests per minute
            limit=rate,
            remaining=max(0, rate - current_count),
            reset_at=now + window,
            retry_after=1.0 if not allowed else None,
        )

    def block(self, key: str, duration: float = 300):
        """
        Temporarily block a key
        """
        self.blocked[key] = time.time() + duration

    def mark_suspicious(self, key: str, duration: float = 3600):
        """
        Mark key as suspicious (reduced limits)
        """
        self.suspicious[key] = time.time() + duration

    def cleanup(self):
        """Clean up expired entries"""
        now = time.time()

        # Clean blocked
        expired = [k for k, v in self.blocked.items() if v < now]
        for k in expired:
            del self.blocked[k]

        # Clean suspicious
        expired = [k for k, v in self.suspicious.items() if v < now]
        for k in expired:
            del self.suspicious[k]

        # Clean old buckets (not accessed for 1 hour)
        cutoff = now - 3600
        old_buckets = [k for k, v in self.buckets.items() if v.last_update < cutoff]
        for k in old_buckets:
            del self.buckets[k]
            self.windows.pop(k, None)

    def get_key(self, ip: str, endpoint: str = "", session_id: str = "") -> str:
        """Generate rate limit key"""
        # Combine IP and endpoint for granular limiting
        key_parts = [ip]

        if endpoint:
            # Normalize endpoint (strip trailing slash, lowercase)
            endpoint = endpoint.lower().rstrip("/")
            key_parts.append(endpoint)

        if session_id:
            key_parts.append(session_id[:16])

        return hashlib.md5(":".join(key_parts).encode()).hexdigest()[:16]


# Singleton
rate_limiter = RateLimiter()


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that adjusts based on attack patterns
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Attack counters per key
        self.attack_counts: Dict[str, int] = defaultdict(int)

        # Escalation thresholds
        self.escalation_thresholds = [
            (3, 0.5),  # 3 attacks: 50% rate
            (5, 0.25),  # 5 attacks: 25% rate
            (10, 0.1),  # 10 attacks: 10% rate
            (20, 0.0),  # 20 attacks: blocked
        ]

    def record_attack(self, key: str):
        """Record an attack from this key"""
        self.attack_counts[key] += 1

        count = self.attack_counts[key]

        # Check escalation
        for threshold, multiplier in self.escalation_thresholds:
            if count >= threshold:
                if multiplier == 0.0:
                    self.block(key, duration=3600)  # 1 hour block
                else:
                    self.mark_suspicious(key)

    def check_with_adaptation(
        self, key: str, endpoint: str = "", attack_score: float = 0.0
    ) -> RateLimitResult:
        """
        Check with attack score adaptation
        """
        result = self.check(key, endpoint)

        if attack_score > 0.7:
            self.record_attack(key)

        return result

    def is_allowed(self, key: str, endpoint: str = "") -> bool:
        """
        Simple boolean check if request is allowed

        Args:
            key: Rate limit key (usually from get_key())
            endpoint: API endpoint path

        Returns:
            True if allowed, False if blocked/rate limited
        """
        result = self.check(key, endpoint)
        return result.allowed

    def get_key(self, client_ip: str, endpoint: str = "") -> str:
        """
        Generate rate limit key for client IP and endpoint

        Args:
            client_ip: Client IP address
            endpoint: API endpoint path

        Returns:
            Rate limit key string
        """
        if endpoint:
            return f"{client_ip}:{endpoint}"
        return client_ip


# Global adaptive limiter
adaptive_limiter = AdaptiveRateLimiter()
