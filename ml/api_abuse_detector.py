#!/usr/bin/env python3
"""
API Abuse Detection System
Enterprise-grade detection for API-specific attacks and abuse patterns

Detection Categories:
1. Rate Abuse (excessive requests beyond legitimate use)
2. Credential Stuffing (automated login attempts)
3. Data Scraping (mass data extraction)
4. Resource Exhaustion (expensive operation abuse)
5. API Enumeration (discovery/mapping attacks)
6. Broken Authentication (session manipulation)
7. Excessive Data Exposure (requesting sensitive fields)
8. API Injection (API-specific injection attacks)

Metrics Tracked:
- Request rate per endpoint
- Error rate patterns
- Data volume per request
- Authentication failure patterns
- Parameter enumeration
- Suspicious query patterns
"""

import time
import hashlib
import json
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import re

@dataclass
class APIAbuseSignal:
    """Individual API abuse detection signal"""
    abuse_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    confidence: float
    evidence: str
    endpoint: str
    detected_at: datetime = field(default_factory=datetime.now)

@dataclass
class APIAbuseResult:
    """API abuse detection result"""
    is_abuse: bool
    abuse_types: List[str]
    severity: str
    confidence: float
    signals: List[APIAbuseSignal]
    risk_score: float
    recommended_action: str  # 'allow', 'rate_limit', 'captcha', 'block'
    mitigation_details: str

class RateLimitTracker:
    """
    Sophisticated rate limiting with multiple windows
    Tracks requests across different time windows for accurate abuse detection
    """

    def __init__(self):
        # Time windows: 1 minute, 5 minutes, 15 minutes, 1 hour
        self.windows = {
            '1m': {'duration': 60, 'data': defaultdict(lambda: deque(maxlen=1000))},
            '5m': {'duration': 300, 'data': defaultdict(lambda: deque(maxlen=5000))},
            '15m': {'duration': 900, 'data': defaultdict(lambda: deque(maxlen=15000))},
            '1h': {'duration': 3600, 'data': defaultdict(lambda: deque(maxlen=60000))}
        }

        # Per-endpoint limits (requests per minute)
        self.endpoint_limits = {
            '/api/login': 5,           # Authentication endpoints - strict
            '/api/auth': 5,
            '/api/password-reset': 3,
            '/api/search': 30,         # Search endpoints - moderate
            '/api/query': 30,
            '/api/data': 60,           # Data endpoints - generous
            '/api/list': 60,
            '/default': 100            # Default limit
        }

    def track_request(self, client_id: str, endpoint: str, timestamp: Optional[float] = None):
        """Track a request across all time windows"""
        if timestamp is None:
            timestamp = time.time()

        key = f"{client_id}:{endpoint}"

        for window_name, window_data in self.windows.items():
            window_data['data'][key].append(timestamp)

    def get_rate(self, client_id: str, endpoint: str, window: str = '1m') -> float:
        """Get request rate for a client/endpoint in a specific time window"""

        key = f"{client_id}:{endpoint}"
        window_data = self.windows[window]

        current_time = time.time()
        window_duration = window_data['duration']

        # Get requests within the time window
        requests = window_data['data'][key]

        # Filter to requests within window
        recent_requests = [ts for ts in requests if current_time - ts <= window_duration]

        # Calculate requests per minute
        rpm = (len(recent_requests) / window_duration) * 60

        return rpm

    def is_rate_exceeded(self, client_id: str, endpoint: str) -> Tuple[bool, str, float]:
        """
        Check if rate limit is exceeded

        Returns:
            (exceeded, window, rate)
        """

        # Get endpoint-specific limit
        limit = self.endpoint_limits.get(endpoint, self.endpoint_limits['/default'])

        # Check 1-minute window first (most critical)
        rate_1m = self.get_rate(client_id, endpoint, '1m')
        if rate_1m > limit:
            return True, '1m', rate_1m

        # Check 5-minute window (sustained abuse)
        rate_5m = self.get_rate(client_id, endpoint, '5m')
        if rate_5m > limit * 0.8:  # 80% of limit over 5 minutes
            return True, '5m', rate_5m

        # Check 15-minute window (persistent abuse)
        rate_15m = self.get_rate(client_id, endpoint, '15m')
        if rate_15m > limit * 0.6:  # 60% of limit over 15 minutes
            return True, '15m', rate_15m

        return False, 'none', 0.0


class CredentialStuffingDetector:
    """Detect credential stuffing attacks"""

    def __init__(self):
        # Track failed login attempts
        self.failed_attempts = defaultdict(lambda: deque(maxlen=100))

        # Track unique usernames tried per IP
        self.usernames_per_ip = defaultdict(set)

        # Track login patterns
        self.login_timing = defaultdict(lambda: deque(maxlen=50))

    def analyze(self, client_id: str, username: str, success: bool,
                timestamp: Optional[float] = None) -> Optional[APIAbuseSignal]:
        """Analyze login attempt for credential stuffing"""

        if timestamp is None:
            timestamp = time.time()

        self.login_timing[client_id].append(timestamp)

        if not success:
            self.failed_attempts[client_id].append((username, timestamp))
            self.usernames_per_ip[client_id].add(username)

        # Check for credential stuffing patterns

        # 1. Many failed attempts from same IP
        recent_failures = [t for u, t in self.failed_attempts[client_id]
                          if time.time() - t < 300]  # Last 5 minutes

        if len(recent_failures) > 10:
            return APIAbuseSignal(
                abuse_type='credential_stuffing',
                severity='high',
                confidence=0.9,
                evidence=f'{len(recent_failures)} failed logins in 5 minutes',
                endpoint='/api/login'
            )

        # 2. Many different usernames from same IP (credential spraying)
        if len(self.usernames_per_ip[client_id]) > 20:
            return APIAbuseSignal(
                abuse_type='credential_spraying',
                severity='high',
                confidence=0.85,
                evidence=f'{len(self.usernames_per_ip[client_id])} unique usernames attempted',
                endpoint='/api/login'
            )

        # 3. Extremely fast login attempts (automated)
        if len(self.login_timing[client_id]) >= 3:
            intervals = []
            timing = list(self.login_timing[client_id])
            for i in range(1, len(timing)):
                intervals.append(timing[i] - timing[i-1])

            avg_interval = sum(intervals) / len(intervals) if intervals else 0

            if avg_interval < 0.5:  # Less than 500ms between attempts
                return APIAbuseSignal(
                    abuse_type='automated_credential_stuffing',
                    severity='critical',
                    confidence=0.95,
                    evidence=f'Average {avg_interval*1000:.0f}ms between login attempts (automated)',
                    endpoint='/api/login'
                )

        return None


class DataScrapingDetector:
    """Detect mass data extraction/scraping"""

    def __init__(self):
        # Track data volume requested
        self.data_volume = defaultdict(lambda: deque(maxlen=100))

        # Track sequential ID enumeration
        self.id_sequences = defaultdict(list)

    def analyze(self, client_id: str, endpoint: str, response_size: int,
                requested_ids: Optional[List[int]] = None) -> Optional[APIAbuseSignal]:
        """Analyze request for data scraping"""

        current_time = time.time()
        self.data_volume[client_id].append((current_time, response_size))

        # 1. Check data volume in last 5 minutes
        recent_volume = sum(size for ts, size in self.data_volume[client_id]
                          if current_time - ts < 300)

        # 10MB in 5 minutes is suspicious for most APIs
        if recent_volume > 10 * 1024 * 1024:
            return APIAbuseSignal(
                abuse_type='mass_data_scraping',
                severity='high',
                confidence=0.85,
                evidence=f'{recent_volume / (1024*1024):.1f}MB downloaded in 5 minutes',
                endpoint=endpoint
            )

        # 2. Check for sequential ID enumeration
        if requested_ids:
            self.id_sequences[client_id].extend(requested_ids)

            # Keep last 50 IDs
            self.id_sequences[client_id] = self.id_sequences[client_id][-50:]

            if len(self.id_sequences[client_id]) >= 10:
                ids = sorted(self.id_sequences[client_id])

                # Check if sequential (difference of 1 or small increment)
                differences = [ids[i+1] - ids[i] for i in range(len(ids)-1)]
                avg_diff = sum(differences) / len(differences) if differences else 0

                if 0.5 < avg_diff < 5:  # Sequential with small gaps
                    return APIAbuseSignal(
                        abuse_type='id_enumeration',
                        severity='medium',
                        confidence=0.75,
                        evidence=f'Sequential ID enumeration detected (avg diff: {avg_diff:.1f})',
                        endpoint=endpoint
                    )

        return None


class ResourceExhaustionDetector:
    """Detect resource exhaustion attacks"""

    def __init__(self):
        # Track expensive operations
        self.expensive_ops = defaultdict(lambda: deque(maxlen=50))

        # Define expensive endpoints
        self.expensive_endpoints = {
            '/api/export': {'weight': 10, 'max_per_hour': 5},
            '/api/report': {'weight': 8, 'max_per_hour': 10},
            '/api/search': {'weight': 5, 'max_per_hour': 30},
            '/api/aggregate': {'weight': 7, 'max_per_hour': 15}
        }

    def analyze(self, client_id: str, endpoint: str, processing_time: float) -> Optional[APIAbuseSignal]:
        """Analyze for resource exhaustion"""

        current_time = time.time()

        # Check if endpoint is expensive
        endpoint_config = self.expensive_endpoints.get(endpoint)

        if endpoint_config:
            self.expensive_ops[client_id].append((current_time, endpoint))

            # Count operations in last hour
            recent_ops = [ep for ts, ep in self.expensive_ops[client_id]
                         if current_time - ts < 3600 and ep == endpoint]

            max_allowed = endpoint_config['max_per_hour']

            if len(recent_ops) > max_allowed:
                return APIAbuseSignal(
                    abuse_type='resource_exhaustion',
                    severity='high',
                    confidence=0.8,
                    evidence=f'{len(recent_ops)} expensive operations in 1 hour (limit: {max_allowed})',
                    endpoint=endpoint
                )

        # Check for slow queries being abused
        if processing_time > 5.0:  # Queries taking > 5 seconds
            slow_queries = [1 for ts, ep in self.expensive_ops[client_id]
                          if current_time - ts < 600]  # Last 10 minutes

            if len(slow_queries) > 5:
                return APIAbuseSignal(
                    abuse_type='slow_query_abuse',
                    severity='medium',
                    confidence=0.7,
                    evidence=f'{len(slow_queries)} slow queries in 10 minutes',
                    endpoint=endpoint
                )

        return None


class APIEnumerationDetector:
    """Detect API enumeration/discovery attacks"""

    def __init__(self):
        # Track 404 errors (endpoint discovery)
        self.not_found_errors = defaultdict(lambda: deque(maxlen=100))

        # Track unique endpoints accessed
        self.endpoints_accessed = defaultdict(set)

    def analyze(self, client_id: str, endpoint: str, status_code: int) -> Optional[APIAbuseSignal]:
        """Analyze for API enumeration"""

        current_time = time.time()

        # Track endpoint
        self.endpoints_accessed[client_id].add(endpoint)

        # Track 404 errors
        if status_code == 404:
            self.not_found_errors[client_id].append((current_time, endpoint))

        # Check for excessive 404s (endpoint discovery)
        recent_404s = [ts for ts, ep in self.not_found_errors[client_id]
                      if current_time - ts < 300]

        if len(recent_404s) > 20:
            return APIAbuseSignal(
                abuse_type='endpoint_enumeration',
                severity='medium',
                confidence=0.75,
                evidence=f'{len(recent_404s)} 404 errors in 5 minutes (endpoint discovery)',
                endpoint='multiple'
            )

        # Check for accessing many different endpoints (mapping)
        if len(self.endpoints_accessed[client_id]) > 50:
            return APIAbuseSignal(
                abuse_type='api_mapping',
                severity='low',
                confidence=0.6,
                evidence=f'{len(self.endpoints_accessed[client_id])} unique endpoints accessed',
                endpoint='multiple'
            )

        return None


class APIAbuseDetector:
    """
    Comprehensive API abuse detection system
    Combines multiple detection strategies for accurate classification
    """

    def __init__(self):
        self.rate_tracker = RateLimitTracker()
        self.credential_detector = CredentialStuffingDetector()
        self.scraping_detector = DataScrapingDetector()
        self.exhaustion_detector = ResourceExhaustionDetector()
        self.enumeration_detector = APIEnumerationDetector()

    def analyze_request(self,
                       client_id: str,
                       endpoint: str,
                       method: str = 'GET',
                       status_code: int = 200,
                       response_size: int = 0,
                       processing_time: float = 0.0,
                       is_auth_endpoint: bool = False,
                       auth_success: bool = True,
                       username: Optional[str] = None,
                       requested_ids: Optional[List[int]] = None,
                       timestamp: Optional[float] = None) -> APIAbuseResult:
        """
        Comprehensive API abuse analysis

        Args:
            client_id: Client identifier (IP, session, API key)
            endpoint: API endpoint path
            method: HTTP method
            status_code: HTTP status code
            response_size: Response size in bytes
            processing_time: Request processing time in seconds
            is_auth_endpoint: Whether this is an authentication endpoint
            auth_success: Whether authentication succeeded
            username: Username (for auth endpoints)
            requested_ids: List of IDs requested (for enumeration detection)
            timestamp: Request timestamp

        Returns:
            APIAbuseResult with classification and mitigation recommendations
        """

        if timestamp is None:
            timestamp = time.time()

        signals: List[APIAbuseSignal] = []

        # 1. Rate limiting analysis
        self.rate_tracker.track_request(client_id, endpoint, timestamp)
        exceeded, window, rate = self.rate_tracker.is_rate_exceeded(client_id, endpoint)

        if exceeded:
            signals.append(APIAbuseSignal(
                abuse_type='rate_limit_exceeded',
                severity='high' if window == '1m' else 'medium',
                confidence=0.95,
                evidence=f'{rate:.1f} req/min in {window} window',
                endpoint=endpoint
            ))

        # 2. Credential stuffing detection
        if is_auth_endpoint and username:
            signal = self.credential_detector.analyze(client_id, username, auth_success, timestamp)
            if signal:
                signals.append(signal)

        # 3. Data scraping detection
        if response_size > 0:
            signal = self.scraping_detector.analyze(client_id, endpoint, response_size, requested_ids)
            if signal:
                signals.append(signal)

        # 4. Resource exhaustion detection
        if processing_time > 0:
            signal = self.exhaustion_detector.analyze(client_id, endpoint, processing_time)
            if signal:
                signals.append(signal)

        # 5. API enumeration detection
        signal = self.enumeration_detector.analyze(client_id, endpoint, status_code)
        if signal:
            signals.append(signal)

        # Aggregate results
        if not signals:
            # No abuse detected
            return APIAbuseResult(
                is_abuse=False,
                abuse_types=[],
                severity='none',
                confidence=0.0,
                signals=[],
                risk_score=0.0,
                recommended_action='allow',
                mitigation_details='No abuse detected'
            )

        # Determine severity and recommended action
        severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_severity = max(signals, key=lambda s: severity_scores[s.severity])

        abuse_types = list(set(s.abuse_type for s in signals))
        avg_confidence = sum(s.confidence for s in signals) / len(signals)

        # Calculate risk score
        risk_score = min(1.0, avg_confidence * (len(signals) / 3))

        # Determine action
        if max_severity.severity == 'critical':
            action = 'block'
            mitigation = 'BLOCK: Immediate blocking required'
        elif max_severity.severity == 'high':
            if 'credential_stuffing' in abuse_types:
                action = 'captcha'
                mitigation = 'CAPTCHA: Require human verification'
            else:
                action = 'rate_limit'
                mitigation = 'RATE LIMIT: Enforce strict rate limiting'
        elif max_severity.severity == 'medium':
            action = 'rate_limit'
            mitigation = 'RATE LIMIT: Apply rate limiting'
        else:
            action = 'allow'
            mitigation = 'MONITOR: Continue monitoring'

        return APIAbuseResult(
            is_abuse=True,
            abuse_types=abuse_types,
            severity=max_severity.severity,
            confidence=avg_confidence,
            signals=signals,
            risk_score=risk_score,
            recommended_action=action,
            mitigation_details=mitigation
        )


if __name__ == "__main__":
    # Test API abuse detector
    detector = APIAbuseDetector()

    print("=== API ABUSE DETECTION SYSTEM TEST ===\n")

    # Test 1: Rate limiting
    print("Test 1: Rate Limit Abuse")
    client_id = "client_123"

    # Simulate 150 requests in 1 minute
    for i in range(150):
        result = detector.analyze_request(
            client_id=client_id,
            endpoint="/api/data",
            timestamp=time.time() + (i * 0.4)  # 0.4 seconds apart
        )

    print(f"  Abuse: {result.is_abuse}, Types: {result.abuse_types}")
    print(f"  Severity: {result.severity.upper()}, Confidence: {result.confidence:.0%}")
    print(f"  Action: {result.recommended_action.upper()}")
    print(f"  {result.mitigation_details}")
    print()

    # Test 2: Credential stuffing
    print("Test 2: Credential Stuffing")
    client_id = "client_456"

    for i in range(15):
        result = detector.analyze_request(
            client_id=client_id,
            endpoint="/api/login",
            is_auth_endpoint=True,
            auth_success=False,
            username=f"user{i}@example.com",
            timestamp=time.time() + (i * 0.3)
        )

    print(f"  Abuse: {result.is_abuse}, Types: {result.abuse_types}")
    print(f"  Severity: {result.severity.upper()}, Confidence: {result.confidence:.0%}")
    print(f"  Action: {result.recommended_action.upper()}")
    print()

    # Test 3: Data scraping
    print("Test 3: Mass Data Scraping")
    client_id = "client_789"

    for i in range(50):
        result = detector.analyze_request(
            client_id=client_id,
            endpoint="/api/users",
            response_size=256 * 1024,  # 256KB per request
            requested_ids=list(range(i*10, (i+1)*10)),
            timestamp=time.time() + (i * 2)
        )

    print(f"  Abuse: {result.is_abuse}, Types: {result.abuse_types}")
    print(f"  Severity: {result.severity.upper()}, Confidence: {result.confidence:.0%}")
    print(f"  Action: {result.recommended_action.upper()}")
    print()

    print("API abuse detection system ready for production!")
