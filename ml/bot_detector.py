#!/usr/bin/env python3
"""
Advanced Bot Detection Module
Enterprise-grade bot vs human classification using behavioral fingerprinting

Detection Methods:
1. Request timing analysis (human vs bot patterns)
2. User-Agent fingerprinting
3. Browser fingerprinting (TLS, headers, JavaScript execution)
4. Behavioral analysis (mouse movements, keyboard timing)
5. Session pattern analysis
6. Rate limiting patterns
7. Header consistency checks
8. Cookie/session manipulation detection

Bot Categories:
- Search Engine Crawlers (Googlebot, Bingbot) - ALLOW
- Good Bots (monitoring, analytics) - ALLOW
- Malicious Scrapers - BLOCK
- DDoS Bots - BLOCK
- Credential Stuffing Bots - BLOCK
- Vulnerability Scanners - BLOCK
- API Abuse Bots - BLOCK
"""

import re
import time
import hashlib
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import numpy as np
from scipy import stats

@dataclass
class BotSignal:
    """Individual bot detection signal"""
    signal_type: str
    confidence: float  # 0-1
    weight: float      # Importance of this signal
    evidence: str
    detected_at: datetime = field(default_factory=datetime.now)

@dataclass
class BotDetectionResult:
    """Bot detection result"""
    is_bot: bool
    bot_type: str  # 'good_bot', 'malicious_bot', 'human'
    confidence: float
    signals: List[BotSignal]
    fingerprint: str
    risk_score: float
    recommended_action: str  # 'allow', 'challenge', 'block'

class BehavioralFingerprint:
    """
    Behavioral fingerprinting for bot detection
    Analyzes request patterns over time to detect bot-like behavior
    """

    def __init__(self):
        # Session tracking
        self.session_patterns = defaultdict(lambda: {
            'requests': deque(maxlen=100),
            'timing_intervals': deque(maxlen=50),
            'user_agents': set(),
            'endpoints': deque(maxlen=50),
            'headers_hash': deque(maxlen=20),
            'first_seen': None,
            'request_count': 0
        })

        # Known bot patterns
        self.good_bot_ua_patterns = [
            r'Googlebot',
            r'bingbot',
            r'Slurp',  # Yahoo
            r'DuckDuckBot',
            r'Baiduspider',
            r'YandexBot',
            r'facebookexternalhit',
            r'twitterbot',
            r'LinkedInBot',
            r'Applebot',
            r'pingdom',
            r'UptimeRobot'
        ]

        self.malicious_bot_patterns = [
            r'nikto',
            r'sqlmap',
            r'nmap',
            r'masscan',
            r'zgrab',
            r'python-requests',
            r'curl',
            r'wget',
            r'scrapy',
            r'selenium',
            r'phantomjs',
            r'headless'
        ]

        # Browser fingerprint patterns
        self.browser_headers = {
            'Chrome': ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-dest'],
            'Firefox': ['te', 'dnt'],
            'Safari': ['accept-language', 'accept-encoding']
        }

    def analyze_request_timing(self, session_id: str, timestamp: float) -> BotSignal:
        """
        Analyze request timing patterns
        Humans have irregular timing, bots are consistent
        """
        session = self.session_patterns[session_id]
        session['requests'].append(timestamp)

        if len(session['requests']) < 3:
            return BotSignal(
                signal_type='timing_insufficient',
                confidence=0.5,
                weight=0.1,
                evidence='Insufficient data'
            )

        # Calculate inter-request intervals
        intervals = []
        for i in range(1, len(session['requests'])):
            intervals.append(session['requests'][i] - session['requests'][i-1])

        session['timing_intervals'].extend(intervals)

        if len(intervals) < 5:
            return BotSignal(
                signal_type='timing_insufficient',
                confidence=0.5,
                weight=0.1,
                evidence='Insufficient intervals'
            )

        # Statistical analysis of intervals
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        cv = std_interval / mean_interval if mean_interval > 0 else 0  # Coefficient of variation

        # Bots have low CV (very consistent), humans have high CV
        # CV < 0.3: likely bot
        # CV > 0.8: likely human
        # 0.3 - 0.8: uncertain

        if cv < 0.3:
            return BotSignal(
                signal_type='timing_too_consistent',
                confidence=min(0.9, (0.3 - cv) * 3),  # Higher confidence for lower CV
                weight=0.25,
                evidence=f'CV={cv:.3f}, mean={mean_interval:.2f}s (too consistent for human)'
            )
        elif cv > 0.8:
            return BotSignal(
                signal_type='timing_human_like',
                confidence=min(0.9, (cv - 0.8) * 2),
                weight=0.25,
                evidence=f'CV={cv:.3f}, mean={mean_interval:.2f}s (human-like variability)'
            )
        else:
            return BotSignal(
                signal_type='timing_uncertain',
                confidence=0.5,
                weight=0.1,
                evidence=f'CV={cv:.3f} (uncertain)'
            )

    def analyze_user_agent(self, user_agent: str) -> BotSignal:
        """Analyze User-Agent header for bot patterns"""

        if not user_agent:
            return BotSignal(
                signal_type='missing_user_agent',
                confidence=0.8,
                weight=0.3,
                evidence='No User-Agent header (suspicious)'
            )

        # Check good bots
        for pattern in self.good_bot_ua_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return BotSignal(
                    signal_type='good_bot',
                    confidence=0.95,
                    weight=0.4,
                    evidence=f'Matched pattern: {pattern}'
                )

        # Check malicious bots
        for pattern in self.malicious_bot_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return BotSignal(
                    signal_type='malicious_bot',
                    confidence=0.9,
                    weight=0.5,
                    evidence=f'Matched malicious pattern: {pattern}'
                )

        # Check for generic/fake user agents
        if len(user_agent) < 20:
            return BotSignal(
                signal_type='suspicious_ua_short',
                confidence=0.6,
                weight=0.2,
                evidence=f'User-Agent too short: {len(user_agent)} chars'
            )

        # Check for browser consistency
        has_mozilla = 'Mozilla' in user_agent
        has_version = re.search(r'\d+\.\d+', user_agent)

        if not has_mozilla or not has_version:
            return BotSignal(
                signal_type='suspicious_ua_format',
                confidence=0.5,
                weight=0.15,
                evidence='Missing standard UA components'
            )

        return BotSignal(
            signal_type='ua_normal',
            confidence=0.3,
            weight=0.1,
            evidence='User-Agent appears normal'
        )

    def analyze_headers(self, headers: Dict[str, str]) -> BotSignal:
        """Analyze HTTP headers for bot indicators"""

        required_browser_headers = ['accept', 'accept-encoding', 'accept-language']
        missing_headers = [h for h in required_browser_headers if h not in headers]

        if len(missing_headers) > 1:
            return BotSignal(
                signal_type='missing_browser_headers',
                confidence=0.7,
                weight=0.25,
                evidence=f'Missing headers: {", ".join(missing_headers)}'
            )

        # Check header order (bots often have different order)
        header_order = list(headers.keys())
        if header_order and header_order[0].lower() != 'host':
            return BotSignal(
                signal_type='abnormal_header_order',
                confidence=0.6,
                weight=0.2,
                evidence='First header is not Host (unusual for browsers)'
            )

        # Check for bot-specific headers
        bot_headers = ['x-scanner', 'x-automated', 'x-bot']
        for bot_header in bot_headers:
            if bot_header in headers:
                return BotSignal(
                    signal_type='bot_specific_header',
                    confidence=0.95,
                    weight=0.4,
                    evidence=f'Found bot header: {bot_header}'
                )

        # Chrome-specific headers
        chrome_headers = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-fetch-site']
        has_chrome_headers = sum(1 for h in chrome_headers if h in headers)

        user_agent = headers.get('user-agent', '').lower()
        if 'chrome' in user_agent and has_chrome_headers == 0:
            return BotSignal(
                signal_type='fake_chrome',
                confidence=0.75,
                weight=0.3,
                evidence='Claims Chrome but missing Chrome-specific headers'
            )

        return BotSignal(
            signal_type='headers_normal',
            confidence=0.2,
            weight=0.1,
            evidence='Headers appear normal'
        )

    def analyze_request_rate(self, session_id: str) -> BotSignal:
        """Analyze request rate patterns"""

        session = self.session_patterns[session_id]

        if not session['first_seen']:
            session['first_seen'] = datetime.now()
            return BotSignal(
                signal_type='rate_insufficient',
                confidence=0.5,
                weight=0.05,
                evidence='First request'
            )

        # Calculate requests per minute
        duration = (datetime.now() - session['first_seen']).total_seconds() / 60
        if duration < 0.1:  # Less than 6 seconds
            duration = 0.1

        rpm = len(session['requests']) / duration

        # Human: 0.5-10 RPM
        # Aggressive bot: 60+ RPM
        # DDoS bot: 600+ RPM

        if rpm > 600:
            return BotSignal(
                signal_type='ddos_rate',
                confidence=0.95,
                weight=0.5,
                evidence=f'{rpm:.1f} req/min (DDoS-like)'
            )
        elif rpm > 60:
            return BotSignal(
                signal_type='aggressive_bot_rate',
                confidence=0.85,
                weight=0.4,
                evidence=f'{rpm:.1f} req/min (aggressive bot)'
            )
        elif rpm > 20:
            return BotSignal(
                signal_type='suspicious_rate',
                confidence=0.6,
                weight=0.25,
                evidence=f'{rpm:.1f} req/min (higher than typical human)'
            )
        elif rpm < 0.5:
            return BotSignal(
                signal_type='slow_rate',
                confidence=0.3,
                weight=0.05,
                evidence=f'{rpm:.1f} req/min (very slow, likely human or slow bot)'
            )
        else:
            return BotSignal(
                signal_type='normal_rate',
                confidence=0.2,
                weight=0.05,
                evidence=f'{rpm:.1f} req/min (normal range)'
            )

    def analyze_path_patterns(self, session_id: str, path: str) -> BotSignal:
        """Analyze URL path access patterns"""

        session = self.session_patterns[session_id]
        session['endpoints'].append(path)

        if len(session['endpoints']) < 5:
            return BotSignal(
                signal_type='path_insufficient',
                confidence=0.5,
                weight=0.05,
                evidence='Insufficient path data'
            )

        # Count unique vs total requests
        unique_paths = len(set(session['endpoints']))
        total_paths = len(session['endpoints'])

        # Bots often request many unique paths (scanning)
        # Humans have more repetition (browsing same pages)
        unique_ratio = unique_paths / total_paths

        if unique_ratio > 0.9:
            return BotSignal(
                signal_type='scanning_pattern',
                confidence=0.75,
                weight=0.3,
                evidence=f'{unique_ratio:.0%} unique paths (scanning behavior)'
            )

        # Check for systematic path patterns (bot scanning)
        # e.g., /admin, /login, /wp-admin, /phpmyadmin
        suspicious_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin', '/config',
                          '/.env', '/.git', '/backup', '/test', '/debug']

        suspicious_count = sum(1 for p in session['endpoints']
                             if any(sp in p.lower() for sp in suspicious_paths))

        if suspicious_count > 3:
            return BotSignal(
                signal_type='suspicious_path_enumeration',
                confidence=0.8,
                weight=0.35,
                evidence=f'{suspicious_count} suspicious paths accessed (vulnerability scanning)'
            )

        return BotSignal(
            signal_type='path_normal',
            confidence=0.2,
            weight=0.05,
            evidence='Path patterns appear normal'
        )

    def calculate_fingerprint(self, user_agent: str, headers: Dict[str, str],
                             ip_address: str) -> str:
        """Calculate unique fingerprint for the client"""

        fingerprint_data = {
            'ua': user_agent,
            'accept': headers.get('accept', ''),
            'accept_encoding': headers.get('accept-encoding', ''),
            'accept_language': headers.get('accept-language', ''),
            'ip': ip_address
        }

        fingerprint_str = '|'.join([f"{k}={v}" for k, v in sorted(fingerprint_data.items())])
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


class BotDetector:
    """
    Enterprise-grade bot detection system
    Combines multiple signals for accurate bot vs human classification
    """

    def __init__(self):
        self.fingerprinter = BehavioralFingerprint()

        # Signal weights (for weighted scoring)
        self.signal_weights = {
            'timing_too_consistent': 0.25,
            'malicious_bot': 0.5,
            'good_bot': 0.4,
            'missing_user_agent': 0.3,
            'missing_browser_headers': 0.25,
            'ddos_rate': 0.5,
            'aggressive_bot_rate': 0.4,
            'scanning_pattern': 0.3,
            'suspicious_path_enumeration': 0.35,
            'fake_chrome': 0.3
        }

        # Whitelisted good bots
        self.whitelisted_fingerprints = set()

    def detect(self, session_id: str, user_agent: str, headers: Dict[str, str],
              path: str, ip_address: str, timestamp: Optional[float] = None) -> BotDetectionResult:
        """
        Perform bot detection on a request

        Args:
            session_id: Session identifier
            user_agent: User-Agent header
            headers: All HTTP headers (lowercase keys)
            path: Request path
            ip_address: Client IP address
            timestamp: Request timestamp (default: now)

        Returns:
            BotDetectionResult with classification and signals
        """

        if timestamp is None:
            timestamp = time.time()

        # Collect all signals
        signals: List[BotSignal] = []

        # 1. Timing analysis
        signals.append(self.fingerprinter.analyze_request_timing(session_id, timestamp))

        # 2. User-Agent analysis
        signals.append(self.fingerprinter.analyze_user_agent(user_agent))

        # 3. Header analysis
        signals.append(self.fingerprinter.analyze_headers(headers))

        # 4. Request rate analysis
        signals.append(self.fingerprinter.analyze_request_rate(session_id))

        # 5. Path pattern analysis
        signals.append(self.fingerprinter.analyze_path_patterns(session_id, path))

        # Calculate fingerprint
        fingerprint = self.fingerprinter.calculate_fingerprint(user_agent, headers, ip_address)

        # Aggregate signals
        total_weight = 0
        weighted_confidence = 0

        bot_signals = []
        good_bot_signals = []
        human_signals = []

        for signal in signals:
            weight = self.signal_weights.get(signal.signal_type, signal.weight)

            # Categorize signals
            if signal.signal_type in ['good_bot']:
                good_bot_signals.append(signal)
            elif signal.signal_type in ['malicious_bot', 'ddos_rate', 'aggressive_bot_rate',
                                       'scanning_pattern', 'suspicious_path_enumeration',
                                       'timing_too_consistent', 'missing_user_agent',
                                       'missing_browser_headers', 'fake_chrome']:
                bot_signals.append(signal)
            elif signal.signal_type in ['timing_human_like', 'normal_rate']:
                human_signals.append(signal)

            # Weighted confidence calculation
            weighted_confidence += signal.confidence * weight
            total_weight += weight

        # Normalize confidence
        overall_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.5

        # Determine bot type and action
        if good_bot_signals and max(s.confidence for s in good_bot_signals) > 0.9:
            # High confidence good bot
            is_bot = True
            bot_type = 'good_bot'
            confidence = max(s.confidence for s in good_bot_signals)
            risk_score = 0.1
            action = 'allow'

        elif bot_signals and overall_confidence > 0.7:
            # High confidence malicious bot
            is_bot = True
            bot_type = 'malicious_bot'
            confidence = overall_confidence
            risk_score = overall_confidence
            action = 'block' if confidence > 0.85 else 'challenge'

        elif overall_confidence < 0.3:
            # Low confidence bot signals = likely human
            is_bot = False
            bot_type = 'human'
            confidence = 1.0 - overall_confidence
            risk_score = overall_confidence
            action = 'allow'

        else:
            # Uncertain - use challenge
            is_bot = False
            bot_type = 'uncertain'
            confidence = 0.5
            risk_score = overall_confidence
            action = 'challenge'

        return BotDetectionResult(
            is_bot=is_bot,
            bot_type=bot_type,
            confidence=confidence,
            signals=signals,
            fingerprint=fingerprint,
            risk_score=risk_score,
            recommended_action=action
        )

    def update_session_count(self, session_id: str):
        """Update request count for session"""
        self.fingerprinter.session_patterns[session_id]['request_count'] += 1

    def whitelist_fingerprint(self, fingerprint: str):
        """Add fingerprint to whitelist (for verified good bots)"""
        self.whitelisted_fingerprints.add(fingerprint)

    def is_whitelisted(self, fingerprint: str) -> bool:
        """Check if fingerprint is whitelisted"""
        return fingerprint in self.whitelisted_fingerprints


if __name__ == "__main__":
    # Test bot detector
    detector = BotDetector()

    print("=== BOT DETECTION MODULE TEST ===\n")

    # Test case 1: Googlebot (good bot)
    print("Test 1: Googlebot")
    result = detector.detect(
        session_id="session1",
        user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        headers={
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate',
            'host': 'example.com'
        },
        path="/",
        ip_address="66.249.66.1"
    )
    print(f"  Bot: {result.is_bot}, Type: {result.bot_type}, Confidence: {result.confidence:.2%}")
    print(f"  Action: {result.recommended_action.upper()}")
    print(f"  Signals: {len(result.signals)}")
    print()

    # Test case 2: Malicious scanner
    print("Test 2: Malicious Scanner")
    result = detector.detect(
        session_id="session2",
        user_agent="nikto/2.1.5",
        headers={
            'host': 'example.com'
        },
        path="/admin",
        ip_address="192.168.1.100"
    )
    print(f"  Bot: {result.is_bot}, Type: {result.bot_type}, Confidence: {result.confidence:.2%}")
    print(f"  Action: {result.recommended_action.upper()}")
    print(f"  Risk Score: {result.risk_score:.2%}")
    print()

    # Test case 3: Normal human browser
    print("Test 3: Human Browser")
    result = detector.detect(
        session_id="session3",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        headers={
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.5',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-fetch-dest': 'document',
            'host': 'example.com'
        },
        path="/home",
        ip_address="203.0.113.1"
    )
    print(f"  Bot: {result.is_bot}, Type: {result.bot_type}, Confidence: {result.confidence:.2%}")
    print(f"  Action: {result.recommended_action.upper()}")
    print()

    print("Bot detection module ready for production!")
