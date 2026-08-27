"""
MIRAGE Core Data Models
Optimized for minimal memory allocation and fast serialization
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import IntEnum, Enum
from datetime import datetime
import hashlib
import time
import orjson

class Action(IntEnum):
    """WAF Actions - ordered by severity"""
    ALLOW = 0
    MONITOR = 1
    CHALLENGE = 2
    THROTTLE = 3
    HONEYPOT = 4
    BLOCK = 5

class RiskLevel(IntEnum):
    """Risk levels"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class Severity(str, Enum):
    """Attack severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class DetectionSource(str, Enum):
    """Where detection originated"""
    BLOOM_FILTER = "bloom"
    FAST_RULES = "rules"
    ML_MODEL = "ml"
    BEHAVIORAL = "behavioral"
    RATE_LIMIT = "ratelimit"
    FINGERPRINT = "fingerprint"
    ZERO_DAY = "zeroday"
    HONEYPOT = "honeypot"

@dataclass(slots=True)
class RequestContext:
    """
    Immutable request context - created once, read many times
    Using slots for memory efficiency and faster attribute access
    """
    # Core identifiers
    request_id: str
    timestamp: float
    
    # Network
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    
    # HTTP
    method: str
    path: str
    query_string: str
    headers: Dict[str, str]
    body: bytes
    
    # Computed (lazy)
    _path_segments: Optional[List[str]] = field(default=None, repr=False)
    _query_params: Optional[Dict[str, str]] = field(default=None, repr=False)
    _body_str: Optional[str] = field(default=None, repr=False)
    _fingerprint: Optional[str] = field(default=None, repr=False)
    
    @property
    def path_segments(self) -> List[str]:
        if self._path_segments is None:
            object.__setattr__(self, '_path_segments', 
                              [s for s in self.path.split('/') if s])
        return self._path_segments
    
    @property
    def query_params(self) -> Dict[str, str]:
        if self._query_params is None:
            params = {}
            if self.query_string:
                for pair in self.query_string.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v
            object.__setattr__(self, '_query_params', params)
        return self._query_params
    
    @property
    def body_str(self) -> str:
        if self._body_str is None:
            try:
                object.__setattr__(self, '_body_str', 
                                  self.body.decode('utf-8', errors='replace'))
            except:
                object.__setattr__(self, '_body_str', '')
        return self._body_str
    
    @property
    def content_type(self) -> str:
        return self.headers.get('content-type', '')
    
    @property
    def user_agent(self) -> str:
        return self.headers.get('user-agent', '')
    
    @property
    def host(self) -> str:
        return self.headers.get('host', '')
    
    def compute_fingerprint(self) -> str:
        """Compute request fingerprint for caching"""
        if self._fingerprint is None:
            fp_data = f"{self.method}:{self.path}:{self.query_string}:{len(self.body)}"
            object.__setattr__(self, '_fingerprint', 
                              hashlib.sha256(fp_data.encode()).hexdigest()[:32])
        return self._fingerprint

@dataclass(slots=True)
class Detection:
    """Single detection event"""
    source: DetectionSource
    category: str
    confidence: float
    severity: Severity = Severity.MEDIUM
    rule_id: Optional[str] = None
    matched_pattern: Optional[str] = None
    matched_value: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict:
        return {
            "source": self.source.value,
            "category": self.category,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "matched_pattern": self.matched_pattern,
        }

@dataclass
class WAFResult:
    """Complete WAF analysis result"""
    request_id: str
    action: Action
    risk_level: RiskLevel
    detections: List[Detection]
    
    # Timing
    start_time: float
    end_time: float = 0.0
    
    # Async results (filled later)
    ml_score: Optional[float] = None
    behavioral_score: Optional[float] = None
    
    # Routing
    route_to_honeypot: bool = False
    honeypot_id: Optional[str] = None
    
    # Zero-day
    is_zero_day: bool = False
    zero_day_signature: Optional[str] = None
    
    @property
    def latency_ms(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0
    
    @property
    def should_block(self) -> bool:
        return self.action == Action.BLOCK
    
    def finalize(self):
        """Mark result as complete"""
        self.end_time = time.perf_counter()
    
    def add_detection(self, detection: Detection):
        self.detections.append(detection)
        # Update risk level based on detection
        if detection.confidence > 0.9:
            self.risk_level = max(self.risk_level, RiskLevel.CRITICAL)
        elif detection.confidence > 0.7:
            self.risk_level = max(self.risk_level, RiskLevel.HIGH)
        elif detection.confidence > 0.5:
            self.risk_level = max(self.risk_level, RiskLevel.MEDIUM)
    
    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "action": self.action.name,
            "risk_level": self.risk_level.name,
            "latency_ms": round(self.latency_ms, 3),
            "detections": [d.to_dict() for d in self.detections],
            "ml_score": self.ml_score,
            "is_zero_day": self.is_zero_day,
        }
    
    def to_json(self) -> bytes:
        return orjson.dumps(self.to_dict())

@dataclass(slots=True)
class SessionState:
    """Per-session state for behavioral analysis"""
    session_id: str
    client_ip: str
    first_seen: float
    last_seen: float
    request_count: int = 0
    blocked_count: int = 0
    suspicious_count: int = 0
    
    # Fingerprints
    ja4_fingerprint: Optional[str] = None
    behavioral_fingerprint: Optional[str] = None
    browser_fingerprint: Optional[str] = None
    
    # Behavioral metrics
    unique_paths: Set[str] = field(default_factory=set)
    unique_user_agents: Set[str] = field(default_factory=set)
    error_count: int = 0
    
    # Risk tracking
    cumulative_risk: float = 0.0
    attack_categories: Set[str] = field(default_factory=set)
    
    # Honeypot tracking
    in_honeypot: bool = False
    honeypot_payloads: List[str] = field(default_factory=list)
    
    # Timing
    request_intervals: List[float] = field(default_factory=list)
    
    def update(self, ctx: RequestContext, result: WAFResult):
        """Update session state with new request"""
        now = time.time()
        
        if self.last_seen > 0:
            interval = now - self.last_seen
            if len(self.request_intervals) < 100:
                self.request_intervals.append(interval)
        
        self.last_seen = now
        self.request_count += 1
        
        if len(self.unique_paths) < 1000:
            self.unique_paths.add(ctx.path)
        
        if ctx.user_agent and len(self.unique_user_agents) < 10:
            self.unique_user_agents.add(ctx.user_agent)
        
        if result.should_block:
            self.blocked_count += 1
        
        if result.risk_level >= RiskLevel.MEDIUM:
            self.suspicious_count += 1
        
        self.cumulative_risk += result.risk_level.value * 0.1
        
        for det in result.detections:
            self.attack_categories.add(det.category)
    
    @property
    def avg_request_interval(self) -> float:
        if not self.request_intervals:
            return 0.0
        return sum(self.request_intervals) / len(self.request_intervals)
    
    @property
    def is_scanner(self) -> bool:
        """Detect scanning behavior"""
        return (
            len(self.unique_paths) > 50 and
            self.avg_request_interval < 0.5 and
            self.request_count > 100
        )
    
    @property
    def is_suspicious(self) -> bool:
        return (
            self.blocked_count > 3 or
            self.suspicious_count > 10 or
            self.cumulative_risk > 5.0 or
            len(self.unique_user_agents) > 3
        )

@dataclass
class AttackerProfile:
    """Comprehensive attacker profile for attribution"""
    profile_id: str
    
    # Fingerprints
    ja4_fingerprints: Set[str] = field(default_factory=set)
    behavioral_fingerprints: Set[str] = field(default_factory=set)
    browser_fingerprints: Set[str] = field(default_factory=set)
    
    # IPs
    source_ips: Set[str] = field(default_factory=set)
    is_tor: bool = False
    is_vpn: bool = False
    
    # Attribution
    attributed_ip: Optional[str] = None  # Real IP if discovered
    geolocation: Optional[Dict] = None
    
    # Attack history
    attack_categories: Set[str] = field(default_factory=set)
    attack_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    # Tools detected
    tools_detected: Set[str] = field(default_factory=set)
    
    # Skill assessment
    skill_level: str = "unknown"  # low, medium, high, advanced
    
    # Linked profiles (same attacker, different sessions)
    linked_profiles: Set[str] = field(default_factory=set)
