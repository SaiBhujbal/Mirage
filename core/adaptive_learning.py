"""
DECEPTICON Adaptive Learning Module
Online learning and feedback loop for continuous improvement
When ML fails, this learns from the miss
"""
import time
import json
import hashlib
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
import numpy as np

@dataclass
class AttackSample:
    """Captured attack sample for learning"""
    timestamp: float
    payload: str
    path: str
    method: str
    headers: Dict[str, str]
    detection_source: str  # What caught it: pattern, ml, advanced, manual
    category: str
    confidence: float
    client_ip: str
    features: Optional[np.ndarray] = None
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "payload": self.payload[:500],  # Truncate for storage
            "path": self.path,
            "method": self.method,
            "detection_source": self.detection_source,
            "category": self.category,
            "confidence": self.confidence,
        }


class AdaptiveLearner:
    """
    Learns from attacks that bypass initial ML detection
    Creates dynamic rules and updates thresholds
    """
    
    def __init__(self, 
                 storage_path: str = "./data/adaptive",
                 learning_rate: float = 0.1,
                 min_samples_for_rule: int = 3):
        
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.learning_rate = learning_rate
        self.min_samples_for_rule = min_samples_for_rule
        
        # Track attacks that ML missed but other layers caught
        self.ml_misses: List[AttackSample] = []
        
        # Dynamic rules generated from patterns
        self.dynamic_rules: Dict[str, Dict] = {}
        
        # Threshold adjustments per category
        self.threshold_adjustments: Dict[str, float] = defaultdict(float)
        
        # Pattern clusters for auto-rule generation
        self.pattern_clusters: Dict[str, List[str]] = defaultdict(list)
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
        # Load existing state
        self._load_state()
    
    def record_ml_miss(self, 
                       sample: AttackSample,
                       ml_score: float,
                       caught_by: str):
        """
        Record when ML missed an attack but another layer caught it
        This is the KEY feedback loop
        """
        with self.lock:
            sample.detection_source = caught_by
            self.ml_misses.append(sample)
            
            # Update pattern clusters
            payload_hash = self._get_payload_pattern(sample.payload)
            self.pattern_clusters[sample.category].append(payload_hash)
            
            # Check if we should generate a rule
            similar_count = self._count_similar_patterns(sample.payload, sample.category)
            
            if similar_count >= self.min_samples_for_rule:
                self._generate_dynamic_rule(sample)
            
            # Adjust ML threshold for this category
            self._adjust_threshold(sample.category, ml_score)
            
            # Persist periodically
            if len(self.ml_misses) % 10 == 0:
                self._save_state()
    
    def get_dynamic_rules(self) -> Dict[str, Dict]:
        """Get all dynamically generated rules"""
        with self.lock:
            return dict(self.dynamic_rules)
    
    def get_threshold_adjustment(self, category: str) -> float:
        """Get ML threshold adjustment for category"""
        with self.lock:
            return self.threshold_adjustments.get(category, 0.0)
    
    def should_lower_threshold(self, category: str) -> Tuple[bool, float]:
        """
        Check if ML threshold should be lowered for a category
        Returns (should_lower, new_threshold)
        """
        adjustment = self.get_threshold_adjustment(category)
        
        # If we've seen many misses, lower the threshold
        if adjustment > 0.1:
            # Base threshold is 0.5, lower it based on misses
            new_threshold = max(0.3, 0.5 - adjustment)
            return True, new_threshold
        
        return False, 0.5
    
    def _get_payload_pattern(self, payload: str) -> str:
        """Extract pattern signature from payload"""
        # Normalize: lowercase, collapse whitespace, remove specific values
        normalized = payload.lower()
        normalized = ' '.join(normalized.split())
        
        # Replace specific values with placeholders
        import re
        normalized = re.sub(r'\d+', 'NUM', normalized)
        normalized = re.sub(r'[a-f0-9]{8,}', 'HEX', normalized)
        normalized = re.sub(r'"[^"]*"', 'STR', normalized)
        normalized = re.sub(r"'[^']*'", 'STR', normalized)
        
        return hashlib.sha256(normalized.encode()).hexdigest()[:32]
    
    def _count_similar_patterns(self, payload: str, category: str) -> int:
        """Count similar patterns we've seen"""
        pattern = self._get_payload_pattern(payload)
        return sum(1 for p in self.pattern_clusters[category] if p == pattern)
    
    def _generate_dynamic_rule(self, sample: AttackSample):
        """Generate a dynamic rule from repeated pattern"""
        import re
        
        payload = sample.payload
        
        # Extract key suspicious elements
        patterns = []
        
        # SQL keywords in context
        sql_match = re.search(r"(['\"]?\s*(?:or|and|union|select|insert|update|delete)\s+[^;]{5,30})", 
                             payload, re.IGNORECASE)
        if sql_match:
            patterns.append(re.escape(sql_match.group(1)))
        
        # XSS patterns
        xss_match = re.search(r"(<[a-z]+[^>]*(?:on\w+|javascript:)[^>]*>)", payload, re.IGNORECASE)
        if xss_match:
            patterns.append(re.escape(xss_match.group(1)))
        
        # Command injection
        cmd_match = re.search(r"([;&|`$]\s*\w+)", payload)
        if cmd_match:
            patterns.append(re.escape(cmd_match.group(1)))
        
        if patterns:
            rule_id = f"DYN-{hashlib.sha256(sample.payload.encode()).hexdigest()[:16]}"
            
            self.dynamic_rules[rule_id] = {
                "patterns": patterns,
                "category": sample.category,
                "created": time.time(),
                "hits": 0,
                "confidence": 0.8,
                "source_payload": sample.payload[:200]
            }
    
    def _adjust_threshold(self, category: str, ml_score: float):
        """Adjust ML threshold based on miss"""
        # If ML gave low score to actual attack, we need lower threshold
        miss_severity = 0.5 - ml_score  # How much ML underestimated
        
        if miss_severity > 0:
            current = self.threshold_adjustments[category]
            # Exponential moving average
            self.threshold_adjustments[category] = (
                current * (1 - self.learning_rate) + 
                miss_severity * self.learning_rate
            )
    
    def _save_state(self):
        """Persist learning state"""
        state = {
            "dynamic_rules": self.dynamic_rules,
            "threshold_adjustments": dict(self.threshold_adjustments),
            "pattern_clusters": {k: v[-100:] for k, v in self.pattern_clusters.items()},  # Keep last 100
            "ml_misses_count": len(self.ml_misses),
        }
        
        state_path = self.storage_path / "adaptive_state.json"
        try:
            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save adaptive state: {e}")
    
    def _load_state(self):
        """Load previous learning state"""
        state_path = self.storage_path / "adaptive_state.json"
        
        if state_path.exists():
            try:
                with open(state_path) as f:
                    state = json.load(f)
                
                self.dynamic_rules = state.get("dynamic_rules", {})
                self.threshold_adjustments = defaultdict(float, state.get("threshold_adjustments", {}))
                self.pattern_clusters = defaultdict(list, state.get("pattern_clusters", {}))
                
            except Exception as e:
                print(f"Warning: Could not load adaptive state: {e}")
    
    def get_stats(self) -> Dict:
        """Get learning statistics"""
        with self.lock:
            return {
                "total_ml_misses": len(self.ml_misses),
                "dynamic_rules_count": len(self.dynamic_rules),
                "threshold_adjustments": dict(self.threshold_adjustments),
                "categories_with_misses": list(self.pattern_clusters.keys()),
            }


class ReputationTracker:
    """
    Track IP/client reputation beyond simple rate limiting
    Uses behavioral signals, not just request count
    """
    
    def __init__(self, decay_hours: float = 24.0):
        self.decay_hours = decay_hours
        
        # Reputation scores (lower = worse)
        self.ip_scores: Dict[str, float] = defaultdict(lambda: 1.0)
        
        # Behavioral signals
        self.ip_signals: Dict[str, Dict] = defaultdict(lambda: {
            "attack_count": 0,
            "probe_count": 0,
            "error_count": 0,
            "unique_paths": set(),
            "user_agents": set(),
            "last_attack": 0,
            "first_seen": time.time(),
        })
        
        self.lock = threading.Lock()
    
    def record_attack(self, client_ip: str, category: str, severity: float):
        """Record attack from IP"""
        with self.lock:
            signals = self.ip_signals[client_ip]
            signals["attack_count"] += 1
            signals["last_attack"] = time.time()
            
            # Decrease reputation based on severity
            self.ip_scores[client_ip] *= (1 - severity * 0.2)
            self.ip_scores[client_ip] = max(0.01, self.ip_scores[client_ip])
    
    def record_probe(self, client_ip: str, path: str, user_agent: str):
        """Record potential probing behavior"""
        with self.lock:
            signals = self.ip_signals[client_ip]
            signals["probe_count"] += 1
            signals["unique_paths"].add(path)
            signals["user_agents"].add(user_agent[:50])
            
            # Many unique paths = scanning
            if len(signals["unique_paths"]) > 50:
                self.ip_scores[client_ip] *= 0.9
            
            # Multiple user agents = suspicious
            if len(signals["user_agents"]) > 3:
                self.ip_scores[client_ip] *= 0.95
    
    def record_error(self, client_ip: str):
        """Record error response (404, 500, etc)"""
        with self.lock:
            signals = self.ip_signals[client_ip]
            signals["error_count"] += 1
            
            # High error rate = scanning
            if signals["error_count"] > 10:
                self.ip_scores[client_ip] *= 0.98
    
    def get_reputation(self, client_ip: str) -> float:
        """Get current reputation score (0-1, lower = more suspicious)"""
        with self.lock:
            score = self.ip_scores[client_ip]
            
            # Apply time decay - reputation recovers over time
            signals = self.ip_signals[client_ip]
            if signals["last_attack"] > 0:
                hours_since_attack = (time.time() - signals["last_attack"]) / 3600
                recovery = min(1.0, hours_since_attack / self.decay_hours)
                score = score + (1 - score) * recovery * 0.5
            
            return score
    
    def is_suspicious(self, client_ip: str) -> Tuple[bool, str]:
        """Check if IP is suspicious"""
        reputation = self.get_reputation(client_ip)
        
        if reputation < 0.3:
            return True, f"Very low reputation: {reputation:.2f}"
        
        with self.lock:
            signals = self.ip_signals[client_ip]
            
            if signals["attack_count"] >= 5:
                return True, f"Multiple attacks: {signals['attack_count']}"
            
            if len(signals["unique_paths"]) > 100:
                return True, f"Path scanning: {len(signals['unique_paths'])} paths"
            
            if len(signals["user_agents"]) > 5:
                return True, f"User-agent rotation: {len(signals['user_agents'])} agents"
        
        return False, ""
    
    def get_adjusted_threshold(self, client_ip: str, base_threshold: float) -> float:
        """Get ML threshold adjusted by reputation"""
        reputation = self.get_reputation(client_ip)
        
        # Lower reputation = lower threshold (more strict)
        adjustment = (1 - reputation) * 0.2
        
        return max(0.2, base_threshold - adjustment)


# Global instances
adaptive_learner = AdaptiveLearner()
reputation_tracker = ReputationTracker()
