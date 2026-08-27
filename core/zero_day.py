"""
DECEPTICON Zero-Day Detection & Auto-Rule Generation
Detect unknown attacks and automatically generate rules
"""
import time
import hashlib
import re
import math
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import threading
import json

from core.models import RequestContext, Detection, DetectionSource, WAFResult
from ml.feature_extraction import FeatureVector, feature_extractor

@dataclass
class ZeroDaySignature:
    """Signature for a potential zero-day attack"""
    signature_id: str
    pattern: str
    confidence: float
    category: str
    first_seen: float
    occurrences: int = 1
    source_ips: Set[str] = field(default_factory=set)
    blocked: bool = False
    auto_rule_generated: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'signature_id': self.signature_id,
            'pattern': self.pattern,
            'confidence': self.confidence,
            'category': self.category,
            'occurrences': self.occurrences,
            'source_ips': list(self.source_ips)[:10],
            'blocked': self.blocked,
        }

@dataclass
class GeneratedRule:
    """Auto-generated WAF rule"""
    rule_id: str
    pattern: str
    category: str
    severity: float
    locations: List[str]
    created_at: float
    source_signature: str
    is_active: bool = False
    false_positives: int = 0
    true_positives: int = 0
    
    def to_modsecurity(self) -> str:
        """Convert to ModSecurity rule format"""
        escaped_pattern = self.pattern.replace('"', '\\"')
        location_map = {
            'path': 'REQUEST_URI',
            'query': 'QUERY_STRING', 
            'body': 'REQUEST_BODY',
            'headers': 'REQUEST_HEADERS'
        }
        
        targets = '|'.join([location_map.get(loc, 'REQUEST_URI') for loc in self.locations])
        
        rule = f'''
SecRule {targets} "@rx {escaped_pattern}" \\
    "id:{self.rule_id},\\
    phase:2,\\
    block,\\
    t:none,t:urlDecodeUni,\\
    msg:'Auto-generated rule - {self.category}',\\
    tag:'decepticon-auto',\\
    tag:'{self.category.lower()}',\\
    severity:'CRITICAL'"
'''
        return rule.strip()

class AnomalyDetector:
    """
    Statistical anomaly detection for zero-day attacks
    Uses multiple techniques for robustness
    """
    
    def __init__(self, window_size: int = 1000, threshold: float = 3.0):
        self.window_size = window_size
        self.threshold = threshold
        
        # Running statistics for each feature
        self.feature_stats: Dict[str, Dict] = {}
        
        # Recent feature vectors (sliding window)
        self.recent_vectors: deque = deque(maxlen=window_size)
        
        # Lock for thread safety
        self.lock = threading.Lock()
    
    def update_baseline(self, features):
        """
        Update baseline statistics with new observation

        Args:
            features: Either a FeatureVector object or numpy array
        """
        # Handle both FeatureVector objects and numpy arrays
        if hasattr(features, 'features'):
            # It's a FeatureVector object
            feature_array = features.features.copy()
            feature_names = features.feature_names
        else:
            # It's already a numpy array
            import numpy as np
            feature_array = np.array(features).copy() if not isinstance(features, np.ndarray) else features.copy()
            feature_names = [f"feature_{i}" for i in range(len(feature_array))]

        with self.lock:
            self.recent_vectors.append(feature_array)

            # Update running stats for each feature
            for i, (name, value) in enumerate(zip(feature_names, feature_array)):
                if name not in self.feature_stats:
                    self.feature_stats[name] = {
                        'count': 0,
                        'mean': 0.0,
                        'M2': 0.0,  # For Welford's algorithm
                    }
                
                stats = self.feature_stats[name]
                stats['count'] += 1
                delta = value - stats['mean']
                stats['mean'] += delta / stats['count']
                delta2 = value - stats['mean']
                stats['M2'] += delta * delta2
    
    def detect_anomaly(self, features: FeatureVector) -> Tuple[bool, float, Dict[str, float]]:
        """
        Detect if feature vector is anomalous
        Returns (is_anomaly, anomaly_score, feature_deviations)
        """
        if len(self.feature_stats) == 0:
            return False, 0.0, {}
        
        deviations = {}
        max_deviation = 0.0
        total_deviation = 0.0
        
        feature_names = features.feature_names if hasattr(features, 'feature_names') else [f"feature_{i}" for i in range(len(features.features) if hasattr(features, 'features') else len(features))]
        features_array = features.features if hasattr(features, 'features') else features
        for i, (name, value) in enumerate(zip(feature_names, features_array)):
            if name not in self.feature_stats:
                continue
            
            stats = self.feature_stats[name]
            if stats['count'] < 100:  # Not enough data
                continue
            
            # Calculate standard deviation
            variance = stats['M2'] / (stats['count'] - 1) if stats['count'] > 1 else 0
            std = math.sqrt(variance) if variance > 0 else 1e-6
            
            # Calculate z-score
            z_score = abs(value - stats['mean']) / std
            
            if z_score > 2.0:  # Only track significant deviations
                deviations[name] = z_score
                max_deviation = max(max_deviation, z_score)
                total_deviation += z_score
        
        # Anomaly if any feature exceeds threshold
        is_anomaly = max_deviation > self.threshold
        
        # Aggregate score
        anomaly_score = min(total_deviation / 10.0, 1.0) if deviations else 0.0
        
        return is_anomaly, anomaly_score, deviations
    
    def get_baseline_stats(self) -> Dict:
        """Get current baseline statistics"""
        return {
            name: {
                'mean': stats['mean'],
                'std': math.sqrt(stats['M2'] / (stats['count'] - 1)) if stats['count'] > 1 else 0,
                'count': stats['count']
            }
            for name, stats in self.feature_stats.items()
        }

class PatternLearner:
    """
    Learn attack patterns from detected anomalies
    Used for automatic rule generation
    """
    
    def __init__(self, min_occurrences: int = 3):
        self.min_occurrences = min_occurrences
        
        # Pattern candidates
        self.pattern_candidates: Dict[str, Dict] = {}
        
        # Confirmed patterns (enough occurrences)
        self.confirmed_patterns: Dict[str, ZeroDaySignature] = {}
        
        # Lock
        self.lock = threading.Lock()
    
    def extract_patterns(self, ctx: RequestContext, 
                         deviations: Dict[str, float]) -> List[str]:
        """
        Extract potential attack patterns from request
        """
        patterns = []
        combined = f"{ctx.path} {ctx.query_string} {ctx.body_str}"
        
        # Extract suspicious substrings
        # SQL-like patterns
        sql_matches = re.findall(
            r"(?:'[^']*'|\"|;|\s(?:OR|AND|UNION|SELECT)\s)[^&\s]{0,50}",
            combined, re.I
        )
        patterns.extend(sql_matches)
        
        # Script/XSS patterns
        script_matches = re.findall(
            r"<[^>]{2,50}>|javascript:[^&\s]{0,30}|on\w+\s*=\s*['\"][^'\"]{0,30}",
            combined, re.I
        )
        patterns.extend(script_matches)
        
        # Command injection patterns
        cmd_matches = re.findall(
            r"[;|`$]\s*\w+[^&\s]{0,30}|\$\([^)]{0,30}\)",
            combined
        )
        patterns.extend(cmd_matches)
        
        # Path traversal
        path_matches = re.findall(
            r"(?:\.\./|\.\.\\){2,}[^&\s]{0,30}",
            combined
        )
        patterns.extend(path_matches)
        
        # Filter and normalize
        normalized = []
        for p in patterns:
            p = p.strip()
            if len(p) >= 5 and len(p) <= 100:
                normalized.append(p)
        
        return normalized
    
    def add_pattern(self, pattern: str, ctx: RequestContext, 
                    confidence: float, category: str = "ZERO_DAY"):
        """
        Add pattern observation
        """
        pattern_id = hashlib.sha256(pattern.encode()).hexdigest()[:32]
        
        with self.lock:
            if pattern_id not in self.pattern_candidates:
                self.pattern_candidates[pattern_id] = {
                    'pattern': pattern,
                    'occurrences': 0,
                    'confidence': confidence,
                    'category': category,
                    'first_seen': time.time(),
                    'source_ips': set(),
                }
            
            candidate = self.pattern_candidates[pattern_id]
            candidate['occurrences'] += 1
            candidate['source_ips'].add(ctx.client_ip)
            candidate['confidence'] = max(candidate['confidence'], confidence)
            
            # Promote to confirmed if enough occurrences
            if candidate['occurrences'] >= self.min_occurrences:
                if pattern_id not in self.confirmed_patterns:
                    sig = ZeroDaySignature(
                        signature_id=pattern_id,
                        pattern=pattern,
                        confidence=candidate['confidence'],
                        category=category,
                        first_seen=candidate['first_seen'],
                        occurrences=candidate['occurrences'],
                        source_ips=candidate['source_ips'].copy(),
                    )
                    self.confirmed_patterns[pattern_id] = sig
                    return sig
                else:
                    self.confirmed_patterns[pattern_id].occurrences = candidate['occurrences']
        
        return None
    
    def get_confirmed_patterns(self) -> List[ZeroDaySignature]:
        """Get all confirmed zero-day patterns"""
        return list(self.confirmed_patterns.values())

class RuleGenerator:
    """
    Generate WAF rules from zero-day signatures
    """
    
    def __init__(self):
        self.generated_rules: Dict[str, GeneratedRule] = {}
        self.rule_counter = 900000  # Start at high ID
    
    def generate_rule(self, signature: ZeroDaySignature) -> GeneratedRule:
        """
        Generate WAF rule from signature
        """
        self.rule_counter += 1
        rule_id = str(self.rule_counter)
        
        # Escape regex special characters
        escaped_pattern = re.escape(signature.pattern)
        
        # Make pattern more flexible
        # Replace escaped spaces with \s+
        escaped_pattern = escaped_pattern.replace(r'\ ', r'\s+')
        
        # Determine locations based on pattern type
        locations = ['query', 'body']
        if '../' in signature.pattern or '..\\' in signature.pattern:
            locations = ['path', 'query']
        elif '<' in signature.pattern:
            locations = ['query', 'body', 'headers']
        
        rule = GeneratedRule(
            rule_id=rule_id,
            pattern=escaped_pattern,
            category=signature.category,
            severity=signature.confidence,
            locations=locations,
            created_at=time.time(),
            source_signature=signature.signature_id,
        )
        
        self.generated_rules[rule_id] = rule
        signature.auto_rule_generated = True
        
        return rule
    
    def activate_rule(self, rule_id: str):
        """Activate a rule for enforcement"""
        if rule_id in self.generated_rules:
            self.generated_rules[rule_id].is_active = True
    
    def deactivate_rule(self, rule_id: str):
        """Deactivate a rule"""
        if rule_id in self.generated_rules:
            self.generated_rules[rule_id].is_active = False
    
    def record_feedback(self, rule_id: str, is_true_positive: bool):
        """Record rule effectiveness feedback"""
        if rule_id in self.generated_rules:
            if is_true_positive:
                self.generated_rules[rule_id].true_positives += 1
            else:
                self.generated_rules[rule_id].false_positives += 1
                
                # Auto-deactivate if too many false positives
                rule = self.generated_rules[rule_id]
                if rule.false_positives > 5 and rule.false_positives > rule.true_positives:
                    rule.is_active = False
    
    def get_active_rules(self) -> List[GeneratedRule]:
        """Get all active rules"""
        return [r for r in self.generated_rules.values() if r.is_active]
    
    def export_modsecurity_rules(self) -> str:
        """Export all active rules as ModSecurity config"""
        rules = []
        rules.append("# DECEPTICON Auto-Generated Rules")
        rules.append(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        rules.append("")
        
        for rule in self.get_active_rules():
            rules.append(rule.to_modsecurity())
            rules.append("")
        
        return '\n'.join(rules)

class ZeroDayDetector:
    """
    Main zero-day detection engine
    Combines anomaly detection, pattern learning, and rule generation
    """
    
    def __init__(self, 
                 anomaly_threshold: float = 3.0,
                 min_pattern_occurrences: int = 3,
                 enable_auto_rules: bool = True):
        
        self.anomaly_detector = AnomalyDetector(threshold=anomaly_threshold)
        self.pattern_learner = PatternLearner(min_occurrences=min_pattern_occurrences)
        self.rule_generator = RuleGenerator()
        self.enable_auto_rules = enable_auto_rules
        
        # Recent detections for deduplication
        self.recent_detections: deque = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'anomalies_detected': 0,
            'patterns_learned': 0,
            'rules_generated': 0,
        }
    
    def analyze(self, ctx: RequestContext, features: FeatureVector,
                existing_detections: List[Detection]) -> Optional[Detection]:
        """
        Analyze request for zero-day attacks
        Returns Detection if zero-day found, None otherwise
        """
        self.stats['total_analyzed'] += 1
        
        # Skip if already detected by rules/ML
        if any(d.confidence > 0.9 for d in existing_detections):
            # Still update baseline with attack
            return None
        
        # Update baseline with normal traffic
        if not existing_detections:
            self.anomaly_detector.update_baseline(features)
            return None
        
        # Check for anomaly
        is_anomaly, anomaly_score, deviations = self.anomaly_detector.detect_anomaly(features)
        
        if not is_anomaly:
            return None
        
        self.stats['anomalies_detected'] += 1
        
        # Extract attack patterns
        patterns = self.pattern_learner.extract_patterns(ctx, deviations)
        
        zero_day_sig = None
        for pattern in patterns:
            sig = self.pattern_learner.add_pattern(
                pattern, ctx, 
                confidence=anomaly_score,
                category="ZERO_DAY"
            )
            if sig:
                zero_day_sig = sig
                self.stats['patterns_learned'] += 1
                
                # Generate rule if enabled
                if self.enable_auto_rules:
                    rule = self.rule_generator.generate_rule(sig)
                    rule.is_active = True  # Auto-activate
                    self.stats['rules_generated'] += 1
        
        # Create detection
        detection = Detection(
            source=DetectionSource.ZERO_DAY,
            category="ZERO_DAY",
            confidence=anomaly_score,
            matched_pattern=patterns[0] if patterns else None,
            metadata={
                'deviations': {k: v for k, v in list(deviations.items())[:5]},
                'signature_id': zero_day_sig.signature_id if zero_day_sig else None,
            }
        )
        
        return detection
    
    def get_zero_day_signatures(self) -> List[Dict]:
        """Get all zero-day signatures"""
        return [sig.to_dict() for sig in self.pattern_learner.get_confirmed_patterns()]
    
    def get_generated_rules(self) -> List[Dict]:
        """Get all generated rules"""
        return [
            {
                'rule_id': r.rule_id,
                'pattern': r.pattern,
                'category': r.category,
                'is_active': r.is_active,
                'true_positives': r.true_positives,
                'false_positives': r.false_positives,
            }
            for r in self.rule_generator.generated_rules.values()
        ]
    
    def export_rules(self) -> str:
        """Export rules as ModSecurity config"""
        return self.rule_generator.export_modsecurity_rules()
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            **self.stats,
            'baseline_features': len(self.anomaly_detector.feature_stats),
            'pattern_candidates': len(self.pattern_learner.pattern_candidates),
            'confirmed_patterns': len(self.pattern_learner.confirmed_patterns),
            'active_rules': len(self.rule_generator.get_active_rules()),
        }

# Global instance
zero_day_detector = ZeroDayDetector()
