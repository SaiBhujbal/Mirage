"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  LEGACY — THIS IS NOT THE WAF.  See ../LEGACY.md                             ║
║                                                                              ║
║  The working system is  waf/engine.py  (run: python -m waf.server).          ║
║  Nothing in waf/, demo/ or tests/ imports this module.                       ║
║                                                                              ║
║  This engine imports ml/secure_inference.py, which is BROKEN: it returns      ║
║  malicious=True confidence=0.992 for EVERY input, benign requests included.   ║
║  Deployed, it would block 100% of your users. It is retained only as the      ║
║  reproducible subject of the project's central finding (train/serve skew).    ║
╚══════════════════════════════════════════════════════════════════════════════╝

DECEPTICON Main WAF Engine (legacy)
Ultra-low latency request analysis and decision making
Target: < 3ms sync path, < 50ms with async enrichment
"""
import time
import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading

from config.settings import settings, LatencyBudget, ATTACK_CATEGORIES
from core.models import (
    RequestContext, Detection, DetectionSource, WAFResult,
    Action, RiskLevel, SessionState
)
from core.pattern_engine import pattern_engine, PatternRule
from core.zero_day import zero_day_detector

# ============================================================================
# SECURITY: Import ONLY secure modules - NO FALLBACK TO VULNERABLE CODE
# ============================================================================

# Import security enforcement first
try:
    import core.security_imports
except ImportError:
    pass  # Security imports not critical for basic operation

# SECURE Rate Limiter (atomic, no race conditions) - REQUIRED
try:
    from core.atomic_rate_limiter import atomic_rate_limiter as rate_limiter
    from core.atomic_rate_limiter import AtomicRateLimiter
    adaptive_limiter = AtomicRateLimiter(default_capacity=200, default_refill_rate=20.0)
    SECURE_RATE_LIMITER = True
except ImportError as e:
    raise ImportError(
        f"SECURITY ERROR: Secure rate limiter not available: {e}\n"
        f"The vulnerable rate_limiter.py has race conditions (CVSS 7.4).\n"
        f"Install core/atomic_rate_limiter.py or fix the import error."
    )

# SECURE Session Manager (256-bit random IDs) - REQUIRED
try:
    from core.secure_session import secure_session_manager as session_manager
    SECURE_SESSION = True
except ImportError as e:
    raise ImportError(
        f"SECURITY ERROR: Secure session manager not available: {e}\n"
        f"The vulnerable session_manager.py uses MD5(IP+UA) for session IDs (CVSS 9.1).\n"
        f"Install core/secure_session.py or fix the import error."
    )

# Import honeypot for deception - prefer comprehensive honeypot
try:
    from deception.comprehensive_honeypot import comprehensive_honeypot
    HONEYPOT_AVAILABLE = True
    COMPREHENSIVE_HONEYPOT = True
except ImportError:
    try:
        from deception.honeypot import honeypot_manager
        comprehensive_honeypot = None
        HONEYPOT_AVAILABLE = True
        COMPREHENSIVE_HONEYPOT = False
    except ImportError:
        comprehensive_honeypot = None
        HONEYPOT_AVAILABLE = False
        COMPREHENSIVE_HONEYPOT = False

# Import new protection modules
try:
    from core.advanced_protection import advanced_protection, ThreatLevel
    ADVANCED_PROTECTION_AVAILABLE = True
except ImportError:
    ADVANCED_PROTECTION_AVAILABLE = False

try:
    from core.adaptive_learning import adaptive_learner, reputation_tracker, AttackSample
    ADAPTIVE_LEARNING_AVAILABLE = True
except ImportError:
    ADAPTIVE_LEARNING_AVAILABLE = False

try:
    from core.rule_generator import rule_generator
    RULE_GENERATOR_AVAILABLE = True
except ImportError:
    RULE_GENERATOR_AVAILABLE = False

try:
    from deception.honeypot import HoneypotRouter, honeypot_router
    HONEYPOT_AVAILABLE = True
except ImportError:
    HONEYPOT_AVAILABLE = False

# SECURE ML Inference (NO PICKLE - ONNX/numpy only) - REQUIRED
try:
    from ml.secure_inference import secure_ml_predictor as ml_engine
    from ml.secure_inference import SafeFeatureExtractor
    feature_extractor = SafeFeatureExtractor()
    SECURE_ML = True
except ImportError as e:
    raise ImportError(
        f"SECURITY ERROR: Secure ML inference not available: {e}\n"
        f"The vulnerable inference.py uses pickle.load() which allows RCE (CVSS 10.0).\n"
        f"Install ml/secure_inference.py or fix the import error."
    )

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("decepticon.waf")

@dataclass
class LatencyMetrics:
    """Track latency for each component"""
    bloom_filter_ms: float = 0.0
    pattern_engine_ms: float = 0.0
    feature_extraction_ms: float = 0.0
    ml_inference_ms: float = 0.0
    rate_limit_ms: float = 0.0
    session_ms: float = 0.0
    zero_day_ms: float = 0.0
    total_sync_ms: float = 0.0
    total_async_ms: float = 0.0

class WAFEngine:
    """
    Main WAF Engine
    
    Processing Pipeline:
    1. SYNC PATH (< 3ms target):
       - Rate limiting check
       - Bloom filter (known signatures)
       - Fast pattern matching
       - Session lookup
       - Quick decision
    
    2. ASYNC PATH (parallel, doesn't block response):
       - ML inference
       - Feature extraction
       - Zero-day detection
       - Behavioral analysis
       - Rule updates
    """
    
    def __init__(self):
        # Core components
        self.pattern_engine = pattern_engine
        self.rate_limiter = adaptive_limiter
        self.session_manager = session_manager
        self.zero_day_detector = zero_day_detector
        self.ml_engine = ml_engine
        self.feature_extractor = feature_extractor
        
        # Deception components
        if HONEYPOT_AVAILABLE:
            self.honeypot_router = honeypot_router
        else:
            self.honeypot_router = None
        
        # Rule generation (feedback loop)
        if RULE_GENERATOR_AVAILABLE:
            self.rule_generator = rule_generator
        else:
            self.rule_generator = None
        
        # Thread pool for async tasks
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Metrics
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'suspicious_requests': 0,
            'honeypot_sessions': 0,
            'zero_days_detected': 0,
            'avg_latency_ms': 0.0,
            'p99_latency_ms': 0.0,
        }
        
        # Latency tracking
        self.latency_samples: List[float] = []
        self.max_latency_samples = 10000
        
        # Lock for metrics
        self.lock = threading.Lock()
    
    def analyze_request(self, ctx: RequestContext, 
                        tls_info: Optional[Dict] = None) -> WAFResult:
        """
        Analyze request and return WAF decision
        This is the main entry point - must be FAST
        
        Target: < 3ms for sync path
        """
        start_time = time.perf_counter()
        latency = LatencyMetrics()
        
        # Initialize result
        result = WAFResult(
            request_id=ctx.request_id,
            action=Action.ALLOW,
            risk_level=RiskLevel.NONE,
            detections=[],
            start_time=start_time,
        )
        
        try:
            # ═══════════════════════════════════════════════════════════
            # STAGE 1: Rate Limiting (< 0.1ms)
            # ═══════════════════════════════════════════════════════════
            t1 = time.perf_counter()
            
            rate_key = self.rate_limiter.get_key(ctx.client_ip, ctx.path)
            rate_result = self.rate_limiter.check(rate_key, ctx.path)
            
            latency.rate_limit_ms = (time.perf_counter() - t1) * 1000
            
            if not rate_result.allowed:
                result.action = Action.THROTTLE
                result.risk_level = RiskLevel.MEDIUM
                result.add_detection(Detection(
                    source=DetectionSource.RATE_LIMIT,
                    category="RATE_LIMIT",
                    confidence=1.0,
                    metadata={'rate': getattr(rate_result, 'current_rate', getattr(rate_result, 'remaining', 0))}
                ))
                result.finalize()
                self._update_metrics(result)
                return result
            
            # ═══════════════════════════════════════════════════════════
            # STAGE 2: Session Lookup (< 0.1ms)
            # ═══════════════════════════════════════════════════════════
            t2 = time.perf_counter()
            
            session = self.session_manager.get_or_create_session(ctx, tls_info)
            
            # Quick check if session is already known bad
            if session.cumulative_risk > 10.0:
                result.action = Action.BLOCK
                result.risk_level = RiskLevel.CRITICAL
                result.add_detection(Detection(
                    source=DetectionSource.BEHAVIORAL,
                    category="REPEAT_OFFENDER",
                    confidence=0.95,
                ))
                result.finalize()
                self._update_metrics(result)
                return result
            
            # ═══════════════════════════════════════════════════════════
            # STAGE 2.5: Honeypot Session Check
            # If this session was previously routed to honeypot, keep them there
            # ═══════════════════════════════════════════════════════════
            if HONEYPOT_AVAILABLE and getattr(session, 'in_honeypot', False):
                # Route to honeypot - learn from their actions
                honeypot_result = self._handle_honeypot_request(ctx, session, result)
                if honeypot_result:
                    return honeypot_result
            
            latency.session_ms = (time.perf_counter() - t2) * 1000
            
            # ═══════════════════════════════════════════════════════════
            # STAGE 3: Fast Pattern Matching (< 0.5ms)
            # ═══════════════════════════════════════════════════════════
            t3 = time.perf_counter()
            
            # Quick bloom filter check first
            combined = f"{ctx.path} {ctx.query_string} {ctx.body_str}"
            is_suspicious, potential_categories = self.pattern_engine.quick_check(combined)

            latency.bloom_filter_ms = (time.perf_counter() - t3) * 1000

            # ALWAYS run scan_request to check for scanner user-agents
            # (even if bloom filter says not suspicious)
            t4 = time.perf_counter()

            # Full pattern scan (includes scanner detection in UA)
            matches = self.pattern_engine.scan_request(
                ctx.path, ctx.query_string, ctx.body_str, ctx.headers
            )

            if matches:
                
                latency.pattern_engine_ms = (time.perf_counter() - t4) * 1000
                
                for rule, match, location in matches:
                    detection = Detection(
                        source=DetectionSource.FAST_RULES,
                        category=rule.category,
                        confidence=rule.severity,
                        rule_id=rule.rule_id,
                        matched_pattern=rule.description,
                        matched_value=match.group(0)[:100],
                    )
                    result.add_detection(detection)
                
                # Determine action based on detections
                if matches:
                    max_severity = max(m[0].severity for m in matches)
                    attack_cat = matches[0][0].category
                    cat_info = ATTACK_CATEGORIES.get(attack_cat, {})
                    
                    if max_severity >= 0.9 and cat_info.get('block', False):
                        result.action = Action.BLOCK
                    elif max_severity >= 0.5:
                        # ═══════════════════════════════════════════════════
                        # HONEYPOT ROUTING: Medium confidence → Honeypot
                        # Let attacker "succeed" while we learn their patterns
                        # ═══════════════════════════════════════════════════
                        if HONEYPOT_AVAILABLE and max_severity < 0.9:
                            result.action = Action.CHALLENGE  # Will be honeypot
                            session.in_honeypot = True
                            self.metrics['honeypot_sessions'] += 1
                            
                            # Start learning from this attacker
                            self.executor.submit(
                                self._learn_from_honeypot,
                                ctx, session, matches, result
                            )
                        else:
                            result.action = Action.CHALLENGE
                    else:
                        result.action = Action.MONITOR
            
            # ═══════════════════════════════════════════════════════════
            # STAGE 3.5: Advanced Protection (XXE, GraphQL, JWT, etc)
            # ═══════════════════════════════════════════════════════════
            if ADVANCED_PROTECTION_AVAILABLE:
                t5 = time.perf_counter()
                
                advanced_detections = advanced_protection.analyze(
                    path=ctx.path,
                    query=ctx.query_string,
                    body=ctx.body_str,
                    headers=ctx.headers,
                    client_ip=ctx.client_ip,
                    ml_score=getattr(result, 'ml_score', 0.0),
                )
                
                for adv_det in advanced_detections:
                    detection = Detection(
                        source=DetectionSource.FAST_RULES,
                        category=adv_det.category,
                        confidence=adv_det.confidence,
                        matched_pattern=adv_det.description,
                        matched_value=adv_det.raw_evidence[:100] if adv_det.raw_evidence else "",
                    )
                    result.add_detection(detection)
                    
                    # Update action based on threat level
                    if adv_det.threat_level == ThreatLevel.CRITICAL:
                        result.action = max(result.action, Action.BLOCK)
                        result.risk_level = RiskLevel.CRITICAL
                    elif adv_det.threat_level == ThreatLevel.HIGH:
                        result.action = max(result.action, Action.BLOCK)
                        result.risk_level = max(result.risk_level, RiskLevel.HIGH)
                    elif adv_det.threat_level == ThreatLevel.MEDIUM:
                        result.action = max(result.action, Action.CHALLENGE)
                        result.risk_level = max(result.risk_level, RiskLevel.MEDIUM)
            
            # Calculate sync latency
            latency.total_sync_ms = (time.perf_counter() - start_time) * 1000
            
            # ═══════════════════════════════════════════════════════════
            # STAGE 4: Async Enrichment (doesn't block response)
            # ═══════════════════════════════════════════════════════════
            if settings.ENABLE_ASYNC_ML:
                # Submit async tasks
                self.executor.submit(
                    self._async_analysis,
                    ctx, session, result, latency
                )
            
            # Finalize result
            result.finalize()
            
            # Update session state
            self.session_manager.update_session(session, ctx, result)
            
            # Update metrics
            self._update_metrics(result)
            
            return result
            
        except Exception as e:
            logger.error(f"WAF analysis error: {e}", exc_info=True)
            # On error, allow but log
            result.finalize()
            return result
    
    def _learn_from_honeypot(self, ctx: RequestContext, session: SessionState,
                              matches: list, result: WAFResult):
        """
        Learn attack patterns from honeypot interactions
        
        When we route an attacker to a honeypot, we let them "succeed" while
        secretly recording their techniques for ML training.
        
        Args:
            matches: List of tuples (rule, match_obj, location)
        """
        try:
            if not ADAPTIVE_LEARNING_AVAILABLE:
                return
            
            # Extract category and confidence from matches
            # matches is a list of (rule, match_obj, location) tuples
            if matches:
                first_rule = matches[0][0]  # First tuple's rule object
                category = first_rule.category if hasattr(first_rule, 'category') else "UNKNOWN"
                confidence = first_rule.severity if hasattr(first_rule, 'severity') else 0.5
            else:
                category = "UNKNOWN"
                confidence = 0.5
            
            # Record this attack sample for learning
            sample = AttackSample(
                timestamp=time.time(),
                payload=f"{ctx.query_string} {ctx.body_str}"[:1000],
                path=ctx.path,
                method=ctx.method,
                headers=dict(ctx.headers),
                detection_source="honeypot",
                category=category,
                confidence=confidence,
                client_ip=ctx.client_ip,
            )
            
            # Record to adaptive learner (using ml_miss with honeypot source)
            # Ensure ml_score is never None
            ml_score = getattr(result, 'ml_score', None)
            if ml_score is None:
                ml_score = 0.0
            
            adaptive_learner.record_ml_miss(
                sample=sample,
                ml_score=ml_score,
                caught_by="honeypot"
            )
            
            # Log for analysis
            logger.info(
                f"[HONEYPOT] Captured attack pattern from {ctx.client_ip}: "
                f"{sample.category} (confidence: {sample.confidence:.2f})"
            )
            
        except Exception as e:
            logger.error(f"Error learning from honeypot: {e}")
    
    def _async_analysis(self, ctx: RequestContext, session: SessionState,
                        result: WAFResult, latency: LatencyMetrics):
        """
        Async analysis tasks - run after response is sent
        Used for enrichment and learning
        """
        try:
            # Feature extraction
            t1 = time.perf_counter()
            session_state = {
                'request_rate_1m': session.request_count,
                'unique_paths_1h': len(session.unique_paths),
                'error_rate_1h': session.error_count / max(session.request_count, 1),
                'session_duration': session.last_seen - session.first_seen,
                'requests_per_session': session.request_count,
                'avg_body_size': len(ctx.body),
                'method_variety': len(set([ctx.method])),
                'ua_consistency': 1.0 if len(session.unique_user_agents) <= 1 else 0.5,
            }
            
            features = self.feature_extractor.extract(ctx, session_state)
            latency.feature_extraction_ms = (time.perf_counter() - t1) * 1000
            
            # ML inference
            t2 = time.perf_counter()
            ml_prediction = self.ml_engine.predict(features)
            latency.ml_inference_ms = (time.perf_counter() - t2) * 1000
            
            result.ml_score = ml_prediction.confidence
            
            # ═══════════════════════════════════════════════════════════
            # ADAPTIVE LEARNING: Track when ML misses but other layers catch
            # ═══════════════════════════════════════════════════════════
            if ADAPTIVE_LEARNING_AVAILABLE:
                # Check if pattern/advanced caught something ML missed
                pattern_caught = any(d.source == DetectionSource.FAST_RULES for d in result.detections)
                ml_missed = not ml_prediction.is_malicious or ml_prediction.confidence < 0.5
                
                if pattern_caught and ml_missed:
                    # Record this for learning
                    sample = AttackSample(
                        timestamp=time.time(),
                        payload=f"{ctx.query_string} {ctx.body_str}"[:500],
                        path=ctx.path,
                        method=ctx.method,
                        headers=dict(ctx.headers),
                        detection_source="pattern" if result.detections else "advanced",
                        category=result.detections[0].category if result.detections else "UNKNOWN",
                        confidence=result.detections[0].confidence if result.detections else 0.5,
                        client_ip=ctx.client_ip,
                    )
                    adaptive_learner.record_ml_miss(
                        sample, 
                        ml_prediction.confidence,
                        caught_by="pattern_engine"
                    )
                
                # Update reputation tracker
                if result.action >= Action.BLOCK:
                    reputation_tracker.record_attack(
                        ctx.client_ip,
                        result.detections[0].category if result.detections else "UNKNOWN",
                        severity=ml_prediction.confidence if ml_prediction.is_malicious else 0.7
                    )
                elif len(session.unique_paths) > 20:
                    # Possible scanning behavior
                    reputation_tracker.record_probe(
                        ctx.client_ip,
                        ctx.path,
                        ctx.headers.get('user-agent', '')
                    )
                
                # Adjust ML threshold based on reputation
                if ml_prediction.is_malicious:
                    adjusted_threshold = reputation_tracker.get_adjusted_threshold(
                        ctx.client_ip, 0.5
                    )
                    if ml_prediction.confidence >= adjusted_threshold:
                        # Use the adjusted (potentially lower) threshold
                        pass  # Keep the detection
            
            # Add ML detection if attack predicted
            if ml_prediction.is_malicious and ml_prediction.confidence > 0.7:
                # Find highest probability attack type
                attack_type = max(
                    ml_prediction.attack_probabilities.items(),
                    key=lambda x: x[1] if x[0] != 'NORMAL' else 0
                )[0]
                
                result.add_detection(Detection(
                    source=DetectionSource.ML_MODEL,
                    category=attack_type,
                    confidence=ml_prediction.confidence,
                    metadata={'probabilities': ml_prediction.attack_probabilities}
                ))
                
                # ═══════════════════════════════════════════════════════════
                # KEY DIFFERENCE FROM PATTERN ENGINE:
                # Pattern Engine (known attacks) → BLOCK with 403
                # ML Model (new attacks) → HONEYPOT to gather intel
                # ═══════════════════════════════════════════════════════════
                
                # Only use HONEYPOT if Pattern Engine didn't already catch it
                pattern_already_caught = any(
                    d.source == DetectionSource.FAST_RULES for d in result.detections
                )
                
                if not pattern_already_caught:
                    # ML caught something Pattern missed → HONEYPOT + Learn
                    result.action = Action.HONEYPOT
                    session.in_honeypot = True
                    
                    # Route to honeypot
                    if HONEYPOT_AVAILABLE and self.honeypot_router:
                        self.route_to_honeypot(ctx, result, session)
                    
                    # Generate rule so next time Pattern Engine catches it
                    if RULE_GENERATOR_AVAILABLE and self.rule_generator:
                        new_rule = self.rule_generator.record_ml_detection(
                            payload=f"{ctx.query_string} {ctx.body_str}",
                            category=attack_type,
                            confidence=ml_prediction.confidence,
                            path=ctx.path,
                            method=ctx.method,
                        )
                        if new_rule:
                            logger.info(f"Auto-generated rule: {new_rule.rule_id} for {attack_type}")
                            # Add to pattern engine dynamically
                            if hasattr(self.pattern_engine, 'add_dynamic_rule'):
                                self.pattern_engine.add_dynamic_rule(
                                    new_rule.rule_id,
                                    new_rule.pattern,
                                    new_rule.category,
                                    new_rule.confidence
                                )
                else:
                    # Pattern already caught it, just upgrade to BLOCK if needed
                    if ml_prediction.confidence > 0.9:
                        result.action = max(result.action, Action.BLOCK)
            
            # Zero-day detection
            t3 = time.perf_counter()
            zd_detection = self.zero_day_detector.analyze(
                ctx, features, result.detections
            )
            latency.zero_day_ms = (time.perf_counter() - t3) * 1000
            
            if zd_detection:
                result.add_detection(zd_detection)
                result.is_zero_day = True
                result.zero_day_signature = zd_detection.metadata.get('signature_id')
                
                # ═══════════════════════════════════════════════════════════
                # ZERO-DAY: Novel anomaly detected → HONEYPOT + Learn
                # Same logic as ML detection - we want to study it
                # ═══════════════════════════════════════════════════════════
                pattern_already_caught = any(
                    d.source == DetectionSource.FAST_RULES for d in result.detections
                )
                
                if not pattern_already_caught:
                    result.action = Action.HONEYPOT
                    session.in_honeypot = True
                    
                    # Route to honeypot
                    if HONEYPOT_AVAILABLE and self.honeypot_router:
                        self.route_to_honeypot(ctx, result, session)
                    
                    # Generate rule from zero-day signature
                    if RULE_GENERATOR_AVAILABLE and self.rule_generator:
                        self.rule_generator.record_ml_detection(
                            payload=f"{ctx.query_string} {ctx.body_str}",
                            category=zd_detection.category,
                            confidence=zd_detection.confidence,
                            path=ctx.path,
                            method=ctx.method,
                        )
                else:
                    result.action = max(result.action, Action.BLOCK)
                
                with self.lock:
                    self.metrics['zero_days_detected'] += 1
            
            # Record attack for rate limiter adaptation
            if result.action >= Action.CHALLENGE:
                self.rate_limiter.record_attack(
                    self.rate_limiter.get_key(ctx.client_ip, ctx.path)
                )
            
            latency.total_async_ms = (time.perf_counter() - result.start_time) * 1000
            
            # Log async completion
            if settings.DEBUG:
                logger.debug(f"Async analysis complete: {latency.total_async_ms:.2f}ms")
                
        except Exception as e:
            logger.error(f"Async analysis error: {e}", exc_info=True)
    
    def _update_metrics(self, result: WAFResult):
        """Update WAF metrics"""
        with self.lock:
            self.metrics['total_requests'] += 1
            
            if result.action == Action.BLOCK:
                self.metrics['blocked_requests'] += 1
            elif result.action >= Action.CHALLENGE:
                self.metrics['suspicious_requests'] += 1
            
            # Track latency
            latency = result.latency_ms
            self.latency_samples.append(latency)
            
            if len(self.latency_samples) > self.max_latency_samples:
                self.latency_samples = self.latency_samples[-self.max_latency_samples:]
            
            # Update averages
            self.metrics['avg_latency_ms'] = sum(self.latency_samples) / len(self.latency_samples)
            
            # P99
            sorted_latencies = sorted(self.latency_samples)
            p99_idx = int(len(sorted_latencies) * 0.99)
            self.metrics['p99_latency_ms'] = sorted_latencies[p99_idx] if sorted_latencies else 0
    
    def get_metrics(self) -> Dict:
        """Get current WAF metrics"""
        with self.lock:
            return {
                **self.metrics.copy(),
                'ml_cache_hit_rate': self.ml_engine.cache_hit_rate,
                'ml_avg_latency_ms': self.ml_engine.avg_latency_ms,
                'session_count': len(self.session_manager.sessions),
                'zero_day_stats': self.zero_day_detector.get_stats(),
            }
    
    def get_health(self) -> Dict:
        """Get health status"""
        metrics = self.get_metrics()
        
        # Determine health status
        status = "healthy"
        issues = []
        
        if metrics['avg_latency_ms'] > LatencyBudget.NOTICEABLE:
            status = "degraded"
            issues.append(f"High latency: {metrics['avg_latency_ms']:.2f}ms")
        
        if metrics['p99_latency_ms'] > LatencyBudget.UNACCEPTABLE:
            status = "unhealthy"
            issues.append(f"P99 latency too high: {metrics['p99_latency_ms']:.2f}ms")
        
        block_rate = (
            metrics['blocked_requests'] / metrics['total_requests'] * 100
            if metrics['total_requests'] > 0 else 0
        )
        
        if block_rate > 50:
            status = "degraded"
            issues.append(f"High block rate: {block_rate:.1f}%")
        
        return {
            'status': status,
            'issues': issues,
            'metrics': metrics,
        }
    
    def _add_dynamic_rule(self, rule):
        """
        Callback from rule generator to add new rules to pattern engine
        This completes the feedback loop: ML → Rule → Pattern Engine
        """
        try:
            # Add to pattern engine's dynamic rules
            from core.pattern_engine import PatternRule
            
            new_rule = PatternRule(
                rule_id=rule.rule_id,
                pattern=rule.pattern,
                category=rule.category,
                severity=rule.severity,
                description=rule.description,
                locations=['query', 'body', 'path'],
            )
            
            # Add to pattern engine
            self.pattern_engine.add_dynamic_rule(new_rule)
            
            with self.lock:
                self.metrics['auto_generated_rules'] = self.metrics.get('auto_generated_rules', 0) + 1
            
            logger.info(f"Dynamic rule added: {rule.rule_id} - {rule.description}")
            
        except Exception as e:
            logger.error(f"Failed to add dynamic rule: {e}")
    
    def route_to_honeypot(self, ctx: RequestContext, result: WAFResult, session: SessionState):
        """
        Route suspicious request to honeypot
        Called when attack is detected with medium-high confidence
        
        Uses comprehensive honeypot for attack-specific responses:
        - SQL Injection: Fake database with canary credentials
        - XSS: Reflected payload with tracking
        - RCE: Fake shell output
        - SSRF: Fake cloud metadata
        - XXE: Fake entity expansion
        - SSTI: Fake template execution
        - NoSQL: Fake MongoDB response
        - JWT: Fake token acceptance
        - GraphQL: Fake introspection
        - And more...
        """
        # Prefer comprehensive honeypot
        if COMPREHENSIVE_HONEYPOT and comprehensive_honeypot:
            try:
                # Determine attack type from detections
                attack_type = 'default'
                if result.detections:
                    attack_type = result.detections[0].category.lower()
                
                # Generate attack-specific response
                honeypot_response = comprehensive_honeypot.generate_response(
                    ctx=ctx,
                    attack_type=attack_type,
                    result=result
                )
                
                with self.lock:
                    self.metrics['honeypot_sessions'] = self.metrics.get('honeypot_sessions', 0) + 1
                
                logger.info(f"Honeypot engaged for {attack_type} attack from {ctx.client_ip}")
                return honeypot_response
                
            except Exception as e:
                logger.error(f"Comprehensive honeypot failed: {e}")
        
        # Fallback to old honeypot router
        if self.honeypot_router:
            try:
                honeypot_response = self.honeypot_router.route_request(
                    ctx=ctx,
                    attack_category=result.detections[0].category if result.detections else "UNKNOWN",
                    confidence=result.detections[0].confidence if result.detections else 0.5,
                )
                
                with self.lock:
                    self.metrics['honeypot_sessions'] = self.metrics.get('honeypot_sessions', 0) + 1
                
                return honeypot_response
                
            except Exception as e:
                logger.error(f"Honeypot routing failed: {e}")
        
        return None
    
    def trigger_rule_generation(self, ctx: RequestContext, result: WAFResult, ml_prediction):
        """
        Trigger rule generation from ML detection
        This is the KEY feedback loop
        """
        if not self.rule_generator:
            return
        
        try:
            payload = f"{ctx.query_string} {ctx.body_str}"
            
            # Find the detected category
            if result.detections:
                category = result.detections[0].category
            elif ml_prediction and ml_prediction.attack_probabilities:
                # Get highest probability attack type
                probs = ml_prediction.attack_probabilities
                category = max(
                    (k for k in probs if k != "NORMAL"),
                    key=lambda k: probs[k],
                    default="UNKNOWN"
                )
            else:
                category = "UNKNOWN"
            
            # Generate rule
            new_rule = self.rule_generator.on_ml_detection(
                payload=payload,
                category=category,
                confidence=ml_prediction.confidence if ml_prediction else 0.8,
                client_ip=ctx.client_ip,
                request_context={
                    "path": ctx.path,
                    "method": ctx.method,
                }
            )
            
            if new_rule:
                logger.info(f"🔧 Auto-generated rule from ML detection: {new_rule.rule_id}")
                
        except Exception as e:
            logger.error(f"Rule generation failed: {e}")

# Global WAF engine instance
waf_engine = WAFEngine()

async def analyze_request_async(ctx: RequestContext,
                                 tls_info: Optional[Dict] = None) -> WAFResult:
    """
    Async wrapper for WAF analysis
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, 
        waf_engine.analyze_request, 
        ctx, 
        tls_info
    )
