"""
MIRAGE WAF Prometheus Metrics Exporter
Exports WAF metrics in Prometheus format
"""
import time
import threading
from typing import Dict, Optional
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Info,
        generate_latest, CONTENT_TYPE_LATEST,
        CollectorRegistry, REGISTRY
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Create custom registry
if PROMETHEUS_AVAILABLE:
    WAF_REGISTRY = CollectorRegistry()
else:
    WAF_REGISTRY = None

@dataclass
class MetricsCollector:
    """Collects and exports WAF metrics"""
    
    # Internal counters
    _requests_total: int = 0
    _requests_blocked: int = 0
    _requests_allowed: int = 0
    _requests_honeypot: int = 0
    _requests_throttled: int = 0
    
    _detections_by_category: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _latencies: list = field(default_factory=list)
    _latency_sum: float = 0
    _latency_count: int = 0
    
    _zero_days_detected: int = 0
    _rules_generated: int = 0
    _canaries_triggered: int = 0
    
    _active_sessions: int = 0
    _blocked_ips: int = 0
    
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        if PROMETHEUS_AVAILABLE:
            self._init_prometheus_metrics()
    
    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        # Request counters
        self.prom_requests_total = Counter(
            'waf_requests_total',
            'Total number of requests processed',
            ['action'],
            registry=WAF_REGISTRY
        )
        
        self.prom_detections = Counter(
            'waf_detections_total',
            'Total number of attack detections',
            ['category'],
            registry=WAF_REGISTRY
        )
        
        # Latency histogram
        self.prom_latency = Histogram(
            'waf_request_latency_seconds',
            'Request processing latency',
            buckets=[.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1.0],
            registry=WAF_REGISTRY
        )
        
        # Gauges
        self.prom_active_sessions = Gauge(
            'waf_active_sessions',
            'Number of active sessions',
            registry=WAF_REGISTRY
        )
        
        self.prom_blocked_ips = Gauge(
            'waf_blocked_ips',
            'Number of blocked IP addresses',
            registry=WAF_REGISTRY
        )
        
        self.prom_zero_days = Counter(
            'waf_zero_day_detections_total',
            'Total zero-day attacks detected',
            registry=WAF_REGISTRY
        )
        
        self.prom_rules_generated = Counter(
            'waf_rules_generated_total',
            'Total rules auto-generated',
            registry=WAF_REGISTRY
        )
        
        self.prom_canaries = Counter(
            'waf_canaries_triggered_total',
            'Total canary tokens triggered',
            registry=WAF_REGISTRY
        )
        
        # Info metric
        self.prom_info = Info(
            'waf',
            'WAF information',
            registry=WAF_REGISTRY
        )
        self.prom_info.info({
            'version': '1.0.0',
            'name': 'MIRAGE'
        })
    
    def record_request(self, action: str, latency_ms: float, 
                       detections: list = None, is_zero_day: bool = False):
        """Record a processed request"""
        with self._lock:
            self._requests_total += 1
            self._latency_sum += latency_ms
            self._latency_count += 1
            
            # Keep last 1000 latencies for percentile calculation
            self._latencies.append(latency_ms)
            if len(self._latencies) > 1000:
                self._latencies.pop(0)
            
            # Count by action
            if action == "BLOCK":
                self._requests_blocked += 1
            elif action == "ALLOW":
                self._requests_allowed += 1
            elif action == "HONEYPOT":
                self._requests_honeypot += 1
            elif action == "THROTTLE":
                self._requests_throttled += 1
            
            # Count detections
            if detections:
                for det in detections:
                    category = det.category if hasattr(det, 'category') else str(det)
                    self._detections_by_category[category] += 1
            
            # Zero-day
            if is_zero_day:
                self._zero_days_detected += 1
        
        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            self.prom_requests_total.labels(action=action).inc()
            self.prom_latency.observe(latency_ms / 1000.0)  # Convert to seconds
            
            if detections:
                for det in detections:
                    category = det.category if hasattr(det, 'category') else str(det)
                    self.prom_detections.labels(category=category).inc()
            
            if is_zero_day:
                self.prom_zero_days.inc()
    
    def record_rule_generated(self):
        """Record auto-generated rule"""
        with self._lock:
            self._rules_generated += 1
        if PROMETHEUS_AVAILABLE:
            self.prom_rules_generated.inc()
    
    def record_canary_triggered(self):
        """Record canary token triggered"""
        with self._lock:
            self._canaries_triggered += 1
        if PROMETHEUS_AVAILABLE:
            self.prom_canaries.inc()
    
    def set_active_sessions(self, count: int):
        """Set active session count"""
        with self._lock:
            self._active_sessions = count
        if PROMETHEUS_AVAILABLE:
            self.prom_active_sessions.set(count)
    
    def set_blocked_ips(self, count: int):
        """Set blocked IP count"""
        with self._lock:
            self._blocked_ips = count
        if PROMETHEUS_AVAILABLE:
            self.prom_blocked_ips.set(count)
    
    def get_metrics(self) -> Dict:
        """Get all metrics as dict"""
        with self._lock:
            avg_latency = self._latency_sum / self._latency_count if self._latency_count > 0 else 0
            
            # Calculate percentiles
            sorted_lat = sorted(self._latencies) if self._latencies else [0]
            p50 = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0
            p95 = sorted_lat[int(len(sorted_lat) * 0.95)] if len(sorted_lat) > 20 else 0
            p99 = sorted_lat[int(len(sorted_lat) * 0.99)] if len(sorted_lat) > 100 else 0
            
            return {
                "requests": {
                    "total": self._requests_total,
                    "blocked": self._requests_blocked,
                    "allowed": self._requests_allowed,
                    "honeypot": self._requests_honeypot,
                    "throttled": self._requests_throttled,
                },
                "detections": dict(self._detections_by_category),
                "latency": {
                    "avg_ms": avg_latency,
                    "p50_ms": p50,
                    "p95_ms": p95,
                    "p99_ms": p99,
                },
                "security": {
                    "zero_days_detected": self._zero_days_detected,
                    "rules_generated": self._rules_generated,
                    "canaries_triggered": self._canaries_triggered,
                },
                "sessions": {
                    "active": self._active_sessions,
                    "blocked_ips": self._blocked_ips,
                },
            }
    
    def get_prometheus_metrics(self) -> bytes:
        """Get metrics in Prometheus format"""
        if PROMETHEUS_AVAILABLE:
            return generate_latest(WAF_REGISTRY)
        else:
            # Generate simple text format
            metrics = self.get_metrics()
            lines = [
                f"# HELP waf_requests_total Total requests processed",
                f"# TYPE waf_requests_total counter",
                f"waf_requests_total{{action=\"BLOCK\"}} {metrics['requests']['blocked']}",
                f"waf_requests_total{{action=\"ALLOW\"}} {metrics['requests']['allowed']}",
                f"waf_requests_total{{action=\"HONEYPOT\"}} {metrics['requests']['honeypot']}",
                f"waf_requests_total{{action=\"THROTTLE\"}} {metrics['requests']['throttled']}",
                "",
                f"# HELP waf_latency_avg_ms Average latency in milliseconds",
                f"# TYPE waf_latency_avg_ms gauge",
                f"waf_latency_avg_ms {metrics['latency']['avg_ms']:.3f}",
                "",
                f"# HELP waf_active_sessions Number of active sessions",
                f"# TYPE waf_active_sessions gauge",
                f"waf_active_sessions {metrics['sessions']['active']}",
                "",
                f"# HELP waf_zero_days_total Zero-day attacks detected",
                f"# TYPE waf_zero_days_total counter",
                f"waf_zero_days_total {metrics['security']['zero_days_detected']}",
            ]
            return "\n".join(lines).encode()

# Global metrics collector
metrics_collector = MetricsCollector()


# FastAPI endpoint for metrics
def create_metrics_app():
    """Create FastAPI app for metrics endpoint"""
    from fastapi import FastAPI, Response
    
    app = FastAPI(title="MIRAGE Metrics")
    
    @app.get("/metrics")
    async def metrics():
        content = metrics_collector.get_prometheus_metrics()
        return Response(
            content=content,
            media_type="text/plain; version=0.0.4; charset=utf-8"
        )
    
    @app.get("/metrics/json")
    async def metrics_json():
        return metrics_collector.get_metrics()
    
    return app
