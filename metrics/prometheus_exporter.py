#!/usr/bin/env python3
"""
Prometheus Metrics Exporter for DECEPTICON WAF
Enterprise-grade metrics collection and export
"""

from prometheus_client import Counter, Histogram, Gauge, Summary, Info, start_http_server
from prometheus_client.core import CollectorRegistry, REGISTRY
import time
import threading
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import os
from pathlib import Path

@dataclass
class MetricSnapshot:
    """Snapshot of current metrics"""
    timestamp: datetime
    total_requests: int
    blocked_requests: int
    ml_predictions: int
    false_positives: int
    false_negatives: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_rps: float
    ml_accuracy: float

class WAFPrometheusExporter:
    """
    Enterprise-grade Prometheus metrics exporter for WAF

    Metrics Categories:
    1. Request Metrics (total, blocked, allowed)
    2. ML Performance (accuracy, latency, predictions)
    3. Attack Detection (by category, severity)
    4. False Positive/Negative Tracking
    5. System Performance (throughput, latency)
    6. Anomaly Detection (timeline, patterns)
    """

    def __init__(self, port: int = 9090, metrics_dir: str = "./data/metrics"):
        self.port = port
        self.metrics_dir = Path(metrics_dir)
        self.metrics_dir.mkdir(parents=True, exist_ok=True)

        # Registry
        self.registry = REGISTRY

        # Request Metrics
        self.requests_total = Counter(
            'waf_requests_total',
            'Total HTTP requests processed',
            ['method', 'status', 'blocked'],
            registry=self.registry
        )

        self.requests_blocked = Counter(
            'waf_requests_blocked_total',
            'Total requests blocked by WAF',
            ['attack_category', 'severity', 'source'],
            registry=self.registry
        )

        self.requests_allowed = Counter(
            'waf_requests_allowed_total',
            'Total requests allowed through WAF',
            ['path', 'method'],
            registry=self.registry
        )

        # ML Performance Metrics
        self.ml_predictions_total = Counter(
            'waf_ml_predictions_total',
            'Total ML model predictions',
            ['model_type', 'result'],
            registry=self.registry
        )

        self.ml_prediction_latency = Histogram(
            'waf_ml_prediction_latency_seconds',
            'ML model prediction latency in seconds',
            ['model_type'],
            buckets=(0.001, 0.0025, 0.005, 0.0075, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0),
            registry=self.registry
        )

        self.ml_accuracy = Gauge(
            'waf_ml_accuracy',
            'Current ML model accuracy (0-1)',
            ['model_type', 'category'],
            registry=self.registry
        )

        self.ml_confidence = Summary(
            'waf_ml_confidence',
            'ML prediction confidence scores',
            ['model_type', 'category'],
            registry=self.registry
        )

        # Attack Detection Metrics
        self.attacks_detected = Counter(
            'waf_attacks_detected_total',
            'Total attacks detected by category',
            ['category', 'severity', 'blocked'],
            registry=self.registry
        )

        self.attack_patterns = Counter(
            'waf_attack_patterns_total',
            'Attack patterns detected',
            ['pattern_type', 'signature'],
            registry=self.registry
        )

        # False Positive/Negative Tracking
        self.false_positives = Counter(
            'waf_false_positives_total',
            'False positive detections',
            ['category', 'corrected_by'],
            registry=self.registry
        )

        self.false_negatives = Counter(
            'waf_false_negatives_total',
            'False negative detections (missed attacks)',
            ['category', 'discovered_by'],
            registry=self.registry
        )

        self.false_positive_rate = Gauge(
            'waf_false_positive_rate',
            'Current false positive rate (0-1)',
            ['category'],
            registry=self.registry
        )

        # System Performance Metrics
        self.request_duration = Histogram(
            'waf_request_duration_seconds',
            'Total request processing duration',
            ['path', 'method', 'status'],
            buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            registry=self.registry
        )

        self.throughput = Gauge(
            'waf_throughput_rps',
            'Current throughput in requests per second',
            registry=self.registry
        )

        self.active_connections = Gauge(
            'waf_active_connections',
            'Number of active connections',
            registry=self.registry
        )

        # Anomaly Detection Metrics
        self.anomalies_detected = Counter(
            'waf_anomalies_detected_total',
            'Total anomalies detected',
            ['type', 'severity', 'source'],
            registry=self.registry
        )

        self.anomaly_score = Histogram(
            'waf_anomaly_score',
            'Anomaly scores from isolation forest',
            ['type'],
            buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
            registry=self.registry
        )

        self.zero_day_detections = Counter(
            'waf_zero_day_detections_total',
            'Potential zero-day attacks detected',
            ['pattern', 'confidence'],
            registry=self.registry
        )

        # Adaptive Learning Metrics
        self.model_updates = Counter(
            'waf_model_updates_total',
            'ML model update/retraining events',
            ['trigger', 'success'],
            registry=self.registry
        )

        self.rule_updates = Counter(
            'waf_rule_updates_total',
            'WAF rule updates',
            ['type', 'source', 'approved'],
            registry=self.registry
        )

        self.feedback_submissions = Counter(
            'waf_feedback_submissions_total',
            'Admin feedback submissions',
            ['type', 'category'],
            registry=self.registry
        )

        # Bot Detection Metrics
        self.bot_detections = Counter(
            'waf_bot_detections_total',
            'Bot vs human classifications',
            ['bot_type', 'confidence', 'blocked'],
            registry=self.registry
        )

        self.api_abuse_detections = Counter(
            'waf_api_abuse_detections_total',
            'API abuse patterns detected',
            ['abuse_type', 'severity'],
            registry=self.registry
        )

        # System Info
        self.waf_info = Info(
            'waf_system',
            'WAF system information',
            registry=self.registry
        )

        self.waf_info.info({
            'version': '2.0.0-secure',
            'security_score': '9.3',
            'ml_model': 'XGBoost + Isolation Forest',
            'deployment': 'production'
        })

        # Internal tracking
        self._request_times = []
        self._request_window = 60  # 60 second window for throughput
        self._lock = threading.Lock()

        # Start background tasks
        self._start_background_tasks()

    def record_request(self, method: str, status: int, blocked: bool, duration_ms: float,
                      path: str = "/", attack_category: Optional[str] = None,
                      severity: str = "medium", source: str = "unknown"):
        """Record a request with all relevant metrics"""

        # Request counters
        self.requests_total.labels(
            method=method,
            status=str(status),
            blocked=str(blocked)
        ).inc()

        if blocked:
            self.requests_blocked.labels(
                attack_category=attack_category or "unknown",
                severity=severity,
                source=source
            ).inc()
        else:
            self.requests_allowed.labels(
                path=path,
                method=method
            ).inc()

        # Request duration
        self.request_duration.labels(
            path=path,
            method=method,
            status=str(status)
        ).observe(duration_ms / 1000.0)

        # Track for throughput calculation
        with self._lock:
            current_time = time.time()
            self._request_times.append(current_time)
            # Remove old entries
            cutoff = current_time - self._request_window
            self._request_times = [t for t in self._request_times if t > cutoff]

    def record_ml_prediction(self, model_type: str, result: str, latency_ms: float,
                           confidence: float, category: str = "general"):
        """Record ML model prediction metrics"""

        self.ml_predictions_total.labels(
            model_type=model_type,
            result=result
        ).inc()

        self.ml_prediction_latency.labels(
            model_type=model_type
        ).observe(latency_ms / 1000.0)

        self.ml_confidence.labels(
            model_type=model_type,
            category=category
        ).observe(confidence)

    def record_attack(self, category: str, severity: str, blocked: bool,
                     pattern_type: Optional[str] = None, signature: Optional[str] = None):
        """Record detected attack"""

        self.attacks_detected.labels(
            category=category,
            severity=severity,
            blocked=str(blocked)
        ).inc()

        if pattern_type and signature:
            self.attack_patterns.labels(
                pattern_type=pattern_type,
                signature=signature[:50]  # Truncate long signatures
            ).inc()

    def record_false_positive(self, category: str, corrected_by: str = "admin"):
        """Record false positive detection"""
        self.false_positives.labels(
            category=category,
            corrected_by=corrected_by
        ).inc()

    def record_false_negative(self, category: str, discovered_by: str = "manual"):
        """Record false negative (missed attack)"""
        self.false_negatives.labels(
            category=category,
            discovered_by=discovered_by
        ).inc()

    def update_ml_accuracy(self, model_type: str, category: str, accuracy: float):
        """Update current ML accuracy gauge"""
        self.ml_accuracy.labels(
            model_type=model_type,
            category=category
        ).set(accuracy)

    def update_false_positive_rate(self, category: str, rate: float):
        """Update false positive rate gauge"""
        self.false_positive_rate.labels(category=category).set(rate)

    def record_anomaly(self, anomaly_type: str, severity: str, source: str,
                      score: float):
        """Record anomaly detection"""

        self.anomalies_detected.labels(
            type=anomaly_type,
            severity=severity,
            source=source
        ).inc()

        self.anomaly_score.labels(type=anomaly_type).observe(score)

    def record_zero_day(self, pattern: str, confidence: str):
        """Record potential zero-day detection"""
        self.zero_day_detections.labels(
            pattern=pattern[:50],
            confidence=confidence
        ).inc()

    def record_model_update(self, trigger: str, success: bool):
        """Record model update event"""
        self.model_updates.labels(
            trigger=trigger,
            success=str(success)
        ).inc()

    def record_rule_update(self, rule_type: str, source: str, approved: bool):
        """Record rule update event"""
        self.rule_updates.labels(
            type=rule_type,
            source=source,
            approved=str(approved)
        ).inc()

    def record_feedback(self, feedback_type: str, category: str):
        """Record admin feedback"""
        self.feedback_submissions.labels(
            type=feedback_type,
            category=category
        ).inc()

    def record_bot_detection(self, bot_type: str, confidence: str, blocked: bool):
        """Record bot detection"""
        self.bot_detections.labels(
            bot_type=bot_type,
            confidence=confidence,
            blocked=str(blocked)
        ).inc()

    def record_api_abuse(self, abuse_type: str, severity: str):
        """Record API abuse detection"""
        self.api_abuse_detections.labels(
            abuse_type=abuse_type,
            severity=severity
        ).inc()

    def update_active_connections(self, count: int):
        """Update active connections gauge"""
        self.active_connections.set(count)

    def _update_throughput(self):
        """Calculate and update throughput metric"""
        with self._lock:
            current_throughput = len(self._request_times) / self._request_window
            self.throughput.set(current_throughput)

    def _start_background_tasks(self):
        """Start background metric update tasks"""

        def throughput_updater():
            while True:
                time.sleep(5)  # Update every 5 seconds
                self._update_throughput()

        threading.Thread(target=throughput_updater, daemon=True).start()

    def get_snapshot(self) -> MetricSnapshot:
        """Get current metrics snapshot"""

        # Calculate metrics from prometheus data
        with self._lock:
            throughput = len(self._request_times) / self._request_window

        # This is a simplified snapshot - in production, parse actual prometheus data
        return MetricSnapshot(
            timestamp=datetime.now(),
            total_requests=0,  # Would query prometheus
            blocked_requests=0,
            ml_predictions=0,
            false_positives=0,
            false_negatives=0,
            avg_latency_ms=0.0,
            p95_latency_ms=0.0,
            p99_latency_ms=0.0,
            throughput_rps=throughput,
            ml_accuracy=0.0
        )

    def export_metrics(self) -> Dict[str, Any]:
        """Export all metrics as JSON"""

        snapshot = self.get_snapshot()

        metrics = {
            'timestamp': snapshot.timestamp.isoformat(),
            'system': {
                'throughput_rps': snapshot.throughput_rps,
                'active_connections': self.active_connections._value._value
            },
            'requests': {
                'total': snapshot.total_requests,
                'blocked': snapshot.blocked_requests,
                'allowed': snapshot.total_requests - snapshot.blocked_requests
            },
            'ml': {
                'predictions': snapshot.ml_predictions,
                'accuracy': snapshot.ml_accuracy,
                'avg_latency_ms': snapshot.avg_latency_ms
            },
            'quality': {
                'false_positives': snapshot.false_positives,
                'false_negatives': snapshot.false_negatives
            }
        }

        # Save to file
        export_file = self.metrics_dir / f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(export_file, 'w') as f:
            json.dump(metrics, f, indent=2)

        return metrics

    def start_server(self):
        """Start Prometheus HTTP server"""
        print(f"[METRICS] Starting Prometheus exporter on port {self.port}")
        start_http_server(self.port, registry=self.registry)
        print(f"[METRICS] Prometheus metrics available at http://localhost:{self.port}/metrics")


# Global instance
_exporter: Optional[WAFPrometheusExporter] = None

def get_exporter(port: int = 9090, metrics_dir: str = "./data/metrics") -> WAFPrometheusExporter:
    """Get global exporter instance"""
    global _exporter
    if _exporter is None:
        _exporter = WAFPrometheusExporter(port=port, metrics_dir=metrics_dir)
    return _exporter


if __name__ == "__main__":
    # Start exporter
    exporter = get_exporter(port=9090)
    exporter.start_server()

    print("\n=== DECEPTICON WAF Prometheus Exporter ===")
    print(f"Metrics endpoint: http://localhost:9090/metrics")
    print("\nAvailable metrics:")
    print("  - waf_requests_total")
    print("  - waf_requests_blocked_total")
    print("  - waf_ml_prediction_latency_seconds")
    print("  - waf_ml_accuracy")
    print("  - waf_attacks_detected_total")
    print("  - waf_false_positives_total")
    print("  - waf_anomalies_detected_total")
    print("  - waf_throughput_rps")
    print("  - And 20+ more metrics...")
    print("\nPress Ctrl+C to stop")

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[METRICS] Exporter stopped")
