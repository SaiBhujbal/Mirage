#!/usr/bin/env python3
"""
False Positive Monitoring and Feedback System
Enterprise-grade FP tracking with automated model improvement

Features:
- Real-time FP rate monitoring
- Automated feedback loop for model retraining
- Pattern analysis of false positives
- Category-specific FP tracking
- Admin review workflow
- Automated rule refinement
"""

import json
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import hashlib

@dataclass
class FalsePositiveReport:
    """False positive report from admin/user"""
    report_id: str
    timestamp: datetime
    payload: str
    detected_category: str
    actual_category: str  # 'benign' or actual attack type
    confidence: float
    source_ip: str
    endpoint: str
    reported_by: str  # 'admin', 'user', 'automated'
    status: str  # 'pending', 'confirmed', 'rejected', 'fixed'
    notes: str = ""
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

@dataclass
class FalseNegativeReport:
    """False negative report (missed attack)"""
    report_id: str
    timestamp: datetime
    payload: str
    actual_category: str
    missed_by: str  # Which detection method missed it
    severity: str
    discovered_by: str  # 'admin', 'honeypot', 'external_report'
    impact: str  # Description of impact
    status: str  # 'pending', 'confirmed', 'fixed'
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

class FalsePositiveMonitor:
    """
    Monitor and track false positives with automated feedback
    Provides insights for model improvement
    """

    def __init__(self, data_dir: str = './data/metrics'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # FP/FN storage
        self.false_positives = deque(maxlen=10000)
        self.false_negatives = deque(maxlen=10000)

        # Counters
        self.fp_counter = 0
        self.fn_counter = 0

        # Category-specific statistics
        self.category_stats = defaultdict(lambda: {
            'total_detections': 0,
            'false_positives': 0,
            'true_positives': 0,
            'false_negatives': 0
        })

        # Pattern analysis
        self.fp_patterns = defaultdict(list)  # Common FP patterns

        # Retraining triggers
        self.retraining_thresholds = {
            'fp_rate': 0.05,  # 5% FP rate triggers retraining
            'fp_count': 100,   # 100 FPs trigger retraining
            'fn_count': 10     # 10 FNs trigger urgent retraining
        }

        self.last_retrain = datetime.now()

    def report_false_positive(self, payload: str, detected_category: str,
                             actual_category: str = 'benign',
                             confidence: float = 0.0,
                             source_ip: str = 'unknown',
                             endpoint: str = '/',
                             reported_by: str = 'admin',
                             notes: str = "") -> FalsePositiveReport:
        """Report a false positive"""

        self.fp_counter += 1

        report = FalsePositiveReport(
            report_id=f"FP-{self.fp_counter:06d}",
            timestamp=datetime.now(),
            payload=payload,
            detected_category=detected_category,
            actual_category=actual_category,
            confidence=confidence,
            source_ip=source_ip,
            endpoint=endpoint,
            reported_by=reported_by,
            status='pending',
            notes=notes
        )

        self.false_positives.append(report)

        # Update category statistics
        self.category_stats[detected_category]['false_positives'] += 1

        # Pattern analysis
        self._analyze_fp_pattern(report)

        # Check retraining triggers
        self._check_retraining_triggers()

        # Save to disk
        self._save_report(report)

        return report

    def report_false_negative(self, payload: str, actual_category: str,
                            missed_by: str = 'ml_model',
                            severity: str = 'high',
                            discovered_by: str = 'admin',
                            impact: str = "") -> FalseNegativeReport:
        """Report a false negative (missed attack)"""

        self.fn_counter += 1

        report = FalseNegativeReport(
            report_id=f"FN-{self.fn_counter:06d}",
            timestamp=datetime.now(),
            payload=payload,
            actual_category=actual_category,
            missed_by=missed_by,
            severity=severity,
            discovered_by=discovered_by,
            impact=impact,
            status='pending'
        )

        self.false_negatives.append(report)

        # Update category statistics
        self.category_stats[actual_category]['false_negatives'] += 1

        # URGENT: False negatives are critical
        print(f"⚠️ CRITICAL: False Negative Detected - {report.report_id}")
        print(f"   Category: {actual_category}, Severity: {severity}")
        print(f"   Payload: {payload[:100]}...")

        # Check retraining triggers (FNs are high priority)
        self._check_retraining_triggers()

        # Save to disk
        self._save_report(report)

        return report

    def record_detection(self, category: str, is_true_positive: bool):
        """Record a detection result for statistics"""

        self.category_stats[category]['total_detections'] += 1

        if is_true_positive:
            self.category_stats[category]['true_positives'] += 1

    def get_fp_rate(self, category: Optional[str] = None,
                   time_window: Optional[timedelta] = None) -> float:
        """
        Calculate false positive rate

        Args:
            category: Specific category or None for overall
            time_window: Time window or None for all time

        Returns:
            FP rate (0-1)
        """

        if time_window:
            cutoff = datetime.now() - time_window
            fps = [fp for fp in self.false_positives if fp.timestamp >= cutoff]
        else:
            fps = list(self.false_positives)

        if category:
            fps = [fp for fp in fps if fp.detected_category == category]
            stats = self.category_stats[category]
            total = stats['total_detections']
        else:
            total = sum(s['total_detections'] for s in self.category_stats.values())

        if total == 0:
            return 0.0

        return len(fps) / total

    def get_fn_rate(self, category: Optional[str] = None) -> float:
        """Calculate false negative rate"""

        if category:
            stats = self.category_stats[category]
            fn_count = stats['false_negatives']
            total = stats['true_positives'] + fn_count
        else:
            fn_count = sum(s['false_negatives'] for s in self.category_stats.values())
            total = sum(s['true_positives'] + s['false_negatives']
                       for s in self.category_stats.values())

        if total == 0:
            return 0.0

        return fn_count / total

    def get_statistics(self, time_window: Optional[timedelta] = None) -> Dict:
        """Get comprehensive FP/FN statistics"""

        if time_window:
            cutoff = datetime.now() - time_window
            fps = [fp for fp in self.false_positives if fp.timestamp >= cutoff]
            fns = [fn for fn in self.false_negatives if fn.timestamp >= cutoff]
        else:
            fps = list(self.false_positives)
            fns = list(self.false_negatives)

        # Overall rates
        overall_fp_rate = self.get_fp_rate(time_window=time_window)
        overall_fn_rate = self.get_fn_rate()

        # Category breakdown
        category_breakdown = {}

        for category, stats in self.category_stats.items():
            total = stats['total_detections']
            if total > 0:
                category_breakdown[category] = {
                    'total_detections': total,
                    'true_positives': stats['true_positives'],
                    'false_positives': stats['false_positives'],
                    'false_negatives': stats['false_negatives'],
                    'fp_rate': stats['false_positives'] / total,
                    'precision': stats['true_positives'] / (stats['true_positives'] + stats['false_positives'])
                                if (stats['true_positives'] + stats['false_positives']) > 0 else 0.0,
                    'recall': stats['true_positives'] / (stats['true_positives'] + stats['false_negatives'])
                             if (stats['true_positives'] + stats['false_negatives']) > 0 else 0.0
                }

        # Common FP patterns
        fp_pattern_summary = {}
        for pattern, occurrences in list(self.fp_patterns.items())[:10]:
            fp_pattern_summary[pattern] = len(occurrences)

        # Reporting sources
        fp_sources = defaultdict(int)
        for fp in fps:
            fp_sources[fp.reported_by] += 1

        return {
            'summary': {
                'total_fps': len(fps),
                'total_fns': len(fns),
                'overall_fp_rate': overall_fp_rate,
                'overall_fn_rate': overall_fn_rate,
                'pending_fps': len([fp for fp in fps if fp.status == 'pending']),
                'pending_fns': len([fn for fn in fns if fn.status == 'pending'])
            },
            'category_breakdown': category_breakdown,
            'fp_patterns': fp_pattern_summary,
            'reporting_sources': dict(fp_sources),
            'time_range': {
                'start': min(fp.timestamp for fp in fps).isoformat() if fps else None,
                'end': max(fp.timestamp for fp in fps).isoformat() if fps else None
            }
        }

    def _analyze_fp_pattern(self, report: FalsePositiveReport):
        """Analyze FP for common patterns"""

        payload = report.payload.lower()

        # Extract pattern signature
        # This helps identify systematic FPs

        # Check for common benign patterns
        benign_patterns = {
            'email': r'@.*\.com|\.edu|\.org',
            'url': r'https?://',
            'json': r'\{.*:.*\}',
            'xml': r'<\w+>.*</\w+>',
            'sql_benign': r'SELECT.*FROM.*WHERE',  # Legitimate SQL in code
        }

        import re
        pattern_type = 'unknown'

        for pattern_name, pattern_regex in benign_patterns.items():
            if re.search(pattern_regex, payload, re.IGNORECASE):
                pattern_type = pattern_name
                break

        # Add to pattern tracking
        pattern_key = f"{report.detected_category}:{pattern_type}"
        self.fp_patterns[pattern_key].append({
            'payload': payload[:100],
            'timestamp': report.timestamp,
            'confidence': report.confidence
        })

    def _check_retraining_triggers(self):
        """Check if model retraining should be triggered"""

        # Check FP rate
        fp_rate_1h = self.get_fp_rate(time_window=timedelta(hours=1))

        if fp_rate_1h > self.retraining_thresholds['fp_rate']:
            print(f"\n⚠️ RETRAINING TRIGGER: FP rate {fp_rate_1h:.2%} > {self.retraining_thresholds['fp_rate']:.2%}")
            self._trigger_retraining('high_fp_rate')
            return

        # Check FP count
        recent_fps = [fp for fp in self.false_positives
                     if (datetime.now() - fp.timestamp) < timedelta(hours=24)]

        if len(recent_fps) > self.retraining_thresholds['fp_count']:
            print(f"\n⚠️ RETRAINING TRIGGER: {len(recent_fps)} FPs in 24h > {self.retraining_thresholds['fp_count']}")
            self._trigger_retraining('fp_count_threshold')
            return

        # Check FN count (CRITICAL)
        recent_fns = [fn for fn in self.false_negatives
                     if (datetime.now() - fn.timestamp) < timedelta(hours=24)]

        if len(recent_fns) > self.retraining_thresholds['fn_count']:
            print(f"\n🚨 URGENT RETRAINING: {len(recent_fns)} FNs detected (CRITICAL)")
            self._trigger_retraining('false_negatives_critical')
            return

    def _trigger_retraining(self, reason: str):
        """Trigger model retraining"""

        # Check cooldown (don't retrain more than once per hour)
        if (datetime.now() - self.last_retrain) < timedelta(hours=1):
            print(f"   Retraining on cooldown (last retrain: {self.last_retrain})")
            return

        print(f"   Reason: {reason}")
        print(f"   Creating retraining dataset with FP/FN examples...")

        # Save retraining trigger
        trigger_file = self.data_dir / f"retrain_trigger_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        trigger_data = {
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'statistics': self.get_statistics(time_window=timedelta(hours=24)),
            'fp_examples': [fp.to_dict() for fp in list(self.false_positives)[-20:]],
            'fn_examples': [fn.to_dict() for fn in list(self.false_negatives)[-20:]]
        }

        with open(trigger_file, 'w') as f:
            json.dump(trigger_data, f, indent=2)

        print(f"   Retraining trigger saved: {trigger_file}")
        print(f"   Admin approval required for retraining")

        self.last_retrain = datetime.now()

    def _save_report(self, report):
        """Save FP/FN report to disk"""

        if isinstance(report, FalsePositiveReport):
            report_type = 'fp'
        else:
            report_type = 'fn'

        report_file = self.data_dir / f"{report_type}_reports_{datetime.now().strftime('%Y%m%d')}.jsonl"

        with open(report_file, 'a') as f:
            f.write(json.dumps(report.to_dict()) + '\n')

    def get_pending_reviews(self) -> Dict[str, List]:
        """Get pending FP/FN reports requiring admin review"""

        pending_fps = [fp for fp in self.false_positives if fp.status == 'pending']
        pending_fns = [fn for fn in self.false_negatives if fn.status == 'pending']

        return {
            'false_positives': [fp.to_dict() for fp in pending_fps],
            'false_negatives': [fn.to_dict() for fn in pending_fns],
            'total_pending': len(pending_fps) + len(pending_fns)
        }

    def update_report_status(self, report_id: str, new_status: str,
                            notes: str = "") -> bool:
        """Update FP/FN report status"""

        # Search in FPs
        for fp in self.false_positives:
            if fp.report_id == report_id:
                fp.status = new_status
                if notes:
                    fp.notes += f"\n[{datetime.now()}] {notes}"
                return True

        # Search in FNs
        for fn in self.false_negatives:
            if fn.report_id == report_id:
                fn.status = new_status
                return True

        return False

    def export_training_data(self, filename: Optional[str] = None) -> str:
        """Export FP/FN examples for model retraining"""

        if filename is None:
            filename = f"fp_fn_training_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Get confirmed FPs and FNs
        confirmed_fps = [fp for fp in self.false_positives if fp.status == 'confirmed']
        confirmed_fns = [fn for fn in self.false_negatives if fn.status == 'confirmed']

        training_data = {
            'generated_at': datetime.now().isoformat(),
            'false_positives': [
                {
                    'payload': fp.payload,
                    'detected_as': fp.detected_category,
                    'actual': fp.actual_category,
                    'label': 0  # Benign
                }
                for fp in confirmed_fps
            ],
            'false_negatives': [
                {
                    'payload': fn.payload,
                    'actual': fn.actual_category,
                    'label': 1  # Malicious
                }
                for fn in confirmed_fns
            ],
            'total_examples': len(confirmed_fps) + len(confirmed_fns)
        }

        export_path = self.data_dir / filename

        with open(export_path, 'w') as f:
            json.dump(training_data, f, indent=2)

        print(f"Training data exported: {export_path}")
        print(f"  FP examples: {len(confirmed_fps)}")
        print(f"  FN examples: {len(confirmed_fns)}")

        return str(export_path)


if __name__ == "__main__":
    print("=== FALSE POSITIVE MONITOR TEST ===\n")

    monitor = FalsePositiveMonitor()

    # Simulate detections and FPs
    print("Simulating detections...\n")

    # True positives
    for i in range(100):
        monitor.record_detection('sqli', is_true_positive=True)

    for i in range(80):
        monitor.record_detection('xss', is_true_positive=True)

    # False positives
    fp_examples = [
        ("SELECT * FROM users WHERE id = ?", "sqli", "benign", 0.85),
        ("<div>Hello World</div>", "xss", "benign", 0.72),
        ("email@example.com", "sqli", "benign", 0.68),
        ("https://example.com/api", "ssrf", "benign", 0.65),
    ]

    for payload, detected, actual, confidence in fp_examples:
        monitor.report_false_positive(
            payload=payload,
            detected_category=detected,
            actual_category=actual,
            confidence=confidence,
            reported_by='admin'
        )

    # False negative (CRITICAL)
    print("Simulating false negative...\n")
    monitor.report_false_negative(
        payload="'; DROP TABLE users;--",
        actual_category='sqli',
        severity='critical',
        discovered_by='manual_review',
        impact='Potential SQL injection attack not blocked'
    )

    # Get statistics
    print("\n=== STATISTICS ===")
    stats = monitor.get_statistics()

    print(f"Total FPs: {stats['summary']['total_fps']}")
    print(f"Total FNs: {stats['summary']['total_fns']}")
    print(f"Overall FP Rate: {stats['summary']['overall_fp_rate']:.2%}")
    print(f"Overall FN Rate: {stats['summary']['overall_fn_rate']:.2%}")

    print(f"\n=== CATEGORY BREAKDOWN ===")
    for category, breakdown in stats['category_breakdown'].items():
        print(f"\n{category.upper()}:")
        print(f"  Total Detections: {breakdown['total_detections']}")
        print(f"  True Positives: {breakdown['true_positives']}")
        print(f"  False Positives: {breakdown['false_positives']}")
        print(f"  FP Rate: {breakdown['fp_rate']:.2%}")
        print(f"  Precision: {breakdown['precision']:.2%}")
        print(f"  Recall: {breakdown['recall']:.2%}")

    # Pending reviews
    print("\n=== PENDING REVIEWS ===")
    pending = monitor.get_pending_reviews()
    print(f"Total Pending: {pending['total_pending']}")
    print(f"  FPs: {len(pending['false_positives'])}")
    print(f"  FNs: {len(pending['false_negatives'])}")

    # Export training data
    print("\n=== EXPORTING TRAINING DATA ===")
    # Confirm some reports first
    for fp in list(monitor.false_positives)[:2]:
        monitor.update_report_status(fp.report_id, 'confirmed')

    export_path = monitor.export_training_data()

    print("\nFalse positive monitor ready!")
