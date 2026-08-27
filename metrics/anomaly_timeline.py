#!/usr/bin/env python3
"""
Anomaly Timeline Tracking System
Enterprise-grade time-series anomaly detection and tracking

Features:
- Real-time anomaly detection with time-series analysis
- Pattern correlation and clustering
- Anomaly severity scoring
- Historical trend analysis
- Attack campaign detection
- Automated alerting
"""

import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import numpy as np
from scipy import stats

@dataclass
class AnomalyEvent:
    """Individual anomaly event"""
    timestamp: datetime
    anomaly_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    anomaly_score: float
    source_ip: str
    endpoint: str
    payload: str
    detection_method: str
    confidence: float
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

@dataclass
class AttackCampaign:
    """Detected attack campaign (correlated anomalies)"""
    campaign_id: str
    start_time: datetime
    end_time: datetime
    event_count: int
    unique_sources: int
    target_endpoints: List[str]
    attack_types: List[str]
    severity: str
    status: str  # 'active', 'ended', 'investigated'

class AnomalyTimelineTracker:
    """
    Track anomalies over time with pattern detection
    Provides time-series analysis and correlation
    """

    def __init__(self, data_dir: str = './data/metrics'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Time-series storage (last 24 hours)
        self.timeline = deque(maxlen=100000)

        # Aggregated metrics by time window
        self.windows = {
            '1m': deque(maxlen=1440),   # Last 24 hours at 1-minute resolution
            '5m': deque(maxlen=288),    # Last 24 hours at 5-minute resolution
            '1h': deque(maxlen=168)     # Last week at 1-hour resolution
        }

        # Attack campaign detection
        self.active_campaigns = {}
        self.campaign_counter = 0

        # Baseline statistics
        self.baseline_stats = {
            'hourly_normal_rate': 10.0,  # Normal anomalies per hour
            'hourly_std': 5.0
        }

        # Pattern clustering
        self.pattern_clusters = defaultdict(list)

    def record_anomaly(self, event: AnomalyEvent):
        """Record an anomaly event"""

        self.timeline.append(event)

        # Update time windows
        self._update_windows(event)

        # Check for attack campaigns
        self._detect_campaigns(event)

        # Update pattern clusters
        self._update_patterns(event)

        # Save to disk periodically
        if len(self.timeline) % 100 == 0:
            self._save_timeline()

    def _update_windows(self, event: AnomalyEvent):
        """Update aggregated time windows"""

        current_time = event.timestamp

        # Update 1-minute window
        if not self.windows['1m'] or \
           (current_time - self.windows['1m'][-1]['timestamp']).total_seconds() >= 60:

            self.windows['1m'].append({
                'timestamp': current_time,
                'count': 1,
                'severity_counts': {event.severity: 1},
                'type_counts': {event.anomaly_type: 1}
            })
        else:
            # Increment current window
            window = self.windows['1m'][-1]
            window['count'] += 1
            window['severity_counts'][event.severity] = \
                window['severity_counts'].get(event.severity, 0) + 1
            window['type_counts'][event.anomaly_type] = \
                window['type_counts'].get(event.anomaly_type, 0) + 1

    def _detect_campaigns(self, event: AnomalyEvent):
        """Detect coordinated attack campaigns"""

        current_time = event.timestamp

        # Look for correlated events in last 5 minutes
        recent_events = [e for e in self.timeline
                        if (current_time - e.timestamp).total_seconds() < 300]

        # Group by source IP
        sources = defaultdict(list)
        for e in recent_events:
            sources[e.source_ip].append(e)

        # Check for campaign indicators
        # 1. Same source, multiple endpoints (scanning)
        # 2. Multiple sources, same endpoint (coordinated)
        # 3. Same attack type, burst pattern

        # Same source, multiple endpoints
        for source_ip, events in sources.items():
            unique_endpoints = set(e.endpoint for e in events)

            if len(events) > 10 and len(unique_endpoints) > 5:
                # Potential scanning campaign
                campaign_id = f"scan_{source_ip}_{int(current_time.timestamp())}"

                if campaign_id not in self.active_campaigns:
                    self.active_campaigns[campaign_id] = AttackCampaign(
                        campaign_id=campaign_id,
                        start_time=min(e.timestamp for e in events),
                        end_time=max(e.timestamp for e in events),
                        event_count=len(events),
                        unique_sources=1,
                        target_endpoints=list(unique_endpoints),
                        attack_types=list(set(e.anomaly_type for e in events)),
                        severity='high',
                        status='active'
                    )

        # Multiple sources, same endpoint (DDoS-like)
        endpoints = defaultdict(set)
        for e in recent_events:
            endpoints[e.endpoint].add(e.source_ip)

        for endpoint, sources_set in endpoints.items():
            if len(sources_set) > 20:
                # Potential DDoS or coordinated attack
                campaign_id = f"ddos_{endpoint}_{int(current_time.timestamp())}"

                if campaign_id not in self.active_campaigns:
                    self.active_campaigns[campaign_id] = AttackCampaign(
                        campaign_id=campaign_id,
                        start_time=current_time - timedelta(minutes=5),
                        end_time=current_time,
                        event_count=len([e for e in recent_events if e.endpoint == endpoint]),
                        unique_sources=len(sources_set),
                        target_endpoints=[endpoint],
                        attack_types=['ddos'],
                        severity='critical',
                        status='active'
                    )

    def _update_patterns(self, event: AnomalyEvent):
        """Update pattern clusters for correlation"""

        # Simple pattern: combination of attack type and endpoint
        pattern_key = f"{event.anomaly_type}:{event.endpoint}"

        self.pattern_clusters[pattern_key].append({
            'timestamp': event.timestamp,
            'source': event.source_ip,
            'score': event.anomaly_score
        })

        # Keep last 1000 events per pattern
        self.pattern_clusters[pattern_key] = \
            self.pattern_clusters[pattern_key][-1000:]

    def get_timeline(self, start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    limit: int = 1000) -> List[AnomalyEvent]:
        """Get anomaly timeline for time range"""

        if start_time is None:
            start_time = datetime.now() - timedelta(hours=24)
        if end_time is None:
            end_time = datetime.now()

        filtered = [e for e in self.timeline
                   if start_time <= e.timestamp <= end_time]

        return filtered[-limit:]

    def get_statistics(self, window: str = '1h') -> Dict:
        """Get anomaly statistics for a time window"""

        if window == '1h':
            # Last hour from timeline
            one_hour_ago = datetime.now() - timedelta(hours=1)
            events = [e for e in self.timeline if e.timestamp >= one_hour_ago]

        elif window == '24h':
            # Last 24 hours
            events = list(self.timeline)

        else:
            events = list(self.timeline)

        if not events:
            return {
                'total_anomalies': 0,
                'severity_breakdown': {},
                'type_breakdown': {},
                'top_sources': [],
                'top_endpoints': []
            }

        # Severity breakdown
        severity_counts = defaultdict(int)
        for e in events:
            severity_counts[e.severity] += 1

        # Type breakdown
        type_counts = defaultdict(int)
        for e in events:
            type_counts[e.anomaly_type] += 1

        # Top sources
        source_counts = defaultdict(int)
        for e in events:
            source_counts[e.source_ip] += 1

        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Top endpoints
        endpoint_counts = defaultdict(int)
        for e in events:
            endpoint_counts[e.endpoint] += 1

        top_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            'total_anomalies': len(events),
            'severity_breakdown': dict(severity_counts),
            'type_breakdown': dict(type_counts),
            'top_sources': [{'ip': ip, 'count': count} for ip, count in top_sources],
            'top_endpoints': [{'endpoint': ep, 'count': count} for ep, count in top_endpoints],
            'time_range': {
                'start': min(e.timestamp for e in events).isoformat(),
                'end': max(e.timestamp for e in events).isoformat()
            }
        }

    def detect_anomaly_spike(self, threshold_multiplier: float = 3.0) -> Optional[Dict]:
        """
        Detect if current anomaly rate is abnormally high
        Uses statistical analysis on historical baseline
        """

        if len(self.windows['1m']) < 60:
            return None  # Insufficient data

        # Get last hour's anomaly counts
        recent_counts = [w['count'] for w in list(self.windows['1m'])[-60:]]

        # Current rate (last 5 minutes)
        current_rate = sum([w['count'] for w in list(self.windows['1m'])[-5:]]) / 5

        # Historical baseline (1 hour ago to 2 hours ago)
        if len(self.windows['1m']) >= 120:
            baseline_counts = [w['count'] for w in list(self.windows['1m'])[-120:-60]]
            baseline_mean = np.mean(baseline_counts)
            baseline_std = np.std(baseline_counts)

            # Check if current rate is anomalous
            if baseline_std > 0:
                z_score = (current_rate - baseline_mean) / baseline_std

                if z_score > threshold_multiplier:
                    return {
                        'alert': 'anomaly_spike',
                        'current_rate': current_rate,
                        'baseline_mean': baseline_mean,
                        'baseline_std': baseline_std,
                        'z_score': z_score,
                        'severity': 'critical' if z_score > 5 else 'high',
                        'message': f'Anomaly rate {z_score:.1f}σ above baseline'
                    }

        return None

    def get_active_campaigns(self) -> List[AttackCampaign]:
        """Get currently active attack campaigns"""

        # Clean up old campaigns
        current_time = datetime.now()

        for campaign_id, campaign in list(self.active_campaigns.items()):
            if (current_time - campaign.end_time).total_seconds() > 600:
                # Campaign ended 10 minutes ago
                campaign.status = 'ended'
                del self.active_campaigns[campaign_id]

        return list(self.active_campaigns.values())

    def _save_timeline(self):
        """Save timeline to disk"""

        export_file = self.data_dir / f"anomaly_timeline_{datetime.now().strftime('%Y%m%d')}.jsonl"

        # Append events to JSONL file
        with open(export_file, 'a') as f:
            # Save last 100 events
            for event in list(self.timeline)[-100:]:
                f.write(json.dumps(event.to_dict()) + '\n')

    def export_report(self, filename: Optional[str] = None) -> str:
        """Export comprehensive anomaly report"""

        if filename is None:
            filename = f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': {
                'last_hour': self.get_statistics('1h'),
                'last_24h': self.get_statistics('24h')
            },
            'active_campaigns': [
                {
                    'campaign_id': c.campaign_id,
                    'start_time': c.start_time.isoformat(),
                    'end_time': c.end_time.isoformat(),
                    'event_count': c.event_count,
                    'unique_sources': c.unique_sources,
                    'target_endpoints': c.target_endpoints,
                    'attack_types': c.attack_types,
                    'severity': c.severity,
                    'status': c.status
                }
                for c in self.get_active_campaigns()
            ],
            'spike_detection': self.detect_anomaly_spike()
        }

        export_path = self.data_dir / filename

        with open(export_path, 'w') as f:
            json.dump(report, f, indent=2)

        return str(export_path)


if __name__ == "__main__":
    print("=== ANOMALY TIMELINE TRACKER TEST ===\n")

    tracker = AnomalyTimelineTracker()

    # Simulate anomaly events
    print("Simulating anomaly events...\n")

    attack_types = ['sqli', 'xss', 'rce', 'path_traversal', 'ssrf']
    endpoints = ['/api/login', '/api/users', '/api/data', '/api/admin']
    sources = [f'192.168.1.{i}' for i in range(1, 50)]

    # Normal baseline (10 anomalies)
    for i in range(10):
        event = AnomalyEvent(
            timestamp=datetime.now() - timedelta(minutes=30-i),
            anomaly_type=np.random.choice(attack_types),
            severity='low',
            anomaly_score=0.6,
            source_ip=np.random.choice(sources),
            endpoint=np.random.choice(endpoints),
            payload="test payload",
            detection_method="isolation_forest",
            confidence=0.7
        )
        tracker.record_anomaly(event)

    # Attack campaign simulation (burst of anomalies)
    print("Simulating attack campaign...\n")

    for i in range(50):
        event = AnomalyEvent(
            timestamp=datetime.now() - timedelta(minutes=5) + timedelta(seconds=i*2),
            anomaly_type='sqli',
            severity='high',
            anomaly_score=0.95,
            source_ip='192.168.1.100',
            endpoint=endpoints[i % len(endpoints)],
            payload="' OR 1=1--",
            detection_method="ml_model",
            confidence=0.95
        )
        tracker.record_anomaly(event)

    # Get statistics
    print("=== STATISTICS (Last Hour) ===")
    stats = tracker.get_statistics('1h')
    print(f"Total Anomalies: {stats['total_anomalies']}")
    print(f"Severity Breakdown: {stats['severity_breakdown']}")
    print(f"Type Breakdown: {stats['type_breakdown']}")
    print(f"\nTop Sources:")
    for source in stats['top_sources'][:5]:
        print(f"  {source['ip']}: {source['count']} anomalies")

    print(f"\nTop Endpoints:")
    for endpoint in stats['top_endpoints'][:5]:
        print(f"  {endpoint['endpoint']}: {endpoint['count']} anomalies")

    # Check for spikes
    print("\n=== ANOMALY SPIKE DETECTION ===")
    spike = tracker.detect_anomaly_spike(threshold_multiplier=2.0)
    if spike:
        print(f"⚠️ ALERT: {spike['alert'].upper()}")
        print(f"  Current Rate: {spike['current_rate']:.1f} anomalies/min")
        print(f"  Baseline: {spike['baseline_mean']:.1f} ± {spike['baseline_std']:.1f}")
        print(f"  Z-Score: {spike['z_score']:.2f}")
        print(f"  Severity: {spike['severity'].upper()}")
    else:
        print("✓ No anomaly spikes detected")

    # Active campaigns
    print("\n=== ACTIVE ATTACK CAMPAIGNS ===")
    campaigns = tracker.get_active_campaigns()

    if campaigns:
        for campaign in campaigns:
            print(f"\nCampaign: {campaign.campaign_id}")
            print(f"  Events: {campaign.event_count}")
            print(f"  Sources: {campaign.unique_sources}")
            print(f"  Targets: {', '.join(campaign.target_endpoints)}")
            print(f"  Attack Types: {', '.join(campaign.attack_types)}")
            print(f"  Severity: {campaign.severity.upper()}")
    else:
        print("No active campaigns detected")

    # Export report
    print("\n=== EXPORTING REPORT ===")
    report_path = tracker.export_report()
    print(f"Report saved: {report_path}")

    print("\nAnomaly timeline tracker ready!")
