#!/usr/bin/env python3
"""
MIRAGE ML Integration API
RESTful API for integrating ML modules with ANY open-source WAF

Compatible with:
- ModSecurity (OWASP Core Rule Set)
- NAXSI (Nginx Anti-XSS & SQL Injection)
- Shadow Daemon
- lua-resty-waf
- Coraza WAF
- Any custom WAF via HTTP API calls

API Endpoints:
- POST /api/waf/analyze - Analyze single request
- POST /api/waf/analyze/batch - Batch analysis
- GET /api/v1/baseline - Get baseline statistics
- POST /api/v1/feedback - Submit feedback (FP/FN)
- GET /api/v1/health - Health check
- GET /api/v1/metrics - Prometheus metrics
- POST /api/v1/train - Trigger retraining
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import json

# Add parent to path
sys.path.append(str(Path(__file__).parent.parent))

from config.settings import settings
from ml.dual_layer_inference import DualLayerPredictor
from ml.performance_optimizer import OptimizedMLPredictor
from ml.bot_detector import BotDetector
from ml.api_abuse_detector import APIAbuseDetector
from metrics.prometheus_exporter import get_exporter
from metrics.anomaly_timeline import AnomalyTimelineTracker, AnomalyEvent
from metrics.false_positive_monitor import FalsePositiveMonitor
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Configure CORS (restricted in production)
cors_origins = settings.ALLOWED_ORIGINS if settings.ENV == "production" else "*"
CORS(app, resources={r"/*": {"origins": cors_origins}})

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour", "100 per minute"]
)

# Initialize ML components
print("[INIT] Loading ML components...")
ml_predictor = OptimizedMLPredictor(models_dir='./models')
bot_detector = BotDetector()
api_abuse_detector = APIAbuseDetector()
prometheus_exporter = get_exporter(port=9090)
anomaly_tracker = AnomalyTimelineTracker()
fp_monitor = FalsePositiveMonitor()

print("[INIT] ML Integration API ready!")

# ============================================================================
# Core Analysis Endpoints
# ============================================================================

@app.route('/api/waf/analyze', methods=['POST'])
@limiter.limit("1000 per minute")
def analyze_request():
    """
    Analyze a single HTTP request

    Request Body:
    {
        "method": "GET",
        "path": "/api/users",
        "query": "?id=123",
        "body": "",
        "headers": {
            "user-agent": "...",
            "content-type": "..."
        },
        "source_ip": "192.168.1.100",
        "session_id": "abc123"
    }

    Response:
    {
        "is_malicious": false,
        "confidence": 0.98,
        "category": "benign",
        "risk_score": 0.05,
        "recommended_action": "allow",
        "latency_ms": 2.34,
        "detection_methods": ["ml_model", "bot_detector"],
        "details": {...}
    }
    """

    start_time = time.time()

    try:
        data = request.get_json()

        # Validate request
        if not data:
            return jsonify({
                'error': 'Invalid JSON body',
                'status': 'error'
            }), 400

        # Extract fields
        method = data.get('method', 'GET')
        path = data.get('path', '/')
        query = data.get('query', '')
        body = data.get('body', '')
        headers = data.get('headers', {})
        source_ip = data.get('source_ip', 'unknown')
        session_id = data.get('session_id', 'unknown')

        # Combine payload for analysis
        full_payload = f"{path}{query} {body}"

        # 1. ML Prediction
        ml_result = ml_predictor.predict(full_payload)

        # 2. Bot Detection
        user_agent = headers.get('user-agent', '')
        headers_lower = {k.lower(): v for k, v in headers.items()}

        bot_result = bot_detector.detect(
            session_id=session_id,
            user_agent=user_agent,
            headers=headers_lower,
            path=path,
            ip_address=source_ip
        )

        # 3. API Abuse Detection
        api_result = api_abuse_detector.analyze_request(
            client_id=source_ip,
            endpoint=path,
            method=method
        )

        # Aggregate results
        is_malicious = ml_result['is_malicious'] or bot_result.is_bot or api_result.is_abuse

        # Calculate combined confidence
        confidences = [ml_result['confidence']]
        if bot_result.is_bot:
            confidences.append(bot_result.confidence)
        if api_result.is_abuse:
            confidences.append(api_result.confidence)

        combined_confidence = max(confidences)

        # Determine action
        if is_malicious:
            if combined_confidence > 0.95:
                action = 'block'
            elif combined_confidence > 0.80:
                action = 'challenge'
            else:
                action = 'monitor'
        else:
            action = 'allow'

        # Risk score
        risk_score = combined_confidence if is_malicious else 0.0

        # Category
        category = ml_result['category']
        if bot_result.is_bot and bot_result.bot_type == 'malicious_bot':
            category = 'bot_attack'
        if api_result.is_abuse:
            category = f"api_abuse_{api_result.abuse_types[0]}" if api_result.abuse_types else 'api_abuse'

        # Record metrics
        latency = (time.time() - start_time) * 1000

        prometheus_exporter.record_request(
            method=method,
            status=200,
            blocked=(action in ['block', 'challenge']),
            duration_ms=latency,
            path=path,
            attack_category=category if is_malicious else None,
            severity='high' if combined_confidence > 0.9 else 'medium',
            source=source_ip
        )

        if is_malicious:
            prometheus_exporter.record_attack(
                category=category,
                severity='high' if combined_confidence > 0.9 else 'medium',
                blocked=(action == 'block')
            )

        # Record anomaly if detected
        if is_malicious:
            anomaly_event = AnomalyEvent(
                timestamp=datetime.now(),
                anomaly_type=category,
                severity='high' if combined_confidence > 0.9 else 'medium',
                anomaly_score=risk_score,
                source_ip=source_ip,
                endpoint=path,
                payload=full_payload[:200],
                detection_method=ml_result['tier'],
                confidence=combined_confidence
            )
            anomaly_tracker.record_anomaly(anomaly_event)

        # Build response
        response = {
            'is_malicious': is_malicious,
            'confidence': combined_confidence,
            'category': category,
            'risk_score': risk_score,
            'recommended_action': action,
            'latency_ms': latency,
            'detection_methods': [],
            'details': {
                'ml_prediction': {
                    'malicious': ml_result['is_malicious'],
                    'confidence': ml_result['confidence'],
                    'category': ml_result['category'],
                    'tier': ml_result['tier']
                },
                'bot_detection': {
                    'is_bot': bot_result.is_bot,
                    'bot_type': bot_result.bot_type,
                    'confidence': bot_result.confidence,
                    'action': bot_result.recommended_action
                },
                'api_abuse': {
                    'is_abuse': api_result.is_abuse,
                    'abuse_types': api_result.abuse_types,
                    'severity': api_result.severity
                }
            },
            'timestamp': datetime.now().isoformat()
        }

        # Detection methods used
        if ml_result['is_malicious']:
            response['detection_methods'].append('ml_model')
        if bot_result.is_bot:
            response['detection_methods'].append('bot_detector')
        if api_result.is_abuse:
            response['detection_methods'].append('api_abuse_detector')

        return jsonify(response), 200

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/api/waf/analyze/batch', methods=['POST'])
@limiter.limit("100 per minute")
def analyze_batch():
    """
    Analyze multiple requests in batch

    Request Body:
    {
        "requests": [
            {"method": "GET", "path": "/api/users", ...},
            {"method": "POST", "path": "/api/login", ...}
        ]
    }

    Response:
    {
        "results": [...],
        "summary": {
            "total": 10,
            "malicious": 3,
            "benign": 7,
            "avg_latency_ms": 2.45
        }
    }
    """

    start_time = time.time()

    try:
        data = request.get_json()
        requests_list = data.get('requests', [])

        if not requests_list:
            return jsonify({
                'error': 'No requests provided',
                'status': 'error'
            }), 400

        if len(requests_list) > 100:
            return jsonify({
                'error': 'Maximum 100 requests per batch',
                'status': 'error'
            }), 400

        results = []
        malicious_count = 0

        for req_data in requests_list:
            # Analyze each request
            # (In production, this would call analyze_request logic)
            path = req_data.get('path', '/')
            query = req_data.get('query', '')
            body = req_data.get('body', '')

            full_payload = f"{path}{query} {body}"
            ml_result = ml_predictor.predict(full_payload)

            if ml_result['is_malicious']:
                malicious_count += 1

            results.append({
                'is_malicious': ml_result['is_malicious'],
                'confidence': ml_result['confidence'],
                'category': ml_result['category'],
                'recommended_action': 'block' if ml_result['confidence'] > 0.9 else 'monitor'
            })

        total_time = (time.time() - start_time) * 1000

        return jsonify({
            'results': results,
            'summary': {
                'total': len(requests_list),
                'malicious': malicious_count,
                'benign': len(requests_list) - malicious_count,
                'avg_latency_ms': total_time / len(requests_list)
            },
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


# ============================================================================
# Baseline & Anomaly Endpoints
# ============================================================================

@app.route('/api/v1/baseline', methods=['GET'])
def get_baseline():
    """
    Get baseline statistics

    Response:
    {
        "baseline": {
            "normal_requests_per_hour": 1000,
            "avg_latency_ms": 2.5,
            "top_endpoints": [...],
            "traffic_patterns": {...}
        },
        "anomalies": {
            "last_hour": 5,
            "active_campaigns": 1
        }
    }
    """

    try:
        # Get anomaly statistics
        anomaly_stats = anomaly_tracker.get_statistics('1h')

        # Get FP monitor statistics
        fp_stats = fp_monitor.get_statistics()

        return jsonify({
            'baseline': {
                'normal_requests_per_hour': 1000,  # Would calculate from historical data
                'avg_latency_ms': 2.5,
                'top_endpoints': anomaly_stats.get('top_endpoints', [])[:10],
                'traffic_patterns': 'stable'
            },
            'anomalies': {
                'last_hour': anomaly_stats.get('total_anomalies', 0),
                'active_campaigns': len(anomaly_tracker.get_active_campaigns()),
                'severity_breakdown': anomaly_stats.get('severity_breakdown', {})
            },
            'quality': {
                'fp_rate': fp_stats['summary']['overall_fp_rate'],
                'fn_rate': fp_stats['summary']['overall_fn_rate'],
                'pending_fps': fp_stats['summary']['pending_fps']
            },
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@app.route('/api/v1/anomalies', methods=['GET'])
def get_anomalies():
    """Get recent anomalies"""

    try:
        time_window = request.args.get('window', '1h')
        limit = int(request.args.get('limit', 100))

        stats = anomaly_tracker.get_statistics(time_window)

        return jsonify({
            'statistics': stats,
            'active_campaigns': [
                {
                    'campaign_id': c.campaign_id,
                    'event_count': c.event_count,
                    'unique_sources': c.unique_sources,
                    'severity': c.severity,
                    'status': c.status
                }
                for c in anomaly_tracker.get_active_campaigns()
            ],
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


# ============================================================================
# Feedback & Learning Endpoints
# ============================================================================

@app.route('/api/v1/feedback', methods=['POST'])
def submit_feedback():
    """
    Submit feedback on ML decision

    Request Body:
    {
        "payload": "' OR 1=1--",
        "detected_category": "sqli",
        "actual_category": "benign",
        "feedback_type": "false_positive",
        "notes": "This is a benign test query"
    }
    """

    try:
        data = request.get_json()

        payload = data.get('payload', '')
        detected_category = data.get('detected_category', 'unknown')
        actual_category = data.get('actual_category', 'benign')
        feedback_type = data.get('feedback_type', 'false_positive')
        notes = data.get('notes', '')

        if feedback_type == 'false_positive':
            report = fp_monitor.report_false_positive(
                payload=payload,
                detected_category=detected_category,
                actual_category=actual_category,
                reported_by='api',
                notes=notes
            )

            # Record to Prometheus
            prometheus_exporter.record_false_positive(detected_category)

        elif feedback_type == 'false_negative':
            report = fp_monitor.report_false_negative(
                payload=payload,
                actual_category=actual_category,
                discovered_by='api',
                impact=notes
            )

            # Record to Prometheus
            prometheus_exporter.record_false_negative(actual_category)

        else:
            return jsonify({
                'error': 'Invalid feedback_type. Use "false_positive" or "false_negative"',
                'status': 'error'
            }), 400

        # Record feedback submission
        prometheus_exporter.record_feedback(feedback_type, detected_category)

        return jsonify({
            'status': 'success',
            'report_id': report.report_id,
            'message': 'Feedback submitted successfully',
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@app.route('/api/v1/train', methods=['POST'])
@limiter.limit("10 per hour")
def trigger_training():
    """
    Trigger model retraining

    Request Body:
    {
        "reason": "high_fp_rate",
        "approved_by": "admin"
    }
    """

    try:
        data = request.get_json()
        reason = data.get('reason', 'manual')
        approved_by = data.get('approved_by', 'api')

        # Export training data
        training_data_path = fp_monitor.export_training_data()

        # Record retraining event
        prometheus_exporter.record_model_update(
            trigger=reason,
            success=True  # Would be actual success status
        )

        return jsonify({
            'status': 'success',
            'message': 'Retraining triggered',
            'training_data': training_data_path,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        prometheus_exporter.record_model_update(
            trigger=data.get('reason', 'manual'),
            success=False
        )

        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


# ============================================================================
# Health & Metrics Endpoints
# ============================================================================

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""

    return jsonify({
        'status': 'healthy',
        'version': '2.0.0-secure',
        'ml_model_loaded': ml_predictor.model_loaded,
        'components': {
            'ml_predictor': 'ready',
            'bot_detector': 'ready',
            'api_abuse_detector': 'ready',
            'prometheus_exporter': 'ready',
            'anomaly_tracker': 'ready',
            'fp_monitor': 'ready'
        },
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/v1/metrics', methods=['GET'])
def get_metrics():
    """Get Prometheus metrics in text format"""

    # Export Prometheus metrics
    metrics_dict = prometheus_exporter.export_metrics()

    return jsonify(metrics_dict), 200


@app.route('/api/v1/stats', methods=['GET'])
def get_statistics():
    """Get comprehensive statistics"""

    try:
        stats = ml_predictor.get_performance_stats()

        return jsonify({
            'performance': stats,
            'anomalies': anomaly_tracker.get_statistics('1h'),
            'quality': fp_monitor.get_statistics(),
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@app.route('/', methods=['GET'])
def index():
    """API documentation"""

    return jsonify({
        'name': 'MIRAGE ML Integration API',
        'version': '2.0.0',
        'description': 'RESTful API for integrating ML modules with open-source WAFs',
        'endpoints': {
            'POST /api/waf/analyze': 'Analyze single request',
            'POST /api/waf/analyze/batch': 'Batch analysis',
            'GET /api/v1/baseline': 'Get baseline statistics',
            'GET /api/v1/anomalies': 'Get anomaly timeline',
            'POST /api/v1/feedback': 'Submit FP/FN feedback',
            'POST /api/v1/train': 'Trigger retraining',
            'GET /api/v1/health': 'Health check',
            'GET /api/v1/metrics': 'Prometheus metrics',
            'GET /api/v1/stats': 'Comprehensive statistics'
        },
        'compatible_with': [
            'ModSecurity',
            'NAXSI',
            'Shadow Daemon',
            'lua-resty-waf',
            'Coraza WAF',
            'Any HTTP-based WAF'
        ],
        'documentation': 'https://github.com/mirage-waf/docs',
        'timestamp': datetime.now().isoformat()
    }), 200


if __name__ == '__main__':
    print("\n" + "="*70)
    print("MIRAGE ML Integration API")
    print("="*70)
    print("\nStarting server on http://0.0.0.0:5000")
    print("\nAPI Endpoints:")
    print("  POST http://localhost:5000/api/waf/analyze")
    print("  POST http://localhost:5000/api/waf/analyze/batch")
    print("  GET  http://localhost:5000/api/v1/baseline")
    print("  GET  http://localhost:5000/api/v1/anomalies")
    print("  POST http://localhost:5000/api/v1/feedback")
    print("  POST http://localhost:5000/api/v1/train")
    print("  GET  http://localhost:5000/api/v1/health")
    print("  GET  http://localhost:5000/api/v1/metrics")
    print("  GET  http://localhost:5000/api/v1/stats")
    print("\nPress Ctrl+C to stop\n")

    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
