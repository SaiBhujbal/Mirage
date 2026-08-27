#!/usr/bin/env python3
"""
DECEPTICON WAF Admin Dashboard
==============================
Naval SWAVLAMBAN 2025 Challenge 3

GUI Requirements (Section 3.1, 5.2):
- User-friendly and informative dashboard
- View and analyse reports/recommendations
- Real-time anomaly detection visualization
- ML explainability display

Security:
- CSRF protection
- Input sanitization
- Authentication required
- Rate limiting
- No XSS vulnerabilities (escaped output)

Author: DECEPTICON Team
Date: December 2025
"""

import os
import sys
import json
import time
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from functools import wraps
from collections import deque
import threading

# Flask for web framework
try:
    from flask import (
        Flask, render_template_string, request, jsonify, 
        redirect, url_for, session, abort, g
    )
    from werkzeug.security import generate_password_hash, check_password_hash
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("⚠️  Flask not available - install with: pip install flask")

import numpy as np

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("decepticon.dashboard")

# ============================================================================
# CONFIGURATION
# ============================================================================

class DashboardConfig:
    """Dashboard configuration"""
    SECRET_KEY = os.environ.get('DASHBOARD_SECRET_KEY', secrets.token_hex(32))
    SESSION_TIMEOUT = 3600  # 1 hour
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 minutes
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60  # seconds
    
    # Default admin credentials (CHANGE IN PRODUCTION!)
    DEFAULT_ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
    DEFAULT_ADMIN_PASS = os.environ.get('ADMIN_PASS', None)  # Must be set via env


# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================

class SecurityManager:
    """Manages authentication and rate limiting"""
    
    def __init__(self):
        self.login_attempts: Dict[str, List[float]] = {}
        self.rate_limits: Dict[str, deque] = {}
        self.sessions: Dict[str, Dict] = {}
        self.lock = threading.Lock()
        
        # Admin user (password must be set via environment)
        self.admin_hash = None
        if DashboardConfig.DEFAULT_ADMIN_PASS:
            self.admin_hash = generate_password_hash(DashboardConfig.DEFAULT_ADMIN_PASS)
    
    def is_locked_out(self, ip: str) -> bool:
        """Check if IP is locked out due to failed attempts"""
        with self.lock:
            attempts = self.login_attempts.get(ip, [])
            # Remove old attempts
            cutoff = time.time() - DashboardConfig.LOCKOUT_DURATION
            attempts = [t for t in attempts if t > cutoff]
            self.login_attempts[ip] = attempts
            return len(attempts) >= DashboardConfig.MAX_LOGIN_ATTEMPTS
    
    def record_failed_attempt(self, ip: str):
        """Record a failed login attempt"""
        with self.lock:
            if ip not in self.login_attempts:
                self.login_attempts[ip] = []
            self.login_attempts[ip].append(time.time())
    
    def clear_attempts(self, ip: str):
        """Clear login attempts after successful login"""
        with self.lock:
            self.login_attempts.pop(ip, None)
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if request is within rate limit"""
        with self.lock:
            now = time.time()
            if ip not in self.rate_limits:
                self.rate_limits[ip] = deque()
            
            # Remove old requests
            while self.rate_limits[ip] and self.rate_limits[ip][0] < now - DashboardConfig.RATE_LIMIT_WINDOW:
                self.rate_limits[ip].popleft()
            
            if len(self.rate_limits[ip]) >= DashboardConfig.RATE_LIMIT_REQUESTS:
                return False
            
            self.rate_limits[ip].append(now)
            return True
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify admin credentials"""
        if username != DashboardConfig.DEFAULT_ADMIN_USER:
            return False
        if not self.admin_hash:
            logger.warning("Admin password not set! Set ADMIN_PASS environment variable.")
            return False
        return check_password_hash(self.admin_hash, password)
    
    def create_session(self, user: str, ip: str) -> str:
        """Create new session"""
        session_id = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[session_id] = {
                'user': user,
                'ip': ip,
                'created': time.time(),
                'last_active': time.time()
            }
        return session_id
    
    def validate_session(self, session_id: str, ip: str) -> Optional[Dict]:
        """Validate session and check timeout"""
        with self.lock:
            if session_id not in self.sessions:
                return None
            
            sess = self.sessions[session_id]
            
            # Check timeout
            if time.time() - sess['last_active'] > DashboardConfig.SESSION_TIMEOUT:
                del self.sessions[session_id]
                return None
            
            # Check IP binding
            if sess['ip'] != ip:
                logger.warning(f"Session IP mismatch: {sess['ip']} vs {ip}")
                del self.sessions[session_id]
                return None
            
            # Update last active
            sess['last_active'] = time.time()
            return sess
    
    def invalidate_session(self, session_id: str):
        """Invalidate session"""
        with self.lock:
            self.sessions.pop(session_id, None)


# ============================================================================
# METRICS COLLECTOR
# ============================================================================

class MetricsCollector:
    """Collects and aggregates WAF metrics for dashboard"""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.lock = threading.Lock()
        
        # Detection history
        self.detections: deque = deque(maxlen=max_history)
        
        # Aggregated metrics
        self.metrics = {
            'total_requests': 0,
            'total_blocked': 0,
            'total_allowed': 0,
            'detections_by_category': {},
            'detections_by_hour': [0] * 24,
            'top_attack_ips': {},
            'false_positives': 0,
            'false_negatives': 0,
            'avg_latency_ms': 0.0,
            'latency_samples': deque(maxlen=1000),
        }
        
        # Real-time counters
        self.requests_per_minute = deque(maxlen=60)
        self.blocks_per_minute = deque(maxlen=60)
        
        # Model performance
        self.model_metrics = {
            'isolation_forest': {'predictions': 0, 'detections': 0},
            'xgboost': {'predictions': 0, 'detections': 0},
            'autoencoder': {'predictions': 0, 'detections': 0},
            'ensemble': {'predictions': 0, 'detections': 0},
        }
    
    def record_detection(self, detection: Dict):
        """Record a detection event"""
        with self.lock:
            self.detections.append({
                **detection,
                'timestamp': datetime.now().isoformat()
            })
            
            self.metrics['total_requests'] += 1
            
            if detection.get('blocked'):
                self.metrics['total_blocked'] += 1
                
                # Category stats
                category = detection.get('category', 'unknown')
                self.metrics['detections_by_category'][category] = \
                    self.metrics['detections_by_category'].get(category, 0) + 1
                
                # Hourly stats
                hour = datetime.now().hour
                self.metrics['detections_by_hour'][hour] += 1
                
                # IP stats
                ip = detection.get('client_ip', 'unknown')
                self.metrics['top_attack_ips'][ip] = \
                    self.metrics['top_attack_ips'].get(ip, 0) + 1
            else:
                self.metrics['total_allowed'] += 1
            
            # Latency
            if 'latency_ms' in detection:
                self.metrics['latency_samples'].append(detection['latency_ms'])
                self.metrics['avg_latency_ms'] = np.mean(list(self.metrics['latency_samples']))
            
            # Model metrics
            for model in ['isolation_forest', 'xgboost', 'autoencoder', 'ensemble']:
                if f'{model}_detected' in detection:
                    self.model_metrics[model]['predictions'] += 1
                    if detection[f'{model}_detected']:
                        self.model_metrics[model]['detections'] += 1
    
    def record_feedback(self, is_false_positive: bool):
        """Record feedback for accuracy tracking"""
        with self.lock:
            if is_false_positive:
                self.metrics['false_positives'] += 1
            else:
                self.metrics['false_negatives'] += 1
    
    def get_dashboard_data(self) -> Dict:
        """Get data for dashboard display"""
        with self.lock:
            # Calculate rates
            block_rate = (self.metrics['total_blocked'] / max(1, self.metrics['total_requests'])) * 100
            
            # Get top categories
            top_categories = sorted(
                self.metrics['detections_by_category'].items(),
                key=lambda x: x[1], reverse=True
            )[:10]
            
            # Get top IPs
            top_ips = sorted(
                self.metrics['top_attack_ips'].items(),
                key=lambda x: x[1], reverse=True
            )[:10]
            
            # Recent detections
            recent = list(self.detections)[-50:]
            recent.reverse()
            
            return {
                'summary': {
                    'total_requests': self.metrics['total_requests'],
                    'total_blocked': self.metrics['total_blocked'],
                    'total_allowed': self.metrics['total_allowed'],
                    'block_rate': round(block_rate, 2),
                    'avg_latency_ms': round(self.metrics['avg_latency_ms'], 2),
                    'false_positives': self.metrics['false_positives'],
                    'false_negatives': self.metrics['false_negatives'],
                },
                'charts': {
                    'categories': dict(top_categories),
                    'hourly': self.metrics['detections_by_hour'],
                    'top_ips': dict(top_ips),
                },
                'model_performance': self.model_metrics,
                'recent_detections': recent,
            }


# ============================================================================
# RULE RECOMMENDATIONS
# ============================================================================

class RuleRecommendationEngine:
    """Generates rule recommendations from ML insights"""
    
    def __init__(self):
        self.pending_rules: List[Dict] = []
        self.approved_rules: List[Dict] = []
        self.rejected_rules: List[Dict] = []
    
    def generate_recommendation(self, detection: Dict) -> Optional[Dict]:
        """Generate rule recommendation from detection"""
        if not detection.get('blocked'):
            return None
        
        category = detection.get('category', 'unknown')
        explanation = detection.get('explanation', {})
        
        # Extract key patterns
        patterns = []
        for feature, info in explanation.items():
            if info.get('contribution', 0) > 0.1:
                patterns.append(f"{feature}>{info.get('value', 0):.2f}")
        
        if not patterns:
            return None
        
        rule = {
            'id': f"AUTO-{secrets.token_hex(4).upper()}",
            'category': category,
            'patterns': patterns,
            'confidence': detection.get('confidence', 0.5),
            'sample_payload': detection.get('payload', '')[:100],
            'created_at': datetime.now().isoformat(),
            'status': 'pending',
            'explanation': explanation,
        }
        
        self.pending_rules.append(rule)
        return rule
    
    def approve_rule(self, rule_id: str) -> bool:
        """Approve a pending rule"""
        for i, rule in enumerate(self.pending_rules):
            if rule['id'] == rule_id:
                rule['status'] = 'approved'
                rule['approved_at'] = datetime.now().isoformat()
                self.approved_rules.append(rule)
                self.pending_rules.pop(i)
                return True
        return False
    
    def reject_rule(self, rule_id: str, reason: str = '') -> bool:
        """Reject a pending rule"""
        for i, rule in enumerate(self.pending_rules):
            if rule['id'] == rule_id:
                rule['status'] = 'rejected'
                rule['rejected_at'] = datetime.now().isoformat()
                rule['rejection_reason'] = reason
                self.rejected_rules.append(rule)
                self.pending_rules.pop(i)
                return True
        return False
    
    def get_pending_rules(self) -> List[Dict]:
        """Get all pending rule recommendations"""
        return self.pending_rules
    
    def export_approved_rules(self) -> str:
        """Export approved rules in ModSecurity format"""
        rules = []
        for rule in self.approved_rules:
            rule_str = f"""
# Auto-generated rule: {rule['id']}
# Category: {rule['category']}
# Confidence: {rule['confidence']:.2%}
# Generated: {rule['created_at']}
SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx {rule['patterns'][0] if rule['patterns'] else '.*'}" \\
    "id:{hash(rule['id']) % 1000000},\\
    phase:2,\\
    block,\\
    t:none,t:urlDecodeUni,t:lowercase,\\
    msg:'DECEPTICON Auto-Rule: {rule['category']}',\\
    severity:CRITICAL,\\
    tag:'DECEPTICON-{rule['id']}'"
"""
            rules.append(rule_str)
        
        return '\n'.join(rules)


# ============================================================================
# FLASK APPLICATION
# ============================================================================

if FLASK_AVAILABLE:
    app = Flask(__name__)
    app.secret_key = DashboardConfig.SECRET_KEY
    
    # Initialize components
    security_manager = SecurityManager()
    metrics_collector = MetricsCollector()
    rule_engine = RuleRecommendationEngine()
    
    # ========================================================================
    # HTML TEMPLATES (Embedded for single-file deployment)
    # ========================================================================
    
    BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>DECEPTICON WAF Dashboard</title>
    <style>
        :root {
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #0f3460;
            --highlight: #e94560;
            --success: #00d9ff;
            --warning: #ffc107;
            --danger: #dc3545;
            --text: #eee;
            --text-muted: #888;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--primary);
            color: var(--text);
            min-height: 100vh;
        }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        header {
            background: var(--secondary);
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--highlight);
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--highlight);
        }
        
        .logo span { color: var(--success); }
        
        nav a {
            color: var(--text);
            text-decoration: none;
            margin-left: 25px;
            padding: 8px 15px;
            border-radius: 5px;
            transition: background 0.2s;
        }
        
        nav a:hover, nav a.active {
            background: var(--accent);
        }
        
        .card {
            background: var(--secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        
        .card h3 {
            color: var(--success);
            margin-bottom: 15px;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--accent);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--success);
        }
        
        .stat-value.danger { color: var(--danger); }
        .stat-value.warning { color: var(--warning); }
        
        .stat-label {
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 5px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--accent);
        }
        
        th {
            color: var(--success);
            font-size: 0.85rem;
            text-transform: uppercase;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        
        .badge-danger { background: var(--danger); }
        .badge-success { background: #28a745; }
        .badge-warning { background: var(--warning); color: #000; }
        .badge-info { background: var(--success); color: #000; }
        
        .btn {
            display: inline-block;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: transform 0.1s, opacity 0.2s;
        }
        
        .btn:hover { transform: translateY(-1px); opacity: 0.9; }
        
        .btn-primary { background: var(--highlight); color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: var(--danger); color: white; }
        
        input, textarea, select {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--accent);
            border-radius: 5px;
            background: var(--primary);
            color: var(--text);
            margin-bottom: 15px;
        }
        
        input:focus, textarea:focus {
            outline: none;
            border-color: var(--success);
        }
        
        .chart-container {
            height: 300px;
            background: var(--accent);
            border-radius: 10px;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .bar-chart {
            display: flex;
            align-items: flex-end;
            height: 200px;
            gap: 10px;
        }
        
        .bar {
            width: 30px;
            background: linear-gradient(to top, var(--highlight), var(--success));
            border-radius: 5px 5px 0 0;
            transition: height 0.3s;
        }
        
        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .alert-success { background: rgba(40, 167, 69, 0.2); border-left: 4px solid #28a745; }
        .alert-danger { background: rgba(220, 53, 69, 0.2); border-left: 4px solid var(--danger); }
        .alert-warning { background: rgba(255, 193, 7, 0.2); border-left: 4px solid var(--warning); }
        
        .explanation-box {
            background: var(--primary);
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.85rem;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .feature-bar {
            display: flex;
            align-items: center;
            margin: 5px 0;
        }
        
        .feature-name {
            width: 150px;
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        
        .feature-value {
            flex: 1;
            height: 20px;
            background: var(--accent);
            border-radius: 10px;
            overflow: hidden;
        }
        
        .feature-fill {
            height: 100%;
            background: linear-gradient(to right, var(--success), var(--highlight));
            transition: width 0.3s;
        }
        
        .login-container {
            max-width: 400px;
            margin: 100px auto;
        }
        
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            header { flex-direction: column; gap: 15px; }
            nav { display: flex; flex-wrap: wrap; justify-content: center; }
            nav a { margin: 5px; }
        }
    </style>
</head>
<body>
    {% block content %}{% endblock %}
    
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
        
        // CSRF token for AJAX
        const csrfToken = '{{ csrf_token }}';
        
        function apiCall(endpoint, method = 'GET', data = null) {
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                }
            };
            if (data) options.body = JSON.stringify(data);
            return fetch(endpoint, options).then(r => r.json());
        }
    </script>
</body>
</html>
"""

    LOGIN_TEMPLATE = """
{% extends "base" %}
{% block content %}
<div class="login-container">
    <div class="card">
        <h3>🛡️ DECEPTICON Login</h3>
        {% if error %}
        <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn btn-primary" style="width:100%">Login</button>
        </form>
    </div>
</div>
{% endblock %}
"""

    DASHBOARD_TEMPLATE = """
{% extends "base" %}
{% block content %}
<header>
    <div class="logo">🛡️ DECEPTI<span>CON</span> WAF</div>
    <nav>
        <a href="/dashboard" class="active">Dashboard</a>
        <a href="/dashboard/detections">Detections</a>
        <a href="/dashboard/rules">Rules</a>
        <a href="/dashboard/test">Test</a>
        <a href="/dashboard/settings">Settings</a>
        <a href="/logout">Logout</a>
    </nav>
</header>

<div class="container">
    <h2 style="margin: 20px 0;">Real-Time Security Overview</h2>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{{ data.summary.total_requests }}</div>
            <div class="stat-label">Total Requests</div>
        </div>
        <div class="stat-card">
            <div class="stat-value danger">{{ data.summary.total_blocked }}</div>
            <div class="stat-label">Blocked Attacks</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ data.summary.block_rate }}%</div>
            <div class="stat-label">Block Rate</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--success)">{{ data.summary.avg_latency_ms }}ms</div>
            <div class="stat-label">Avg Latency</div>
        </div>
        <div class="stat-card">
            <div class="stat-value warning">{{ data.summary.false_positives }}</div>
            <div class="stat-label">False Positives</div>
        </div>
        <div class="stat-card">
            <div class="stat-value danger">{{ data.summary.false_negatives }}</div>
            <div class="stat-label">False Negatives</div>
        </div>
    </div>
    
    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px;">
        <div class="card">
            <h3>📊 Detections by Hour (24h)</h3>
            <div class="chart-container">
                <div class="bar-chart">
                    {% for count in data.charts.hourly %}
                    <div class="bar" style="height: {{ (count / (data.charts.hourly|max + 1)) * 180 }}px;" title="Hour {{ loop.index0 }}: {{ count }}"></div>
                    {% endfor %}
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>🎯 Top Attack Categories</h3>
            {% for cat, count in data.charts.categories.items() %}
            <div class="feature-bar">
                <span class="feature-name">{{ cat }}</span>
                <div class="feature-value">
                    <div class="feature-fill" style="width: {{ (count / (data.charts.categories.values()|max + 1)) * 100 }}%"></div>
                </div>
                <span style="margin-left: 10px; color: var(--text-muted)">{{ count }}</span>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div class="card">
            <h3>🤖 Model Performance</h3>
            <table>
                <tr>
                    <th>Model</th>
                    <th>Predictions</th>
                    <th>Detections</th>
                    <th>Rate</th>
                </tr>
                {% for model, stats in data.model_performance.items() %}
                <tr>
                    <td>{{ model }}</td>
                    <td>{{ stats.predictions }}</td>
                    <td>{{ stats.detections }}</td>
                    <td>{{ "%.1f"|format((stats.detections / (stats.predictions + 1)) * 100) }}%</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        
        <div class="card">
            <h3>🚨 Top Attacking IPs</h3>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Attacks</th>
                </tr>
                {% for ip, count in data.charts.top_ips.items() %}
                <tr>
                    <td>{{ ip }}</td>
                    <td><span class="badge badge-danger">{{ count }}</span></td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>
    
    <div class="card">
        <h3>🔍 Recent Detections</h3>
        <table>
            <tr>
                <th>Time</th>
                <th>IP</th>
                <th>Category</th>
                <th>Confidence</th>
                <th>Action</th>
            </tr>
            {% for det in data.recent_detections[:10] %}
            <tr>
                <td>{{ det.timestamp[:19] }}</td>
                <td>{{ det.client_ip }}</td>
                <td>{{ det.category }}</td>
                <td>{{ "%.1f"|format(det.confidence * 100) }}%</td>
                <td>
                    {% if det.blocked %}
                    <span class="badge badge-danger">BLOCKED</span>
                    {% else %}
                    <span class="badge badge-success">ALLOWED</span>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>
</div>
{% endblock %}
"""

    TEST_TEMPLATE = """
{% extends "base" %}
{% block content %}
<header>
    <div class="logo">🛡️ DECEPTI<span>CON</span> WAF</div>
    <nav>
        <a href="/dashboard">Dashboard</a>
        <a href="/dashboard/detections">Detections</a>
        <a href="/dashboard/rules">Rules</a>
        <a href="/dashboard/test" class="active">Test</a>
        <a href="/dashboard/settings">Settings</a>
        <a href="/logout">Logout</a>
    </nav>
</header>

<div class="container">
    <h2 style="margin: 20px 0;">🧪 Payload Tester</h2>
    
    <div class="card">
        <h3>Test Payload Analysis</h3>
        <form id="testForm">
            <textarea name="payload" rows="4" placeholder="Enter payload to test...">{{ test_payload or "" }}</textarea>
            <button type="submit" class="btn btn-primary">Analyze Payload</button>
        </form>
    </div>
    
    {% if result %}
    <div class="card">
        <h3>Analysis Result</h3>
        
        <div class="alert {% if result.is_malicious %}alert-danger{% else %}alert-success{% endif %}">
            <strong>{% if result.is_malicious %}⚠️ MALICIOUS{% else %}✅ BENIGN{% endif %}</strong>
            - Confidence: {{ "%.1f"|format(result.confidence * 100) }}%
            {% if result.category %} | Category: {{ result.category }}{% endif %}
        </div>
        
        <h4 style="margin: 15px 0 10px; color: var(--success)">Model Scores</h4>
        {% for model, score in result.model_scores.items() %}
        <div class="feature-bar">
            <span class="feature-name">{{ model }}</span>
            <div class="feature-value">
                <div class="feature-fill" style="width: {{ score * 100 }}%; max-width: 100%"></div>
            </div>
            <span style="margin-left: 10px">{{ "%.3f"|format(score) }}</span>
        </div>
        {% endfor %}
        
        {% if result.explanation %}
        <h4 style="margin: 15px 0 10px; color: var(--success)">Feature Explanation</h4>
        <div class="explanation-box">
            {% for feat, info in result.explanation.items() %}
            <div>{{ feat }}: {{ "%.4f"|format(info.value) }} (contrib: {{ "%.4f"|format(info.contribution) }})</div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if result.category_probabilities %}
        <h4 style="margin: 15px 0 10px; color: var(--success)">Category Probabilities</h4>
        {% for cat, prob in result.category_probabilities.items() %}
        <div class="feature-bar">
            <span class="feature-name">{{ cat }}</span>
            <div class="feature-value">
                <div class="feature-fill" style="width: {{ prob * 100 }}%"></div>
            </div>
            <span style="margin-left: 10px">{{ "%.1f"|format(prob * 100) }}%</span>
        </div>
        {% endfor %}
        {% endif %}
    </div>
    {% endif %}
    
    <div class="card">
        <h3>Quick Test Payloads</h3>
        <div style="display: flex; flex-wrap: wrap; gap: 10px;">
            <button class="btn btn-danger" onclick="testPayload(\\\"' OR 1=1--\\\")">SQL Injection</button>
            <button class="btn btn-danger" onclick="testPayload('<script>alert(1)</script>')">XSS</button>
            <button class="btn btn-danger" onclick="testPayload('; cat /etc/passwd')">RCE</button>
            <button class="btn btn-danger" onclick="testPayload('../../../etc/passwd')">Path Traversal</button>
            <button class="btn btn-success" onclick="testPayload('search?q=hello+world')">Benign Search</button>
            <button class="btn btn-success" onclick="testPayload('api/users/123')">Benign API</button>
        </div>
    </div>
</div>

<script>
function testPayload(payload) {
    document.querySelector('textarea[name=payload]').value = payload;
    document.getElementById('testForm').submit();
}

document.getElementById('testForm').onsubmit = function(e) {
    e.preventDefault();
    const payload = document.querySelector('textarea[name=payload]').value;
    window.location.href = '/dashboard/test?payload=' + encodeURIComponent(payload);
};
</script>
{% endblock %}
"""

    RULES_TEMPLATE = """
{% extends "base" %}
{% block content %}
<header>
    <div class="logo">🛡️ DECEPTI<span>CON</span> WAF</div>
    <nav>
        <a href="/dashboard">Dashboard</a>
        <a href="/dashboard/detections">Detections</a>
        <a href="/dashboard/rules" class="active">Rules</a>
        <a href="/dashboard/test">Test</a>
        <a href="/dashboard/settings">Settings</a>
        <a href="/logout">Logout</a>
    </nav>
</header>

<div class="container">
    <h2 style="margin: 20px 0;">📋 Rule Recommendations</h2>
    
    <div class="card">
        <h3>Pending Approval ({{ pending_rules|length }})</h3>
        {% if pending_rules %}
        <table>
            <tr>
                <th>Rule ID</th>
                <th>Category</th>
                <th>Patterns</th>
                <th>Confidence</th>
                <th>Actions</th>
            </tr>
            {% for rule in pending_rules %}
            <tr>
                <td><code>{{ rule.id }}</code></td>
                <td><span class="badge badge-info">{{ rule.category }}</span></td>
                <td><code>{{ rule.patterns|join(', ') }}</code></td>
                <td>{{ "%.1f"|format(rule.confidence * 100) }}%</td>
                <td>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                        <input type="hidden" name="rule_id" value="{{ rule.id }}">
                        <button type="submit" name="action" value="approve" class="btn btn-success">✓</button>
                        <button type="submit" name="action" value="reject" class="btn btn-danger">✗</button>
                    </form>
                </td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p style="color: var(--text-muted)">No pending rule recommendations.</p>
        {% endif %}
    </div>
    
    <div class="card">
        <h3>Approved Rules ({{ approved_rules|length }})</h3>
        {% if approved_rules %}
        <table>
            <tr>
                <th>Rule ID</th>
                <th>Category</th>
                <th>Patterns</th>
                <th>Approved</th>
            </tr>
            {% for rule in approved_rules %}
            <tr>
                <td><code>{{ rule.id }}</code></td>
                <td><span class="badge badge-success">{{ rule.category }}</span></td>
                <td><code>{{ rule.patterns|join(', ') }}</code></td>
                <td>{{ rule.approved_at[:10] }}</td>
            </tr>
            {% endfor %}
        </table>
        <div style="margin-top: 15px;">
            <a href="/dashboard/rules/export" class="btn btn-primary">📥 Export as ModSecurity Rules</a>
        </div>
        {% else %}
        <p style="color: var(--text-muted)">No approved rules yet.</p>
        {% endif %}
    </div>
</div>
{% endblock %}
"""

    # ========================================================================
    # DECORATORS
    # ========================================================================
    
    def login_required(f):
        """Require authentication"""
        @wraps(f)
        def decorated(*args, **kwargs):
            session_id = session.get('session_id')
            if not session_id:
                return redirect(url_for('login'))
            
            ip = request.remote_addr
            sess = security_manager.validate_session(session_id, ip)
            if not sess:
                session.clear()
                return redirect(url_for('login'))
            
            g.user = sess['user']
            return f(*args, **kwargs)
        return decorated
    
    def rate_limit(f):
        """Apply rate limiting"""
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr
            if not security_manager.check_rate_limit(ip):
                return jsonify({'error': 'Rate limit exceeded'}), 429
            return f(*args, **kwargs)
        return decorated
    
    def csrf_protect(f):
        """CSRF protection for POST requests"""
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == 'POST':
                token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
                if not token or token != session.get('csrf_token'):
                    abort(403)
            return f(*args, **kwargs)
        return decorated
    
    # ========================================================================
    # ROUTES
    # ========================================================================
    
    @app.before_request
    def before_request():
        """Generate CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        g.csrf_token = session['csrf_token']
    
    @app.context_processor
    def inject_csrf():
        """Inject CSRF token into templates"""
        return {'csrf_token': session.get('csrf_token', '')}
    
    def render(template_name, **kwargs):
        """Render template with base"""
        templates = {
            'base': BASE_TEMPLATE,
            'login': LOGIN_TEMPLATE,
            'dashboard': DASHBOARD_TEMPLATE,
            'test': TEST_TEMPLATE,
            'rules': RULES_TEMPLATE,
        }
        
        from jinja2 import Environment, BaseLoader
        
        # autoescape=True: the dashboard renders captured attack data (payloads, headers,
        # request fields) that is attacker-controlled. Without escaping, viewing the dashboard
        # is stored XSS. Use an explicit |safe filter for any value that is intentionally HTML.
        env = Environment(loader=BaseLoader(), autoescape=True)
        env.globals['csrf_token'] = session.get('csrf_token', '')
        
        # Register base template
        base_tpl = env.from_string(templates['base'])
        
        # Create child template that extends base
        child_src = templates[template_name].replace('{% extends "base" %}', '')
        child_src = child_src.replace('{% block content %}', '').replace('{% endblock %}', '')
        
        # Combine
        full_template = templates['base'].replace('{% block content %}{% endblock %}', child_src)
        
        return render_template_string(full_template, **kwargs)
    
    @app.route('/')
    def index():
        return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    @rate_limit
    def login():
        ip = request.remote_addr
        error = None
        
        if security_manager.is_locked_out(ip):
            error = "Too many failed attempts. Try again later."
            return render('login', error=error)
        
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            # Input validation
            if len(username) > 50 or len(password) > 100:
                error = "Invalid credentials"
            elif security_manager.verify_password(username, password):
                security_manager.clear_attempts(ip)
                session_id = security_manager.create_session(username, ip)
                session['session_id'] = session_id
                return redirect(url_for('dashboard'))
            else:
                security_manager.record_failed_attempt(ip)
                error = "Invalid credentials"
        
        return render('login', error=error)
    
    @app.route('/logout')
    def logout():
        session_id = session.get('session_id')
        if session_id:
            security_manager.invalidate_session(session_id)
        session.clear()
        return redirect(url_for('login'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        data = metrics_collector.get_dashboard_data()
        return render('dashboard', data=data)
    
    @app.route('/dashboard/test', methods=['GET'])
    @login_required
    def test_page():
        payload = request.args.get('payload', '')
        result = None
        
        if payload:
            # Import trainer and make prediction
            try:
                from ml.adaptive_trainer import AdaptiveEnsembleTrainer, AdaptiveTrainingConfig
                
                config = AdaptiveTrainingConfig()
                trainer = AdaptiveEnsembleTrainer(config)
                
                # Check if model exists
                if Path('./models/ensemble_metadata.json').exists():
                    # Load model and predict
                    result = trainer.predict(payload)
                else:
                    # Use mock result for demo
                    result = {
                        'is_malicious': any(ind in payload.lower() for ind in 
                                           ["'", '<script', '../', ';', 'select', 'union']),
                        'confidence': 0.85,
                        'category': 'sqli' if "'" in payload else 'benign',
                        'model_scores': {
                            'isolation_forest': 0.7,
                            'xgboost': 0.9,
                            'autoencoder': 0.6
                        },
                        'explanation': {
                            'sql_keyword_count': {'value': 2, 'contribution': 0.3},
                            'special_char_ratio': {'value': 0.15, 'contribution': 0.2}
                        },
                        'category_probabilities': {
                            'benign': 0.1,
                            'sqli': 0.7,
                            'xss': 0.1,
                            'rce': 0.05,
                            'other': 0.05
                        }
                    }
            except Exception as e:
                logger.error(f"Prediction error: {e}")
                result = {'error': str(e)}
        
        return render('test', test_payload=payload, result=result)
    
    @app.route('/dashboard/rules', methods=['GET', 'POST'])
    @login_required
    @csrf_protect
    def rules_page():
        if request.method == 'POST':
            rule_id = request.form.get('rule_id')
            action = request.form.get('action')
            
            if action == 'approve':
                rule_engine.approve_rule(rule_id)
            elif action == 'reject':
                rule_engine.reject_rule(rule_id, 'Manual rejection')
        
        return render('rules', 
                     pending_rules=rule_engine.get_pending_rules(),
                     approved_rules=rule_engine.approved_rules)
    
    @app.route('/dashboard/rules/export')
    @login_required
    def export_rules():
        rules = rule_engine.export_approved_rules()
        return rules, 200, {'Content-Type': 'text/plain'}
    
    @app.route('/dashboard/detections')
    @login_required  
    def detections_page():
        data = metrics_collector.get_dashboard_data()
        return render('dashboard', data=data)
    
    @app.route('/dashboard/settings')
    @login_required
    def settings_page():
        return render('dashboard', data=metrics_collector.get_dashboard_data())
    
    # ========================================================================
    # API ENDPOINTS
    # ========================================================================
    
    @app.route('/api/analyze', methods=['POST'])
    @rate_limit
    def api_analyze():
        """API endpoint for payload analysis"""
        data = request.get_json()
        if not data or 'payload' not in data:
            return jsonify({'error': 'Missing payload'}), 400
        
        payload = data['payload'][:10000]  # Limit size
        
        try:
            from ml.adaptive_trainer import AdaptiveEnsembleTrainer, AdaptiveTrainingConfig
            
            config = AdaptiveTrainingConfig()
            trainer = AdaptiveEnsembleTrainer(config)
            
            result = trainer.predict(payload)
            
            # Record detection
            metrics_collector.record_detection({
                'payload': payload[:100],
                'client_ip': request.remote_addr,
                'blocked': result['is_malicious'],
                'category': result['category'],
                'confidence': result['confidence'],
            })
            
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/feedback', methods=['POST'])
    @login_required
    @csrf_protect
    def api_feedback():
        """Record feedback on detection"""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing data'}), 400
        
        is_fp = data.get('is_false_positive', False)
        metrics_collector.record_feedback(is_fp)
        
        return jsonify({'status': 'recorded'})
    
    @app.route('/api/metrics')
    @login_required
    def api_metrics():
        """Get metrics for AJAX refresh"""
        return jsonify(metrics_collector.get_dashboard_data())


# ============================================================================
# MAIN
# ============================================================================

def run_dashboard(host: str = '0.0.0.0', port: int = 8080, debug: bool = False):
    """Run the dashboard server"""
    if not FLASK_AVAILABLE:
        print("Flask not installed. Run: pip install flask")
        return
    
    admin_user = DashboardConfig.DEFAULT_ADMIN_USER
    admin_pass = DashboardConfig.DEFAULT_ADMIN_PASS

    if not admin_pass:
        admin_pass = secrets.token_urlsafe(16)
        print("\n" + "="*60)
        print("⚠️  WARNING: Admin password not set!")
        print("   Set ADMIN_PASS environment variable before production use.")
        print(f"   For testing, using generated password: '{admin_pass}'")
        print("="*60 + "\n")
        security_manager.admin_hash = generate_password_hash(admin_pass)

    display_pass = admin_pass if not DashboardConfig.DEFAULT_ADMIN_PASS else "********"

    url_line = f"     http://{host}:{port}"
    creds_line = f"     Credentials: {admin_user} / {display_pass}"
    note_line = f"     (Set ADMIN_PASS env var for production)"
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     DECEPTICON WAF Admin Dashboard                              ║
    ║{url_line:<66}║
    ║                                                                  ║
    ║{creds_line:<66}║
    ║{note_line:<66}║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='DECEPTICON Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
    parser.add_argument('--port', type=int, default=8080, help='Port')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    
    args = parser.parse_args()
    run_dashboard(args.host, args.port, args.debug)
