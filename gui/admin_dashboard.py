#!/usr/bin/env python3
"""
DECEPTICON WAF - Admin Feedback Dashboard
Enterprise-grade administrative interface for WAF management

Features:
- Rule approval/rejection system
- False positive reporting
- ML decision review
- Real-time metrics monitoring
- Model retraining triggers
- Attack pattern analysis
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from pathlib import Path
import json
import os
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from ml.dual_layer_inference import DualLayerPredictor
from metrics.prometheus_exporter import get_exporter

# ---------------------------------------------------------------------------
# Honest metric sourcing
# ---------------------------------------------------------------------------
# Every model-quality number shown below is read at runtime from the artifact
# the training pipeline actually wrote (models/training_report.json). If that
# artifact is missing or unreadable the dashboard renders "n/a" - it never
# falls back to a literal. Hardcoded figures here previously advertised 99.84%
# accuracy, a synthetic-data number the project's own LEGACY.md records as
# disproved; the measured XGBoost accuracy is 97.43%.

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAINING_REPORT_PATH = PROJECT_ROOT / "models" / "training_report.json"

UNKNOWN = "n/a"
SAMPLE_DATA_NOTE = (
    "Illustrative sample data - not live telemetry. "
    "Wire to Prometheus before treating these as real."
)


def load_training_report(path: Path = TRAINING_REPORT_PATH):
    """Read the training report artifact. Returns None if absent/unreadable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError):
        return None
    return report if isinstance(report, dict) else None


def report_number(report, *keys):
    """Walk a nested key path in the report. None if any hop is missing."""
    node = report
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node if isinstance(node, (int, float)) and not isinstance(node, bool) else None


def as_percent(value, digits=2):
    """Format a 0-1 ratio as a percentage, or 'n/a' when unmeasured."""
    return UNKNOWN if value is None else f"{value * 100:.{digits}f}%"


def report_age(report):
    """Human-readable age of the training run, or 'n/a'."""
    stamp = (report or {}).get("timestamp")
    if not isinstance(stamp, str):
        return UNKNOWN
    try:
        trained_at = datetime.fromisoformat(stamp)
    except ValueError:
        return UNKNOWN
    now = datetime.now(trained_at.tzinfo) if trained_at.tzinfo else datetime.now()
    delta = now - trained_at
    if delta.total_seconds() < 0:
        return trained_at.strftime("%Y-%m-%d %H:%M")
    days = delta.days
    if days >= 1:
        return f"{days}d ago ({trained_at.strftime('%Y-%m-%d')})"
    hours = int(delta.total_seconds() // 3600)
    return f"{hours}h ago" if hours else "<1h ago"


def ml_posture():
    """Deployed ML enforcement posture, read from the WAF's own env contract.

    waf/server.py reads WAF_ML_ENFORCE and defaults it to false: the ML layer
    scores traffic and records would-blocks but enforces nothing. Say that
    rather than "ACTIVE", which reads as "currently blocking attacks".
    """
    enforcing = os.environ.get("WAF_ML_ENFORCE", "false").strip().lower() in (
        "1",
        "true",
        "on",
        "yes",
    )
    if enforcing:
        return "Enforcing (blocking)", "WAF_ML_ENFORCE is set - ML decisions block."
    return (
        "Shadow (observing, not enforcing)",
        "WAF_ML_ENFORCE unset/false (default) - ML records would-blocks only; "
        "signature layers still enforce.",
    )


def waf_mode():
    """Deployed proxy mode, read from WAF_MODE (waf/server.py default: block)."""
    mode = os.environ.get("WAF_MODE", "block").strip().lower()
    if mode in ("shadow", "monitor"):
        return "Shadow (log-only, nothing blocked)"
    if mode == "block":
        return "Block (signature layers enforce)"
    return f"Unknown ({mode})"


TRAINING_REPORT = load_training_report()
ML_POSTURE, ML_POSTURE_DETAIL = ml_posture()
OFFLINE_ACCURACY = as_percent(report_number(TRAINING_REPORT, "http_layer", "xgboost", "accuracy"))
OFFLINE_F1 = as_percent(report_number(TRAINING_REPORT, "http_layer", "ensemble", "f1"), digits=3)
OFFLINE_FPR = as_percent(report_number(TRAINING_REPORT, "http_layer", "ensemble", "fpr"))
OFFLINE_SOURCE = (
    f"Source: {TRAINING_REPORT_PATH.as_posix()} (offline held-out test set, not live traffic)."
    if TRAINING_REPORT
    else f"No training report at {TRAINING_REPORT_PATH.as_posix()} - model quality unmeasured here."
)

# Page configuration
st.set_page_config(
    page_title="DECEPTICON WAF - Admin Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown(
    """
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .critical-alert {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .success-alert {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .warning-alert {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Initialize session state
if "pending_rules" not in st.session_state:
    st.session_state.pending_rules = []
if "feedback_log" not in st.session_state:
    st.session_state.feedback_log = []
if "predictor" not in st.session_state:
    st.session_state.predictor = DualLayerPredictor(models_dir="./models")
if "metrics_exporter" not in st.session_state:
    st.session_state.metrics_exporter = get_exporter()

# Header
st.markdown(
    '<div class="main-header">🛡️ DECEPTICON WAF - Admin Console</div>',
    unsafe_allow_html=True,
)
st.markdown(
    f"**WAF mode:** {waf_mode()} | **ML layer:** {ML_POSTURE} | "
    f"**Page rendered:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)
st.caption(ML_POSTURE_DETAIL)
st.markdown("---")

# Sidebar
with st.sidebar:
    st.title("Navigation")
    page = st.radio(
        "Select Page:",
        [
            "📊 Dashboard Overview",
            "🔍 ML Decision Review",
            "✅ Rule Approval System",
            "⚠️ False Positive Management",
            "🤖 Model Management",
            "📈 Performance Analytics",
            "🎯 Live Testing",
            "⚙️ System Configuration",
        ],
    )

    st.markdown("---")
    st.markdown("### Quick Actions")

    if st.button("🔄 Refresh Data"):
        st.rerun()

    if st.button("📥 Export Report"):
        st.info("Report export is not implemented yet.")

    st.markdown("---")
    st.markdown("### System Health")
    st.metric("ML Layer", ML_POSTURE)
    st.metric("Model artifact", "loaded" if TRAINING_REPORT else "no training report")
    st.caption("Prometheus/Grafana status is not probed by this page.")

# Main content based on selected page
if page == "📊 Dashboard Overview":
    st.header("Dashboard Overview")

    # Key metrics
    # Traffic counters are placeholders until this page is wired to Prometheus;
    # model-quality figures come from the training report artifact at runtime.
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(label="Total Requests (24h)", value=UNKNOWN)
        st.caption("Not wired to Prometheus yet.")

    with col2:
        st.metric(label="Attacks Blocked (24h)", value=UNKNOWN)
        st.caption("Not wired to Prometheus yet.")

    with col3:
        st.metric(label="ML Accuracy (offline test)", value=OFFLINE_ACCURACY)
        st.caption("XGBoost held-out accuracy from the training report.")

    with col4:
        st.metric(label="False Positive Rate (offline test)", value=OFFLINE_FPR)
        st.caption("Ensemble FPR from the training report.")

    st.caption(OFFLINE_SOURCE)
    st.info(
        f"ML layer posture: **{ML_POSTURE}**. {ML_POSTURE_DETAIL} "
        "Offline test-set scores do not predict production accuracy on your traffic."
    )

    # Charts
    st.subheader("Attack Timeline (Last 24 Hours)")
    st.caption(SAMPLE_DATA_NOTE)

    # Sample data - in production, query from Prometheus
    timeline_data = pd.DataFrame(
        {
            "timestamp": pd.date_range(start="2026-01-01", periods=24, freq="H"),
            "sqli": [
                12,
                15,
                8,
                23,
                45,
                67,
                34,
                23,
                12,
                8,
                15,
                23,
                34,
                45,
                23,
                12,
                8,
                15,
                23,
                12,
                8,
                15,
                23,
                12,
            ],
            "xss": [
                8,
                12,
                15,
                18,
                23,
                34,
                23,
                12,
                8,
                5,
                8,
                12,
                23,
                34,
                12,
                8,
                5,
                8,
                12,
                8,
                5,
                8,
                12,
                8,
            ],
            "rce": [
                3,
                5,
                2,
                8,
                12,
                15,
                8,
                5,
                3,
                2,
                3,
                5,
                8,
                12,
                5,
                3,
                2,
                3,
                5,
                3,
                2,
                3,
                5,
                3,
            ],
            "other": [
                5,
                8,
                5,
                12,
                18,
                23,
                12,
                8,
                5,
                3,
                5,
                8,
                12,
                18,
                8,
                5,
                3,
                5,
                8,
                5,
                3,
                5,
                8,
                5,
            ],
        }
    )

    fig = go.Figure()
    for category in ["sqli", "xss", "rce", "other"]:
        fig.add_trace(
            go.Scatter(
                x=timeline_data["timestamp"],
                y=timeline_data[category],
                mode="lines",
                name=category.upper(),
                stackgroup="one",
                fill="tonexty",
            )
        )

    fig.update_layout(
        title="Attacks Detected by Category",
        xaxis_title="Time",
        yaxis_title="Attack Count",
        hovermode="x unified",
    )

    st.plotly_chart(fig, use_container_width=True)

    # Recent alerts
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🚨 Recent Critical Alerts")
        st.caption(SAMPLE_DATA_NOTE)
        alerts = [
            {
                "time": "2 min ago",
                "type": "Zero-Day",
                "severity": "CRITICAL",
                "message": "Potential zero-day pattern detected",
            },
            {
                "time": "15 min ago",
                "type": "SQL Injection",
                "severity": "HIGH",
                "message": "Advanced SQLi bypass attempt blocked",
            },
            {
                "time": "32 min ago",
                "type": "Bot Attack",
                "severity": "MEDIUM",
                "message": "Bot wave detected and blocked",
            },
        ]

        for alert in alerts:
            severity_color = {
                "CRITICAL": "critical-alert",
                "HIGH": "warning-alert",
                "MEDIUM": "metric-card",
            }
            st.markdown(
                f"""
            <div class="{severity_color[alert['severity']]}">
                <strong>{alert['type']}</strong> - {alert['severity']}<br>
                {alert['message']}<br>
                <small>{alert['time']}</small>
            </div>
            """,
                unsafe_allow_html=True,
            )

    with col2:
        st.subheader("✅ Recent Actions")
        st.caption(SAMPLE_DATA_NOTE)
        actions = [
            {
                "time": "5 min ago",
                "action": "Rule Approved",
                "user": "admin",
                "details": "SQLi pattern #847",
            },
            {
                "time": "18 min ago",
                "action": "False Positive Reported",
                "user": "security_team",
                "details": "XSS FP #23",
            },
            {
                "time": "45 min ago",
                "action": "Model Retrained",
                "user": "system",
                "details": "See Model Management for measured scores",
            },
        ]

        for action in actions:
            st.markdown(
                f"""
            <div class="success-alert">
                <strong>{action['action']}</strong> by {action['user']}<br>
                {action['details']}<br>
                <small>{action['time']}</small>
            </div>
            """,
                unsafe_allow_html=True,
            )

elif page == "🔍 ML Decision Review":
    st.header("ML Decision Review")
    st.markdown("Review and provide feedback on ML model predictions")
    st.caption(SAMPLE_DATA_NOTE)

    # Filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_category = st.selectbox(
            "Category", ["All", "SQLi", "XSS", "RCE", "SSRF", "Path Traversal"]
        )
    with col2:
        filter_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.5)
    with col3:
        filter_time = st.selectbox(
            "Time Range", ["Last Hour", "Last 24 Hours", "Last 7 Days"]
        )

    # Sample ML decisions
    ml_decisions = pd.DataFrame(
        {
            "timestamp": pd.date_range(
                start="2026-01-01 00:00", periods=20, freq="3min"
            ),
            "request": [
                "' OR 1=1--",
                "<script>alert(1)</script>",
                "; cat /etc/passwd",
                "../../../etc/passwd",
                "http://169.254.169.254/",
                "' UNION SELECT * FROM users--",
                "<img src=x onerror=alert(1)>",
                "`whoami`",
                "....//....//etc/passwd",
                "http://localhost/admin",
            ]
            * 2,
            "category": ["SQLi", "XSS", "RCE", "Path Traversal", "SSRF"] * 4,
            "confidence": [0.98, 0.96, 0.99, 0.97, 0.94, 0.95, 0.93, 0.97, 0.96, 0.91]
            * 2,
            "blocked": [True] * 20,
            "reviewed": [False] * 20,
        }
    )

    st.dataframe(
        ml_decisions,
        column_config={
            "timestamp": st.column_config.DatetimeColumn(
                "Timestamp", format="YYYY-MM-DD HH:mm:ss"
            ),
            "request": st.column_config.TextColumn("Request", width="medium"),
            "category": st.column_config.TextColumn("Category"),
            "confidence": st.column_config.ProgressColumn(
                "Confidence", format="%.2f", min_value=0, max_value=1
            ),
            "blocked": st.column_config.CheckboxColumn("Blocked"),
            "reviewed": st.column_config.CheckboxColumn("Reviewed"),
        },
        hide_index=True,
        use_container_width=True,
    )

    # Review interface
    st.subheader("Review Selected Decision")

    selected_idx = st.number_input(
        "Select row to review", min_value=0, max_value=len(ml_decisions) - 1, value=0
    )
    selected = ml_decisions.iloc[selected_idx]

    col1, col2 = st.columns(2)

    with col1:
        st.code(selected["request"], language="text")
        st.write(f"**Category:** {selected['category']}")
        st.write(f"**Confidence:** {selected['confidence']:.2%}")
        st.write(f"**Blocked:** {'Yes' if selected['blocked'] else 'No'}")

    with col2:
        st.subheader("Your Feedback")

        feedback_type = st.radio(
            "Decision Correctness:",
            [
                "✅ Correct (True Positive)",
                "❌ Incorrect (False Positive)",
                "⚠️ Needs Review",
            ],
        )

        feedback_notes = st.text_area("Additional Notes (optional)")

        if st.button("Submit Feedback", type="primary"):
            # Record feedback
            feedback = {
                "timestamp": datetime.now(),
                "request": selected["request"],
                "category": selected["category"],
                "feedback_type": feedback_type,
                "notes": feedback_notes,
            }
            st.session_state.feedback_log.append(feedback)

            # Record to metrics
            if "False Positive" in feedback_type:
                st.session_state.metrics_exporter.record_false_positive(
                    selected["category"]
                )

            st.session_state.metrics_exporter.record_feedback(
                feedback_type=feedback_type.split()[0], category=selected["category"]
            )

            st.success("Feedback submitted successfully!")
            st.rerun()

elif page == "✅ Rule Approval System":
    st.header("Rule Approval System")
    st.markdown("Review and approve automatically generated WAF rules")

    # Generate sample pending rules
    if len(st.session_state.pending_rules) == 0:
        st.session_state.pending_rules = [
            {
                "id": 1,
                "pattern": r"(?i)(union.*select|select.*from.*where)",
                "category": "SQLi",
                "confidence": 0.92,
                "source": "ML Auto-Generated",
                "created": datetime.now() - timedelta(hours=2),
                "attacks_matched": 45,
            },
            {
                "id": 2,
                "pattern": r"<script[^>]*>.*?</script>",
                "category": "XSS",
                "confidence": 0.88,
                "source": "Pattern Analysis",
                "created": datetime.now() - timedelta(hours=5),
                "attacks_matched": 23,
            },
            {
                "id": 3,
                "pattern": r"(?i)(exec|system|passthru|shell_exec)\s*\(",
                "category": "RCE",
                "confidence": 0.95,
                "source": "Zero-Day Detection",
                "created": datetime.now() - timedelta(hours=1),
                "attacks_matched": 12,
            },
        ]

    # Display pending rules
    st.subheader(f"Pending Rules ({len(st.session_state.pending_rules)})")

    for rule in st.session_state.pending_rules:
        with st.expander(
            f"Rule #{rule['id']} - {rule['category']} ({rule['confidence']:.0%} confidence)"
        ):
            col1, col2 = st.columns([2, 1])

            with col1:
                st.code(rule["pattern"], language="regex")
                st.write(f"**Category:** {rule['category']}")
                st.write(f"**Source:** {rule['source']}")
                st.write(
                    f"**Created:** {rule['created'].strftime('%Y-%m-%d %H:%M:%S')}"
                )
                st.write(f"**Attacks Matched:** {rule['attacks_matched']}")

            with col2:
                st.metric("Confidence", f"{rule['confidence']:.0%}")

                # Test pattern
                st.subheader("Test Pattern")
                test_input = st.text_input(
                    f"Test input (Rule #{rule['id']})", key=f"test_{rule['id']}"
                )

                if test_input:
                    import re

                    match = re.search(rule["pattern"], test_input)
                    if match:
                        st.success(f"✅ MATCH: {match.group()}")
                    else:
                        st.info("❌ No match")

            # Approval actions
            col1, col2, col3 = st.columns(3)

            with col1:
                if st.button(
                    f"✅ Approve", key=f"approve_{rule['id']}", type="primary"
                ):
                    st.session_state.metrics_exporter.record_rule_update(
                        rule_type=rule["category"], source="admin", approved=True
                    )
                    st.session_state.pending_rules.remove(rule)
                    st.success(f"Rule #{rule['id']} approved!")
                    st.rerun()

            with col2:
                if st.button(f"❌ Reject", key=f"reject_{rule['id']}"):
                    st.session_state.metrics_exporter.record_rule_update(
                        rule_type=rule["category"], source="admin", approved=False
                    )
                    st.session_state.pending_rules.remove(rule)
                    st.warning(f"Rule #{rule['id']} rejected")
                    st.rerun()

            with col3:
                if st.button(f"✏️ Edit", key=f"edit_{rule['id']}"):
                    st.info("Edit functionality coming soon...")

elif page == "⚠️ False Positive Management":
    st.header("False Positive Management")
    st.markdown("Track and manage false positive detections")

    # FP statistics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total FPs (24h)", UNKNOWN)
    with col2:
        st.metric("FP Rate (offline test)", OFFLINE_FPR)
    with col3:
        st.metric("Resolved FPs", UNKNOWN)
    with col4:
        session_fp_reports = sum(
            1
            for entry in st.session_state.feedback_log
            if "False Positive" in entry.get("feedback_type", "")
        )
        st.metric("FPs Flagged (this session)", str(session_fp_reports))

    st.caption(
        f"{OFFLINE_SOURCE} Live FP counts require Prometheus wiring; the session "
        "counter reflects only reviews submitted in this browser session."
    )

    # FP timeline
    st.subheader("False Positive Timeline")
    st.caption(SAMPLE_DATA_NOTE)

    fp_data = pd.DataFrame(
        {
            "date": pd.date_range(start="2025-12-25", end="2026-01-01", freq="D"),
            "sqli": [8, 6, 7, 5, 4, 6, 5, 3],
            "xss": [5, 4, 6, 3, 2, 4, 3, 2],
            "rce": [2, 1, 2, 1, 1, 2, 1, 1],
            "other": [3, 2, 3, 2, 1, 2, 2, 1],
        }
    )

    fig = px.bar(
        fp_data,
        x="date",
        y=["sqli", "xss", "rce", "other"],
        title="False Positives by Category (Last 7 Days)",
        labels={"value": "Count", "date": "Date", "variable": "Category"},
    )

    st.plotly_chart(fig, use_container_width=True)

    # Report false positive
    st.subheader("Report False Positive")

    with st.form("fp_report"):
        col1, col2 = st.columns(2)

        with col1:
            fp_request = st.text_area("Request that was incorrectly blocked")
            fp_category = st.selectbox(
                "Detected as", ["SQLi", "XSS", "RCE", "SSRF", "Path Traversal", "Other"]
            )

        with col2:
            fp_actual_category = st.selectbox(
                "Actually was",
                ["Benign", "SQLi", "XSS", "RCE", "SSRF", "Path Traversal"],
            )
            fp_description = st.text_area("Description/Context")

        submitted = st.form_submit_button(
            "Submit False Positive Report", type="primary"
        )

        if submitted:
            st.session_state.metrics_exporter.record_false_positive(
                category=fp_category, corrected_by="admin"
            )
            st.success("False positive recorded to the metrics exporter.")
            st.caption("Recording a report does not trigger retraining.")

elif page == "🤖 Model Management":
    st.header("Model Management")

    # Model status
    predictor = st.session_state.predictor

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("ML Layer Posture", ML_POSTURE)
        st.metric("Model Type", "XGBoost + Isolation Forest")

    with col2:
        st.metric("Accuracy (offline test)", OFFLINE_ACCURACY)
        st.metric("False Positive Rate (offline test)", OFFLINE_FPR)

    with col3:
        st.metric("Ensemble F1 (offline test)", OFFLINE_F1)
        st.metric("Last Trained", report_age(TRAINING_REPORT))

    st.caption(f"{ML_POSTURE_DETAIL} {OFFLINE_SOURCE}")

    # Retraining
    st.subheader("Model Retraining")

    retrain_reason = st.selectbox(
        "Retraining Trigger",
        [
            "Manual",
            "False Positive Accumulation",
            "False Negative Detected",
            "Accuracy Degradation",
            "New Attack Patterns",
        ],
    )

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔄 Trigger Retraining", type="primary"):
            st.session_state.metrics_exporter.record_model_update(
                trigger=retrain_reason, success=True
            )
            st.info(
                "Retraining request recorded. This page does not run training - "
                "run the training pipeline, then reload for updated scores from "
                f"{TRAINING_REPORT_PATH.as_posix()}."
            )

    with col2:
        if st.button("📥 Export Model"):
            st.info("Model export is not implemented yet.")

    # Feature importance
    st.subheader("Top Features by Importance")
    st.caption(SAMPLE_DATA_NOTE + " These weights are not read from the trained model.")

    feature_importance = pd.DataFrame(
        {
            "feature": [
                "Query complexity",
                "SQL keywords",
                "Script tags",
                "Special characters",
                "URL encoding",
                "Path traversal patterns",
                "Command injection patterns",
                "Request length",
                "Entropy",
                "Unusual characters",
            ],
            "importance": [0.18, 0.15, 0.12, 0.10, 0.09, 0.08, 0.07, 0.06, 0.08, 0.07],
        }
    )

    fig = px.bar(
        feature_importance,
        x="importance",
        y="feature",
        orientation="h",
        title="Feature Importance Analysis",
    )

    st.plotly_chart(fig, use_container_width=True)

elif page == "📈 Performance Analytics":
    st.header("Performance Analytics")
    st.warning(
        "This page is not wired to live telemetry. Latency and throughput are "
        "unmeasured here - scrape /waf/metrics from waf/server.py for real numbers."
    )

    # Performance metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Avg Latency", UNKNOWN)
    with col2:
        st.metric("P95 Latency", UNKNOWN)
    with col3:
        st.metric("P99 Latency", UNKNOWN)
    with col4:
        st.metric("Throughput", UNKNOWN)

    # Latency distribution
    st.subheader("Latency Distribution (Last Hour)")
    st.caption("Randomly generated illustration of chart shape - not measured latency.")

    import numpy as np

    latency_samples = np.concatenate(
        [
            np.random.gamma(2, 1.5, 800),  # Most requests
            np.random.gamma(4, 2, 150),  # Some slower
            np.random.gamma(6, 1.5, 50),  # Few outliers
        ]
    )

    fig = px.histogram(
        latency_samples,
        nbins=50,
        title="Request Latency Distribution",
        labels={"value": "Latency (ms)", "count": "Frequency"},
    )
    fig.add_vline(x=5, line_dash="dash", line_color="red", annotation_text="5ms target")

    st.plotly_chart(fig, use_container_width=True)

    # Throughput over time
    st.subheader("Throughput Over Time")
    st.caption(SAMPLE_DATA_NOTE)

    throughput_data = pd.DataFrame(
        {
            "timestamp": pd.date_range(start="2026-01-01", periods=24, freq="H"),
            "throughput": [
                250,
                280,
                260,
                290,
                310,
                340,
                320,
                300,
                280,
                290,
                310,
                330,
                350,
                320,
                310,
                300,
                290,
                310,
                330,
                350,
                320,
                300,
                290,
                280,
            ],
        }
    )

    fig = px.line(
        throughput_data,
        x="timestamp",
        y="throughput",
        title="Throughput (Requests/Second)",
    )
    fig.add_hline(
        y=200, line_dash="dash", line_color="green", annotation_text="Target: 200 req/s"
    )

    st.plotly_chart(fig, use_container_width=True)

elif page == "🎯 Live Testing":
    st.header("Live Testing Interface")
    st.markdown("Test the WAF with custom payloads")

    # Test input
    test_payload = st.text_area("Enter test payload:", value="' OR 1=1--", height=100)

    col1, col2 = st.columns(2)

    with col1:
        test_type = st.radio(
            "Request Type", ["Query Parameter", "POST Body", "URL Path", "Header"]
        )

    with col2:
        show_features = st.checkbox("Show extracted features", value=False)

    if st.button("🧪 Test Payload", type="primary"):
        predictor = st.session_state.predictor

        # Run prediction
        with st.spinner("Analyzing payload..."):
            result = predictor.predict(query=test_payload)

        # Display results
        col1, col2, col3 = st.columns(3)

        with col1:
            if result.is_malicious:
                st.error(f"🚨 **BLOCKED**")
            else:
                st.success(f"✅ **ALLOWED**")

        with col2:
            st.metric("Confidence", f"{result.confidence:.2%}")

        with col3:
            st.metric("Category", result.unified_category.upper())

        st.metric("Latency", f"{result.latency_ms:.2f}ms")

        # Feature extraction
        if show_features:
            st.subheader("Extracted Features")
            st.json(
                {
                    "length": len(test_payload),
                    "sql_keywords": (
                        "SELECT, UNION" if "select" in test_payload.lower() else "None"
                    ),
                    "special_chars": "', --, OR",
                    "entropy": "4.2",
                    "url_encoded": "False",
                }
            )

elif page == "⚙️ System Configuration":
    st.header("System Configuration")

    # Configuration sections
    st.subheader("Detection Thresholds")

    col1, col2 = st.columns(2)

    with col1:
        ml_threshold = st.slider("ML Confidence Threshold", 0.0, 1.0, 0.7, 0.05)
        anomaly_threshold = st.slider("Anomaly Score Threshold", 0.0, 1.0, 0.5, 0.05)

    with col2:
        rate_limit = st.number_input("Rate Limit (req/min)", value=100)
        session_timeout = st.number_input("Session Timeout (minutes)", value=30)

    st.subheader("Alert Configuration")

    alert_fp_threshold = st.slider("Alert on FP rate above (%)", 0, 20, 5)
    alert_latency_threshold = st.slider("Alert on latency above (ms)", 0, 50, 10)

    if st.button("💾 Save Configuration", type="primary"):
        st.info(
            "This page does not persist configuration. Set thresholds in "
            "config/settings.py and the WAF_* environment variables."
        )

# Footer
st.markdown("---")
st.markdown(
    """
<div style='text-align: center; color: gray; padding: 1rem;'>
    <strong>DECEPTICON WAF</strong> v2.0.0-secure |
    Naval SWAVLAMBAN 2025 Challenge 3
</div>
""",
    unsafe_allow_html=True,
)
st.caption(
    "Model-quality figures on this page are read at runtime from "
    f"{TRAINING_REPORT_PATH.as_posix()} and describe an offline held-out test set. "
    "Anything shown as 'n/a' is not measured by this dashboard."
)
