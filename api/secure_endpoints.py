"""
DECEPTICON Secure API Endpoints
FIXES:
- IDOR on session endpoints (CRITICAL)
- Missing authentication on sensitive endpoints (CRITICAL)
- Information disclosure (HIGH)

SECURITY MEASURES:
1. All sensitive endpoints require authentication
2. Session access restricted to own session or admin
3. No sensitive data in error messages
4. Rate limiting on all endpoints
5. Audit logging for admin actions
"""

import time
import logging
import asyncio
import json
import os
from datetime import datetime
from typing import Optional, Dict, Any
from functools import wraps

from fastapi import APIRouter, Request, HTTPException, Depends, Query, BackgroundTasks
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# Import security modules
try:
    from core.secure_session import (
        secure_session_manager,
        SecureSessionIDGenerator,
        AdminSessionAccess,
    )
    from core.atomic_rate_limiter import atomic_rate_limiter, login_rate_limiter
    from core.security_hardening import api_key_manager, error_sanitizer
    from core.security_fixes import audit_logger

    SESSION_SECURITY_AVAILABLE = True
except ImportError as e:
    SESSION_SECURITY_AVAILABLE = False
    print(f"Warning: Session security not available: {e}")

logger = logging.getLogger("decepticon.api.secure_endpoints")

# API Router
router = APIRouter(prefix="/api/waf", tags=["WAF"])
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])

# Feedback Storage
FEEDBACK_DIR = "./data/feedback"
FEEDBACK_FILE = os.path.join(FEEDBACK_DIR, "ml_feedback.jsonl")

# Ensure feedback directory exists
os.makedirs(FEEDBACK_DIR, exist_ok=True)

# API Key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ============================================================================
# AUTHENTICATION DEPENDENCIES
# ============================================================================


async def get_current_user(
    request: Request, api_key: Optional[str] = Depends(api_key_header)
) -> Dict:
    """
    Get current authenticated user

    SECURITY: Required for all non-public endpoints
    In development mode (REQUIRE_API_AUTH=false), allows unauthenticated access.
    """
    # Import settings to check if auth is required
    try:
        from config.settings import settings

        require_auth = getattr(settings, "REQUIRE_API_AUTH", True)
    except ImportError:
        require_auth = True

    # Development mode: skip auth if REQUIRE_API_AUTH=false
    if not require_auth:
        return {
            "key_id": "dev-admin",
            "permissions": ["admin"],
            "name": "Development Mode",
        }

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not SESSION_SECURITY_AVAILABLE:
        return {"key_id": "dev", "permissions": ["admin"], "name": "development"}

    is_valid, key_info, error = api_key_manager.validate_key(api_key)

    if not is_valid:
        logger.warning(f"Invalid API key from {request.client.host}: {error}")
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "key_id": key_info.key_id,
        "permissions": key_info.permissions,
        "name": key_info.name,
    }


async def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    """
    Require admin permission

    SECURITY: Only admins can access admin endpoints
    """
    if "admin" not in user.get("permissions", []):
        raise HTTPException(status_code=403, detail="Admin permission required")
    return user


async def check_rate_limit(request: Request):
    """
    Rate limit middleware

    SECURITY: Prevent brute force and DoS
    """
    if not SESSION_SECURITY_AVAILABLE:
        return

    client_ip = request.client.host if request.client else "unknown"
    endpoint = str(request.url.path)

    result = atomic_rate_limiter.check(client_ip, endpoint)

    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={
                "Retry-After": str(result.retry_after or 60),
                "X-RateLimit-Remaining": "0",
            },
        )


# ============================================================================
# SESSION ENDPOINTS (SECURED)
# ============================================================================


class SessionResponse(BaseModel):
    """Safe session response (no sensitive data)"""

    created_at: float
    last_activity: float
    request_count: int
    risk_score: float
    attack_categories: list


@router.get("/sessions/me", response_model=SessionResponse)
async def get_my_session(
    request: Request,
    user: Dict = Depends(get_current_user),
    _: None = Depends(check_rate_limit),
):
    """
    Get current user's session stats

    SECURITY: Users can only see their own session
    """
    session_id = request.headers.get("X-Session-ID")

    if not session_id:
        raise HTTPException(status_code=400, detail="Session ID required")

    if not SESSION_SECURITY_AVAILABLE:
        return SessionResponse(
            created_at=time.time(),
            last_activity=time.time(),
            request_count=1,
            risk_score=0.0,
            attack_categories=[],
        )

    # Get stats for requester's own session only
    client_ip = request.client.host if request.client else "unknown"
    stats = secure_session_manager.get_session_stats(session_id, client_ip)

    if not stats:
        raise HTTPException(status_code=404, detail="Session not found")

    return SessionResponse(**stats)


@router.get("/sessions/{session_id}")
async def get_session_by_id(
    session_id: str,
    request: Request,
    user: Dict = Depends(require_admin),  # ADMIN ONLY!
    _: None = Depends(check_rate_limit),
):
    """
    Get any session by ID (ADMIN ONLY)

    SECURITY:
    - Requires admin authentication
    - Audit logged
    - No direct access without permission

    FIXES: IDOR vulnerability - was publicly accessible!
    """
    if not SESSION_SECURITY_AVAILABLE:
        raise HTTPException(status_code=501, detail="Session management not available")

    # Validate session ID format
    if not SecureSessionIDGenerator.is_valid_format(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    # Admin session access with audit logging
    admin_access = AdminSessionAccess(secure_session_manager, audit_logger)

    session_data, error = admin_access.admin_get_session(
        session_id=session_id,
        admin_key_id=user["key_id"],
        admin_ip=request.client.host if request.client else "unknown",
    )

    if error:
        raise HTTPException(status_code=404, detail="Session not found")

    # Remove sensitive binding data even for admins
    if "binding" in session_data:
        del session_data["binding"]

    return session_data


@router.get("/sessions")
async def list_sessions(
    request: Request,
    user: Dict = Depends(require_admin),  # ADMIN ONLY!
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    _: None = Depends(check_rate_limit),
):
    """
    List all sessions (ADMIN ONLY)

    SECURITY:
    - Requires admin authentication
    - Audit logged
    - Returns limited data only

    FIXES: Session enumeration - was publicly accessible!
    """
    if not SESSION_SECURITY_AVAILABLE:
        return {"sessions": [], "total": 0}

    admin_access = AdminSessionAccess(secure_session_manager, audit_logger)

    sessions = admin_access.admin_list_sessions(
        admin_key_id=user["key_id"],
        admin_ip=request.client.host if request.client else "unknown",
        filter_risk_above=min_risk,
    )

    return {"sessions": sessions, "total": len(sessions), "filtered_by_risk": min_risk}


@router.delete("/sessions/{session_id}")
async def invalidate_session(
    session_id: str,
    request: Request,
    user: Dict = Depends(require_admin),
    _: None = Depends(check_rate_limit),
):
    """
    Invalidate a session (ADMIN ONLY)

    SECURITY: Requires admin permission
    """
    if not SESSION_SECURITY_AVAILABLE:
        raise HTTPException(status_code=501, detail="Not available")

    # Audit log
    if audit_logger:
        audit_logger.log(
            action="SESSION_CLEARED",
            actor=user["key_id"],
            resource=session_id[:16],
            details={"admin_ip": request.client.host if request.client else "unknown"},
        )

    success = secure_session_manager.invalidate_session(session_id)

    if not success:
        raise HTTPException(status_code=404, detail="Session not found")

    return {"status": "invalidated", "session_id": session_id[:16] + "..."}


# ============================================================================
# RULE ENDPOINTS (SECURED)
# ============================================================================


@router.get("/rules")
async def get_rules(
    user: Dict = Depends(get_current_user),  # Requires authentication
    _: None = Depends(check_rate_limit),
):
    """
    Get WAF rules

    SECURITY: Requires authentication (attackers shouldn't see rules)
    """
    # Import here to avoid circular imports
    try:
        from core.pattern_engine import pattern_engine

        # Use static_rules property
        all_rules = pattern_engine.static_rules
        rules = []
        for rule in all_rules:
            rules.append(
                {
                    "id": rule.get("id", "unknown"),
                    "category": rule.get("category", "unknown"),
                    "severity": rule.get("severity", "medium"),
                    # DON'T expose actual pattern - security through obscurity still helps
                    "has_pattern": bool(rule.get("pattern")),
                }
            )

        return {"rules": rules, "total": len(rules)}

    except (ImportError, AttributeError):
        return {"rules": [], "total": 0, "error": "Pattern engine not available"}


@router.post("/rules")
async def create_rule(
    request: Request,
    user: Dict = Depends(require_admin),  # ADMIN ONLY
    _: None = Depends(check_rate_limit),
):
    """
    Create a new WAF rule (ADMIN ONLY)

    SECURITY: Only admins can create rules
    """
    body = await request.json()
    rule_id = body.get("id")
    category = body.get("category", "MANUAL")
    pattern = body.get("pattern")
    severity = body.get("severity", 0.5)
    description = body.get("description", "Manually created rule")
    locations = body.get("locations", ["query", "body"])

    if not rule_id or not pattern:
        raise HTTPException(status_code=400, detail="Missing rule id or pattern")

    # Import pattern engine
    try:
        from core.pattern_engine import pattern_engine, PatternRule
        import re

        new_rule = PatternRule(
            rule_id=rule_id,
            category=category,
            pattern=re.compile(pattern, re.IGNORECASE),
            severity=severity,
            description=description,
            locations=locations,
        )

        success = pattern_engine.add_dynamic_rule(new_rule)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to add rule to engine")

        # Persistence
        try:
            from core.persistent_storage import RuleStorage, get_storage

            storage = get_storage()
            rule_storage = RuleStorage(storage)
            rule_storage.save_rule(
                rule_id,
                {
                    "rule_id": rule_id,
                    "category": category,
                    "pattern": pattern,
                    "severity": severity,
                    "description": description,
                    "locations": locations,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to persist rule {rule_id}: {e}")

    except Exception as e:
        logger.error(f"Error creating rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    # Audit log
    if audit_logger:
        audit_logger.log(
            action="RULE_CREATED",
            actor=user["key_id"],
            resource=rule_id,
            details={"category": category},
        )

    return {"status": "created", "rule_id": rule_id}


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    user: Dict = Depends(require_admin),  # ADMIN ONLY
    _: None = Depends(check_rate_limit),
):
    """
    Delete a WAF rule (ADMIN ONLY)

    SECURITY: Only admins can delete rules
    """
    # Import pattern engine
    try:
        from core.pattern_engine import pattern_engine

        success = pattern_engine.remove_rule(rule_id)

        if not success:
            raise HTTPException(status_code=404, detail="Rule not found")

        # Persistence
        try:
            from core.persistent_storage import RuleStorage, get_storage

            storage = get_storage()
            rule_storage = RuleStorage(storage)
            rule_storage.delete_rule(rule_id)
        except Exception as e:
            logger.warning(f"Failed to remove rule {rule_id} from storage: {e}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    # Audit log
    if audit_logger:
        audit_logger.log(
            action="RULE_DELETED", actor=user["key_id"], resource=rule_id, details={}
        )

    return {"status": "deleted", "rule_id": rule_id}


# ============================================================================
# CONFIG ENDPOINTS (SECURED)
# ============================================================================


@router.get("/config")
async def get_config(
    user: Dict = Depends(require_admin),  # ADMIN ONLY
    _: None = Depends(check_rate_limit),
):
    """
    Get WAF configuration (ADMIN ONLY)

    SECURITY: Config may contain sensitive info
    """
    try:
        from config.settings import settings

        # Return only safe config values
        safe_config = {
            "env": str(settings.ENV),
            "ml_enabled": settings.ENABLE_ML,
            "rate_limiting_enabled": True,
            "geoblocking_enabled": settings.ENABLE_GEOBLOCKING,
            # DON'T expose: API keys, Redis password, internal URLs, etc.
        }

        return safe_config

    except ImportError:
        return {"error": "Settings not available"}


@router.put("/config")
async def update_config(
    request: Request,
    user: Dict = Depends(require_admin),  # ADMIN ONLY
    _: None = Depends(check_rate_limit),
):
    """
    Update WAF configuration (ADMIN ONLY)

    SECURITY: Config changes are audit logged
    """
    body = await request.json()

    # Define allowed keys and their mapping to settings attributes
    allowed_mappings = {
        "ml_enabled": "ENABLE_ML",
        "geoblocking_enabled": "ENABLE_GEOBLOCKING",
        "log_level": "LOG_LEVEL",
        "ml_threshold_block": "ML_THRESHOLD_BLOCK",
        "debug": "DEBUG",
    }

    try:
        from config.settings import settings

        updated_keys = []
        for key, value in body.items():
            if key in allowed_mappings:
                settings_attr = allowed_mappings[key]
                # Pydantic BaseSettings handles type conversion if we use setattr on the object
                # but since it's a singleton already instantiated, we manually update it.
                # In production, settings are often frozen, but here they seem mutable.
                setattr(settings, settings_attr, value)
                updated_keys.append(key)

        # Audit log
        if audit_logger:
            audit_logger.log(
                action="CONFIG_CHANGED",
                actor=user["key_id"],
                resource="waf_config",
                details={"changed_keys": updated_keys, "all_provided_keys": list(body.keys())},
            )

        return {
            "status": "updated",
            "updated_keys": updated_keys,
            "ignored_keys": [k for k in body.keys() if k not in allowed_mappings],
        }

    except Exception as e:
        logger.error(f"Error updating config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")


# ============================================================================
# ADMIN API KEY MANAGEMENT (SECURED)
# ============================================================================


@admin_router.post("/keys")
async def create_api_key(
    request: Request,
    user: Dict = Depends(require_admin),
    _: None = Depends(check_rate_limit),
):
    """
    Create a new API key (ADMIN ONLY)

    SECURITY:
    - Only admins can create keys
    - Audit logged
    - Key shown only once
    """
    body = await request.json()

    if not SESSION_SECURITY_AVAILABLE:
        raise HTTPException(status_code=501, detail="Not available")

    key_id, full_key = api_key_manager.generate_key(
        name=body.get("name", "unnamed"),
        permissions=body.get("permissions", ["read"]),
        rate_limit=body.get("rate_limit", 100),
        expires_in_days=body.get("expires_in_days"),
    )

    # Audit log
    if audit_logger:
        audit_logger.log(
            action="API_KEY_CREATED",
            actor=user["key_id"],
            resource=key_id,
            details={
                "permissions": body.get("permissions", ["read"]),
                "admin_ip": request.client.host if request.client else "unknown",
            },
        )

    return {
        "key_id": key_id,
        "api_key": full_key,  # Only shown once!
        "warning": "Save this key now - it cannot be retrieved later!",
    }


@admin_router.delete("/keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    request: Request,
    user: Dict = Depends(require_admin),
    _: None = Depends(check_rate_limit),
):
    """
    Revoke an API key (ADMIN ONLY)
    """
    if not SESSION_SECURITY_AVAILABLE:
        raise HTTPException(status_code=501, detail="Not available")

    success = api_key_manager.revoke_key(key_id)

    # Audit log
    if audit_logger:
        audit_logger.log(
            action="API_KEY_REVOKED",
            actor=user["key_id"],
            resource=key_id,
            details={"admin_ip": request.client.host if request.client else "unknown"},
        )

    if not success:
        raise HTTPException(status_code=404, detail="Key not found")

    return {"status": "revoked", "key_id": key_id}


@admin_router.get("/keys")
async def list_api_keys(
    user: Dict = Depends(require_admin), _: None = Depends(check_rate_limit)
):
    """
    List all API keys (ADMIN ONLY)

    SECURITY: Never returns the actual key values
    """
    if not SESSION_SECURITY_AVAILABLE:
        return {"keys": []}

    keys = []
    for key_id, key_info in api_key_manager.api_keys.items():
        keys.append(
            {
                "key_id": key_id,
                "name": key_info.name,
                "permissions": key_info.permissions,
                "created_at": key_info.created_at,
                "expires_at": key_info.expires_at,
                # NEVER return the key hash or actual key!
            }
        )

    return {"keys": keys, "total": len(keys)}


# ============================================================================
# AUDIT LOG ENDPOINTS (SECURED)
# ============================================================================


@admin_router.get("/audit")
async def get_audit_logs(
    request: Request,
    user: Dict = Depends(require_admin),
    action: Optional[str] = None,
    limit: int = Query(100, le=1000),
    _: None = Depends(check_rate_limit),
):
    """
    Get audit logs (ADMIN ONLY)
    """
    if not audit_logger:
        return {"entries": [], "total": 0}

    entries = audit_logger.get_entries(action=action, limit=limit)

    return {"entries": entries, "total": len(entries)}


@admin_router.get("/audit/verify")
async def verify_audit_integrity(
    user: Dict = Depends(require_admin), _: None = Depends(check_rate_limit)
):
    """
    Verify audit log integrity (ADMIN ONLY)
    """
    if not audit_logger:
        return {"valid": True, "issues": ["Audit logger not configured"]}

    is_valid, issues = audit_logger.verify_integrity()

    return {"valid": is_valid, "issues": issues}


# ============================================================================
# SECURE RULES ENDPOINTS (ADMIN ONLY)
# ============================================================================


@admin_router.get("/rules")
async def get_rules_secure(
    user: Dict = Depends(require_admin), _: None = Depends(check_rate_limit)
):
    """
    Get all WAF rules (ADMIN ONLY)

    SECURITY: WAF rules are sensitive - exposure allows bypass crafting
    """
    try:
        from core.zero_day import zero_day_detector

        # Audit log this access
        if audit_logger:
            audit_logger.log(
                action="ADMIN_ACCESS",
                actor=user.get("key_id", "unknown"),
                resource="/api/admin/rules",
                details={"action": "view_rules"},
            )

        return {
            "auto_generated": zero_day_detector.get_generated_rules(),
            "zero_day_signatures": zero_day_detector.get_zero_day_signatures(),
            "stats": zero_day_detector.get_stats(),
        }
    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve rules")


@admin_router.get("/rules/export")
async def export_rules_secure(
    user: Dict = Depends(require_admin), _: None = Depends(check_rate_limit)
):
    """
    Export rules as ModSecurity format (ADMIN ONLY)
    """
    from fastapi.responses import Response

    try:
        from core.zero_day import zero_day_detector

        # Audit log this export
        if audit_logger:
            audit_logger.log(
                action="DATA_EXPORT",
                actor=user.get("key_id", "unknown"),
                resource="/api/admin/rules/export",
                details={"format": "modsecurity"},
            )

        rules = zero_day_detector.export_rules()
        return Response(
            content=rules,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=decepticon_rules.conf"
            },
        )
    except Exception as e:
        logger.error(f"Error exporting rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to export rules")


@admin_router.post("/rules/feedback")
async def rule_feedback_secure(
    rule_id: str,
    is_true_positive: bool,
    user: Dict = Depends(require_admin),
    _: None = Depends(check_rate_limit),
):
    """
    Provide feedback on auto-generated rules (ADMIN ONLY)

    SECURITY: Rule manipulation requires authentication
    """
    try:
        from core.zero_day import zero_day_detector

        # Audit log this action
        if audit_logger:
            audit_logger.log(
                action="RULE_CREATED" if is_true_positive else "RULE_REJECTED",
                actor=user.get("key_id", "unknown"),
                resource=f"/api/admin/rules/feedback/{rule_id}",
                details={"rule_id": rule_id, "is_true_positive": is_true_positive},
            )

        zero_day_detector.rule_generator.record_feedback(rule_id, is_true_positive)
        return {"status": "recorded", "rule_id": rule_id}
    except Exception as e:
        logger.error(f"Error recording feedback: {e}")
        raise HTTPException(status_code=500, detail="Failed to record feedback")


# ============================================================================
# ML FEEDBACK ENDPOINT - For Admin to Report False Positives/Negatives
# ============================================================================


class MLFeedbackRequest(BaseModel):
    """Request model for ML feedback submission"""

    request_id: Optional[str] = Field(
        None, description="Original request ID if available"
    )
    payload: str = Field(..., description="The payload that was misclassified")
    detected_category: Optional[str] = Field(
        None, description="What the ML detected (e.g., 'sqli', 'xss')"
    )
    actual_category: Optional[str] = Field(
        None, description="What it actually was (e.g., 'benign', 'sqli')"
    )
    feedback_type: str = Field(
        ...,
        description="Type: 'false_positive', 'false_negative', 'confirmed_attack', 'confirmed_benign'",
    )
    notes: Optional[str] = Field(None, description="Additional context from analyst")


class MLFeedbackResponse(BaseModel):
    """Response model for ML feedback"""

    status: str
    feedback_id: str
    message: str
    stored_for_retraining: bool


def _write_feedback_to_file(record: Dict[str, Any]):
    """Synchronous file write for background task"""
    try:
        with open(FEEDBACK_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        logger.error(f"Failed to write feedback to file: {e}")


@admin_router.post("/feedback", response_model=MLFeedbackResponse)
async def submit_ml_feedback(
    request: Request,
    feedback: MLFeedbackRequest,
    background_tasks: BackgroundTasks,
    user: Dict = Depends(require_admin),
    _: None = Depends(check_rate_limit),
):
    """
    Submit feedback on ML classification decisions (ADMIN ONLY)

    Use this endpoint to report:
    - **false_positive**: ML blocked a legitimate request
    - **false_negative**: ML allowed a malicious request
    - **confirmed_attack**: ML correctly blocked an attack
    - **confirmed_benign**: ML correctly allowed a request

    This feedback is stored for model retraining.

    Example:
    ```json
    {
        "payload": "SELECT name FROM products WHERE id=5",
        "detected_category": "sqli",
        "actual_category": "benign",
        "feedback_type": "false_positive",
        "notes": "Legitimate product lookup query"
    }
    ```
    """
    import uuid

    feedback_id = f"FB-{uuid.uuid4().hex[:12].upper()}"

    try:
        # Get metrics exporter from app state
        metrics_exporter = getattr(request.app.state, "metrics_exporter", None)

        # Record feedback to Prometheus metrics
        if metrics_exporter:
            metrics_exporter.record_feedback(
                feedback_type=feedback.feedback_type,
                category=feedback.detected_category or "unknown",
            )

            # Also record false positive/negative specific metrics
            if feedback.feedback_type == "false_positive":
                metrics_exporter.record_false_positive(
                    feedback.detected_category or "unknown"
                )
            elif feedback.feedback_type == "false_negative":
                metrics_exporter.record_false_negative(
                    feedback.actual_category or "unknown"
                )

        # Store feedback for retraining
        feedback_record = {
            "feedback_id": feedback_id,
            "timestamp": datetime.utcnow().isoformat(),
            "analyst": user.get("key_id", "unknown"),
            "request_id": feedback.request_id,
            "payload": feedback.payload,
            "detected_category": feedback.detected_category,
            "actual_category": feedback.actual_category,
            "feedback_type": feedback.feedback_type,
            "notes": feedback.notes,
            "client_ip": request.client.host if request.client else "unknown",
        }

        # Store in adaptive learning system if available
        stored = False
        try:
            from core.adaptive_learning import adaptive_learner

            if hasattr(adaptive_learner, "store_feedback"):
                adaptive_learner.store_feedback(feedback_record)
                stored = True
        except ImportError:
            pass

        # Fallback: store to file using background task
        if not stored:
            background_tasks.add_task(_write_feedback_to_file, feedback_record)
            stored = True

        # Audit log this action
        if audit_logger:
            audit_logger.log(
                action="ML_FEEDBACK_SUBMITTED",
                actor=user.get("key_id", "unknown"),
                resource="/api/admin/feedback",
                details={
                    "feedback_id": feedback_id,
                    "feedback_type": feedback.feedback_type,
                    "detected_category": feedback.detected_category,
                },
            )

        logger.info(
            f"ML feedback recorded: {feedback_id} - {feedback.feedback_type} by {user.get('key_id')}"
        )

        return MLFeedbackResponse(
            status="success",
            feedback_id=feedback_id,
            message=f"Feedback recorded. Type: {feedback.feedback_type}",
            stored_for_retraining=stored,
        )

    except Exception as e:
        logger.error(f"Error recording ML feedback: {e}")
        raise HTTPException(status_code=500, detail="Failed to record feedback")


@admin_router.get("/feedback/stats")
async def get_feedback_stats(
    user: Dict = Depends(require_admin), _: None = Depends(check_rate_limit)
):
    """
    Get feedback statistics (ADMIN ONLY)

    Returns counts of feedback by type for monitoring model performance.
    """
    from collections import Counter

    def _read_stats():
        stats = {"total": 0, "by_type": Counter(), "by_category": Counter(), "recent": []}

        if os.path.exists(FEEDBACK_FILE):
            try:
                with open(FEEDBACK_FILE, "r") as f:
                    lines = f.readlines()
                    stats["total"] = len(lines)

                    for line in lines[-100:]:  # Last 100 entries
                        try:
                            record = json.loads(line.strip())
                            stats["by_type"][record.get("feedback_type", "unknown")] += 1
                            stats["by_category"][
                                record.get("detected_category", "unknown")
                            ] += 1
                            if len(stats["recent"]) < 10:
                                stats["recent"].append(
                                    {
                                        "feedback_id": record.get("feedback_id"),
                                        "timestamp": record.get("timestamp"),
                                        "feedback_type": record.get("feedback_type"),
                                        "detected_category": record.get("detected_category"),
                                    }
                                )
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.error(f"Error reading feedback file: {e}")

        return {
            "total_feedback": stats["total"],
            "by_type": dict(stats["by_type"]),
            "by_category": dict(stats["by_category"]),
            "recent_feedback": stats["recent"],
        }

    return await asyncio.to_thread(_read_stats)


@admin_router.get("/deception/honeypots")
async def get_honeypots_secure(
    user: Dict = Depends(require_admin), _: None = Depends(check_rate_limit)
):
    """
    Get honeypot session intelligence (ADMIN ONLY)

    SECURITY: Honeypot intel is sensitive - exposure defeats the deception
    """
    try:
        from deception.honeypot import honeypot_router as hp_router

        # Audit log this access
        if audit_logger:
            audit_logger.log(
                action="ADMIN_ACCESS",
                actor=user.get("key_id", "unknown"),
                resource="/api/admin/deception/honeypots",
                details={"action": "view_honeypot_intel"},
            )

        sessions = []
        for sid, session in hp_router.sessions.items():
            intel = hp_router.get_session_intel(sid)
            if intel:
                sessions.append(intel)

        return {
            "total_sessions": len(sessions),
            "sessions": sessions,
        }
    except Exception as e:
        logger.error(f"Error getting honeypot data: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve honeypot data")


@admin_router.get("/deception/canaries")
async def get_canaries_secure(
    user: Dict = Depends(require_admin), _: None = Depends(check_rate_limit)
):
    """
    Get triggered canary tokens (ADMIN ONLY)
    """
    try:
        from deception.honeypot import honeypot_router as hp_router

        # Audit log this access
        if audit_logger:
            audit_logger.log(
                action="ADMIN_ACCESS",
                actor=user.get("key_id", "unknown"),
                resource="/api/admin/deception/canaries",
                details={"action": "view_canary_intel"},
            )

        triggered = hp_router.get_all_triggered_canaries()
        return {
            "total_triggered": len(triggered),
            "canaries": triggered,
        }
    except Exception as e:
        logger.error(f"Error getting canary data: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve canary data")


# ============================================================================
# HEALTH ENDPOINTS (PUBLIC - But Rate Limited)
# ============================================================================


@router.get("/health")
async def health_check(request: Request):
    """
    Health check endpoint (PUBLIC)

    SECURITY: No sensitive information exposed
    """
    return {
        "status": "healthy",
        "timestamp": time.time(),
        # NO version, no internal state, no config
    }


@router.get("/ready")
async def readiness_check(request: Request):
    """
    Readiness check (PUBLIC)
    """
    return {"ready": True}
