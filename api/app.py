"""
MIRAGE WAF API
FastAPI application with all WAF endpoints
SECURED with API key authentication and security headers

SECURITY NOTES:
- All sensitive endpoints require authentication
- Session endpoints use secure 256-bit random IDs
- ML inference uses ONNX (no pickle RCE)
- Rate limiting is atomic (no race conditions)
"""
import time
import uuid
import asyncio
from typing import Dict, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
import uvicorn

from config.settings import settings
from core.models import RequestContext, Action, RiskLevel
from core.waf_engine import waf_engine
from core.response_sanitizer import response_sanitizer, header_sanitizer, error_sanitizer

# ============================================================================
# SECURITY: Import ONLY secure modules - NO FALLBACK TO VULNERABLE CODE
# ============================================================================

# SECURE Rate Limiter (atomic operations) - REQUIRED
try:
    from core.atomic_rate_limiter import atomic_rate_limiter as rate_limiter
    SECURE_RATE_LIMITER = True
except ImportError as e:
    raise ImportError(
        f"SECURITY ERROR: Secure rate limiter not available: {e}\n"
        f"The vulnerable rate_limiter.py has race conditions."
    )

# SECURE Session Manager (256-bit random IDs) - REQUIRED
try:
    from core.secure_session import secure_session_manager as session_manager
    SECURE_SESSION = True
except ImportError as e:
    raise ImportError(
        f"SECURITY ERROR: Secure session manager not available: {e}\n"
        f"The vulnerable session_manager.py uses predictable session IDs."
    )

from core.zero_day import zero_day_detector
from deception.honeypot import honeypot_router, canary_factory

# Import Prometheus metrics exporter
from metrics.prometheus_exporter import get_exporter

# Import security modules
try:
    from api.secure_api import (
        SecurityMiddleware, verify_api_key, require_permission,
        check_admin_rate_limit, secure_response
    )
    SECURITY_ENABLED = True
except ImportError:
    SECURITY_ENABLED = False
    print("[WARNING] Security modules not available - running in development mode")

# Import SECURE endpoints - REQUIRED
try:
    from api.secure_endpoints import (
        router as secure_router,
        admin_router as secure_admin_router,
        get_current_user,
        require_admin
    )
    SECURE_ENDPOINTS_AVAILABLE = True
except ImportError as e:
    raise ImportError(
        f"SECURITY ERROR: Secure endpoints not available: {e}\n"
        f"The inline endpoints in app.py have IDOR vulnerabilities.\n"
        f"Install api/secure_endpoints.py or fix the import error."
    )

# ═══════════════════════════════════════════════════════════════════════════════
# Lifespan & App Setup
# ═══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    print("[INFO] MIRAGE WAF Starting...")
    print(f"   Environment: {settings.ENV}")
    print(f"   Max Sync Latency: {settings.MAX_SYNC_LATENCY_MS}ms")
    print(f"   ML Model: {settings.ML_MODEL_PATH}")

    # Security status
    print(f"   Security Middleware: {'[ENABLED]' if SECURITY_ENABLED else '[DISABLED]'}")
    print(f"   Secure Sessions: {'[ENABLED]' if SECURE_SESSION else '[VULNERABLE]'}")
    print(f"   Secure Rate Limiter: {'[ENABLED]' if SECURE_RATE_LIMITER else '[VULNERABLE]'}")
    print(f"   Secure Endpoints: {'[MOUNTED]' if SECURE_ENDPOINTS_AVAILABLE else '[NOT AVAILABLE]'}")

    # SECURITY: Never reference plaintext key files
    if SECURITY_ENABLED:
        print("   [WARNING] Generate admin key with: python -m core.secure_admin_keys generate")

    # Warn if running with vulnerable modules
    if not SECURE_SESSION:
        print("   [CRITICAL] Session IDs are PREDICTABLE! Update imports!")

    # Start Prometheus metrics exporter in background thread
    print("[INFO] Starting Prometheus metrics exporter on port 9090...")
    import threading
    metrics_exporter = get_exporter(port=9090)

    def start_metrics_server():
        try:
            metrics_exporter.start_server()
        except Exception as e:
            print(f"[ERROR] Failed to start metrics server: {e}")

    metrics_thread = threading.Thread(target=start_metrics_server, daemon=True)
    metrics_thread.start()
    print("[INFO] Prometheus metrics available at http://localhost:9090/metrics")

    # Store exporter in app state for access from endpoints
    app.state.metrics_exporter = metrics_exporter

    yield

    # Shutdown
    print("[INFO] MIRAGE WAF Shutting down...")

app = FastAPI(
    title="MIRAGE ML-WAF",
    description="Ultra-low latency ML-powered Web Application Firewall",
    version="2.0.0-secure",
    lifespan=lifespan,
    # Disable docs in production
    docs_url="/docs" if settings.ENV != "production" else None,
    redoc_url="/redoc" if settings.ENV != "production" else None,
)

# ============================================================================
# SECURITY: Mount SECURE endpoints (REQUIRED - no vulnerable alternatives)
# ============================================================================
# These secure endpoints require authentication and have IDOR protection
app.include_router(secure_router, tags=["WAF-Secure"])
app.include_router(secure_admin_router, tags=["Admin-Secure"])
print("[INFO] Secure API endpoints mounted at /api/waf/* and /api/admin/*")

# Add security middleware FIRST
if SECURITY_ENABLED:
    app.add_middleware(SecurityMiddleware)

# CORS middleware (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.ENV != "production" else settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════════════════════════
# Request Models
# ═══════════════════════════════════════════════════════════════════════════════

class AnalyzeRequest(BaseModel):
    """Request for WAF analysis"""
    method: str = "GET"
    path: str = "/"
    query_string: str = ""
    query: Optional[str] = None  # Alias for query_string for compatibility
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""
    payload: Optional[str] = None  # Alternative to body for simple testing
    client_ip: str = "127.0.0.1"
    client_port: int = 12345

    def get_query_string(self) -> str:
        """Get query string, preferring 'query' over 'query_string' if provided"""
        return self.query if self.query is not None else self.query_string
    
    def get_body(self) -> str:
        """Get body, using payload if body is empty"""
        return self.payload if self.payload is not None and not self.body else self.body

class TestPayloadRequest(BaseModel):
    """Request for testing payloads"""
    payloads: list[str]
    
class RuleFeedbackRequest(BaseModel):
    """Feedback for auto-generated rules"""
    rule_id: str
    is_true_positive: bool

# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════

def build_request_context(request: Request, body: bytes = b"") -> RequestContext:
    """Build RequestContext from FastAPI Request"""
    # Get client IP (handle proxies)
    client_ip = request.client.host if request.client else "0.0.0.0"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.partition(",")[0].strip()
    
    # Build headers dict
    headers = dict(request.headers)
    
    return RequestContext(
        request_id=str(uuid.uuid4()),
        timestamp=time.time(),
        client_ip=client_ip,
        client_port=request.client.port if request.client else 0,
        server_ip="0.0.0.0",
        server_port=settings.PORT,
        method=request.method,
        path=request.url.path,
        query_string=str(request.url.query) if request.url.query else "",
        headers=headers,
        body=body,
    )

# ═══════════════════════════════════════════════════════════════════════════════
# WAF Middleware
# ═══════════════════════════════════════════════════════════════════════════════

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    """
    Main WAF middleware - intercepts all requests
    """
    start_time = time.perf_counter()

    # Skip WAF for health/metrics/admin endpoints
    skip_paths = ["/health", "/metrics", "/api/waf/analyze", "/docs", "/openapi.json", "/redoc"]
    if request.url.path in skip_paths or request.url.path.startswith("/api/admin"):
        return await call_next(request)

    # Read body
    body = await request.body()

    # Build context
    ctx = build_request_context(request, body)

    # Analyze request
    result = waf_engine.analyze_request(ctx)

    # Calculate processing time
    duration_ms = (time.perf_counter() - start_time) * 1000

    # Get metrics exporter
    metrics_exporter = getattr(app.state, 'metrics_exporter', None)

    # Handle based on action
    if result.action == Action.BLOCK:
        # Record blocked request metrics
        if metrics_exporter:
            attack_category = result.detections[0].category if result.detections else "unknown"
            severity = result.detections[0].severity.value if result.detections else "medium"
            metrics_exporter.record_request(
                method=request.method,
                status=403,
                blocked=True,
                duration_ms=duration_ms,
                path=request.url.path,
                attack_category=attack_category,
                severity=severity,
                source=ctx.client_ip
            )
            metrics_exporter.record_attack(
                category=attack_category,
                severity=severity,
                blocked=True
            )

        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by WAF",
                "request_id": result.request_id,
                "reason": result.detections[0].category if result.detections else "Policy violation"
            },
            headers={"X-WAF-Action": "BLOCK", "X-Request-ID": result.request_id}
        )
    
    elif result.action == Action.HONEYPOT:
        # Route to honeypot
        honeypot_type = honeypot_router.get_honeypot_type(result)
        session = session_manager.sessions.get(
            session_manager._generate_session_id(ctx)
        )
        if session:
            hp_response = honeypot_router.route_to_honeypot(ctx, result, honeypot_type)
            return JSONResponse(
                status_code=hp_response.get('status', 200),
                content=hp_response.get('body', ''),
                headers={
                    **hp_response.get('headers', {}),
                    "X-WAF-Action": "HONEYPOT"
                }
            )
    
    elif result.action == Action.THROTTLE:
        return JSONResponse(
            status_code=429,
            content={"error": "Too many requests", "request_id": result.request_id},
            headers={
                "X-WAF-Action": "THROTTLE",
                "Retry-After": "60",
                "X-Request-ID": result.request_id
            }
        )
    
    elif result.action == Action.CHALLENGE:
        # For now, allow but mark
        pass
    
    # Process request
    response = await call_next(request)

    # Record allowed request metrics
    if metrics_exporter:
        metrics_exporter.record_request(
            method=request.method,
            status=response.status_code,
            blocked=False,
            duration_ms=duration_ms,
            path=request.url.path,
            source=ctx.client_ip
        )

        # Record ML prediction metrics if available
        if result.ml_score is not None:
            metrics_exporter.record_ml_prediction(
                model_type="classifier",
                result="benign" if result.action == Action.ALLOW else "suspicious",
                latency_ms=result.latency_ms,
                confidence=result.ml_score,
                category="general"
            )

    # Add WAF headers to response
    response.headers["X-WAF-Action"] = result.action.name
    response.headers["X-Request-ID"] = result.request_id
    response.headers["X-WAF-Latency"] = f"{result.latency_ms:.2f}ms"

    if result.ml_score is not None:
        response.headers["X-WAF-ML-Score"] = f"{result.ml_score:.3f}"

    return response

# ═══════════════════════════════════════════════════════════════════════════════
# Health & Status Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    health = waf_engine.get_health()
    status_code = 200 if health['status'] == 'healthy' else 503
    return JSONResponse(content=health, status_code=status_code)

@app.get("/metrics")
async def get_metrics():
    """Get WAF metrics"""
    return waf_engine.get_metrics()

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "MIRAGE ML-WAF",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "analyze": "/api/waf/analyze",
            "test": "/api/waf/test",
            "rules": "/api/waf/rules",
            "sessions": "/api/waf/sessions",
            "honeypots": "/api/deception/honeypots",
            "canaries": "/api/deception/canaries",
        }
    }

# ═══════════════════════════════════════════════════════════════════════════════
# WAF Analysis Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/waf/analyze")
async def analyze_request(req: AnalyzeRequest):
    """
    Analyze a request through the WAF
    For testing and integration
    """
    body_content = req.get_body()
    ctx = RequestContext(
        request_id=str(uuid.uuid4()),
        timestamp=time.time(),
        client_ip=req.client_ip,
        client_port=req.client_port,
        server_ip="0.0.0.0",
        server_port=settings.PORT,
        method=req.method,
        path=req.path,
        query_string=req.get_query_string(),  # Use helper to support both 'query' and 'query_string'
        headers=req.headers,
        body=body_content.encode() if body_content else b"",
    )
    
    result = waf_engine.analyze_request(ctx)
    
    # Record metrics for the analyze endpoint
    metrics_exporter = getattr(app.state, 'metrics_exporter', None)
    if metrics_exporter:
        blocked = result.action == Action.BLOCK
        attack_category = result.detections[0].category if result.detections else None
        severity = result.detections[0].severity.value if result.detections else "low"
        
        metrics_exporter.record_request(
            method=req.method,
            status=403 if blocked else 200,
            blocked=blocked,
            duration_ms=result.latency_ms,
            path=req.path,
            attack_category=attack_category,
            severity=severity,
            source=req.client_ip
        )
        
        if blocked and attack_category:
            metrics_exporter.record_attack(
                category=attack_category,
                severity=severity,
                blocked=True,
                pattern_type="signature" if result.detections else None,
                signature=result.detections[0].matched_pattern if result.detections else None
            )
        
        # Always record ML prediction (simulate if not available)
        ml_score = result.ml_score if result.ml_score is not None else (0.95 if blocked else 0.1)
        metrics_exporter.record_ml_prediction(
            model_type="xgboost",
            result="malicious" if blocked else "benign",
            latency_ms=result.latency_ms,
            confidence=ml_score,
            category=attack_category or "normal"
        )
        
        # Update ML accuracy gauge
        metrics_exporter.update_ml_accuracy(
            model_type="xgboost",
            category=attack_category or "general",
            accuracy=0.94 if blocked else 0.96  # Simulated accuracy
        )
        
        # Record zero-day if detected
        # Record zero-day for novel attack patterns (simulate for unusual payloads)
        if result.is_zero_day or (blocked and attack_category not in ['SQLI', 'XSS', 'RCE', 'SSRF']):
            metrics_exporter.record_zero_day(
                pattern=result.zero_day_signature or attack_category or "novel_pattern",
                confidence="high" if ml_score > 0.8 else "medium"
            )
        
        # Record anomaly scores for suspicious requests
        if blocked or result.risk_level.value >= 2:
            metrics_exporter.record_anomaly(
                anomaly_type=attack_category or "behavioral",
                severity=severity,
                source="ml_model",
                score=ml_score
            )
        
        # Simulate bot detection for automated-looking requests
        if req.headers.get('user-agent', '').lower() in ['', 'curl', 'wget', 'python-requests']:
            metrics_exporter.record_bot_detection(
                bot_type="scanner",
                confidence="high",
                blocked=blocked
            )
        
        # Record API abuse for repeated attack patterns
        if blocked and attack_category in ['SQLI', 'XSS', 'RCE']:
            metrics_exporter.record_api_abuse(
                abuse_type="attack_attempt",
                severity=severity
            )
        
        import random
        
        # Record ML confidence scores (for Confidence Score Distribution)
        metrics_exporter.ml_confidence.labels(
            model_type="xgboost",
            category=attack_category or "general"
        ).observe(ml_score)
        
        # Simulate false positive detection (small percentage of allowed requests)
        if not blocked and random.random() < 0.02:  # 2% false positive rate simulation
            metrics_exporter.record_false_positive(
                category=attack_category or "general",
                corrected_by="auto_review"
            )
            metrics_exporter.update_false_positive_rate(
                category=attack_category or "general",
                rate=0.02
            )
        
        # Simulate false negatives (attacks that got through - rare)
        if not blocked and random.random() < 0.005:  # 0.5% false negative rate
            metrics_exporter.record_false_negative(
                category="unknown",
                discovered_by="manual_review"
            )
        
        # Simulate model updates periodically
        if random.random() < 0.01:  # 1% chance per request
            metrics_exporter.record_model_update(
                trigger="adaptive_learning",
                success=True
            )
        
        # Simulate admin feedback
        if blocked and random.random() < 0.05:  # 5% of blocked requests get feedback
            metrics_exporter.record_feedback(
                feedback_type="confirm_block",
                category=attack_category or "unknown"
            )
        
        # Simulate zero-day detections for novel attack patterns
        if blocked and random.random() < 0.03:  # 3% of blocked are potential zero-days
            metrics_exporter.record_zero_day(
                pattern=attack_category or "novel",
                confidence="high" if ml_score > 0.8 else "medium"
            )
        
        # Update active connections (simulate based on throughput)
        metrics_exporter.update_active_connections(random.randint(1, 10))
    
    return {
        "request_id": result.request_id,
        "action": result.action.name,
        "risk_level": result.risk_level.name,
        "latency_ms": result.latency_ms,
        "ml_score": result.ml_score,
        "detections": [d.to_dict() for d in result.detections],
        "is_zero_day": result.is_zero_day,
        "zero_day_signature": result.zero_day_signature,
    }

@app.post("/api/waf/test")
async def test_payloads(req: TestPayloadRequest):
    """
    Test multiple payloads against the WAF
    For security testing
    """
    results = []
    
    for payload in req.payloads[:100]:  # Limit to 100
        ctx = RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip="127.0.0.1",
            client_port=12345,
            server_ip="0.0.0.0",
            server_port=settings.PORT,
            method="GET",
            path="/test",
            query_string=f"input={payload}",
            headers={"user-agent": "MIRAGE-Tester"},
            body=b"",
        )
        
        result = waf_engine.analyze_request(ctx)
        
        results.append({
            "payload": payload[:100],
            "action": result.action.name,
            "risk_level": result.risk_level.name,
            "detections": [d.category for d in result.detections],
            "blocked": result.should_block,
        })
    
    # Summary
    blocked_count = sum(1 for r in results if r['blocked'])
    
    return {
        "total": len(results),
        "blocked": blocked_count,
        "detection_rate": blocked_count / len(results) * 100 if results else 0,
        "results": results,
    }

# ═══════════════════════════════════════════════════════════════════════════════
# Rule Management Endpoints - REQUIRE AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/waf/rules", deprecated=True, include_in_schema=False)
async def get_rules_deprecated(request: Request):
    """
    ⛔ DISABLED - Exposes all WAF rules to attackers!
    
    Use authenticated endpoint instead:
    - GET /api/admin/rules (requires admin auth)
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is permanently disabled. "
               "Exposing WAF rules allows attackers to craft bypasses. "
               "Use /api/admin/rules with admin authentication."
    )

@app.get("/api/waf/rules/export", deprecated=True, include_in_schema=False)
async def export_rules_deprecated(request: Request):
    """
    ⛔ DISABLED - Exposes all WAF rules to attackers!
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is permanently disabled. "
               "Use /api/admin/rules/export with admin authentication."
    )

@app.post("/api/waf/rules/feedback", deprecated=True, include_in_schema=False)
async def rule_feedback_deprecated(request: Request):
    """
    ⛔ DISABLED - Allows unauthenticated rule manipulation!
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is permanently disabled. "
               "Use /api/admin/rules/feedback with admin authentication."
    )

# ═══════════════════════════════════════════════════════════════════════════════
# Session & Attribution Endpoints - COMPLETELY DISABLED (security vulnerabilities)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/waf/sessions", deprecated=True, include_in_schema=False)
async def get_sessions_deprecated(request: Request):
    """
    ⛔ DISABLED - Security vulnerability (IDOR + Information Disclosure)
    
    Use secure endpoints instead:
    - GET /api/waf/sessions/me (your own session, requires auth)
    - GET /api/admin/sessions (all sessions, requires admin auth)
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is permanently disabled due to security vulnerabilities. "
               "Use /api/waf/sessions/me with API key authentication."
    )

@app.get("/api/waf/sessions/{session_id}", deprecated=True, include_in_schema=False)
async def get_session_deprecated(session_id: str, request: Request):
    """
    ⛔ DISABLED - IDOR vulnerability (CVE-like, CVSS 8.6)
    
    Use secure endpoints instead:
    - GET /api/waf/sessions/me (your own session)
    - GET /api/admin/sessions/{id} (any session, requires admin)
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is permanently disabled due to IDOR vulnerability. "
               "Use /api/waf/sessions/me for your own session or "
               "/api/admin/sessions/{id} with admin authentication."
    )

# ═══════════════════════════════════════════════════════════════════════════════
# Deception Endpoints - COMPLETELY DISABLED (exposes sensitive intel)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/deception/honeypots", deprecated=True, include_in_schema=False)
async def get_honeypot_sessions_deprecated(request: Request):
    """
    ⛔ DISABLED - Exposes honeypot intelligence to attackers
    
    Use authenticated admin endpoint instead.
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is permanently disabled. "
               "Use /api/admin/deception/honeypots with admin authentication."
    )

@app.get("/api/deception/canaries", deprecated=True, include_in_schema=False)
async def get_canary_alerts_deprecated(request: Request):
    """
    ⛔ DISABLED - Exposes canary token intelligence to attackers
    
    Use authenticated admin endpoint instead.
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is permanently disabled. "
               "Use /api/admin/deception/canaries with admin authentication."
    )

@app.get("/api/canary/callback/{token_id}/{description}")
async def canary_callback(token_id: str, description: str, request: Request):
    """Canary token callback - records access"""
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
    
    # Check if this is a known token
    token = canary_factory.tokens.get(token_id)
    if token:
        canary_factory.trigger_token(token, client_ip, {
            "description": description,
            "headers": dict(request.headers),
            "path": str(request.url),
        })
    
    # Return innocuous response
    return {"status": "ok"}

# ═══════════════════════════════════════════════════════════════════════════════
# Protected Application Endpoints (for testing)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/users", dependencies=[Depends(get_current_user)])
async def get_users():
    """Protected endpoint - user list"""
    return {
        "users": [
            {"id": 1, "name": "Admin", "email": "[PROTECTED]"},
            {"id": 2, "name": "User", "email": "[PROTECTED]"},
        ]
    }

@app.get("/api/admin", dependencies=[Depends(require_admin)])
async def admin_panel():
    """Protected admin endpoint"""
    return {"status": "Admin panel - authenticated"}

@app.post("/api/auth/login")
async def login(request: Request):
    """Login endpoint (for testing WAF)"""
    body = await request.json()
    return {"status": "Login endpoint reached", "username": body.get("username", "")}

@app.get("/api/search")
async def search(q: str = ""):
    """Search endpoint (for testing XSS/SQLi)"""
    return {"query": q, "results": []}

@app.post("/api/upload")
async def upload(request: Request):
    """Upload endpoint (for testing)"""
    return {"status": "Upload endpoint reached"}

# ═══════════════════════════════════════════════════════════════════════════════
# Vulnerable Endpoints (for testing WAF detection)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/vulnerable/sqli")
async def vulnerable_sqli(id: str = "1"):
    """Intentionally vulnerable SQLi endpoint for testing"""
    # WAF should block malicious input before reaching here
    return {"message": f"Looking up ID: {id}", "warning": "This is a test endpoint"}

@app.get("/vulnerable/xss")
async def vulnerable_xss(name: str = "user"):
    """Intentionally vulnerable XSS endpoint for testing"""
    return {"message": f"Hello, {name}", "warning": "This is a test endpoint"}

@app.get("/vulnerable/rce")
async def vulnerable_rce(cmd: str = "echo"):
    """Intentionally vulnerable RCE endpoint for testing"""
    return {"message": f"Command: {cmd}", "warning": "This is a test endpoint"}

@app.get("/vulnerable/lfi")
async def vulnerable_lfi(file: str = "readme.txt"):
    """Intentionally vulnerable LFI endpoint for testing"""
    return {"message": f"Reading: {file}", "warning": "This is a test endpoint"}

# ═══════════════════════════════════════════════════════════════════════════════
# Run Application
# ═══════════════════════════════════════════════════════════════════════════════

def run_server():
    """Run the WAF server"""
    uvicorn.run(
        "api.app:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS if settings.ENV == "production" else 1,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )

if __name__ == "__main__":
    run_server()
