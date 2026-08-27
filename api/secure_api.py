"""
DECEPTICON Secure API Middleware
Handles authentication, TLS enforcement, request size limits, MFA, and secure error responses
"""
import time
import logging
from typing import Optional, Callable
from functools import wraps

from fastapi import Request, Response, HTTPException, Depends
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Import security modules
try:
    from core.security_hardening import (
        api_key_manager, error_sanitizer, geo_blocker, 
        tls_enforcer, siem, ErrorSanitizer
    )
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False

try:
    from core.security_fixes import (
        request_size_limiter, totp_manager, audit_logger,
        configure_secure_logging, AdminKeyCleanup
    )
    SECURITY_FIXES_AVAILABLE = True
except ImportError:
    SECURITY_FIXES_AVAILABLE = False

try:
    from config.settings import settings
    SETTINGS_AVAILABLE = True
except ImportError:
    SETTINGS_AVAILABLE = False

logger = logging.getLogger("decepticon.api.security")


# ============================================================================
# API KEY AUTHENTICATION
# ============================================================================

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
totp_header = APIKeyHeader(name="X-TOTP-Token", auto_error=False)


async def verify_api_key(
    request: Request,
    api_key: Optional[str] = Depends(api_key_header),
    totp_token: Optional[str] = Depends(totp_header)
) -> Optional[dict]:
    """
    Verify API key for protected endpoints
    Optionally verify TOTP for MFA-enabled keys
    """
    if not SECURITY_AVAILABLE:
        return {"permissions": ["admin"], "name": "development"}
    
    # Check if this is a public endpoint
    public_paths = [
        "/health", "/ready", "/metrics", "/docs", "/openapi.json", "/redoc",
        "/api/waf/analyze", "/api/waf/test",  # Testing/integration endpoints
        "/", "/api/users", "/api/search", "/vulnerable/"  # Demo endpoints
    ]
    if any(request.url.path.startswith(p) for p in public_paths):
        return None
    
    # Check for API key
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Validate key
    is_valid, key_info, error = api_key_manager.validate_key(api_key)
    
    if not is_valid:
        logger.warning(f"Invalid API key attempt: {error} from {request.client.host}")
        
        if SECURITY_FIXES_AVAILABLE:
            audit_logger.log(
                action="AUTH_FAILURE",
                actor=request.client.host if request.client else "unknown",
                resource="api_key",
                details={"error": error, "path": str(request.url.path)}
            )
        
        siem.send_event(
            event_type="auth_failure",
            severity="medium",
            data={
                "path": str(request.url.path),
                "client_ip": request.client.host if request.client else "unknown",
                "error": error,
            }
        )
        
        raise HTTPException(
            status_code=401 if "not found" in error.lower() else 403,
            detail="Invalid or expired API key",
        )
    
    # Check MFA if enabled and required for admin
    if SECURITY_FIXES_AVAILABLE and SETTINGS_AVAILABLE:
        if settings.ENABLE_MFA_FOR_ADMIN and "admin" in key_info.permissions:
            totp_secret = getattr(key_info, 'totp_secret', None)
            
            if totp_secret:
                if not totp_token:
                    raise HTTPException(
                        status_code=401,
                        detail="TOTP token required for admin access",
                        headers={"X-MFA-Required": "true"},
                    )
                
                if not totp_manager.verify(totp_secret, totp_token):
                    audit_logger.log(
                        action="AUTH_FAILURE",
                        actor=key_info.key_id,
                        resource="mfa",
                        details={"reason": "invalid_totp"}
                    )
                    raise HTTPException(
                        status_code=401,
                        detail="Invalid TOTP token",
                    )
    
    # Log successful auth for admin
    if SECURITY_FIXES_AVAILABLE and "admin" in key_info.permissions:
        audit_logger.log(
            action="AUTH_SUCCESS",
            actor=key_info.key_id,
            resource=str(request.url.path),
            details={"permissions": key_info.permissions}
        )
    
    return {
        "permissions": key_info.permissions, 
        "name": key_info.name, 
        "key_id": key_info.key_id
    }


def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            auth = kwargs.get("auth")
            
            if not auth:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            if not SECURITY_AVAILABLE:
                return await func(*args, **kwargs)
            
            if not api_key_manager.check_permission(
                type("obj", (), {"permissions": auth["permissions"]})(),
                permission
            ):
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission '{permission}' required"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# REQUEST SIZE LIMIT MIDDLEWARE
# ============================================================================

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request body size to prevent DoS"""
    
    def __init__(self, app, max_size: int = 1024 * 1024):
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        
        if content_length:
            try:
                size = int(content_length)
                if size > self.max_size:
                    return JSONResponse(
                        {"error": f"Request body too large. Maximum: {self.max_size} bytes"},
                        status_code=413
                    )
            except ValueError:
                return JSONResponse(
                    {"error": "Invalid Content-Length header"},
                    status_code=400
                )
        
        return await call_next(request)


# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware for all requests
    
    Handles:
    - Request size limits
    - TLS enforcement
    - Geoblocking
    - Security headers
    - Error sanitization
    - Audit logging
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        
        try:
            # 1. Request Size Limit
            if SECURITY_FIXES_AVAILABLE and SETTINGS_AVAILABLE:
                content_length = request.headers.get("content-length")
                is_allowed, error = request_size_limiter.check_size(content_length)
                if not is_allowed:
                    return JSONResponse({"error": error}, status_code=413)
            
            # 2. TLS Enforcement
            if SECURITY_AVAILABLE:
                is_https = (
                    request.url.scheme == "https" or
                    request.headers.get("x-forwarded-proto") == "https"
                )
                
                tls_ok, tls_error = tls_enforcer.check_request(
                    is_https=is_https,
                    tls_version=request.headers.get("x-tls-version")
                )
                
                if not tls_ok and tls_enforcer.require_tls:
                    logger.warning(f"TLS required but not present from {client_ip}")
                    return JSONResponse(
                        {"error": "HTTPS required"},
                        status_code=426,
                        headers={"Upgrade": "TLS/1.2"}
                    )
            
            # 3. Geoblocking
            if SECURITY_AVAILABLE:
                is_blocked, block_reason = geo_blocker.is_blocked(client_ip)
                
                if is_blocked:
                    logger.warning(f"Geoblocked: {client_ip} - {block_reason}")
                    
                    siem.send_event(
                        event_type="geo_blocked",
                        severity="low",
                        data={"client_ip": client_ip, "reason": block_reason}
                    )
                    
                    return JSONResponse(
                        {"error": "Access denied"},
                        status_code=403,
                    )
            
            # 4. Process request
            response = await call_next(request)
            
            # 5. Add security headers
            if SECURITY_AVAILABLE:
                for header, value in tls_enforcer.get_security_headers().items():
                    response.headers[header] = value
            
            # 6. Audit logging for admin endpoints
            if SECURITY_FIXES_AVAILABLE and request.url.path.startswith("/api/admin"):
                audit_logger.log(
                    action="ADMIN_ACCESS",
                    actor=client_ip,
                    resource=str(request.url.path),
                    details={
                        "method": request.method,
                        "status": response.status_code,
                    }
                )
            
            # 7. SIEM logging
            if SECURITY_AVAILABLE and request.url.path.startswith("/api/waf"):
                duration_ms = (time.time() - start_time) * 1000
                
                siem.send_event(
                    event_type="api_request",
                    severity="info",
                    data={
                        "path": str(request.url.path),
                        "method": request.method,
                        "client_ip": client_ip,
                        "status_code": response.status_code,
                        "duration_ms": round(duration_ms, 2),
                    }
                )
            
            return response
            
        except HTTPException:
            raise
            
        except Exception as e:
            logger.error(f"Unhandled error: {e}", exc_info=True)
            
            if SECURITY_AVAILABLE:
                detailed = ErrorSanitizer.log_detailed(e, {
                    "path": str(request.url.path),
                    "method": request.method,
                    "client_ip": client_ip,
                })
                logger.error(detailed)
                
                siem.send_event(
                    event_type="api_error",
                    severity="high",
                    data={
                        "path": str(request.url.path),
                        "error_type": type(e).__name__,
                        "client_ip": client_ip,
                    }
                )
                
                return JSONResponse(
                    status_code=500,
                    content=ErrorSanitizer.safe_response("error"),
                )
            else:
                return JSONResponse(
                    status_code=500,
                    content={"error": "An error occurred"},
                )


# ============================================================================
# ADMIN RATE LIMITER
# ============================================================================

class AdminRateLimiter:
    """Separate rate limiter for admin API"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
    
    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        
        history = self.requests.get(client_ip, [])
        history = [t for t in history if t > cutoff]
        
        if len(history) >= self.max_requests:
            return False
        
        history.append(now)
        self.requests[client_ip] = history
        return True


admin_rate_limiter = AdminRateLimiter()


async def check_admin_rate_limit(request: Request):
    """Dependency to check admin rate limit"""
    client_ip = request.client.host if request.client else "unknown"
    
    if not admin_rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for admin API",
            headers={"Retry-After": "60"},
        )


# ============================================================================
# SECURE RESPONSE HELPER
# ============================================================================

def secure_response(data: dict, status_code: int = 200) -> JSONResponse:
    """Create a secure JSON response with proper headers"""
    response = JSONResponse(content=data, status_code=status_code)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    
    return response
