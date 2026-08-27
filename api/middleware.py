"""
DECEPTICON WAF Middleware
ASGI/WSGI middleware for framework integration
Drop-in protection for any Python web application
"""
import time
import uuid
import asyncio
from typing import Callable, Dict, Optional, Any
from dataclasses import dataclass

# Import WAF components
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings
from core.models import RequestContext, Action
from core.waf_engine import WAFEngine
from core.response_sanitizer import response_sanitizer, header_sanitizer

@dataclass
class WAFConfig:
    """WAF middleware configuration"""
    enabled: bool = True
    block_mode: bool = settings.BLOCK_MODE  # False = monitor only
    log_requests: bool = True
    sanitize_responses: bool = True
    add_headers: bool = True
    
    # Paths to skip
    skip_paths: list = None
    
    # Custom block response
    block_status: int = 403
    block_body: bytes = b'{"error": "Request blocked by WAF"}'
    block_content_type: str = "application/json"
    
    def __post_init__(self):
        if self.skip_paths is None:
            self.skip_paths = ["/health", "/metrics", "/favicon.ico"]


class DecepticonASGI:
    """
    ASGI Middleware for DECEPTICON WAF
    
    Usage with FastAPI:
        app = FastAPI()
        app = DecepticonASGI(app)
    
    Usage with Starlette:
        app = Starlette()
        app = DecepticonASGI(app)
    """
    
    def __init__(self, app, config: Optional[WAFConfig] = None):
        self.app = app
        self.config = config or WAFConfig()
        self.waf = WAFEngine()
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Skip configured paths
        path = scope.get("path", "/")
        if path in self.config.skip_paths:
            await self.app(scope, receive, send)
            return
        
        if not self.config.enabled:
            await self.app(scope, receive, send)
            return
        
        # Read request body
        body = b""
        
        async def receive_wrapper():
            nonlocal body
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
            return message
        
        # Build request context
        ctx = self._build_context(scope, body)
        
        # Analyze request
        result = self.waf.analyze_request(ctx)
        
        # Handle based on action
        if self.config.block_mode and result.action == Action.BLOCK:
            await self._send_block_response(send, result)
            return
        
        if result.action == Action.THROTTLE:
            await self._send_throttle_response(send, result)
            return
        
        # Wrap send to add headers and sanitize response
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                if self.config.add_headers:
                    headers = list(message.get("headers", []))
                    headers.append((b"x-waf-action", result.action.name.encode()))
                    headers.append((b"x-request-id", result.request_id.encode()))
                    headers.append((b"x-waf-latency", f"{result.latency_ms:.2f}ms".encode()))
                    message["headers"] = headers
            
            elif message["type"] == "http.response.body":
                if self.config.sanitize_responses:
                    body = message.get("body", b"")
                    if body:
                        sanitized = response_sanitizer.sanitize(body)
                        message["body"] = sanitized.content
            
            await send(message)
        
        # Process request with body already read
        async def receive_with_body():
            return {"type": "http.request", "body": body}
        
        await self.app(scope, receive_with_body, send_wrapper)
    
    def _build_context(self, scope: Dict, body: bytes) -> RequestContext:
        """Build RequestContext from ASGI scope"""
        # Get client info
        client = scope.get("client", ("0.0.0.0", 0))
        server = scope.get("server", ("0.0.0.0", 80))
        
        # Build headers dict
        headers = {}
        for key, value in scope.get("headers", []):
            headers[key.decode().lower()] = value.decode()
        
        # Get forwarded IP if behind proxy
        client_ip = client[0]
        if "x-forwarded-for" in headers:
            client_ip = headers["x-forwarded-for"].partition(",")[0].strip()
        elif "x-real-ip" in headers:
            client_ip = headers["x-real-ip"]
        
        # Build query string
        query_string = scope.get("query_string", b"").decode()
        
        return RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip=client_ip,
            client_port=client[1],
            server_ip=server[0],
            server_port=server[1],
            method=scope.get("method", "GET"),
            path=scope.get("path", "/"),
            query_string=query_string,
            headers=headers,
            body=body,
        )
    
    async def _send_block_response(self, send, result):
        """Send block response"""
        headers = [
            (b"content-type", self.config.block_content_type.encode()),
            (b"x-waf-action", b"BLOCK"),
            (b"x-request-id", result.request_id.encode()),
        ]
        
        await send({
            "type": "http.response.start",
            "status": self.config.block_status,
            "headers": headers,
        })
        
        await send({
            "type": "http.response.body",
            "body": self.config.block_body,
        })
    
    async def _send_throttle_response(self, send, result):
        """Send throttle response"""
        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"retry-after", b"60"),
                (b"x-waf-action", b"THROTTLE"),
            ],
        })
        
        await send({
            "type": "http.response.body",
            "body": b'{"error": "Too many requests"}',
        })


class DecepticonWSGI:
    """
    WSGI Middleware for DECEPTICON WAF
    
    Usage with Flask:
        app = Flask(__name__)
        app.wsgi_app = DecepticonWSGI(app.wsgi_app)
    
    Usage with Django:
        # In wsgi.py
        application = DecepticonWSGI(application)
    """
    
    def __init__(self, app, config: Optional[WAFConfig] = None):
        self.app = app
        self.config = config or WAFConfig()
        self.waf = WAFEngine()
    
    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        
        # Skip configured paths
        if path in self.config.skip_paths:
            return self.app(environ, start_response)
        
        if not self.config.enabled:
            return self.app(environ, start_response)
        
        # Build request context
        ctx = self._build_context(environ)
        
        # Analyze request
        result = self.waf.analyze_request(ctx)
        
        # Handle based on action
        if self.config.block_mode and result.action == Action.BLOCK:
            return self._block_response(start_response, result)
        
        if result.action == Action.THROTTLE:
            return self._throttle_response(start_response, result)
        
        # Wrap start_response to add headers
        def custom_start_response(status, headers, exc_info=None):
            if self.config.add_headers:
                headers.append(("X-WAF-Action", result.action.name))
                headers.append(("X-Request-ID", result.request_id))
                headers.append(("X-WAF-Latency", f"{result.latency_ms:.2f}ms"))
            return start_response(status, headers, exc_info)
        
        return self.app(environ, custom_start_response)
    
    def _build_context(self, environ: Dict) -> RequestContext:
        """Build RequestContext from WSGI environ"""
        # Get client IP
        client_ip = environ.get("REMOTE_ADDR", "0.0.0.0")
        if environ.get("HTTP_X_FORWARDED_FOR"):
            client_ip = environ["HTTP_X_FORWARDED_FOR"].partition(",")[0].strip()
        elif environ.get("HTTP_X_REAL_IP"):
            client_ip = environ["HTTP_X_REAL_IP"]
        
        # Build headers
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").lower()
                headers[header_name] = value
        
        # Read body
        try:
            content_length = int(environ.get("CONTENT_LENGTH", 0))
        except (ValueError, TypeError):
            content_length = 0
        
        body = b""
        if content_length > 0:
            body = environ["wsgi.input"].read(content_length)
            # Reset stream for downstream
            from io import BytesIO
            environ["wsgi.input"] = BytesIO(body)
        
        return RequestContext(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            client_ip=client_ip,
            client_port=int(environ.get("REMOTE_PORT", 0)),
            server_ip=environ.get("SERVER_NAME", "0.0.0.0"),
            server_port=int(environ.get("SERVER_PORT", 80)),
            method=environ.get("REQUEST_METHOD", "GET"),
            path=environ.get("PATH_INFO", "/"),
            query_string=environ.get("QUERY_STRING", ""),
            headers=headers,
            body=body,
        )
    
    def _block_response(self, start_response, result):
        """Return block response"""
        start_response(
            f"{self.config.block_status} Forbidden",
            [
                ("Content-Type", self.config.block_content_type),
                ("X-WAF-Action", "BLOCK"),
                ("X-Request-ID", result.request_id),
            ]
        )
        return [self.config.block_body]
    
    def _throttle_response(self, start_response, result):
        """Return throttle response"""
        start_response(
            "429 Too Many Requests",
            [
                ("Content-Type", "application/json"),
                ("Retry-After", "60"),
                ("X-WAF-Action", "THROTTLE"),
            ]
        )
        return [b'{"error": "Too many requests"}']


# Convenience function for quick setup
def protect_app(app, framework: str = "auto", **config_kwargs):
    """
    Quick setup function to protect any Python web app
    
    Args:
        app: Your web application
        framework: "asgi", "wsgi", or "auto" (detect automatically)
        **config_kwargs: WAF configuration options
    
    Returns:
        Protected application
    
    Example:
        # FastAPI
        app = protect_app(FastAPI(), framework="asgi")
        
        # Flask
        app.wsgi_app = protect_app(app.wsgi_app, framework="wsgi")
    """
    config = WAFConfig(**config_kwargs)
    
    if framework == "auto":
        # Try to detect framework
        if asyncio.iscoroutinefunction(getattr(app, "__call__", None)):
            framework = "asgi"
        else:
            framework = "wsgi"
    
    if framework == "asgi":
        return DecepticonASGI(app, config)
    else:
        return DecepticonWSGI(app, config)
