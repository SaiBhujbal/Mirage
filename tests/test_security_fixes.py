import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import pytest
pytest.importorskip("fastapi")  # legacy suite dep — skip cleanly if not installed
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
import json

from core.security_fixes import RequestSizeLimiter, create_size_limit_middleware

class TestRequestSizeLimiter(unittest.TestCase):
    def setUp(self):
        self.max_size = 1000
        self.limiter = RequestSizeLimiter(max_size=self.max_size)

    def test_content_length_none(self):
        is_allowed, msg = self.limiter.check_size(None)
        self.assertTrue(is_allowed)
        self.assertEqual(msg, "")

    def test_content_length_within_limit(self):
        is_allowed, msg = self.limiter.check_size("500")
        self.assertTrue(is_allowed)
        self.assertEqual(msg, "")

    def test_content_length_at_limit(self):
        is_allowed, msg = self.limiter.check_size("1000")
        self.assertTrue(is_allowed)
        self.assertEqual(msg, "")

    def test_content_length_exceeds_limit(self):
        is_allowed, msg = self.limiter.check_size("1001")
        self.assertFalse(is_allowed)
        self.assertEqual(msg, "Request body too large. Max: 1000 bytes")

    def test_invalid_content_length_string(self):
        is_allowed, msg = self.limiter.check_size("abc")
        self.assertFalse(is_allowed)
        self.assertEqual(msg, "Invalid Content-Length header")

    def test_invalid_content_length_empty(self):
        is_allowed, msg = self.limiter.check_size("")
        self.assertFalse(is_allowed)
        self.assertEqual(msg, "Invalid Content-Length header")

    def test_invalid_content_length_float(self):
        is_allowed, msg = self.limiter.check_size("500.5")
        self.assertFalse(is_allowed)
        self.assertEqual(msg, "Invalid Content-Length header")

    def test_content_length_whitespace(self):
        is_allowed, msg = self.limiter.check_size("  500  ")
        self.assertTrue(is_allowed)
        self.assertEqual(msg, "")

    def test_content_length_negative(self):
        # Even if a negative size is sent, size limiter passes it,
        # as it is not larger than max. This tests current code behavior.
        is_allowed, msg = self.limiter.check_size("-1")
        self.assertTrue(is_allowed)
        self.assertEqual(msg, "")

    def test_content_length_huge(self):
        is_allowed, msg = self.limiter.check_size("99999999999999999999")
        self.assertFalse(is_allowed)
        self.assertEqual(msg, "Request body too large. Max: 1000 bytes")

class TestSizeLimitMiddlewareAsync(unittest.IsolatedAsyncioTestCase):
    async def test_middleware_allowed(self):
        MiddlewareClass = create_size_limit_middleware(max_size=2000)
        # MagicMock the app because BaseHTTPMiddleware requires an app
        mock_app = MagicMock()
        middleware = MiddlewareClass(app=mock_app)

        mock_request = MagicMock()
        mock_request.headers = {"content-length": "1500"}

        mock_response = Response(content="ok")

        async def call_next(req):
            return mock_response

        # dispatch is what BaseHTTPMiddleware subclasses implement
        response = await middleware.dispatch(mock_request, call_next)
        self.assertEqual(response, mock_response)

    async def test_middleware_blocked_too_large(self):
        MiddlewareClass = create_size_limit_middleware(max_size=2000)
        mock_app = MagicMock()
        middleware = MiddlewareClass(app=mock_app)

        mock_request = MagicMock()
        mock_request.headers = {"content-length": "2001"}

        async def call_next(req):
            return Response(content="ok")

        response = await middleware.dispatch(mock_request, call_next)
        self.assertIsInstance(response, JSONResponse)
        self.assertEqual(response.status_code, 413)
        body = json.loads(response.body.decode())
        self.assertEqual(body["error"], "Request body too large. Max: 2000 bytes")

    async def test_middleware_blocked_invalid_header(self):
        MiddlewareClass = create_size_limit_middleware(max_size=2000)
        mock_app = MagicMock()
        middleware = MiddlewareClass(app=mock_app)

        mock_request = MagicMock()
        mock_request.headers = {"content-length": "invalid"}

        async def call_next(req):
            return Response(content="ok")

        response = await middleware.dispatch(mock_request, call_next)
        self.assertIsInstance(response, JSONResponse)
        self.assertEqual(response.status_code, 413)
        body = json.loads(response.body.decode())
        self.assertEqual(body["error"], "Invalid Content-Length header")

    async def test_middleware_no_header(self):
        MiddlewareClass = create_size_limit_middleware(max_size=2000)
        mock_app = MagicMock()
        middleware = MiddlewareClass(app=mock_app)

        mock_request = MagicMock()
        mock_request.headers = {}

        mock_response = Response(content="ok")
        async def call_next(req):
            return mock_response

        response = await middleware.dispatch(mock_request, call_next)
        self.assertEqual(response, mock_response)

# Test with FastAPI and TestClient
def create_test_app(max_size: int):
    app = FastAPI()
    SizeLimitMiddleware = create_size_limit_middleware(max_size=max_size)
    app.add_middleware(SizeLimitMiddleware)

    @app.post("/test")
    async def test_route(request: Request):
        return {"status": "success"}

    return app

class TestSizeLimitMiddlewareIntegration(unittest.TestCase):
    def setUp(self):
        self.app = create_test_app(max_size=50)
        self.client = TestClient(self.app)

    def test_request_within_limit(self):
        payload = "x" * 40
        # Passing string as content bypasses automatic json serialization
        # and lets us set exact content length via payload length if needed,
        # but httpx will set content-length.
        response = self.client.post("/test", content=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "success"})

    def test_request_exceeds_limit(self):
        payload = "x" * 51
        response = self.client.post("/test", content=payload)
        self.assertEqual(response.status_code, 413)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "Request body too large. Max: 50 bytes")

    def test_request_explicit_header_override(self):
        # The TestClient might normally set Content-Length based on content.
        # We can override the header to test invalid values directly.
        response = self.client.post("/test", content="small", headers={"content-length": "999"})
        self.assertEqual(response.status_code, 413)

        response = self.client.post("/test", content="small", headers={"content-length": "notanumber"})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"], "Invalid Content-Length header")

def run_all_tests():
    unittest.main()

if __name__ == '__main__':
    run_all_tests()
