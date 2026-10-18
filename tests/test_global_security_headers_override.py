from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

APP_CSP = {"default-src": ["'self'", "https://app.example"]}
GLOBAL_CSP = {"default-src": ["'self'", "https://global.example"]}
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


class _Handler(SecurityHandler):
    def get(self) -> None:
        self.write({"ok": True})


@pytest.fixture(autouse=True)
async def _clean_global_manager() -> AsyncGenerator[None, None]:
    await security_headers_manager.reset()
    yield
    await security_headers_manager.reset()


def _middleware(**overrides: Any) -> SecurityMiddleware:
    values: dict[str, Any] = {
        "enable_redis": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": False,
        "security_headers": {
            "enabled": True,
            "csp": APP_CSP,
            "frame_options": "DENY",
        },
    }
    values.update(overrides)
    return SecurityMiddleware(config=SecurityConfig(**values))


@pytest.fixture
async def port() -> AsyncGenerator[int, None]:
    middleware = _middleware()
    app = tornado.web.Application(
        [(r"/x", _Handler), (r"/y", _Handler)], security_middleware=middleware
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    try:
        yield int(sockets[0].getsockname()[1])
    finally:
        server.stop()
        await middleware.reset()


async def _get(port: int, path: str) -> Any:
    return await AsyncHTTPClient().fetch(f"http://127.0.0.1:{port}{path}")


async def test_the_global_configure_reaches_a_guarded_app(port: int) -> None:
    assert (
        (await _get(port, "/x"))
        .headers["Content-Security-Policy"]
        .endswith("app.example")
    )

    security_headers_manager.configure(csp=GLOBAL_CSP)

    for path in ("/x", "/y"):
        response = await _get(port, path)
        assert response.headers["Content-Security-Policy"] == (
            "default-src 'self' https://global.example"
        )
        assert response.headers["X-Frame-Options"] == "DENY"


async def test_without_a_global_call_the_app_keeps_its_own_config(port: int) -> None:
    response = await _get(port, "/x")

    assert response.headers["Content-Security-Policy"].endswith("app.example")


async def test_the_response_manager_reaches_the_redis_of_its_app() -> None:
    middleware = _middleware(enable_redis=True, redis_url=REDIS_URL)

    assert middleware.redis_handler is not None
    assert middleware.response_factory is not None
    assert middleware.response_factory.security_headers_manager.redis_handler is (
        middleware.redis_handler
    )
