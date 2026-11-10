from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tests.redis_isolation import close_redis_of, suite_redis_prefix
from tornadoapi_guard import SecurityHandler, SecurityMiddleware

ORIGIN_A = "https://a.example"
ORIGIN_B = "https://b.example"
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


class _Handler(SecurityHandler):
    def get(self) -> None:
        self.write({"ok": True})


async def _serve(
    name: str, origin: str, max_age: int, redis: bool
) -> tuple[int, SecurityMiddleware, tornado.httpserver.HTTPServer]:
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=redis,
            redis_url=REDIS_URL if redis else None,
            redis_prefix=suite_redis_prefix("wp102"),
            enable_rate_limiting=False,
            enable_ip_banning=False,
            enable_cors=True,
            cors_allow_origins=[origin],
            security_headers={
                "enabled": True,
                "csp": {"default-src": ["'self'", f"https://{name}.csp.example"]},
                "hsts": {"max_age": max_age, "include_subdomains": True},
                "frame_options": "DENY" if name == "a" else "SAMEORIGIN",
                "custom": {"X-App-Name": name},
            },
        )
    )
    app = tornado.web.Application([(r"/x", _Handler)], security_middleware=middleware)
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    return int(sockets[0].getsockname()[1]), middleware, server


async def _get(port: int, origin: str) -> Any:
    return (
        await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{port}/x", headers={"Origin": origin}
        )
    ).headers


@pytest.fixture(params=[False, True], ids=["no-redis", "redis"])
async def two_apps(request: pytest.FixtureRequest) -> AsyncGenerator[Any, None]:
    port_a, mw_a, server_a = await _serve("a", ORIGIN_A, 31536000, request.param)
    port_b, mw_b, server_b = await _serve("b", ORIGIN_B, 63072000, request.param)
    try:
        yield port_a, port_b
    finally:
        server_a.stop()
        server_b.stop()
        await mw_a.reset()
        await mw_b.reset()
        await close_redis_of(mw_a)
        await close_redis_of(mw_b)


async def test_two_apps_in_one_process_each_answer_with_their_own_headers(
    two_apps: Any,
) -> None:
    port_a, port_b = two_apps
    for _ in range(2):
        a = await _get(port_a, ORIGIN_A)
        b = await _get(port_b, ORIGIN_B)
        assert a["Content-Security-Policy"].endswith("https://a.csp.example")
        assert b["Content-Security-Policy"].endswith("https://b.csp.example")
        assert a["Strict-Transport-Security"].startswith("max-age=31536000")
        assert b["Strict-Transport-Security"].startswith("max-age=63072000")
        assert a["X-App-Name"] == "a"
        assert b["X-App-Name"] == "b"
        assert a["X-Frame-Options"] == "DENY"
        assert b["X-Frame-Options"] == "SAMEORIGIN"
        assert a["Access-Control-Allow-Origin"] == ORIGIN_A
        assert b["Access-Control-Allow-Origin"] == ORIGIN_B
        cross = await _get(port_a, ORIGIN_B)
        assert "Access-Control-Allow-Origin" not in cross
