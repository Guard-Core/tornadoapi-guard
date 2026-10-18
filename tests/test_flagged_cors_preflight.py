from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

ORIGIN = "https://app.example.com"


class _RootHandler(SecurityHandler):
    def get(self) -> None:
        self.write({"ok": "yes"})


async def _serve(
    config: SecurityConfig,
) -> tuple[tornado.httpserver.HTTPServer, int, SecurityMiddleware]:
    middleware = SecurityMiddleware(config=config)
    app = tornado.web.Application(
        [(r"/", _RootHandler)], security_middleware=middleware
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    return server, sockets[0].getsockname()[1], middleware


@pytest.fixture
async def cors_off_server() -> AsyncGenerator[tuple[int, SecurityMiddleware], None]:
    server, port, middleware = await _serve(SecurityConfig(enable_redis=False))
    try:
        yield port, middleware
    finally:
        server.stop()
        await middleware.reset()
        await security_headers_manager.reset()


async def _preflight(port: int) -> int:
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(
            f"http://127.0.0.1:{port}/",
            method="OPTIONS",
            allow_nonstandard_methods=True,
            headers={"Origin": ORIGIN, "Access-Control-Request-Method": "GET"},
        )
    except HTTPClientError as error:
        return error.code
    assert response.headers.get("Access-Control-Allow-Origin") == ORIGIN
    return response.code


async def test_a_flagged_enable_cors_call_makes_the_pipeline_answer_the_preflight(
    cors_off_server: tuple[int, SecurityMiddleware],
) -> None:
    port, _ = cors_off_server
    assert await _preflight(port) == 405
    security_headers_manager.configure(
        enable_cors=True, cors_origins=[ORIGIN], override_apps=True
    )
    assert await _preflight(port) == 200


async def test_the_check_exists_only_for_an_app_built_without_cors() -> None:
    off_server, _, off = await _serve(SecurityConfig(enable_redis=False))
    on_server, _, on = await _serve(
        SecurityConfig(
            enable_redis=False, enable_cors=True, cors_allow_origins=[ORIGIN]
        )
    )
    try:
        assert off.security_pipeline is not None and on.security_pipeline is not None
        assert "cors_preflight" in [c.check_name for c in off.security_pipeline.checks]
        assert "cors_preflight" not in [
            c.check_name for c in on.security_pipeline.checks
        ]
    finally:
        off_server.stop()
        on_server.stop()
        await off.reset()
        await on.reset()
