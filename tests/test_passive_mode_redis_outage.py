from __future__ import annotations

import logging
from collections.abc import Generator
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
import tornado.websocket
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest

from tornadoapi_guard import (
    SecurityHandler,
    SecurityMiddleware,
    SecurityWebSocketHandler,
)
from tornadoapi_guard import middleware as middleware_module

DEAD_REDIS_URL = "redis://127.0.0.1:1"
INIT_OUTAGE_LINE = "Redis unavailable during initialization"


class Ping(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


class GuardedEcho(SecurityWebSocketHandler):
    def open(self, *args: str, **kwargs: str) -> None:
        self.write_message("connected")


@pytest.fixture(autouse=True)
def _reset_outage_samples() -> Generator[None, None, None]:
    middleware_module._init_outage_samples.clear()
    yield
    middleware_module._init_outage_samples.clear()


async def _fetch_http_and_ws(passive_mode: bool) -> tuple[list[int], str]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=DEAD_REDIS_URL,
        enable_penetration_detection=False,
        passive_mode=passive_mode,
    )
    middleware = SecurityMiddleware(config=config)
    app = tornado.web.Application(
        [(r"/ping", Ping), (r"/ws", GuardedEcho)], security_middleware=middleware
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    client = AsyncHTTPClient()
    codes: list[int] = []
    try:
        for _ in range(3):
            try:
                codes.append((await client.fetch(f"http://127.0.0.1:{port}/ping")).code)
            except HTTPClientError as exc:
                codes.append(exc.code)
        try:
            connection = await tornado.websocket.websocket_connect(
                HTTPRequest(f"ws://127.0.0.1:{port}/ws")
            )
            message: Any = await connection.read_message()
            connection.close()
            ws = f"accepted:{message}"
        except HTTPClientError as exc:
            ws = f"refused:{exc.code}"
        return codes, ws
    finally:
        client.close()
        server.stop()


async def test_passive_cold_start_with_redis_down_admits_http_and_websocket(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR):
        codes, ws = await _fetch_http_and_ws(passive_mode=True)

    assert codes == [200, 200, 200]
    assert ws == "accepted:connected"
    lines = [
        r
        for r in caplog.records
        if INIT_OUTAGE_LINE in r.getMessage() and "passive_mode" in r.getMessage()
    ]
    assert len(lines) == 1


async def test_not_passive_cold_start_with_redis_down_keeps_503() -> None:
    codes, ws = await _fetch_http_and_ws(passive_mode=False)

    assert codes == [503, 503, 503]
    assert ws == "refused:503"
