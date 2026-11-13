from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
import tornado.websocket
from guard_core._utils.app_scope import _current_app_scope, app_scope_of
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.web import RequestHandler

from tornadoapi_guard import (
    SecurityHandler,
    SecurityMiddleware,
    SecurityWebSocketHandler,
)


class Plain(SecurityHandler):
    async def get(self) -> None:
        self.write("seen" if _current_app_scope.get() is not None else "none")


class Socket(SecurityWebSocketHandler):
    def open(self, *args: str, **kwargs: str) -> None:
        self.write_message("connected")


class _Recording(SecurityMiddleware):
    def __init__(self, *, config: SecurityConfig, seen: list[Any]) -> None:
        super().__init__(config=config)
        self.seen = seen

    async def run_pre_processing(self, handler: RequestHandler) -> GuardResponse | None:
        self.seen.append(_current_app_scope.get())
        return await super().run_pre_processing(handler)


@pytest.fixture
async def served() -> AsyncGenerator[tuple[int, SecurityConfig, list[Any]], None]:
    seen: list[Any] = []
    config = SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
        ban_on_hostile_signals=False,
    )
    middleware = _Recording(config=config, seen=seen)
    app = tornado.web.Application(
        [(r"/plain", Plain), (r"/ws", Socket)], security_middleware=middleware
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    await middleware.initialize()
    yield int(sockets[0].getsockname()[1]), config, seen
    server.stop()
    await middleware.reset()


async def test_the_app_scope_is_held_when_an_http_request_enters_the_pipeline(
    served: tuple[int, SecurityConfig, list[Any]],
) -> None:
    port, config, seen = served
    await AsyncHTTPClient().fetch(f"http://127.0.0.1:{port}/plain")

    assert seen == [app_scope_of(config)]


async def test_the_app_scope_is_held_when_an_upgrade_enters_the_pipeline(
    served: tuple[int, SecurityConfig, list[Any]],
) -> None:
    port, config, seen = served
    connection = await tornado.websocket.websocket_connect(
        HTTPRequest(f"ws://127.0.0.1:{port}/ws")
    )
    await connection.read_message()
    connection.close()

    assert seen == [app_scope_of(config)]


async def test_an_upgrade_leaves_no_scope_behind(
    served: tuple[int, SecurityConfig, list[Any]],
) -> None:
    port, _, _ = served
    connection = await tornado.websocket.websocket_connect(
        HTTPRequest(f"ws://127.0.0.1:{port}/ws")
    )
    await connection.read_message()
    connection.close()

    assert _current_app_scope.get() is None


async def test_the_first_request_of_an_app_still_serves_its_view_in_scope() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
        ban_on_hostile_signals=False,
    )
    middleware = SecurityMiddleware(config=config)
    app = tornado.web.Application([(r"/plain", Plain)], security_middleware=middleware)
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    try:
        response = await AsyncHTTPClient().fetch(f"http://127.0.0.1:{port}/plain")
    finally:
        server.stop()
        await middleware.reset()

    assert response.body == b"seen"
