from __future__ import annotations

import logging
from collections.abc import AsyncGenerator, Awaitable, Callable
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


class Open(SecurityHandler):
    async def get(self) -> None:
        self.write("served")


class Echo(SecurityWebSocketHandler):
    def open(self, *args: str, **kwargs: str) -> None:
        self.write_message("connected")


Serve = Callable[..., Awaitable[int]]


def _middleware(**overrides: Any) -> SecurityMiddleware:
    return SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            ban_on_hostile_signals=False,
            **overrides,
        )
    )


@pytest.fixture
async def serve() -> AsyncGenerator[Serve, None]:
    servers: list[tornado.httpserver.HTTPServer] = []

    async def start(**settings: Any) -> int:
        app = tornado.web.Application([(r"/open", Open), (r"/ws", Echo)], **settings)
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        servers.append(server)
        return int(sockets[0].getsockname()[1])

    yield start
    for server in servers:
        server.stop()


async def _status(port: int) -> tuple[int, str]:
    response = await AsyncHTTPClient().fetch(
        f"http://127.0.0.1:{port}/open", raise_error=False
    )
    return int(response.code), response.body.decode()


async def test_no_middleware_setting_refuses_the_request(serve: Serve) -> None:
    code, body = await _status(await serve())

    assert code == 500
    assert body != "served"


async def test_a_misspelled_setting_refuses_and_names_the_key(
    serve: Serve, caplog: pytest.LogCaptureFixture
) -> None:
    port = await serve(security_middlware=_middleware())
    with caplog.at_level(logging.ERROR):
        code, body = await _status(port)

    assert (code, body == "served") == (500, False)
    assert "security_middlware" in caplog.text


async def test_the_flag_off_serves_unguarded_and_warns_once(
    serve: Serve, caplog: pytest.LogCaptureFixture
) -> None:
    port = await serve(security_middlware=_middleware(fail_on_misconfiguration=False))
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        first = await _status(port)
        second = await _status(port)

    assert first == second == (200, "served")
    warned = [r for r in caplog.records if "security_middlware" in r.getMessage()]
    assert len(warned) == 1


async def test_a_wired_application_is_untouched(serve: Serve) -> None:
    middleware = _middleware()
    code, body = await _status(await serve(security_middleware=middleware))
    await middleware.reset()

    assert (code, body) == (200, "served")


async def test_a_websocket_upgrade_without_the_middleware_is_refused(
    serve: Serve,
) -> None:
    port = await serve()
    with pytest.raises(HTTPClientError) as refused:
        await tornado.websocket.websocket_connect(
            HTTPRequest(f"ws://127.0.0.1:{port}/ws")
        )

    assert refused.value.code == 500
