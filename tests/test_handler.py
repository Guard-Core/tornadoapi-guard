from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import cast

import pytest
import tornado.httpserver
import tornado.httputil
import tornado.netutil
import tornado.web
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import HTTPConnection

from tornadoapi_guard import SecurityHandler
from tornadoapi_guard.handler import SecurityHandler as HandlerClass


class SimpleHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


@pytest.fixture
async def unguarded_server() -> AsyncGenerator[int, None]:
    app = tornado.web.Application([(r"/", SimpleHandler)])
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.stop()


async def test_handler_without_middleware_serves_normally(
    unguarded_server: int,
) -> None:
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(f"http://127.0.0.1:{unguarded_server}/")
        assert response.code == 200
    finally:
        client.close()


async def test_get_security_middleware_rejects_wrong_type() -> None:
    app = tornado.web.Application(
        [(r"/", SimpleHandler)], security_middleware="not-a-middleware"
    )
    request = tornado.httputil.HTTPServerRequest(
        method="GET",
        uri="/",
        headers=tornado.httputil.HTTPHeaders(),
        connection=cast(HTTPConnection, _FakeConnection()),
    )
    handler = HandlerClass(app, request)
    assert handler._get_security_middleware() is None


class _FakeConnection:
    def __init__(self) -> None:
        self.context = tornado.httputil.RequestStartLine("GET", "/", "HTTP/1.1")

    def set_close_callback(self, _callback: object) -> None:
        pass

    def write_headers(self, *_args: object, **_kwargs: object) -> None:
        pass

    def write(self, *_args: object, **_kwargs: object) -> None:
        pass

    def finish(self) -> None:
        pass
