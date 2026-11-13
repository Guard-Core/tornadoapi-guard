from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient
from tornado.web import stream_request_body

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

ATTACK = b"q=' OR 1=1 UNION SELECT password FROM users --"


@stream_request_body
class Upload(SecurityHandler):
    async def prepare(self) -> None:
        self.received = bytearray()
        await super().prepare()

    def data_received(self, chunk: bytes) -> None:
        self.received += chunk

    async def post(self) -> None:
        self.write({"received": len(self.received)})


class Whole(SecurityHandler):
    async def post(self) -> None:
        self.write({"received": len(self.request.body)})


Post = Callable[[str, bytes], Awaitable[int]]


@pytest.fixture
async def serve() -> AsyncGenerator[Callable[..., Awaitable[Post]], None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(**overrides: Any) -> Post:
        middleware = SecurityMiddleware(
            config=SecurityConfig(
                enable_redis=False,
                enable_rate_limiting=False,
                enable_ip_banning=False,
                ban_on_hostile_signals=False,
                **overrides,
            )
        )
        app = tornado.web.Application(
            [(r"/upload", Upload), (r"/whole", Whole)],
            security_middleware=middleware,
        )
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        port = sockets[0].getsockname()[1]

        async def post(path: str, body: bytes) -> int:
            response = await AsyncHTTPClient().fetch(
                f"http://127.0.0.1:{port}{path}",
                method="POST",
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                raise_error=False,
            )
            return int(response.code)

        return post

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def test_a_whole_body_attack_is_refused(
    serve: Callable[..., Awaitable[Post]],
) -> None:
    post = await serve()
    assert await post("/whole", ATTACK) == 400


async def test_a_streamed_body_attack_is_refused(
    serve: Callable[..., Awaitable[Post]],
) -> None:
    post = await serve()
    assert await post("/upload", ATTACK) == 400


async def test_a_streamed_request_without_a_body_is_served(
    serve: Callable[..., Awaitable[Post]],
) -> None:
    post = await serve()
    assert await post("/upload", b"") == 200


async def test_a_streamed_body_passes_when_detection_is_off(
    serve: Callable[..., Awaitable[Post]],
) -> None:
    post = await serve(enable_penetration_detection=False)
    assert await post("/upload", ATTACK) == 200
