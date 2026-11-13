from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class Repeating(SecurityHandler):
    async def get(self) -> None:
        self.add_header("Vary", "Accept")
        self.add_header("Vary", "Cookie")
        self.add_header("X-Tag", "first")
        self.add_header("X-Tag", "second")
        self.write("ok")


@pytest.fixture
async def answer() -> AsyncGenerator[HTTPResponse, None]:
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            enable_rate_limiting=False,
            enable_penetration_detection=False,
            ban_on_hostile_signals=False,
            enable_cors=True,
            cors_allow_origins=["https://app.example"],
        )
    )
    app = tornado.web.Application(
        [(r"/repeat", Repeating)], security_middleware=middleware
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    yield await AsyncHTTPClient().fetch(
        f"http://127.0.0.1:{port}/repeat", headers={"Origin": "https://app.example"}
    )
    server.stop()
    await middleware.reset()


async def test_a_header_the_handler_repeats_keeps_every_value(
    answer: HTTPResponse,
) -> None:
    assert answer.headers.get_list("X-Tag") == ["first", "second"]


async def test_the_cors_vary_merge_keeps_every_value_the_handler_set(
    answer: HTTPResponse,
) -> None:
    vary = ",".join(answer.headers.get_list("Vary"))

    assert {"accept", "cookie", "origin"} <= {
        token.strip().lower() for token in vary.split(",")
    }
