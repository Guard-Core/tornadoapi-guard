from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

ORIGIN = "https://app.example.com"


class _VaryHandler(SecurityHandler):
    def get(self, value: str) -> None:
        if value != "none":
            self.set_header("Vary", value)
        self.write({"ok": "yes"})


@pytest.fixture
async def port() -> AsyncGenerator[int, None]:
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_cors=True,
            cors_allow_origins=[ORIGIN],
            enable_redis=False,
            enable_rate_limiting=False,
            enable_ip_banning=False,
        )
    )
    app = tornado.web.Application(
        [(r"/vary/(.+)", _VaryHandler)], security_middleware=middleware
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


@pytest.mark.parametrize(
    ("app_vary", "expected"),
    [
        ("none", "Origin"),
        ("Accept-Encoding", "Accept-Encoding, Origin"),
        ("Accept-Encoding, Cookie", "Accept-Encoding, Cookie, Origin"),
        ("origin", "origin"),
        ("*", "*"),
    ],
)
async def test_cors_vary_is_merged_into_the_vary_of_the_application(
    port: int, app_vary: str, expected: str
) -> None:
    response = await AsyncHTTPClient().fetch(
        f"http://127.0.0.1:{port}/vary/{app_vary.replace(' ', '%20')}",
        headers={"Origin": ORIGIN},
    )

    assert response.headers.get_list("Vary") == [expected]
