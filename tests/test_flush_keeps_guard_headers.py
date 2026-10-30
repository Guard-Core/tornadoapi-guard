from collections.abc import AsyncGenerator

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

ORIGIN = "https://app.example"


class _Flushing(SecurityHandler):
    async def get(self) -> None:
        self.write("a")
        await self.flush()
        self.write("b")


class _Plain(SecurityHandler):
    async def get(self) -> None:
        self.write("ab")


@pytest.fixture
async def port() -> AsyncGenerator[int, None]:
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            exclude_paths=["/pass-flush", "/pass-plain"],
            enable_cors=True,
            cors_allow_origins=[ORIGIN],
            ban_on_hostile_signals=False,
            fail_on_misconfiguration=False,
            rate_limit=1000,
        )
    )
    application = tornado.web.Application(
        [
            (r"/pass-flush", _Flushing),
            (r"/pass-plain", _Plain),
            (r"/g-flush", _Flushing),
            (r"/g-plain", _Plain),
        ],
        security_middleware=middleware,
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(application)
    server.add_sockets(sockets)
    try:
        yield int(sockets[0].getsockname()[1])
    finally:
        server.stop()
        await middleware.reset()


async def _headers(port: int, path: str) -> dict[str, str]:
    response = await AsyncHTTPClient().fetch(
        f"http://127.0.0.1:{port}{path}", headers={"Origin": ORIGIN}
    )
    assert response.body == b"ab"
    return {name.lower(): value for name, value in response.headers.get_all()}


@pytest.mark.parametrize("route", ["pass", "g"])
async def test_a_flushing_handler_carries_the_headers_of_its_plain_twin(
    port: int, route: str
) -> None:
    plain = await _headers(port, f"/{route}-plain")
    flushed = await _headers(port, f"/{route}-flush")

    for name in (
        "x-content-type-options",
        "strict-transport-security",
        "access-control-allow-origin",
    ):
        assert flushed[name] == plain[name]
