from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

RAW_ATTACK_PATHS = [
    "/cos%0Asystem%0A(S'id'%0AtR.",
    "/name=x%0D%0AHTTP/1.1%20200%20OK",
    "/search=x%0D%0ALocation:%20http://evil.example",
    "/id=1%0D%0ASet-Cookie:%20session=hijacked",
    "/value%0ALocation:%20http://evil.example",
]


class CatchAll(SecurityHandler):
    async def get(self, _path: str = "") -> None:
        self.write("REACHED")


@pytest.fixture
async def guarded_server() -> AsyncGenerator[int, None]:
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            enable_rate_limiting=False,
            enable_ip_banning=False,
        )
    )
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"(?s)(.*)", CatchAll)], security_middleware=middleware
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    try:
        yield int(sockets[0].getsockname()[1])
    finally:
        server.stop()


async def _get_raw(port: int, raw_path: str) -> tuple[int, str]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        request = (
            f"GET {raw_path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode("ascii"))
        await writer.drain()
        response = (await reader.read()).decode("utf-8", errors="replace")
    finally:
        writer.close()
        await writer.wait_closed()
    status = int(response.split(" ", 2)[1])
    return status, response.partition("\r\n\r\n")[2]


@pytest.mark.parametrize("raw_path", RAW_ATTACK_PATHS)
async def test_real_server_refuses_a_percent_encoded_attack_path(
    guarded_server: int, raw_path: str
) -> None:
    status, body = await _get_raw(guarded_server, raw_path)
    assert status == 400, body
    assert "REACHED" not in body


async def test_real_server_lets_a_benign_path_through(guarded_server: int) -> None:
    status, body = await _get_raw(guarded_server, "/hello%20world")
    assert status == 200
    assert body == "REACHED"
