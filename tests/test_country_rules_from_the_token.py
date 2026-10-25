from __future__ import annotations

from collections.abc import AsyncGenerator, Callable, Generator
from pathlib import Path
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tests.geo_database import CLIENT_IP, country_database_bytes
from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _config(
    tmp_path: Path, blocked_countries: frozenset[str] = frozenset()
) -> SecurityConfig:
    db_path = tmp_path / "geo.mmdb"
    db_path.write_bytes(country_database_bytes("CN"))
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        ipinfo_token="tok",
        ipinfo_db_path=db_path,
        lazy_init=False,
        trusted_proxies=("127.0.0.1",),
        blocked_countries=blocked_countries,
    )


@pytest.fixture
async def serve() -> AsyncGenerator[Callable[[SecurityConfig], Any], None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(config: SecurityConfig) -> int:
        decorator = SecurityDecorator(config)

        class Blocked(SecurityHandler):
            @decorator.block_countries(["CN"])
            def get(self) -> None:
                self.write("blocked")

        class Open(SecurityHandler):
            def get(self) -> None:
                self.write("open")

        middleware = SecurityMiddleware(config=config)
        middleware.set_decorator_handler(decorator)
        app = tornado.web.Application(
            [(r"/blocked", Blocked), (r"/open", Open)], security_middleware=middleware
        )
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        port: int = sockets[0].getsockname()[1]
        return port

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def _status(port: int, path: str) -> int:
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(
            f"http://127.0.0.1:{port}{path}",
            headers={"X-Forwarded-For": CLIENT_IP},
            raise_error=False,
        )
        return int(response.code)
    finally:
        client.close()


async def test_global_blocked_countries_from_the_token_block(
    serve: Any, tmp_path: Path
) -> None:
    port = await serve(_config(tmp_path, blocked_countries=frozenset({"CN"})))

    assert await _status(port, "/open") == 403


async def test_route_block_countries_blocks_without_a_global_country_rule(
    serve: Any, tmp_path: Path
) -> None:
    port = await serve(_config(tmp_path))

    assert await _status(port, "/blocked") == 403
    assert await _status(port, "/open") == 200
