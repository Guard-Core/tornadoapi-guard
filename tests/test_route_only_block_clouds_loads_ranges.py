from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

AWS_RANGE = ipaddress.ip_network("198.51.100.0/24")
CLIENT = {"X-Forwarded-For": "198.51.100.77"}


@pytest.fixture
async def route_only_server() -> AsyncGenerator[int, None]:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        trusted_proxies=["127.0.0.1"],
    )
    decorator = SecurityDecorator(config)
    middleware = SecurityMiddleware(config=config)
    middleware.set_decorator_handler(decorator)

    class RouteHandler(SecurityHandler):
        @decorator.block_clouds(["AWS"])
        async def get(self) -> None:
            self.write({"ok": "yes"})

    app = tornado.web.Application(
        [(r"/r", RouteHandler)],
        security_middleware=middleware,
        guard_decorator=decorator,
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port: int = sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.stop()
        await middleware.reset()


async def test_a_route_only_block_clouds_loads_its_ranges_and_blocks(
    route_only_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetch_aws = AsyncMock(return_value=({AWS_RANGE}, {}))
    monkeypatch.setattr(
        "guard_core.handlers.cloud_handler._fetch_provider_ranges", fetch_aws
    )
    client = AsyncHTTPClient()
    try:
        url = f"http://127.0.0.1:{route_only_server}/r"
        await client.fetch(url, headers=CLIENT, raise_error=False)
        await asyncio.sleep(0.5)
        response = await client.fetch(url, headers=CLIENT, raise_error=False)
    finally:
        client.close()

    fetch_aws.assert_awaited_with("AWS")
    assert response.code == 403
