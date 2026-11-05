from __future__ import annotations

import asyncio
import gc

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient
from tornado.web import RequestHandler

from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class _Page(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        blocked_user_agents=["badbot"],
    )


async def _serve_requests(count: int, app: tornado.web.Application) -> None:
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    port = sockets[0].getsockname()[1]
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    client = AsyncHTTPClient()
    statuses = []
    for index in range(count):
        headers = {"User-Agent": "badbot" if index % 5 == 4 else "friendly"}
        response = await client.fetch(
            f"http://127.0.0.1:{port}/", headers=headers, raise_error=False
        )
        statuses.append(response.code)
    server.stop()
    await server.close_all_connections()
    assert 403 in statuses
    assert 200 in statuses


def _one_app_serves(count: int) -> None:
    async def run() -> None:
        middleware = SecurityMiddleware(config=_config())
        app = tornado.web.Application([(r"/", _Page)], security_middleware=middleware)
        await _serve_requests(count, app)

    asyncio.run(run())


def _many_apps_each_serve_five(apps: int) -> None:
    async def run() -> None:
        for _ in range(apps):
            middleware = SecurityMiddleware(config=_config())
            app = tornado.web.Application(
                [(r"/", _Page)], security_middleware=middleware
            )
            await _serve_requests(5, app)

    asyncio.run(run())


def _live_handlers() -> int:
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, RequestHandler))


def _live_configs() -> int:
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, SecurityConfig))


@pytest.mark.parametrize("count", [10, 50])
def test_finished_requests_leave_no_live_handler(count: int) -> None:
    before = _live_handlers()
    _one_app_serves(count)
    assert _live_handlers() == before


def test_live_handlers_do_not_depend_on_the_request_count() -> None:
    _one_app_serves(10)
    at_ten = _live_handlers()
    _one_app_serves(50)
    assert _live_handlers() == at_ten


def test_live_configs_do_not_depend_on_the_app_count() -> None:
    _many_apps_each_serve_five(10)
    at_ten = _live_configs()
    _many_apps_each_serve_five(50)
    at_fifty = _live_configs()
    assert at_fifty == at_ten
