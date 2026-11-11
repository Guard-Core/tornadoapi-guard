from __future__ import annotations

import gc
from collections.abc import Iterator

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

import tornadoapi_guard
from tornadoapi_guard import SecurityHandler, SecurityMiddleware, release_app

_REQUESTS = 25


class _Page(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


def _config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False, enable_rate_limiting=False)


def _default_ban_manager_serves_a_new_app() -> bool:
    return ip_ban_manager_for(_config(), bind=True) is ipban_module.ip_ban_manager


async def _serve_requests(middleware: SecurityMiddleware, count: int) -> None:
    app = tornado.web.Application([(r"/", _Page)], security_middleware=middleware)
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    port = sockets[0].getsockname()[1]
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    client = AsyncHTTPClient()
    for _ in range(count):
        response = await client.fetch(f"http://127.0.0.1:{port}/")
        assert response.code == 200
    server.stop()
    await server.close_all_connections()


@pytest.fixture
def collector_off() -> Iterator[None]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def test_release_app_is_the_engines_function_for_a_host_to_call() -> None:
    import guard_core

    assert "release_app" in tornadoapi_guard.__all__
    assert release_app is guard_core.release_app


@pytest.mark.usefixtures("collector_off")
async def test_requests_through_an_app_leave_the_default_binding_unchanged() -> None:
    config = _config()
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    assert ip_ban_manager_for(config) is ipban_module.ip_ban_manager
    await _serve_requests(middleware, _REQUESTS)
    assert ip_ban_manager_for(config) is ipban_module.ip_ban_manager
    assert not _default_ban_manager_serves_a_new_app()


@pytest.mark.usefixtures("collector_off")
async def test_a_host_release_hands_the_default_to_the_next_app() -> None:
    config = _config()
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    await _serve_requests(middleware, 1)
    release_app(config)
    assert _default_ban_manager_serves_a_new_app()


@pytest.mark.usefixtures("collector_off")
async def test_an_app_that_is_never_released_keeps_its_default_until_collected() -> (
    None
):
    middleware = SecurityMiddleware(config=_config())
    await middleware.initialize()
    await _serve_requests(middleware, 1)
    assert not _default_ban_manager_serves_a_new_app()
    assert middleware is not None


async def test_the_config_is_bound_before_the_pipeline_is_built() -> None:
    SecurityMiddleware(config=_config())
    second_config = SecurityConfig(enable_redis=False)
    second = SecurityMiddleware(config=second_config)
    await second.initialize()
    assert second.security_pipeline is not None
    limiters = [
        check
        for check in second.security_pipeline.checks
        if isinstance(check, RateLimitCheck)
    ]
    own = ip_ban_manager_for(second_config)
    assert own is not ipban_module.ip_ban_manager
    assert limiters
    assert all(limiter.ip_ban_manager is own for limiter in limiters)
