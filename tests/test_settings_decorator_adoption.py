from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

security = SecurityDecorator(
    SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
)


class Counted(SecurityHandler):
    async def get(self) -> None:
        self.write("ok")


class Walled(SecurityHandler):
    async def get(self) -> None:
        self.write("ok")


class Banning(SecurityHandler):
    async def get(self) -> None:
        self.write("ok")


# Registered by call: the engine types decorated functions as DecoratedFunction.
security.usage_monitor(max_calls=2, window=60, action="throttle")(Counted.get)
security.require_ip(whitelist=["203.0.113.50"])(Walled.get)
security.usage_monitor(max_calls=1, window=60, action="ban")(Banning.get)

Fetch = Callable[[str], Awaitable[int]]


@pytest.fixture
async def settings_only_app() -> AsyncGenerator[tuple[Fetch, SecurityMiddleware], None]:
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_rate_limiting=False,
            trusted_proxies=["127.0.0.1"],
            ban_on_hostile_signals=False,
        )
    )
    app = tornado.web.Application(
        [(r"/counted", Counted), (r"/walled", Walled), (r"/banning", Banning)],
        security_middleware=middleware,
        guard_decorator=security,
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]

    async def fetch(path: str) -> int:
        client: Any = AsyncHTTPClient()
        response = await client.fetch(
            f"http://127.0.0.1:{port}{path}",
            headers={"X-Forwarded-For": "198.51.100.77"},
            raise_error=False,
        )
        return int(response.code)

    yield fetch, middleware
    server.stop()
    await middleware.reset()


async def test_a_route_rule_set_through_the_settings_applies(
    settings_only_app: tuple[Fetch, SecurityMiddleware],
) -> None:
    fetch, _ = settings_only_app
    assert await fetch("/walled") == 403


async def test_a_behavior_rule_set_through_the_settings_applies(
    settings_only_app: tuple[Fetch, SecurityMiddleware],
) -> None:
    fetch, _ = settings_only_app
    assert [await fetch("/counted") for _ in range(4)] == [200, 200, 429, 429]


async def test_the_settings_decorator_reaches_every_context_the_setter_binds(
    settings_only_app: tuple[Fetch, SecurityMiddleware],
) -> None:
    fetch, middleware = settings_only_app
    await fetch("/counted")
    assert middleware.guard_decorator is security
    assert middleware.handler_initializer.guard_decorator is security
    assert middleware.route_resolver.context.guard_decorator is security
    assert middleware.response_factory.context.guard_decorator is security
    assert middleware.behavioral_processor.context.guard_decorator is security


async def test_a_ban_rule_set_through_the_settings_bans_on_the_apps_ban_manager(
    settings_only_app: tuple[Fetch, SecurityMiddleware],
) -> None:
    fetch, middleware = settings_only_app
    apps_manager = ip_ban_manager_for(middleware.config)

    for _ in range(3):
        await fetch("/banning")

    assert await apps_manager.is_ip_banned("198.51.100.77")
    assert security.behavior_tracker.bound_ban_manager is apps_manager
