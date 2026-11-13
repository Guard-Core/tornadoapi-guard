import uuid
from collections.abc import AsyncGenerator, Callable
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.exceptions import MisconfigurationError
from guard_core.handlers.ipban_handler import ip_ban_manager, ip_ban_manager_for
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tests.redis_isolation import REDIS_PREFIX, REDIS_URL
from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

PEER = "203.0.113.9"


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "ban_on_hostile_signals": False,
        "rate_limit": 1000,
        "trusted_proxies": ["127.0.0.1"],
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _quiet_decorator() -> SecurityDecorator:
    return SecurityDecorator(SecurityConfig(fail_on_misconfiguration=False))


def _handler(
    name: str, decorator: SecurityDecorator, wrap: Callable[..., Any] | None
) -> type[SecurityHandler]:
    def get(self: SecurityHandler) -> None:
        self.write("ok")

    get.__qualname__ = f"{name}.get"
    method = get if wrap is None else wrap(get)
    return type(name, (SecurityHandler,), {"get": method})


class Plain(SecurityHandler):
    def get(self) -> None:
        self.write("ok")


@pytest.fixture
async def serve() -> AsyncGenerator[Any, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(
        config: SecurityConfig, decorator: SecurityDecorator
    ) -> tuple[int, SecurityMiddleware]:
        middleware = SecurityMiddleware(config=config)
        routes = [
            ("/plain", Plain),
            (
                "/counted",
                _handler(
                    "Counted",
                    decorator,
                    decorator.usage_monitor(max_calls=1, window=60, action="ban"),
                ),
            ),
            (
                "/by-country",
                _handler("ByCountry", decorator, decorator.block_countries(["XX"])),
            ),
        ]
        app = tornado.web.Application(routes, security_middleware=middleware)
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        port = int(sockets[0].getsockname()[1])
        assert await _get(port, "/plain") == 200
        return port, middleware

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def _get(port: int, path: str) -> int:
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(
            f"http://127.0.0.1:{port}{path}",
            headers={"X-Forwarded-For": PEER},
            raise_error=False,
        )
        return int(response.code)
    finally:
        client.close()


async def test_a_ban_rule_of_a_late_decorator_bans_on_the_apps_ban_manager(
    serve: Any,
) -> None:
    decorator = _quiet_decorator()
    first = _config()
    await serve(first, _quiet_decorator())
    config = _config()
    port, middleware = await serve(config, decorator)
    apps_manager = ip_ban_manager_for(config)
    assert apps_manager is not ip_ban_manager

    middleware.set_decorator_handler(decorator)
    statuses = [await _get(port, "/counted") for _ in range(3)]

    assert statuses[0] == 200
    assert await apps_manager.is_ip_banned(PEER)
    assert decorator.behavior_tracker.bound_ban_manager is apps_manager


async def test_a_late_decorators_rule_counts_on_the_decorators_tracker_only(
    serve: Any,
) -> None:
    decorator = _quiet_decorator()
    port, middleware = await serve(_config(), decorator)

    middleware.set_decorator_handler(decorator)
    assert await _get(port, "/counted") == 200

    held = middleware.behavioral_processor.context.behavior_tracker
    assert held in (None, decorator.behavior_tracker)
    assert middleware.handler_initializer.behavior_tracker in (
        None,
        decorator.behavior_tracker,
    )
    assert any(decorator.behavior_tracker.usage_counts.values())


async def test_a_late_decorators_tracker_gets_redis_once_adoption_completed(
    serve: Any,
) -> None:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"{REDIS_PREFIX}wp779{uuid.uuid4().hex[:8]}:",
    )
    decorator = _quiet_decorator()
    port, middleware = await serve(config, decorator)

    middleware.set_decorator_handler(decorator)
    assert await _get(port, "/plain") == 200

    initializer = middleware.handler_initializer
    assert decorator.behavior_tracker.redis_handler is initializer.redis_handler
    assert decorator.behavior_tracker.redis_handler is not None


async def test_a_route_country_rule_of_a_late_decorator_builds_the_geo_handler(
    serve: Any,
) -> None:
    decorator = _quiet_decorator()
    _, middleware = await serve(_config(ipinfo_token="test_token"), decorator)
    before = middleware.geo_ip_handler

    middleware.set_decorator_handler(decorator)

    assert before is None
    assert middleware.geo_ip_handler is middleware.handler_initializer.geo_ip_handler
    assert middleware.geo_ip_handler is not None


async def test_a_raise_in_the_adoption_leaves_the_previous_decorator_bound(
    serve: Any,
) -> None:
    candidate = _quiet_decorator()
    _, middleware = await serve(_config(), candidate)
    previous = SecurityDecorator(SecurityConfig())
    middleware.set_decorator_handler(previous)
    candidate.config.fail_on_misconfiguration = True

    with pytest.raises(MisconfigurationError):
        middleware.set_decorator_handler(candidate)

    assert middleware.guard_decorator is previous
    assert middleware.handler_initializer.guard_decorator is previous
    assert middleware.route_resolver.context.guard_decorator is previous
    assert middleware.response_factory.context.guard_decorator is previous
    assert middleware.behavioral_processor.context.guard_decorator is previous
