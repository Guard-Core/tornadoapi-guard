from __future__ import annotations

import itertools
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

_IPS = itertools.count(1)

security = SecurityDecorator(
    SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
)


class LimitedHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


# Registered by call, not as a decorator: the engine types decorated
# functions as DecoratedFunction, which mypy rejects as a get() override.
security.usage_monitor(max_calls=2, window=60, action="throttle")(LimitedHandler.get)


class PingHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


class NotFoundHandler(SecurityHandler):
    async def get(self) -> None:
        raise tornado.web.HTTPError(404)


Fetch = Callable[[list[str]], Awaitable[list[HTTPResponse]]]
Serve = Callable[..., Awaitable[Fetch]]


@pytest.fixture
async def serve() -> AsyncGenerator[Serve, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def _serve(**overrides: Any) -> Fetch:
        fields: dict[str, Any] = {
            "enable_redis": False,
            "enable_penetration_detection": False,
            "enable_rate_limiting": False,
            "enable_ip_banning": True,
            "trusted_proxies": ["127.0.0.1"],
            "ban_on_hostile_signals": False,
        }
        fields.update(overrides)
        middleware = SecurityMiddleware(config=SecurityConfig(**fields))
        middleware.set_decorator_handler(security)
        app = tornado.web.Application(
            [(r"/limited", LimitedHandler), (r"/ping", PingHandler)],
            default_handler_class=NotFoundHandler,
            security_middleware=middleware,
            guard_decorator=security,
        )
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        port = sockets[0].getsockname()[1]
        headers = {"X-Forwarded-For": f"198.51.100.{next(_IPS)}"}

        async def fetch(paths: list[str]) -> list[HTTPResponse]:
            return [
                await AsyncHTTPClient().fetch(
                    f"http://127.0.0.1:{port}{path}", headers=headers, raise_error=False
                )
                for path in paths
            ]

        return fetch

    yield _serve
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def test_route_throttle_answers_429_with_retry_after(serve: Serve) -> None:
    fetch = await serve()
    responses = await fetch(["/limited"] * 4)
    assert [r.code for r in responses] == [200, 200, 429, 429]
    assert ["Retry-After" in r.headers for r in responses] == [
        False,
        False,
        True,
        True,
    ]
    assert all(1 <= int(r.headers["Retry-After"]) <= 60 for r in responses[2:])


async def test_global_throttle_covers_unrouted_paths(serve: Serve) -> None:
    fetch = await serve(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="usage", threshold=2, window=60, action="throttle"
            ),
        )
    )
    responses = await fetch(["/nope-1", "/nope-2", "/nope-3"])
    assert [r.code for r in responses] == [404, 404, 429]


async def test_throttled_requests_still_count_toward_a_global_ban_rule(
    serve: Serve,
) -> None:
    fetch = await serve(
        global_behavior_rules=(
            BehaviorRuleConfig(rule_type="usage", threshold=3, window=60, action="ban"),
        )
    )
    responses = await fetch(["/limited"] * 5)
    assert [r.code for r in responses] == [200, 200, 429, 429, 403]


async def test_global_return_rule_halves_its_threshold_after_a_detection_hit(
    serve: Serve,
) -> None:
    fetch = await serve(
        enable_penetration_detection=True,
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=4,
                window=60,
                pattern="status:404",
                action="ban",
                correlate_with_detection=True,
            ),
        ),
    )
    probe = "/ping?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    responses = await fetch([probe] + ["/missing"] * 4 + ["/ping"])
    assert [r.code for r in responses[1:]] == [404, 404, 404, 403, 403]


@pytest.mark.parametrize("client_ip", ["", "127.0.0.1"])
async def test_requests_without_rules_skip_the_usage_call(
    client_ip: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    middleware = SecurityMiddleware(
        config=SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
    )
    usage = AsyncMock()
    monkeypatch.setattr(middleware.behavioral_processor, "process_usage_rules", usage)
    assert await middleware._process_behavioral_usage(Mock(), client_ip, None) is None
    usage.assert_not_called()
