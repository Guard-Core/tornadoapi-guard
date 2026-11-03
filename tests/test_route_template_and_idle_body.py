from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any, cast

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from tornado.routing import PathMatches

import tornadoapi_guard.middleware as middleware_module
from tornadoapi_guard import SecurityHandler, SecurityMiddleware
from tornadoapi_guard.adapters import TornadoGuardRequest


def _application_of(middleware: SecurityMiddleware) -> tornado.web.Application:
    application = middleware._routing_application
    assert application is not None
    return application


class PageHandler(SecurityHandler):
    async def get(self, *args: str) -> None:
        self.write({"ok": True})

    async def post(self, *args: str) -> None:
        self.write({"received": len(self.request.body)})


ROUTES: list[Any] = [
    (r"/shop/cart\.php", PageHandler),
    (r"/forum/viewtopic[.]php", PageHandler),
    (r"/files/(.*)", PageHandler),
    (r"/legacy/(.*)\.php", PageHandler),
    (r"/echo", PageHandler),
    (r"/(?P<language>[^/]+)/news", PageHandler),
]


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "geo_ip_handler": None,
        "enable_redis": False,
        "enable_penetration_detection": True,
        "enable_rate_limiting": False,
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


async def _start(
    config: SecurityConfig,
) -> tuple[tornado.httpserver.HTTPServer, int, SecurityMiddleware]:
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    app = tornado.web.Application(ROUTES, security_middleware=middleware)
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    return server, sockets[0].getsockname()[1], middleware


@pytest.fixture
async def app() -> AsyncGenerator[tuple[int, SecurityMiddleware], None]:
    server, port, middleware = await _start(_config())
    try:
        yield port, middleware
    finally:
        server.stop()
        await middleware.reset()


async def _status(port: int, path: str, **kwargs: Any) -> int:
    try:
        response = await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{port}{path}", **kwargs
        )
    except HTTPClientError as error:
        return error.code
    return int(response.code)


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/shop/cart.php", 200),
        ("/forum/viewtopic.php", 200),
        ("/legacy/x/y.php", 200),
        ("/files/shop/cart.php", 400),
        ("/files/a.php", 400),
        ("/echo", 200),
        ("/language/news", 400),
    ],
)
async def test_a_script_path_is_clean_only_when_the_app_declares_it(
    app: tuple[int, SecurityMiddleware], path: str, status: int
) -> None:
    port, _ = app

    assert await _status(port, path) == status


async def test_the_matched_template_is_the_regex_of_the_matching_rule(
    app: tuple[int, SecurityMiddleware],
) -> None:
    port, middleware = app
    await _status(port, "/echo")

    assert middleware.route_template("/shop/cart.php") == r"/shop/cart\.php$"
    assert middleware.route_template("/files/x.php") == "/files/(.*)$"
    assert middleware.route_template("/legacy/a.php") == r"/legacy/(.*)\.php$"
    assert middleware.route_template("/nowhere.php") is None


async def test_a_middleware_that_has_seen_no_request_has_no_template() -> None:
    middleware = SecurityMiddleware(config=_config())

    assert middleware.route_template("/shop/cart.php") is None


async def test_the_template_is_cached_until_the_route_count_changes(
    app: tuple[int, SecurityMiddleware], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, middleware = app
    await _status(port, "/echo")
    calls: list[str] = []
    real = middleware_module._matched_template

    def counting(rules: Any, request: Any) -> str | None:
        if rules is _application_of(middleware).default_router.rules:
            calls.append(request.path)
        return real(rules, request)

    monkeypatch.setattr(middleware_module, "_matched_template", counting)

    middleware.route_template("/shop/cart.php")
    middleware.route_template("/shop/cart.php")
    assert calls == ["/shop/cart.php"]

    application = _application_of(middleware)
    application.wildcard_router.add_rules([(r"/late\.php", PageHandler)])
    middleware.route_template("/shop/cart.php")
    assert calls == ["/shop/cart.php", "/shop/cart.php"]
    assert middleware.route_template("/late.php") == r"/late\.php$"


async def test_the_template_cache_is_cleared_when_the_rules_object_changes(
    app: tuple[int, SecurityMiddleware],
) -> None:
    port, middleware = app
    await _status(port, "/echo")
    assert middleware.route_template("/shop/cart.php") == r"/shop/cart\.php$"

    application = _application_of(middleware)
    application.default_router.rules = [
        type(rule)(rule.matcher, rule.target)
        for rule in application.default_router.rules
    ]
    application.wildcard_router.rules[:] = [
        rule
        for rule in application.wildcard_router.rules
        if not (
            isinstance(rule.matcher, PathMatches)
            and "cart" in str(rule.matcher.regex.pattern)
        )
    ]

    assert middleware.route_template("/shop/cart.php") is None


async def test_the_template_cache_drops_its_oldest_entry_at_the_limit(
    app: tuple[int, SecurityMiddleware], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, middleware = app
    await _status(port, "/echo")
    monkeypatch.setattr(middleware_module, "_ROUTE_TEMPLATE_CACHE_SIZE", 2)

    for path in ("/a.php", "/b.php", "/c.php"):
        middleware.route_template(path)

    assert list(middleware._route_template_cache) == [
        ("localhost", "/b.php"),
        ("localhost", "/c.php"),
    ]
    middleware.route_template("/b.php")
    middleware.route_template("/d.php")
    assert list(middleware._route_template_cache) == [
        ("localhost", "/b.php"),
        ("localhost", "/d.php"),
    ]


async def test_the_idle_read_returns_the_buffered_prefix() -> None:
    class _Request:
        body = b"hello world"

    class _Handler:
        request = _Request()
        application = None

    guard_request = TornadoGuardRequest(cast(Any, _Handler()))

    assert await guard_request.read_body_prefix_until_idle(5, 1.0) == b"hello"
    assert await guard_request.read_body_prefix_until_idle(0, 1.0) == b""


async def test_a_body_over_the_inspect_cap_is_scanned_on_its_prefix() -> None:
    server, port, middleware = await _start(
        _config(detection_max_body_inspect_bytes=1024)
    )
    try:
        body = b"q=<script>alert(1)</script>" + b"a" * 5000
        status = await _status(
            port,
            "/echo",
            method="POST",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    finally:
        server.stop()
        await middleware.reset()

    assert status == 400
