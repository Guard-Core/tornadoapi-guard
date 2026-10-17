from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class Page(SecurityHandler):
    def get(self, *args: str) -> None:
        self.write("page")


ROUTES: list[tuple[str, type[tornado.web.RequestHandler]]] = [
    (r"/health", Page),
    (r"/items/(\d+)", Page),
    (r"/admin/(.*)", Page),
]


@pytest.fixture
async def serve() -> AsyncGenerator[Any, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(entries: list[str]) -> Any:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            exclude_paths=entries,
            ban_on_hostile_signals=False,
        )
        middleware = SecurityMiddleware(config=config)
        app = tornado.web.Application(ROUTES, security_middleware=middleware)
        app.add_handlers(r"example\.test", [(r"/vhost", Page)])
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        return sockets[0].getsockname()[1], middleware

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def _get(port: int, path: str, count: int = 1) -> None:
    client = AsyncHTTPClient()
    try:
        for _ in range(count):
            await client.fetch(f"http://127.0.0.1:{port}{path}", raise_error=False)
    finally:
        client.close()


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and "exclude_paths entry" in r.getMessage()
    ]


def _typo(entry: str) -> str:
    return (
        f"exclude_paths entry {entry!r} matches no registered route; check it for "
        "a typo."
    )


async def test_only_a_typo_entry_warns_once_on_a_real_application(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    entries = [
        "/docs",
        "/health",
        "/items",
        "/items/7",
        "/admin",
        "/admin/anything",
        "/vhost",
        "/static",
        "/typo",
    ]
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        port, _ = await serve(entries)
        await _get(port, "/health", 3)

    assert _warnings(caplog) == [_typo("/typo")]


async def test_the_prefixes_list_every_pattern_head_including_virtual_hosts(
    serve: Any,
) -> None:
    port, middleware = await serve([])
    await _get(port, "/health")

    assert set(middleware.static_route_prefixes()) == {
        "/health",
        "/items/",
        "/admin/",
        "/vhost",
    }


async def test_the_prefixes_are_the_open_root_before_the_app_is_known() -> None:
    middleware = SecurityMiddleware(
        config=SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
    )

    assert middleware.static_route_prefixes() == ("/",)


async def test_a_rule_without_a_path_regex_counts_as_a_match_for_everything(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from tornado.routing import AnyMatches, Rule

    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            exclude_paths=["/anything"],
            ban_on_hostile_signals=False,
        )
    )
    app = tornado.web.Application(
        [Rule(AnyMatches(), Page)], security_middleware=middleware
    )
    middleware._routing_application = app

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        assert middleware.static_route_prefixes() == ("/",)
