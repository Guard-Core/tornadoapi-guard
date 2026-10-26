from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core._utils.app_scope import (
    _current_app_scope,
    app_scope_of,
    hold_app_scope,
    release_app_scope,
)
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
PROXY = "10.0.0.1"


class _Handler(SecurityHandler):
    def initialize(self, seen: dict[str, Any], config: SecurityConfig) -> None:
        self.seen = seen
        self.config = config

    async def prepare(self) -> None:
        self.seen.setdefault("before", []).append(_current_app_scope.get())
        await super().prepare()

    async def get(self) -> None:
        self.seen["scope"] = _current_app_scope.get()
        manager = ip_ban_manager_for(self.config)
        self.seen["banned"] = await manager.ban_ip(PROXY, 60)
        self.write({"ok": True})


class _Boom(SecurityHandler):
    def initialize(self, seen: dict[str, Any], config: SecurityConfig) -> None:
        self.seen = seen

    async def get(self) -> None:
        raise RuntimeError("view failed")


async def _serve(
    prefix: str, proxies: tuple[str, ...], seen: dict[str, Any]
) -> tuple[int, SecurityConfig, tornado.httpserver.HTTPServer]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        trusted_proxies=proxies,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(config=config)
    app = tornado.web.Application(
        [
            (r"/ban", _Handler, {"seen": seen, "config": config}),
            (r"/boom", _Boom, {"seen": seen, "config": config}),
        ],
        security_middleware=middleware,
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    return int(sockets[0].getsockname()[1]), config, server


async def _get(port: int, path: str) -> int:
    try:
        return (await AsyncHTTPClient().fetch(f"http://127.0.0.1:{port}{path}")).code
    except HTTPClientError as error:
        return error.code


@pytest.fixture
async def servers() -> AsyncGenerator[list[tornado.httpserver.HTTPServer], None]:
    started: list[tornado.httpserver.HTTPServer] = []
    yield started
    for server in started:
        server.stop()


async def test_a_ban_in_a_handler_goes_through_the_handlers_own_app(
    servers: list[tornado.httpserver.HTTPServer],
) -> None:
    seen_a: dict[str, Any] = {}
    seen_b: dict[str, Any] = {}
    port_a, config_a, server_a = await _serve("wp136-hold:", (PROXY,), seen_a)
    port_b, config_b, server_b = await _serve("wp136-hold:", (), seen_b)
    servers.extend([server_a, server_b])
    try:
        assert await _get(port_a, "/ban") == 200
        assert await _get(port_b, "/ban") == 200
        assert await _get(port_a, "/ban") == 200
    finally:
        await ip_ban_manager_for(config_b).unban_ip(PROXY, config=config_b)

    assert seen_a["scope"] is app_scope_of(config_a)
    assert seen_b["scope"] is app_scope_of(config_b)
    assert seen_a["banned"] is False
    assert seen_b["banned"] is True


async def test_a_raising_handler_leaves_no_scope_for_the_next_request(
    servers: list[tornado.httpserver.HTTPServer],
) -> None:
    seen: dict[str, Any] = {}
    port, config, server = await _serve("wp136-boom:", (), seen)
    servers.append(server)

    assert await _get(port, "/boom") == 500
    assert await _get(port, "/ban") == 200
    await ip_ban_manager_for(config).unban_ip(PROXY, config=config)

    assert seen["before"] == [None]
    assert _current_app_scope.get() is None


async def test_a_nested_hold_hands_back_the_outer_apps_scope() -> None:
    outer = SecurityConfig(enable_redis=False)
    inner = SecurityConfig(enable_redis=False)
    app_scope_of(outer), app_scope_of(inner)
    outer_token = hold_app_scope(outer)
    inner_token = hold_app_scope(inner)
    assert _current_app_scope.get() is app_scope_of(inner)

    release_app_scope(inner_token)

    assert _current_app_scope.get() is app_scope_of(outer)
    release_app_scope(outer_token)
    assert _current_app_scope.get() is None
