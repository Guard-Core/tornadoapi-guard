"""LEDGER 6.793 / D-317 amendment 2: a request on an app that was released rebinds
and initializes it before it decides, once, whatever the number of first requests."""

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers._ipban_bans import _VERSION_PAIR
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError

from tests.redis_isolation import REDIS_PREFIX, REDIS_URL
from tornadoapi_guard import SecurityHandler, SecurityMiddleware, release_app

CLIENT_IP = "127.0.0.1"


class _Page(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {"enable_redis": False, "enable_agent": False}
    settings.update(overrides)
    return SecurityConfig(**settings)


@asynccontextmanager
async def _serving(middleware: SecurityMiddleware) -> AsyncIterator[str]:
    app = tornado.web.Application([(r"/", _Page)], security_middleware=middleware)
    sockets = tornado.netutil.bind_sockets(0, CLIENT_IP)
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    try:
        yield f"http://{CLIENT_IP}:{sockets[0].getsockname()[1]}/"
    finally:
        server.stop()
        await server.close_all_connections()


async def _status(url: str) -> int:
    try:
        return (await AsyncHTTPClient().fetch(url)).code
    except HTTPClientError as refused:
        return refused.code


def _limiter_managers(middleware: SecurityMiddleware) -> list[Any]:
    assert middleware.security_pipeline is not None
    return [
        check.ip_ban_manager
        for check in middleware.security_pipeline.checks
        if isinstance(check, RateLimitCheck)
    ]


async def test_a_late_request_rebinds_and_its_ban_lands_on_its_own_manager() -> None:
    config = _config()
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    other_config = _config()
    async with _serving(middleware) as url:
        assert await _status(url) == 200
        release_app(config)
        assert (
            ip_ban_manager_for(other_config, bind=True) is ipban_module.ip_ban_manager
        )
        try:
            assert await _status(url) == 200
            own = ip_ban_manager_for(config)
            assert own is not ipban_module.ip_ban_manager
            managers = _limiter_managers(middleware)
            assert managers
            assert all(manager is own for manager in managers)
            await managers[0].ban_ip("198.51.100.7", 60, "pin")
            assert await own.is_ip_banned("198.51.100.7")
            assert not await ipban_module.ip_ban_manager.is_ip_banned("198.51.100.7")
        finally:
            release_app(other_config)


async def test_two_concurrent_first_requests_after_a_release_initialize_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    async with _serving(middleware) as url:
        assert await _status(url) == 200
        calls: list[float] = []

        async def counted_initialize() -> None:
            calls.append(time.monotonic())
            await asyncio.sleep(0.1)

        monkeypatch.setattr(
            middleware.handler_initializer,
            "initialize_redis_handlers",
            counted_initialize,
        )
        release_app(config)
        statuses = await asyncio.gather(_status(url), _status(url))
    assert statuses == [200, 200]
    assert len(calls) == 1


async def test_a_ban_another_worker_wrote_in_redis_is_refused_after_a_release() -> None:
    prefix = f"{REDIS_PREFIX}wp620r3:{uuid.uuid4().hex[:8]}:"
    config = _config(enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix)
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    async with _serving(middleware) as url:
        assert await _status(url) == 200
        release_app(config)
        worker = RedisManager(
            SecurityConfig(
                enable_redis=True,
                redis_url=REDIS_URL,
                redis_prefix=prefix,
                enable_agent=False,
            )
        )
        await worker.initialize()
        try:
            await worker.write_ban_extending_only(
                "banned_ips",
                CLIENT_IP,
                str(time.time() + 300),
                300,
                version=_VERSION_PAIR,
            )
            assert await _status(url) == 403
            assert ip_ban_manager_for(config).redis_handler is not None
        finally:
            await worker.close()
            if middleware.handler_initializer.redis_handler is not None:
                await middleware.handler_initializer.redis_handler.close()
