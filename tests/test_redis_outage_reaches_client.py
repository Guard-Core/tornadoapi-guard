"""D-188 end to end: a runtime Redis outage reaches the Tornado client as 503
with Retry-After.

Real Tornado HTTP server and client, real engine. Only the Redis client the
engine holds is replaced, by one whose commands raise redis' own
ConnectionError.
"""

from __future__ import annotations

from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from tornado.httpclient import AsyncHTTPClient

from tests.redis_isolation import REDIS_PREFIX, REDIS_URL
from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class _DeadRedis(Redis):
    async def execute_command(self, *args: Any, **options: Any) -> Any:
        raise RedisConnectionError("Redis went away")


class OpenHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "ok"})


async def _status_and_retry_after_after_redis_died(
    path: str, **overrides: Any
) -> tuple[int, str | None]:
    settings: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": f"{REDIS_PREFIX}wp192:",
        "enable_agent": False,
        "fail_secure": True,
        "redis_fail_open": False,
        "enable_penetration_detection": False,
        "exclude_paths": ["/health"],
    }
    settings.update(overrides)
    middleware = SecurityMiddleware(config=SecurityConfig(**settings))
    app = tornado.web.Application(
        [(r"/open", OpenHandler), (r"/health", OpenHandler)],
        security_middleware=middleware,
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    base = f"http://127.0.0.1:{sockets[0].getsockname()[1]}"
    try:
        client = AsyncHTTPClient()
        warm = await client.fetch(f"{base}/open", raise_error=False)
        assert warm.code == 200
        assert middleware.redis_handler is not None
        middleware.redis_handler._redis = _DeadRedis()
        response = await client.fetch(f"{base}{path}", raise_error=False)
        return response.code, response.headers.get("Retry-After")
    finally:
        server.stop()
        await middleware.reset()


@pytest.mark.parametrize("path", ["/open", "/health"])
async def test_runtime_outage_answers_503_with_retry_after(path: str) -> None:
    status, retry_after = await _status_and_retry_after_after_redis_died(path)
    assert status == 503
    assert retry_after == "5"


@pytest.mark.parametrize("path", ["/open", "/health"])
async def test_passive_mode_admits_during_a_runtime_outage(path: str) -> None:
    status, _ = await _status_and_retry_after_after_redis_died(path, passive_mode=True)
    assert status == 200


@pytest.mark.parametrize("path", ["/open", "/health"])
async def test_redis_fail_open_admits_during_a_runtime_outage(path: str) -> None:
    status, _ = await _status_and_retry_after_after_redis_died(
        path, redis_fail_open=True
    )
    assert status == 200
