from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

RIGHT_KEY = "right-key"

security = SecurityDecorator(SecurityConfig(enable_redis=False))


def _verify(request: Any, credential: str) -> dict[str, str] | None:
    return {"user": "ok"} if credential == RIGHT_KEY else None


class KeyedHandler(SecurityHandler):
    async def get(self) -> None:
        self.write("keyed-handler-body")


# Registered by call, not as a decorator: the engine types decorated
# functions as DecoratedFunction, which mypy rejects as a get() override.
security.api_key_auth(verifier=_verify)(KeyedHandler.get)

Fetch = Callable[[dict[str, str]], Awaitable[HTTPResponse]]


@pytest.fixture
async def fetch() -> AsyncGenerator[Fetch, None]:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )
    middleware = SecurityMiddleware(config=config)
    middleware.set_decorator_handler(security)
    app = tornado.web.Application(
        [(r"/keyed", KeyedHandler)],
        security_middleware=middleware,
        guard_decorator=security,
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]

    async def _fetch(headers: dict[str, str]) -> HTTPResponse:
        return await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{port}/keyed", headers=headers, raise_error=False
        )

    yield _fetch
    server.stop()
    await middleware.reset()


async def test_missing_key_is_refused(fetch: Fetch) -> None:
    response = await fetch({})
    # D-153 / WP13: the exact 401 waits for the 5.x engine floor; guard-core 4.4.0
    # answers 400 for a missing key, so both are accepted until then.
    assert response.code in (400, 401)
    assert b"keyed-handler-body" not in response.body


async def test_wrong_key_is_refused(fetch: Fetch) -> None:
    response = await fetch({"X-API-Key": "wrong-key"})
    assert response.code == 401
    assert b"keyed-handler-body" not in response.body


async def test_right_key_reaches_the_handler(fetch: Fetch) -> None:
    response = await fetch({"X-API-Key": RIGHT_KEY})
    assert response.code == 200
    assert response.body == b"keyed-handler-body"
