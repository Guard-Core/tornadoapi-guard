from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.core.checks import DEFAULT_CHECK_CLASSES
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

BANNED_IP = "10.0.0.99"
OTHER_IP = "10.0.0.7"

config = SecurityConfig(
    blacklist=[BANNED_IP],
    trusted_proxies=["127.0.0.1"],
    enable_redis=False,
    enable_penetration_detection=False,
    enable_cors=True,
    cors_allow_origins=["https://app.example.com"],
    auth_verifier=lambda request, credential: {"user": "ok"} if credential else None,
)
security = SecurityDecorator(config)


class NeedsHeaderHandler(SecurityHandler):
    async def get(self) -> None:
        self.write("needs-header-body")


class LimitedAndAuthedHandler(SecurityHandler):
    async def get(self) -> None:
        self.write("limited-and-authed-body")


# Registered by call, not as a decorator: the engine types decorated
# functions as DecoratedFunction, which mypy rejects as a get() override.
security.require_headers({"X-Client-ID": "required"})(NeedsHeaderHandler.get)
security.require_auth()(LimitedAndAuthedHandler.get)
security.rate_limit(requests=1, window=60)(LimitedAndAuthedHandler.get)

Fetch = Callable[[str, str], Awaitable[HTTPResponse]]


@pytest.fixture
async def served() -> AsyncGenerator[tuple[Fetch, SecurityMiddleware], None]:
    middleware = SecurityMiddleware(config=config)
    middleware.set_decorator_handler(security)
    app = tornado.web.Application(
        [
            (r"/needs-header", NeedsHeaderHandler),
            (r"/limited-and-authed", LimitedAndAuthedHandler),
        ],
        security_middleware=middleware,
        guard_decorator=security,
    )
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]

    async def _fetch(path: str, client_ip: str) -> HTTPResponse:
        return await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{port}{path}",
            headers={"X-Forwarded-For": client_ip},
            raise_error=False,
        )

    yield _fetch, middleware
    server.stop()
    await middleware.reset()


async def test_a_banned_ip_without_a_required_header_gets_the_ban_answer(
    served: tuple[Fetch, SecurityMiddleware],
) -> None:
    fetch, _ = served

    banned = await fetch("/needs-header", BANNED_IP)
    missing_header = await fetch("/needs-header", OTHER_IP)

    assert banned.code == 403
    assert missing_header.code == 400


async def test_a_request_over_the_rate_limit_that_fails_authentication_gets_429(
    served: tuple[Fetch, SecurityMiddleware],
) -> None:
    fetch, _ = served

    first = await fetch("/limited-and-authed", OTHER_IP)
    second = await fetch("/limited-and-authed", OTHER_IP)

    assert first.code == 401
    assert second.code == 429


async def test_the_pipeline_keeps_the_engine_default_order(
    served: tuple[Fetch, SecurityMiddleware],
) -> None:
    _, middleware = served
    engine_order = [cls(middleware).check_name for cls in DEFAULT_CHECK_CLASSES]

    assert middleware.security_pipeline is not None
    names = middleware.security_pipeline.get_check_names()
    assert "cors_preflight" in names
    assert names == [name for name in engine_order if name in names]
