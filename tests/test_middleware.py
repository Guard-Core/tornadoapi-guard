from __future__ import annotations

from collections.abc import AsyncGenerator
from unittest.mock import Mock

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import JsonValue
from tornado.httpclient import AsyncHTTPClient, HTTPClientError

from tornadoapi_guard import SecurityHandler, SecurityMiddleware


def _buffer_stats(stats: dict[str, JsonValue]) -> dict[str, JsonValue]:
    buffer_stats = stats["buffer_stats"]
    assert isinstance(buffer_stats, dict)
    return buffer_stats


class HelloHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


async def _start_server(
    config: SecurityConfig,
) -> tuple[tornado.httpserver.HTTPServer, int, SecurityMiddleware]:
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/", HelloHandler)],
        security_middleware=middleware,
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    return server, port, middleware


@pytest.fixture
async def hello_app() -> AsyncGenerator[tuple[int, SecurityMiddleware], None]:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        whitelist=[],
        blacklist=[],
        security_headers={
            "enabled": True,
            "frame_options": "DENY",
            "content_type_options": "nosniff",
        },
    )
    server, port, middleware = await _start_server(config)
    try:
        yield port, middleware
    finally:
        server.stop()
        await middleware.reset()


@pytest.fixture
async def blacklist_app() -> AsyncGenerator[tuple[int, SecurityMiddleware], None]:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        blacklist=["127.0.0.1"],
        custom_error_responses={403: "Custom Forbidden"},
    )
    server, port, middleware = await _start_server(config)
    try:
        yield port, middleware
    finally:
        server.stop()
        await middleware.reset()


async def test_basic_request_succeeds(
    hello_app: tuple[int, SecurityMiddleware],
) -> None:
    port, _ = hello_app
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(f"http://127.0.0.1:{port}/")
        assert response.code == 200
        assert b'"ok"' in response.body
    finally:
        client.close()


async def test_security_headers_applied(
    hello_app: tuple[int, SecurityMiddleware],
) -> None:
    port, _ = hello_app
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(f"http://127.0.0.1:{port}/")
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
    finally:
        client.close()


async def test_blacklisted_ip_blocked(
    blacklist_app: tuple[int, SecurityMiddleware],
) -> None:
    port, _ = blacklist_app
    client = AsyncHTTPClient()
    try:
        with pytest.raises(HTTPClientError) as exc_info:
            await client.fetch(f"http://127.0.0.1:{port}/")
        assert exc_info.value.code == 403
    finally:
        client.close()


async def test_agent_stats_returns_disabled_when_agent_handler_unset() -> None:
    config = SecurityConfig(enable_agent=False)
    middleware = SecurityMiddleware(config=config)
    assert middleware.agent_handler is None
    assert middleware.agent_stats == {"enabled": False}


async def test_agent_stats_returns_enabled_with_agent_handler_stats() -> None:
    config = SecurityConfig()
    middleware = SecurityMiddleware(config=config)

    fake_handler = Mock()
    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
        "transport_stats": {"circuit_breaker_state": "CLOSED"},
    }
    middleware.agent_handler = fake_handler

    stats = middleware.agent_stats
    assert stats["enabled"] is True
    assert stats["buffer_stats"] == {"events_dropped": 0, "metrics_dropped": 0}
    assert stats["transport_stats"] == {"circuit_breaker_state": "CLOSED"}
    fake_handler.get_stats.assert_called_once()


async def test_agent_stats_reflects_live_drop_counter_increments() -> None:
    config = SecurityConfig()
    middleware = SecurityMiddleware(config=config)

    fake_handler = Mock()
    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
        "transport_stats": {"circuit_breaker_state": "CLOSED"},
    }
    middleware.agent_handler = fake_handler

    first = middleware.agent_stats
    assert _buffer_stats(first)["events_dropped"] == 0

    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 7, "metrics_dropped": 3},
        "transport_stats": {"circuit_breaker_state": "OPEN"},
    }

    second = middleware.agent_stats
    assert _buffer_stats(second)["events_dropped"] == 7
    assert _buffer_stats(second)["metrics_dropped"] == 3
    transport = second["transport_stats"]
    assert isinstance(transport, dict)
    assert transport["circuit_breaker_state"] == "OPEN"
    assert fake_handler.get_stats.call_count == 2
