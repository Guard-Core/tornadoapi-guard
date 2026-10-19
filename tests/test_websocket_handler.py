from __future__ import annotations

from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
import tornado.websocket
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest

from tornadoapi_guard import (
    SecurityHandler,
    SecurityMiddleware,
    SecurityWebSocketHandler,
)

OPERATOR = "203.0.113.9"


class Ping(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


class GuardedEcho(SecurityWebSocketHandler):
    def open(self, *args: str, **kwargs: str) -> None:
        self.write_message("connected")


class UnguardedEcho(tornado.websocket.WebSocketHandler):
    def open(self, *args: str, **kwargs: str) -> None:
        self.write_message("connected")


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "exclude_paths": [],
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


async def _serve(
    config: SecurityConfig | None, handler: type[tornado.web.RequestHandler]
) -> tuple[tornado.httpserver.HTTPServer, int, SecurityMiddleware | None]:
    settings: dict[str, Any] = {}
    middleware = None
    if config is not None:
        middleware = SecurityMiddleware(config=config)
        await middleware.initialize()
        settings["security_middleware"] = middleware
    app = tornado.web.Application([(r"/ping", Ping), (r"/ws", handler)], **settings)
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    return server, sockets[0].getsockname()[1], middleware


async def _verdicts(
    config: SecurityConfig | None,
    handler: type[tornado.web.RequestHandler] = GuardedEcho,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    server, port, middleware = await _serve(config, handler)
    client = AsyncHTTPClient()
    try:
        try:
            http = (
                await client.fetch(f"http://127.0.0.1:{port}/ping", headers=headers)
            ).code
        except HTTPClientError as exc:
            http = exc.code
        try:
            connection = await tornado.websocket.websocket_connect(
                HTTPRequest(f"ws://127.0.0.1:{port}/ws", headers=headers)
            )
            message = await connection.read_message()
            connection.close()
            ws = f"accepted:{message}"
        except HTTPClientError as exc:
            ws = f"refused:{exc.code}"
        return http, ws
    finally:
        client.close()
        server.stop()
        if middleware is not None:
            await middleware.reset()


async def test_emergency_mode_refuses_the_upgrade_like_the_http_route() -> None:
    config = _config(emergency_mode=True, emergency_whitelist=[OPERATOR])

    assert await _verdicts(config) == (503, "refused:503")


async def test_an_emergency_exempt_path_stays_open_to_the_upgrade() -> None:
    config = _config(
        emergency_mode=True,
        emergency_whitelist=[OPERATOR],
        emergency_exempt_paths=["/ws"],
    )

    assert await _verdicts(config) == (503, "accepted:connected")


async def test_a_blocked_user_agent_refuses_the_upgrade() -> None:
    config = _config(blocked_user_agents=["badbot"])

    assert await _verdicts(config, headers={"User-Agent": "badbot/1"}) == (
        403,
        "refused:403",
    )


async def test_a_blacklisted_client_refuses_the_upgrade() -> None:
    config = _config(blacklist=["127.0.0.1"])

    assert await _verdicts(config) == (403, "refused:403")


async def test_passive_mode_logs_and_lets_the_upgrade_through() -> None:
    config = _config(blacklist=["127.0.0.1"], passive_mode=True)

    assert await _verdicts(config) == (200, "accepted:connected")


async def test_an_allowed_client_upgrades_normally() -> None:
    assert await _verdicts(_config()) == (200, "accepted:connected")


async def test_rate_limit_applies_to_the_upgrade_requests() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=1, rate_limit_window=60)
    server, port, middleware = await _serve(config, GuardedEcho)
    try:
        first = await tornado.websocket.websocket_connect(
            HTTPRequest(f"ws://127.0.0.1:{port}/ws")
        )
        assert await first.read_message() == "connected"
        first.close()

        with pytest.raises(HTTPClientError) as refused:
            await tornado.websocket.websocket_connect(
                HTTPRequest(f"ws://127.0.0.1:{port}/ws")
            )
    finally:
        server.stop()
        assert middleware is not None
        await middleware.reset()

    assert refused.value.code == 429


async def test_without_a_middleware_the_upgrade_proceeds() -> None:
    server, port, _ = await _serve(None, GuardedEcho)
    try:
        connection = await tornado.websocket.websocket_connect(
            HTTPRequest(f"ws://127.0.0.1:{port}/ws")
        )
        assert await connection.read_message() == "connected"
        connection.close()
    finally:
        server.stop()


async def test_a_plain_websocket_handler_stays_unguarded() -> None:
    config = _config(blacklist=["127.0.0.1"])

    assert await _verdicts(config, handler=UnguardedEcho) == (403, "accepted:connected")
