"""The response wrapper declares whether the body is in memory.

A Tornado handler holds its response in a write buffer until the headers go out.
After a flush the earlier chunks are with the client, so only an unflushed
response is materialized. The engine reads ``body_is_materialized`` once per
response: True hands a modifier the real response and its real body, anything
else takes the bounded path.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.core.responses import reads_response_body
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import (
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
    TornadoGuardResponse,
)

_BODY = bytes(range(256)) * 40
_CAP = 262144
_security = SecurityDecorator(SecurityConfig())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MemoryHandler(SecurityHandler):
    async def get(self) -> None:
        self.set_header("Content-Type", "application/octet-stream")
        self.write(_BODY)


class BigMemoryHandler(SecurityHandler):
    async def get(self) -> None:
        self.set_header("Content-Type", "application/octet-stream")
        self.write(_BODY * 30)


class FlushedChunkedHandler(SecurityHandler):
    async def get(self) -> None:
        self.set_header("Content-Type", "application/octet-stream")
        self.write(_BODY[:1000])
        await self.flush()
        self.write(_BODY[1000:])


class FlushedDeclaredHandler(SecurityHandler):
    async def get(self) -> None:
        self.set_header("Content-Type", "application/octet-stream")
        self.set_header("Content-Length", str(len(_BODY)))
        self.write(_BODY[:1000])
        await self.flush()
        self.write(_BODY[1000:])


class EventStreamHandler(SecurityHandler):
    async def get(self) -> None:
        self.set_header("Content-Type", "text/event-stream")
        self.write(_BODY[:1000])
        await self.flush()
        self.write(_BODY[1000:])


@dataclass
class Seen:
    calls: int = 0
    body: bytes | None = None
    refused: bool = False
    capabilities: list[object] = field(default_factory=list)


def _modifier(seen: Seen) -> Any:
    @reads_response_body
    async def modifier(response: Any) -> Any:
        seen.calls += 1
        try:
            seen.body = response.body
        except AttributeError:
            seen.refused = True
        return response

    return modifier


@dataclass
class Server:
    port: int

    async def get(self, path: str) -> HTTPResponse:
        return await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{self.port}{path}", raise_error=False
        )


ServerFactory = Callable[[Seen], Awaitable[Server]]


@pytest.fixture
async def serve(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[ServerFactory, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def _serve(seen: Seen) -> Server:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            whitelist=None,
            blacklist=[],
            trusted_proxies=["127.0.0.1"],
            custom_response_modifier=_modifier(seen),
        )
        middleware = SecurityMiddleware(config=config)
        middleware.set_decorator_handler(_security)
        app = tornado.web.Application(
            [
                (r"/memory", MemoryHandler),
                (r"/big-memory", BigMemoryHandler),
                (r"/flushed-chunked", FlushedChunkedHandler),
                (r"/flushed-declared", FlushedDeclaredHandler),
                (r"/event-stream", EventStreamHandler),
            ],
            security_middleware=middleware,
            guard_decorator=_security,
        )
        assert middleware.response_factory is not None
        real = middleware.response_factory.process_response

        async def spy(request: Any, response: Any, *args: Any, **kwargs: Any) -> Any:
            seen.capabilities.append(getattr(response, "body_is_materialized", None))
            return await real(request, response, *args, **kwargs)

        monkeypatch.setattr(middleware.response_factory, "process_response", spy)
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        return Server(sockets[0].getsockname()[1])

    yield _serve
    for server, middleware in started:
        server.stop()
        await middleware.reset()


@pytest.mark.parametrize(
    ("route", "body", "materialized"),
    [
        pytest.param("/memory", _BODY, True, id="memory"),
        pytest.param("/big-memory", _BODY * 30, True, id="big-memory"),
        pytest.param("/flushed-chunked", None, False, id="flushed-chunked"),
        pytest.param("/flushed-declared", None, False, id="flushed-declared"),
        pytest.param("/event-stream", None, False, id="event-stream"),
    ],
)
async def test_the_capability_follows_the_handler_buffer(
    serve: ServerFactory, route: str, body: bytes | None, materialized: bool
) -> None:
    seen = Seen()
    response = await (await serve(seen)).get(route)
    assert response.code == 200
    assert _sha(response.body) == _sha(body if body is not None else _BODY)
    assert seen.capabilities == [materialized]
    assert seen.calls == 1
    assert seen.refused is not materialized
    assert seen.body == body


def test_a_response_built_with_its_body_is_materialized() -> None:
    assert TornadoGuardResponse(status_code=200, body=b"x").body_is_materialized is True


def test_a_response_can_be_declared_not_materialized() -> None:
    response = TornadoGuardResponse(
        status_code=200, body=b"x", body_is_materialized=False
    )
    assert response.body_is_materialized is False
