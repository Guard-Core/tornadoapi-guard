from __future__ import annotations

import itertools
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

CAP = 1024
LARGE_LIMIT = 7000
_PAYLOAD = b"1' UNION SELECT password FROM users--"
_PAST_THE_CAP_PAYLOAD = b"A" * (LARGE_LIMIT - len(_PAYLOAD) - 1) + _PAYLOAD
_ONE_BYTE_PAST = b"A" * (CAP + 1)
_AT_THE_CAP = b"A" * CAP
_IPS = itertools.count(1)

security = SecurityDecorator(
    SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
)


class SmallHandler(SecurityHandler):
    async def post(self) -> None:
        self.write({"ok": "small"})


class LargeHandler(SecurityHandler):
    async def post(self) -> None:
        self.write({"ok": "large"})


security.max_request_size(LARGE_LIMIT)(LargeHandler.post)

Post = Callable[[str, bytes, bool], Awaitable[HTTPResponse]]
Serve = Callable[[bool], Awaitable[Post]]


@pytest.fixture
def captured_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    original = SecurityEventBus.send_middleware_event

    async def _capture(self: SecurityEventBus, *args: Any, **kwargs: Any) -> None:
        events.append(kwargs)
        await original(self, *args, **kwargs)

    monkeypatch.setattr(SecurityEventBus, "send_middleware_event", _capture)
    return events


@pytest.fixture
async def serve() -> AsyncGenerator[Serve, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def _serve(fail_secure: bool) -> Post:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
            detection_max_body_inspect_bytes=CAP,
            fail_secure=fail_secure,
            trusted_proxies=["127.0.0.1"],
            auto_ban_threshold=2,
            ban_on_hostile_signals=False,
        )
        middleware = SecurityMiddleware(config=config)
        middleware.set_decorator_handler(security)
        app = tornado.web.Application(
            [(r"/small", SmallHandler), (r"/large", LargeHandler)],
            security_middleware=middleware,
            guard_decorator=security,
        )
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        port = sockets[0].getsockname()[1]
        headers = {
            "X-Forwarded-For": f"198.51.100.{next(_IPS)}",
            "Content-Type": "text/plain",
        }

        async def post(path: str, body: bytes, chunked: bool) -> HTTPResponse:
            url = f"http://127.0.0.1:{port}{path}"
            if not chunked:
                return await AsyncHTTPClient().fetch(
                    url, method="POST", body=body, headers=headers, raise_error=False
                )

            async def producer(write: Callable[[bytes], Awaitable[None]]) -> None:
                for start in range(0, len(body), 512):
                    await write(body[start : start + 512])

            return await AsyncHTTPClient().fetch(
                url,
                method="POST",
                body_producer=producer,
                headers={**headers, "Transfer-Encoding": "chunked"},
                raise_error=False,
            )

        return post

    yield _serve
    for server, middleware in started:
        server.stop()
        await middleware.reset()


def _body_read_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if "Request body read failed" in e.get("reason", "")]


@pytest.mark.parametrize("chunked", [False, True])
@pytest.mark.parametrize("body", [_ONE_BYTE_PAST, _PAST_THE_CAP_PAYLOAD])
async def test_a_body_past_the_cap_is_refused_with_an_event_and_no_strike(
    serve: Serve, body: bytes, chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    post = await serve(True)

    statuses = [(await post("/small", body, chunked)).code for _ in range(4)]
    after = await post("/small", b"hello", False)

    assert statuses == [400, 400, 400, 400]
    assert after.code == 200
    assert len(_body_read_events(captured_events)) == 4
    assert {e["action_taken"] for e in _body_read_events(captured_events)} == {
        "request_blocked"
    }


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_body_past_the_cap_passes_with_an_event_without_fail_secure(
    serve: Serve, chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    post = await serve(False)

    response = await post("/small", _PAST_THE_CAP_PAYLOAD, chunked)

    assert response.code == 200
    assert [e["action_taken"] for e in _body_read_events(captured_events)] == [
        "logged_only"
    ]


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_route_with_max_request_size_above_the_cap_is_scanned_in_full(
    serve: Serve, chunked: bool
) -> None:
    post = await serve(True)

    raised = await post("/large", _PAST_THE_CAP_PAYLOAD, chunked)
    sibling = await post("/small", _PAST_THE_CAP_PAYLOAD, chunked)

    assert raised.code == 400
    assert b"Suspicious activity detected" in raised.body
    assert sibling.code == 400
    assert b"Suspicious activity detected" not in sibling.body


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_body_at_exactly_the_cap_is_scanned_in_full_and_unchanged(
    serve: Serve, chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    post = await serve(True)
    hit = _AT_THE_CAP[: CAP - len(_PAYLOAD)] + _PAYLOAD

    clean = await post("/small", _AT_THE_CAP, chunked)
    attack = await post("/small", hit, chunked)

    assert clean.code == 200
    assert attack.code == 400
    assert b"Suspicious activity detected" in attack.body
    assert _body_read_events(captured_events) == []
