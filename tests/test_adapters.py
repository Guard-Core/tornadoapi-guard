from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

import pytest
from tornado.httputil import HTTPHeaders
from tornado.web import RequestHandler

from tornadoapi_guard.adapters import (
    TornadoGuardRequest,
    TornadoGuardResponse,
    TornadoResponseFactory,
    apply_guard_response,
    unwrap_response,
)


class _FakeHandler:
    def __init__(self, request: object, application: object) -> None:
        self.request = request
        self.application = application


def make_handler(
    *,
    method: str = "GET",
    path: str = "/test",
    protocol: str = "http",
    remote_ip: str = "127.0.0.1",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    query_arguments: dict[str, list[bytes]] | None = None,
    settings: dict[str, object] | None = None,
) -> RequestHandler:
    http_headers = HTTPHeaders()
    for name, value in (headers or {}).items():
        http_headers.add(name, value)

    request = SimpleNamespace(
        method=method,
        path=path,
        protocol=protocol,
        remote_ip=remote_ip,
        headers=http_headers,
        body=body,
        query_arguments=query_arguments or {},
        full_url=lambda: f"{protocol}://localhost{path}",
    )
    application = SimpleNamespace(settings=settings or {})
    return cast(RequestHandler, _FakeHandler(request=request, application=application))


async def test_request_url_path() -> None:
    handler = make_handler(path="/hello")
    guard_request = TornadoGuardRequest(handler)
    assert guard_request.url_path == "/hello"


async def test_request_method() -> None:
    handler = make_handler(method="POST")
    guard_request = TornadoGuardRequest(handler)
    assert guard_request.method == "POST"


async def test_request_client_host() -> None:
    handler = make_handler(remote_ip="10.0.0.5")
    guard_request = TornadoGuardRequest(handler)
    assert guard_request.client_host == "10.0.0.5"


async def test_request_headers() -> None:
    handler = make_handler(headers={"X-Custom": "value"})
    guard_request = TornadoGuardRequest(handler)
    assert guard_request.headers.get("x-custom") == "value"


async def test_request_query_params() -> None:
    handler = make_handler(query_arguments={"key": [b"val"]})
    guard_request = TornadoGuardRequest(handler)
    assert guard_request.query_params.get("key") == "val"


async def test_request_scheme() -> None:
    handler = make_handler(protocol="https")
    guard_request = TornadoGuardRequest(handler)
    assert guard_request.url_scheme == "https"


async def test_request_url_replace_scheme() -> None:
    handler = make_handler(protocol="http", path="/foo")
    guard_request = TornadoGuardRequest(handler)
    result = guard_request.url_replace_scheme("https")
    assert result.startswith("https://")


async def test_request_body() -> None:
    handler = make_handler(body=b"payload")
    guard_request = TornadoGuardRequest(handler)
    body = await guard_request.body()
    assert body == b"payload"


async def test_request_state_is_persistent() -> None:
    handler = make_handler()
    guard_request = TornadoGuardRequest(handler)
    guard_request.state.foo = "bar"
    assert TornadoGuardRequest(handler).state.foo == "bar"


async def test_request_scope() -> None:
    handler = make_handler(path="/scope", method="POST")
    guard_request = TornadoGuardRequest(handler)
    scope = guard_request.scope
    assert scope["path"] == "/scope"
    assert scope["method"] == "POST"
    assert scope["handler"] is handler
    assert scope["application"] is handler.application


async def test_response_properties() -> None:
    response = TornadoGuardResponse(
        status_code=200, headers={"X-Test": "1"}, body=b"ok"
    )
    assert response.status_code == 200
    assert response.headers["X-Test"] == "1"
    assert response.body == b"ok"


async def test_response_read_body_prefix() -> None:
    response = TornadoGuardResponse(status_code=200, body=b"abcdef")
    assert await response.read_body_prefix(3) == b"abc"
    assert await response.read_body_prefix(0) == b""
    assert await TornadoGuardResponse(status_code=204).read_body_prefix(5) == b""


async def test_response_headers_mutable() -> None:
    response = TornadoGuardResponse(status_code=200)
    response.headers["X-New"] = "v"
    assert response.headers["X-New"] == "v"


async def test_response_factory_create() -> None:
    factory = TornadoResponseFactory()
    response = factory.create_response("error", 403)
    assert response.status_code == 403
    assert response.body == b"error"


async def test_response_factory_redirect() -> None:
    factory = TornadoResponseFactory()
    response = factory.create_redirect_response("https://example.com", 301)
    assert response.status_code == 301
    assert response.headers["Location"] == "https://example.com"


async def test_apply_guard_response_writes_through_handler() -> None:
    handler = MagicMock()
    response = TornadoGuardResponse(
        status_code=403, headers={"X-Blocked": "yes"}, body=b"nope"
    )
    apply_guard_response(handler, response)
    handler.clear.assert_called_once()
    handler.set_status.assert_called_once_with(403)
    handler.set_header.assert_any_call("X-Blocked", "yes")
    handler.write.assert_called_once_with(b"nope")
    handler.finish.assert_called_once()


async def test_apply_guard_response_without_body() -> None:
    handler = MagicMock()
    response = TornadoGuardResponse(status_code=204, headers={}, body=None)
    apply_guard_response(handler, response)
    handler.write.assert_not_called()
    handler.finish.assert_called_once()


async def test_unwrap_response_passthrough() -> None:
    response = TornadoGuardResponse(status_code=200)
    assert unwrap_response(response) is response


async def test_unwrap_response_generic() -> None:
    mock_resp = MagicMock()
    mock_resp.body = b"body"
    mock_resp.status_code = 404
    mock_resp.headers = {"X-Test": "val"}
    unwrapped = unwrap_response(mock_resp)
    assert unwrapped.status_code == 404
    assert unwrapped.body == b"body"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
