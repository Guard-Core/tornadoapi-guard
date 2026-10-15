from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse, urlunparse
from weakref import WeakKeyDictionary

from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from tornado.web import RequestHandler


_guard_state_store: WeakKeyDictionary[Any, SimpleNamespace] = WeakKeyDictionary()


def get_guard_state(handler: RequestHandler) -> SimpleNamespace:
    state = _guard_state_store.get(handler)
    if state is None:
        state = SimpleNamespace()
        _guard_state_store[handler] = state
    return state


class TornadoGuardRequest:
    def __init__(self, handler: RequestHandler) -> None:
        self._handler = handler
        self._request = handler.request
        self._state = get_guard_state(handler)

    @property
    def url_path(self) -> str:
        return self._request.path

    @property
    def url_scheme(self) -> str:
        return self._request.protocol

    @property
    def url_full(self) -> str:
        return self._request.full_url()

    def url_replace_scheme(self, scheme: str) -> str:
        parsed = urlparse(self._request.full_url())
        return urlunparse(parsed._replace(scheme=scheme))

    @property
    def method(self) -> str:
        return self._request.method or "GET"

    @property
    def client_host(self) -> str | None:
        return self._request.remote_ip

    @property
    def headers(self) -> Mapping[str, str]:
        return cast(Mapping[str, str], self._request.headers)

    @property
    def query_params(self) -> Mapping[str, str]:
        return {
            key: values[0].decode("utf-8", errors="replace")
            for key, values in self._request.query_arguments.items()
            if values
        }

    async def body(self) -> bytes:
        return self._request.body or b""

    @property
    def state(self) -> Any:
        return self._state

    @property
    def scope(self) -> dict[str, Any]:
        return {
            "handler": self._handler,
            "app": self._handler.application,
            "application": self._handler.application,
            "settings": self._handler.application.settings,
            "path": self._request.path,
            "method": self._request.method,
        }


class TornadoGuardResponse:
    def __init__(
        self,
        status_code: int,
        headers: MutableMapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> None:
        self._status_code = status_code
        self._headers: MutableMapping[str, str] = headers if headers is not None else {}
        self._body = body

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return self._headers

    @property
    def body(self) -> bytes | None:
        return self._body

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        return (self._body or b"")[:max_bytes]

    @classmethod
    def from_handler(cls, handler: RequestHandler) -> TornadoGuardResponse:
        raw_headers = getattr(handler, "_headers", None)
        headers: dict[str, str] = (
            {name: value for name, value in raw_headers.get_all()}
            if raw_headers is not None
            else {}
        )
        buffer = getattr(handler, "_write_buffer", None)
        body = b"".join(buffer) if buffer else b""
        return cls(
            status_code=handler.get_status(),
            headers=headers,
            body=body,
        )


class TornadoResponseFactory:
    def create_response(self, content: str, status_code: int) -> TornadoGuardResponse:
        encoded = content.encode("utf-8")
        return TornadoGuardResponse(
            status_code=status_code,
            headers={
                "Content-Type": "text/plain; charset=utf-8",
                "Content-Length": str(len(encoded)),
            },
            body=encoded,
        )

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> TornadoGuardResponse:
        return TornadoGuardResponse(
            status_code=status_code,
            headers={"Location": url, "Content-Length": "0"},
            body=b"",
        )


def apply_guard_response(
    handler: RequestHandler, guard_response: GuardResponse
) -> None:
    handler.clear()
    handler.set_status(guard_response.status_code)
    for key, value in guard_response.headers.items():
        handler.set_header(key, value)
    body = guard_response.body
    if body:
        handler.write(body)
    handler.finish()


def _normalize_header_name(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("-"))


def sync_guard_response(
    handler: RequestHandler,
    before_headers: Mapping[str, str],
    before_body: bytes | None,
    response: GuardResponse,
) -> None:
    if response.status_code != handler.get_status():
        handler.set_status(response.status_code)
    after = {_normalize_header_name(k): v for k, v in response.headers.items()}
    for name in before_headers.keys() - after.keys():
        handler.clear_header(name)
    for name, value in after.items():
        if before_headers.get(name) != value:
            handler.set_header(name, value)
    if response.body != before_body:
        cast(Any, handler)._write_buffer = [response.body or b""]


def unwrap_response(guard_response: GuardResponse) -> TornadoGuardResponse:
    if isinstance(guard_response, TornadoGuardResponse):
        return guard_response
    return TornadoGuardResponse(
        status_code=guard_response.status_code,
        headers=dict(guard_response.headers),
        body=guard_response.body,
    )
