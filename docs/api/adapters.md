---

title: Adapters API - TornadoAPI Guard
description: Reference for the Tornado protocol adapters that bridge tornado types to guard-core's framework-agnostic protocols
keywords: tornado, adapters, guard-core, protocol, request, response, guard request, guard response
---

Adapters
========

`tornadoapi-guard` is a thin layer over [guard-core](https://github.com/Guard-Core/guard-core), a framework-agnostic security engine. guard-core is written against a small set of protocol types (`GuardRequest`, `GuardResponse`, `GuardResponseFactory`) so that it can be reused by different web frameworks. The **adapter** module translates Tornado's concrete types (`RequestHandler`, `HTTPServerRequest`, `HTTPHeaders`) into those protocols.

All adapter classes live in `tornadoapi_guard.adapters` and are re-exported from the top-level package:

```python
from tornadoapi_guard import (
    TornadoGuardRequest,
    TornadoGuardResponse,
    TornadoResponseFactory,
    apply_guard_response,
    unwrap_response,
)
```

Most users never touch these classes directly — `SecurityMiddleware` builds them under the hood. You do need them when writing a `custom_request_check`, a `custom_response_modifier`, or a custom validator that needs to return a typed response.

___

TornadoGuardRequest
-------------------

```python
class TornadoGuardRequest:
    def __init__(self, handler: RequestHandler) -> None: ...
```

Wraps a `tornado.web.RequestHandler` and its `HTTPServerRequest`. Implements the `GuardRequest` protocol from guard-core. The middleware builds one of these per request inside `run_pre_processing`, so you normally do not instantiate them by hand.

___

TornadoGuardRequest Properties
------------------------------

| Property | Return type | Description |
|---|---|---|
| `url_path` | `str` | `handler.request.path` |
| `url_scheme` | `str` | `handler.request.protocol` (for example `"http"` or `"https"`) |
| `url_full` | `str` | `handler.request.full_url()` |
| `method` | `str` | HTTP method, defaulting to `"GET"` if Tornado reports `None` |
| `client_host` | `str \| None` | `handler.request.remote_ip` — the IP that Tornado resolved for the peer |
| `headers` | `Mapping[str, str]` | Case-insensitive header mapping (Tornado's `HTTPHeaders`) |
| `query_params` | `Mapping[str, str]` | Query-string decoded to `str` values; repeated keys collapse to the first value |
| `state` | `SimpleNamespace` | Per-handler state container — see [Per-handler state](#per-handler-state) below |
| `scope` | `dict[str, Any]` | Dict exposing `handler`, `app`, `application`, `settings`, `path`, and `method`; compatible with guard-core code that inspects `scope.get("app")` |

___

TornadoGuardRequest Methods
---------------------------

```python
def url_replace_scheme(self, scheme: str) -> str: ...
```

Returns a rebuilt URL with the given scheme swapped in (useful for HTTPS enforcement redirects).

```python
async def body(self) -> bytes: ...
```

Returns the raw request body. Tornado already buffers the body on the request object, so this is effectively synchronous from an IO perspective — the `async` signature exists to match the `GuardRequest` protocol, which is shared with ASGI adapters where body access is genuinely async.

___

TornadoGuardResponse
--------------------

```python
class TornadoGuardResponse:
    def __init__(
        self,
        status_code: int,
        headers: MutableMapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> None: ...
```

A standalone, framework-agnostic response snapshot. Implements the `GuardResponse` protocol. Unlike FastAPI, Tornado does not have a first-class response object — responses are written incrementally via `handler.write()` / `handler.set_header()` / `handler.finish()`. `TornadoGuardResponse` bridges that gap by providing a single container that guard-core can inspect and modify.

___

TornadoGuardResponse Properties
-------------------------------

| Property | Return type | Description |
|---|---|---|
| `status_code` | `int` | HTTP status code |
| `headers` | `MutableMapping[str, str]` | Mutable header mapping (guard-core mutates this to add security headers, CORS headers, and custom-response-modifier headers) |
| `body` | `bytes \| None` | Raw response body |

___

TornadoGuardResponse.from_handler
---------------------------------

```python
@classmethod
def from_handler(cls, handler: RequestHandler) -> TornadoGuardResponse: ...
```

Snapshots the current state of a `RequestHandler` into a `TornadoGuardResponse`. It reads:

- `handler.get_status()` for the status code.
- `handler._headers` (Tornado's internal `HTTPHeaders` container) for the accumulated response headers.
- `handler._write_buffer` for the accumulated response body.

Used by `SecurityMiddleware.run_post_processing` to build a response object from a handler that has already written its reply, so that behavioral return rules and metrics collectors can see the actual status / headers / body that went on the wire.

___

TornadoResponseFactory
----------------------

```python
class TornadoResponseFactory:
    def create_response(
        self, content: str, status_code: int
    ) -> TornadoGuardResponse: ...

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> TornadoGuardResponse: ...
```

Implements the `GuardResponseFactory` protocol. guard-core uses this factory whenever it needs to construct a blocking response (for example, a `403` ban, a `429` rate-limit, or a `301` HTTPS redirect). The factory produces typed `TornadoGuardResponse` instances with sensible default headers:

- `create_response(...)` UTF-8 encodes the content, sets `Content-Type: text/plain; charset=utf-8`, and fills in `Content-Length`.
- `create_redirect_response(...)` sets `Location: <url>` and `Content-Length: 0` with an empty body.

The middleware stores a singleton instance on itself and exposes it through `middleware.guard_response_factory`.

___

apply_guard_response
--------------------

```python
def apply_guard_response(
    handler: RequestHandler, guard_response: GuardResponse
) -> None: ...
```

Writes a `GuardResponse` back through a Tornado `RequestHandler`. The procedure is:

1. `handler.clear()` — discard any previously buffered output.
2. `handler.set_status(guard_response.status_code)` — set the status line.
3. `handler.set_header(key, value)` for every entry in `guard_response.headers`.
4. `handler.write(body)` if a body was provided.
5. `handler.finish()` — terminate the request.

`SecurityHandler.prepare` calls this helper when the security pipeline returns a blocking response, and you may call it yourself from a custom validator if you construct a `TornadoGuardResponse` and want to write it out immediately.

___

unwrap_response
---------------

```python
def unwrap_response(guard_response: GuardResponse) -> TornadoGuardResponse: ...
```

Returns its input unchanged if it is already a `TornadoGuardResponse`. Otherwise, it constructs a new `TornadoGuardResponse` from any `GuardResponse`-shaped object (copying `status_code`, `headers` as a fresh `dict`, and `body`). Symmetric with fastapi-guard's helper of the same name, and useful when you receive a response of unknown concrete type from a guard-core hook and want to guarantee a Tornado-friendly container.

___

Writing Custom Hooks
--------------------

`SecurityConfig` accepts two user-provided callables:

- `custom_request_check(request)` — runs at the end of the security pipeline. Return a `GuardResponse` to short-circuit the request, or `None` to let it through.
- `custom_response_modifier(response)` — runs during post-processing. Receives the built response and may mutate its headers (or construct a new response) before the middleware hands it back.

Use `TornadoGuardResponse` for return values so that `SecurityMiddleware` can apply headers, CORS, and the custom modifier uniformly. The pattern below mirrors `examples/simple_app/main.py`:

```python
import json

from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

from tornadoapi_guard import SecurityConfig, TornadoGuardResponse


async def custom_request_check(request: GuardRequest) -> GuardResponse | None:
    if request.query_params.get("debug") == "true":
        return TornadoGuardResponse(
            status_code=403,
            headers={"Content-Type": "application/json; charset=utf-8"},
            body=json.dumps({"detail": "Debug mode not allowed"}).encode("utf-8"),
        )
    return None


async def custom_response_modifier(response: GuardResponse) -> GuardResponse:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


config = SecurityConfig(
    custom_request_check=custom_request_check,
    custom_response_modifier=custom_response_modifier,
)
```

A few notes:

- Inside `custom_request_check` you can read the request through the `GuardRequest` protocol (`request.query_params`, `request.headers`, `request.client_host`, `await request.body()`). You do **not** need to know that the concrete type is `TornadoGuardRequest` — stick to the protocol and the same hook will work against any guard-core adapter.
- Inside `custom_response_modifier` you receive a `GuardResponse` (concretely a `TornadoGuardResponse` when running under `tornadoapi-guard`). Mutating `response.headers` is safe because the mapping is declared `MutableMapping[str, str]` in the protocol.
- If you need a typed `TornadoGuardResponse` from an unknown `GuardResponse`, call `unwrap_response(response)`.

___

Per-handler State
-----------------

`TornadoGuardRequest.state` returns a `SimpleNamespace` that the middleware uses to stash per-request data: the guard request itself, the resolved route config, the extracted client IP, and the request start time. Behavioral hooks, post-processing, and custom validators read from this namespace.

The storage is backed by a module-level `WeakKeyDictionary` keyed by the handler instance:

```python
_guard_state_store: WeakKeyDictionary[Any, SimpleNamespace] = WeakKeyDictionary()


def get_guard_state(handler: RequestHandler) -> SimpleNamespace:
    state = _guard_state_store.get(handler)
    if state is None:
        state = SimpleNamespace()
        _guard_state_store[handler] = state
    return state
```

The `WeakKeyDictionary` is an implementation detail — do not rely on it. What you should know:

- State is scoped to a **single handler instance**, which in Tornado means a single request.
- The entry is cleaned up automatically when the handler is garbage-collected at the end of the request.
- Two different handlers never share state, so it is safe to stash mutable data there.
- Inside a `custom_request_check`, use `request.state.<attr>` to read and write.

If you need to survive beyond a single request (for example, cross-request counters keyed by IP), use Redis through the configured `RedisManager`, not `request.state`.

___

See Also
--------

- [SecurityHandler](security-handler.md) — the base class that invokes the middleware through the adapters.
- [SecurityMiddleware](security-middleware.md) — orchestrates the adapters and the security pipeline.
- [Core Architecture](core-architecture.md) — details on the guard-core protocols these adapters implement.
- [API Overview](overview.md) — complete API reference.
