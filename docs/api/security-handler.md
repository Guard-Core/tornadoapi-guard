---

title: SecurityHandler API - TornadoAPI Guard
description: Complete API reference for TornadoAPI Guard's SecurityHandler base class and its lifecycle hooks
keywords: tornado, security, middleware, request handler, lifecycle hooks, prepare, finish
---

SecurityHandler
===============

The `SecurityHandler` class is the Tornado-specific base class that every handler inherits from in order to participate in the `tornadoapi-guard` security pipeline.

!!! info "Why a base handler instead of middleware?"
    Tornado does not have an application-level middleware chain like ASGI frameworks (FastAPI, Starlette). There is no `app.add_middleware(...)` equivalent. Instead, Tornado exposes hooks on `tornado.web.RequestHandler` (`prepare`, `finish`). `tornadoapi-guard` plugs into these hooks through a base class: subclassing `SecurityHandler` is what "attaches" the security pipeline to a route.

___

Class Signature
---------------

```python
from tornado.web import RequestHandler


class SecurityHandler(RequestHandler):
    async def prepare(self) -> None: ...
    def finish(self, chunk=None) -> Future[None]: ...
    def _get_security_middleware(self) -> SecurityMiddleware | None: ...
```

Subclass `SecurityHandler` for every handler that needs security checks. Handlers that should run outside the pipeline (for example, a public `/health` endpoint) can keep inheriting from `tornado.web.RequestHandler` directly, or can be added to `SecurityConfig.exclude_paths`.

___

Lifecycle Hook: `prepare`
-------------------------

```python
async def prepare(self) -> None:
    middleware = self._get_security_middleware()
    if middleware is None:
        return

    early = await middleware.run_pre_processing(self)
    if early is not None:
        apply_guard_response(self, early)
```

`prepare()` runs **before** the HTTP method (`get`, `post`, etc.) is dispatched. `SecurityHandler` overrides it to:

1. Look up the middleware via `self.application.settings["security_middleware"]`.
2. Call `middleware.run_pre_processing(self)`, which mirrors fastapi-guard's `dispatch`: the CORS preflight, the engine passthrough handling (excluded paths stay scoped so the checks that apply to them still run, and a request with no client address gets the `fail_secure` 403), the route all-checks bypass (the real handler method is called and the response modifier applied), and the 17-check security pipeline (route config, emergency mode, HTTPS enforcement, request logging, request size/content, required headers, authentication, referrer, custom validators, time window, cloud IP refresh, IP security, cloud provider, user agent, rate limit, suspicious activity, and custom request check).
3. If any of those produces a response (blocked, preflight, bypass, or the Redis-unavailable 503), `apply_guard_response()` writes the status, headers, and body back through the handler (via `clear`, `set_status`, `set_header`, `write`, `finish`) with the CORS headers attached. The actual HTTP method is **not** invoked again, and this response does not go through the response pass below, so it emits no request metrics.

Because `prepare()` is `async`, the pipeline can perform async work (Redis lookups, IPInfo API calls, agent event publishing) without blocking the Tornado IOLoop.

___

Response Pass: `finish`
-----------------------

```python
def finish(self, chunk=None) -> Future[None]:
    ...
```

When the request proceeds to your handler method, `SecurityHandler` overrides `finish()` so the engine response pass runs on the outgoing response **before it is flushed**, exactly like fastapi-guard's `_process_response`. `finish()` returns a future (like Tornado's own), so `await self.finish()` and a bare `self.finish()` both work, and a second call (for example Tornado's auto-finish) returns the same pending future. The pass:

- Processes route and global behavioral return rules, including body-based patterns, because the buffered body is visible before the flush.
- Collects request metrics (response time, status code).
- Applies the security headers, the CORS headers, and `custom_response_modifier`. Header, status and body changes made by the modifier reach the client.

If the handler already flushed part of the response (`flush()` before `finish()`), the headers are on the wire, so the pass still observes the response (metrics and return rules over what is buffered) but cannot change what was sent. If the pass itself raises, the error is logged and the response is finished unmodified.

___

Internal Lookup: `_get_security_middleware`
-------------------------------------------

```python
def _get_security_middleware(self) -> SecurityMiddleware | None:
    value = self.application.settings.get("security_middleware")
    if isinstance(value, SecurityMiddleware):
        return value
    return None
```

Internal lookup. Returns the `SecurityMiddleware` instance stored in `application.settings["security_middleware"]`, or `None` if no middleware is configured. When `None` is returned, both `prepare()` and `finish()` short-circuit - see [Degraded mode](#degraded-mode) below.

___

Registration
------------

The `SecurityMiddleware` instance is attached to the Tornado `Application` via a settings entry named `security_middleware`. `SecurityHandler` looks it up from there on every request.

```python
import asyncio

import tornado.web

from tornadoapi_guard import SecurityConfig, SecurityHandler, SecurityMiddleware

config = SecurityConfig(
    rate_limit=100,
    enable_rate_limiting=True,
    enable_redis=False,
)
middleware = SecurityMiddleware(config=config)


class MyHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"status": "ok"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/", MyHandler)],
        security_middleware=middleware,
    )
    app.listen(8000)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```

Two things to notice:

- `await middleware.initialize()` must run **before** the application starts serving requests. It builds the security pipeline, initializes Redis handlers, and wires up agent integrations.
- The keyword argument `security_middleware=middleware` placed on `tornado.web.Application(...)` ends up in `app.settings["security_middleware"]`, which is exactly where `SecurityHandler._get_security_middleware` reads it from.

___

Combining with `tornado.websocket.WebSocketHandler`
---------------------------------------------------

`SecurityHandler` extends `tornado.web.RequestHandler`, not `tornado.websocket.WebSocketHandler`. WebSocket handlers therefore do **not** flow through the `tornadoapi-guard` pipeline — `prepare()` is not overridden for them and the middleware's security checks will not run.

If you need to protect a WebSocket endpoint, implement the checks directly on the WebSocket handler:

```python
import tornado.websocket


class ProtectedWebSocketHandler(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin: str) -> bool:
        return origin in {"https://example.com", "https://app.example.com"}

    async def open(self) -> None:
        token = self.request.headers.get("Authorization")
        if not token or not await verify_token(token):
            self.close(code=4401, reason="unauthorized")
            return
```

The example application in `examples/simple_app/main.py` ships with an `EchoWebSocketHandler` that demonstrates this pattern.

___

Interaction with `set_default_headers`
--------------------------------------

`tornadoapi-guard` does **not** override `set_default_headers` on `SecurityHandler`. Security headers are applied by the engine response pass in `finish()`, because the `SecurityHeadersManager.get_headers()` method is asynchronous (it may read configuration from Redis) and Tornado's `set_default_headers` is **synchronous**.

You are free to override `set_default_headers` on your own handlers to add static headers (for example, `X-Service-Name`). The headers you set there are applied first, and the response pass then adds (or overrides) the guard-managed security and CORS headers on top. Like fastapi-guard, responses produced by the pipeline itself (a `429` for a rate-limited client, for example) carry the CORS headers but not the security headers, which are only added to responses that came out of your handler.

___

Degraded Mode
-------------

If a handler inherits from `SecurityHandler` but the `Application` does **not** have a `security_middleware` entry in its settings (for example, in a unit test, a minimal sandbox, or during local development without the full middleware stack), `_get_security_middleware()` returns `None` and both hooks short-circuit:

- `prepare()` returns immediately — no headers are injected, no pipeline runs.
- `finish()` finishes the response immediately - no response pass runs.

In this degraded state `SecurityHandler` behaves exactly like a plain `tornado.web.RequestHandler`. This is intentional: it lets you write test fixtures that instantiate handlers without having to stand up a full `SecurityMiddleware` and its Redis/agent dependencies. Just remember that **no security checks are being performed** when the middleware is absent.

___

See Also
--------

- [SecurityMiddleware](security-middleware.md) — the orchestration layer that `SecurityHandler` delegates to.
- [Adapters](adapters.md) — `TornadoGuardRequest` / `TornadoGuardResponse` and `apply_guard_response()`.
- [SecurityDecorators](decorators.md) — route-level security via decorators on handler methods.
- [API Overview](overview.md) — complete API reference.
