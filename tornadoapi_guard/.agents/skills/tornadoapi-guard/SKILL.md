---
name: tornadoapi-guard
description: TornadoAPI Guard, the Tornado security adapter over guard-core. Use when securing Tornado apps with IP filtering, rate limiting, penetration detection, security headers, cloud-provider blocking, route-level security decorators, or behavioral rules; when wiring SecurityHandler (RequestHandler.prepare/on_finish) or SecurityMiddleware into a tornado.web.Application via the security_middleware setting; when adapting HTTPServerRequest/RequestHandler types to guard-core's GuardRequest/GuardResponse protocols; or when debugging the silent no-guard path when the middleware setting is missing, decorator-route visibility via set_decorator_handler, Redis connectivity, or bytes-valued request.arguments. Also use when porting fastapi-guard patterns to Tornado or choosing the right Guard adapter.
---

# TornadoAPI Guard

Security adapter for Tornado: IP filtering, rate limiting, signature-based attack-pattern detection, security headers, and route-level security decorators. Import package is `tornadoapi_guard` (distribution name `tornadoapi_guard`). Current as of tornadoapi-guard 1.0.0 over guard-core.

TornadoAPI Guard is a thin adapter: all security logic (models, handlers, decorators, detection engine, protocols) lives in `guard_core`. Tornado is async, so this adapter uses the async `guard_core.*` tree directly (unlike the Flask/Django siblings, which use the `guard_core.sync` mirror).

## Quick Reference

* Install: `uv add tornadoapi-guard` (or `pip install tornadoapi-guard`).
* Wire it: build `SecurityMiddleware(config=...)`, pass it to `tornado.web.Application` as the `security_middleware` setting, and subclass `SecurityHandler` for guarded handlers; see [Setup](#setup).
* `SecurityMiddleware(config=...)` is keyword-only; call `await security_middleware.initialize()` before serving.
* All behavior is guard-core's `SecurityConfig`; do not mutate handlers directly.
* Route rules: `SecurityDecorator` writes per-route `RouteConfig`; wire it with `security_middleware.set_decorator_handler(guard_decorator)` so the pipeline is derived from registered routes.
* Tornado shapes to remember: `prepare()` / `on_finish()` hooks, `request.remote_ip`, case-insensitive `HTTPHeaders`, bytes-valued `request.arguments`, no built-in response object (`handler.write()` / `handler.finish()`).

## Installation

```bash
uv add tornadoapi-guard        # or: pip install tornadoapi-guard
```

Requires Python 3.10-3.14, `tornado`, and `guard-core` (installed automatically).

## Setup

```python
import tornado.web
from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
)

config = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    enable_rate_limiting=True,
)

security_middleware = SecurityMiddleware(config=config)
security_middleware.set_decorator_handler(SecurityDecorator(config))
await security_middleware.initialize()


class ProtectedHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


app = tornado.web.Application(
    [(r"/", ProtectedHandler)],
    security_middleware=security_middleware,
)
```

`SecurityHandler.prepare()` runs pre-flight headers, pre-processing (bypass handling, route resolution, the 17-check `SecurityCheckPipeline`), and CORS preflight handling; a blocking verdict is written through `apply_guard_response`. `on_finish()` schedules post-processing (metrics, logging) as a background task. `security_middleware.agent_stats` exposes the agent's live buffer state for health-check endpoints.

## Route-Level Security Decorators

Decorators from `guard_core.decorators` write per-route `RouteConfig` objects; the middleware resolves them per request via the registered `guard_decorator`. Pass your `SecurityDecorator` through `security_middleware.set_decorator_handler(...)` and it as an `Application` setting (`guard_decorator=...`) so the pipeline is derived from the registered routes; checks that only decorators can trigger (auth, referrer, required headers, custom validators, time window, request size/content) are built only when the middleware can see the route config.

`RouteConfig.bypassed_checks` accepts only recognized tokens (`all`, `ip_ban`, `ip`, `clouds`, `rate_limit`, `penetration`); an unknown token is dropped with a warning, so a typo cannot make a check look disabled while it stays enforced.

## Footguns

* **A `RequestHandler` that does not subclass `SecurityHandler` is not guarded.** The pipeline runs in `SecurityHandler.prepare()`; plain `RequestHandler` subclasses bypass security entirely. Using `default_handler_class=JSONHandler` (a `SecurityHandler`) covers unrouted paths.
* **A missing `security_middleware` Application setting disables guarding silently.** `SecurityHandler` reads `self.application.settings.get("security_middleware")`; when the setting is absent every hook returns early and requests pass unprotected. Always pass the middleware instance when building the `Application`.
* **`enable_redis` defaults to `True`** with `redis_url="redis://localhost:6379"`. Without a reachable Redis, stateful checks fail; set `enable_redis=False` in no-Redis environments or point at a real instance.
* **Decorator-only checks vanish without `set_decorator_handler`.** Without the registered decorator, decorator-triggered checks are not built and their rules never fire.
* **`request.arguments` values are bytes.** Decode before passing them anywhere that expects `str`.
* **`passive_mode=True` logs but never blocks.** Use it to trial rules; switch to `False` once logs confirm the traffic you expect.

## Related Projects

* [guard-core](https://github.com/Guard-Core/guard-core): framework-agnostic security engine this adapter wraps.
* [fastapi-guard](https://github.com/Guard-Core/fastapi-guard): FastAPI/Starlette adapter (async reference implementation).
* [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard): Flask extension adapter (sync mirror).
* [djapi-guard](https://github.com/Guard-Core/djapi-guard): Django middleware adapter (sync mirror).
* [guard-agent](https://github.com/Guard-Core/guard-agent): telemetry client used by `enable_agent=True`.
* [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp): MCP server for config validation and docs search.
* [guard-core-app](https://github.com/Guard-Core/guard-core-app): SaaS platform the agent reports to.
