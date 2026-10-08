---

title: Example Application - TornadoAPI Guard Demo
description: Walkthrough of the TornadoAPI Guard reference example application
keywords: tornadoapi-guard example, example application, security middleware demo, docker compose
---

Example Application
===================

TornadoAPI Guard ships with a fully functional reference application at `examples/simple_app/main.py` that exercises every major security feature. Use it as a living reference for how to structure handlers, attach decorators, and wire the middleware into a `tornado.web.Application`.

___

What the Example Demonstrates
-----------------------------

- IP whitelist/blacklist filtering
- Geographic restrictions and cloud provider blocking
- Global and per-route rate limiting (including geographic rate limits)
- Authentication decorators (HTTPS enforcement, bearer tokens, API keys, custom headers)
- Behavioral analysis (usage monitoring, return-pattern monitoring, frequency detection, composite rules)
- Content filtering (user agent blocking, content-type filtering, size limits, referrer checks, custom validators)
- Security headers (CSP, HSTS, frame options, custom headers) and a CSP-report endpoint
- Time-window and honeypot decorators
- Admin endpoints that are locked down by IP whitelist
- A WebSocket echo endpoint

___

Running with Docker Compose
---------------------------

The easiest way to run the example is with Docker Compose, which also brings up a Redis instance:

```bash
git clone https://github.com/Guard-Core/tornadoapi-guard.git
cd tornadoapi-guard
docker compose up
```

The example app listens on <http://0.0.0.0:8000>.

___

Running Locally with uv
-----------------------

```bash
make install-dev
make start-example
# or directly:
REDIS_URL=redis://localhost:6379 uv run python examples/simple_app/main.py
```

___

Architecture Overview
---------------------

The example is built around three objects that every TornadoAPI Guard application needs:

- **`SecurityMiddleware`** — holds the security pipeline, the metrics collector, and the event bus. Instantiated once at module level and then `await security_middleware.initialize()` is called in `main()` before the server starts.
- **`SecurityHandler`** — base class that every route inherits from (directly or via a small project-specific subclass like the `JSONHandler` in the example). `SecurityHandler.prepare()` runs the full security pipeline before the handler method, and `SecurityHandler.on_finish()` runs post-processing hooks.
- **`SecurityDecorator`** — route-level decorator set. Instantiated once at module level and registered with the middleware via `security_middleware.set_decorator_handler(guard_decorator)`. Applied to handler methods (`get`, `post`, `put`, ...), never to the class.

The example also defines a project-specific `JSONHandler(SecurityHandler)` subclass that adds `write_json` / `write_error` helpers — a useful pattern for any production app.

```python
security_middleware = SecurityMiddleware(config=security_config)
guard_decorator = SecurityDecorator(security_config)
security_middleware.set_decorator_handler(guard_decorator)
```

The application is then built in `build_application()`:

```python
return tornado.web.Application(
    handlers,
    security_middleware=security_middleware,
    guard_decorator=guard_decorator,
    default_handler_class=JSONHandler,
)
```

Both `security_middleware` and `guard_decorator` are passed as `Application` settings so the handler base class and the middleware can resolve them at request time.

___

Handler Groups Overview
-----------------------

Routes are organized into logical groups. For each group below you will find the list of endpoints and one representative handler class.

___

Basic Handler Group (`/basic/*`)
--------------------------------

- `/` — `RootHandler`: landing page listing all route groups.
- `/basic/` — `BasicRootHandler`
- `/basic/ip` — `BasicIPHandler`: echoes client IP + geo placeholders.
- `/basic/health` — `BasicHealthHandler`
- `/basic/echo` — `BasicEchoHandler`: echoes JSON body and headers.

```python
class BasicEchoHandler(JSONHandler):
    async def post(self) -> None:
        try:
            data = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            data = {"raw": self.request.body.decode("utf-8", errors="replace")}
        self.write_json(
            {
                "message": "Echo response",
                "details": {
                    "data": data,
                    "headers": dict(self.request.headers),
                    "method": self.request.method,
                    "url": self.request.full_url(),
                },
            }
        )
```

___

Access Control Handler Group (`/access/*`)
------------------------------------------

- `/access/ip-whitelist` — `AccessIPWhitelistHandler`
- `/access/ip-blacklist` — `AccessIPBlacklistHandler`
- `/access/country-block` — `AccessCountryBlockHandler`
- `/access/country-allow` — `AccessCountryAllowHandler`
- `/access/no-cloud` — `AccessNoCloudHandler`
- `/access/no-aws` — `AccessNoAWSHandler`
- `/access/bypass-demo` — `AccessBypassHandler`

```python
class AccessIPWhitelistHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
    async def get(self) -> None:
        self.write_json({"message": "Access granted from whitelisted IP"})
```

___

Authentication Handler Group (`/auth/*`)
----------------------------------------

- `/auth/https-only` — `AuthHttpsHandler`
- `/auth/bearer-auth` — `AuthBearerHandler`
- `/auth/api-key` — `AuthAPIKeyHandler`
- `/auth/custom-headers` — `AuthCustomHeadersHandler`

```python
class AuthBearerHandler(JSONHandler):
    @guard_decorator.require_auth(type="bearer")
    async def get(self) -> None:
        self.write_json(
            {
                "authenticated": True,
                "user": "example_user",
                "method": "bearer",
                "permissions": ["read", "write"],
            }
        )
```

___

Rate Limiting Handler Group (`/rate/*`)
---------------------------------------

- `/rate/custom-limit` — `RateCustomLimitHandler` (5 per 60s)
- `/rate/strict-limit` — `RateStrictLimitHandler` (1 per 10s)
- `/rate/geo-rate-limit` — `RateGeoHandler`

```python
class RateGeoHandler(JSONHandler):
    @guard_decorator.geo_rate_limit(
        {
            "US": (100, 60),
            "CN": (10, 60),
            "RU": (20, 60),
            "*": (50, 60),
        }
    )
    async def get(self) -> None:
        self.write_json({"message": "Geographic rate limiting applied"})
```

___

Behavioral Handler Group (`/behavior/*`)
----------------------------------------

- `/behavior/usage-monitor` — `BehaviorUsageHandler`
- `/behavior/return-monitor/<code>` — `BehaviorReturnMonitorHandler`
- `/behavior/suspicious-frequency` — `BehaviorSuspiciousFrequencyHandler`
- `/behavior/behavior-rules` — `BehaviorComplexHandler`

```python
class BehaviorComplexHandler(JSONHandler):
    @guard_decorator.behavior_analysis(
        [
            BehaviorRule(
                rule_type="frequency", threshold=10, window=60, action="throttle"
            ),
            BehaviorRule(
                rule_type="return_pattern",
                pattern="404",
                threshold=5,
                window=60,
                action="ban",
            ),
        ]
    )
    async def post(self) -> None:
        self.write_json({"message": "Complex behavior analysis active"})
```

___

Headers Handler Group (`/headers/*`)
------------------------------------

- `/headers/` — `HeadersInfoHandler`
- `/headers/test-page` — `HeadersTestPageHandler`
- `/headers/csp-report` — `HeadersCspReportHandler`
- `/headers/frame-test` — `HeadersFrameTestHandler`
- `/headers/hsts-info` — `HeadersHSTSHandler`
- `/headers/security-analysis` — `HeadersAnalysisHandler`

```python
class HeadersCspReportHandler(JSONHandler):
    async def post(self) -> None:
        try:
            payload = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            payload = {}
        report = payload.get("csp-report", {})
        logger.warning(
            "CSP Violation: %s blocked %s on %s",
            report.get("violated-directive", "unknown"),
            report.get("blocked-uri", "unknown"),
            report.get("document-uri", "unknown"),
        )
        self.write_json({"message": "CSP violation report received"})
```

___

Content Handler Group (`/content/*`)
------------------------------------

- `/content/no-bots` — `ContentNoBotsHandler`
- `/content/json-only` — `ContentJSONOnlyHandler`
- `/content/size-limit` — `ContentSizeLimitHandler`
- `/content/referrer-check` — `ContentReferrerHandler`
- `/content/custom-validation` — `ContentCustomValidationHandler`

```python
class ContentJSONOnlyHandler(JSONHandler):
    @guard_decorator.content_type_filter(["application/json"])
    async def post(self) -> None:
        try:
            data = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            data = {}
        self.write_json({"message": "JSON content received", "details": {"data": data}})
```

___

Advanced Handler Group (`/advanced/*`)
--------------------------------------

- `/advanced/business-hours` — `AdvancedBusinessHoursHandler`
- `/advanced/weekend-only` — `AdvancedWeekendHandler`
- `/advanced/honeypot` — `AdvancedHoneypotHandler`
- `/advanced/suspicious-patterns` — `AdvancedSuspiciousHandler`

```python
class AdvancedBusinessHoursHandler(JSONHandler):
    @guard_decorator.time_window(start_time="09:00", end_time="17:00", timezone="UTC")
    async def get(self) -> None:
        self.write_json({"message": "Access granted during business hours"})
```

___

Admin Handler Group (`/admin/*`)
--------------------------------

All admin endpoints are locked to `127.0.0.1` via `@guard_decorator.require_ip(whitelist=["127.0.0.1"])`.

- `/admin/unban-ip` — `AdminUnbanHandler`
- `/admin/stats` — `AdminStatsHandler`
- `/admin/clear-cache` — `AdminClearCacheHandler`
- `/admin/emergency-mode` — `AdminEmergencyModeHandler`
- `/admin/cloud-status` — `AdminCloudStatusHandler`

```python
class AdminStatsHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1"])
    async def get(self) -> None:
        self.write_json({"total_requests": 1500, "blocked_requests": 75})
```

___

Test Handler Group (`/test/*`)
------------------------------

Endpoints used to feed payloads through the penetration-detection pipeline.

- `/test/xss-test` — `TestXSSHandler`
- `/test/sql-injection` — `TestSQLHandler`
- `/test/path-traversal/<path>` — `TestPathTraversalHandler`
- `/test/command-injection` — `TestCommandInjectionHandler`
- `/test/mixed-attack` — `TestMixedAttackHandler`

```python
class TestSQLHandler(JSONHandler):
    async def get(self) -> None:
        query = self.get_query_argument("query", default="")
        self.write_json(
            {
                "message": "SQL injection test processed",
                "details": {"query": query, "detected": False},
            }
        )
```

___

WebSocket Handler Group (`/ws`)
-------------------------------

The example exposes a simple echo WebSocket at `/ws` using Tornado's native `WebSocketHandler`. Note that WebSocket handlers inherit from `tornado.websocket.WebSocketHandler` and do **not** go through `SecurityHandler.prepare()` — the HTTP upgrade request is still routed through Tornado, but the security pipeline is not applied. Use HTTP-level decorators on an adjacent handler if you need to gate WebSocket access.

```python
class EchoWebSocketHandler(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin: str) -> bool:
        return True

    async def on_message(self, message: str | bytes) -> None:
        text = message.decode("utf-8") if isinstance(message, bytes) else message
        await self.write_message(f"Echo: {text}")
```

___

Sample curl Commands
--------------------

```bash
# Basic
curl http://0.0.0.0:8000/basic/health

# Access control
curl http://0.0.0.0:8000/access/ip-whitelist

# Authentication (expect 401 without token)
curl http://0.0.0.0:8000/auth/bearer-auth

# Rate limiting (trigger 429 after the 5th request)
for i in {1..6}; do curl http://0.0.0.0:8000/rate/custom-limit; done

# Behavioral
curl http://0.0.0.0:8000/behavior/usage-monitor

# Headers (inspect response headers)
curl -I http://0.0.0.0:8000/headers/

# Content filtering
curl -X POST -H "Content-Type: application/json" -d '{"ok": true}' http://0.0.0.0:8000/content/json-only

# Advanced
curl http://0.0.0.0:8000/advanced/business-hours

# Admin (works from localhost only)
curl http://0.0.0.0:8000/admin/stats

# Penetration detection
curl "http://0.0.0.0:8000/test/sql-injection?query=SELECT%20*%20FROM%20users"
curl -X POST -d '<script>alert(1)</script>' http://0.0.0.0:8000/test/xss-test
```

___

A Note on `/docs`
-----------------

Unlike FastAPI, Tornado does not generate OpenAPI documentation automatically, so there is no `/docs` (Swagger UI) endpoint in the example. The authoritative list of routes and their handlers lives in `build_application()` inside `examples/simple_app/main.py`.

___

Source
------

The full source code lives at [`examples/simple_app/main.py`](https://github.com/Guard-Core/tornadoapi-guard/blob/master/examples/simple_app/main.py). Reading that file end-to-end is the fastest way to get comfortable with TornadoAPI Guard.
