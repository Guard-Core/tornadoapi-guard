---

title: Release Notes - TornadoAPI Guard
description: Release notes for TornadoAPI Guard, detailing new features, improvements, and bug fixes
keywords: release notes, tornadoapi guard, security middleware, api security
---

Release Notes
=============

___

v2.0.0 (2026-10-15)
-------------------

Engine routing parity with fastapi-guard, response pass before the flush (v2.0.0)
---------------------------------------------------------------------------------

### Breaking changes

- **`SecurityMiddleware.apply_pre_flight_headers` is removed** (#39, closes #38). It was the reimplemented path that set security and CORS headers before the handler ran. Security headers, CORS and return-rule effects are now applied by the engine response pass in `SecurityHandler.finish()`, and blocked responses carry CORS only, like fastapi-guard.
- **Upgrade action** - Delete any call to `middleware.apply_pre_flight_headers(...)` from your own handlers or subclasses. Subclass `SecurityHandler` and nothing else is needed.
- **`SecurityHandler.finish()` returns a future.** It returns an awaitable like Tornado's own `finish()`, so `await self.finish()` and a bare `self.finish()` both work, and a second call returns the same pending future.
- **The `guard-core` floor moves from `>=4.0.0` to `>=4.1.0`**, the first release with the engine APIs this adapter now uses.
- **A request with no client address is now answered with `403`** under the default `fail_secure=True`. It used to pass through. Set `fail_secure=False` to keep the old behavior.

### Fixed

- **The engine response pass now runs in `finish()` before the flush** instead of in `on_finish` after the response was sent. `custom_response_modifier`, the security headers, CORS and return-rule effects now reach the client, and body-based return rules see the buffered body. Streamed responses that call `flush()` before `finish()` already have their headers on the wire, so the pass observes them (metrics, return rules over the buffered body) but cannot change them.
- **Passthrough and the route all-checks bypass go through the engine `BypassHandler`.** Excluded paths are scoped, so bans and IP rules still apply to them, and a bypassed route calls the real handler method with the modifier applied.
- **Blocked, preflight and bypass responses no longer emit request metrics** and skip the response pass. Excluded paths still reach it.
- **Global behavioral return rules now run.**
- **A Redis failure during initialization now returns `503` with `Retry-After`**.

### Documentation and tests

- The handler, middleware and adapter docs, the tutorial pages, the agent guidance and the package skill describe the new flow.
- `tests/test_engine_parity.py` runs a real Tornado server and client against the real engine handlers. The tests that asserted the old bypass behavior and the removed pre-flight headers were replaced.

### Compatibility

- The detection and dynamic rule fixes in guard-core 4.4.0 reach this adapter by upgrading guard-core (for example `pip install -U guard-core`), with no change to this package.

### Chore

- The sponsor button points at the maintainer's Sponsors page, the mkdocs `site_url` drops `/latest/` so canonical URLs resolve, the README markdown lint errors that blocked the docs deploy are fixed and the README was brought to content parity, a CODEOWNERS file was added, the family Discord relay workflow was added, and the `upload-sarif` action was bumped (#29, #30, #31, #32, #34, #36, #37).

___

v1.2.1 (2026-10-08)
-------------------

Guard-Core org migration
------------------------

Metadata release: PyPI project URLs, the docs canonical domain, and all repository links moved to the Guard-Core org. No code changes.

___

v1.0.0 (2026-09-24)
-------------------

First stable release: full pipeline parity, CORS through the engine, guard-core 4.0.x tracking (v1.0.0)
--------------------------------------------------------------------------------------------------------

This is the first tagged, stable release of tornadoapi-guard. PyPI 0.0.1 (2026-04-05) was a scaffolding pre-release; the v1.0.0 draft entries below were never published and are superseded by this entry, which summarizes the full delta since 0.0.1.

- **Parity with the other adapters** - `SecurityMiddleware` was rebuilt around guard-core's own components instead of a thin partial wrapper: the `SecurityCheckPipeline` runs the full check chain, with `HandlerInitializer`, `RouteConfigResolver`/`RoutingContext`, `RequestValidator`/`ValidationContext`, `ErrorResponseFactory`/`ResponseContext`, `BehavioralProcessor`/`BehavioralContext`, `SecurityEventBus`/`MetricsCollector`, the cloud handler, `RateLimitManager`, the security headers manager, and per-route decorators through `BaseSecurityDecorator`/`RouteConfig`. The request/response adapters (`tornadoapi_guard/adapters.py`) were reworked to feed the pipeline the same shape the FastAPI and Flask adapters produce.
- **Pipeline-first CORS** - `SecurityHandler.prepare()` runs the security pipeline before any CORS short-circuit, and preflight handling is delegated to `guard_core.sync.handlers.cors_handler.CorsHandler` (with `is_preflight`), so banned IPs and rate-limited clients can no longer preflight freely.
- **Compatibility** - The `guard-core` dependency moves from unconstrained to `>=4.0.0` (no upper bound) in `pyproject.toml`; master's previous `>=1.0.1,<2.0.0` cap excluded the current 4.0.x engine line. This release tracks guard-core 4.0.4.
- **Added (tests)** - New suites covering the middleware pipeline end to end and in unit form, wiring, lifecycle, CORS through the pipeline, the Tornado handler, the adapters, and the public re-exports.
- **Added (examples)** - `examples/simple_app` demonstrating middleware and handler integration.
- **Packaging (dev)** - `guard-agent` is added to the `dev` extra, matching the other adapters: the middleware lifecycle test constructs the middleware with `enable_agent=True`, and CI installs only `uv sync --extra dev`, so without it the suite fails with `AgentPackageNotInstalledError`.
- **Documentation** - Added `AGENTS.md`/`CLAUDE.md` agent guidance, the tornadoapi-guard package skill, and corrected the decorator docs to list valid bypass tokens and remove invalid examples.

___

v1.0.0 (2026-04-30)
-------------------

Initial public release — fail-secure by default (upstream), agent-stats surface, version reporting (v1.0.0)
-----------------------------------------------------------------------------------------------------------

- **Upstream behavior — `SecurityConfig.fail_secure` defaults to `True`** (inherited from `guard-core >= 3.0.0`). When any security check raises an unhandled exception, the request is blocked with HTTP 500 instead of logging and falling through. Restore the old behavior on deployments that depend on it via `SecurityConfig(fail_secure=False)`. Recommended posture: keep the new default, surface any check exceptions in your monitoring, and fix them — the alternative could mask serious bugs.
- **Added** — `SecurityMiddleware.agent_stats` read-only `@property` returning the agent's telemetry buffer state. Returns `{"enabled": False}` when no agent is wired; otherwise returns `{"enabled": True, **agent_handler.get_stats()}` exposing `events_dropped`, `metrics_dropped`, `circuit_breaker_state`, and other agent counters. No caching — fresh on each call. Lets app teams build health endpoints that surface agent-side drops and circuit-breaker trips without scraping the agent directly.
- **Added** — `from tornadoapi_guard import __version__` — package version is exported via `importlib.metadata.version("tornadoapi_guard")` with a `"0.0.0+unknown"` fallback if the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` so application code can wire the tornadoapi-guard version through to the agent for SaaS-side telemetry attribution: `SecurityConfig(agent_guard_version=__version__)`.
- **Public API** — `SecurityMiddleware.agent_stats` and `__version__` are part of the public surface from this first release.

___

v1.0.0 (2026-04-25)
-------------------

guard-core 2.0.0 protocol alignment (v1.0.0)
--------------------------------------------

### Changed

- `SecurityMiddleware.suspicious_request_counts` is now `dict[str, dict[str, int]]` to match the per-category counter shape introduced in guard-core 2.0.0. The middleware annotation is the only call site touched in the adapter; behaviour is delegated to guard-core which now stores counts grouped by detection category instead of a flat per-IP integer.

### Requires

- `guard-core>=2.0.0`. Adapter middleware updated to match the new `suspicious_request_counts: dict[str, dict[str, int]]` protocol shape. tornadoapi-guard does not call `detect_penetration_attempt` / `detect_penetration_patterns` directly so the new `DetectionResult` return type does not require code changes here. User code that didn't reach into the protocol internals is unaffected.

### Compat notes

- No public API changes on `SecurityMiddleware`. Users that read `middleware.suspicious_request_counts` directly will see the new nested mapping shape and should update their introspection accordingly.

___

v1.0.0 (2026-04-25, OTel hot-path)
----------------------------------

Integration fixes for OTel + enrichment pipeline (v1.0.0)
---------------------------------------------------------

### Fixed

- `SecurityMiddleware.initialize()` is now invoked on the first request via a `_ensure_initialized()` asyncio-lock guard inside `run_pre_processing()`. Previously the method existed but was never called, so `HandlerInitializer.initialize_agent_integrations()` never ran and the composite handler stayed `None`. Without this fix, no OTel span or Logfire log was ever emitted regardless of config.
- After composite construction, `self.agent_handler` is rebound from the bare `guard-agent` client to the composite. Downstream callers that receive `middleware.agent_handler` (most notably `guard_core.utils.extract_client_ip → send_agent_event`) now route through the composite, so enrichment and OTel see every event.
- `BehavioralContext` now receives `handler_initializer.behavior_tracker`, matching the guard-core 1.2.1 wiring. This closes the architectural gap so `guard.behavior.recent_event_count` populates end-to-end when `enable_enrichment=True`.

### Requires

- `guard-core>=1.2.1` for the matching OTLP endpoint normalization and `BehaviorTracker` wiring fixes. Install the latest with `uv add tornadoapi-guard guard-core` or `pip install -U tornadoapi-guard guard-core`.

### Compat notes

- No public API changes. `SecurityMiddleware.__init__` signature unchanged.

___

v1.0.0 (2026-04-24)
-------------------

Telemetry pipeline wiring fix (v1.0.0)
--------------------------------------

Adopts guard-core 1.1.0 and fixes a middleware wiring bug that prevented OpenTelemetry, Logfire, and event/metric/check-log muting from seeing anything emitted by the request-path security pipeline.

- **Fixed** — `SecurityMiddleware.__init__` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` directly, using the bare `guard_agent` handler (or `None`). `middleware.initialize()` then called `HandlerInitializer.initialize_agent_integrations()` which built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were already frozen on the bare handler. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release extracts event-bus construction into `_build_event_bus_and_contexts()`, which consults `handler_initializer.composite_handler` and uses `build_event_bus()` / `build_metrics_collector()` when the composite is available. `initialize()` re-invokes `_build_event_bus_and_contexts()` after `initialize_agent_integrations()` so the dependent contexts (`ResponseContext`, `ValidationContext`, `BehavioralContext`) bind to the post-init event bus.
- **Added** — `tests/test_middleware_wiring.py` — four regression tests that pin `mw.event_bus.agent_handler` and `mw.metrics_collector.agent_handler` to `CompositeAgentHandler` after `middleware.initialize()` when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** — `guard-core>=1.1.0,<2.0.0`.
- **User-visible impact** — Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) — but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.

___

v1.0.0 (2026-04-16)
-------------------

Initial Release (v1.0.0)
------------------------

- **Tornado adapter layer**: `TornadoGuardRequest`, `TornadoGuardResponse`, `TornadoResponseFactory` mapping Tornado's `RequestHandler` to guard-core's protocol interface.
- **SecurityHandler**: Base handler subclass integrating guard-core's security pipeline via `prepare()` / `on_finish()` hooks.
- **SecurityMiddleware**: Full security check pipeline (17 checks) with config via `Application.settings["security_middleware"]`.
- **Public API re-exports**: All guard-core exports available through `tornadoapi_guard` for a clean import surface.
- **Example application**: Comprehensive Tornado app demonstrating IP filtering, rate limiting, behavioral analysis, security headers, decorators, and WebSocket support.
- **Full documentation**: MkDocs site with API reference, configuration guides, decorator usage, and security tutorials.
- **CI/CD**: GitHub Actions workflows for CI, CodeQL, container release, docs deployment, scheduled linting, and PyPI release.
- **Development tooling**: Pre-commit hooks, Makefile targets, Docker Compose setup, Python 3.10-3.14 support.
