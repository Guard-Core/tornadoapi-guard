Release Notes
=============

___

Unreleased
----------

- **Changed** - **`fail_on_misconfiguration` now governs the first-request report of a `detection_exclusion(path_params=...)` problem (release note, behavior change).** The first request used to log one WARNING whatever the flag said. The adapter first sees the Application at a request and `add_handlers` can still add routes, so the first request is the earliest point it can check: with `fail_on_misconfiguration=True` a request now raises a fresh engine error (a `ValueError` listing every problem, Tornado answers 500) built from the cached result, and the Application is walked again only when its rules change, so a route that `add_handlers` adds later is checked too and joins the error. With the flag off the first request logs one WARNING per problem, as before, and a route added later logs its own once. Each problem carries a stable kind, `decorator.detection_exclusion.param_not_in_template` or `decorator.detection_exclusion.param_without_literal_segment`, from one guard-core helper that every adapter shares.

- **Added** - **A `detection_exclusion(path_params=...)` name its route does not have is logged at the first request.** The first request through an `Application` reads its rules (host rules and nested applications included) and logs once per application, as a WARNING, each declared name that is missing from the route's regex or has no literal segment before it; a rule with positional groups has no names, so any declared name there is reported. A handler on several rules is checked per rule. It never raises, whatever `fail_on_misconfiguration` says.

- **Added** - **`release_app(config)` is the host and test API for releasing an app.** Tornado offers no shutdown hook that this adapter uses (the application is not told when its server stops), so `SecurityMiddleware` never releases its app by itself and N requests through an application leave the module-level default binding as it was. A host that stops a server, and a test suite that builds several apps, call `tornadoapi_guard.release_app(config)` (guard-core's `release_app`, now re-exported) with the `SecurityConfig` the middleware was built with; the default managers then go to the next app at that moment instead of whenever the cyclic garbage collector frees the earlier app. An app that is never released keeps the collector-timed handoff of guard-core 5.0.0. Calling it twice is harmless, and a request that reaches a released app is still screened with the managers its pipeline captured at build time. Never call it from `RequestHandler.on_finish` or `on_connection_close`: it would release a live app on every request. The suite's `tests/conftest.py` releases every app's config between tests.

- **Fixed** - **The `guard-core` floor is `>=5.0.0,<6`.** This release's code uses engine names that guard-core 4.4.x does not have, so an environment that kept 4.4.x imported a broken package. Upgrading now installs guard-core 5.x and stops below the next major. An install that must stay on guard-core 4.x stays on the previous release of this package. The lock follows the floor once guard-core 5.0.0 is published.

- **Fixed** - **A finished request no longer stays in memory for the life of the process.** `get_guard_state(handler)` kept each handler's state in a module-level `WeakKeyDictionary`, but the state reached its own key (the pending `guard_finish` task holds the handler, and `state.guard_request` holds the request wrapper that holds the handler), so the weak key never died: one app serving 200 requests kept 200 handlers alive, and through them the `Application`, the `SecurityMiddleware` and the `SecurityConfig`. The state is now an attribute of the handler, so the handler and its state form a cycle with no module-level root and the garbage collector frees them when the request is done. `get_guard_state` keeps its name and signature. `tests/test_handler_state_release.py` serves 10 and 50 requests (a blocked 403 among them) and builds and serves 10 and 50 apps, and checks that the live handlers and `SecurityConfig` objects do not grow with the count.

- **Fixed** - **On Python 3.10, tornado 6.5.10 carries three advisories with no fixed release, and the CVE gate now says so.** GHSA-pcg2-g6cj-q92c (quadratic CPU on folded header lines), GHSA-r4j5-9xpp-3985 (chunked bodies with many small chunks block the event loop) and GHSA-pw9p-v7r6-gx4p (open redirect in `tornado.web.RedirectHandler`) are fixed only in tornado 6.6, which requires Python 3.11 or later. The first two run in tornado's HTTP/1 parser before any handler code, so the adapter cannot stop them; the third reaches apps that route to `RedirectHandler` (the adapter does not use it). Python 3.10 stays supported. Use Python 3.11 or later to get tornado 6.6; on 3.10, tornado's `max_header_size` (default 65536) and `max_body_size` server settings bound the cost of the first two, they do not fix them. The three suppressions in `osv-scanner.toml` now state that they reach 3.10 users, and they expire on 2026-12-15, when the PyPI and OSV reads are repeated.

- **Fixed** - **`route_template(path)` descends into a nested `Application` rule.** A rule whose target is another `Application` gave the outer rule's pattern (`/sub/(.*)$`) instead of the inner rule's whole template, so a `detection_exclusion` path parameter of the inner route never matched. Nested routers already gave the whole template.

- **Fixed** - **`route_template(path)` is cached per (Host, path), not per path.** With `add_handlers` virtual hosts the first host's template was served to every other host. The key now carries the request's Host, with the same 4096-entry bound and the hashed form for an over-long path or Host.

- **Fixed** - **The tornado adapter builds its probe requests the Tornado 6.6 way.** The middleware builds its internal route-probe requests with `start_line=RequestStartLine(...)` and the `Host` header instead of the `method`, `uri`, `version` and `host` arguments of `HTTPServerRequest`, which Tornado 6.6 deprecates (a `-W error` run turned them into failures: 47 tests, and a static-file or route-template probe that failed closed to the unprobed path). It works on Tornado 6.5.10 and 6.6.

- **Fixed** - **Every shipped dependency declares a lower bound with no known advisory.** The declared floor is now `tornado>=6.6` on Python 3.11 and later and `tornado>=6.5.10` on Python 3.10 (it had none). Tornado 6.6 requires Python 3.11 and no 6.5.x release carries its fixes (the upstream `branch6.5` equals v6.5.10), so on Python 3.10 three advisories stay open and listed in `osv-scanner.toml` with an expiry; Python 3.10 support is kept. The suite passes at these floors on Python 3.10 and 3.11.

- **Fixed** - **The lock moved past every known advisory and the supply chain is pinned.** The lock moves `certifi` to 2026.10.18 and resolves `tornado` 6.6 on Python 3.11 and later; on Python 3.10 tornado 6.6 does not install, so the three tornado advisories fixed in 6.6 stay open there and are suppressed per advisory in `osv-scanner.toml` with a reason and an expiry (decide at the next release whether 3.10 stays supported). A new CVE gate (`cve-scan.yml`, run on every pull request, push, daily and before a release) fails on any open advisory in the lock, in the declared dependency floors and in the published image, and every workflow action and tool install is pinned to a commit or version.

- **Fixed** - **A scan that only waited for a regex worker answers 503 with `Retry-After`, not 400.** With 64 uploads in flight on Flask and Django, guard-core 5.0.0 refused 1 to 4 of 64 benign 1 MiB uploads: a scan that got no regex worker within `detection_compiler_timeout` answered `400 Request body could not be read`, and a started scan that waited for the GIL past that time was refused as `400 Suspicious activity detected` with a strike. guard-core now runs its six windowed built-in rows on the request thread, judges a started custom scan by its worker's CPU, and answers a scan that got no worker in time with `503` and `Retry-After` set to `ceil(detection_compiler_timeout)`, no strike, and its own log line and event naming the wait and the surface. `custom_error_responses[503]` replaces the message, a real body read failure keeps its `400`, and `fail_secure=False` and passive mode pass with the event. `tornadoapi-guard` carries a test that holds the regex pool busy and checks the `503`, the `Retry-After` header and the custom message.

- **Fixed** - **The detection engine pages state numbers measured on guard-core 5.0.0, each with the command that reproduces it.** The 'Latency Impact' and 'Memory Usage' sections of `architecture.md` and the benchmark section and checklist of `performance-tuning.md` carry CPU time per call (interleaved with an A/A arm) and Python heap and RSS per step in place of the old estimates (`< 1ms` preprocessing, `1-5ms` semantic analysis, `5-20ms` total detection, `~100KB`, `~1MB` and `~2-5MB`), measured with `python -m perf_gate.detection_components` from a guard-core checkout. The measurements corrected three remarks: capture groups cost nothing measurable on the example pattern, a higher `detection_semantic_threshold` does not make detection faster (the CPU is the same at 0.6, 0.7 and 0.8), and `detection_max_content_length=2000` cuts the CPU of a 10,000-character value by 23%. The checklist lists the pattern validation cache hit rate, which guard-core 5.0.0 reports through `get_cache_stats()`: 0.0 at the first boot and 1.0 at the second for 20 custom patterns.

- **Fixed** - **Every shipped Markdown example and stated default matches the 5.0.0 API, and a test keeps it true.** `tests/test_markdown_python_blocks.py` parses every Python block of the README, `docs/`, the examples and the packaged skill files, runs the blocks of each file one after another in a sandbox with no network, and checks every Guard import, call, keyword and attribute against the installed guard-core 5.0.0 objects. It also compares every default and range a table or bullet states with `SecurityConfig`, checks the documented signature listings, and checks the telemetry mute values against the engine. It failed on the old pages, and the pages now show what 5.0.0 accepts: `SecurityConfig` keywords that do not exist (`db_path`, `redis_host`, `redis_port`, `redis_db`, `redis_pool_size`, `redis_ttl`, `log_level`, `use_redis`, `rate_limit_requests`), `SusPatternsManager.clear_custom_patterns` (it does not exist), `cloud_handler.refresh()` shown as synchronous (it is a coroutine here), and `redis_handler.get` (the key is read with `get_key("patterns", "custom_list")`); country decorators and return monitors shown without the geo source and the response body scanning 5.0.0 requires, `block_user_agents` patterns such as `.*bot.*` that the ReDoS validator refuses, custom patterns that `add_pattern` rejects, `blocked_countries` set together with `whitelist_countries`, `Cloudflare` as a cloud provider, custom GeoIP handler listings that left out members, `avg_execution_time` where the pages said `average_time`, the detection engine component pages (module paths, constructors, methods and result shapes), the check order (up to 18 checks), the telemetry mute values, and stale defaults (`rate_limit` 120, `enable_redis` off unless a Redis field is set, `redis_prefix` `guard_core:`, `Cross-Origin-Resource-Policy` `same-site`, no `Cross-Origin-Embedder-Policy`). The packaged skill file no longer says it is current for an older release, that `enable_redis` defaults to `True`, or that the default limit is 10 requests per 60 seconds.

- **Added** - **A test runs the packaged agent skill file.** Every Python block of `tornadoapi_guard/.agents/skills/tornadoapi-guard/SKILL.md` is executed, top-level `await` included, so a renamed or missing API in the skill file fails the suite. The file needed no change.

- **Breaking changes** - **A country rule or geo rate limit with no geo source now raises when the route is declared.** `@block_countries`, `@allow_countries` and `@geo_rate_limit` raise `ValueError` at import when the decorator's config has neither `geo_ip_handler` nor `ipinfo_token`, or has `ipinfo_token` without the `maxminddb` package and `aiohttp`, as long as `fail_on_misconfiguration` is `True` (the 5.0.0 engine default). Before, the app started and the first request raised. `fail_on_misconfiguration=False` keeps starting and logs the warning once at initialization. A decorator built from a config without a geo source and paired with a middleware config that has `ipinfo_token` now raises at import: give the decorator's config the token. Needs the guard-core release that carries the declaration check.

- **Fixed** - **Country rules need no global rule.** The middleware keeps `config.geo_ip_handler` whenever one is configured and reads back the handler the engine built from `ipinfo_token` for a route-level `block_countries`, `allow_countries` or `geo_rate_limit`, so those rules work without a global country rule. The examples no longer carry a placeholder `blocked_countries`.

- **Fixed** - **The middleware runs the engine's check order.** It builds its pipeline with the engine's `build_default_pipeline` instead of a list of its own, so the order is the engine's and a later engine change reaches it. IP security, cloud, user agent and rate limiting now run before `required_headers`, `authentication`, `referrer`, `custom_validators` and `time_window`: a banned IP that also lacks a required header gets the ban answer, and a request over the rate limit that also fails authentication gets `429`. The startup log line is unchanged in form, and the pipeline holds only the checks the config and the registered routes need, as in fastapi-guard.

- **Breaking changes** - **The base install no longer carries `redis`, `maxminddb`, `aiohttp` or `requests`.** They follow guard-core 5.0.0, whose base install is `cachetools`, `pydantic` and `typing-extensions`. `tornadoapi-guard` gains three extras that forward to guard-core's: `tornadoapi-guard[redis]` (the Redis client, needed when Redis is on), `tornadoapi-guard[geo]` (`maxminddb` and the downloader of the built-in GeoIP manager, needed for country rules) and `tornadoapi-guard[cloud]` (`aiohttp` and `requests`, needed for cloud-provider blocking). A config that needs a package you did not install is refused when `SecurityConfig` is built, with a message that names the adapter's extra, and the Redis, cloud, geo and rate-limit names the package re-exports load lazily, so the import works without them. Add the extra your config uses, for example `pip install "tornadoapi-guard[redis,geo]"`.

- **Added** - **The route gate: the middleware answers `route_template(path)` and `static_file_exists`, and the buffered body is offered as a bounded prefix.** `SecurityMiddleware.route_template(path)` returns the pattern of the rule that matches the path (`URLSpec.regex.pattern`, nested routers searched, `None` when nothing matches) through an LRU of 4096 entries per middleware, cleared when the number of rules changes or the rules object is replaced. guard-core's route gate calls it only for a path that passes its extension prefilter: a pattern that carries the extension, such as `r"/legacy/(.*)\.php"`, is the app's own route and `r"/files/(.*)"` carries none and stays flagged. A `.ts` or `.map` path whose matching rule is a `StaticFileHandler` subclass is clean when the handler's own `get_absolute_path` and `validate_absolute_path` accept it (root prefix, symlink directories, a regular file), run in a worker thread; a missing file, a traversal, a symlink out of the root, a bad percent escape and any other handler keep the path flagged as in 2.0.0. `TornadoGuardRequest.read_body_prefix_until_idle(max_bytes, idle_timeout)` returns the first `max_bytes` of the buffered body, because Tornado hands a handler the body only after its server has received all of it and its own body and idle timeouts are the deadline. Before, the adapter offered no bounded reader, so guard-core skipped a body over `detection_max_body_inspect_bytes` unscanned; now its prefix is scanned. The middleware also lists its static route prefixes (`static_route_prefixes()`) so guard-core can warn once about an `exclude_paths` entry that matches no route.

- **Changed (behavior)** - **`endpoint_rate_limits` keys follow the Tornado router.** Each key is resolved through the application's rules at startup and when a dynamic rule is applied, so a key counts the requests that reach the same handler with the same path parameters, and a key that matches no rule falls back to a normalized match (`//` collapsed, dot segments resolved, one trailing slash stripped, case kept). Two paths routed to one handler class share one budget per HTTP method (`(r"/login", SignInHandler)` and `(r"/signin", SignInHandler)` count against one limit, so a stacked path cannot get a fresh budget), and a generic handler routed on many paths shares one too, so give each limited path its own handler class.

- **Added** - **`SecurityWebSocketHandler` guards the WebSocket upgrade.** `SecurityHandler` checks in `prepare()` and a `WebSocketHandler` never flowed through it, so a banned, blocked, rate-limited or emergency-locked client got a socket. `SecurityWebSocketHandler` runs the same pipeline on the upgrade request before the handshake, a denial answers like the HTTP route and opens no socket, and `passive_mode` logs and lets the upgrade through. Under `passive_mode` a Redis outage at initialization also admits the upgrade. The example's `/ws` is guarded and both docs pages say how.

- **Changed (behavior)** - **Throttle rules answer `429`, route and global, unrouted paths included.** The adapter called `process_usage_rules` as a bare statement and dropped the refusal it returned, so a usage `throttle` rule recorded its trips and never refused. It now answers the engine's `429 Too many requests` with `Retry-After` for route and global throttle rules on routed and unrouted paths, and passes itself to the behavioral processor so `correlate_with_detection` sees the detection hits. guard-core 5.0.0 also enforces the rules in its own pipeline and each request records its hit once, so the adapter's call and the engine's never count a request twice. If your clients began to receive `429` after the upgrade, a throttle rule you configured is now doing what it says: raise its threshold or window.

- **Changed (behavior)** - **`security_headers` settings are applied by guard-core's `apply_security_headers_settings`, and the startup call of the global manager no longer overrides other apps.** The adapter's own reader is gone: a partial block merges over the engine defaults (a block that leaves `xss_protection` out sends `X-XSS-Protection: 0`, where the adapter's reader sent `1; mode=block`), and `hsts: None` configures the manager instead of raising. The middleware's own call to the global `security_headers_manager.configure(...)` passes `override_apps=False`, so it fills the manager's own state as before and no longer sets the cross-app override to this app's config: two apps with different CSPs each keep their own. A call you make yourself with `override_apps=True` still reaches every guarded app, and one without it reaches none.

- **Added** - **A CORS preflight is answered for an app built without CORS, once another worker calls `configure(enable_cors=True, override_apps=True)`.** The adapter builds its own check list, so such a call never made its pipeline answer a preflight: the request reached the handler and got a `405`. The engine's `CorsPreflightCheck` is added after `UserAgentCheck` when `enable_cors` is off, and the simple responses of an app built without CORS carry the flagged CORS override (an app with CORS off and no override still emits nothing and skips requests without an `Origin`). It needs the guard-core release that ships `CorsPreflightCheck`.

- **Changed (behavior)** - **`Origin` is merged into the application's `Vary`.** The CORS pass replaced the response's `Vary` with the engine's, dropping a `Vary` the handler had set. It now merges `Origin` into the existing header and keeps a value that already lists `Origin` or `*` as it is.

- **Changed (behavior)** - **`passive_mode` admits a request when Redis is down at initialization.** A `GuardRedisError` from the first initialization answered `503`. Under `passive_mode` it now passes the request through unguarded with a sampled log line. Without `passive_mode` the answer stays `503` with `Retry-After`.

- **Fixed** - **A ban made inside a view goes through its own app.** The adapter holds the app's scope across the handler and releases it where the request ends, so a ban, an event or a Redis write made from a handler of one app goes through that app's own handlers, trusted proxies and Redis prefix when two apps share a process.

- **Fixed** - **`agent_stats` answers with the agent on.** Once the engine swapped in its `CompositeAgentHandler`, `agent_stats` raised `AttributeError` because the composite had no `get_stats`. The adapter now calls `get_stats` on the handler without a cast, and guard-core returns the stats of the handlers that have one.

- **Added** - **The response wrapper declares `body_is_materialized`.** A response built from a handler is materialized only while its headers have not gone out. After a flush the earlier chunks are with the client and the write buffer holds just the rest, so the engine takes its bounded path and refuses a body read instead of handing a modifier a partial body; a response built with its body (an error, a redirect, a preflight) is materialized.

- **Changed** - **The adapter has no `cast` and no explicit `Any`, and the agent is the async `GuardAgentHandler`.** The middleware builds `GuardAgentHandler` and never the auto-detecting factory, production `assert` statements are replaced by explicit narrowing and a `RuntimeError`, and `mypy` runs with `disallow_any_explicit` on `tornadoapi_guard` behind a ratchet.

- **Added** - **Python 3.15 is supported.** `requires-python` is now `>=3.10,<3.16` and 3.15 joins the test matrix as a required version.

- **Fixed** - **The route-template cache holds bounded keys.** It keyed on the raw request path with no length cap, so 4096 distinct 60 KB `.php` paths retained about 246 MB per middleware. A path longer than 256 characters is now keyed by its hash (randomized per process, so a collision cannot be built); hits and misses stay cached, so a templated route with a long parameter is still a hit.

- **Fixed** - **A directory path under a `StaticFileHandler` with a `default_filename` no longer raises in the route gate.** `static_file_exists` let the handler build the redirect Tornado answers a directory without a trailing slash with, which needs a connection the gate has not got: a `TypeError` and one `ERROR` log line per request. It now answers that the path is no file served.

- **Fixed** - **Routes of a virtual host (`add_handlers(host_regex, ...)`) are visible to the route gate.** `resolve_route`, `route_template` and `static_file_exists` matched against a request whose Host was `localhost`, so a virtual-host route was not found: its own `.map` and `.php` routes stayed flagged and endpoint identity was lost. They now match under the request's Host.

- **Fixed** - **A handler that calls `flush()` carries the security and CORS headers.** The headers go out with the first `flush()`, before the response pass, which skips its header work once they are sent: the response had no security headers and no CORS headers, with no log line, on guarded and `exclude_paths` routes alike. `SecurityHandler.flush()` now applies them before the first flush. A test that pinned the missing headers on a streamed response now pins their presence.

- **Fixed (docs)** - **The docs state how a dynamic rule combines with the config, and what `passive_mode` does for a client with no address.** A dynamic rule adds to your configuration and never wipes it: blocked countries, blocked cloud providers and blocked user agents are added to your static lists, `whitelist_countries` is replaced only when the rule's value is non-empty and valid, and `endpoint_rate_limits` merge per endpoint (the rule's value wins for the endpoints it names, your static limits stay for the rest); the `endpoint_rate_limits` row no longer says dynamic rules set it. A request from a client with no address is refused under `fail_secure` (the default) and logged and admitted under `passive_mode`.

- **Fixed (test)** - **A test pins the no-address client under `passive_mode`.** `tests/test_unknown_client_passive_mode.py` checks that a request from a client with no address is refused with `403` under `fail_secure` and admitted under `passive_mode`, the behavior the docs describe; the passive arm needs guard-core's change that admits and logs a client with no address in passive mode.

- **Fixed** - **A response a custom hook returns without a `Content-Type` is served as `text/plain; charset=utf-8`.** `unwrap_response` handed the framework default type (`text/html`, or a sniffed one) to a foreign `GuardResponse` that named none, so a `custom_request_check` response that echoes request text was a reflected XSS. The unwrapped response now carries `text/plain; charset=utf-8` when no header named `Content-Type` in any case is present; a `Content-Type` the hook sets, in any case, is kept as it is. Behavior change for a hook that returned HTML or JSON without naming the type: it now has to set `Content-Type` itself.

___

v2.0.0 (2026-10-15)
-------------------

Engine routing parity with fastapi-guard, response pass before the flush (v2.0.0)
---------------------------------------------------------------------------------

### Breaking changes

- **`SecurityMiddleware.apply_pre_flight_headers` is removed** (#39, closes #38). It was the reimplemented path that set security and CORS headers before the handler ran. Security headers, CORS and return-rule effects are now applied by the engine response pass in `SecurityHandler.finish()`, and blocked responses carry CORS only, like fastapi-guard.
- **Upgrade action** - Delete any call to `middleware.apply_pre_flight_headers(...)` from your own handlers or subclasses. Subclass `SecurityHandler` and nothing else is needed.
- **The `guard-core` floor moves from `>=4.0.0` to `>=4.4.0`**, which carries the engine APIs this adapter now uses (first shipped in 4.1.0) and the guard-core 4.4.0 detection and dynamic rule fixes.
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

- The `>=4.4.0` floor means upgrading tornadoapi-guard also brings the guard-core 4.4.0 detection and dynamic rule fixes (Cookie header scanned per pair, the per-request scan budget, the semantic-only header opt-out and dynamic rule versions applied over the base config).

### Chore

- The sponsor button points at the maintainer's Sponsors page, the mkdocs `site_url` drops `/latest/` so canonical URLs resolve, the README markdown lint errors that blocked the docs deploy are fixed and the README was brought to content parity, a CODEOWNERS file was added, the family Discord relay workflow was added, and the `upload-sarif` action was bumped (#29, #30, #31, #32, #34, #36, #37).

___

v1.2.1 (2026-10-08)
-------------------

Guard-Core org migration
------------------------

Metadata release: PyPI project URLs, the docs canonical domain, and all repository links moved to the Guard-Core org. No code changes.

___

v1.2.0 (unreleased)
-------------------

Adapter parity with the family baseline (targets the 1.2.0 adapter train)

- **CI modernization** - `ci.yml` uses `pull_request` instead of `pull_request_target` (no base-branch secrets context on PR code), all actions align on v7 majors, and the release build uses `python -m build` instead of the legacy `setup.py sdist bdist_wheel`.
- **New workflows to match the adapter set** - `live-smoke.yml` (builds the wheel from the checkout and smoke-tests the example app in Docker), `upstream-drift.yml` (daily suite run against a guard-core@master wheel), and `docksec.yml` (Dockerfile scanning with SARIF).
- **Added (examples)** - `examples/advanced_app`: production-shaped topology with an nginx edge (connection shedding, forwarded headers), Redis-backed guard state, health/ready endpoints for orchestration, a route-scoped strict rate limit, and an admin-token-protected utility route.
- **Docs deploy serialization** - `docs.yml` gains the `docs-deploy` concurrency group the other adapters already use.

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

Initial public release - fail-secure by default (upstream), agent-stats surface, version reporting (v1.0.0)
-----------------------------------------------------------------------------------------------------------

- **Upstream behavior - `SecurityConfig.fail_secure` defaults to `True`** (inherited from `guard-core >= 3.0.0`). When any security check raises an unhandled exception, the request is blocked with HTTP 500 instead of logging and falling through. Restore the old behavior on deployments that depend on it via `SecurityConfig(fail_secure=False)`. Recommended posture: keep the new default, surface any check exceptions in your monitoring, and fix them - the alternative could mask serious bugs.
- **Added** - `SecurityMiddleware.agent_stats` read-only `@property` returning the agent's telemetry buffer state. Returns `{"enabled": False}` when no agent is wired; otherwise returns `{"enabled": True, **agent_handler.get_stats()}` exposing `events_dropped`, `metrics_dropped`, `circuit_breaker_state`, and other agent counters. No caching - fresh on each call. Lets app teams build health endpoints that surface agent-side drops and circuit-breaker trips without scraping the agent directly.
- **Added** - `from tornadoapi_guard import __version__` - package version is exported via `importlib.metadata.version("tornadoapi_guard")` with a `"0.0.0+unknown"` fallback if the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` so application code can wire the tornadoapi-guard version through to the agent for SaaS-side telemetry attribution: `SecurityConfig(agent_guard_version=__version__)`.
- **Public API** - `SecurityMiddleware.agent_stats` and `__version__` are part of the public surface from this first release.

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

- **Fixed** - `SecurityMiddleware.__init__` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` directly, using the bare `guard_agent` handler (or `None`). `middleware.initialize()` then called `HandlerInitializer.initialize_agent_integrations()` which built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were already frozen on the bare handler. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release extracts event-bus construction into `_build_event_bus_and_contexts()`, which consults `handler_initializer.composite_handler` and uses `build_event_bus()` / `build_metrics_collector()` when the composite is available. `initialize()` re-invokes `_build_event_bus_and_contexts()` after `initialize_agent_integrations()` so the dependent contexts (`ResponseContext`, `ValidationContext`, `BehavioralContext`) bind to the post-init event bus.
- **Added** - `tests/test_middleware_wiring.py` - four regression tests that pin `mw.event_bus.agent_handler` and `mw.metrics_collector.agent_handler` to `CompositeAgentHandler` after `middleware.initialize()` when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** - `guard-core>=1.1.0,<2.0.0`.
- **User-visible impact** - Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) - but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.

___

v1.0.0 (2026-04-16)
-------------------

Initial Release (v1.0.0)
------------

- **Tornado adapter layer**: `TornadoGuardRequest`, `TornadoGuardResponse`, `TornadoResponseFactory` mapping Tornado's `RequestHandler` to guard-core's protocol interface.
- **SecurityHandler**: Base handler subclass integrating guard-core's security pipeline via `prepare()` / `on_finish()` hooks.
- **SecurityMiddleware**: Full security check pipeline (17 checks) with config via `Application.settings["security_middleware"]`.
- **Public API re-exports**: All guard-core exports available through `tornadoapi_guard` for a clean import surface.
- **Example application**: Comprehensive Tornado app demonstrating IP filtering, rate limiting, behavioral analysis, security headers, decorators, and WebSocket support.
- **Full documentation**: MkDocs site with API reference, configuration guides, decorator usage, and security tutorials.
- **CI/CD**: GitHub Actions workflows for CI, CodeQL, container release, docs deployment, scheduled linting, and PyPI release.
- **Development tooling**: Pre-commit hooks, Makefile targets, Docker Compose setup, Python 3.10-3.14 support.

___

v0.0.1 (2026-04-05)
-------------------

Initial Release (v0.0.1)
------------

- **Initial project scaffolding**: Project structure matching Guard ecosystem conventions.
- **Guard-core integration**: Thin adapter over [guard-core](https://github.com/rennf93/guard-core), the framework-agnostic security engine.
- **Tornado adapters**: `TornadoGuardRequest`, `TornadoGuardResponse`, `TornadoResponseFactory` for mapping Tornado's `RequestHandler` to guard-core interfaces.
- **CI/CD pipeline**: GitHub Actions workflows for CI, release, CodeQL, docs, container release, and scheduled linting.
- **Development tooling**: Pre-commit hooks, Makefile targets, Docker Compose setup, Python 3.10-3.14 support.
