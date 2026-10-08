---

title: Security Configuration - TornadoAPI Guard
description: Complete guide to TornadoAPI Guard's SecurityConfig model and every supported configuration field
keywords: security config, configuration, settings, tornadoapi-guard
---

Security Configuration
======================

TornadoAPI Guard configuration is provided by `SecurityConfig`, a Pydantic `BaseModel` re-exported from [guard-core](https://github.com/Guard-Core/guard-core). Every security feature — IP control, rate limiting, behavioral analysis, security headers, Redis, agent telemetry, and the detection engine — is driven by fields on this model.

___

SecurityConfig
--------------

```python
from tornadoapi_guard import SecurityConfig

config = SecurityConfig(
    rate_limit=100,
    auto_ban_threshold=5,
    enable_penetration_detection=True,
)
```

`SecurityConfig` is a plain Pydantic model. It does **not** read environment variables automatically — wire up your own loader (e.g. `os.getenv`, `pydantic-settings`, or your framework's config module) if you need env-driven configuration.

___

Core Security Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `passive_mode` | bool | False | Log-only mode — detect without blocking |
| `enable_ip_banning` | bool | True | Enable automatic and manual IP banning |
| `enable_rate_limiting` | bool | True | Enable rate limiting |
| `enable_penetration_detection` | bool | True | Enable penetration attempt detection |
| `auto_ban_threshold` | int | 10 | Number of suspicious requests before auto-ban |
| `auto_ban_duration` | int | 3600 | Ban duration in seconds |
| `enforce_https` | bool | False | Reject or redirect non-HTTPS requests |
| `exclude_paths` | list[str] | `["/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static"]` | Paths that bypass the security pipeline |

___

IP Management Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `whitelist` | list[str] \| None | None | Always-allowed IP addresses and CIDR ranges |
| `blacklist` | list[str] | `[]` | Always-blocked IP addresses and CIDR ranges |
| `trusted_proxies` | list[str] | `[]` | Proxies trusted to supply `X-Forwarded-For` |
| `trusted_proxy_depth` | int | 1 | Number of hops to trust in the proxy chain |
| `trust_x_forwarded_proto` | bool | False | Trust `X-Forwarded-Proto` for HTTPS detection |

___

Rate Limiting Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rate_limit` | int | 10 | Maximum requests allowed per window |
| `rate_limit_window` | int | 60 | Window length in seconds |
| `endpoint_rate_limits` | dict[str, tuple[int, int]] | `{}` | Per-endpoint `{path: (requests, window)}` overrides (set by dynamic rules) |

___

Geographic Settings
-------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `geo_ip_handler` | GeoIPHandler \| None | None | Custom geolocation handler implementing `GeoIPHandler` protocol |
| `whitelist_countries` | list[str] | `[]` | ISO country codes always allowed |
| `blocked_countries` | list[str] | `[]` | ISO country codes always blocked |
| `ipinfo_token` | str \| None | None | *(Deprecated)* IPInfo API token. Prefer `geo_ip_handler` |
| `ipinfo_db_path` | Path \| None | `Path("data/ipinfo/country_asn.mmdb")` | *(Deprecated)* Path to IPInfo database |

Setting `blocked_countries` or `whitelist_countries` without a `geo_ip_handler` (or a deprecated `ipinfo_token`) raises a validation error.

___

Cloud Provider Settings
-----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_cloud_providers` | set[str] \| None | None | Set of `{"AWS", "GCP", "Azure"}` to block |
| `cloud_ip_refresh_interval` | int | 3600 | Seconds between cloud IP range refreshes (60-86400) |

Only `AWS`, `GCP`, and `Azure` are recognized. Unknown provider names are filtered out by the validator.

___

User Agent Settings
-------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `blocked_user_agents` | list[str] | `[]` | Substring patterns to block in the User-Agent header |

___

Detection Engine Settings
-------------------------

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `detection_compiler_timeout` | float | 2.0 | 0.1–10.0 | Pattern compilation/execution timeout (seconds) |
| `detection_max_content_length` | int | 10000 | 1000–100000 | Maximum content length analyzed per request |
| `detection_preserve_attack_patterns` | bool | True | — | Preserve known attack patterns during truncation |
| `detection_semantic_threshold` | float | 0.7 | 0.0–1.0 | Minimum threat score for semantic detection |
| `detection_anomaly_threshold` | float | 3.0 | 1.0–10.0 | Standard deviations from mean to flag anomaly |
| `detection_slow_pattern_threshold` | float | 0.1 | 0.01–1.0 | Execution time to flag a pattern as slow (seconds) |
| `detection_monitor_history_size` | int | 1000 | 100–10000 | Number of performance metrics kept in history |
| `detection_max_tracked_patterns` | int | 1000 | 100–5000 | Maximum patterns tracked for performance stats |

See the full [Detection Engine Configuration Guide](../security/detection-engine/configuration.md) for tuning details.

___

Redis Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_redis` | bool | True | Enable Redis-backed distributed state |
| `redis_url` | str \| None | `"redis://localhost:6379"` | Redis connection URL |
| `redis_prefix` | str | `"guard_core:"` | Prefix for all Redis keys |

___

Agent Settings
--------------

Guard Agent is an optional telemetry and dynamic-rule SaaS platform.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_agent` | bool | False | Enable Guard Agent integration |
| `agent_api_key` | str \| None | None | SaaS API key (required when `enable_agent=True`) |
| `agent_endpoint` | str | `"https://api.guard-core.com"` | SaaS endpoint URL |
| `agent_project_id` | str \| None | None | Project ID for organizing telemetry |
| `agent_buffer_size` | int | 100 | Events buffered before auto-flush |
| `agent_flush_interval` | int | 30 | Seconds between automatic buffer flushes |
| `agent_enable_events` | bool | True | Send security events to the SaaS platform |
| `agent_enable_metrics` | bool | True | Send performance metrics to the SaaS platform |
| `agent_timeout` | int | 30 | HTTP request timeout (seconds) |
| `agent_retry_attempts` | int | 3 | Retry attempts for failed requests |
| `enable_dynamic_rules` | bool | False | Accept dynamic rule updates from the SaaS platform |
| `dynamic_rule_interval` | int | 300 | Seconds between dynamic rule polls |

Setting `enable_agent=True` without `agent_api_key` raises a validation error. Setting `enable_dynamic_rules=True` without `enable_agent=True` also raises.

Install the agent package separately (framework-agnostic; the legacy `fastapi-guard-agent` meta-package still works):

=== "uv"

    ```bash
    uv add guard-agent
    ```

=== "poetry"

    ```bash
    poetry add guard-agent
    ```

=== "pip"

    ```bash
    pip install guard-agent
    ```

___

Emergency Mode
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `emergency_mode` | bool | False | Lockdown — block all requests except those on `emergency_whitelist` |
| `emergency_whitelist` | list[str] | `[]` | IPs allowed during emergency mode |

Emergency mode is typically toggled at runtime through dynamic rules, but can also be set at construction for drills.

___

Security Headers Settings
-------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `security_headers` | dict[str, Any] \| None | See below | Security headers configuration (see nested fields) |

Default value:

```python
{
    "enabled": True,
    "hsts": {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": False,
    },
    "csp": None,
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "1; mode=block",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": None,
}
```

Sub-field reference:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | True | Enable or disable all security headers |
| `hsts.max_age` | int | 31536000 | `Strict-Transport-Security` max-age in seconds |
| `hsts.include_subdomains` | bool | True | Include `includeSubDomains` in HSTS |
| `hsts.preload` | bool | False | Include `preload` in HSTS |
| `csp` | dict[str, list[str]] \| None | None | Content Security Policy directives |
| `frame_options` | str | `"SAMEORIGIN"` | `X-Frame-Options` (`DENY` \| `SAMEORIGIN`) |
| `content_type_options` | str | `"nosniff"` | `X-Content-Type-Options` |
| `xss_protection` | str | `"1; mode=block"` | `X-XSS-Protection` |
| `referrer_policy` | str | `"strict-origin-when-cross-origin"` | `Referrer-Policy` |
| `permissions_policy` | str | `"geolocation=(), microphone=(), camera=()"` | `Permissions-Policy` |
| `custom` | dict[str, str] \| None | None | Additional custom headers applied to every response |

Headers are applied automatically by `SecurityHandler.prepare()` via `SecurityMiddleware.apply_pre_flight_headers()` — no extra wiring required.

___

CORS Settings
-------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_cors` | bool | False | Enable CORS response headers |
| `cors_allow_origins` | list[str] | `["*"]` | Origins allowed in the `Access-Control-Allow-Origin` header |
| `cors_allow_methods` | list[str] | `["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]` | Methods allowed |
| `cors_allow_headers` | list[str] | `["*"]` | Headers allowed |
| `cors_allow_credentials` | bool | False | Include `Access-Control-Allow-Credentials: true` |
| `cors_expose_headers` | list[str] | `[]` | Headers exposed to the browser |
| `cors_max_age` | int | 600 | `Access-Control-Max-Age` in seconds |

See [CORS Configuration](cors.md) for how Tornado's handler lifecycle differs from ASGI frameworks when handling CORS.

___

Logging Settings
----------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `custom_log_file` | str \| None | None | Path to a custom log file. `None` means stderr only |
| `log_request_level` | str \| None | None | Log level for incoming requests (`INFO`, `DEBUG`, `WARNING`, `ERROR`, `CRITICAL`). `None` disables request logging |
| `log_suspicious_level` | str \| None | `"WARNING"` | Log level for suspicious requests |
| `log_format` | Literal["text", "json"] | `"text"` | Log output format |

See [Logging Configuration](logging.md) for formatters, handlers, and custom filters.

___

Custom Hooks
------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `custom_request_check` | async callable \| None | None | Additional per-request check. Signature: `async (GuardRequest) -> GuardResponse \| None` |
| `custom_response_modifier` | async callable \| None | None | Mutate responses before they're sent. Signature: `async (GuardResponse) -> GuardResponse` |
| `custom_error_responses` | dict[int, str] | `{}` | Custom body text for specific HTTP status codes |

See [Adapters API](../../api/adapters.md) for a worked example using `TornadoGuardResponse` inside a `custom_request_check`.

___

Usage Example
-------------

```python
from tornadoapi_guard import SecurityConfig

config = SecurityConfig(
    passive_mode=False,
    enable_penetration_detection=True,
    auto_ban_threshold=5,
    auto_ban_duration=3600,
    whitelist=["127.0.0.1", "10.0.0.0/8"],
    blacklist=["192.168.100.0/24"],
    trusted_proxies=["127.0.0.1", "10.0.0.0/8"],
    trusted_proxy_depth=2,
    rate_limit=100,
    rate_limit_window=60,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    blocked_user_agents=["badbot", "sqlmap"],
    enable_redis=True,
    redis_url="redis://localhost:6379",
    redis_prefix="myapp:",
    enable_cors=True,
    cors_allow_origins=["https://example.com"],
    cors_allow_credentials=True,
    security_headers={
        "enabled": True,
        "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False},
        "frame_options": "DENY",
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
        },
    },
    exclude_paths=["/health", "/metrics"],
    custom_log_file="security.log",
    log_request_level="INFO",
    log_format="json",
)
```

___

Validation
----------

`SecurityConfig` enforces several validators at construction time:

- `whitelist` and `blacklist` entries must be valid IPs or CIDR ranges.
- `trusted_proxies` entries must be valid IPs or CIDR ranges.
- `trusted_proxy_depth` must be at least 1.
- `block_cloud_providers` is filtered to the known set `{"AWS", "GCP", "Azure"}`.
- `blocked_countries` or `whitelist_countries` requires a `geo_ip_handler` (or a deprecated `ipinfo_token`).
- `enable_agent=True` requires `agent_api_key`.
- `enable_dynamic_rules=True` requires `enable_agent=True`.
- `detection_*` fields are clamped to their documented ranges.

Validation errors raise `pydantic.ValidationError` at construction time.

___

Environment Variables
---------------------

`SecurityConfig` itself does not read environment variables — guard-core does not ship a `BaseSettings` subclass. Users who want env-driven configuration can wrap it:

```python
import os

from tornadoapi_guard import SecurityConfig


def load_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=bool(os.getenv("REDIS_URL")),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
        redis_prefix=os.getenv("REDIS_PREFIX", "tornadoapi_guard:"),
        enable_agent=os.getenv("GUARD_AGENT_ENABLED") == "true",
        agent_api_key=os.getenv("GUARD_AGENT_API_KEY"),
        auto_ban_threshold=int(os.getenv("GUARD_AUTO_BAN_THRESHOLD", "10")),
    )
```

Or use [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) to build a settings wrapper that composes `SecurityConfig`.

___

See Also
--------

- [SecurityMiddleware](../../api/security-middleware.md) — how to register the config with a Tornado Application
- [SecurityHandler](../../api/security-handler.md) — base handler that runs the guard pipeline
- [Adapters API](../../api/adapters.md) — custom request/response hook examples
- [Detection Engine Configuration](../security/detection-engine/configuration.md) — detection engine tuning
- [Logging Configuration](logging.md) — log formatting and handlers
- [CORS Configuration](cors.md) — CORS handling in Tornado
