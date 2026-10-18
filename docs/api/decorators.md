---

title: Security Decorators API - TornadoAPI Guard
description: API reference for managing security decorators in TornadoAPI Guard
keywords: security decorators, tornadoapi guard, security middleware, python api reference
---

Security Decorators
======================

The decorators module provides route-level security controls that can be applied to individual Tornado handler methods. These decorators offer fine-grained control over security policies on a per-route basis, complementing the global `SecurityMiddleware` security features.

The decorator implementation lives in `guard_core` and is re-exported through `tornadoapi_guard`. The API surface is identical to `fastapi-guard` — only the application pattern differs, since Tornado dispatches to handler methods instead of plain route functions.

___

Overview
---------------

Security decorators allow you to:

- Apply specific security rules to individual routes
- Override global security settings for specific endpoints
- Combine multiple security measures in a clean, readable way
- Implement behavioral analysis and monitoring per endpoint

___

Setup
-----

Create the `SecurityDecorator` once at module level and register it with the middleware before any handler is dispatched:

```python
from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
)

config = SecurityConfig()
middleware = SecurityMiddleware(config=config)
guard_deco = SecurityDecorator(config)
middleware.set_decorator_handler(guard_deco)
```

Pass both the middleware and the decorator as `Application` settings so the framework and the pipeline can resolve them:

```python
app = tornado.web.Application(
    routes,
    security_middleware=middleware,
    guard_decorator=guard_deco,
)
```

**Decorators must be applied to handler methods (`get`, `post`, `put`, ...), never to the handler class itself.**

___

Main Decorator Class
---------------

SecurityDecorator
-----------------

::: guard_core.decorators.SecurityDecorator

The main decorator class that combines all security capabilities. This is the primary class you'll use in your application.

**Example Usage:**

```python
class SensitiveHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=5, window=300)
    @guard_deco.require_ip(whitelist=["10.0.0.0/8"])
    @guard_deco.block_countries(["CN", "RU"])
    async def get(self) -> None:
        self.write({"data": "sensitive"})
```

___

Base Classes
------------

BaseSecurityDecorator
---------------------

::: guard_core.decorators.base.BaseSecurityDecorator

Base class providing core decorator functionality and route configuration management.

RouteConfig
-----------

::: guard_core.decorators.base.RouteConfig

Configuration class that stores security settings for individual routes.

___

Mixin Classes
-------------

The decorator system uses mixins to organize different types of security features:

AccessControlMixin
------------------

::: guard_core.decorators.access_control.AccessControlMixin

Provides IP-based and geographic access control decorators.

**Available Decorators:**

- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(countries=[])` - Block specific countries
- `@guard_deco.allow_countries(countries=[])` - Allow only specific countries
- `@guard_deco.block_clouds(providers=[])` - Block cloud provider IPs
- `@guard_deco.bypass(checks=[])` - Bypass specific security checks

**Example:**

```python
class AccessIPWhitelistHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
    async def get(self) -> None:
        self.write({"message": "Access granted from whitelisted IP"})
```

AuthenticationMixin
-------------------

::: guard_core.decorators.authentication.AuthenticationMixin

Provides authentication and authorization decorators.

**Available Decorators:**

- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer")` - Require authentication
- `@guard_deco.api_key_auth(header_name="X-API-Key")` - API key authentication
- `@guard_deco.require_headers(headers={})` - Require specific headers

**Example:**

```python
class AuthBearerHandler(SecurityHandler):
    @guard_deco.require_auth(type="bearer")
    async def get(self) -> None:
        self.write({"authenticated": True})
```

RateLimitingMixin
-----------------

::: guard_core.decorators.rate_limiting.RateLimitingMixin

Provides rate limiting decorators.

**Available Decorators:**

- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={})` - Geographic rate limiting

**Example:**

```python
class RateCustomLimitHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=5, window=60)
    async def get(self) -> None:
        self.write({"message": "rate limited"})
```

BehavioralMixin
---------------

::: guard_core.decorators.behavioral.BehavioralMixin

Provides behavioral analysis and monitoring decorators.

**Available Decorators:**

- `@guard_deco.usage_monitor(max_calls, window, action)` - Monitor endpoint usage
- `@guard_deco.return_monitor(pattern, max_occurrences, window, action)` - Monitor return patterns
- `@guard_deco.behavior_analysis(rules=[])` - Apply multiple behavioral rules
- `@guard_deco.suspicious_frequency(max_frequency, window, action)` - Detect suspicious frequency

**Example:**

```python
class BehaviorUsageHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=10, window=300, action="log")
    async def get(self) -> None:
        self.write({"message": "Usage monitoring active"})
```

ContentFilteringMixin
---------------------

::: guard_core.decorators.content_filtering.ContentFilteringMixin

Provides content and request filtering decorators.

**Available Decorators:**

- `@guard_deco.block_user_agents(patterns=[])` - Block user agent patterns
- `@guard_deco.content_type_filter(allowed_types=[])` - Filter content types
- `@guard_deco.max_request_size(size_bytes)` - Limit request size
- `@guard_deco.require_referrer(allowed_domains=[])` - Require specific referrers
- `@guard_deco.custom_validation(validator)` - Add custom validation logic

**Example:**

```python
class ContentJSONOnlyHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/json"])
    async def post(self) -> None:
        self.write({"message": "JSON content received"})
```

AdvancedMixin
-------------

::: guard_core.decorators.advanced.AdvancedMixin

Provides advanced detection and time-based decorators.

**Available Decorators:**

- `@guard_deco.time_window(start_time, end_time, timezone)` - Time-based access control
- `@guard_deco.suspicious_detection(enabled=True)` - Toggle suspicious pattern detection
- `@guard_deco.honeypot_detection(trap_fields=[])` - Detect bots using honeypot fields

**Example:**

```python
class AdvancedBusinessHoursHandler(SecurityHandler):
    @guard_deco.time_window(start_time="09:00", end_time="17:00", timezone="UTC")
    async def get(self) -> None:
        self.write({"message": "Access granted during business hours"})
```

___

Utility Functions
-----------------

. get_route_decorator_config
---------------------------

::: guard_core.decorators.base.get_route_decorator_config

Extract route security configuration from the current request. `SecurityMiddleware` invokes this internally via `RouteConfigResolver.get_route_config()` to read the decorator metadata attached to the currently dispatched handler method.

___

Integration with Middleware
---------------------------

The decorators work in conjunction with `SecurityMiddleware` to provide comprehensive protection:

1. **Route Configuration** — decorators attach metadata onto the handler method
2. **Middleware Processing** — `SecurityMiddleware.run_pre_processing()` reads that metadata and applies the corresponding checks
3. **Override Behavior** — route-specific settings override global middleware settings for the matched handler

**Example Integration:**

```python
import asyncio

import tornado.web
from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
)

config = SecurityConfig(
    enable_ip_banning=True,
    enable_rate_limiting=True,
    rate_limit_requests=100,
    rate_limit_window=3600,
)

middleware = SecurityMiddleware(config=config)
guard_deco = SecurityDecorator(config)
middleware.set_decorator_handler(guard_deco)


class LimitedHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10, window=300)  # Override: 10 requests/5min
    async def get(self) -> None:
        self.write({"data": "limited"})


class PublicHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"data": "public"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [
            (r"/api/limited", LimitedHandler),
            (r"/api/public", PublicHandler),
        ],
        security_middleware=middleware,
        guard_decorator=guard_deco,
    )
    app.listen(8000)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```

___

Best Practices
--------------

Decorator Order
---------------------

Apply decorators in logical order, with more specific restrictions first:

```python
class AdminSensitiveHandler(SecurityHandler):
    @guard_deco.require_https()  # Security requirement
    @guard_deco.require_auth(type="bearer")  # Authentication
    @guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Access control
    @guard_deco.rate_limit(requests=5, window=3600)  # Rate limiting
    @guard_deco.suspicious_detection(enabled=True)  # Monitoring
    async def post(self) -> None:
        self.write({"status": "admin action"})
```

Combining Behavioral Analysis
-----------------------------

Use multiple behavioral decorators for comprehensive monitoring:

```python
class RewardsHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
    @guard_deco.return_monitor(
        "rare_item", max_occurrences=3, window=86400, action="ban"
    )
    @guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="alert")
    async def get(self) -> None:
        self.write({"reward": "rare_item", "value": 1000})
```

Geographic and Cloud Controls
-----------------------------

Combine geographic and cloud provider controls:

```python
class RestrictedHandler(SecurityHandler):
    @guard_deco.allow_countries(["US", "CA", "GB"])
    @guard_deco.block_clouds(["AWS", "GCP"])
    async def get(self) -> None:
        self.write({"data": "geo-restricted"})
```

Content Filtering
--------------------

Apply content filtering for upload endpoints:

```python
class UploadHandler(SecurityHandler):
    @guard_deco.content_type_filter(["image/jpeg", "image/png"])
    @guard_deco.max_request_size(5 * 1024 * 1024)
    @guard_deco.require_referrer(["myapp.com"])
    async def post(self) -> None:
        self.write({"status": "uploaded"})
```

___

Error Handling
--------------

Decorators integrate with the middleware's error handling system. When decorator conditions are not met, appropriate HTTP responses are returned:

. 403 Forbidden
---------------------

IP restrictions, country blocks, authentication failures

. 429 Too Many Requests
---------------------

Rate limiting violations

. 400 Bad Request
---------------------

Content type mismatches, missing headers

. 413 Payload Too Large
---------------------

Request size limits exceeded

___

Configuration Priority
--------------

Security settings are applied in the following priority order:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows for flexible override behavior where routes can customize their security requirements while maintaining global defaults.
