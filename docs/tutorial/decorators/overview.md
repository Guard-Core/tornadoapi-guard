---

title: Security Decorators Overview - TornadoAPI Guard
description: Learn how to use TornadoAPI Guard's security decorators for route-level protection and fine-grained security controls
keywords: security decorators, route protection, tornado security, middleware decorators
---

Security Decorators Overview
=============================

TornadoAPI Guard's security decorators allow you to apply fine-grained security controls to individual handler methods, complementing the global middleware protection. This gives you the flexibility to customize security policies on a per-endpoint basis.

___

What are Security Decorators?
-----------------------------

Security decorators are Python decorators that you apply to the HTTP-method coroutines (`get`, `post`, `put`, `delete`, ...) on your `SecurityHandler` subclasses. They work alongside the global `SecurityMiddleware` to provide layered protection.

**Important:** Decorators must be applied to the method, not the handler class. Tornado dispatches to `get`/`post`/etc., and the middleware inspects the decorated method to read its route configuration.

```python
import asyncio

import tornado.web
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


class PublicHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "This uses global security settings"})


class RestrictedHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=5, window=300)
    @guard_deco.require_ip(whitelist=["10.0.0.0/8"])
    async def get(self) -> None:
        self.write({"message": "This has additional route-specific restrictions"})
```

___

Key Features
------------

- **Route-Level Controls**: Apply security rules to specific endpoints
- **Override Global Settings**: Route decorators can override global middleware settings
- **Stacking Support**: Combine multiple decorators for comprehensive protection
- **Behavioral Analysis**: Monitor endpoint usage patterns and detect anomalies
- **Content Filtering**: Control request types and sizes per endpoint
- **Time-Based Access**: Restrict access to specific time windows

___

Decorator Categories
--------------------

. Access Control
--------------

Control who can access your endpoints based on IP, geography, and cloud providers.

```python
class SensitiveHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["192.168.1.0/24"])
    @guard_deco.block_countries(["CN", "RU"])
    @guard_deco.block_clouds(["AWS", "GCP"])
    async def get(self) -> None:
        self.write({"data": "restricted"})
```

. Authentication & Authorization
------------------------------

Enforce authentication requirements and secure headers.

```python
class AuthenticatedHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.require_auth(type="bearer")
    @guard_deco.api_key_auth(header_name="X-API-Key")
    async def get(self) -> None:
        self.write({"data": "authenticated"})
```

. Rate Limiting
-------------

Apply custom rate limits to specific endpoints.

```python
class LimitedHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
    @guard_deco.geo_rate_limit({"US": (100, 3600), "CN": (5, 3600)})
    async def get(self) -> None:
        self.write({"data": "rate limited"})
```

. Behavioral Analysis
-------------------

Monitor and analyze user behavior patterns.

```python
class GameHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
    @guard_deco.return_monitor("win", max_occurrences=3, window=86400, action="alert")
    async def get(self) -> None:
        self.write({"result": "win", "reward": "rare_item"})
```

. Content Filtering
-----------------

Control request content and format.

```python
class UploadHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/json"])
    @guard_deco.max_request_size(1024 * 1024)  # 1MB limit
    @guard_deco.require_referrer(["myapp.com"])
    async def post(self) -> None:
        self.write({"status": "uploaded"})
```

. Advanced Features
-----------------

Time-based controls and sophisticated detection mechanisms.

```python
class AdvancedHandler(SecurityHandler):
    @guard_deco.time_window("09:00", "17:00", "UTC")  # Business hours only
    @guard_deco.suspicious_detection(enabled=True)
    @guard_deco.honeypot_detection(["bot_trap", "hidden_field"])
    async def get(self) -> None:
        self.write({"data": "advanced protection"})
```

___

Basic Setup
-----------

. Initialize the Decorator
---------------------------

Create a single `SecurityDecorator` instance at module level and register it with the middleware so the middleware can read route configurations. You also need to pass the decorator as a setting on `tornado.web.Application` so it is resolvable from handler instances.

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

# IMPORTANT: Register the decorator with the middleware so route configs are resolved.
middleware.set_decorator_handler(guard_deco)
```

. Apply Decorators to Handler Methods
-------------------------------------

```python
class LoginHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.rate_limit(requests=5, window=300)  # Stricter limit for login
    @guard_deco.suspicious_detection(enabled=True)
    async def post(self) -> None:
        self.write({"token": "jwt_token"})


class AdminHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
    @guard_deco.require_auth(type="bearer")
    @guard_deco.time_window("09:00", "17:00", "UTC")  # Business hours
    async def get(self) -> None:
        self.write({"message": "Admin access granted"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [
            (r"/api/login", LoginHandler),
            (r"/api/admin", AdminHandler),
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

Configuration Priority
----------------------

Security settings are applied in this order (highest to lowest priority):

1. Decorator Settings - Route-specific configurations
2. Global Middleware Settings - Application-wide defaults
3. Built-in Defaults - Library defaults

This allows flexible overrides where routes can customize their security while maintaining global baselines.

```python
# Global: 100 requests/hour
config = SecurityConfig(rate_limit_requests=100, rate_limit_window=3600)


class PublicHandler(SecurityHandler):
    async def get(self) -> None:
        # Uses global: 100 requests/hour
        self.write({"data": "public"})


class LimitedHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10, window=300)  # Override: 10 requests/5min
    async def get(self) -> None:
        # Uses decorator: 10 requests/5min
        self.write({"data": "limited"})
```

___

Best Practices
--------------

. Logical Decorator Order
--------------------------

Apply decorators from most specific to most general:

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

. Combine Related Decorators
-----------------------------

Group related security measures:

```python
class SecureHandler(SecurityHandler):
    # Geographic restrictions
    @guard_deco.allow_countries(["US", "CA", "GB"])
    @guard_deco.block_clouds(["AWS", "GCP"])
    # Content controls
    @guard_deco.content_type_filter(["image/jpeg", "image/png"])
    @guard_deco.max_request_size(5 * 1024 * 1024)
    # Behavioral monitoring
    @guard_deco.usage_monitor(max_calls=50, window=3600)
    @guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400)
    async def post(self) -> None:
        self.write({"status": "ok"})
```

. Error Handling
-----------------

Decorators integrate with middleware error handling:

- **403 Forbidden**: IP restrictions, country blocks, auth failures
- **429 Too Many Requests**: Rate limiting violations
- **400 Bad Request**: Content type mismatches, missing headers
- **413 Payload Too Large**: Request size exceeded

___

Next Steps
----------

Now that you understand the overview, dive deeper into specific decorator categories:

- **[Access Control](access-control.md)** - IP filtering and geographic restrictions
- **[Authentication](authentication.md)** - HTTPS, auth requirements, and API keys
- **[Rate Limiting](rate-limiting.md)** - Custom rate limits and geographic limits
- **[Behavioral Analysis](behavioral.md)** - Usage monitoring and anomaly detection
- **[Content Filtering](content-filtering.md)** - Request validation and content controls
- **[Advanced Features](advanced.md)** - Time windows and sophisticated detection

For complete API reference, see the [Security Decorators API Documentation](../../api/decorators.md).
