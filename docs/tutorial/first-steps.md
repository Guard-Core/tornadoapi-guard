---

title: Getting Started with TornadoAPI Guard
description: First steps guide for implementing TornadoAPI Guard security features in your Tornado application
keywords: tornado security tutorial, tornadoapi guard setup, python security middleware
---

First Steps
===========

Let's start with a simple example that shows how to add TornadoAPI Guard to your application.

Create a Tornado application
----------------------------

First, create a new Tornado application. TornadoAPI Guard integrates via two objects: the `SecurityMiddleware` (which holds the security pipeline) and the `SecurityHandler` base class (which wires the pipeline into Tornado's `prepare`/`finish` hooks). Every handler that should be protected must inherit from `SecurityHandler`.

```python
import asyncio

import tornado.web
from tornadoapi_guard import SecurityHandler


class RootHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "Hello World"})
```

___

Configure Security Settings
----------------------------

Create a `SecurityConfig` instance with your desired settings. The configuration model is framework-agnostic and is identical to the one used in `fastapi-guard`:

```python
from tornadoapi_guard import IPInfoManager, SecurityConfig

config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required for geolocation
    db_path="data/ipinfo/country_asn.mmdb",  # Optional, default: ./data/ipinfo/country_asn.mmdb
    enable_redis=True,  # Enable Redis integration
    redis_url="redis://localhost:6379",  # Redis URL
    rate_limit=100,  # Max requests per minute
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    custom_log_file="security.log",  # Custom log file
)
```

Note: TornadoAPI Guard only loads resources as needed. The IPInfo database is only downloaded when country filtering is configured, and cloud IP ranges are only fetched when cloud provider blocking is enabled.

___

Initialize the Middleware
-------------------------

Instantiate `SecurityMiddleware` with your config and call `await middleware.initialize()` before the Tornado server starts accepting requests. `initialize()` builds the security pipeline and brings up Redis/agent integrations when enabled.

```python
from tornadoapi_guard import SecurityMiddleware

middleware = SecurityMiddleware(config=config)

async def startup() -> None:
    await middleware.initialize()
```

___

Register the Middleware with your Application
---------------------------------------------

Pass the middleware instance to `tornado.web.Application` as the `security_middleware` setting. The `SecurityHandler` base class looks up this setting to locate the middleware at request time:

```python
app = tornado.web.Application(
    [(r"/", RootHandler)],
    security_middleware=middleware,
)
```

___

Inherit from SecurityHandler
----------------------------

Every request handler that should be protected must subclass `SecurityHandler`. The base class overrides `prepare()` to run the full security pipeline (IP checks, rate limiting, penetration detection, etc.) before your method runs, and overrides `finish()` to run the response pass (metrics, behavioral return rules, security headers, CORS and your `custom_response_modifier`) before the response is flushed. If you inherit from `tornado.web.RequestHandler` directly, no security checks will run for that route.

```python
from tornadoapi_guard import SecurityHandler


class ProtectedHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"status": "ok"})
```

___

Complete Example
----------------

Here's a complete working example:

```python
import asyncio

import tornado.web
from tornadoapi_guard import (
    IPInfoManager,
    SecurityConfig,
    SecurityHandler,
    SecurityMiddleware,
)

config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    enable_redis=True,
    redis_url="redis://localhost:6379",
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    rate_limit=100,
    custom_log_file="security.log",
)

middleware = SecurityMiddleware(config=config)


class RootHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "Hello World"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/", RootHandler)],
        security_middleware=middleware,
    )
    app.listen(8000)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```

___

Run the Application
-------------------

Run your application directly with Python:

```bash
python main.py
```

Your API is now protected by TornadoAPI Guard.

___

What's Next
-----------

- Learn about [IP Management](ip-management/banning.md)
- Configure [Rate Limiting](ip-management/rate-limiter.md)
- Set up [Penetration Detection](security/penetration-detection.md)
- Learn about [Redis Integration](redis-integration/caching.md)
