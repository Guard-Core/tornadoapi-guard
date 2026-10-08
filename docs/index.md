---

title: TornadoAPI Guard - Security Middleware for Tornado
description: Comprehensive security library for Tornado applications providing IP control, request logging, and penetration detection
keywords: tornado, security, middleware, python, ip control, penetration detection, cybersecurity
---

TornadoAPI Guard
================

![TornadoAPI Guard Logo](assets/tornadoapi_guard_legend.svg)

[![PyPI version](https://badge.fury.io/py/tornadoapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4)](https://badge.fury.io/py/tornadoapi-guard)
[![Release](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/release.yml/badge.svg)](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/code-ql.yml/badge.svg)](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/code-ql.yml)

[![pages-build-deployment](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages)](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/pages/pages-build-deployment)
[![Docs Update](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/docs.yml/badge.svg)](https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/docs.yml)
[![Downloads](https://pepy.tech/badge/tornadoapi-guard)](https://pepy.tech/project/tornadoapi-guard)

`tornadoapi-guard` is a comprehensive security library for Tornado applications, providing middleware to control IPs, log requests, and detect penetration attempts. It integrates seamlessly with Tornado to offer robust protection against various security threats, ensuring your application remains secure and reliable.

___

Quick Start
-----------

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
    geo_ip_handler=IPInfoManager("your_token_here"),
    enable_redis=False,
    rate_limit=100,
    auto_ban_threshold=5,
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

Example App
-----------

Inside [examples](https://github.com/Guard-Core/tornadoapi-guard/tree/master/examples), you can find a simple example app that demonstrates how to use TornadoAPI Guard. The canonical reference implementation lives in `examples/simple_app/main.py`.

___

Docker Container
----------------

You can also download the example app as a Docker container from [GitHub Container Registry](https://github.com/orgs/Guard-Core/packages/container/tornadoapi-guard-example).

```bash
# Pull the latest version
docker pull ghcr.io/guard-core/tornadoapi-guard-example:latest

# Or pull a specific version (matches library releases)
docker pull ghcr.io/guard-core/tornadoapi-guard-example:v1.0.0
```

___

Running the Example App
-----------------------

Using Docker Compose (Recommended)
-----------------------------------

The easiest way to run the example app is with Docker Compose, which automatically sets up Redis:

```bash
# Clone the repository
git clone https://github.com/Guard-Core/tornadoapi-guard.git
cd tornadoapi-guard

# Start the example app with Redis
docker compose up
```

This will start both the TornadoAPI Guard example app and Redis service. The app will be available at <http://0.0.0.0:8000>.

Using Docker Container Only
----------------------------

Alternatively, you can run just the container:

```bash
# Run with default settings
docker run --host 0.0.0.0 -p 8000:8000 ghcr.io/guard-core/tornadoapi-guard-example:latest

# Run with custom Redis connection
docker run --host 0.0.0.0 -p 8000:8000 \
 -e REDIS_URL=redis://your-redis-host:your-redis-port \
 -e REDIS_PREFIX=your-redis-prefix \
 -e IPINFO_TOKEN=your-ipinfo-token \
 ghcr.io/guard-core/tornadoapi-guard-example:latest
```

The example app includes endpoints that exercise the various security features of TornadoAPI Guard. Because Tornado does not generate OpenAPI documentation automatically, there is no `/docs` UI — see `examples/simple_app/main.py` and the [Example App tutorial](tutorial/examples/example-app.md) for the list of endpoints and their purposes.

___

Features
--------

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP.
- **Automatic IP Banning**: Automatically ban IPs after a certain number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts.
- **Custom Logging**: Log security events to a custom file.
- **CORS Configuration**: Configure CORS settings for your Tornado application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use IPInfo.io API to determine the country of an IP address.
- **Optimized Performance**: Selective loading of external resources based on configuration.
- **Flexible Storage**: Choose between Redis-backed distributed state or in-memory storage.
- **Automatic Fallback**: Seamless operation with/without Redis connection.
- **Secure Proxy Handling**: Protection against X-Forwarded-For header injection attacks.

___

Documentation
-------------

- [Installation](installation.md)
- [First Steps](tutorial/first-steps.md)
- [IP Management](tutorial/ip-management/banning.md)
- [Rate Limiting](tutorial/ip-management/rate-limiter.md)
- [API Reference](api/overview.md)
- [Redis Integration Guide](tutorial/redis-integration/caching.md)
- [Example App](tutorial/examples/example-app.md)

[Learn More in the Tutorial](tutorial/first-steps.md)
