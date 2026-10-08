<p align="center">
    <a href="https://guard-core.github.io/tornadoapi-guard/latest/">
        <img src="https://guard-core.github.io/tornadoapi-guard/latest/assets/tornadoapi_guard_legend.svg" alt="TornadoAPI Guard">
    </a>
</p>

---

**tornadoapi-guard is a security library for Tornado that provides middleware to control IPs, log requests, detect penetration attempts and more. It integrates seamlessly with Tornado to offer robust protection against various security threats. Powered by [guard-core](https://github.com/Guard-Core/guard-core).**

<p align="center">
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
    <a href="https://guard-core.github.io/tornadoapi-guard/latest/">
        <img src="https://github.com/Guard-Core/tornadoapi-guard/actions/workflows/docs.yml/badge.svg" alt="Docs">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/tornadoapi-guard?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&amp;logo=Python&amp;logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Tornado-000000.svg?style=flat&amp;logo=Tornado&amp;logoColor=white" alt="Tornado">
    <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&amp;logo=Redis&amp;logoColor=white" alt="Redis">
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/tornadoapi-guard/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

## Ecosystem

TornadoAPI Guard is the Tornado adapter for the Guard security ecosystem. Powered by `guard-core` and compatible with the shared telemetry agent. Parallel implementations exist for TypeScript (on npm) and Rust (on crates.io).

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter (this package) | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope. Source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |

### Rust

Published on crates.io. **🚧 Placeholder crates — implementation in progress.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core-rs) | Core engine | [![crates.io](https://img.shields.io/crates/v/guard-core)](https://crates.io/crates/guard-core) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |

___

Features
--------

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP.
- **Automatic IP Banning**: Automatically ban IPs after a certain number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts.
- **HTTP Security Headers**: Comprehensive security headers management (CSP, HSTS, X-Frame-Options, etc.)
- **Custom Logging**: Log security events to a custom file.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use a service like IPInfo.io API to determine the country of an IP address.
- **Distributed State Management**: (Optional) Redis integration for shared security state across instances
- **Flexible Storage**: Redis-enabled distributed storage or in-memory storage for single instance deployments

___

Installation
------------

To install `tornadoapi-guard`, use pip:

```bash
pip install tornadoapi-guard
```

___

v1.0.0 release notes
--------------------

`tornadoapi-guard` 1.0.0 ships against `guard-core >= 3.0.0` and exposes two adapter-side surfaces alongside the upstream fail-secure default.

### Upstream fail-secure default

`SecurityConfig.fail_secure` defaults to `True` (inherited from `guard-core 3.0.0`). If any security check raises an unhandled exception, the request is blocked with HTTP 500 instead of falling through. Opt out on deployments that need fail-open behavior:

```python
from tornadoapi_guard import SecurityConfig, SecurityMiddleware

config = SecurityConfig(
    fail_secure=False,
)
middleware = SecurityMiddleware(config=config)
```

The recommended migration is to keep the new default, surface check exceptions in your monitoring, and fix them at the root.

### Reading agent buffer state

`SecurityMiddleware.agent_stats` exposes the agent's live buffer drop counters and circuit-breaker state without reaching into the agent directly. Wire it into a Tornado-style health-check handler:

```python
import tornado.web
from tornadoapi_guard import SecurityMiddleware


class AgentHealthHandler(tornado.web.RequestHandler):
    async def get(self) -> None:
        middleware: SecurityMiddleware = self.application.settings["security_middleware"]
        self.write(middleware.agent_stats)
# {"enabled": True,
#  "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0, ...},
#  "transport_stats": {"circuit_breaker_state": "CLOSED", ...}}
```

When the agent is disabled or failed to initialize, the property returns `{"enabled": False}`. Read it on each scrape — it reflects live counters and is not cached.

### Wiring the package version through to the agent

```python
from tornadoapi_guard import SecurityConfig, __version__

config = SecurityConfig(
    enable_agent=True,
    agent_api_key="...",
    agent_guard_version=__version__,
)
```

`__version__` resolves via `importlib.metadata.version("tornadoapi_guard")` and falls back to `"0.0.0+unknown"` when the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` for SaaS-side telemetry attribution.

___

Quick Start
-----------

```python
import asyncio
import tornado.web
from tornadoapi_guard import SecurityConfig, SecurityHandler, SecurityMiddleware

config = SecurityConfig(
    rate_limit=100,
    auto_ban_threshold=5,
    enable_penetration_detection=True,
)
middleware = SecurityMiddleware(config=config)


class HelloHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "hello"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/", HelloHandler)],
        security_middleware=middleware,
    )
    app.listen(8000)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```

See [`examples/simple_app/main.py`](examples/simple_app/main.py) for a full reference application exercising every decorator and security feature.

___

Documentation
-------------

Full documentation is published at <https://guard-core.github.io/tornadoapi-guard/latest/>, or build locally with `make serve-docs`.

___

Development
-----------

```bash
# Install dependencies
make install-dev

# Run tests locally
make local-test

# Run linters
make lint

# Fix formatting
make fix

# Run all checks
make check-all
```

___

Contributing
------------

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

___

License
-------

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

___

Author
------

Renzo Franceschini - [contact@guard-core.com](mailto:contact@guard-core.com) .

___

Acknowledgements
----------------

- [Tornado](https://www.tornadoweb.org/)
- [guard-core](https://github.com/Guard-Core/guard-core)
- [Redis](https://redis.io/)
