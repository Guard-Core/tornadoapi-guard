<p align="center">
    <a href="https://guard-core.github.io/tornadoapi-guard/latest/">
        <img src="https://guard-core.github.io/tornadoapi-guard/latest/assets/tornadoapi_guard_legend.svg" alt="TornadoAPI Guard">
    </a>
</p>

---


## Documentation

📚 **[Documentation](https://guard-core.github.io/tornadoapi-guard/latest/)** - full technical documentation for this package.

🛡️ **[Guard Core](https://guard-core.github.io/guard-core/latest/)** - the engine's reference documentation.

🤖 **[Monitoring Agent Integration](https://github.com/Guard-Core/guard-agent)** - monitor your Guard instance with a monitoring agent.
___

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

Guard Core is the Python engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols. The telemetry agents ship security events and metrics to the monitoring backend. Parallel engine implementations exist for Go, PHP, TypeScript (on npm), and Rust (on crates.io) - all ports of the same reference semantics, conformance-tested against the shared adversarial corpus.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### Go

Go modules published via GitHub releases. **Production-ready.**

| Package | Role | Release |
|---|---|---|
| [guard-core-go](https://github.com/Guard-Core/guard-core-go) | Go engine | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-core-go?label=tag)](https://github.com/Guard-Core/guard-core-go/releases) |
| [nethttp-guard](https://github.com/Guard-Core/nethttp-guard) | net/http adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/nethttp-guard?label=tag)](https://github.com/Guard-Core/nethttp-guard/releases) |
| [gin-guard](https://github.com/Guard-Core/gin-guard) | Gin adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/gin-guard?label=tag)](https://github.com/Guard-Core/gin-guard/releases) |
| [echo-guard](https://github.com/Guard-Core/echo-guard) | Echo (v4) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/echo-guard?label=tag)](https://github.com/Guard-Core/echo-guard/releases) |
| [fiber-guard](https://github.com/Guard-Core/fiber-guard) | Fiber (v3) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/fiber-guard?label=tag)](https://github.com/Guard-Core/fiber-guard/releases) |
| [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) | Telemetry agent | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-agent-go?label=tag)](https://github.com/Guard-Core/guard-agent-go/releases) |

### PHP

Published on [Packagist](https://packagist.org/) under the `rennf93` vendor. **Production-ready.**

| Package | Role | Packagist |
|---|---|---|
| [guard-core-php](https://github.com/Guard-Core/guard-core-php) | PHP engine | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-core-php)](https://packagist.org/packages/rennf93/guard-core-php) |
| [laravel-guard](https://github.com/Guard-Core/laravel-guard) | Laravel adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/laravel-guard)](https://packagist.org/packages/rennf93/laravel-guard) |
| [symfony-guard](https://github.com/Guard-Core/symfony-guard) | Symfony adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/symfony-guard)](https://packagist.org/packages/rennf93/symfony-guard) |
| [psr15-guard](https://github.com/Guard-Core/psr15-guard) | PSR-15 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/psr15-guard)](https://packagist.org/packages/rennf93/psr15-guard) |
| [slim-guard](https://github.com/Guard-Core/slim-guard) | Slim 4 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/slim-guard)](https://packagist.org/packages/rennf93/slim-guard) |
| [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) | Telemetry agent | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-agent-php)](https://packagist.org/packages/rennf93/guard-agent-php) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope; source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| | [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/@guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono (edge) adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |
| [guardagent](https://github.com/Guard-Core/guard-agent-ts) | Telemetry agent | [![npm](https://img.shields.io/npm/v/guardagent)](https://www.npmjs.com/package/guardagent) |

### Rust

Published on crates.io. **Production-ready.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core-engine](https://github.com/Guard-Core/guard-core-rs) | Core engine crate | [![crates.io](https://img.shields.io/crates/v/guard-core-engine)](https://crates.io/crates/guard-core-engine) |
| [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) | Facade crate (consumer entry point) | [![crates.io](https://img.shields.io/crates/v/guard-core-rs)](https://crates.io/crates/guard-core-rs) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix Web adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs) | Telemetry agent | [![crates.io](https://img.shields.io/crates/v/guard-agent-rs)](https://crates.io/crates/guard-agent-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp) | MCP server: config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

---

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