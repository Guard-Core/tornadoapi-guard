# AGENTS.md

Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

TornadoAPI Guard is a production-ready security library for Tornado applications that provides:

- IP control and rate limiting
- Request logging and monitoring
- Penetration attempt detection
- Security headers management
- Redis-based distributed caching
- Route-level security decorators

- **PyPI Package**: `tornadoapi_guard`
- **Import Name**: `tornadoapi_guard`
- **Python Support**: 3.10, 3.11, 3.12, 3.13, 3.14
- **Package Manager**: uv (modern Python package manager)
- **Build System**: Docker + Make

## Ecosystem Position

TornadoAPI Guard is a **thin adapter** over [guard-core](https://github.com/Guard-Core/guard-core). All security logic (models, handlers, decorators, detection engine, protocols, utilities) lives in the `guard_core` package; this repo contains only the Tornado integration layer.

```text
guard-core (engine, PyPI dependency)   <- all security logic
└── tornadoapi-guard (this repo)       <- Tornado handler/middleware adapter
    ├── fastapi-guard                  <- sibling adapter (ASGI middleware)
    ├── flaskapi-guard                 <- sibling adapter (Flask extension, sync mirror)
    └── djapi-guard                    <- sibling adapter (Django middleware, sync mirror)
```

Tornado is async, so this adapter imports `guard_core.*` directly (the Flask and Django siblings import the unasync-generated `guard_core.sync.*` mirror instead).

### Package Components

- **`tornadoapi_guard/__init__.py`** - Re-exports items from `guard_core` so users can `from tornadoapi_guard import SecurityConfig, SecurityDecorator, ...` without knowing about guard-core. Also exports `SecurityMiddleware` and `SecurityHandler`, and the adapter classes `TornadoGuardRequest`, `TornadoGuardResponse`, `TornadoResponseFactory`, `apply_guard_response`, `unwrap_response`.
- **`tornadoapi_guard/middleware.py`** - `SecurityMiddleware`, the orchestrator. It builds the `SecurityCheckPipeline` from the config, runs pre-processing (bypass handling, route resolution, the 17 checks) and post-processing (metrics, logging), applies CORS/pre-flight headers, and exposes `set_decorator_handler` so the pipeline can be derived from registered route config.
- **`tornadoapi_guard/handler.py`** - `SecurityHandler(RequestHandler)`. Wrap handler classes that should be guarded: `prepare()` runs pre-flight headers, pre-processing, CORS preflight handling, and applies a blocking response via `apply_guard_response`; `on_finish()` schedules post-processing as a background task.
- **`tornadoapi_guard/adapters.py`** - Protocol adapters bridging Tornado types to guard-core protocols: `TornadoGuardRequest` (wraps `RequestHandler` + `HTTPServerRequest`), `TornadoGuardResponse` (standalone response container), `TornadoResponseFactory`, plus `apply_guard_response()` (writes a guard response back through the handler) and `unwrap_response()`.

### Public API

All public imports go through `tornadoapi_guard`:

```python
from tornadoapi_guard import SecurityConfig, SecurityDecorator, RouteConfig
from tornadoapi_guard import IPBanManager, RateLimitManager, RedisManager
from tornadoapi_guard import GeoIPHandler, RedisHandlerProtocol
from tornadoapi_guard import SecurityHandler, SecurityMiddleware
```

### Tornado-Specific Considerations

Tornado's architecture differs from FastAPI/Starlette:

- `RequestHandler` is the main abstraction (not a separate request/response pair)
- `RequestHandler.request` gives `HTTPServerRequest`
- `RequestHandler.prepare()` is the async hook for pre-processing (security pipeline)
- `RequestHandler.on_finish()` is the post-processing hook (metrics, logging)
- No built-in response object; responses are written via `handler.write()` / `handler.finish()`
- `request.remote_ip` for client IP
- `request.headers` for headers (`HTTPHeaders`, case-insensitive)
- `request.arguments` for query params (returns bytes, needs decoding)
- `request.body` for the raw body (bytes, already available, no await needed)
- No built-in per-request state container; guard state is attached to the handler instance

## Boundary Rules

- **This repo MUST NOT** contain security logic (checks, handlers, models, detection patterns, `SecurityConfig`). Those belong in [guard-core](https://github.com/Guard-Core/guard-core); a security fix belongs upstream, not here.
- **This repo MUST** bridge Tornado native types to guard-core's `GuardRequest` / `GuardResponse` / response-factory protocols through `tornadoapi_guard/adapters.py`, and import guard-core's async tree (Tornado is async).
- **This repo MUST** keep `SecurityMiddleware` and `SecurityHandler` thin orchestrators that delegate to `SecurityCheckPipeline`; do not fork or reimplement pipeline behavior.
- **This repo MUST** re-export new guard-core public surface from `tornadoapi_guard/__init__.py` when it becomes part of the adapter's user-facing API.
- This repo should only change when:
  - The Tornado adapter layer needs updates
  - New guard-core exports need to be re-exported from `tornadoapi_guard/__init__.py`
  - Tornado-specific middleware orchestration changes

## Quick Start

```bash
# Install dependencies with uv
make install-dev

# Run tests locally
make local-test

# Start example application
make start-example

# Run linting and formatting
make fix
```

```python
import tornado.web
from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
)

config = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    enable_rate_limiting=True,
)

security_middleware = SecurityMiddleware(config=config)
security_middleware.set_decorator_handler(SecurityDecorator(config))
await security_middleware.initialize()


class ProtectedHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


app = tornado.web.Application(
    [(r"/", ProtectedHandler)],
    security_middleware=security_middleware,  # SecurityHandler reads this setting
)
```

`SecurityHandler` resolves its `SecurityMiddleware` from `self.application.settings["security_middleware"]`, so pass the middleware instance as an `Application` setting. `SecurityMiddleware(config=...)` is keyword-only, and `set_decorator_handler` wires the route decorator so the pipeline is derived from registered routes.

## Development Commands

### Package Management (uv)

- `make install` - Install core dependencies
- `make install-dev` - Install with dev dependencies
- `make lock` - Update lock file
- `make upgrade` - Upgrade lock dependencies and install
- `uv sync` - Sync dependencies from lock file
- `uv sync --extra dev` - Sync with dev extras
- `uv run <command>` - Run command in virtual environment

### Testing

- `make test` - Run tests in Docker (Python 3.10)
- `make test-all` - Test all Python versions (3.10-3.14)
- `make test-3.11` - Test specific Python version
- `make local-test` - Run tests locally with uv

### Code Quality

- `make lint` - Run all linters in Docker (ruff, mypy, vulture)
- `make fix` - Auto-fix formatting issues with ruff
- `make vulture` - Find dead code
- `make bandit` - Security scan
- `make safety` - Check dependency vulnerabilities
- `make pip-audit` - Audit dependencies
- `make radon` - Analyze code complexity
- `make xenon` - Check complexity thresholds
- `make deptry` - Analyze dependencies
- `make security` - Run all security checks (bandit, safety, pip-audit)
- `make quality` - Run all quality checks (lint, vulture, radon, xenon)
- `make check-all` - Run everything (lint, security, quality, analysis)
- `uv run ruff check tornadoapi_guard/ tests/` - Check with ruff
- `uv run ruff format tornadoapi_guard/ tests/` - Format code
- `uv run mypy tornadoapi_guard/` - Type checking

### Documentation

- `make serve-docs` - Serve MkDocs locally
- `make lint-docs` - Lint markdown files
- `make fix-docs` - Fix markdown issues

### Docker Operations

- `make start-example` - Start example app with Docker
- `make run-example` - Build and run example
- `make stop` - Stop all containers
- `make restart` - Restart services
- `make prune` - Clean Docker resources
- `make clean` - Clean Python cache files

Environment variables:

- `PYTHON_VERSION` - Python version (3.10-3.14)
- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token

Services: `tornadoapi-guard-example` (example application), `tornadoapi-guard` (test runner), `redis` (cache).

### Version Management

- `make bump-version VERSION=x.y.z` - Bump package version

## Project Structure

```text
tornadoapi-guard/
├── tornadoapi_guard/      # Adapter package (thin layer over guard-core)
│   ├── __init__.py        # Re-exports from guard_core + SecurityMiddleware/SecurityHandler
│   ├── middleware.py      # SecurityMiddleware (pipeline orchestration)
│   ├── handler.py         # SecurityHandler(RequestHandler) (prepare/on_finish hooks)
│   ├── adapters.py        # Tornado request/response protocol adapters
│   ├── .agents/skills/tornadoapi-guard/  # Package skill (SKILL.md)
│   └── py.typed           # PEP 561 marker
├── tests/                 # Test suite
├── examples/              # Example implementations
├── docs/                  # MkDocs documentation
├── Makefile              # Build automation
├── compose.yml           # Docker Compose config
├── Dockerfile            # Docker image definition
├── pyproject.toml        # Project metadata & config
├── uv.lock              # Locked dependencies
├── setup.py             # Minimal (package discovery only, no version)
└── .pre-commit-config.yaml  # Pre-commit hooks
```

### Configuration Files

- **pyproject.toml** - Project metadata and dependencies; tool configurations for ruff, mypy, pytest, vulture, bandit, radon, xenon, deptry, pymarkdown; Python 3.10+ requirement
- **uv.lock** - Locked dependency versions, updated with `make lock`
- **compose.yml / Dockerfile** - Multi-version Python support (3.10-3.14), Redis service for testing, volume mounts for development
- **.pre-commit-config.yaml** - ruff format, ruff check, mypy, vulture, bandit, safety, radon, xenon, deptry

## Technology Stack

### Core Dependencies

- **Tornado** - Async web framework and networking library
- **guard-core** - Framework-agnostic security engine (all security logic)

### Development Tools

- **uv** - Fast Python package manager
- **pytest** - Testing framework
- **pytest-asyncio** - Async test support
- **pytest-cov** - Coverage reporting
- **pytest-mock** - Mock fixtures
- **ruff** - Fast Python linter/formatter
- **mypy** - Static type checker
- **vulture** - Dead code finder
- **bandit** - Security linter
- **radon/xenon** - Complexity analysis
- **deptry** - Dependency analysis
- **pre-commit** - Git hooks
- **mkdocs** - Documentation generator
- **mkdocs-material** - MkDocs theme
- **pymarkdownlnt** - Markdown linter

## Testing Guidelines

### Running Tests

```bash
# Local testing with coverage
make local-test

# Docker testing (default Python 3.10)
make test

# Test all Python versions
make test-all

# Specific Python version
make test-3.12
```

### Test Configuration (pyproject.toml)

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
python_files = ["test_*.py"]
asyncio_default_fixture_loop_scope = "function"
addopts = "--cov=tornadoapi_guard --cov-branch --cov-report=term-missing"
markers = [
    "asyncio: mark tests as async"
]
```

Tests need a reachable Redis at `localhost:6379` (or set `REDIS_URL`).

### Run Specific Tests

```bash
# Run specific test file
REDIS_URL=redis://localhost:6379 uv run pytest tests/test_adapters.py -v

# Run with pattern matching
REDIS_URL=redis://localhost:6379 uv run pytest -k "adapter" -v
```

## Code Quality Standards

### Ruff Configuration

- Target Python 3.10+
- Selected rules: E, F, UP, B, I
- Auto-fixable issues

### MyPy Configuration

- Strict type checking enabled
- No implicit Optional
- Warn on unused configs
- Check untyped definitions

### Pre-commit Workflow

1. Automatic formatting with ruff
2. Linting checks
3. Type checking with mypy
4. Dead code detection with vulture
5. Security scanning with bandit
6. Complexity analysis with radon/xenon
7. Dependency analysis with deptry
8. All run via `uv run` commands

## Best Practices

1. **Always use uv** for package management
2. **Run tests** before committing
3. **Use Make commands** for consistency
4. **Test multiple Python versions** for compatibility
5. **Keep dependencies updated** with `make upgrade`
6. **Use type hints** and run mypy
7. **Follow ruff** formatting standards
8. **Document changes** in appropriate docs/

### Security Considerations

- This is a security library - all code must be defensive
- Validate all inputs with Pydantic
- Use Redis for distributed rate limiting
- Implement proper error handling
- Log security events appropriately
- Never expose sensitive data in logs

## Related Projects

- **guard-core** - Framework-agnostic security engine (the engine this adapter wraps): <https://github.com/Guard-Core/guard-core>
- **fastapi-guard** - FastAPI/Starlette adapter (async reference implementation): <https://github.com/Guard-Core/fastapi-guard>
- **flaskapi-guard** - Flask extension adapter (sync mirror): <https://github.com/Guard-Core/flaskapi-guard>
- **djapi-guard** - Django middleware adapter (sync mirror): <https://github.com/Guard-Core/djapi-guard>
- **guard-agent** - Telemetry and monitoring agent: <https://github.com/Guard-Core/guard-agent>
- **guard-core-mcp** - MCP server for config validation and docs search: <https://github.com/Guard-Core/guard-core-mcp>
- **guard-core-app** - SaaS platform (API, dashboard, playground): <https://github.com/Guard-Core/guard-core-app>
