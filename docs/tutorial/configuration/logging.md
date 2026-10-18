---

title: Logging Configuration - TornadoAPI Guard
description: Configure security event logging and monitoring in TornadoAPI Guard with custom log formats and levels
keywords: tornado logging, security logging, event monitoring, log configuration
---

Logging Configuration
=====================

TornadoAPI Guard includes powerful logging capabilities to help you monitor and track security-related events in your application.

___

Basic Logging Setup
-------------------

TornadoAPI Guard uses a hierarchical logging namespace (`tornadoapi_guard`) with automatic console output and optional file logging:

```python
config = SecurityConfig(
    # Optional: Enable file logging by providing a path
    custom_log_file="security.log"  # Creates file + console output
    # OR
    # custom_log_file=None  # Console output only (default)
)
```

**Key Features:**

- Console output is **always enabled** for visibility
- File logging is **optional** and only enabled when `custom_log_file` is set
- All TornadoAPI Guard components use the `tornadoapi_guard.*` namespace

___

Configurable Log Levels
------------------------

TornadoAPI Guard supports different log levels for normal and suspicious requests:

```python
config = SecurityConfig(
    # Log normal requests as INFO (or set to None to disable)
    log_request_level="INFO",
    # Log suspicious activity as WARNING
    log_suspicious_level="WARNING",
)
```

Available log levels:

- `"INFO"`: Informational messages
- `"DEBUG"`: Detailed debug information
- `"WARNING"`: Warning messages (default for suspicious activity)
- `"ERROR"`: Error conditions
- `"CRITICAL"`: Critical errors
- `None`: Disable logging completely

___

Structured JSON Logging
------------------------

TornadoAPI Guard supports structured JSON log output for integration with log aggregation systems like ELK, Datadog, or CloudWatch:

```python
config = SecurityConfig(log_format="json", custom_log_file="security.log")
```

When `log_format="json"` is set, all log output (both console and file) uses structured JSON:

```json
{"timestamp": "2026-03-14 08:30:00,123", "level": "INFO", "logger": "tornadoapi_guard", "message": "Request from 192.168.1.1"}
{"timestamp": "2026-03-14 08:30:01,456", "level": "WARNING", "logger": "tornadoapi_guard", "message": "Suspicious activity detected from 10.0.0.5"}
```

The default `log_format="text"` preserves the human-readable format:

```text
[tornadoapi_guard] 2026-03-14 08:30:00 - INFO - Request from 192.168.1.1
```

___

Performance Optimization
-------------------------

For high-traffic production environments, consider disabling normal request logging:

```python
config = SecurityConfig(
    # Disable normal request logging (default)
    log_request_level=None,
    # Keep security event logging enabled
    log_suspicious_level="WARNING",
)
```

___

Custom Logger
-------------

The `setup_custom_logging` function is automatically called by the middleware during initialization:

```python
from guard_core.utils import setup_custom_logging

# Manual setup (if needed outside of middleware)
# Console only (no file)
logger = setup_custom_logging(None)

# Console + file logging
logger = setup_custom_logging("security.log")

# The logger uses the "tornadoapi_guard" namespace
# All handlers automatically use sub-namespaces like:
# - "tornadoapi_guard.handlers.redis"
# - "tornadoapi_guard.handlers.cloud"
# - "tornadoapi_guard.handlers.ipban"
```

**Note:** The function is synchronous (not async) and handles directory creation automatically.

___

Logging
-------

TornadoAPI Guard uses a unified logging approach with the `log_activity` function that handles different types of log events:

```python
from guard_core.utils import log_activity

# Log a regular request
await log_activity(request, logger)

# Log suspicious activity
await log_activity(
    request, logger, log_type="suspicious", reason="Suspicious IP address detected"
)

# Log penetration attempt in passive mode
await log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="SQL injection attempt detected",
    passive_mode=True,
    trigger_info="Detected pattern: ' OR 1=1 --",
)

# Log with specific level
await log_activity(request, logger, level="ERROR", reason="Authentication failure")
```

___

Logging Parameters
------------------

The `log_activity` function accepts the following parameters:

- `request`: The Tornado `RequestHandler.request` object (an `HTTPServerRequest`)
- `logger`: The logger instance to use
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to format log as passive mode detection
- `trigger_info`: Details about what triggered detection
- `level`: The logging level to use. If `None`, logging is disabled. Defaults to "WARNING".

___

Logger Namespace Hierarchy
---------------------------

TornadoAPI Guard uses a hierarchical namespace structure for organized logging:

```diagram
tornadoapi_guard                    # Root logger for all TornadoAPI Guard components
├── tornadoapi_guard.handlers       # Handler components
│   ├── tornadoapi_guard.handlers.redis
│   ├── tornadoapi_guard.handlers.cloud
│   ├── tornadoapi_guard.handlers.ipinfo
│   ├── tornadoapi_guard.handlers.ipban
│   ├── tornadoapi_guard.handlers.ratelimit
│   ├── tornadoapi_guard.handlers.behavior
│   ├── tornadoapi_guard.handlers.suspatterns
│   └── tornadoapi_guard.handlers.dynamic_rule
├── tornadoapi_guard.decorators     # Decorator components
│   └── tornadoapi_guard.decorators.base
└── tornadoapi_guard.detection_engine  # Detection engine components
```

This namespace isolation ensures:

- TornadoAPI Guard logs are separate from your application logs
- You can configure log levels for specific components
- Test frameworks can capture logs via propagation
- No interference with user-defined loggers

___

Log Format
----------

By default, logs include the following information:

- Timestamp
- Logger name (showing the component namespace)
- Log level
- Client IP address
- HTTP method
- Request path
- Request headers
- Request body (if available)
- Reason for logging (for suspicious activities)
- Detection trigger details (for penetration attempts)

___

Complete Examples
-----------------

Example 1: Production Setup with File Logging
----------------------------------------------

```python
import asyncio
import tornado.web
from tornadoapi_guard import SecurityConfig, SecurityHandler, SecurityMiddleware

config = SecurityConfig(
    custom_log_file="/var/log/tornadoapi-guard/security.log",
    log_request_level=None,
    log_suspicious_level="WARNING",
    enable_redis=True,
    enable_penetration_detection=True,
)
middleware = SecurityMiddleware(config=config)


class ExampleHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"status": "ok"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/", ExampleHandler)],
        security_middleware=middleware,
    )
    app.listen(8000)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```

Example 2: Development Setup with Console Only
-----------------------------------------------

```python
import asyncio
import tornado.web
from tornadoapi_guard import SecurityConfig, SecurityHandler, SecurityMiddleware

config = SecurityConfig(
    custom_log_file=None,
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    passive_mode=True,
)
middleware = SecurityMiddleware(config=config)


class ExampleHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"status": "ok"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/", ExampleHandler)],
        security_middleware=middleware,
    )
    app.listen(8000)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```

Example 3: Custom Component-Level Configuration
------------------------------------------------

```python
import logging
from tornadoapi_guard import SecurityConfig

# Configure specific component log levels
logging.getLogger("tornadoapi_guard.handlers.redis").setLevel(logging.DEBUG)
logging.getLogger("tornadoapi_guard.handlers.ipban").setLevel(logging.INFO)
logging.getLogger("tornadoapi_guard.detection_engine").setLevel(logging.WARNING)

# This works because TornadoAPI Guard uses hierarchical namespaces
config = SecurityConfig(
    custom_log_file="security.log",
    # ... other settings
)
```

Example 4: Integration with Application Logging
------------------------------------------------

```python
import asyncio
import logging
import tornado.web
from tornadoapi_guard import SecurityConfig, SecurityHandler, SecurityMiddleware

app_logger = logging.getLogger("myapp")
app_logger.setLevel(logging.INFO)

config = SecurityConfig(
    custom_log_file="security.log",
)
middleware = SecurityMiddleware(config=config)


class ExampleHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"status": "ok"})


async def main() -> None:
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/", ExampleHandler)],
        security_middleware=middleware,
    )
    app.listen(8000)
    app_logger.info("Application started")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
```
