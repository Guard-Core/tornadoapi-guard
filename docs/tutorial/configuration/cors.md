---

title: CORS Configuration - TornadoAPI Guard
description: Learn how to configure Cross-Origin Resource Sharing (CORS) settings in TornadoAPI Guard for secure API access
keywords: tornado cors, cors configuration, api security, cross origin resource sharing
---

CORS Configuration
==================

TornadoAPI Guard provides comprehensive CORS (Cross-Origin Resource Sharing) configuration through the `SecurityConfig` model. Unlike frameworks that ship with a standalone CORS middleware, the Tornado adapter applies CORS headers directly from the handler pipeline: whenever `enable_cors=True` is set on the config, the CORS preflight is answered from `SecurityHandler.prepare()`, and the engine response pass in `SecurityHandler.finish()` writes the CORS headers onto the response (blocked responses carry them too).

The generated headers include:

- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Allow-Credentials`
- `Access-Control-Expose-Headers`
- `Access-Control-Max-Age`

Each of these is derived from the matching field on `SecurityConfig` (`cors_allow_origins`, `cors_allow_methods`, `cors_allow_headers`, `cors_allow_credentials`, `cors_expose_headers`, `cors_max_age`).

Because the Tornado middleware has no `app.add_middleware(...)` equivalent, there is no `SecurityMiddleware.configure_cors(app, config)` helper — setting the fields on `SecurityConfig` is all you need.

___

Basic CORS Setup
-----------------

Enable CORS with permissive defaults:

```python
from tornadoapi_guard import SecurityConfig

config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["*"],
)
```

___

Advanced Configuration
----------------------

Configure specific CORS settings:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=[
        "https://example.com",
        "https://api.example.com",
    ],
    cors_allow_methods=["GET", "POST", "PUT", "DELETE"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
)
```

___

Origin Patterns
---------------

Use patterns to match multiple origins:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=[
        "https://*.example.com",
        "https://*.api.example.com",
    ],
)
```

___

Credentials Support
-------------------

Enable credentials support for authenticated requests:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_credentials=True,
    cors_allow_origins=[
        "https://app.example.com",  # Must be specific origin when using credentials
    ],
)
```

___

Custom Headers
--------------

Configure custom headers for CORS:

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Custom-Header",
    ],
    cors_expose_headers=[
        "X-Custom-Response-Header",
    ],
)
```

___

Preflight (OPTIONS) Requests
----------------------------

Tornado's `RequestHandler.options()` returns an empty `200 OK` by default. When a preflight arrives, `SecurityHandler.prepare()` runs first and the CORS headers derived from your config are already attached — which is enough for most use cases.

If you need custom preflight behavior (for example, to return extra headers or a specific body on `OPTIONS`), override `options()` on your `SecurityHandler` subclass:

```python
from tornadoapi_guard import SecurityHandler


class APIHandler(SecurityHandler):
    async def options(self, *args, **kwargs) -> None:
        self.set_status(204)
        self.finish()

    async def get(self) -> None:
        self.write({"data": "value"})
```

The CORS headers configured via `SecurityConfig` are still applied automatically — you only need to override `options()` when the default behavior is insufficient.

___

Troubleshooting
---------------

Common issues:

1. **Missing CORS headers**: Ensure `enable_cors=True` is set and the request actually carries an `Origin` header. Requests without an `Origin` header do not receive CORS headers.
2. **Credentials + wildcard origin**: Browsers reject `Access-Control-Allow-Origin: *` when credentials are enabled. Use an explicit origin list when `cors_allow_credentials=True`.
3. **Preflight failing**: Verify that the methods and headers your client sends are included in `cors_allow_methods` and `cors_allow_headers`.
4. **Security headers disabled**: CORS headers are emitted by the security headers manager. If `security_headers={"enabled": False}` is set on the config, CORS headers will not be written either.
