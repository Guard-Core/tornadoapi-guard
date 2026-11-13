---

title: Upgrading to 5.0.0 - TornadoAPI Guard
description: What changes for an existing application and its tests when guard-core 5.0.0 refuses a misconfiguration
keywords: tornadoapi guard upgrade, 5.0.0, fail_on_misconfiguration, SecurityDecorator, route id
---

Upgrading to 5.0.0
==================

___

A test app with its own `SecurityDecorator`
-------------------------------------------

guard-core 5.0.0 sets `fail_on_misconfiguration` to `True` by default, so a misconfiguration is refused instead of logged. One case shows up in test suites. A test builds an app with a `SecurityDecorator` of its own, while the routes it mounts were decorated with a different `SecurityDecorator` instance (the one the production app uses). The middleware only knows the route ids of its own decorator, so the first request raises:

```text
MisconfigurationError: 159 misconfigurations:
- Route 'app.handlers.items.ItemHandler.get' carries a route id that this SecurityDecorator does not know: it was decorated by a different SecurityDecorator instance than the one the middleware uses, so none of its decorators apply. Decorate the route with the SecurityDecorator the middleware uses.
```

The count and the route names are the app's own: one line per handler. With a single route the message has no count and carries that one line.

The fix is to build the test application the way production builds it: one `SecurityDecorator` per application, passed as the `guard_decorator` setting and used on every handler of that application. A factory that production and the tests both call does this without any test-only wiring:

```python
import tornado.web

from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
)


def create_app(config: SecurityConfig) -> tornado.web.Application:
    decorator = SecurityDecorator(config)

    class ItemHandler(SecurityHandler):
        async def get(self) -> None:
            self.write({"ok": True})

    decorator.rate_limit(requests=10, window=60)(ItemHandler.get)

    return tornado.web.Application(
        [(r"/items", ItemHandler)],
        security_middleware=SecurityMiddleware(config=config),
        guard_decorator=decorator,
    )
```

Do not set `fail_on_misconfiguration=False` to make the error go away. The message says that no decorator of those routes applies, so the test would pass while it checks nothing of what the decorators declare.
