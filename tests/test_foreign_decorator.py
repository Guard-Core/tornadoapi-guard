"""A handler stamped by a SecurityDecorator other than the one the middleware uses
is reported at the first request, and a nested Application that carries a
SecurityMiddleware of its own is left to it."""

import logging
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core._utils.route_gate import route_unknown_to_decorator_problem
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

KIND = route_unknown_to_decorator_problem("x").kind
NEED = {"X-Need": "1"}


def _config(flag: bool) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        ban_on_hostile_signals=False,
        fail_on_misconfiguration=flag,
    )


def _guarded(decorator: SecurityDecorator, name: str) -> type[SecurityHandler]:
    # A route id is the function's module and qualified name, so two decorators
    # only differ on functions with different names.
    def get(self: SecurityHandler) -> None:
        self.write("ok")

    get.__qualname__ = f"{name}.get"
    return type(
        name,
        (SecurityHandler,),
        {"get": decorator.require_headers({"X-Need": "required"})(get)},
    )


class Plain(SecurityHandler):
    def get(self) -> None:
        self.write("ok")


@pytest.fixture
async def serve() -> AsyncGenerator[Any, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(
        flag: bool, routes: Any, decorator: SecurityDecorator, middleware: Any = None
    ) -> int:
        middleware = middleware or SecurityMiddleware(config=_config(flag))
        middleware.set_decorator_handler(decorator)
        app = tornado.web.Application(routes, security_middleware=middleware)
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        return int(sockets[0].getsockname()[1])

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def _get(port: int, path: str, **headers: str) -> int:
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(
            f"http://127.0.0.1:{port}{path}", headers=headers, raise_error=False
        )
        return int(response.code)
    finally:
        client.close()


def _foreign(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if any(kind == KIND for kind, _ in r.__dict__.get("problems", ()))
    ]


def _root(flag: bool) -> tuple[SecurityConfig, SecurityDecorator]:
    config = _config(flag)
    return config, SecurityDecorator(config)


async def test_a_foreign_handler_is_refused_by_default_with_every_route(
    serve: Any,
) -> None:
    _, root = _root(True)
    other = SecurityDecorator(_config(True))
    port = await serve(
        True,
        [("/hello", _guarded(root, "Hello")), ("/pkg", _guarded(other, "Pkg"))],
        root,
    )

    assert await _get(port, "/pkg", **NEED) == 500
    assert await _get(port, "/hello", **NEED) == 500


async def test_a_foreign_handler_is_served_and_reported_once_with_the_flag_off(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _, root = _root(False)
    other = SecurityDecorator(_config(False))
    caplog.set_level(logging.WARNING)
    port = await serve(
        False,
        [("/hello", _guarded(root, "Hello")), ("/pkg", _guarded(other, "Pkg"))],
        root,
    )

    assert [await _get(port, "/pkg", **NEED) for _ in range(3)] == [200, 200, 200]
    assert await _get(port, "/hello") == 400
    assert await _get(port, "/hello", **NEED) == 200
    (record,) = _foreign(caplog)
    label = record.__dict__["problems"][0][1]
    assert str(route_unknown_to_decorator_problem(label)) in record.getMessage()


async def test_one_handler_on_two_routes_is_reported_once(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _, root = _root(False)
    handler = _guarded(SecurityDecorator(_config(False)), "Foreign")
    caplog.set_level(logging.WARNING)
    port = await serve(False, [("/a", handler), ("/b", handler)], root)

    assert await _get(port, "/a", **NEED) == 200
    assert len(_foreign(caplog)) == 1


async def test_a_handler_sharing_the_root_decorator_or_never_decorated_is_not_reported(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _, root = _root(True)
    SecurityDecorator(_config(True))
    caplog.set_level(logging.WARNING)
    port = await serve(
        True, [("/hello", _guarded(root, "Hello")), ("/plain", Plain)], root
    )

    assert await _get(port, "/hello") == 400
    assert await _get(port, "/hello", **NEED) == 200
    assert await _get(port, "/plain") == 200
    assert _foreign(caplog) == []


async def test_a_nested_application_with_its_own_guard_is_not_reported(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _, root = _root(True)
    inner_config, inner = _root(True)
    inner_middleware = SecurityMiddleware(config=inner_config)
    inner_middleware.set_decorator_handler(inner)
    nested = tornado.web.Application(
        [("/admin", _guarded(inner, "Admin"))], security_middleware=inner_middleware
    )
    caplog.set_level(logging.WARNING)
    port = await serve(
        True, [("/hello", _guarded(root, "Hello")), (r"/sub/.*", nested)], root
    )

    assert await _get(port, "/hello") == 400
    assert await _get(port, "/hello", **NEED) == 200
    assert _foreign(caplog) == []
    await inner_middleware.reset()


async def test_a_nested_application_without_a_guard_of_its_own_is_reported(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _, root = _root(False)
    nested = tornado.web.Application(
        [("/admin", _guarded(SecurityDecorator(_config(False)), "Foreign"))]
    )
    caplog.set_level(logging.WARNING)
    port = await serve(False, [("/hello", Plain), (r"/sub/.*", nested)], root)

    assert await _get(port, "/hello") == 200
    assert len(_foreign(caplog)) == 1


async def test_a_nested_application_served_by_the_same_middleware_is_still_walked(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _, root = _root(False)
    middleware = SecurityMiddleware(config=_config(False))
    nested = tornado.web.Application(
        [("/admin", _guarded(SecurityDecorator(_config(False)), "Foreign"))],
        security_middleware=middleware,
    )
    caplog.set_level(logging.WARNING)
    port = await serve(
        False, [("/hello", Plain), (r"/sub/.*", nested)], root, middleware
    )

    assert await _get(port, "/hello") == 200
    assert len(_foreign(caplog)) == 1


async def test_a_nested_application_whose_guard_has_no_decorator_is_reported(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    _, root = _root(False)
    inner_middleware = SecurityMiddleware(config=_config(False))
    nested = tornado.web.Application(
        [("/sub/admin", _guarded(root, "Admin"))], security_middleware=inner_middleware
    )
    caplog.set_level(logging.WARNING)
    port = await serve(False, [("/hello", Plain), (r"/sub/.*", nested)], root)

    assert await _get(port, "/hello") == 200
    assert len(_foreign(caplog)) == 1
    await inner_middleware.reset()


async def test_a_nested_application_whose_guard_has_no_decorator_is_refused_by_default(
    serve: Any,
) -> None:
    _, root = _root(True)
    inner_middleware = SecurityMiddleware(config=_config(True))
    nested = tornado.web.Application(
        [("/sub/admin", _guarded(root, "Admin"))], security_middleware=inner_middleware
    )
    port = await serve(True, [("/hello", Plain), (r"/sub/.*", nested)], root)

    assert await _get(port, "/hello") == 500
    await inner_middleware.reset()
