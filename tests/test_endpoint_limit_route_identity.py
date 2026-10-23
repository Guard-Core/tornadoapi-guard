from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from typing import Any
from unittest.mock import patch

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class Login(SecurityHandler):
    def get(self) -> None:
        self.write("login")


class Base(SecurityHandler):
    def get(self) -> None:
        self.write("base")


class ChildOne(Base):
    pass


class ChildTwo(Base):
    pass


class User(SecurityHandler):
    def get(self, user_id: str) -> None:
        self.write(user_id)


class Named(SecurityHandler):
    def get(self, name: str = "") -> None:
        self.write(name)

    def post(self, name: str = "") -> None:
        self.write(name)


ROUTES: list[tuple[str, type[tornado.web.RequestHandler]]] = [
    (r"/login/?", Login),
    (r"/one", ChildOne),
    (r"/two", ChildTwo),
    (r"/users/(\d+)", User),
    (r"/named/(?P<name>[^/]+)", Named),
]


@pytest.fixture
async def serve() -> AsyncGenerator[Callable[[dict[str, tuple[int, int]]], Any], None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(limits: dict[str, tuple[int, int]], **config_options: Any) -> Any:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_rate_limiting=True,
            rate_limit=1000,
            endpoint_rate_limits=limits,
            passive_mode=False,
            **config_options,
        )
        middleware = SecurityMiddleware(config=config)
        app = tornado.web.Application(ROUTES, security_middleware=middleware)
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        return sockets[0].getsockname()[1], middleware

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def _statuses(port: int, paths: list[str]) -> list[int]:
    client = AsyncHTTPClient()
    try:
        codes = []
        for path in paths:
            response = await client.fetch(
                f"http://127.0.0.1:{port}{path}", raise_error=False
            )
            codes.append(response.code)
        return codes
    finally:
        client.close()


async def test_optional_slash_regex_shares_one_limit(serve: Any) -> None:
    port, _ = await serve({"/login": (2, 60)})

    assert await _statuses(port, ["/login", "/login/", "/login", "/login/"]) == [
        200,
        200,
        429,
        429,
    ]


async def test_inherited_get_on_two_routes_does_not_share_a_limit(serve: Any) -> None:
    port, _ = await serve({"/one": (1, 60)})

    assert await _statuses(port, ["/one", "/two", "/two", "/one"]) == [
        200,
        200,
        200,
        429,
    ]


async def test_concrete_id_key_stays_per_resource(serve: Any) -> None:
    port, _ = await serve({"/users/42": (1, 60)})

    assert await _statuses(
        port, ["/users/42", "/users/7", "/users/7", "/users/42"]
    ) == [
        200,
        200,
        200,
        429,
    ]


async def test_login_and_login_slash_keys_are_both_enforced(serve: Any) -> None:
    port, _ = await serve({"/login": (3, 60), "/login/": (1, 60)})

    assert await _statuses(port, ["/login", "/login", "/login"]) == [200, 429, 429]


async def test_key_the_router_cannot_resolve_still_limits_through_the_fallback(
    serve: Any,
) -> None:
    port, _ = await serve({"//login/.": (1, 60)}, fail_on_misconfiguration=False)

    assert await _statuses(port, ["/login", "/login"]) == [200, 429]


async def test_key_the_router_cannot_resolve_refuses_to_start_by_default(
    serve: Any,
) -> None:
    with pytest.raises(ValueError, match="has a dot segment"):
        await serve({"//login/.": (1, 60)})


async def test_resolve_route_reports_each_defined_method_with_decoded_params(
    serve: Any,
) -> None:
    port, middleware = await serve({"/login": (5, 60)})
    await _statuses(port, ["/login"])

    assert middleware.resolve_route("/named/a%2fb") == (
        ((Named, "get"), (("name", "a/b"),)),
        ((Named, "post"), (("name", "a/b"),)),
    )
    assert middleware.resolve_route("/users/42") == (((User, "get"), (("0", "42"),)),)


async def test_resolve_route_returns_nothing_for_unrouted_paths(serve: Any) -> None:
    port, middleware = await serve({"/login": (5, 60)})
    await _statuses(port, ["/login"])

    assert middleware.resolve_route("/nope") == ()


async def test_resolve_route_before_the_first_request_returns_nothing() -> None:
    middleware = SecurityMiddleware(config=SecurityConfig(enable_redis=False))

    assert middleware.resolve_route("/login") == ()


async def test_resolve_route_ignores_delegates_without_a_handler_class(
    serve: Any,
) -> None:
    port, middleware = await serve({"/login": (5, 60)})
    await _statuses(port, ["/login"])
    application = middleware._routing_application
    with patch.object(application, "find_handler", lambda request: object()):
        assert middleware.resolve_route("/login") == ()


@pytest.mark.parametrize(
    "path,handler,params",
    [
        ("/login", (Login, "get"), ()),
        ("/login/", (Login, "get"), ()),
        ("/users/5", (User, "get"), (("0", "5"),)),
        ("/named/x", (Named, "get"), (("name", "x"),)),
    ],
)
async def test_request_identity_equals_the_identity_resolve_route_returns(
    serve: Any, path: str, handler: tuple[type, str], params: Any
) -> None:
    port, middleware = await serve({path: (50, 60)})
    seen: list[Any] = []
    original = middleware._populate_guard_state

    def spy(guard_request: Any, request_handler: Any) -> None:
        original(guard_request, request_handler)
        seen.append(guard_request.state.guard_route_identity)

    with patch.object(middleware, "_populate_guard_state", spy):
        await _statuses(port, [path])

    assert seen == [(handler, params)]
    assert seen[0] in middleware.resolve_route(path)


async def test_request_identity_is_not_built_without_endpoint_limits(
    serve: Any,
) -> None:
    port, middleware = await serve({})
    seen: list[bool] = []
    original = middleware._populate_guard_state

    def spy(guard_request: Any, request_handler: Any) -> None:
        original(guard_request, request_handler)
        seen.append(hasattr(guard_request.state, "guard_route_identity"))

    with patch.object(middleware, "_populate_guard_state", spy):
        await _statuses(port, ["/login"])

    assert seen == [False]
