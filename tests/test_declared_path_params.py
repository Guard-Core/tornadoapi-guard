"""LEDGER 6.851: a declared detection_exclusion path param the route does not have is
logged once as a WARNING at the first request, read from the Application's rules (a
positional group has no name, so any declared name there warns). It never raises."""

import logging
from collections.abc import AsyncGenerator, Callable
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient
from tornado.routing import AnyMatches, Rule

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

LOGGER = "guard_core.models"
Routes = list[tuple[str, type[tornado.web.RequestHandler]]]
Build = Callable[[SecurityDecorator], Routes]


def _missing(template: str, name: str = "ghost") -> str:
    return (
        f"declares {name!r}, which is not in the route template {template!r}, so it "
        "exempts nothing."
    )


def _rootless(template: str, name: str = "tail") -> str:
    return (
        f"declares {name!r}, which has no literal segment before it in the route "
        f"template {template!r}: it would exempt the whole path from the probe rows, "
        "so the whole path is scanned."
    )


def build_missing(decorator: SecurityDecorator) -> Routes:
    class Item(SecurityHandler):
        @decorator.detection_exclusion(path_params={"ghost"})
        def get(self, item_id: str) -> None:
            self.write("ok")

    return [(r"/items/(?P<item_id>[0-9]+)", Item)]


def build_positional_group(decorator: SecurityDecorator) -> Routes:
    class Item(SecurityHandler):
        @decorator.detection_exclusion(path_params={"ghost"})
        def get(self, item_id: str) -> None:
            self.write("ok")

    return [(r"/pos/([0-9]+)", Item)]


def build_rootless(decorator: SecurityDecorator) -> Routes:
    class CatchAll(SecurityHandler):
        @decorator.detection_exclusion(path_params={"tail"})
        def get(self, tail: str) -> None:
            self.write("ok")

    return [(r"/(?P<tail>.*)", CatchAll)]


def build_one_handler_on_two_routes(decorator: SecurityDecorator) -> Routes:
    class Both(SecurityHandler):
        @decorator.detection_exclusion(path_params={"ghost"})
        def get(self, *args: str, **kwargs: str) -> None:
            self.write("ok")

    return [(r"/a/(?P<x>[0-9]+)", Both), (r"/b/(?P<y>[0-9]+)", Both)]


def build_valid(decorator: SecurityDecorator) -> Routes:
    class Item(SecurityHandler):
        @decorator.detection_exclusion(path_params={"item_id"})
        def get(self, item_id: str) -> None:
            self.write("ok")

    return [(r"/items/(?P<item_id>[0-9]+)", Item)]


def build_unguarded_and_empty(decorator: SecurityDecorator) -> Routes:
    class Plain(SecurityHandler):
        def get(self, x: str) -> None:
            self.write("ok")

    class Headers(SecurityHandler):
        @decorator.detection_exclusion(headers={"x-trace"})
        def get(self, y: str) -> None:
            self.write("ok")

    return [(r"/items/(?P<x>[0-9]+)", Plain), (r"/headers/(?P<y>[0-9]+)", Headers)]


class Plain(SecurityHandler):
    def get(self) -> None:
        self.write("ok")


@pytest.fixture
async def serve() -> AsyncGenerator[Any, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(build: Build, flag: bool, *, nested: bool = False) -> int:
        config = SecurityConfig(
            enable_redis=False,
            ban_on_hostile_signals=False,
            fail_on_misconfiguration=flag,
        )
        decorator = SecurityDecorator(config)
        middleware = SecurityMiddleware(config=config)
        middleware.set_decorator_handler(decorator)
        rules: list[Any] = build(decorator)
        if nested:
            rules = [
                Rule(AnyMatches(), Plain),
                ("/ok", Plain),
                (r"/inner/.*", tornado.web.Application(rules)),
            ]
        app = tornado.web.Application(rules, security_middleware=middleware)
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        return int(sockets[0].getsockname()[1])

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def _get(port: int, path: str) -> int:
    client = AsyncHTTPClient()
    try:
        response = await client.fetch(
            f"http://127.0.0.1:{port}{path}", raise_error=False
        )
        return int(response.code)
    finally:
        client.close()


def _problems(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and "@detection_exclusion" in r.getMessage()
    ]


@pytest.mark.parametrize("flag", [True, False])
@pytest.mark.parametrize(
    ("build", "path", "tail"),
    [
        (build_missing, "/items/7", _missing("/items/(?P<item_id>[0-9]+)$")),
        (build_positional_group, "/pos/7", _missing("/pos/([0-9]+)$")),
        (build_rootless, "/anything", _rootless("/(?P<tail>.*)$")),
    ],
)
async def test_the_first_request_warns_once_and_never_raises(
    serve: Any,
    flag: bool,
    build: Build,
    path: str,
    tail: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    port = await serve(build, flag)

    assert await _get(port, path) == 200
    assert await _get(port, path) == 200

    (problem,) = _problems(caplog)
    assert tail in problem


async def test_a_nested_application_is_walked(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    port = await serve(build_missing, True, nested=True)

    assert await _get(port, "/ok") == 200

    (problem,) = _problems(caplog)
    assert _missing("/items/(?P<item_id>[0-9]+)$") in problem


async def test_one_handler_on_two_routes_is_checked_per_route(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    port = await serve(build_one_handler_on_two_routes, True)

    assert await _get(port, "/a/1") == 200

    problems = _problems(caplog)
    assert len(problems) == 2
    assert any(_missing("/a/(?P<x>[0-9]+)$") in problem for problem in problems)
    assert any(_missing("/b/(?P<y>[0-9]+)$") in problem for problem in problems)


@pytest.mark.parametrize("build", [build_valid, build_unguarded_and_empty])
async def test_a_sound_declaration_reports_nothing(
    serve: Any, build: Build, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    port = await serve(build, True)

    assert await _get(port, "/items/7") == 200

    assert _problems(caplog) == []
