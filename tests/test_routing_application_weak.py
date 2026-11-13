"""The middleware reads the last Application it served without keeping it alive."""

import gc
import weakref
from pathlib import Path

import tornado.web
from guard_core.models import SecurityConfig

from tests.test_middleware_unit import _make_handler
from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class _Page(SecurityHandler):
    def get(self, item_id: str) -> None:
        self.write(item_id)


def _middleware() -> SecurityMiddleware:
    return SecurityMiddleware(
        config=SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
    )


def _application(tmp_path: Path, name: str) -> tornado.web.Application:
    (tmp_path / "a.txt").write_text("x")
    return tornado.web.Application(
        [
            (rf"/{name}/(?P<item_id>[0-9]+)", _Page),
            (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": str(tmp_path)}),
        ]
    )


async def _serve(middleware: SecurityMiddleware, app: tornado.web.Application) -> None:
    handler = _make_handler()
    handler.application = app
    await middleware.run_pre_processing(handler)


async def test_the_middleware_does_not_keep_the_last_application_alive(
    tmp_path: Path,
) -> None:
    middleware = _middleware()
    app = _application(tmp_path, "items")
    await _serve(middleware, app)
    alive = weakref.ref(app)

    del app
    gc.collect()

    assert alive() is None
    await middleware.reset()


async def _assert_defaults(middleware: SecurityMiddleware) -> None:
    assert middleware.resolve_route("/items/5") == ()
    assert middleware.route_template("/items/5") is None
    assert await middleware.static_file_exists("/static/a.txt") is False
    assert middleware.static_route_prefixes() == ("/",)


async def test_every_reader_gives_its_default_before_a_request_and_after_collection(
    tmp_path: Path,
) -> None:
    middleware = _middleware()
    await _assert_defaults(middleware)

    app = _application(tmp_path, "items")
    await _serve(middleware, app)
    assert middleware.resolve_route("/items/5") != ()
    assert middleware.route_template("/items/5") is not None
    assert await middleware.static_file_exists("/static/a.txt") is True
    assert middleware.static_route_prefixes() != ("/",)

    del app
    gc.collect()
    await _assert_defaults(middleware)
    await middleware.reset()


async def test_two_applications_served_alternately_each_route_to_their_own(
    tmp_path: Path,
) -> None:
    middleware = _middleware()
    first = _application(tmp_path, "first")
    second = _application(tmp_path, "second")

    for _ in range(2):
        await _serve(middleware, first)
        assert middleware.resolve_route("/first/1") != ()
        assert middleware.resolve_route("/second/1") == ()
        await _serve(middleware, second)
        assert middleware.resolve_route("/second/1") != ()
        assert middleware.resolve_route("/first/1") == ()
    await middleware.reset()


async def test_an_unchanged_application_keeps_the_same_reference(
    tmp_path: Path,
) -> None:
    middleware = _middleware()
    app = _application(tmp_path, "items")
    await _serve(middleware, app)
    reference = middleware._routing_application
    await _serve(middleware, app)
    assert middleware._routing_application is reference
    await middleware.reset()
