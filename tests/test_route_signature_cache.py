"""The per-request route signature costs one check per router, not one walk per rule,
and a rule added at any depth still changes it."""

import gc
import logging
import weakref
from collections.abc import Callable
from typing import Any

import pytest
import tornado.web
from guard_core.models import SecurityConfig
from tornado.routing import PathMatches, Rule

from tests.test_declared_path_params import _get, build_valid
from tests.test_declared_path_params_flag import (
    Handlers,
    _late_route,
    _refusals,
    running,
)
from tests.test_middleware_unit import _make_handler
from tornadoapi_guard import SecurityHandler, SecurityMiddleware

__all__ = ["running"]


class _WatchedRule(Rule):
    """A rule no request matches, so only a walk of the rules reads its target."""

    def __init__(self, reads: list[int]) -> None:
        self._reads = reads
        super().__init__(PathMatches("/never"), SecurityHandler)

    @property
    def target(self) -> Any:
        self._reads.append(1)
        return self._target

    @target.setter
    def target(self, value: Any) -> None:
        self._target = value


async def test_unchanged_rules_are_walked_once_however_many_requests() -> None:
    reads: list[int] = []
    config = SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
    middleware = SecurityMiddleware(config=config)
    app = tornado.web.Application([(r"/items/(?P<item_id>[0-9]+)", SecurityHandler)])
    app.default_router.rules.insert(0, _WatchedRule(reads))
    handler = _make_handler()
    handler.application = app

    await middleware.run_pre_processing(handler)
    first = len(reads)
    for _ in range(49):
        await middleware.run_pre_processing(handler)
    await middleware.reset()

    assert first >= 1
    assert len(reads) == first


def _nested_target(app: tornado.web.Application) -> Any:
    return app.wildcard_router.rules[-1].target


def _build_nested_router(decorator: Any) -> list[Any]:
    return [Rule(PathMatches("/.*"), build_valid(decorator))]


def _build_nested_application(decorator: Any) -> list[Any]:
    inner = tornado.web.Application([(r"/x", SecurityHandler)])
    return [*build_valid(decorator), Rule(PathMatches("/.*"), inner)]


def _add_handlers(served: Handlers) -> None:
    served.app.add_handlers(r".*", _late_route(served.decorator, "ghost"))


def _add_rules_on_nested_router(served: Handlers) -> None:
    _nested_target(served.app).add_rules(_late_route(served.decorator, "ghost"))


def _add_handlers_on_nested_application(served: Handlers) -> None:
    _nested_target(served.app).add_handlers(
        r".*", _late_route(served.decorator, "ghost")
    )


def _reassign_nested_rules(served: Handlers) -> None:
    router = _nested_target(served.app)
    late = _late_route(served.decorator, "ghost")[0]
    router.rules = [*router.rules, Rule(PathMatches(late[0]), late[1])]


@pytest.mark.parametrize(
    ("build", "mutate"),
    [
        (build_valid, _add_handlers),
        (_build_nested_router, _add_rules_on_nested_router),
        (_build_nested_application, _add_handlers_on_nested_application),
        (_build_nested_router, _reassign_nested_rules),
    ],
    ids=[
        "add_handlers",
        "add_rules_on_a_nested_router",
        "add_handlers_on_a_nested_application",
        "reassigned_nested_rules",
    ],
)
async def test_a_route_added_after_the_first_request_is_seen_at_any_depth(
    running: Any,
    build: Callable[[Any], list[Any]],
    mutate: Callable[[Handlers], None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    served = await running(build, True)
    assert await _get(served.port, "/items/7") == 200
    before = served.middleware.route_template("/late/5")

    mutate(served)
    assert await _get(served.port, "/items/7") == 500

    assert served.middleware.route_template("/late/5") != before
    last = _refusals(caplog)[-1]
    assert [p.subject for p in last.problems] == ["ghost"]


async def test_a_collected_application_leaves_nothing_behind() -> None:
    config = SecurityConfig(enable_redis=False, ban_on_hostile_signals=False)
    middleware = SecurityMiddleware(config=config)
    app = tornado.web.Application([(r"/items/(?P<item_id>[0-9]+)", SecurityHandler)])
    handler = _make_handler()
    handler.application = app
    await middleware.run_pre_processing(handler)
    alive = weakref.ref(app)

    del app, handler
    middleware._routing_application = None
    gc.collect()

    assert alive() is None
    assert len(middleware._path_params_state) == 0
    await middleware.reset()
