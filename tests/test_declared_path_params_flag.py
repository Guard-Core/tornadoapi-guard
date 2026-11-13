"""fail_on_misconfiguration governs the first-request report of a declared
detection_exclusion path param, and the kind travels with every report."""

import logging
import pathlib
from collections.abc import AsyncGenerator, Iterable
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core._misconfiguration_kinds import MisconfigurationError, Problem
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.models import SecurityConfig
from tornado.routing import Rule

import tornadoapi_guard
from tests.test_declared_path_params import (
    LOGGER,
    Build,
    Routes,
    _get,
    _missing,
    _problems,
    _rootless,
    build_missing,
    build_positional_group,
    build_rootless,
    serve,
)
from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware

__all__ = ["serve"]

CASES = [
    (build_missing, "/items/7", _missing("/items/(?P<item_id>[0-9]+)$")),
    (build_positional_group, "/pos/7", _missing("/pos/([0-9]+)$")),
    (build_rootless, "/anything", _rootless("/(?P<tail>.*)$")),
]


def _refusals(caplog: pytest.LogCaptureFixture) -> list[MisconfigurationError]:
    return [
        record.exc_info[1]
        for record in caplog.records
        if record.exc_info is not None
        and isinstance(record.exc_info[1], MisconfigurationError)
    ]


@pytest.mark.parametrize(("build", "path", "tail"), CASES)
async def test_with_the_flag_on_the_first_request_refuses_instead_of_warning(
    serve: Any,
    build: Build,
    path: str,
    tail: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    port = await serve(build, True)

    assert await _get(port, path) == 500

    [refusal] = _refusals(caplog)
    assert tail in str(refusal)


async def test_with_the_flag_on_every_request_refuses_while_the_problem_stands(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    port = await serve(build_missing, True)

    assert [await _get(port, "/items/7") for _ in range(2)] == [500, 500]
    assert len(_refusals(caplog)) == 2


async def test_the_refusal_carries_the_kind_and_the_declared_name(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    port = await serve(build_missing, True)

    await _get(port, "/items/7")

    [refusal] = _refusals(caplog)
    assert [(p.kind, p.subject) for p in refusal.problems] == [
        ("decorator.detection_exclusion.param_not_in_template", "ghost")
    ]


async def test_with_the_flag_off_the_warning_carries_its_kind_and_the_request_is_served(
    serve: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    port = await serve(build_missing, False)

    assert await _get(port, "/items/7") == 200
    assert await _get(port, "/items/7") == 200

    assert len(_problems(caplog)) == 1
    carried = [
        r.__dict__["problems"] for r in caplog.records if "problems" in r.__dict__
    ]
    assert (
        ("decorator.detection_exclusion.param_not_in_template", "ghost"),
    ) in carried


def test_the_adapter_holds_no_copy_of_the_engine_text() -> None:
    root = pathlib.Path(tornadoapi_guard.__file__).parent
    assert not [
        p.name
        for p in root.rglob("*.py")
        if "@detection_exclusion(path_params=...) on route" in p.read_text()
    ]


class Handlers:
    """A served Application the test can add routes to after it has started."""

    def __init__(
        self,
        port: int,
        app: tornado.web.Application,
        decorator: SecurityDecorator,
        middleware: SecurityMiddleware,
    ) -> None:
        self.port = port
        self.app = app
        self.decorator = decorator
        self.middleware = middleware


@pytest.fixture
async def running() -> AsyncGenerator[Any, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def start(
        build: Build,
        flag: bool,
        *,
        fail_secure: bool = True,
        passive_mode: bool = False,
    ) -> Handlers:
        config = SecurityConfig(
            enable_redis=False,
            ban_on_hostile_signals=False,
            fail_on_misconfiguration=flag,
            fail_secure=fail_secure,
            passive_mode=passive_mode,
        )
        decorator = SecurityDecorator(config)
        middleware = SecurityMiddleware(config=config)
        middleware.set_decorator_handler(decorator)
        app = tornado.web.Application(build(decorator), security_middleware=middleware)
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        return Handlers(int(sockets[0].getsockname()[1]), app, decorator, middleware)

    yield start
    for server, middleware in started:
        server.stop()
        await middleware.reset()


def _late_route(
    decorator: SecurityDecorator, name: str
) -> list[tuple[str, type[tornado.web.RequestHandler]]]:
    class Late(SecurityHandler):
        @decorator.detection_exclusion(path_params={name})
        def get(self, late_id: str) -> None:
            self.write("ok")

    return [(r"/late/(?P<late_id>[0-9]+)", Late)]


def _depth(error: BaseException) -> int:
    depth, trace = 0, error.__traceback__
    while trace is not None:
        depth, trace = depth + 1, trace.tb_next
    return depth


async def test_three_refusals_are_three_distinct_errors_of_equal_traceback_depth(
    running: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    served = await running(build_missing, True)

    for _ in range(3):
        assert await _get(served.port, "/items/7") == 500

    refusals = _refusals(caplog)
    assert len({id(error) for error in refusals}) == 3
    assert len({_depth(error) for error in refusals}) == 1


async def test_a_failing_application_is_walked_again_only_when_its_rules_change(
    running: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import tornadoapi_guard._declared_path_params as module

    walks: list[int] = []
    real = module.declared_path_param_problems

    def counting(
        application: tornado.web.Application, decorator: BaseSecurityDecorator | None
    ) -> list[Problem]:
        walks.append(1)
        return real(application, decorator)

    monkeypatch.setattr(module, "declared_path_param_problems", counting)
    caplog.set_level(logging.WARNING)
    served = await running(build_missing, True)

    for _ in range(3):
        await _get(served.port, "/items/7")
    assert len(walks) == 1

    served.app.add_handlers(r".*", _late_route(served.decorator, "ghost"))
    await _get(served.port, "/items/7")
    await _get(served.port, "/items/7")

    assert len(walks) == 2


async def test_a_late_broken_route_joins_the_refusal_of_a_failing_application(
    running: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    served = await running(build_missing, True)
    await _get(served.port, "/items/7")

    served.app.add_handlers(r".*", _late_route(served.decorator, "phantom"))
    await _get(served.port, "/items/7")

    last = _refusals(caplog)[-1]
    assert sorted(p.subject or "" for p in last.problems) == ["ghost", "phantom"]


async def test_a_route_added_after_a_clean_check_warns_with_the_flag_off(
    running: Any, caplog: pytest.LogCaptureFixture
) -> None:
    from tests.test_declared_path_params import build_valid

    caplog.set_level(logging.WARNING, logger=LOGGER)
    served = await running(build_valid, False)
    assert await _get(served.port, "/items/7") == 200
    assert _problems(caplog) == []

    served.app.add_handlers(r".*", _late_route(served.decorator, "ghost"))
    assert await _get(served.port, "/late/5") == 200
    assert await _get(served.port, "/late/5") == 200

    assert len(_problems(caplog)) == 1


async def test_one_rule_count_per_request_is_shared_with_the_route_template(
    running: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tornadoapi_guard.middleware as module

    counts: list[int] = []
    real = module._rule_count

    def counting(rules: Iterable[Rule]) -> int:
        counts.append(1)
        return real(rules)

    monkeypatch.setattr(module, "_rule_count", counting)
    served = await running(build_valid_for_count, False)

    await _get(served.port, "/items/7")
    first = len(counts)
    await _get(served.port, "/items/7")

    assert len(counts) - first == first
    assert first >= 1


def build_valid_for_count(decorator: SecurityDecorator) -> Routes:
    from tests.test_declared_path_params import build_valid

    return build_valid(decorator)


async def test_the_reporter_walks_the_application_itself_when_it_is_given_no_problems(
    running: Any, caplog: pytest.LogCaptureFixture
) -> None:
    from tornadoapi_guard._declared_path_params import report_declared_path_params

    served = await running(build_missing, False)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    report_declared_path_params(served.middleware.config, served.app, served.decorator)

    assert len(_problems(caplog)) == 1


@pytest.mark.parametrize(
    ("fail_secure", "passive_mode"),
    [(True, False), (False, False), (True, True)],
    ids=["fail_secure", "fail_open", "passive"],
)
async def test_the_refusal_is_a_500_and_the_endpoint_never_runs(
    running: Any, fail_secure: bool, passive_mode: bool
) -> None:
    ran: list[str] = []

    def build(decorator: SecurityDecorator) -> Routes:
        class Item(SecurityHandler):
            @decorator.detection_exclusion(path_params={"ghost"})
            def get(self, item_id: str) -> None:
                ran.append(item_id)
                self.write("ok")

        return [(r"/items/(?P<item_id>[0-9]+)", Item)]

    served = await running(
        build, True, fail_secure=fail_secure, passive_mode=passive_mode
    )

    codes = [await _get(served.port, "/items/7") for _ in range(3)]

    assert codes == [500, 500, 500]
    assert ran == []
