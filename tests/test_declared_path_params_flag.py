"""fail_on_misconfiguration governs the first-request report of a declared
detection_exclusion path param, and the kind travels with every report."""

import logging
import pathlib
from typing import Any

import pytest
from guard_core._misconfiguration_kinds import MisconfigurationError

import tornadoapi_guard
from tests.test_declared_path_params import (
    LOGGER,
    Build,
    _get,
    _missing,
    _problems,
    _rootless,
    build_missing,
    build_positional_group,
    build_rootless,
    serve,
)

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
