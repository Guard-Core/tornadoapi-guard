from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

import pytest
from guard_core.exceptions import AgentPackageNotInstalledError
from guard_core.models import SecurityConfig

from tornadoapi_guard import SecurityMiddleware


def _config(**kwargs: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="0123456789abcdef",
        **kwargs,
    )


def _missing_package() -> Any:
    return patch.object(
        SecurityConfig,
        "to_agent_config",
        side_effect=AgentPackageNotInstalledError("nope"),
    )


async def test_missing_agent_package_fails_soft_with_the_adapters_install_hint(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _missing_package(), caplog.at_level(logging.ERROR):
        middleware = SecurityMiddleware(config=_config())

    assert middleware.agent_handler is None
    assert middleware.agent_degraded is True
    assert any("tornadoapi-guard[agent]" in r.message for r in caplog.records)


async def test_missing_agent_package_with_agent_strict_raises() -> None:
    config = _config(agent_strict=True)

    with _missing_package(), pytest.raises(AgentPackageNotInstalledError):
        SecurityMiddleware(config=config)


async def test_an_agent_init_failure_fires_the_on_error_hook() -> None:
    captured: list[tuple[str, BaseException, dict[str, Any]]] = []
    error = AgentPackageNotInstalledError("nope")
    config = _config(on_error=lambda s, e, c: captured.append((s, e, c)))

    with patch.object(SecurityConfig, "to_agent_config", side_effect=error):
        SecurityMiddleware(config=config)

    assert captured[0][0] == "agent_init"
    assert captured[0][1] is error


async def test_agent_stats_reports_degraded_after_an_init_failure() -> None:
    with _missing_package():
        middleware = SecurityMiddleware(config=_config())

    assert middleware.agent_stats == {"enabled": False, "degraded": True}


async def test_a_generic_agent_init_failure_fails_soft(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with (
        patch.object(
            SecurityConfig, "to_agent_config", side_effect=RuntimeError("boom")
        ),
        caplog.at_level(logging.ERROR),
    ):
        middleware = SecurityMiddleware(config=_config())

    assert middleware.agent_handler is None
    assert middleware.agent_degraded is True
    assert any("Failed to initialize Guard Agent" in r.message for r in caplog.records)
