from __future__ import annotations

import pytest

import tornadoapi_guard


def test_all_symbols_present() -> None:
    for name in tornadoapi_guard.__all__:
        assert hasattr(tornadoapi_guard, name), f"Missing export: {name}"


def test_core_types_importable() -> None:
    from tornadoapi_guard import (
        BehaviorRule,
        BehaviorTracker,
        GuardRequest,
        GuardResponse,
        GuardResponseFactory,
        IPBanManager,
        RateLimitManager,
        RedisManager,
        RouteConfig,
        SecurityConfig,
        SecurityDecorator,
        SecurityHandler,
        SecurityHeadersManager,
        SecurityMiddleware,
        SecurityWebSocketHandler,
        TornadoGuardRequest,
        TornadoGuardResponse,
        TornadoResponseFactory,
        apply_guard_response,
        unwrap_response,
    )

    assert SecurityConfig is not None
    assert SecurityMiddleware is not None
    assert SecurityHandler is not None
    assert SecurityWebSocketHandler is not None
    assert TornadoGuardRequest is not None
    assert TornadoGuardResponse is not None
    assert TornadoResponseFactory is not None
    assert apply_guard_response is not None
    assert unwrap_response is not None
    assert SecurityDecorator is not None
    assert RouteConfig is not None
    assert BehaviorRule is not None
    assert BehaviorTracker is not None
    assert IPBanManager is not None
    assert RateLimitManager is not None
    assert RedisManager is not None
    assert SecurityHeadersManager is not None
    assert GuardRequest is not None
    assert GuardResponse is not None
    assert GuardResponseFactory is not None


def test_version_exported_matches_package_metadata() -> None:
    from importlib.metadata import version

    from tornadoapi_guard import __version__

    assert __version__ == version("tornadoapi_guard")
    assert __version__ != "0.0.0+unknown"


def test_version_falls_back_when_package_metadata_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib
    from importlib.metadata import PackageNotFoundError

    def _raise(name: str) -> str:
        raise PackageNotFoundError(name)

    monkeypatch.setattr("importlib.metadata.version", _raise)
    reloaded = importlib.reload(tornadoapi_guard)
    try:
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        importlib.reload(tornadoapi_guard)


def test_endpoint_rate_limit_key_problems_is_the_engines_function() -> None:
    import guard_core

    import tornadoapi_guard

    assert "endpoint_rate_limit_key_problems" in tornadoapi_guard.__all__
    assert (
        tornadoapi_guard.endpoint_rate_limit_key_problems
        is guard_core.endpoint_rate_limit_key_problems
    )
