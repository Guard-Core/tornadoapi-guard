from __future__ import annotations

from collections.abc import AsyncGenerator
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from tornado.web import RequestHandler

from tornadoapi_guard import SecurityMiddleware
from tornadoapi_guard.adapters import TornadoGuardRequest, get_guard_state


class _StampedEndpoint:
    __module__ = "tests.test_middleware_unit"
    __qualname__ = "stamped_endpoint"

    def __init__(self, route_id: str) -> None:
        self._guard_route_id = route_id

    def __call__(self) -> None:
        return None


class _FakeHandler:
    def __init__(
        self,
        request: object,
        application: object,
    ) -> None:
        self.request = request
        self.application = application
        self._headers_store: dict[str, str] = {}

    def set_header(self, name: str, value: str) -> None:
        self._headers_store[name] = value


def _make_handler(
    *,
    method: str = "GET",
    path: str = "/test",
    remote_ip: str = "10.0.0.1",
    headers: dict[str, str] | None = None,
    settings: dict[str, object] | None = None,
    endpoint_attr: str = "get",
    endpoint_value: object | None = None,
) -> RequestHandler:
    from tornado.httputil import HTTPHeaders

    http_headers = HTTPHeaders()
    for n, v in (headers or {}).items():
        http_headers.add(n, v)

    request = SimpleNamespace(
        method=method,
        path=path,
        protocol="http",
        remote_ip=remote_ip,
        headers=http_headers,
        body=b"",
        query_arguments={},
        full_url=lambda: f"http://localhost{path}",
    )
    application = SimpleNamespace(settings=settings or {})
    handler = _FakeHandler(request=request, application=application)
    if endpoint_value is not None:
        setattr(handler, endpoint_attr, endpoint_value)
    return cast(RequestHandler, handler)


@pytest.fixture
async def simple_middleware() -> AsyncGenerator[SecurityMiddleware, None]:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    yield middleware
    await middleware.reset()


async def test_init_with_redis_enabled() -> None:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=True,
        redis_url="redis://localhost:6379",
        redis_prefix="test_init",
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(config=config)
    assert middleware.redis_handler is not None


async def test_init_with_blocked_countries_sets_geoip() -> None:
    geo = MagicMock()
    config = SecurityConfig(
        geo_ip_handler=geo,
        enable_redis=False,
        enable_penetration_detection=False,
        blocked_countries=["CN"],
    )
    middleware = SecurityMiddleware(config=config)
    assert middleware.geo_ip_handler is geo


async def test_init_with_agent_missing_package_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "guard_agent", None)
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        enable_agent=True,
        agent_api_key="sk-test",
    )
    monkeypatch.setattr(
        SecurityConfig,
        "to_agent_config",
        lambda self: object(),
        raising=False,
    )
    middleware = SecurityMiddleware(config=config)
    assert middleware.agent_handler is None


async def test_init_with_agent_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    import types as _types

    sentinel = object()

    def _ok(_cfg: object) -> object:
        return sentinel

    fake = _types.SimpleNamespace(guard_agent=_ok)
    monkeypatch.setitem(sys.modules, "guard_agent", fake)

    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        enable_agent=True,
        agent_api_key="sk-test",
    )
    monkeypatch.setattr(
        SecurityConfig,
        "to_agent_config",
        lambda self: object(),
        raising=False,
    )
    middleware = SecurityMiddleware(config=config)
    assert middleware.agent_handler is sentinel


async def test_init_with_agent_init_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    import types as _types

    def _raise(_cfg: object) -> object:
        raise RuntimeError("boom")

    fake = _types.SimpleNamespace(guard_agent=_raise)
    monkeypatch.setitem(sys.modules, "guard_agent", fake)

    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        enable_agent=True,
        agent_api_key="sk-test",
    )
    monkeypatch.setattr(
        SecurityConfig,
        "to_agent_config",
        lambda self: object(),
        raising=False,
    )
    middleware = SecurityMiddleware(config=config)
    assert middleware.agent_handler is None


async def test_init_with_agent_invalid_config_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        enable_agent=True,
        agent_api_key="sk-test",
    )
    monkeypatch.setattr(
        SecurityConfig, "to_agent_config", lambda self: None, raising=False
    )
    middleware = SecurityMiddleware(config=config)
    assert middleware.agent_handler is None


async def test_configure_security_headers_none() -> None:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        security_headers=None,
    )
    SecurityMiddleware(config=config)
    assert security_headers_manager.enabled is False


async def test_configure_security_headers_disabled() -> None:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        security_headers={"enabled": False},
    )
    SecurityMiddleware(config=config)
    assert security_headers_manager.enabled is False


async def test_guard_response_factory_property(
    simple_middleware: SecurityMiddleware,
) -> None:
    assert simple_middleware.guard_response_factory is not None


async def test_set_decorator_handler(simple_middleware: SecurityMiddleware) -> None:
    decorator = MagicMock()
    simple_middleware.set_decorator_handler(decorator)
    assert simple_middleware.guard_decorator is decorator
    assert simple_middleware.handler_initializer.guard_decorator is decorator


async def test_check_time_window_helper(
    simple_middleware: SecurityMiddleware,
) -> None:
    result = await simple_middleware._check_time_window({})
    assert result is True


async def test_check_route_ip_access_helper(
    simple_middleware: SecurityMiddleware,
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["10.0.0.1"]
    result = await simple_middleware._check_route_ip_access("10.0.0.1", route_config)
    assert result is True


async def test_check_user_agent_allowed_helper(
    simple_middleware: SecurityMiddleware,
) -> None:
    result = await simple_middleware._check_user_agent_allowed(
        "Mozilla/5.0", RouteConfig()
    )
    assert result is True


async def test_populate_guard_state_with_decorator_and_endpoint(
    simple_middleware: SecurityMiddleware,
) -> None:
    decorator = MagicMock()
    simple_middleware.set_decorator_handler(decorator)

    endpoint = _StampedEndpoint("route-42")
    handler = _make_handler(endpoint_value=endpoint)
    guard_request = TornadoGuardRequest(handler)
    simple_middleware._populate_guard_state(guard_request, handler)
    assert guard_request.state.guard_decorator is decorator
    assert guard_request.state.guard_route_id == "route-42"


async def test_populate_guard_state_endpoint_missing(
    simple_middleware: SecurityMiddleware,
) -> None:
    handler = _make_handler()
    guard_request = TornadoGuardRequest(handler)
    simple_middleware._populate_guard_state(guard_request, handler)
    assert not hasattr(guard_request.state, "guard_route_id")


async def test_run_pre_processing_no_client_host_is_fail_secure_403(
    simple_middleware: SecurityMiddleware,
) -> None:
    handler = _make_handler(remote_ip="")
    result = await simple_middleware.run_pre_processing(handler)
    assert result is not None
    assert result.status_code == 403


async def test_run_pre_processing_lazy_builds_pipeline() -> None:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(config=config)
    pre_pipeline = middleware.security_pipeline
    handler = _make_handler(remote_ip="")
    await middleware.run_pre_processing(handler)
    assert pre_pipeline is None
    assert middleware.security_pipeline is not None
    await middleware.reset()


async def test_run_pre_processing_blocking_with_cors_origin() -> None:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=False,
        blacklist=["10.0.0.1"],
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
    )
    middleware = SecurityMiddleware(config=config)
    await middleware.initialize()
    handler = _make_handler(
        remote_ip="10.0.0.1",
        headers={"origin": "https://example.com"},
    )
    blocking = await middleware.run_pre_processing(handler)
    assert blocking is not None
    assert blocking.status_code == 403
    await middleware.reset()


async def test_run_pre_processing_triggers_usage_rules(
    simple_middleware: SecurityMiddleware,
) -> None:
    from guard_core.handlers.behavior_handler import BehaviorRule

    decorator = MagicMock()
    decorator.get_route_config = MagicMock()
    route_config = RouteConfig()
    route_config.behavior_rules = [BehaviorRule(rule_type="usage", threshold=1)]
    decorator.get_route_config.return_value = route_config
    simple_middleware.set_decorator_handler(decorator)

    endpoint = _StampedEndpoint("route-x")
    handler = _make_handler(endpoint_value=endpoint)
    with patch.object(
        simple_middleware.behavioral_processor, "process_usage_rules", new=AsyncMock()
    ) as mock_rules:
        await simple_middleware.run_pre_processing(handler)
        mock_rules.assert_awaited()


async def test_run_post_processing_without_request(
    simple_middleware: SecurityMiddleware,
) -> None:
    handler = _make_handler()
    await simple_middleware.run_post_processing(handler)


async def test_run_post_processing_with_request(
    simple_middleware: SecurityMiddleware,
) -> None:
    import time

    handler = _make_handler()
    guard_request = TornadoGuardRequest(handler)
    state = get_guard_state(handler)
    state.guard_request = guard_request
    state.route_config = None
    state.request_start_time = time.time()

    from tornado.httputil import HTTPHeaders

    response_handler = MagicMock()
    response_handler._headers = HTTPHeaders()
    response_handler._write_buffer = [b"body"]
    response_handler.get_status = MagicMock(return_value=200)
    await simple_middleware.run_post_processing(response_handler)


async def test_refresh_cloud_ip_ranges_no_providers(
    simple_middleware: SecurityMiddleware,
) -> None:
    await simple_middleware.refresh_cloud_ip_ranges()
    assert simple_middleware.last_cloud_ip_refresh == 0


async def test_refresh_cloud_ip_ranges_sync_path(
    simple_middleware: SecurityMiddleware,
) -> None:
    simple_middleware.config.block_cloud_providers = {"AWS"}
    with patch.object(cloud_handler, "refresh", new=AsyncMock()) as mock_refresh:
        await simple_middleware.refresh_cloud_ip_ranges()
        mock_refresh.assert_awaited_once()
    assert simple_middleware.last_cloud_ip_refresh > 0


async def test_refresh_cloud_ip_ranges_redis_path() -> None:
    config = SecurityConfig(
        geo_ip_handler=None,
        enable_redis=True,
        redis_url="redis://localhost:6379",
        redis_prefix="test_cloud",
        enable_penetration_detection=False,
        block_cloud_providers={"AWS"},
    )
    middleware = SecurityMiddleware(config=config)
    with patch.object(cloud_handler, "refresh_async", new=AsyncMock()) as mock_async:
        await middleware.refresh_cloud_ip_ranges()
        mock_async.assert_awaited()
    await middleware.reset()


async def test_create_error_response(
    simple_middleware: SecurityMiddleware,
) -> None:
    response = await simple_middleware.create_error_response(404, "not found")
    assert response.status_code == 404


async def test_initialize_is_idempotent(
    simple_middleware: SecurityMiddleware,
) -> None:
    pipeline_before = simple_middleware.security_pipeline
    await simple_middleware.initialize()
    assert simple_middleware.security_pipeline is pipeline_before
