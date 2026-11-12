import importlib.util
import json
import time
from collections.abc import AsyncGenerator
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import AsyncMock

import pytest
import redis
import tornado.httpserver
import tornado.netutil
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from tornado.httpclient import AsyncHTTPClient

from tests.redis_isolation import REDIS_PREFIX, REDIS_URL, close_redis_of

EXAMPLE_MAIN = (
    Path(__file__).resolve().parents[1] / "examples" / "simple_app" / "main.py"
)
BANNED_IP = "203.0.113.5"
WINDOWED_IP = "203.0.113.6"


def _redis_window_keys(config: Any, ip: str) -> list[str]:
    client = redis.Redis.from_url(config.redis_url, decode_responses=True)
    try:
        return sorted(client.scan_iter(f"{config.redis_prefix}rate_limit:rate:{ip}*"))
    finally:
        client.close()


def _load_simple_app(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("REDIS_PREFIX", REDIS_PREFIX)
    spec = importlib.util.spec_from_file_location("simple_app_main", EXAMPLE_MAIN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
async def example(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[tuple[str, ModuleType], None]:
    module = _load_simple_app(monkeypatch)
    app = module.build_application()
    await module.security_middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    try:
        yield f"http://127.0.0.1:{sockets[0].getsockname()[1]}", module
    finally:
        server.stop()
        await module.security_middleware.reset()
        await close_redis_of(module.security_middleware)


async def test_clear_cache_route_drops_the_bans_and_the_rate_windows(
    example: tuple[str, ModuleType],
) -> None:
    base_url, module = example
    assert module.security_config.redis_prefix != "tornadoapi_guard:"
    bans = ip_ban_manager_for(module.security_config)
    windows = module.security_middleware.rate_limit_handler
    await bans.ban_ip(BANNED_IP, 300, "test")
    windows.request_timestamps[WINDOWED_IP].append(time.time())
    assert await bans.is_ip_banned(BANNED_IP)
    assert windows.request_timestamps[WINDOWED_IP]
    await AsyncHTTPClient().fetch(base_url + "/")
    assert _redis_window_keys(module.security_config, "127.0.0.1")

    response = await AsyncHTTPClient().fetch(
        base_url + "/admin/clear-cache", method="POST", body=b"", raise_error=False
    )

    assert response.code == 200
    assert not await bans.is_ip_banned(BANNED_IP)
    assert not windows.request_timestamps.get(WINDOWED_IP)
    assert not _redis_window_keys(module.security_config, "127.0.0.1")
    assert b"geo_cache" not in response.body


async def test_unban_route_lifts_the_ban_it_names(
    example: tuple[str, ModuleType],
) -> None:
    base_url, module = example
    assert module.security_config.redis_prefix != "tornadoapi_guard:"
    bans = ip_ban_manager_for(module.security_config)
    await bans.ban_ip(BANNED_IP, 300, "test")
    assert await bans.is_ip_banned(BANNED_IP)

    response = await AsyncHTTPClient().fetch(
        base_url + "/admin/unban-ip",
        method="POST",
        body=json.dumps({"ip": BANNED_IP}),
        raise_error=False,
    )

    assert response.code == 200
    assert not await bans.is_ip_banned(BANNED_IP)
    assert json.loads(response.body)["details"]["ip"] == BANNED_IP


@pytest.mark.parametrize("garbage", ["not-an-ip", "203.0.113.0/24", "", "1.2.3.999"])
async def test_unban_route_refuses_input_that_is_not_an_ip(
    example: tuple[str, ModuleType], garbage: str
) -> None:
    base_url, _ = example
    response = await AsyncHTTPClient().fetch(
        base_url + "/admin/unban-ip",
        method="POST",
        body=json.dumps({"ip": garbage}),
        raise_error=False,
    )
    assert response.code == 400


OUTSIDER = {"X-Forwarded-For": "10.0.0.6, 10.0.0.9"}


async def _fetch(
    base_url: str, path: str, method: str = "GET", body: object = None, **kw: str
) -> int:
    response = await AsyncHTTPClient().fetch(
        base_url + path,
        method=method,
        body=None if body is None else json.dumps(body),
        headers=kw or None,
        raise_error=False,
    )
    return int(response.code)


async def test_emergency_switch_refuses_outsiders_and_keeps_the_admin(
    example: tuple[str, ModuleType],
) -> None:
    base_url, module = example
    config = module.security_config
    assert await _fetch(base_url, "/", **OUTSIDER) == 200

    assert (
        await _fetch(base_url, "/admin/emergency-mode", "PUT", {"enable": True}) == 200
    )
    assert config.emergency_mode is True
    assert await _fetch(base_url, "/", **OUTSIDER) == 503
    assert await _fetch(base_url, "/") == 200

    assert (
        await _fetch(base_url, "/admin/emergency-mode", "PUT", {"enable": False}) == 200
    )
    assert await _fetch(base_url, "/", **OUTSIDER) == 200
    assert await _fetch(base_url, "/") == 200


@pytest.mark.parametrize("body", [{"enable": "yes"}, {"enable": 1}, {}, [True]])
async def test_emergency_switch_refuses_a_body_that_is_not_a_boolean(
    example: tuple[str, ModuleType], body: object
) -> None:
    base_url, module = example
    assert await _fetch(base_url, "/admin/emergency-mode", "PUT", body) == 400
    assert module.security_config.emergency_mode is False


async def test_emergency_switch_defers_to_the_dashboard_when_dynamic_rules_are_on(
    example: tuple[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    base_url, module = example
    monkeypatch.setattr("guard_agent.GuardAgentHandler", lambda config: AsyncMock())
    config = module.security_config
    monkeypatch.setattr(config, "agent_api_key", "test-key")
    monkeypatch.setattr(config, "enable_agent", True)
    monkeypatch.setattr(config, "enable_dynamic_rules", True)
    response = await AsyncHTTPClient().fetch(
        base_url + "/admin/emergency-mode",
        method="PUT",
        body=json.dumps({"enable": True}),
        raise_error=False,
    )
    assert response.code == 409
    assert b"dashboard" in response.body
    assert config.emergency_mode is False


async def test_stats_come_from_the_engine_and_carry_no_invented_numbers(
    example: tuple[str, ModuleType],
) -> None:
    base_url, module = example
    bans = ip_ban_manager_for(module.security_config)

    async def stats() -> dict[str, Any]:
        response = await AsyncHTTPClient().fetch(base_url + "/admin/stats")
        payload: dict[str, Any] = json.loads(response.body)
        return payload

    before = await stats()
    await bans.ban_ip(BANNED_IP, 300, "test")
    after = await stats()
    await bans.unban_ip(BANNED_IP)
    lifted = await stats()

    assert BANNED_IP not in before["banned_ips"]
    assert BANNED_IP in after["banned_ips"]
    assert BANNED_IP not in lifted["banned_ips"]
    assert not {"total_requests", "blocked_requests", "suspicious_activities"} & set(
        after
    )
    assert after["active_rules"]["rate_limit"] == module.security_config.rate_limit


async def _stats(base_url: str) -> dict[str, Any]:
    response = await AsyncHTTPClient().fetch(base_url + "/admin/stats")
    payload: dict[str, Any] = json.loads(response.body)
    return payload


async def test_stats_name_redis_as_the_store_when_redis_holds_the_windows(
    example: tuple[str, ModuleType],
) -> None:
    base_url, module = example
    for _ in range(5):
        await AsyncHTTPClient().fetch(base_url + "/")
    assert _redis_window_keys(module.security_config, "127.0.0.1")

    stats = await _stats(base_url)

    assert stats["rate_limit_store"] == "redis"
    assert stats["rate_limit_windows"] is None
    assert stats["redis_prefix"] == module.security_config.redis_prefix


async def test_stats_count_the_process_windows_when_redis_is_off(
    example: tuple[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    base_url, module = example
    monkeypatch.setattr(module.security_config, "enable_redis", False)
    module.security_middleware.rate_limit_handler.request_timestamps[
        WINDOWED_IP
    ].append(time.time())

    stats = await _stats(base_url)

    assert stats["rate_limit_store"] == "memory"
    assert stats["rate_limit_windows"][WINDOWED_IP] == 1
    assert stats["redis_prefix"] is None


async def _switch(base_url: str, enable: bool) -> dict[str, Any]:
    response = await AsyncHTTPClient().fetch(
        base_url + "/admin/emergency-mode",
        method="PUT",
        body=json.dumps({"enable": enable}),
        raise_error=False,
    )
    payload: dict[str, Any] = json.loads(response.body)
    details: dict[str, Any] = payload["details"]
    return details


async def test_emergency_switch_reports_the_whitelist_entry_it_adds_and_removes(
    example: tuple[str, ModuleType],
) -> None:
    base_url, module = example
    on = await _switch(base_url, True)
    assert on["added_to_emergency_whitelist"] == ["127.0.0.1"]
    assert on["emergency_whitelist"] == ["127.0.0.1"]
    off = await _switch(base_url, False)
    assert off["removed_from_emergency_whitelist"] == ["127.0.0.1"]
    assert module.security_config.emergency_whitelist == []


async def test_emergency_switch_leaves_a_whitelist_it_did_not_extend_alone(
    example: tuple[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    base_url, module = example
    monkeypatch.setattr(module.security_config, "emergency_whitelist", ["127.0.0.1"])
    on = await _switch(base_url, True)
    off = await _switch(base_url, False)
    assert on["added_to_emergency_whitelist"] == []
    assert off["removed_from_emergency_whitelist"] == []
    assert module.security_config.emergency_whitelist == ["127.0.0.1"]
