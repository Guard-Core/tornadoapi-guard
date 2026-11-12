import importlib.util
import json
import time
from collections.abc import AsyncGenerator
from pathlib import Path
from types import ModuleType

import pytest
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

    response = await AsyncHTTPClient().fetch(
        base_url + "/admin/clear-cache", method="POST", body=b"", raise_error=False
    )

    assert response.code == 200
    assert not await bans.is_ip_banned(BANNED_IP)
    assert not windows.request_timestamps.get(WINDOWED_IP)
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
