from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.ipban_handler import reset_global_state
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    rate_limit_handler,
)
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig

from tests.redis_isolation import (
    REDIS_PREFIX,
    REDIS_URL,
    delete_every_key_under_the_suite_prefix,
    point_security_config_defaults_at_the_test_redis,
    refuse_connections_to_the_default_redis_port,
    refused_connections,
)
from tornadoapi_guard import SecurityMiddleware

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

point_security_config_defaults_at_the_test_redis()


@pytest.fixture(scope="session", autouse=True)
def _refuse_the_default_redis_port() -> Generator[None, None, None]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        refuse_connections_to_the_default_redis_port(monkeypatch)
        yield


@pytest.fixture(autouse=True)
def refused_redis_connections() -> Generator[list[tuple[Any, ...]], None, None]:
    refused_connections.clear()
    yield refused_connections
    attempts = list(refused_connections)
    refused_connections.clear()
    assert not attempts, f"the test connected to port 6379: {attempts}"


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    terminalreporter.write_line(
        f"redis isolation: REDIS_URL={REDIS_URL} REDIS_PREFIX={REDIS_PREFIX}"
    )


def _maybe_geo_ip() -> IPInfoManager | None:
    if not IPINFO_TOKEN:
        return None
    return IPInfoManager(IPINFO_TOKEN, None)


@pytest.fixture(autouse=True)
async def reset_state() -> AsyncGenerator[None, None]:
    await reset_global_state()
    await security_headers_manager.reset()
    original_patterns = sus_patterns_handler.patterns.copy()

    cloud_instance = cloud_handler._instance
    if cloud_instance:
        cloud_instance.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
        cloud_instance.redis_handler = None

    if IPInfoManager._instance:
        if IPInfoManager._instance.reader:
            IPInfoManager._instance.reader.close()
        IPInfoManager._instance = None

    RateLimitManager._instance = None

    yield
    sus_patterns_handler.patterns = original_patterns.copy()


@pytest.fixture(autouse=True)
async def reset_rate_limiter() -> None:
    config = SecurityConfig(geo_ip_handler=_maybe_geo_ip(), enable_redis=False)
    limiter = rate_limit_handler(config)
    await limiter.reset()


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(
        geo_ip_handler=_maybe_geo_ip(),
        enable_redis=False,
        enable_penetration_detection=False,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
    )


@pytest.fixture
async def security_middleware(
    security_config: SecurityConfig,
) -> AsyncGenerator[SecurityMiddleware, None]:
    middleware = SecurityMiddleware(config=security_config)
    await middleware.initialize()
    yield middleware
    await middleware.reset()


@pytest.fixture(autouse=True)
def redis_cleanup() -> None:
    delete_every_key_under_the_suite_prefix()
