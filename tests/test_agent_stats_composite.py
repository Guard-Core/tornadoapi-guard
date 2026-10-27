import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import JsonValue

from tornadoapi_guard import SecurityMiddleware


class _StatsAgentStub:
    def __init__(self) -> None:
        self.stats: dict[str, JsonValue] = {"buffer_stats": {"events_dropped": 3}}

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def flush_buffer(self) -> None: ...

    async def send_event(self, event: object) -> None: ...

    async def send_metric(self, metric: object) -> None: ...

    async def initialize_redis(self, redis_handler: object) -> None: ...

    async def get_dynamic_rules(self) -> None:
        return None

    async def get_status(self) -> None:
        return None

    async def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, JsonValue]:
        return self.stats


async def test_agent_stats_answers_after_the_composite_handler_is_swapped_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = _StatsAgentStub()
    monkeypatch.setitem(
        sys.modules, "guard_agent", SimpleNamespace(guard_agent=lambda _cfg: stub)
    )
    config = SecurityConfig(enable_agent=True, agent_api_key="x", enable_redis=False)
    with patch.object(SecurityConfig, "to_agent_config", return_value=object()):
        middleware = SecurityMiddleware(config=config)
    assert middleware.agent_handler is stub

    await middleware.initialize()

    assert middleware.agent_handler is not stub
    stats = middleware.agent_stats
    assert stats["enabled"] is True
    assert stats["buffer_stats"] == {"events_dropped": 3}
