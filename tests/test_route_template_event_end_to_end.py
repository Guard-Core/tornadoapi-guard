"""A real request to a routed endpoint makes the security event carry the
normalised ``route_template`` (LEDGER 6.549)."""

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_agent import GuardAgentHandler
from guard_agent.models import SecurityEvent
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError

from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class ItemHandler(SecurityHandler):
    async def get(self, item_id: str) -> None:
        self.write({"id": item_id})


async def test_a_blocked_request_event_carries_the_route_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[SecurityEvent] = []

    async def record(self: GuardAgentHandler, event: SecurityEvent) -> None:
        sent.append(event)

    monkeypatch.setattr(GuardAgentHandler, "send_event", record)
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            geo_ip_handler=None,
            enable_redis=False,
            enable_agent=True,
            agent_api_key="sk-test-0123456789",
            enable_rate_limiting=False,
            enable_ip_banning=False,
            blocked_user_agents=["badbot"],
        )
    )
    await middleware.initialize()
    app = tornado.web.Application(
        [(r"/items/(?P<item_id>[0-9]+)", ItemHandler)], security_middleware=middleware
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    try:
        with pytest.raises(HTTPClientError) as refused:
            await AsyncHTTPClient().fetch(
                f"http://127.0.0.1:{port}/items/42", headers={"User-Agent": "badbot"}
            )
    finally:
        server.stop()
        await middleware.reset()

    assert refused.value.code == 403
    assert [event.endpoint for event in sent] == ["/items/42"]
    assert [event.route_template for event in sent] == ["/items/{item_id}"]
