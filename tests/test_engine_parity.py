"""Engine parity: the adapter routes through the engine exactly like fastapi-guard.

Real Tornado HTTP server and client, real engine bypass handler and response
factory. The metrics collector is spied on (it still runs) to prove which
responses reach the engine response pass.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import (
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
    TornadoGuardResponse,
)

security = SecurityDecorator(SecurityConfig(behavior_scan_response_body=True))
XFF_BLOCKED = {"X-Forwarded-For": "10.9.9.9"}
XFF_REMOTE = {"X-Forwarded-For": "203.0.113.9"}


class HealthHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "ok"})


class OpenHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "Echo response"})


class NoClientHandler(SecurityHandler):
    async def prepare(self) -> None:
        self.request.remote_ip = None  # type: ignore[assignment]
        await super().prepare()

    async def get(self) -> None:
        self.write({"message": "Echo response"})


class NoClientHealthHandler(NoClientHandler):
    pass


class BypassedHandler(SecurityHandler):
    @security.bypass(["all"])
    async def get(self) -> None:
        self.write({"message": "real view"})
        self.finish()


class RouteRuleHandler(SecurityHandler):
    @security.return_monitor(
        "json:message==Echo response", max_occurrences=2, window=60, action="ban"
    )
    async def get(self) -> None:
        self.write({"message": "Echo response"})


class ExplicitFinishHandler(SecurityHandler):
    async def get(self) -> None:
        self.write({"message": "explicit"})
        await self.finish()


class NonAwaitedFinishHandler(SecurityHandler):
    def get(self) -> None:
        self.write({"message": "sync finish"})
        self.finish()


class SyncBypassedHandler(SecurityHandler):
    @security.bypass(["all"])
    def get(self) -> None:
        self.finish("sync bypassed")


class StreamingHandler(SecurityHandler):
    async def get(self) -> None:
        self.write("a")
        await self.flush()
        self.write("b")


class ErrorHandler(SecurityHandler):
    async def get(self) -> None:
        raise tornado.web.HTTPError(500)


@dataclass
class Server:
    port: int
    middleware: SecurityMiddleware
    metrics: list[str] = field(default_factory=list)

    async def get(
        self, path: str, headers: dict[str, str] | None = None, method: str = "GET"
    ) -> HTTPResponse:
        return await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{self.port}{path}",
            method=method,
            headers=headers,
            raise_error=False,
            allow_nonstandard_methods=True,
        )


ServerFactory = Callable[..., Awaitable[Server]]


@pytest.fixture
async def serve() -> AsyncGenerator[ServerFactory, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def _serve(**overrides: Any) -> Server:
        base: dict[str, Any] = {
            "enable_redis": False,
            "enable_penetration_detection": False,
            "whitelist": None,
            "blacklist": ["10.9.9.9"],
            "trusted_proxies": ["127.0.0.1"],
            "exclude_paths": ["/health"],
            "security_headers": {"enabled": True},
        }
        base.update(overrides)
        middleware = SecurityMiddleware(config=SecurityConfig(**base))
        middleware.set_decorator_handler(security)
        app = tornado.web.Application(
            [
                (r"/health", HealthHandler),
                (r"/open", OpenHandler),
                (r"/noclient", NoClientHandler),
                (r"/noclient-health", NoClientHealthHandler),
                (r"/bypassed", BypassedHandler),
                (r"/route-rule", RouteRuleHandler),
                (r"/explicit", ExplicitFinishHandler),
                (r"/sync-finish", NonAwaitedFinishHandler),
                (r"/sync-bypassed", SyncBypassedHandler),
                (r"/streaming", StreamingHandler),
                (r"/error", ErrorHandler),
            ],
            security_middleware=middleware,
            guard_decorator=security,
        )
        metrics: list[str] = []
        real = middleware.metrics_collector.collect_request_metrics

        async def spy(request: Any, response_time: float, status_code: int) -> None:
            metrics.append(request.url_path)
            await real(request, response_time, status_code)

        middleware.metrics_collector.collect_request_metrics = spy  # type: ignore[method-assign]
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        return Server(sockets[0].getsockname()[1], middleware, metrics)

    yield _serve
    for server, middleware in started:
        server.stop()
        await middleware.reset()


async def test_excluded_path_reaches_view_with_scoped_checks_and_response_pass(
    serve: ServerFactory,
) -> None:
    srv = await serve()

    ok = await srv.get("/health")
    assert ok.code == 200
    assert ok.headers["X-Content-Type-Options"] == "nosniff"
    assert srv.metrics == ["/health"]

    blocked = await srv.get("/health", XFF_BLOCKED)
    assert blocked.code == 403
    assert srv.metrics == ["/health"]


async def test_no_client_address_gets_fail_secure_403_by_default(
    serve: ServerFactory,
) -> None:
    srv = await serve()

    resp = await srv.get("/noclient")

    assert resp.code == 403
    assert b"Client address could not be determined" in resp.body
    assert srv.metrics == []


async def test_no_client_address_on_excluded_path_is_scoped_not_bypassed(
    serve: ServerFactory,
) -> None:
    srv = await serve(exclude_paths=["/noclient-health"])

    resp = await srv.get("/noclient-health")

    assert resp.code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert srv.metrics == ["/noclient-health"]


async def test_no_client_address_fail_secure_false_runs_the_pipeline(
    serve: ServerFactory,
) -> None:
    srv = await serve(fail_secure=False)

    resp = await srv.get("/noclient")

    assert resp.code == 200
    assert srv.metrics == ["/noclient"]


async def test_route_bypass_reaches_real_view_and_skips_response_pass(
    serve: ServerFactory,
) -> None:
    async def modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Modified"] = "1"
        return response

    srv = await serve(custom_response_modifier=modifier)

    resp = await srv.get("/bypassed")

    assert resp.code == 200
    assert b"real view" in resp.body
    assert resp.headers["X-Modified"] == "1"
    assert srv.metrics == []
    assert "X-Content-Type-Options" not in resp.headers


async def test_blocked_request_emits_no_request_metrics(serve: ServerFactory) -> None:
    srv = await serve()

    assert (await srv.get("/open", XFF_BLOCKED)).code == 403
    assert srv.metrics == []
    assert (await srv.get("/open")).code == 200
    assert srv.metrics == ["/open"]


async def test_custom_response_modifier_reaches_the_client(
    serve: ServerFactory,
) -> None:
    async def modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Modified"] = "yes"
        return response

    srv = await serve(custom_response_modifier=modifier)

    resp = await srv.get("/open")

    assert resp.code == 200
    assert resp.headers["X-Modified"] == "yes"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


async def test_response_modifier_can_replace_the_response(
    serve: ServerFactory,
) -> None:
    async def modifier(response: GuardResponse) -> GuardResponse:
        return TornadoGuardResponse(
            status_code=201,
            headers={**response.headers, "X-Modified": "yes"},
            body=b"replaced",
        )

    srv = await serve(custom_response_modifier=modifier)

    resp = await srv.get("/open")

    assert resp.code == 201
    assert resp.headers["X-Modified"] == "yes"
    assert resp.body == b"replaced"
    assert resp.headers["Content-Length"] == "8"


async def test_explicit_finish_and_http_errors_get_the_response_pass(
    serve: ServerFactory,
) -> None:
    srv = await serve()

    explicit = await srv.get("/explicit")
    assert explicit.code == 200
    assert explicit.headers["X-Content-Type-Options"] == "nosniff"

    errored = await srv.get("/error")
    assert errored.code == 500
    assert errored.headers["X-Content-Type-Options"] == "nosniff"
    assert srv.metrics == ["/explicit", "/error"]


async def test_preflight_emits_no_request_metrics_and_carries_cors(
    serve: ServerFactory,
) -> None:
    srv = await serve(enable_cors=True, cors_allow_origins=["https://example.com"])

    resp = await srv.get(
        "/open",
        {
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
        },
        method="OPTIONS",
    )

    assert resp.code == 200
    assert resp.headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert srv.metrics == []


async def test_blocked_response_carries_cors_headers(serve: ServerFactory) -> None:
    srv = await serve(enable_cors=True, cors_allow_origins=["https://example.com"])

    resp = await srv.get("/open", {**XFF_BLOCKED, "Origin": "https://example.com"})

    assert resp.code == 403
    assert resp.headers["Access-Control-Allow-Origin"] == "https://example.com"


async def test_global_behavior_return_rule_fires_on_response_body(
    serve: ServerFactory,
) -> None:
    srv = await serve(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            {
                "rule_type": "return_pattern",
                "threshold": 2,
                "window": 60,
                "pattern": "json:message==Echo response",
                "action": "ban",
                "ban_duration": 30,
            }
        ],
    )

    codes = [(await srv.get("/open", XFF_REMOTE)).code for _ in range(5)]

    assert codes[0] == 200
    assert 403 in codes


async def test_route_return_rule_fires_on_response_body(serve: ServerFactory) -> None:
    srv = await serve(behavior_scan_response_body=True)

    codes = [(await srv.get("/route-rule", XFF_REMOTE)).code for _ in range(5)]

    assert codes[0] == 200
    assert 403 in codes


async def test_redis_unavailable_at_init_returns_503(serve: ServerFactory) -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url="redis://127.0.0.1:1",
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(config=config)
    middleware.set_decorator_handler(security)
    app = tornado.web.Application(
        [(r"/open", OpenHandler)], security_middleware=middleware
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    try:
        resp = await Server(sockets[0].getsockname()[1], middleware).get("/open")
    finally:
        server.stop()

    assert resp.code == 503
    assert resp.headers["Retry-After"] == "5"


async def test_unawaited_finish_is_idempotent_and_gets_the_response_pass(
    serve: ServerFactory,
) -> None:
    srv = await serve()

    resp = await srv.get("/sync-finish")

    assert resp.code == 200
    assert b"sync finish" in resp.body
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert srv.metrics == ["/sync-finish"]


async def test_route_bypass_of_a_sync_view_that_finishes_with_a_chunk(
    serve: ServerFactory,
) -> None:
    srv = await serve()

    resp = await srv.get("/sync-bypassed")

    assert resp.code == 200
    assert resp.body == b"sync bypassed"
    assert srv.metrics == []


async def test_streamed_response_is_observed_but_headers_are_already_sent(
    serve: ServerFactory,
) -> None:
    srv = await serve()

    resp = await srv.get("/streaming")

    assert resp.code == 200
    assert resp.body == b"ab"
    assert "X-Content-Type-Options" not in resp.headers
    assert srv.metrics == ["/streaming"]


async def test_response_modifier_can_remove_a_header(serve: ServerFactory) -> None:
    async def modifier(response: GuardResponse) -> GuardResponse:
        del response.headers["Server"]
        return response

    srv = await serve(custom_response_modifier=modifier)

    resp = await srv.get("/open")

    assert resp.code == 200
    assert "Server" not in resp.headers


async def test_response_pass_failure_still_finishes_the_response(
    serve: ServerFactory,
) -> None:
    srv = await serve()

    async def boom(_handler: Any) -> None:
        raise RuntimeError("boom")

    srv.middleware.run_post_processing = boom  # type: ignore[method-assign]

    resp = await srv.get("/open")

    assert resp.code == 200
    assert b"Echo response" in resp.body
