"""Production-shaped TornadoAPI Guard example: nginx edge, trusted proxies,
admin-token-protected utilities, and health endpoints for orchestration."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import tornado.httpserver
import tornado.ioloop
import tornado.web
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
    TornadoGuardResponse,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _json_dumps(payload: dict[str, Any]) -> str:
    def _default(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError(f"{type(value).__name__} is not JSON serializable")

    return json.dumps(payload, default=_default)


class JSONHandler(SecurityHandler):
    def write_json(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self.set_status(status_code)
        self.set_header("Content-Type", "application/json; charset=utf-8")
        self.write(_json_dumps(payload))

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        self.set_header("Content-Type", "application/json; charset=utf-8")
        # Static reason phrase lookup: never reflect request-derived text
        reason = tornado.httputil.responses.get(status_code, "error")
        self.finish(
            _json_dumps(
                {
                    "detail": reason,
                    "error_code": f"HTTP_{status_code}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )


_REDIS_URL = os.getenv("REDIS_URL", "")
_ENABLE_REDIS = bool(_REDIS_URL)
_ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin-token-change-me")


async def reject_debug(request: GuardRequest) -> GuardResponse | None:
    if request.query_params.get("debug") == "true":
        return TornadoGuardResponse(
            status_code=403,
            headers={"Content-Type": "application/json; charset=utf-8"},
            body=_json_dumps({"detail": "Debug mode not allowed"}).encode("utf-8"),
        )
    return None


security_config = SecurityConfig(
    trusted_proxies=["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12"],
    trusted_proxy_depth=1,
    trust_x_forwarded_proto=True,
    enable_rate_limiting=True,
    rate_limit=int(os.getenv("RATE_LIMIT", "30")),
    rate_limit_window=int(os.getenv("RATE_LIMIT_WINDOW", "60")),
    enable_ip_banning=True,
    auto_ban_threshold=int(os.getenv("AUTO_BAN_THRESHOLD", "5")),
    auto_ban_duration=int(os.getenv("AUTO_BAN_DURATION", "300")),
    enable_penetration_detection=True,
    log_format="json",
    enable_redis=_ENABLE_REDIS,
    redis_url=_REDIS_URL or "redis://localhost:6379",
    redis_prefix=os.getenv("REDIS_PREFIX", "tornadoapi_guard:"),
    enforce_https=False,
    exclude_paths=["/health", "/ready"],
    passive_mode=False,
    custom_request_check=reject_debug,
)

security_middleware = SecurityMiddleware(config=security_config)
guard_decorator = SecurityDecorator(security_config)
security_middleware.set_decorator_handler(guard_decorator)


class RootHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json(
            {
                "message": "TornadoAPI Guard advanced example",
                "details": {
                    "topology": "nginx edge -> tornado app",
                    "routes": {
                        "/health": "Liveness (guard-excluded)",
                        "/ready": "Readiness (guard-excluded)",
                        "/rate/strict": "Strict per-route rate limit",
                        "/admin/check": "Admin-token-protected utility",
                    },
                },
            }
        )


class HealthHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json({"status": "healthy"})


class ReadyHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json({"status": "ready"})


class RateStrictHandler(JSONHandler):
    @guard_decorator.rate_limit(requests=5, window=60)
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Strict rate limit endpoint",
                "details": {"limit": "5 requests per 60 seconds"},
            }
        )


class AdminCheckHandler(JSONHandler):
    @guard_decorator.require_headers({"X-Admin-Token": _ADMIN_TOKEN})
    async def get(self) -> None:
        # No request-derived values in the response: forwarded headers are
        # attacker-controlled and must not be reflected back.
        self.write_json(
            {
                "message": "Admin check passed",
                "details": {"timestamp": datetime.now(timezone.utc)},
            }
        )


def build_application() -> tornado.web.Application:
    handlers: list[tuple[str, type[tornado.web.RequestHandler]]] = [
        (r"/", RootHandler),
        (r"/health", HealthHandler),
        (r"/ready", ReadyHandler),
        (r"/rate/strict", RateStrictHandler),
        (r"/admin/check", AdminCheckHandler),
    ]
    return tornado.web.Application(
        handlers,
        security_middleware=security_middleware,
        guard_decorator=guard_decorator,
        default_handler_class=JSONHandler,
    )


async def main() -> None:
    logger.info("TornadoAPI Guard advanced example starting up...")
    await security_middleware.initialize()
    app = build_application()
    server = tornado.httpserver.HTTPServer(app)
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    server.listen(port, address=host)
    logger.info("Listening on http://%s:%s", host, port)
    try:
        await asyncio.Event().wait()
    finally:
        logger.info("TornadoAPI Guard advanced example shutting down...")
        server.stop()
        await security_middleware.reset()


if __name__ == "__main__":
    asyncio.run(main())
