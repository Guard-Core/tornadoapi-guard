from __future__ import annotations

import asyncio
import gc
import os
import uuid
import warnings

import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tests.redis_isolation import suite_redis_prefix
from tornadoapi_guard import SecurityHandler, SecurityMiddleware

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")


class _Page(SecurityHandler):
    async def get(self) -> None:
        self.write({"ok": True})


def _app() -> tornado.web.Application:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix(f"wp537{uuid.uuid4().hex[:8]}"),
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
    )
    return tornado.web.Application(
        [(r"/", _Page)], security_middleware=SecurityMiddleware(config=config)
    )


async def _status_of_one_request(app: tornado.web.Application) -> int:
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    port = sockets[0].getsockname()[1]
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    response = await AsyncHTTPClient().fetch(
        f"http://127.0.0.1:{port}/", raise_error=False
    )
    server.stop()
    await server.close_all_connections()
    return int(response.code)


def test_the_first_request_of_a_second_event_loop_is_served_not_a_503() -> None:
    app = _app()

    statuses = [asyncio.run(_status_of_one_request(app)) for _ in range(3)]

    assert statuses == [200, 200, 200]


def test_a_client_left_by_a_finished_event_loop_leaks_no_socket() -> None:
    app = _app()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        for _ in range(3):
            asyncio.run(_status_of_one_request(app))
        gc.collect()

    assert [str(w.message) for w in caught if w.category is ResourceWarning] == []
