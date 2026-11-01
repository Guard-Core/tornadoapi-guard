from __future__ import annotations

import concurrent.futures
import threading
from collections.abc import AsyncGenerator, Iterator

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.detection_engine import compiler as compiler_module
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

BUSY_ROW = "[xyz]7"


class _PingHandler(SecurityHandler):
    def get(self) -> None:
        self.write({"ok": "yes"})


@pytest.fixture
def saturated_regex_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    workers = compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    monkeypatch.setattr(compiler_module, "_shared_executor", pool)
    release = threading.Event()
    all_running = threading.Barrier(workers + 1)

    def hold() -> None:
        all_running.wait(10)
        release.wait(30)

    for _ in range(workers):
        pool.submit(hold)
    all_running.wait(10)
    yield
    release.set()
    pool.shutdown(wait=True)


@pytest.fixture
async def port() -> AsyncGenerator[int, None]:
    config = SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        enable_ip_banning=False,
        fail_secure=True,
        detection_compiler_timeout=0.3,
        custom_error_responses={503: "Busy, retry shortly"},
    )
    middleware = SecurityMiddleware(config=config)
    app = tornado.web.Application(
        [(r"/ping", _PingHandler)], security_middleware=middleware
    )
    await middleware.initialize()
    await sus_patterns_manager_for(config).add_pattern(BUSY_ROW, custom=True)
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    try:
        yield int(sockets[0].getsockname()[1])
    finally:
        server.stop()
        await sus_patterns_manager_for(config).remove_pattern(BUSY_ROW, custom=True)
        await middleware.reset()


@pytest.mark.usefixtures("saturated_regex_pool")
async def test_a_queue_wait_answers_503_with_retry_after_and_the_custom_message(
    port: int,
) -> None:
    with pytest.raises(HTTPClientError) as refused:
        await AsyncHTTPClient().fetch(f"http://127.0.0.1:{port}/ping?q=hello")

    assert refused.value.code == 503
    assert refused.value.response is not None
    assert refused.value.response.headers["Retry-After"] == "1"
    assert refused.value.response.body.decode() == "Busy, retry shortly"


async def test_the_same_request_on_a_free_pool_passes(port: int) -> None:
    response = await AsyncHTTPClient().fetch(f"http://127.0.0.1:{port}/ping?q=hello")

    assert response.code == 200
