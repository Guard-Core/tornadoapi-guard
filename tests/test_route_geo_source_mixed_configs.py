import logging

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard import SecurityDecorator, SecurityHandler, SecurityMiddleware


class GeoHandler(SecurityHandler):
    async def get(self) -> None:
        self.write("geo-handler-body")


async def test_decorator_false_under_middleware_true_starts_and_answers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    decorator = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    )
    decorator.block_countries(["CN"])(GeoHandler.get)
    middleware = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            fail_on_misconfiguration=True,
        )
    )
    middleware.set_decorator_handler(decorator)
    app = tornado.web.Application(
        [(r"/geo", GeoHandler)],
        security_middleware=middleware,
        guard_decorator=decorator,
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        port = sockets[0].getsockname()[1]
        client = AsyncHTTPClient()
        first = await client.fetch(f"http://127.0.0.1:{port}/geo", raise_error=False)
        second = await client.fetch(f"http://127.0.0.1:{port}/geo", raise_error=False)
        server.stop()
        await middleware.reset()

    assert (first.code, second.code) == (200, 200)
    assert caplog.text.count("no GeoIP database") == 1
