from pathlib import Path

import tornado.httpserver
import tornado.netutil
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient
from tornado.web import Application, RequestHandler, StaticFileHandler

from tornadoapi_guard._route_gate_host import (
    hold_route_gate_host,
    release_route_gate_host,
)
from tornadoapi_guard.middleware import SecurityMiddleware

HOST = "api.example.com"


class _Handler(RequestHandler):
    def get(self, *args: str) -> None:
        return None


def _middleware(application: Application) -> SecurityMiddleware:
    middleware = SecurityMiddleware(
        config=SecurityConfig(enable_redis=False, trusted_proxies=[])
    )
    middleware._routing_application = application
    return middleware


async def test_the_gate_helpers_find_a_virtual_host_route_under_the_requests_host(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.js.map").write_text("{}")
    application = Application([])
    application.add_handlers(
        r"api\.example\.com",
        [
            (r"/static/(.*)", StaticFileHandler, {"path": str(tmp_path)}),
            (r"/legacy/(.*)\.php", _Handler),
        ],
    )
    middleware = _middleware(application)

    token = hold_route_gate_host(HOST)
    try:
        served = await middleware.static_file_exists("/static/app.js.map")
        template = middleware.route_template("/legacy/x.php")
        identities = middleware.resolve_route("/legacy/x.php")
    finally:
        release_route_gate_host(token)

    assert served is True
    assert template == r"/legacy/(.*)\.php$"
    assert len(identities) == 1


class _PageHandler(RequestHandler):
    async def get(self, *args: str) -> None:
        self.write({"ok": True})


async def test_a_script_route_of_a_virtual_host_is_not_struck_for_its_own_path() -> (
    None
):
    guard = SecurityMiddleware(
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
            ban_on_hostile_signals=False,
            geo_ip_handler=None,
        )
    )
    await guard.initialize()
    application = Application([], security_middleware=guard)
    application.add_handlers(
        r"api\.example\.com", [(r"/legacy/(.*)\.php", _PageHandler)]
    )
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(application)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    try:
        response = await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{port}/legacy/x.php", headers={"Host": HOST}
        )
    finally:
        server.stop()
        await guard.reset()

    assert response.code == 200
