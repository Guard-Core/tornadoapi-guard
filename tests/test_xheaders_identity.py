from __future__ import annotations

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from tornado.httpclient import AsyncHTTPClient

from tornadoapi_guard.adapters import TornadoGuardRequest


class Whoami(tornado.web.RequestHandler):
    async def get(self) -> None:
        self.write(TornadoGuardRequest(self).client_host or "")


async def _client_host(xheaders: bool) -> str:
    app = tornado.web.Application([(r"/whoami", Whoami)])
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app, xheaders=xheaders)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    try:
        response = await AsyncHTTPClient().fetch(
            f"http://127.0.0.1:{port}/whoami", headers={"X-Real-Ip": "198.51.100.9"}
        )
    finally:
        server.stop()
    return response.body.decode()


@pytest.mark.parametrize(
    ("xheaders", "expected"), [(False, "127.0.0.1"), (True, "198.51.100.9")]
)
async def test_the_client_host_is_tornados_remote_ip_so_xheaders_decides_it(
    xheaders: bool, expected: str
) -> None:
    assert await _client_host(xheaders) == expected
