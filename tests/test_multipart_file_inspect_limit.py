from __future__ import annotations

import itertools
from collections.abc import AsyncGenerator, Awaitable, Callable

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPResponse

from tornadoapi_guard import SecurityHandler, SecurityMiddleware

BODY_LIMIT = 262144
DEFAULT_FILE_LIMIT = SecurityConfig().detection_max_file_inspect_bytes
PAST_THE_LIMIT_PADDING = BODY_LIMIT + 1024
RAISED_FILE_LIMIT = 1_000_000
BOUNDARY = "wp251boundary"
_PAYLOAD = "1' UNION SELECT password FROM users--"
_FORWARDED = {"X-Forwarded-For": "203.0.113.50"}
_MULTIPART_TYPE = f"multipart/form-data; boundary={BOUNDARY}"


def _multipart_body() -> bytes:
    pad = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="pad"\r\n\r\n'
        f"{'A' * PAST_THE_LIMIT_PADDING}\r\n"
    )
    comment = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="comment"\r\n\r\n'
        f"{_PAYLOAD}\r\n--{BOUNDARY}--\r\n"
    )
    return (pad + comment).encode()


def _json_body() -> bytes:
    pad = "A" * PAST_THE_LIMIT_PADDING
    return ('{"pad": "' + pad + '", "comment": "' + _PAYLOAD + '"}').encode()


_IPS = itertools.count(1)

Post = Callable[[bytes, str, bool], Awaitable[HTTPResponse]]
Serve = Callable[[int], Awaitable[Post]]


class UploadHandler(SecurityHandler):
    async def post(self) -> None:
        self.write({"ok": "upload"})


@pytest.fixture
async def serve() -> AsyncGenerator[Serve, None]:
    started: list[tuple[tornado.httpserver.HTTPServer, SecurityMiddleware]] = []

    async def _serve(file_limit: int) -> Post:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
            trusted_proxies=["127.0.0.1"],
            ban_on_hostile_signals=False,
            detection_max_file_inspect_bytes=file_limit,
        )
        middleware = SecurityMiddleware(config=config)
        app = tornado.web.Application(
            [(r"/upload", UploadHandler)], security_middleware=middleware
        )
        await middleware.initialize()
        sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets(sockets)
        started.append((server, middleware))
        port = sockets[0].getsockname()[1]
        forwarded = {"X-Forwarded-For": f"198.51.100.{next(_IPS)}"}

        async def post(body: bytes, content_type: str, chunked: bool) -> HTTPResponse:
            url = f"http://127.0.0.1:{port}/upload"
            headers = {**forwarded, "Content-Type": content_type}
            if not chunked:
                return await AsyncHTTPClient().fetch(
                    url, method="POST", body=body, headers=headers, raise_error=False
                )

            async def producer(write: Callable[[bytes], Awaitable[None]]) -> None:
                for start in range(0, len(body), 8192):
                    await write(body[start : start + 8192])

            return await AsyncHTTPClient().fetch(
                url,
                method="POST",
                body_producer=producer,
                headers={**headers, "Transfer-Encoding": "chunked"},
                raise_error=False,
            )

        return post

    yield _serve
    for server, middleware in started:
        server.stop()
        await middleware.reset()


@pytest.mark.parametrize("chunked", [False, True])
async def test_multipart_past_the_body_limit_is_scanned_under_a_raised_file_limit(
    serve: Serve, chunked: bool
) -> None:
    post = await serve(RAISED_FILE_LIMIT)

    response = await post(_multipart_body(), _MULTIPART_TYPE, chunked)

    assert response.code == 400
    assert b"Suspicious activity detected" in response.body


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_multipart_body_past_the_default_file_limit_is_refused_not_passed(
    serve: Serve, chunked: bool
) -> None:
    post = await serve(DEFAULT_FILE_LIMIT)

    response = await post(_multipart_body(), _MULTIPART_TYPE, chunked)

    assert response.code == 400
    assert b"Suspicious activity detected" not in response.body


@pytest.mark.parametrize("chunked", [False, True])
async def test_a_json_body_of_the_same_size_stays_refused_under_a_raised_file_limit(
    serve: Serve, chunked: bool
) -> None:
    post = await serve(RAISED_FILE_LIMIT)

    response = await post(_json_body(), "application/json", chunked)

    assert response.code == 400
    assert b"Suspicious activity detected" not in response.body
