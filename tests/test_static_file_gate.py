from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from guard_core.models import SecurityConfig
from tornado.httpclient import AsyncHTTPClient, HTTPClientError
from tornado.web import StaticFileHandler

from tornadoapi_guard import SecurityHandler, SecurityMiddleware


class GuardedStaticFiles(SecurityHandler, StaticFileHandler):
    pass


class PageHandler(SecurityHandler):
    async def get(self, *args: str) -> None:
        self.write({"ok": True})


def _tree(root: Path) -> Path:
    for name in (
        "hls/live/segment_001.ts",
        "static/js/app.4f3a.js.map",
        "static/app.py",
        "static/dump.sql",
        "static/app.php",
        "static/real.ts",
        "secret.ts",
    ):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    (root / "static" / "folder.ts").mkdir()
    os.symlink(root / "secret.ts", root / "static" / "link.ts")
    return root


def _config() -> SecurityConfig:
    return SecurityConfig(
        geo_ip_handler=None,
        enable_redis=False,
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        ban_on_hostile_signals=False,
        exclude_paths=[],
    )


def _routes(root: Path) -> list[Any]:
    return [
        (r"/hls/(.*)", GuardedStaticFiles, {"path": str(root / "hls")}),
        (
            r"/static/(?P<path>.*)",
            GuardedStaticFiles,
            {"path": str(root / "static")},
        ),
        (r"/page/(.*)", PageHandler),
    ]


@pytest.fixture
async def app(
    tmp_path: Path,
) -> AsyncGenerator[tuple[int, SecurityMiddleware, Path], None]:
    root = _tree(tmp_path)
    middleware = SecurityMiddleware(config=_config())
    await middleware.initialize()
    application = tornado.web.Application(_routes(root), security_middleware=middleware)
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(application)
    server.add_sockets(sockets)
    try:
        yield sockets[0].getsockname()[1], middleware, root
    finally:
        server.stop()
        await middleware.reset()


async def _status(port: int, path: str) -> int:
    try:
        response = await AsyncHTTPClient().fetch(f"http://127.0.0.1:{port}{path}")
    except HTTPClientError as error:
        return error.code
    return int(response.code)


@pytest.mark.parametrize(
    ("path", "flagged"),
    [
        ("/hls/live/segment_001.ts", False),
        ("/static/js/app.4f3a.js.map", False),
        ("/static/real.ts", False),
        ("/static/real.ts;jsessionid=1", True),
        ("/hls/live/missing.ts", True),
        ("/static/js/missing.js.map", True),
        ("/static/folder.ts", True),
        ("/static/link.ts", True),
        ("/static/app.py", True),
        ("/static/dump.sql", True),
        ("/static/app.php", True),
        ("/page/segment_001.ts", True),
    ],
)
async def test_a_ts_or_map_file_is_clean_only_when_the_static_mount_has_it(
    app: tuple[int, SecurityMiddleware, Path], path: str, flagged: bool
) -> None:
    port, _, _ = app

    assert (await _status(port, path) == 400) is flagged


async def test_the_lookup_is_traversal_safe_and_never_cached(
    app: tuple[int, SecurityMiddleware, Path],
) -> None:
    port, middleware, root = app
    await _status(port, "/page/x")
    late = root / "static" / "late.ts"

    assert await middleware.static_file_exists("/static/real.ts") is True
    assert await middleware.static_file_exists("/nowhere/seg.ts") is False
    assert await middleware.static_file_exists("/page/seg.ts") is False
    assert await middleware.static_file_exists("/static/../secret.ts") is False
    assert await middleware.static_file_exists("/static/%ff.ts") is False
    assert await middleware.static_file_exists("/static/late.ts") is False
    late.write_text("x")
    assert await middleware.static_file_exists("/static/late.ts") is True
    late.unlink()
    assert await middleware.static_file_exists("/static/late.ts") is False


async def test_a_middleware_that_has_seen_no_request_answers_false() -> None:
    middleware = SecurityMiddleware(config=_config())

    assert await middleware.static_file_exists("/static/real.ts") is False


STATIC_MOUNT_CORPUS = (
    "hls/live/segment_000.ts",
    "hls/live/segment_001.ts",
    "hls/vod/720p/chunk-00042.ts",
    "hls/vod/1080p/chunk-00001.ts",
    "hls/audio/seg-12.ts",
    "assets/index-4f3a9c1e.js.map",
    "assets/vendor-b82d.js.map",
    "assets/main.css.map",
    "_next/static/chunks/app/page-9d8c.js.map",
    "_next/static/chunks/webpack-1a2b.js.map",
    "static/js/main.4f3a.chunk.js.map",
    "static/css/main.8e1.chunk.css.map",
    "dist/bundle.min.js.map",
    "build/static/js/2.abc123.chunk.js.map",
    "js/jquery.min.map",
    "assets/ts/sample.ts",
    "examples/demo.ts",
)


@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
async def test_the_static_mount_benign_corpus_is_clean_when_the_files_exist(
    app: tuple[int, SecurityMiddleware, Path], name: str
) -> None:
    port, _, root = app
    target = root / "hls" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x")

    assert await _status(port, f"/hls/{name}") == 200


@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
async def test_the_static_mount_benign_corpus_is_flagged_without_a_static_mount(
    app: tuple[int, SecurityMiddleware, Path], name: str
) -> None:
    port, _, _ = app

    assert await _status(port, f"/page/{name}") == 400
