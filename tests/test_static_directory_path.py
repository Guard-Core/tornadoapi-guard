from pathlib import Path

from guard_core.models import SecurityConfig
from tornado.web import Application, StaticFileHandler

from tornadoapi_guard.middleware import SecurityMiddleware


def _middleware(application: Application) -> SecurityMiddleware:
    middleware = SecurityMiddleware(
        config=SecurityConfig(enable_redis=False, trusted_proxies=[])
    )
    middleware._routing_application = application
    return middleware


async def test_a_directory_path_is_no_file_served_and_raises_nothing(
    tmp_path: Path,
) -> None:
    (tmp_path / "pkg.map").mkdir()
    (tmp_path / "pkg.map" / "index.html").write_text("x")
    (tmp_path / "real.map").write_text("{}")
    application = Application(
        [
            (
                r"/static/(.*)",
                StaticFileHandler,
                {"path": str(tmp_path), "default_filename": "index.html"},
            )
        ]
    )
    middleware = _middleware(application)

    assert await middleware.static_file_exists("/static/real.map") is True
    assert await middleware.static_file_exists("/static/pkg.map") is False
    assert await middleware.static_file_exists("/static/missing.map") is False
