import importlib.util
from collections.abc import AsyncGenerator
from pathlib import Path
from types import ModuleType

import pytest
import tornado.httpserver
import tornado.netutil
import tornado.web
from tornado.httpclient import AsyncHTTPClient
from tornado.routing import PathMatches

from tests.redis_isolation import REDIS_PREFIX, REDIS_URL, close_redis_of

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BLOCKED_COUNTRY_CLIENT = {"X-Forwarded-For": "10.0.0.5, 10.0.0.9"}
ALLOWED_COUNTRY_CLIENT = {"X-Forwarded-For": "10.0.0.6, 10.0.0.9"}
EXAMPLE_NAMES = ("simple_app", "advanced_app")


class _CountryStubGeoIPHandler:
    def __init__(
        self,
        token: str,
        db_path: Path | None = None,
        max_age: int = 86400,
        download_url: str | None = None,
    ) -> None:
        self.download_url = download_url

    @property
    def is_initialized(self) -> bool:
        return True

    async def initialize(self) -> None:
        return

    async def initialize_redis(self, redis_handler: object) -> None:
        return

    async def initialize_agent(self, agent_handler: object) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return "CN" if ip == "10.0.0.5" else "US"

    async def refresh(self) -> None:
        return

    def close(self) -> None:
        return


def _load_example(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("REDIS_PREFIX", REDIS_PREFIX)
    monkeypatch.setattr(
        "guard_core.handlers.ipinfo_handler.IPInfoManager", _CountryStubGeoIPHandler
    )
    spec = importlib.util.spec_from_file_location(
        f"{name}_main", EXAMPLES / name / "main.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.security_config.enable_ip_banning = False
    module.security_config.rate_limit = 100000
    return module


def _documented_paths(app: tornado.web.Application) -> list[str]:
    patterns = [
        rule.matcher.regex.pattern.rstrip("$")
        for rule in app.wildcard_router.rules
        if isinstance(rule.matcher, PathMatches)
    ]
    return [pattern for pattern in patterns if "(" not in pattern]


async def _first_answer_status(
    base_url: str, path: str, headers: dict[str, str]
) -> int:
    for method in ("GET", "POST", "PUT"):
        response = await AsyncHTTPClient().fetch(
            base_url + path,
            method=method,
            body=None if method == "GET" else b"{}",
            headers=headers,
            raise_error=False,
            follow_redirects=False,
        )
        if response.code != 405:
            return response.code
    return 405


@pytest.fixture
async def example_server(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> AsyncGenerator[tuple[str, tornado.web.Application], None]:
    module = _load_example(request.param, monkeypatch)
    app = module.build_application()
    await module.security_middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    try:
        yield f"http://127.0.0.1:{sockets[0].getsockname()[1]}", app
    finally:
        server.stop()
        await module.security_middleware.reset()
        await close_redis_of(module.security_middleware)


@pytest.mark.parametrize("example_server", EXAMPLE_NAMES, indirect=True)
async def test_every_documented_example_route_answers_without_a_server_error(
    example_server: tuple[str, tornado.web.Application],
) -> None:
    base_url, app = example_server
    answers = {
        path: await _first_answer_status(base_url, path, ALLOWED_COUNTRY_CLIENT)
        for path in _documented_paths(app)
    }
    assert answers
    assert {path: code for path, code in answers.items() if code >= 500} == {}


@pytest.mark.parametrize("example_server", ["simple_app"], indirect=True)
async def test_example_country_block_route_blocks_the_blocked_country_only(
    example_server: tuple[str, tornado.web.Application],
) -> None:
    base_url, _ = example_server
    blocked = await _first_answer_status(
        base_url, "/access/country-block", BLOCKED_COUNTRY_CLIENT
    )
    allowed = await _first_answer_status(
        base_url, "/access/country-block", ALLOWED_COUNTRY_CLIENT
    )
    assert (blocked, allowed) == (403, 200)
