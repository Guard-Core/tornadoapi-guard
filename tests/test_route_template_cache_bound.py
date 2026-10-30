import tracemalloc
from collections.abc import Iterable

import pytest
from guard_core.models import SecurityConfig
from tornado.httputil import HTTPServerRequest
from tornado.routing import Rule
from tornado.web import Application, RequestHandler

import tornadoapi_guard.middleware as middleware_module
from tornadoapi_guard.middleware import _ROUTE_TEMPLATE_CACHE_SIZE, SecurityMiddleware


class _Handler(RequestHandler):
    def get(self, *args: str) -> None:
        return None


def _middleware() -> SecurityMiddleware:
    middleware = SecurityMiddleware(
        config=SecurityConfig(enable_redis=False, trusted_proxies=[])
    )
    middleware._routing_application = Application(
        [(r"/ok", _Handler), (r"/long/(.*)", _Handler)]
    )
    return middleware


def _long_miss(index: int) -> str:
    return "/" + "a" * 60000 + f"{index}.php"


def test_long_paths_do_not_pin_their_text_in_the_cache() -> None:
    middleware = _middleware()
    tracemalloc.start()
    try:
        for index in range(_ROUTE_TEMPLATE_CACHE_SIZE + 50):
            middleware.route_template(_long_miss(index))
        retained_mb = tracemalloc.get_traced_memory()[0] / 1e6
    finally:
        tracemalloc.stop()

    assert retained_mb < 20


def test_a_long_path_is_still_answered_from_the_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    middleware = _middleware()
    calls: list[str] = []
    original = middleware_module._matched_template

    def counting(rules: Iterable[Rule], request: HTTPServerRequest) -> str | None:
        calls.append("match")
        return original(rules, request)

    monkeypatch.setattr(middleware_module, "_matched_template", counting)
    miss, hit = _long_miss(0), "/long/" + "b" * 5000

    first = [middleware.route_template(path) for path in (miss, hit)]
    matched_once = len(calls)
    second = [middleware.route_template(path) for path in (miss, hit)]

    assert first == second == [None, "/long/(.*)$"]
    assert len(calls) == matched_once
