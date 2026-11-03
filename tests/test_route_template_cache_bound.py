import tracemalloc
from collections.abc import Iterable

import pytest
from guard_core.models import SecurityConfig
from tornado.httputil import HTTPServerRequest
from tornado.routing import Rule
from tornado.web import Application, RequestHandler

import tornadoapi_guard.middleware as middleware_module
from tornadoapi_guard._route_gate_host import (
    hold_route_gate_host,
    release_route_gate_host,
)
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


_ADMIN_HOST = "admin.example"
_WWW_HOST = "www.example"
_ADMIN_TEMPLATE = "/items/(?P<admin_item>[0-9]+)$"
_WWW_TEMPLATE = "/items/(?P<item_id>[0-9]+)$"


def _two_host_middleware() -> SecurityMiddleware:
    middleware = SecurityMiddleware(
        config=SecurityConfig(enable_redis=False, trusted_proxies=[])
    )
    application = Application([(r"/items/(?P<item_id>[0-9]+)", _Handler)])
    application.add_handlers(
        r"admin\.example", [(r"/items/(?P<admin_item>[0-9]+)", _Handler)]
    )
    middleware._routing_application = application
    return middleware


def _template_under(middleware: SecurityMiddleware, host: str, path: str) -> str | None:
    token = hold_route_gate_host(host)
    try:
        return middleware.route_template(path)
    finally:
        release_route_gate_host(token)


@pytest.mark.parametrize(
    "order",
    [(_ADMIN_HOST, _WWW_HOST), (_WWW_HOST, _ADMIN_HOST)],
    ids=["admin-first", "www-first"],
)
def test_a_virtual_host_is_never_served_another_hosts_template(
    order: tuple[str, str],
) -> None:
    middleware = _two_host_middleware()
    expected = {_ADMIN_HOST: _ADMIN_TEMPLATE, _WWW_HOST: _WWW_TEMPLATE}

    first = {host: _template_under(middleware, host, "/items/5") for host in order}
    again = {host: _template_under(middleware, host, "/items/5") for host in order}

    assert first == again == expected


def test_a_long_host_is_keyed_by_its_hash_and_still_answered_from_the_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    middleware = _two_host_middleware()
    calls: list[str] = []
    original = middleware_module._matched_template

    def counting(rules: Iterable[Rule], request: HTTPServerRequest) -> str | None:
        calls.append("match")
        return original(rules, request)

    monkeypatch.setattr(middleware_module, "_matched_template", counting)
    host = "h" * 5000 + ".example"

    first = _template_under(middleware, host, "/items/5")
    matched_once = len(calls)
    second = _template_under(middleware, host, "/items/5")

    assert first == second == _WWW_TEMPLATE
    assert len(calls) == matched_once
    assert all(
        isinstance(part, int) or len(part) <= 256
        for key in middleware._route_template_cache
        for part in key
    )
