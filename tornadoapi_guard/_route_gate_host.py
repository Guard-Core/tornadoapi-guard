from contextvars import ContextVar, Token

_host: ContextVar[str] = ContextVar("guard_route_gate_host", default="localhost")


def hold_route_gate_host(host: str) -> Token[str]:
    """Make this request's Host the one the route-gate helpers match against.

    The engine asks the adapter about a path (`resolve_route`, `route_template`,
    `static_file_exists`) without a request, so a virtual-host rule
    (`add_handlers(host_regex, ...)`) is only found when the request's Host is in
    force while the engine asks.
    """
    return _host.set(host or "localhost")


def release_route_gate_host(token: Token[str]) -> None:
    _host.reset(token)


def route_gate_host() -> str:
    return _host.get()
