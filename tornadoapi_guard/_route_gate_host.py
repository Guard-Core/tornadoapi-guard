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


_signature: ContextVar[tuple[int, int] | None] = ContextVar(
    "guard_route_signature", default=None
)


def hold_route_signature(signature: tuple[int, int]) -> Token[tuple[int, int] | None]:
    """The rule signature this request computed once, shared with route_template."""
    return _signature.set(signature)


def release_route_signature(token: Token[tuple[int, int] | None]) -> None:
    _signature.reset(token)


def route_signature() -> tuple[int, int] | None:
    return _signature.get()


def route_gate_host() -> str:
    return _host.get()
