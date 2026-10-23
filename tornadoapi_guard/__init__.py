from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import TYPE_CHECKING, Any

import guard_core
from guard_core import (
    BehaviorRule,
    BehaviorTracker,
    GeoIPHandler,
    GuardRequest,
    GuardResponse,
    GuardResponseFactory,
    IPBanManager,
    RedisHandlerProtocol,
    RouteConfig,
    SecurityConfig,
    SecurityDecorator,
    SecurityHeadersManager,
    ip_ban_manager,
    security_headers_manager,
    sus_patterns_handler,
)
from guard_core._config_capabilities import register_adapter

from tornadoapi_guard.adapters import (
    TornadoGuardRequest,
    TornadoGuardResponse,
    TornadoResponseFactory,
    apply_guard_response,
    unwrap_response,
)
from tornadoapi_guard.handler import SecurityHandler, SecurityWebSocketHandler
from tornadoapi_guard.middleware import SecurityMiddleware

register_adapter("tornadoapi-guard")

if TYPE_CHECKING:
    from guard_core import (
        CloudManager,
        IPInfoManager,
        RateLimitManager,
        RedisManager,
        cloud_handler,
        rate_limit_handler,
        redis_handler,
    )

_LAZY_GUARD_CORE_NAMES = frozenset(
    {
        "CloudManager",
        "IPInfoManager",
        "RateLimitManager",
        "RedisManager",
        "cloud_handler",
        "rate_limit_handler",
        "redis_handler",
    }
)


def __getattr__(name: str) -> Any:
    if name not in _LAZY_GUARD_CORE_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(guard_core, name)
    globals()[name] = value
    return value


try:
    __version__ = _pkg_version("tornadoapi_guard")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = [
    "__version__",
    "SecurityMiddleware",
    "SecurityHandler",
    "SecurityWebSocketHandler",
    "SecurityConfig",
    "SecurityDecorator",
    "RouteConfig",
    "BehaviorTracker",
    "BehaviorRule",
    "ip_ban_manager",
    "IPBanManager",
    "cloud_handler",
    "CloudManager",
    "IPInfoManager",
    "rate_limit_handler",
    "RateLimitManager",
    "redis_handler",
    "RedisManager",
    "security_headers_manager",
    "SecurityHeadersManager",
    "sus_patterns_handler",
    "GeoIPHandler",
    "RedisHandlerProtocol",
    "GuardRequest",
    "GuardResponse",
    "GuardResponseFactory",
    "TornadoGuardRequest",
    "TornadoGuardResponse",
    "TornadoResponseFactory",
    "apply_guard_response",
    "unwrap_response",
]
