from guard_core.models import SecurityConfig

from tests.test_middleware_unit import _make_handler
from tornadoapi_guard.middleware import SecurityMiddleware


def _middleware(passive_mode: bool) -> SecurityMiddleware:
    return SecurityMiddleware(
        config=SecurityConfig(
            geo_ip_handler=None,
            enable_redis=False,
            enable_penetration_detection=False,
            passive_mode=passive_mode,
            fail_secure=True,
        )
    )


async def test_a_client_with_no_address_is_refused_outside_passive_mode() -> None:
    middleware = _middleware(False)

    refused = await middleware.run_pre_processing(_make_handler(remote_ip=""))

    assert refused is not None and refused.status_code == 403
    await middleware.reset()


async def test_a_client_with_no_address_in_passive_mode_is_admitted() -> None:
    middleware = _middleware(True)

    refused = await middleware.run_pre_processing(_make_handler(remote_ip=""))

    assert refused is None
    await middleware.reset()
