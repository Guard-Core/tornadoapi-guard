from __future__ import annotations

import asyncio
import logging
import weakref
from contextvars import Token

from guard_core.adapter_support import AppScope, hold_app_scope, release_app_scope
from guard_core.exceptions import MisconfigurationError
from tornado.web import OutputTransform, RequestHandler
from tornado.websocket import WebSocketHandler

from tornadoapi_guard.adapters import apply_guard_response, get_guard_state
from tornadoapi_guard.middleware import SecurityMiddleware

_background_tasks: set[asyncio.Future[None]] = set()
_unwired_logger = logging.getLogger("guard_core.models")
_unwired_reported: weakref.WeakSet[object] = weakref.WeakSet()


def _security_middleware_of(handler: RequestHandler) -> SecurityMiddleware | None:
    value = handler.application.settings.get("security_middleware")
    if isinstance(value, SecurityMiddleware):
        return value
    return None


def _report_unwired_guard(handler: RequestHandler) -> None:
    # No middleware means no config to read the flag from, unless one sits under
    # another settings key (the usual typo): then its flag decides and the key is named.
    settings = handler.application.settings
    misnamed = next(
        (
            (key, value)
            for key, value in settings.items()
            if isinstance(value, SecurityMiddleware)
        ),
        None,
    )
    message = (
        "The application settings have no SecurityMiddleware under "
        '"security_middleware", so this guarded handler would serve unguarded.'
    )
    if misnamed is not None:
        message += f' One sits under "{misnamed[0]}": rename that setting.'
    fail = True if misnamed is None else misnamed[1].config.fail_on_misconfiguration
    if fail:
        raise MisconfigurationError(
            f"{message} Set fail_on_misconfiguration=False to serve anyway.", []
        )
    if handler.application not in _unwired_reported:
        _unwired_reported.add(handler.application)
        _unwired_logger.warning(
            f"{message} fail_on_misconfiguration=False keeps serving it."
        )


async def _guard_handshake_or_request(handler: RequestHandler) -> None:
    middleware = _security_middleware_of(handler)
    if middleware is None:
        _report_unwired_guard(handler)
        return

    early = await middleware.run_pre_processing(handler)
    if early is not None:
        apply_guard_response(handler, early)


class SecurityHandler(RequestHandler):
    _guard_scope_token: Token[AppScope | None] | None = None

    async def prepare(self) -> None:
        middleware = _security_middleware_of(self)
        if middleware is not None:
            self._guard_scope_token = hold_app_scope(middleware.config)
        await _guard_handshake_or_request(self)
        if middleware is not None and self._guard_scope_token is None:
            # The app's first request builds its scope inside the pipeline.
            self._guard_scope_token = hold_app_scope(middleware.config)

    async def _execute(
        self, transforms: list[OutputTransform], *args: bytes, **kwargs: bytes
    ) -> None:
        # Released here, in the context that held it: a connection's task serves
        # its requests one after another, so a scope left set would reach the next.
        try:
            await super()._execute(transforms, *args, **kwargs)
        finally:
            release_app_scope(self._guard_scope_token)
            self._guard_scope_token = None

    def flush(self, include_footers: bool = False) -> asyncio.Future[None]:
        state = get_guard_state(self)
        middleware = self._get_security_middleware()
        if (
            middleware is None
            or not getattr(state, "guard_response_pass", False)
            or getattr(state, "guard_headers_flushed", False)
            or self._headers_written
        ):
            return super().flush(include_footers)
        return asyncio.ensure_future(
            self._flush_with_guard_headers(middleware, include_footers)
        )

    async def _flush_with_guard_headers(
        self, middleware: SecurityMiddleware, include_footers: bool
    ) -> None:
        await middleware.apply_headers_before_flush(self)
        await super().flush(include_footers)

    def finish(
        self, chunk: str | bytes | dict[str, object] | None = None
    ) -> asyncio.Future[None]:
        state = get_guard_state(self)
        pending = getattr(state, "guard_finish", None)
        if isinstance(pending, asyncio.Future):
            return pending
        if getattr(state, "guard_capturing", False):
            if chunk is not None:
                self.write(chunk)
            done: asyncio.Future[None] = asyncio.get_running_loop().create_future()
            done.set_result(None)
            return done
        if not getattr(state, "guard_response_pass", False):
            return super().finish(chunk)
        task = asyncio.ensure_future(self._guard_finish(chunk))
        state.guard_finish = task
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        return task

    async def _guard_finish(
        self, chunk: str | bytes | dict[str, object] | None
    ) -> None:
        middleware = self._get_security_middleware()
        if middleware is None:
            raise RuntimeError(
                "security_middleware missing from the application settings "
                "while a guarded response was finishing"
            )
        try:
            if chunk is not None:
                self.write(chunk)
            await middleware.run_post_processing(self)
        except Exception:
            middleware.logger.exception("Response processing failed")
        # The finish flushes synchronously: nothing is left to add before it.
        get_guard_state(self).guard_headers_flushed = True
        await super().finish()

    def _get_security_middleware(self) -> SecurityMiddleware | None:
        return _security_middleware_of(self)


class SecurityWebSocketHandler(WebSocketHandler):
    """Runs the security pipeline on the upgrade request, before the handshake.

    A denied upgrade is answered like any denied request (403, 429, 503 and so
    on) and no WebSocket is opened. With passive_mode the denial is logged and
    the upgrade proceeds. The response pass (return rules, security headers,
    metrics) belongs to an HTTP response, so it does not run for the 101.
    """

    async def prepare(self) -> None:
        middleware = _security_middleware_of(self)
        token = None if middleware is None else hold_app_scope(middleware.config)
        try:
            await _guard_handshake_or_request(self)
        finally:
            release_app_scope(token)
