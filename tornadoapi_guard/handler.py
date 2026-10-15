from __future__ import annotations

import asyncio
from typing import Any

from tornado.web import RequestHandler

from tornadoapi_guard.adapters import apply_guard_response, get_guard_state
from tornadoapi_guard.middleware import SecurityMiddleware

_background_tasks: set[asyncio.Future[None]] = set()


class SecurityHandler(RequestHandler):
    async def prepare(self) -> None:
        middleware = self._get_security_middleware()
        if middleware is None:
            return

        early = await middleware.run_pre_processing(self)
        if early is not None:
            apply_guard_response(self, early)

    def finish(self, chunk: str | bytes | dict[str, Any] | None = None) -> Any:
        state = get_guard_state(self)
        pending = getattr(state, "guard_finish", None)
        if pending is not None:
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

    async def _guard_finish(self, chunk: str | bytes | dict[str, Any] | None) -> None:
        middleware = self._get_security_middleware()
        assert middleware is not None
        try:
            if chunk is not None:
                self.write(chunk)
            await middleware.run_post_processing(self)
        except Exception:
            middleware.logger.exception("Response processing failed")
        await super().finish()

    def _get_security_middleware(self) -> SecurityMiddleware | None:
        value = self.application.settings.get("security_middleware")
        if isinstance(value, SecurityMiddleware):
            return value
        return None
