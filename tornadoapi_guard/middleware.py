from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, cast

from guard_core.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.core.bypass import BypassContext, BypassHandler
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.events import MetricsCollector, SecurityEventBus
from guard_core.core.initialization import HandlerInitializer
from guard_core.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip, setup_custom_logging

from tornadoapi_guard.adapters import (
    TornadoGuardRequest,
    TornadoGuardResponse,
    TornadoResponseFactory,
    get_guard_state,
    sync_guard_response,
    unwrap_response,
)

if TYPE_CHECKING:
    from tornado.web import RequestHandler


class SecurityMiddleware:
    def __init__(self, *, config: SecurityConfig) -> None:
        self.config = config
        self.logger = setup_custom_logging(
            config.custom_log_file, log_format=config.log_format
        )
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(config)
        self.guard_decorator: BaseSecurityDecorator | None = None

        self._configure_security_headers(config)

        self.geo_ip_handler = None
        if config.whitelist_countries or config.blocked_countries:
            self.geo_ip_handler = config.geo_ip_handler

        self.redis_handler = None
        if config.enable_redis:
            from guard_core.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

        self.agent_handler: Any = None
        if config.enable_agent:
            agent_config = config.to_agent_config()
            if agent_config:
                try:
                    from guard_agent import guard_agent

                    self.agent_handler = guard_agent(agent_config)
                    self.logger.info("Guard Agent initialized successfully")
                except ImportError:
                    self.logger.warning(
                        "Agent enabled but guard_agent package not installed. "
                        "Install with: pip install guard-agent"
                    )
                except Exception as e:
                    self.logger.error(f"Failed to initialize Guard Agent: {e}")
                    self.logger.warning("Continuing without agent functionality")
            else:
                self.logger.warning(
                    "Agent enabled but configuration is invalid. "
                    "Check agent_api_key and other required fields."
                )

        self.security_pipeline: SecurityCheckPipeline | None = None

        self._guard_response_factory = TornadoResponseFactory()
        self._cors_handler: CorsHandler | None = (
            CorsHandler(config) if config.enable_cors else None
        )

        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

        self._build_event_bus_and_contexts()

        self._initialized = False
        self._init_lock = asyncio.Lock()

    def _is_initialized(self) -> bool:
        return self._initialized

    async def _ensure_initialized(self) -> None:
        if self._is_initialized():
            return
        async with self._init_lock:
            if self._is_initialized():
                return
            await self.initialize()
            self._initialized = True

    def _build_event_bus_and_contexts(self) -> None:
        if self.handler_initializer.composite_handler is not None:
            self.event_bus = self.handler_initializer.build_event_bus(
                geo_ip_handler=self.geo_ip_handler
            )
            self.metrics_collector = self.handler_initializer.build_metrics_collector()
        else:
            self.event_bus = SecurityEventBus(
                self.agent_handler, self.config, self.geo_ip_handler
            )
            self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            guard_decorator=self.guard_decorator,
            response_factory=self._guard_response_factory,
        )
        self.response_factory = ErrorResponseFactory(response_context)

        validation_context = ValidationContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        bypass_context = BypassContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            route_resolver=self.route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        behavioral_context = BehavioralContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
            behavior_tracker=self.handler_initializer.behavior_tracker,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)

    @property
    def guard_response_factory(self) -> TornadoResponseFactory:
        return self._guard_response_factory

    @property
    def agent_stats(self) -> dict[str, Any]:
        if self.agent_handler is None:
            return {"enabled": False}
        handler_stats = cast(Any, self.agent_handler).get_stats()
        return {"enabled": True, **handler_stats}

    def _configure_security_headers(self, config: SecurityConfig) -> None:
        if not config.security_headers:
            security_headers_manager.enabled = False
            return

        if not config.security_headers.get("enabled", True):
            security_headers_manager.enabled = False
            return

        security_headers_manager.enabled = True
        headers_config = config.security_headers
        hsts_config = headers_config.get("hsts", {})

        security_headers_manager.configure(
            enabled=headers_config.get("enabled", True),
            csp=headers_config.get("csp"),
            hsts_max_age=hsts_config.get("max_age"),
            hsts_include_subdomains=hsts_config.get("include_subdomains", True),
            hsts_preload=hsts_config.get("preload", False),
            frame_options=headers_config.get("frame_options", "SAMEORIGIN"),
            content_type_options=headers_config.get("content_type_options", "nosniff"),
            xss_protection=headers_config.get("xss_protection", "1; mode=block"),
            referrer_policy=headers_config.get(
                "referrer_policy", "strict-origin-when-cross-origin"
            ),
            permissions_policy=headers_config.get("permissions_policy", "UNSET"),
            custom_headers=headers_config.get("custom"),
            cors_origins=config.cors_allow_origins if config.enable_cors else None,
            cors_allow_credentials=config.cors_allow_credentials,
            cors_allow_methods=config.cors_allow_methods,
            cors_allow_headers=config.cors_allow_headers,
        )

    def _build_security_pipeline(self) -> None:
        from guard_core.core.checks import (
            AuthenticationCheck,
            CloudIpRefreshCheck,
            CloudProviderCheck,
            CustomRequestCheck,
            CustomValidatorsCheck,
            EmergencyModeCheck,
            HttpsEnforcementCheck,
            IpSecurityCheck,
            RateLimitCheck,
            ReferrerCheck,
            RequestLoggingCheck,
            RequestSizeContentCheck,
            RequiredHeadersCheck,
            RouteConfigCheck,
            SuspiciousActivityCheck,
            TimeWindowCheck,
            UserAgentCheck,
        )

        checks = [
            RouteConfigCheck(self),
            EmergencyModeCheck(self),
            HttpsEnforcementCheck(self),
            RequestLoggingCheck(self),
            RequestSizeContentCheck(self),
            RequiredHeadersCheck(self),
            AuthenticationCheck(self),
            ReferrerCheck(self),
            CustomValidatorsCheck(self),
            TimeWindowCheck(self),
            CloudIpRefreshCheck(self),
            IpSecurityCheck(self),
            CloudProviderCheck(self),
            UserAgentCheck(self),
            RateLimitCheck(self),
            SuspiciousActivityCheck(self),
            CustomRequestCheck(self),
        ]

        self.security_pipeline = SecurityCheckPipeline(checks)
        self.logger.info(
            f"Security pipeline initialized with {len(checks)} checks: "
            f"{self.security_pipeline.get_check_names()}"
        )

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        self.guard_decorator = decorator_handler
        self.handler_initializer.guard_decorator = decorator_handler

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        result: bool = await self.validator.check_time_window(time_restrictions)
        return result

    async def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        from guard_core.core.checks.helpers import check_route_ip_access

        result: bool | None = await check_route_ip_access(client_ip, route_config, self)
        return result

    async def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        from guard_core.core.checks.helpers import check_user_agent_allowed

        result: bool = await check_user_agent_allowed(
            user_agent, route_config, self.config
        )
        return result

    def _populate_guard_state(
        self,
        guard_request: TornadoGuardRequest,
        handler: RequestHandler,
    ) -> None:
        app_decorator = self.guard_decorator or handler.application.settings.get(
            "guard_decorator"
        )
        if app_decorator:
            guard_request.state.guard_decorator = app_decorator

        method_name = (handler.request.method or "get").lower()
        endpoint = getattr(handler, method_name, None)
        if endpoint is None:
            return

        route_id = getattr(endpoint, "_guard_route_id", None)
        if route_id:
            guard_request.state.guard_route_id = route_id

        module = getattr(endpoint, "__module__", None)
        qualname = getattr(endpoint, "__qualname__", None)
        if module and qualname:
            guard_request.state.guard_endpoint_id = f"{module}.{qualname}"

    def _inject_cors(
        self, response: GuardResponse, request_headers: Mapping[str, str]
    ) -> None:
        if self._cors_handler is None:
            return
        cors_headers = self._cors_handler.build_response_headers(dict(request_headers))
        for key, value in cors_headers.items():
            response.headers[key] = value

    def _view_caller(
        self, handler: RequestHandler
    ) -> Callable[[Any], Awaitable[GuardResponse]]:
        async def call_view(_guard_request: Any) -> GuardResponse:
            state = get_guard_state(handler)
            state.guard_capturing = True
            try:
                view = getattr(handler, (handler.request.method or "GET").lower())
                result = view(*handler.path_args, **handler.path_kwargs)
                if inspect.isawaitable(result):
                    await result
            finally:
                state.guard_capturing = False
            return TornadoGuardResponse.from_handler(handler)

        return call_view

    async def _handle_preflight(
        self, guard_request: TornadoGuardRequest
    ) -> GuardResponse | None:
        if self._cors_handler is None:
            return None
        headers = dict(guard_request.headers)
        if not is_preflight(guard_request.method, headers):
            return None
        assert self.security_pipeline is not None
        blocking = await self.security_pipeline.execute(guard_request)
        if blocking is not None:
            self._inject_cors(blocking, headers)
            return blocking
        preflight = self._cors_handler.build_preflight_response(headers)
        return TornadoGuardResponse(
            status_code=preflight.status_code,
            headers=dict(preflight.headers),
            body=preflight.body.encode("utf-8"),
        )

    async def _redis_unavailable_response(self) -> GuardResponse:
        response = await self.create_error_response(
            503, "Service temporarily unavailable"
        )
        response.headers["Retry-After"] = "5"
        return response

    async def _guard_phase(
        self, handler: RequestHandler, guard_request: TornadoGuardRequest
    ) -> GuardResponse | None:
        assert self.security_pipeline is not None
        call_view = self._view_caller(handler)

        passthrough = await self.bypass_handler.handle_passthrough(
            guard_request, call_view
        )
        if passthrough is not None:
            return passthrough

        client_ip = await extract_client_ip(
            guard_request, self.config, self.agent_handler
        )
        route_config = self.route_resolver.get_route_config(guard_request)
        guard_request.state.route_config = route_config
        guard_request.state.client_ip = client_ip

        bypass = await self.bypass_handler.handle_security_bypass(
            guard_request, call_view, route_config
        )
        if bypass is not None:
            return bypass

        blocking = await self.security_pipeline.execute(guard_request)
        if blocking is not None:
            return blocking

        if route_config and route_config.behavior_rules and client_ip:
            await self.behavioral_processor.process_usage_rules(
                guard_request, client_ip, route_config
            )
        return None

    async def run_pre_processing(self, handler: RequestHandler) -> GuardResponse | None:
        guard_request = TornadoGuardRequest(handler)
        try:
            await self._ensure_initialized()
        except GuardRedisError as e:
            self.logger.error("Redis unavailable during initialization: %s", e)
            unavailable = await self._redis_unavailable_response()
            self._inject_cors(unavailable, guard_request.headers)
            return unavailable

        self._populate_guard_state(guard_request, handler)
        guard_request.state.guard_request = guard_request
        guard_request.state.request_start_time = time.time()

        preflight = await self._handle_preflight(guard_request)
        if preflight is not None:
            return preflight

        early = await self._guard_phase(handler, guard_request)
        if early is not None:
            self._inject_cors(early, guard_request.headers)
            return early

        guard_request.state.guard_response_pass = True
        return None

    async def run_post_processing(self, handler: RequestHandler) -> None:
        state = get_guard_state(handler)
        guard_request: TornadoGuardRequest | None = getattr(
            state, "guard_request", None
        )
        if guard_request is None:
            return

        route_config: RouteConfig | None = getattr(state, "route_config", None)
        start_time: float = getattr(state, "request_start_time", time.time())
        response_time = time.time() - start_time

        guard_response = TornadoGuardResponse.from_handler(handler)
        before_headers = dict(guard_response.headers)
        before_body = guard_response.body

        result = await self.response_factory.process_response(
            guard_request,
            guard_response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
            process_global_behavioral_rules=(
                self.behavioral_processor.process_global_return_rules
            ),
        )
        final = unwrap_response(result)
        self._inject_cors(final, guard_request.headers)
        if not cast(Any, handler)._headers_written:
            sync_guard_response(handler, before_headers, before_body, final)

    async def refresh_cloud_ip_ranges(self) -> None:
        if not self.config.block_cloud_providers:
            return

        if self.config.enable_redis and self.redis_handler:
            await cloud_handler.refresh_async(
                self.config.block_cloud_providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )
        else:
            await cloud_handler.refresh(self.config.block_cloud_providers)
        self.last_cloud_ip_refresh = int(time.time())

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        result: GuardResponse = await self.response_factory.create_error_response(
            status_code, default_message
        )
        return result

    async def reset(self) -> None:
        await self.rate_limit_handler.reset()

    async def initialize(self) -> None:
        if not self.security_pipeline:
            self._build_security_pipeline()

        self.handler_initializer.guard_decorator = self.guard_decorator

        await self.handler_initializer.initialize_redis_handlers()

        await self.handler_initializer.initialize_agent_integrations()

        if self.handler_initializer.composite_handler is not None:
            self.agent_handler = self.handler_initializer.composite_handler
            self._build_event_bus_and_contexts()
