from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.websocket
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

from tornadoapi_guard import (
    BehaviorRule,
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
    TornadoGuardResponse,
    cloud_handler,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _json_dumps(payload: dict[str, Any]) -> str:
    def _default(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError(f"{type(value).__name__} is not JSON serializable")

    return json.dumps(payload, default=_default)


class JSONHandler(SecurityHandler):
    def write_json(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self.set_status(status_code)
        self.set_header("Content-Type", "application/json; charset=utf-8")
        self.write(_json_dumps(payload))

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        self.set_header("Content-Type", "application/json; charset=utf-8")
        reason = self._reason or "error"
        self.finish(
            _json_dumps(
                {
                    "detail": reason,
                    "error_code": f"HTTP_{status_code}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )


async def custom_request_check(request: GuardRequest) -> GuardResponse | None:
    debug = request.query_params.get("debug")
    if debug == "true":
        logger.warning(f"Blocked debug request from {request.client_host or 'unknown'}")
        return TornadoGuardResponse(
            status_code=403,
            headers={"Content-Type": "application/json; charset=utf-8"},
            body=_json_dumps({"detail": "Debug mode not allowed"}).encode("utf-8"),
        )
    return None


async def custom_response_modifier(response: GuardResponse) -> GuardResponse:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


_REDIS_URL = os.getenv("REDIS_URL", "")
_ENABLE_REDIS = bool(_REDIS_URL)


security_config = SecurityConfig(
    # Include the Docker client networks so host curls are not flagged
    whitelist=["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    blacklist=["192.168.100.0/24"],
    trusted_proxies=["127.0.0.1", "10.0.0.0/8"],
    trusted_proxy_depth=2,
    trust_x_forwarded_proto=True,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    blocked_user_agents=["badbot", "evil-crawler", "sqlmap"],
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=300,
    enable_penetration_detection=True,
    behavior_scan_response_body=True,
    cloud_ip_refresh_interval=1800,
    log_format="json",
    enable_redis=_ENABLE_REDIS,
    redis_url=_REDIS_URL or "redis://localhost:6379",
    redis_prefix=os.getenv("REDIS_PREFIX", "tornadoapi_guard:"),
    enforce_https=False,
    custom_request_check=custom_request_check,
    custom_response_modifier=custom_response_modifier,
    security_headers={
        "enabled": True,
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'strict-dynamic'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "connect-src": ["'self'", "ws://localhost:8000"],
        },
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False,
        },
        "frame_options": "SAMEORIGIN",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        ),
        "custom": {
            "X-App-Name": "TornadoAPI-Guard-Example",
            "X-Security-Contact": "security@example.com",
        },
    },
    enable_cors=True,
    cors_allow_origins=["http://localhost:3000", "https://example.com"],
    cors_allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Total-Count"],
    cors_max_age=3600,
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    custom_log_file="security.log",
    exclude_paths=[
        "/favicon.ico",
        "/health",
    ],
    passive_mode=False,
)


security_middleware = SecurityMiddleware(config=security_config)
guard_decorator = SecurityDecorator(security_config)
security_middleware.set_decorator_handler(guard_decorator)


class RootHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json(
            {
                "message": "TornadoAPI Guard Comprehensive Example API",
                "details": {
                    "version": "2.0.0",
                    "features": [
                        "IP filtering",
                        "Country blocking",
                        "Cloud provider blocking",
                        "Rate limiting",
                        "Security headers",
                        "Behavioral analysis",
                        "Content filtering",
                        "Authentication",
                        "Advanced security features",
                    ],
                    "routes": {
                        "/basic": "Basic security features",
                        "/access": "Access control demonstrations",
                        "/auth": "Authentication examples",
                        "/rate": "Rate limiting examples",
                        "/behavior": "Behavioral analysis",
                        "/headers": "Security headers demonstration",
                        "/content": "Content filtering",
                        "/advanced": "Advanced features",
                        "/admin": "Admin utilities",
                        "/test": "Security testing",
                        "/ws": "WebSocket endpoint",
                    },
                },
            }
        )


class BasicRootHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json({"message": "Basic features endpoint"})


class BasicIPHandler(JSONHandler):
    async def get(self) -> None:
        client = self.request.remote_ip or "unknown"
        try:
            client = str(ip_address(client))
        except ValueError:
            pass
        self.write_json(
            {
                "ip": client,
                "country": "US",
                "city": "Example City",
                "region": "Example Region",
                "is_vpn": False,
                "is_cloud": False,
            }
        )


class BasicHealthHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json(
            {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc),
            }
        )


class BasicEchoHandler(JSONHandler):
    async def post(self) -> None:
        try:
            data = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            data = {"raw": self.request.body.decode("utf-8", errors="replace")}
        self.write_json(
            {
                "message": "Echo response",
                "details": {
                    "data": data,
                    "headers": dict(self.request.headers),
                    "method": self.request.method,
                    "url": self.request.full_url(),
                },
            }
        )


class AccessIPWhitelistHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
    async def get(self) -> None:
        self.write_json({"message": "Access granted from whitelisted IP"})


class AccessIPBlacklistHandler(JSONHandler):
    @guard_decorator.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
    async def get(self) -> None:
        self.write_json({"message": "Access granted - you're not blacklisted"})


class AccessCountryBlockHandler(JSONHandler):
    @guard_decorator.block_countries(["CN", "RU", "KP"])
    async def get(self) -> None:
        self.write_json({"message": "Access granted - your country is not blocked"})


class AccessCountryAllowHandler(JSONHandler):
    @guard_decorator.allow_countries(["US", "CA", "GB", "AU"])
    async def get(self) -> None:
        self.write_json({"message": "Access granted from allowed country"})


class AccessNoCloudHandler(JSONHandler):
    @guard_decorator.block_clouds()
    async def get(self) -> None:
        self.write_json({"message": "Access granted - not from cloud provider"})


class AccessNoAWSHandler(JSONHandler):
    @guard_decorator.block_clouds(["AWS"])
    async def get(self) -> None:
        self.write_json({"message": "Access granted - not from AWS"})


class AccessBypassHandler(JSONHandler):
    @guard_decorator.bypass(["rate_limit", "ip"])
    async def get(self) -> None:
        self.write_json(
            {
                "message": (
                    "This endpoint bypasses rate limiting and IP/country/cloud checks"
                ),
                "details": {"bypassed_checks": ["rate_limit", "ip"]},
            }
        )


class AuthHttpsHandler(JSONHandler):
    @guard_decorator.require_https()
    async def get(self) -> None:
        self.write_json(
            {
                "message": "HTTPS connection verified",
                "details": {"protocol": self.request.protocol},
            }
        )


class AuthBearerHandler(JSONHandler):
    @guard_decorator.require_auth(type="bearer")
    async def get(self) -> None:
        self.write_json(
            {
                "authenticated": True,
                "user": "example_user",
                "method": "bearer",
                "permissions": ["read", "write"],
            }
        )


class AuthAPIKeyHandler(JSONHandler):
    @guard_decorator.api_key_auth(header_name="X-API-Key")
    async def get(self) -> None:
        self.write_json(
            {
                "authenticated": True,
                "user": "api_user",
                "method": "api_key",
                "permissions": ["read"],
            }
        )


class AuthCustomHeadersHandler(JSONHandler):
    @guard_decorator.require_headers(
        {"X-Custom-Header": "required-value", "X-Client-ID": "required-value"}
    )
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Required headers verified",
                "details": {"headers": dict(self.request.headers)},
            }
        )


class RateCustomLimitHandler(JSONHandler):
    @guard_decorator.rate_limit(requests=5, window=60)
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Custom rate limit endpoint",
                "details": {"limit": "5 requests per 60 seconds"},
            }
        )


class RateStrictLimitHandler(JSONHandler):
    @guard_decorator.rate_limit(requests=1, window=10)
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Strict rate limit endpoint",
                "details": {"limit": "1 request per 10 seconds"},
            }
        )


class RateGeoHandler(JSONHandler):
    @guard_decorator.geo_rate_limit(
        {
            "US": (100, 60),
            "CN": (10, 60),
            "RU": (20, 60),
            "*": (50, 60),
        }
    )
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Geographic rate limiting applied",
                "details": {"description": "Rate limits vary by country"},
            }
        )


class BehaviorUsageHandler(JSONHandler):
    @guard_decorator.usage_monitor(max_calls=10, window=300, action="log")
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Usage monitoring active",
                "details": {"monitoring": "10 calls per 5 minutes"},
            }
        )


class BehaviorReturnMonitorHandler(JSONHandler):
    @guard_decorator.return_monitor(
        pattern="404", max_occurrences=3, window=60, action="ban"
    )
    async def get(self, status_code: str) -> None:
        code = int(status_code)
        if code == 404:
            self.set_status(404)
            self.write_json({"detail": "Not found"}, status_code=404)
            return
        self.write_json({"message": f"Status code: {code}"})


class BehaviorSuspiciousFrequencyHandler(JSONHandler):
    @guard_decorator.suspicious_frequency(
        max_frequency=0.5, window=10, action="throttle"
    )
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Frequency monitoring active",
                "details": {"max_frequency": "1 request per 2 seconds"},
            }
        )


class BehaviorComplexHandler(JSONHandler):
    @guard_decorator.behavior_analysis(
        [
            BehaviorRule(
                rule_type="frequency", threshold=10, window=60, action="throttle"
            ),
            BehaviorRule(
                rule_type="return_pattern",
                pattern="404",
                threshold=5,
                window=60,
                action="ban",
            ),
        ]
    )
    async def post(self) -> None:
        self.write_json(
            {
                "message": "Complex behavior analysis active",
                "details": {"rules": ["frequency", "return_pattern"]},
            }
        )


class HeadersInfoHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json(
            {
                "message": "All responses include comprehensive security headers",
                "details": {
                    "headers": [
                        "X-Content-Type-Options: nosniff",
                        "X-Frame-Options: SAMEORIGIN",
                        "X-XSS-Protection: 1; mode=block",
                        "Strict-Transport-Security: max-age=31536000",
                        "Content-Security-Policy: default-src 'self'",
                        "Referrer-Policy: strict-origin-when-cross-origin",
                        "Permissions-Policy: accelerometer=(), camera=(), ...",
                        "X-App-Name: TornadoAPI-Guard-Example",
                        "X-Security-Contact: security@example.com",
                    ],
                    "note": "Check browser developer tools to see all headers",
                },
            }
        )


_TEST_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Headers Demo</title>
</head>
<body>
    <h1>TornadoAPI Guard Security Headers Demo</h1>
    <p>Inspect the Network tab in DevTools to see applied security headers.</p>
</body>
</html>
"""


class HeadersTestPageHandler(SecurityHandler):
    async def get(self) -> None:
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.write(_TEST_PAGE_HTML)


class HeadersCspReportHandler(JSONHandler):
    async def post(self) -> None:
        try:
            payload = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            payload = {}
        report = payload.get("csp-report", {})
        logger.warning(
            "CSP Violation: %s blocked %s on %s",
            report.get("violated-directive", "unknown"),
            report.get("blocked-uri", "unknown"),
            report.get("document-uri", "unknown"),
        )
        self.write_json(
            {
                "message": "CSP violation report received",
                "details": {
                    "violated_directive": report.get("violated-directive"),
                    "blocked_uri": report.get("blocked-uri"),
                    "source_file": report.get("source-file"),
                    "line_number": report.get("line-number"),
                },
            }
        )


class HeadersFrameTestHandler(SecurityHandler):
    async def get(self) -> None:
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.write(
            "<!DOCTYPE html><html><head><title>Frame Options Test</title></head>"
            "<body><h1>X-Frame-Options Test</h1>"
            "<p>This page has X-Frame-Options: SAMEORIGIN header.</p></body></html>"
        )


class HeadersHSTSHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json(
            {
                "message": "HSTS (HTTP Strict Transport Security) is active",
                "details": {
                    "max_age": "31536000 seconds (1 year)",
                    "include_subdomains": True,
                    "preload": False,
                    "description": "Forces HTTPS connections for improved security",
                },
            }
        )


class HeadersAnalysisHandler(JSONHandler):
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Security analysis of current request",
                "details": {
                    "request_headers": {
                        "user_agent": self.request.headers.get(
                            "user-agent", "Not provided"
                        ),
                        "origin": self.request.headers.get("origin", "Not provided"),
                        "referer": self.request.headers.get("referer", "Not provided"),
                        "x_forwarded_for": self.request.headers.get(
                            "x-forwarded-for", "Not provided"
                        ),
                    },
                    "security_features": [
                        "Content-Type sniffing protection",
                        "Clickjacking protection",
                        "XSS filtering",
                        "HTTPS enforcement",
                        "Content restrictions",
                        "Referrer policy control",
                        "Feature permissions control",
                        "Custom security headers",
                    ],
                    "recommendations": [
                        "Always use HTTPS in production",
                        "Regularly review and tighten CSP directives",
                        "Monitor CSP violation reports",
                        "Consider HSTS preload for production domains",
                    ],
                },
            }
        )


class ContentNoBotsHandler(JSONHandler):
    @guard_decorator.block_user_agents(["bot", "crawler", "spider", "scraper"])
    async def get(self) -> None:
        self.write_json({"message": "Human users only - bots blocked"})


class ContentJSONOnlyHandler(JSONHandler):
    @guard_decorator.content_type_filter(["application/json"])
    async def post(self) -> None:
        try:
            data = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            data = {}
        self.write_json({"message": "JSON content received", "details": {"data": data}})


class ContentSizeLimitHandler(JSONHandler):
    @guard_decorator.max_request_size(1024 * 100)
    async def post(self) -> None:
        try:
            data = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            data = {}
        self.write_json(
            {
                "message": "Data received within size limit",
                "details": {"size_limit": "100KB", "data": data},
            }
        )


class ContentReferrerHandler(JSONHandler):
    @guard_decorator.require_referrer(
        ["https://example.com", "https://app.example.com"]
    )
    async def get(self) -> None:
        referrer = self.request.headers.get("referer", "No referrer")
        self.write_json(
            {"message": "Valid referrer", "details": {"referrer": referrer}}
        )


async def suspicious_user_agent_validator(
    request: GuardRequest,
) -> GuardResponse | None:
    user_agent = request.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return TornadoGuardResponse(
            status_code=403,
            headers={"Content-Type": "application/json; charset=utf-8"},
            body=_json_dumps({"detail": "Suspicious user agent detected"}).encode(
                "utf-8"
            ),
        )
    return None


class ContentCustomValidationHandler(JSONHandler):
    @guard_decorator.custom_validation(suspicious_user_agent_validator)
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Custom validation passed",
                "details": {"validator": "suspicious_user_agent_validator"},
            }
        )


class AdvancedBusinessHoursHandler(JSONHandler):
    @guard_decorator.time_window(start_time="09:00", end_time="17:00", timezone="UTC")
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Access granted during business hours",
                "details": {"hours": "09:00-17:00 UTC"},
            }
        )


class AdvancedWeekendHandler(JSONHandler):
    @guard_decorator.time_window(start_time="00:00", end_time="23:59", timezone="UTC")
    async def get(self) -> None:
        self.write_json(
            {
                "message": "Weekend access endpoint",
                "details": {"note": "Implement weekend check in time_window"},
            }
        )


class AdvancedHoneypotHandler(JSONHandler):
    @guard_decorator.honeypot_detection(
        ["honeypot_field", "trap_input", "hidden_field"]
    )
    async def post(self) -> None:
        self.write_json(
            {
                "message": "Human user verified",
                "details": {"honeypot_status": "clean"},
            }
        )


class AdvancedSuspiciousHandler(JSONHandler):
    @guard_decorator.suspicious_detection(enabled=True)
    async def get(self) -> None:
        query = self.get_query_argument("query", default=None)
        self.write_json(
            {
                "message": "No suspicious patterns detected",
                "details": {"query": query},
            }
        )


class AdminUnbanHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1"])
    async def post(self) -> None:
        try:
            data = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            data = {}
        ip = data.get("ip", "")
        logger.info(f"Unbanning IP: {ip}")
        self.write_json(
            {
                "message": f"IP {ip} has been unbanned",
                "details": {"action": "unban", "ip": ip},
            }
        )


class AdminStatsHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1"])
    async def get(self) -> None:
        self.write_json(
            {
                "total_requests": 1500,
                "blocked_requests": 75,
                "banned_ips": ["192.168.1.100", "10.0.0.50"],
                "rate_limited_ips": {"192.168.1.200": 5, "172.16.0.10": 3},
                "suspicious_activities": [
                    {
                        "ip": "192.168.1.100",
                        "reason": "SQL injection attempt",
                        "timestamp": datetime.now(timezone.utc),
                    },
                    {
                        "ip": "10.0.0.50",
                        "reason": "Rapid requests",
                        "timestamp": datetime.now(timezone.utc),
                    },
                ],
                "active_rules": {
                    "rate_limit": 30,
                    "rate_window": 60,
                    "auto_ban_threshold": 5,
                    "blocked_clouds": ["AWS", "GCP", "Azure"],
                },
            }
        )


class AdminClearCacheHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1"])
    async def post(self) -> None:
        self.write_json(
            {
                "message": "Security caches cleared",
                "details": {
                    "cleared": ["rate_limit_cache", "ip_ban_cache", "geo_cache"]
                },
            }
        )


class AdminEmergencyModeHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1"])
    async def put(self) -> None:
        try:
            data = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            data = {}
        enable = bool(data.get("enable", False))
        mode = "enabled" if enable else "disabled"
        self.write_json(
            {
                "message": f"Emergency mode {mode}",
                "details": {
                    "emergency_mode": enable,
                    "timestamp": datetime.now(timezone.utc),
                },
            }
        )


class AdminCloudStatusHandler(JSONHandler):
    @guard_decorator.require_ip(whitelist=["127.0.0.1"])
    async def get(self) -> None:
        last_updated: dict[str, str | None] = {}
        for provider, dt in cloud_handler.last_updated.items():
            last_updated[provider] = dt.isoformat() if dt else None
        self.write_json(
            {
                "message": "Cloud provider IP range status",
                "details": {
                    "refresh_interval": security_config.cloud_ip_refresh_interval,
                    "providers": last_updated,
                },
            }
        )


class TestXSSHandler(JSONHandler):
    async def post(self) -> None:
        payload = self.request.body.decode("utf-8", errors="replace")
        self.write_json(
            {
                "message": "XSS test payload processed",
                "details": {"payload": payload, "detected": False},
            }
        )


class TestSQLHandler(JSONHandler):
    async def get(self) -> None:
        query = self.get_query_argument("query", default="")
        self.write_json(
            {
                "message": "SQL injection test processed",
                "details": {"query": query, "detected": False},
            }
        )


class TestPathTraversalHandler(JSONHandler):
    async def get(self, file_path: str) -> None:
        self.write_json(
            {
                "message": "Path traversal test",
                "details": {"path": file_path, "detected": False},
            }
        )


class TestCommandInjectionHandler(JSONHandler):
    async def post(self) -> None:
        command = self.request.body.decode("utf-8", errors="replace")
        self.write_json(
            {
                "message": "Command injection test processed",
                "details": {"command": command, "detected": False},
            }
        )


class TestMixedAttackHandler(JSONHandler):
    async def post(self) -> None:
        try:
            payload = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            payload = {}
        self.write_json(
            {
                "message": "Mixed attack test processed",
                "details": {
                    "xss_test": payload.get("input"),
                    "sql_test": payload.get("query"),
                    "path_test": payload.get("path"),
                    "cmd_test": payload.get("cmd"),
                    "honeypot": payload.get("honeypot_field"),
                },
            }
        )


class EchoWebSocketHandler(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin: str) -> bool:
        return True

    async def on_message(self, message: str | bytes) -> None:
        text = message.decode("utf-8") if isinstance(message, bytes) else message
        await self.write_message(f"Echo: {text}")
        if text == "status":
            await self.write_message(
                json.dumps(
                    {
                        "type": "status",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "security": "active",
                    }
                )
            )

    def on_close(self) -> None:
        logger.info("WebSocket disconnected")


def build_application() -> tornado.web.Application:
    handlers: list[tuple[str, type[tornado.web.RequestHandler]]] = [
        (r"/", RootHandler),
        (r"/basic/?", BasicRootHandler),
        (r"/basic/ip", BasicIPHandler),
        (r"/basic/health", BasicHealthHandler),
        (r"/basic/echo", BasicEchoHandler),
        (r"/access/ip-whitelist", AccessIPWhitelistHandler),
        (r"/access/ip-blacklist", AccessIPBlacklistHandler),
        (r"/access/country-block", AccessCountryBlockHandler),
        (r"/access/country-allow", AccessCountryAllowHandler),
        (r"/access/no-cloud", AccessNoCloudHandler),
        (r"/access/no-aws", AccessNoAWSHandler),
        (r"/access/bypass-demo", AccessBypassHandler),
        (r"/auth/https-only", AuthHttpsHandler),
        (r"/auth/bearer-auth", AuthBearerHandler),
        (r"/auth/api-key", AuthAPIKeyHandler),
        (r"/auth/custom-headers", AuthCustomHeadersHandler),
        (r"/rate/custom-limit", RateCustomLimitHandler),
        (r"/rate/strict-limit", RateStrictLimitHandler),
        (r"/rate/geo-rate-limit", RateGeoHandler),
        (r"/behavior/usage-monitor", BehaviorUsageHandler),
        (r"/behavior/return-monitor/(\d+)", BehaviorReturnMonitorHandler),
        (r"/behavior/suspicious-frequency", BehaviorSuspiciousFrequencyHandler),
        (r"/behavior/behavior-rules", BehaviorComplexHandler),
        (r"/headers/?", HeadersInfoHandler),
        (r"/headers/test-page", HeadersTestPageHandler),
        (r"/headers/csp-report", HeadersCspReportHandler),
        (r"/headers/frame-test", HeadersFrameTestHandler),
        (r"/headers/hsts-info", HeadersHSTSHandler),
        (r"/headers/security-analysis", HeadersAnalysisHandler),
        (r"/content/no-bots", ContentNoBotsHandler),
        (r"/content/json-only", ContentJSONOnlyHandler),
        (r"/content/size-limit", ContentSizeLimitHandler),
        (r"/content/referrer-check", ContentReferrerHandler),
        (r"/content/custom-validation", ContentCustomValidationHandler),
        (r"/advanced/business-hours", AdvancedBusinessHoursHandler),
        (r"/advanced/weekend-only", AdvancedWeekendHandler),
        (r"/advanced/honeypot", AdvancedHoneypotHandler),
        (r"/advanced/suspicious-patterns", AdvancedSuspiciousHandler),
        (r"/admin/unban-ip", AdminUnbanHandler),
        (r"/admin/stats", AdminStatsHandler),
        (r"/admin/clear-cache", AdminClearCacheHandler),
        (r"/admin/emergency-mode", AdminEmergencyModeHandler),
        (r"/admin/cloud-status", AdminCloudStatusHandler),
        (r"/test/xss-test", TestXSSHandler),
        (r"/test/sql-injection", TestSQLHandler),
        (r"/test/path-traversal/(.*)", TestPathTraversalHandler),
        (r"/test/command-injection", TestCommandInjectionHandler),
        (r"/test/mixed-attack", TestMixedAttackHandler),
        (r"/ws", EchoWebSocketHandler),
    ]
    return tornado.web.Application(
        handlers,
        security_middleware=security_middleware,
        guard_decorator=guard_decorator,
        default_handler_class=JSONHandler,
    )


async def main() -> None:
    logger.info("TornadoAPI Guard Example starting up...")
    logger.info(
        "Security features enabled: rate_limiting=%s ip_banning=%s "
        "penetration_detection=%s redis=%s agent=%s",
        security_config.enable_rate_limiting,
        security_config.enable_ip_banning,
        security_config.enable_penetration_detection,
        security_config.enable_redis,
        security_config.enable_agent,
    )
    await security_middleware.initialize()
    app = build_application()
    server = tornado.httpserver.HTTPServer(app)
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    server.listen(port, address=host)
    logger.info("Listening on http://%s:%s", host, port)
    try:
        await asyncio.Event().wait()
    finally:
        logger.info("TornadoAPI Guard Example shutting down...")
        server.stop()
        await security_middleware.reset()


if __name__ == "__main__":
    asyncio.run(main())
