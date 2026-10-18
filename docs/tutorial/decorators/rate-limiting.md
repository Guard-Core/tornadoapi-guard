---

title: Rate Limiting Decorators - TornadoAPI Guard
description: Learn how to use rate limiting decorators for custom request rate controls and geographic rate limiting
keywords: rate limiting, request throttling, geographic limits, api rate control, security decorators
---

Rate Limiting Decorators
=========================

Rate limiting decorators allow you to apply custom rate limits to specific endpoints, overriding global settings and providing fine-grained control over request frequencies. These decorators help prevent abuse and ensure fair usage of your API resources.

All examples below assume the following setup exists once at module level:

```python
from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
)

config = SecurityConfig()
middleware = SecurityMiddleware(config=config)
guard_deco = SecurityDecorator(config)
middleware.set_decorator_handler(guard_deco)
```

___

Basic Rate Limiting
-------------------

Apply custom rate limits to specific routes:

. Simple Rate Limit
----------------------------

```python
class RateCustomLimitHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
    async def get(self) -> None:
        self.write({"data": "rate limited"})
```

. Override Global Settings
----------------------------

```python
# Global rate limit: 100 requests/hour
config = SecurityConfig(rate_limit_requests=100, rate_limit_window=3600)


class RatePublicHandler(SecurityHandler):
    async def get(self) -> None:
        # Uses global: 100 requests/hour
        self.write({"data": "public"})


class RateStrictLimitHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=5, window=300)  # Override: 5 requests/5min
    async def get(self) -> None:
        # Uses decorator: 5 requests/5min
        self.write({"data": "strictly limited"})
```

. Different Limits for Different Operations
-----------------------------------------

```python
class RateReadHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=100, window=3600)  # 100 reads/hour
    async def get(self) -> None:
        self.write({"data": "read operation"})


class RateWriteHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10, window=3600)  # 10 writes/hour
    async def post(self) -> None:
        self.write({"status": "write operation"})


class RateDeleteHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=5, window=3600)  # 5 deletes/hour
    async def delete(self) -> None:
        self.write({"status": "delete operation"})
```

___

Endpoint-Specific Rate Limits
-------------------

Tailor rate limits to endpoint sensitivity and usage patterns:

. Authentication Endpoints
------------------------

```python
class LoginHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=5, window=300)  # 5 attempts per 5 minutes
    async def post(self) -> None:
        self.write({"token": "jwt_token"})


class RegisterHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=3, window=3600)  # 3 registrations per hour
    async def post(self) -> None:
        self.write({"status": "user created"})


class ForgotPasswordHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=2, window=3600)  # 2 reset requests per hour
    async def post(self) -> None:
        self.write({"status": "reset email sent"})
```

. Sensitive Operations
------------------------

```python
class PaymentHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=3, window=600)  # 3 payments per 10 minutes
    async def post(self) -> None:
        self.write({"status": "payment processed"})


class AdminBanHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10, window=3600)  # 10 bans per hour
    async def post(self) -> None:
        self.write({"status": "user banned"})


class AdminPurgeHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=1, window=86400)  # 1 purge per day
    async def delete(self) -> None:
        self.write({"status": "data purged"})
```

. Resource-Intensive Operations
-----------------------------

```python
class ExportHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=2, window=3600)  # 2 exports per hour
    async def post(self) -> None:
        self.write({"status": "export started"})


class ReportHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=5, window=3600)  # 5 reports per hour
    async def post(self) -> None:
        self.write({"status": "report generating"})


class ComplexSearchHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=20, window=300)  # 20 searches per 5 minutes
    async def post(self) -> None:
        self.write({"results": "search results"})
```

___

Geographic Rate Limiting
-------------------------

Apply different rate limits based on user's geographic location:

. Country-Specific Limits
-----------------------

```python
class RateGeoHandler(SecurityHandler):
    @guard_deco.geo_rate_limit(
        {
            "US": (100, 3600),  # 100 requests/hour for US
            "CA": (100, 3600),  # 100 requests/hour for Canada
            "GB": (80, 3600),  # 80 requests/hour for UK
            "DE": (80, 3600),  # 80 requests/hour for Germany
            "CN": (10, 3600),  # 10 requests/hour for China
            "*": (50, 3600),  # 50 requests/hour for others
        }
    )
    async def get(self) -> None:
        self.write({"data": "geographic rate limited"})
```

. Tiered Geographic Access
------------------------

```python
class PremiumGeoHandler(SecurityHandler):
    @guard_deco.geo_rate_limit(
        {
            # Tier 1: Premium countries
            "US": (200, 3600),
            "CA": (200, 3600),
            "GB": (200, 3600),
            "DE": (200, 3600),
            "AU": (200, 3600),
            # Tier 2: Standard countries
            "FR": (100, 3600),
            "IT": (100, 3600),
            "ES": (100, 3600),
            "JP": (100, 3600),
            # Tier 3: Limited countries
            "IN": (50, 3600),
            "BR": (50, 3600),
            "MX": (50, 3600),
            # Default: Very limited
            "*": (20, 3600),
        }
    )
    async def get(self) -> None:
        self.write({"data": "premium geographic content"})
```

. Regional Business Hours
-----------------------

```python
class SupportGeoHandler(SecurityHandler):
    @guard_deco.geo_rate_limit(
        {
            "US": (50, 3600),  # US business hours
            "EU": (40, 3600),  # European business hours
            "APAC": (30, 3600),  # Asia-Pacific business hours
            "*": (20, 3600),  # Outside business regions
        }
    )
    async def get(self) -> None:
        self.write({"data": "support information"})
```

___

Time-Based Rate Limiting
------------------------

Combine rate limiting with time windows:

. Business Hours vs After Hours
-----------------------------

```python
class BusinessHoursOrderHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=50, window=3600)  # 50 orders/hour during business
    @guard_deco.time_window("09:00", "17:00", "EST")
    async def post(self) -> None:
        self.write({"status": "business hours order"})


class AfterHoursOrderHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=20, window=3600)  # 20 orders/hour after hours
    async def post(self) -> None:
        self.write({"status": "after hours order"})
```

. Weekend vs Weekday
------------------

```python
class WeekdayDataHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=100, window=3600)
    async def get(self) -> None:
        self.write({"data": "weekday business data"})


class WeekendDataHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=30, window=3600)
    async def get(self) -> None:
        self.write({"data": "weekend personal data"})
```

___

Advanced Rate Limiting Patterns
-------------------------------

. Graduated Rate Limits
---------------------

Different limits based on endpoint complexity:

```python
class SimpleStatusHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=1000, window=3600)
    async def get(self) -> None:
        self.write({"status": "ok"})


class MediumDataHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=100, window=3600)
    async def get(self) -> None:
        self.write({"data": "medium complexity"})


class ComplexAnalysisHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10, window=3600)
    async def post(self) -> None:
        self.write({"result": "complex analysis"})
```

. User Tier-Based Limits
----------------------

```python
class FreeTierHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=100, window=86400)  # 100 per day
    async def get(self) -> None:
        self.write({"data": "free tier"})


class PremiumTierHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=1000, window=3600)  # 1000 per hour
    async def get(self) -> None:
        self.write({"data": "premium tier"})


class EnterpriseTierHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=10000, window=3600)  # 10000 per hour
    async def get(self) -> None:
        self.write({"data": "enterprise tier"})
```

. API Versioning Rate Limits
--------------------------

```python
class V1DataHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=50, window=3600)
    async def get(self) -> None:
        self.write({"data": "legacy v1", "deprecated": True})


class V2DataHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=100, window=3600)
    async def get(self) -> None:
        self.write({"data": "current v2"})


class V3DataHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=200, window=3600)
    async def get(self) -> None:
        self.write({"data": "beta v3"})
```

___

Combining with Other Decorators
-------------------------------

Stack rate limiting with other security measures:

. Rate Limiting + Access Control
------------------------------

```python
class AdminActionHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
    @guard_deco.rate_limit(requests=20, window=3600)  # 20 actions per hour
    async def post(self) -> None:
        self.write({"status": "admin action completed"})
```

. Rate Limiting + Authentication
-----------------------------

```python
class UserProfileHandler(SecurityHandler):
    @guard_deco.require_auth(type="bearer")
    @guard_deco.rate_limit(requests=60, window=3600)  # 60 requests per hour
    async def get(self) -> None:
        self.write({"profile": "user data"})
```

. Rate Limiting + Behavioral Analysis
----------------------------------

```python
class GameActionHandler(SecurityHandler):
    @guard_deco.rate_limit(requests=100, window=3600)  # 100 actions per hour
    @guard_deco.usage_monitor(max_calls=50, window=300)  # Monitor for burst usage
    async def post(self) -> None:
        self.write({"result": "game action completed"})
```

___

Error Handling
--------------

Rate limiting decorators return specific HTTP status codes:

- **429 Too Many Requests**: Rate limit exceeded
- **503 Service Unavailable**: Rate limiting service unavailable

. Custom Rate Limit Messages
--------------------------

```python
config = SecurityConfig(
    custom_error_responses={
        429: "Rate limit exceeded. Please try again later.",
    }
)

# The response will include rate limit headers:
# X-RateLimit-Limit: 10
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1640995200
```

___

Best Practices
--------------

. Match Limits to Endpoint Purpose
----------------------------------

Consider the business purpose and resource cost:

```python
# Good: High limits for lightweight operations
@guard_deco.rate_limit(requests=1000, window=3600)  # Status checks

# Good: Low limits for expensive operations
@guard_deco.rate_limit(requests=5, window=3600)     # Data exports

# Avoid: Same limits for all endpoints
```

. Consider User Experience
---------------------------

Don't make limits so strict they hurt legitimate users:

```python
# Good: Reasonable limits for normal usage
@guard_deco.rate_limit(requests=100, window=3600)   # Allows normal browsing

# Bad: Too restrictive for normal use
# @guard_deco.rate_limit(requests=5, window=3600)   # Hurts legitimate users
```

. Use Geographic Limits Thoughtfully
------------------------------------

Consider infrastructure and business presence:

```python
# Good: Higher limits where you have better infrastructure
@guard_deco.geo_rate_limit({
    "US": (200, 3600),  # Strong US presence
    "EU": (150, 3600),  # Good EU infrastructure
    "AS": (100, 3600),  # Developing APAC presence
})
```

. Provide Clear Error Messages
----------------------------

Help users understand the limits:

```python
config = SecurityConfig(
    custom_error_responses={
        429: "Rate limit exceeded. You can make 100 requests per hour. Current window resets at {reset_time}.",
    }
)
```

___

Monitoring and Analytics
-----------------------

Track rate limiting effectiveness:

```python
# Enable detailed logging for rate limiting analysis
config = SecurityConfig(
    log_request_level="INFO",  # Log all requests
    log_suspicious_level="WARNING",  # Log rate limit violations
)

# Logs will show:
# "Rate limit exceeded for IP: 203.0.113.1"
# "Rate limit window reset for endpoint: /api/data"
```

___

Testing Rate Limits
-------------------

Test your rate limiting decorators with `AsyncHTTPTestCase`:

```python
import time

from tornado.testing import AsyncHTTPTestCase


class RateLimitTests(AsyncHTTPTestCase):
    def get_app(self):
        return build_application()

    def test_rate_limit(self):
        for _ in range(5):
            response = self.fetch("/api/limited")
            self.assertEqual(response.code, 200)

        response = self.fetch("/api/limited")
        self.assertEqual(response.code, 429)

        time.sleep(301)
        response = self.fetch("/api/limited")
        self.assertEqual(response.code, 200)
```

___

Next Steps
----------

Now that you understand rate limiting decorators, explore other security features:

- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Rate Limiting API Documentation](../../api/decorators.md#ratelimitingmixin).
