---

title: Content Filtering Decorators - TornadoAPI Guard
description: Learn how to use content filtering decorators for request validation, content type filtering, and size limits
keywords: content filtering, request validation, content types, size limits, user agent blocking
---

Content Filtering Decorators
============================

Content filtering decorators allow you to control and validate incoming requests based on content type, size, user agents, referrers, and custom validation logic. These decorators help ensure your endpoints receive only the expected types of requests.

All examples below assume the following setup exists once at module level:

```python
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
    TornadoGuardResponse,
)

config = SecurityConfig()
middleware = SecurityMiddleware(config=config)
guard_deco = SecurityDecorator(config)
middleware.set_decorator_handler(guard_deco)
```

___

Content Type Filtering
----------------------

Control which content types are accepted by specific endpoints:

. Basic Content Type Restriction
------------------------------

```python
class ContentJSONOnlyHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/json"])
    async def post(self) -> None:
        self.write({"received": "json"})
```

. Multiple Content Types
----------------------

```python
class ContentFlexibleHandler(SecurityHandler):
    @guard_deco.content_type_filter(
        [
            "application/json",
            "application/x-www-form-urlencoded",
            "text/plain",
        ]
    )
    async def post(self) -> None:
        self.write({"message": "Multiple content types accepted"})
```

. Image Upload Endpoints
----------------------

```python
class ImageUploadHandler(SecurityHandler):
    @guard_deco.content_type_filter(
        [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
        ]
    )
    async def post(self) -> None:
        self.write({"status": "Image upload endpoint"})


class AvatarUploadHandler(SecurityHandler):
    @guard_deco.content_type_filter(["image/jpeg", "image/png"])
    async def post(self) -> None:
        self.write({"status": "Avatar upload - JPEG/PNG only"})
```

___

Request Size Limits
-------------------

Control the maximum size of incoming requests:

. Basic Size Limits
-----------------

```python
class ContentSizeLimitHandler(SecurityHandler):
    @guard_deco.max_request_size(1024 * 1024)  # 1MB limit
    async def post(self) -> None:
        self.write({"status": "Small file upload"})


class LargeUploadHandler(SecurityHandler):
    @guard_deco.max_request_size(50 * 1024 * 1024)  # 50MB limit
    async def post(self) -> None:
        self.write({"status": "Large file upload"})
```

. Size Limits with Content Types
-----------------------------

```python
class DocumentUploadHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/pdf", "text/plain"])
    @guard_deco.max_request_size(10 * 1024 * 1024)  # 10MB for documents
    async def post(self) -> None:
        self.write({"status": "Document uploaded"})


class MediaUploadHandler(SecurityHandler):
    @guard_deco.content_type_filter(["video/mp4", "audio/mpeg"])
    @guard_deco.max_request_size(100 * 1024 * 1024)  # 100MB for media
    async def post(self) -> None:
        self.write({"status": "Media uploaded"})
```

. Progressive Size Limits
-----------------------

```python
class BasicUploadHandler(SecurityHandler):
    @guard_deco.max_request_size(1024 * 1024)  # 1MB for basic users
    async def post(self) -> None:
        self.write({"tier": "basic", "limit": "1MB"})


class PremiumUploadHandler(SecurityHandler):
    @guard_deco.max_request_size(10 * 1024 * 1024)  # 10MB for premium
    async def post(self) -> None:
        self.write({"tier": "premium", "limit": "10MB"})


class EnterpriseUploadHandler(SecurityHandler):
    @guard_deco.max_request_size(100 * 1024 * 1024)  # 100MB for enterprise
    async def post(self) -> None:
        self.write({"tier": "enterprise", "limit": "100MB"})
```

___

User Agent Blocking
-------------------

Block specific user agent patterns for individual routes:

. Block Bot User Agents
---------------------

```python
class ContentNoBotsHandler(SecurityHandler):
    @guard_deco.block_user_agents(
        [
            r"bot",
            r"crawler",
            r"spider",
            r"scraper",
        ]
    )
    async def get(self) -> None:
        self.write({"message": "Human users only"})
```

. Block Specific Tools
--------------------

```python
class NoAutomationHandler(SecurityHandler):
    @guard_deco.block_user_agents(
        [
            r"curl.*",
            r"wget.*",
            r"Python-urllib.*",
            r"Python-requests.*",
            r"PostmanRuntime.*",
        ]
    )
    async def get(self) -> None:
        self.write({"message": "No automation tools"})
```

. Block Malicious User Agents
---------------------------

```python
class NoScannersHandler(SecurityHandler):
    @guard_deco.block_user_agents(
        [
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"masscan",
            r"nessus",
            r"burp",
        ]
    )
    async def get(self) -> None:
        self.write({"data": "Protected from security scanners"})
```

___

Referrer Requirements
--------------------

Require requests to come from specific referrer domains:

. Basic Referrer Validation
-------------------------

```python
class ContentReferrerHandler(SecurityHandler):
    @guard_deco.require_referrer(["myapp.com", "app.mycompany.com"])
    async def get(self) -> None:
        self.write({"message": "Internal API access"})
```

. Multiple Domain Support
-----------------------

```python
class PartnerReferrerHandler(SecurityHandler):
    @guard_deco.require_referrer(
        [
            "partner1.com",
            "partner2.com",
            "api.partner3.com",
            "subdomain.partner4.com",
        ]
    )
    async def get(self) -> None:
        self.write({"data": "Partner API access"})
```

. Development vs Production Referrers
-----------------------------------

```python
class DevReferrerHandler(SecurityHandler):
    @guard_deco.require_referrer(
        [
            "localhost:3000",
            "127.0.0.1:3000",
            "dev.myapp.com",
        ]
    )
    async def get(self) -> None:
        self.write({"env": "development"})


class ProdReferrerHandler(SecurityHandler):
    @guard_deco.require_referrer(["myapp.com", "www.myapp.com"])
    async def get(self) -> None:
        self.write({"env": "production"})
```

___

Custom Validation
-----------------

Add custom validation logic for complex requirements. Custom validators are async functions that accept a `GuardRequest` (the framework-agnostic request protocol exposed by `guard_core`) and return a `GuardResponse` to block the request or `None` to let it through.

. Header Validation
-----------------

```python
async def validate_api_version(request: GuardRequest) -> GuardResponse | None:
    version = request.headers.get("api-version")
    if not version:
        return TornadoGuardResponse(
            status_code=400,
            headers={"Content-Type": "text/plain"},
            body=b"Missing API-Version header",
        )
    if version not in ["1.0", "2.0", "2.1"]:
        return TornadoGuardResponse(
            status_code=400,
            headers={"Content-Type": "text/plain"},
            body=b"Unsupported API version",
        )
    return None


class VersionedHandler(SecurityHandler):
    @guard_deco.custom_validation(validate_api_version)
    async def get(self) -> None:
        self.write({"message": "Version validated"})
```

. Request Body Validation
-----------------------

```python
import json


async def validate_json_structure(request: GuardRequest) -> GuardResponse | None:
    if request.method not in ("POST", "PUT", "PATCH"):
        return None
    if "application/json" not in request.headers.get("content-type", ""):
        return None
    try:
        body = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return TornadoGuardResponse(
            status_code=400,
            headers={"Content-Type": "text/plain"},
            body=b"Invalid JSON",
        )
    for field in ("user_id", "action", "timestamp"):
        if field not in body:
            return TornadoGuardResponse(
                status_code=400,
                headers={"Content-Type": "text/plain"},
                body=f"Missing required field: {field}".encode("utf-8"),
            )
    if not isinstance(body.get("user_id"), int):
        return TornadoGuardResponse(
            status_code=400,
            headers={"Content-Type": "text/plain"},
            body=b"user_id must be integer",
        )
    return None


class StructuredHandler(SecurityHandler):
    @guard_deco.custom_validation(validate_json_structure)
    async def post(self) -> None:
        self.write({"status": "Structure validated"})
```

. Authentication Token Validation
-------------------------------

```python
async def validate_bearer_token(request: GuardRequest) -> GuardResponse | None:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return TornadoGuardResponse(
            status_code=401,
            headers={"Content-Type": "text/plain"},
            body=b"Invalid authorization format",
        )
    token = auth_header[7:]
    if len(token.split(".")) != 3:
        return TornadoGuardResponse(
            status_code=401,
            headers={"Content-Type": "text/plain"},
            body=b"Invalid token format",
        )
    return None


class TokenValidatedHandler(SecurityHandler):
    @guard_deco.custom_validation(validate_bearer_token)
    async def get(self) -> None:
        self.write({"message": "Token format validated"})
```

___

Combining Content Filters
-------------------------

Stack multiple content filtering decorators for comprehensive validation:

. Complete Upload Endpoint
------------------------

```python
class CompleteUploadHandler(SecurityHandler):
    @guard_deco.content_type_filter(["image/jpeg", "image/png"])
    @guard_deco.max_request_size(5 * 1024 * 1024)  # 5MB limit
    @guard_deco.require_referrer(["myapp.com"])
    @guard_deco.block_user_agents([r"bot", r"curl.*"])
    async def post(self) -> None:
        self.write({"status": "All validations passed"})
```

. API Gateway Pattern
-------------------

```python
class PublicAPIHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/json"])
    @guard_deco.max_request_size(1024 * 1024)
    async def post(self) -> None:
        self.write({"tier": "public"})


class PartnerAPIHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/json", "application/xml"])
    @guard_deco.max_request_size(10 * 1024 * 1024)
    @guard_deco.require_referrer(["partner.com"])
    async def post(self) -> None:
        self.write({"tier": "partner"})


class InternalAPIHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/json"])
    @guard_deco.max_request_size(50 * 1024 * 1024)
    @guard_deco.require_referrer(["internal.mycompany.com"])
    @guard_deco.block_user_agents([r"bot"])
    async def post(self) -> None:
        self.write({"tier": "internal"})
```

___

Advanced Patterns
-----------------

. Content Type Based Routing
--------------------------

```python
class JSONProcessorHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/json"])
    async def post(self) -> None:
        self.write({"processor": "json"})


class XMLProcessorHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/xml", "text/xml"])
    async def post(self) -> None:
        self.write({"processor": "xml"})


class FormProcessorHandler(SecurityHandler):
    @guard_deco.content_type_filter(["application/x-www-form-urlencoded"])
    async def post(self) -> None:
        self.write({"processor": "form"})
```

. Size-Based Processing
---------------------

```python
class SmallProcessorHandler(SecurityHandler):
    @guard_deco.max_request_size(1024 * 1024)
    async def post(self) -> None:
        self.write({"processing": "fast", "queue": "immediate"})


class MediumProcessorHandler(SecurityHandler):
    @guard_deco.max_request_size(10 * 1024 * 1024)
    async def post(self) -> None:
        self.write({"processing": "normal", "queue": "standard"})


class LargeProcessorHandler(SecurityHandler):
    @guard_deco.max_request_size(100 * 1024 * 1024)
    async def post(self) -> None:
        self.write({"processing": "slow", "queue": "background"})
```

___

Error Handling
--------------

Content filtering decorators return specific HTTP status codes:

- **400 Bad Request**: Missing required headers, invalid content
- **413 Payload Too Large**: Request size exceeds limit
- **415 Unsupported Media Type**: Content type not allowed
- **403 Forbidden**: User agent blocked, referrer not allowed

. Custom Error Messages
---------------------

```python
config = SecurityConfig(
    custom_error_responses={
        400: "Request validation failed",
        413: "File too large for this endpoint",
        415: "Content type not supported",
        403: "Request source not authorized",
    }
)
```

___

Best Practices
--------------

. Layer Content Controls
----------------------

Apply multiple content filters for defense in depth:

```python
@guard_deco.content_type_filter(["application/json"])  # Only JSON
@guard_deco.max_request_size(1024 * 1024)              # Size limit
@guard_deco.require_referrer(["myapp.com"])            # Trusted source
@guard_deco.block_user_agents([r"bot"])            # No bots
```

. Match Limits to Functionality
-----------------------------

Set appropriate size limits based on expected use:

```python
# Text API - small limit
@guard_deco.max_request_size(64 * 1024)  # 64KB

# Image upload - medium limit
@guard_deco.max_request_size(5 * 1024 * 1024)  # 5MB

# Video upload - large limit
@guard_deco.max_request_size(100 * 1024 * 1024)  # 100MB
```

. Use Specific Content Type Lists
------------------------------

Be explicit about allowed content types:

```python
# Good: Specific types
@guard_deco.content_type_filter(["image/jpeg", "image/png"])

# Avoid: Too permissive
# @guard_deco.content_type_filter(["*/*"])
```

. Validate Referrers Carefully
----------------------------

Include all legitimate sources:

```python
@guard_deco.require_referrer(
    [
        "myapp.com",
        "www.myapp.com",
        "app.myapp.com",
        "mobile.myapp.com",  # Don't forget mobile subdomain
    ]
)
```

___

Testing Content Filters
-----------------------

Test your content filtering decorators with `AsyncHTTPTestCase`:

```python
from tornado.testing import AsyncHTTPTestCase


class ContentTests(AsyncHTTPTestCase):
    def get_app(self):
        return build_application()

    def test_content_type_filter(self):
        response = self.fetch(
            "/api/json-only",
            method="POST",
            body="plain text",
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(response.code, 415)

        response = self.fetch(
            "/api/json-only",
            method="POST",
            body='{"data": "test"}',
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.code, 200)

    def test_size_limit(self):
        large_data = "x" * (2 * 1024 * 1024)
        response = self.fetch(
            "/api/small-upload",
            method="POST",
            body=large_data,
        )
        self.assertEqual(response.code, 413)

    def test_user_agent_block(self):
        response = self.fetch(
            "/api/human-only",
            headers={"User-Agent": "GoogleBot/1.0"},
        )
        self.assertEqual(response.code, 403)
```

___

Next Steps
----------

Now that you understand content filtering decorators, explore other security features:

- **[Advanced Decorators](advanced.md)** - Time windows and detection controls
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements

For complete API reference, see the [Content Filtering API Documentation](../../api/decorators.md#contentfilteringmixin).
