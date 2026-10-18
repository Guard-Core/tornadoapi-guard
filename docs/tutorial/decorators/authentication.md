---

title: Authentication Decorators - TornadoAPI Guard
description: Learn how to use authentication decorators for HTTPS enforcement, auth requirements, and API key validation
keywords: authentication, https, api keys, security headers, authorization decorators
---

Authentication Decorators
=========================

Authentication decorators provide route-level authentication and authorization controls. These decorators help ensure secure communication and proper authentication for sensitive endpoints.

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

HTTPS Enforcement
-----------------

Force secure connections for specific routes:

. Basic HTTPS Requirement
-----------------------

```python
class AuthHttpsHandler(SecurityHandler):
    @guard_deco.require_https()
    async def post(self) -> None:
        self.write({"token": "secure_jwt_token"})
```

. Combined with Global HTTPS
--------------------------

```python
# Global HTTPS enforcement
config = SecurityConfig(enforce_https=True)


class AuthPublicHttpsHandler(SecurityHandler):
    @guard_deco.require_https()  # Explicit requirement
    async def get(self) -> None:
        self.write({"data": "definitely secure"})
```

. HTTPS for Sensitive Operations
-----------------------------

```python
class AuthPaymentHandler(SecurityHandler):
    @guard_deco.require_https()
    async def post(self) -> None:
        self.write({"status": "payment processed securely"})


class AuthPasswordHandler(SecurityHandler):
    @guard_deco.require_https()
    async def post(self) -> None:
        self.write({"status": "password updated"})
```

___

Authentication Requirements
---------------------------

Enforce different types of authentication:

. Bearer Token Authentication
--------------------------

```python
class AuthBearerHandler(SecurityHandler):
    @guard_deco.require_auth(type="bearer")
    async def get(self) -> None:
        self.write({"profile": "user data"})
```

. Multiple Authentication Types
----------------------------

```python
class AuthAdminHandler(SecurityHandler):
    @guard_deco.require_auth(type="bearer")
    async def get(self) -> None:
        self.write({"admin": "data"})


class AuthServiceHandler(SecurityHandler):
    @guard_deco.require_auth(type="basic")
    async def get(self) -> None:
        self.write({"service": "data"})
```

. Combined HTTPS and Auth
----------------------

```python
class AuthSecureAdminHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.require_auth(type="bearer")
    async def post(self) -> None:
        self.write({"data": "doubly secure"})
```

___

API Key Authentication
----------------------

Require API keys for endpoint access:

. Basic API Key Requirement
------------------------

```python
class AuthAPIKeyHandler(SecurityHandler):
    @guard_deco.api_key_auth(header_name="X-API-Key")
    async def get(self) -> None:
        self.write({"data": "api key required"})
```

. Custom Header Names
-------------------

```python
class AuthCustomKeyHandler(SecurityHandler):
    @guard_deco.api_key_auth(header_name="X-Custom-Auth")
    async def get(self) -> None:
        self.write({"data": "custom header auth"})


class AuthServiceKeyHandler(SecurityHandler):
    @guard_deco.api_key_auth(header_name="Authorization-Key")
    async def get(self) -> None:
        self.write({"data": "service authentication"})
```

. Multiple Key Requirements
-------------------------

```python
class AuthDualKeyHandler(SecurityHandler):
    @guard_deco.api_key_auth(header_name="X-API-Key")
    @guard_deco.api_key_auth(header_name="X-Service-Key")
    async def get(self) -> None:
        self.write({"data": "dual key authentication"})
```

___

Required Headers
----------------

Enforce specific headers for authentication and security:

. Security Headers
----------------

```python
class AuthCustomHeadersHandler(SecurityHandler):
    @guard_deco.require_headers(
        {
            "X-Requested-With": "XMLHttpRequest",
            "X-CSRF-Token": "required",
        }
    )
    async def get(self) -> None:
        self.write({"data": "csrf protected"})
```

. API Versioning Headers
----------------------

```python
class AuthVersionedHandler(SecurityHandler):
    @guard_deco.require_headers(
        {
            "Accept": "application/vnd.api+json",
            "API-Version": "2.0",
        }
    )
    async def get(self) -> None:
        self.write({"data": "version 2.0", "format": "json-api"})
```

. Client Identification
----------------------

```python
class AuthClientHandler(SecurityHandler):
    @guard_deco.require_headers(
        {
            "X-Client-ID": "required",
            "X-Client-Version": "required",
            "User-Agent": "required",
        }
    )
    async def get(self) -> None:
        self.write({"data": "client identified"})
```

___

Combined Authentication Patterns
--------------------------------

Stack multiple authentication decorators for comprehensive security:

. Maximum Security Endpoint
-------------------------

```python
class AuthCriticalAdminHandler(SecurityHandler):
    @guard_deco.require_https()  # Secure connection
    @guard_deco.require_auth(type="bearer")  # Bearer token
    @guard_deco.api_key_auth(header_name="X-Admin-Key")  # Admin API key
    @guard_deco.require_headers(
        {
            "X-CSRF-Token": "required",  # CSRF protection
            "X-Request-ID": "required",  # Request tracking
        }
    )
    async def post(self) -> None:
        self.write({"status": "critical operation completed"})
```

. Service-to-Service Authentication
---------------------------------

```python
class AuthWebhookHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.api_key_auth(header_name="X-Service-Key")
    @guard_deco.require_headers(
        {
            "X-Signature": "required",
            "Content-Type": "application/json",
        }
    )
    async def post(self) -> None:
        self.write({"status": "webhook processed"})
```

. Client Application Authentication
---------------------------------

```python
class AuthMobileHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.require_auth(type="bearer")
    @guard_deco.require_headers(
        {
            "X-App-Version": "required",
            "X-Device-ID": "required",
            "Accept": "application/json",
        }
    )
    async def get(self) -> None:
        self.write({"data": "mobile app data"})
```

___

Authentication Flow Examples
----------------------------

. Login Endpoint
--------------

```python
class LoginHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.require_headers(
        {
            "Content-Type": "application/json",
            "X-CSRF-Token": "required",
        }
    )
    async def post(self) -> None:
        self.write({"token": "jwt_token", "expires": "3600"})
```

. Token Refresh
-------------

```python
class RefreshHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.require_auth(type="bearer")
    @guard_deco.require_headers({"X-Refresh-Token": "required"})
    async def post(self) -> None:
        self.write({"token": "new_jwt_token", "expires": "3600"})
```

. Logout
------

```python
class LogoutHandler(SecurityHandler):
    @guard_deco.require_auth(type="bearer")
    @guard_deco.require_headers({"X-CSRF-Token": "required"})
    async def post(self) -> None:
        self.write({"status": "logged out"})
```

___

API Gateway Pattern
-------------------

Different authentication for different API tiers:

. Public API
----------

```python
class PublicStatusHandler(SecurityHandler):
    @guard_deco.api_key_auth(header_name="X-Public-Key")
    async def get(self) -> None:
        self.write({"status": "public api active"})
```

. Partner API
-----------

```python
class PartnerDataHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.api_key_auth(header_name="X-Partner-Key")
    @guard_deco.require_headers({"X-Partner-ID": "required"})
    async def get(self) -> None:
        self.write({"data": "partner exclusive"})
```

. Internal API
------------

```python
class InternalAdminHandler(SecurityHandler):
    @guard_deco.require_https()
    @guard_deco.require_auth(type="bearer")
    @guard_deco.api_key_auth(header_name="X-Internal-Key")
    @guard_deco.require_headers(
        {
            "X-Service-Name": "required",
            "X-Request-Context": "required",
        }
    )
    async def get(self) -> None:
        self.write({"data": "internal admin access"})
```

___

Error Handling
--------------

Authentication decorators return specific HTTP status codes:

- **400 Bad Request**: Missing required headers
- **401 Unauthorized**: Invalid or missing authentication
- **403 Forbidden**: Valid auth but insufficient permissions
- **301/302 Redirect**: HTTP to HTTPS redirect

. Custom Error Responses
----------------------

```python
config = SecurityConfig(
    custom_error_responses={
        400: "Missing required authentication headers",
        401: "Invalid authentication credentials",
        403: "Insufficient privileges for this operation",
    }
)
```

___

Best Practices
--------------

. Layer Authentication Methods
----------------------------

Use multiple authentication factors for sensitive operations:

```python
# Good: Multiple authentication layers
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-API-Key")

# Avoid: Single authentication method for sensitive data
# @guard_deco.api_key_auth(header_name="X-API-Key")  # Too weak for sensitive ops
```

. Always Use HTTPS for Authentication
----------------------------------

Never transmit credentials over unencrypted connections:

```python
# Good: HTTPS enforced for login
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")

# Bad: Authentication without HTTPS
# @guard_deco.require_auth(type="bearer")  # Credentials could be intercepted
```

. Validate Header Content
-----------------------

Don't just check for presence, validate the content:

```python
# The middleware handles presence validation
@guard_deco.require_headers({"X-API-Key": "required"})

# Your handler should validate the actual key value
class ValidatedAPIKeyHandler(SecurityHandler):
    @guard_deco.require_headers({"X-API-Key": "required"})
    async def get(self) -> None:
        api_key = self.request.headers.get("X-API-Key")
        if api_key not in VALID_KEYS:
            self.set_status(401)
            self.write({"error": "invalid key"})
            return
        self.write({"data": "ok"})
```

. Use Appropriate Authentication for Each Endpoint
----------------------------------------------

Match authentication strength to data sensitivity:

```python
# Public data: Light authentication
@guard_deco.api_key_auth(header_name="X-Public-Key")

# User data: Medium authentication
@guard_deco.require_auth(type="bearer")

# Admin data: Heavy authentication
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-Admin-Key")
```

___

Testing Authentication
----------------------

Test your authentication decorators with Tornado's `AsyncHTTPTestCase`:

```python
from tornado.testing import AsyncHTTPTestCase


class AuthTests(AsyncHTTPTestCase):
    def get_app(self):
        return build_application()

    def test_api_key_required(self):
        response = self.fetch("/api/key-protected")
        self.assertEqual(response.code, 400)

        response = self.fetch(
            "/api/key-protected",
            headers={"X-API-Key": "valid-key"},
        )
        self.assertEqual(response.code, 200)
```

___

Next Steps
----------

Now that you understand authentication decorators, explore other security features:

- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Rate Limiting Decorators](rate-limiting.md)** - Request rate controls
- **[Behavioral Analysis](behavioral.md)** - Monitor authentication patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Authentication API Documentation](../../api/decorators.md#authenticationmixin).
