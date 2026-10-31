---

title: Access Control Decorators - TornadoAPI Guard
description: Learn how to use access control decorators for IP filtering, geographic restrictions, and cloud provider blocking
keywords: access control, ip filtering, geographic restrictions, cloud blocking, security decorators
---

Access Control Decorators
==========================

Access control decorators allow you to restrict access to specific endpoints based on IP addresses, geographic location, and cloud providers. These decorators provide fine-grained control over who can access your routes.

All examples below assume the following setup exists once at module level:

```python
from tornadoapi_guard import (
    SecurityConfig,
    SecurityDecorator,
    SecurityHandler,
    SecurityMiddleware,
)

config = SecurityConfig(
    # geo source for block_countries, allow_countries and geo_rate_limit
    ipinfo_token="your_ipinfo_token_here",
)
middleware = SecurityMiddleware(config=config)
guard_deco = SecurityDecorator(config)
middleware.set_decorator_handler(guard_deco)
```

___

IP Address Filtering
--------------------

Control access based on specific IP addresses or CIDR ranges:

. IP Whitelist
------------

Only allow access from specific IP addresses:

```python
class AccessIPWhitelistHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["192.168.1.0/24", "10.0.0.1"])
    async def get(self) -> None:
        self.write({"message": "Internal network access only"})
```

. IP Blacklist
------------

Block specific IP addresses while allowing others:

```python
class AccessIPBlacklistHandler(SecurityHandler):
    @guard_deco.require_ip(blacklist=["203.0.113.0/24", "198.51.100.1"])
    async def get(self) -> None:
        self.write({"message": "Public access except blocked IPs"})
```

. Combined IP Rules
-----------------

Use both whitelist and blacklist together:

```python
class AccessRestrictedHandler(SecurityHandler):
    @guard_deco.require_ip(
        whitelist=["192.168.0.0/16"],  # Allow internal network
        blacklist=["192.168.1.100"],  # Except this specific IP
    )
    async def get(self) -> None:
        self.write({"data": "Carefully controlled access"})
```

___

Geographic Restrictions
-----------------------

Control access based on the user's country location:

. Block Specific Countries
------------------------

Prevent access from certain countries:

```python
class AccessCountryBlockHandler(SecurityHandler):
    @guard_deco.block_countries(["CN", "RU", "IR", "KP"])
    async def get(self) -> None:
        self.write({"data": "Compliance-restricted content"})
```

. Allow Only Specific Countries
-----------------------------

Restrict access to certain countries only:

```python
class AccessUSOnlyHandler(SecurityHandler):
    @guard_deco.allow_countries(["US"])
    async def get(self) -> None:
        self.write({"data": "US-only content"})


class AccessEUOnlyHandler(SecurityHandler):
    @guard_deco.allow_countries(["GB", "DE", "FR", "IT", "ES", "NL"])
    async def get(self) -> None:
        self.write({"data": "EU-only content"})
```

. Regional Access
---------------

Create region-specific endpoints:

```python
class AccessNorthAmericaHandler(SecurityHandler):
    @guard_deco.allow_countries(["US", "CA", "MX"])
    async def get(self) -> None:
        self.write({"data": "North America region"})


class AccessAsiaPacificHandler(SecurityHandler):
    @guard_deco.allow_countries(["JP", "KR", "AU", "SG", "IN"])
    async def get(self) -> None:
        self.write({"data": "Asia-Pacific region"})
```

___

Cloud Provider Blocking
------------------------

Block requests originating from cloud provider IP ranges:

. Block Specific Cloud Providers
-----------------------------

```python
class AccessNoAWSHandler(SecurityHandler):
    @guard_deco.block_clouds(["AWS", "GCP"])
    async def get(self) -> None:
        self.write({"data": "No cloud provider access"})
```

. Block All Major Cloud Providers
-------------------------------

```python
class AccessResidentialOnlyHandler(SecurityHandler):
    @guard_deco.block_clouds(["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"])
    async def get(self) -> None:
        self.write({"data": "Residential IP addresses only"})
```

. Block All Supported Clouds
--------------------------

```python
class AccessNoCloudHandler(SecurityHandler):
    @guard_deco.block_clouds()  # Blocks all supported cloud providers
    async def get(self) -> None:
        self.write({"data": "No automated/cloud access"})
```

___

Bypassing Security Checks
-------------------------

Selectively disable specific security checks for certain routes:

. Valid Bypass Tokens
-------------------

| Token | Skips |
|---|---|
| `all` | The entire security pipeline for the route |
| `ip_ban` | The standing banned-IP check |
| `ip` | Global IP whitelist/blacklist, blocked countries and blocked clouds |
| `clouds` | The cloud provider check |
| `rate_limit` | Global, endpoint, route and geo rate limiting |
| `penetration` | Detection engine / suspicious activity |

Unknown tokens are ignored, so a typo leaves the check fully enforced rather than raising. There is no country-only token: country blocking is bypassed by `ip`, which also lifts the global IP whitelist and blacklist for that route.

. Bypass Specific Checks
----------------------

```python
class AccessHealthHandler(SecurityHandler):
    @guard_deco.bypass(["rate_limit", "ip"])  # Bypass rate limiting and IP checks
    async def get(self) -> None:
        self.write({"status": "healthy"})
```

. Bypass All Security
-------------------

```python
class AccessPublicHealthHandler(SecurityHandler):
    @guard_deco.bypass(["all"])  # Bypass all security checks
    async def get(self) -> None:
        self.write({"status": "public health endpoint"})
```

. Common Bypass Scenarios
-----------------------

```python
class MetricsHandler(SecurityHandler):
    @guard_deco.bypass(["rate_limit"])
    async def get(self) -> None:
        self.write({"metrics": "data"})


class PublicDocsHandler(SecurityHandler):
    @guard_deco.bypass(["ip"])
    async def get(self) -> None:
        self.write({"docs": "public documentation"})
```

___

Combining Access Controls
-------------------------

Stack multiple access control decorators for comprehensive protection:

. Multi-Layer Protection
----------------------

```python
class AdminSensitiveHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["10.0.0.0/8"])  # Internal network only
    @guard_deco.allow_countries(["US", "CA"])  # North America only
    @guard_deco.block_clouds(["AWS", "GCP"])  # No cloud providers
    async def post(self) -> None:
        self.write({"data": "Maximum security endpoint"})
```

. Tiered Access Control
---------------------

```python
class FinancialTransferHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["192.168.1.0/24"])  # Company network only
    @guard_deco.allow_countries(["US"])  # US jurisdiction only
    @guard_deco.block_clouds()  # No cloud/automation
    async def post(self) -> None:
        self.write({"status": "transfer initiated"})


class UserProfileHandler(SecurityHandler):
    @guard_deco.block_countries(["CN", "RU", "IR"])  # Block certain countries
    @guard_deco.block_clouds(["AWS", "GCP"])  # Block major clouds
    async def get(self) -> None:
        self.write({"profile": "user data"})


class PublicContentHandler(SecurityHandler):
    @guard_deco.block_clouds(["DigitalOcean"])  # Block only specific providers
    async def get(self) -> None:
        self.write({"content": "public information"})
```

___

Advanced Patterns
-----------------

. Geographic Failover
-------------------

Allow broader access if primary regions fail:

```python
class PrimaryRegionHandler(SecurityHandler):
    @guard_deco.allow_countries(["US", "CA"])
    async def get(self) -> None:
        self.write({"region": "primary"})


class FallbackRegionHandler(SecurityHandler):
    @guard_deco.allow_countries(["GB", "DE", "AU"])
    async def get(self) -> None:
        self.write({"region": "fallback"})
```

. Time-Based Geographic Access
----------------------------

Different geographic rules for different times:

```python
class BusinessHoursHandler(SecurityHandler):
    @guard_deco.allow_countries(["US"])
    @guard_deco.time_window("09:00", "17:00", "EST")
    async def get(self) -> None:
        self.write({"data": "business hours access"})


class AfterHoursHandler(SecurityHandler):
    @guard_deco.allow_countries(["US", "CA", "GB"])
    async def get(self) -> None:
        self.write({"data": "after hours access"})
```

___

Error Handling
--------------

Access control decorators return specific HTTP status codes:

- **403 Forbidden**: IP not in whitelist, IP in blacklist
- **403 Forbidden**: Country blocked or not in allowed list
- **403 Forbidden**: Cloud provider IP detected and blocked

. Custom Error Messages
---------------------

```python
config = SecurityConfig(
    custom_error_responses={
        403: "Access denied: Geographic restrictions apply",
    }
)
```

___

Best Practices
--------------

. Start Restrictive, Then Open Up
-------------------------------

Begin with strict controls and gradually relax as needed:

```python
# Start with company network only
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])

# Then add specific external IPs
@guard_deco.require_ip(whitelist=["10.0.0.0/8", "203.0.113.100"])

# Finally add geographic controls
@guard_deco.allow_countries(["US", "CA"])
```

. Layer Different Types of Controls
---------------------------------

Combine IP, geographic, and cloud controls for defense in depth:

```python
class DefenceInDepthHandler(SecurityHandler):
    @guard_deco.require_ip(whitelist=["192.168.0.0/16"])  # Internal network
    @guard_deco.allow_countries(["US"])  # US only
    @guard_deco.block_clouds()  # No automation
    async def get(self) -> None:
        self.write({"data": "secure"})
```

. Use Bypass Strategically
------------------------

Only bypass security for truly public endpoints:

```python
# Good: Health checks need to work from monitoring systems
@guard_deco.bypass(["rate_limit"])

# Bad: Don't bypass security for sensitive data
# @guard_deco.bypass(["all"])  # Avoid this for sensitive endpoints
```

. Test Geographic Controls
------------------------

Test with VPN connections from different countries to verify behavior:

```python
# Ensure your geographic controls work as expected
@guard_deco.allow_countries(["US", "CA"])
# Test: Connect via VPN from blocked country, should get 403
```

___

Troubleshooting
--------------

. Common Issues
-------------

1. VPN/Proxy Detection: Users behind VPNs may be incorrectly geo-located
2. Cloud Provider Classification: Some legitimate users may come from cloud IPs
3. IP Range Conflicts: Overlapping whitelist/blacklist rules

. Debugging Tips
--------------

```python
# Enable detailed logging to see why access was denied
config = SecurityConfig(
    log_suspicious_level="DEBUG",
    log_request_level="INFO",
)

# Check logs for messages like:
# "IP not allowed by route config: 203.0.113.1"
# "Blocked cloud provider IP: 54.239.28.85"
```

___

Next Steps
----------

Now that you understand access control decorators, explore other security features:

- **[Authentication Decorators](authentication.md)** - HTTPS and auth requirements
- **[Rate Limiting Decorators](rate-limiting.md)** - Custom rate controls
- **[Behavioral Analysis](behavioral.md)** - Monitor usage patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Access Control API Documentation](../../api/decorators.md#accesscontrolmixin).
