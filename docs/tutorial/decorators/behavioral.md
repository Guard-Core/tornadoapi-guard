---

title: Behavioral Analysis Decorators - TornadoAPI Guard
description: Learn how to use behavioral analysis decorators for usage monitoring, return pattern detection, and anomaly analysis
keywords: behavioral analysis, usage monitoring, pattern detection, anomaly detection, security decorators
---

Behavioral Analysis Decorators
==============================

Behavioral analysis decorators provide advanced monitoring capabilities to detect suspicious usage patterns, automated behavior, and potential abuse of your API endpoints. These decorators help identify bots, scrapers, and malicious users through behavioral analysis.

All examples below assume the following setup exists once at module level:

```python
from tornadoapi_guard import (
    BehaviorRule,
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

Usage Monitoring
----------------

Monitor how frequently individual IPs access specific endpoints:

. Basic Usage Monitoring
----------------------

```python
class BehaviorUsageHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")
    async def get(self) -> None:
        self.write({"data": "sensitive information"})
```

. Gaming Endpoint Protection
--------------------------

```python
class LootboxHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=5, window=3600, action="ban")
    async def post(self) -> None:
        self.write({"reward": "rare_item", "value": 1000})


class DailyRewardHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=1, window=86400, action="ban")
    async def post(self) -> None:
        self.write({"reward": "daily_bonus", "amount": 100})
```

. API Rate Abuse Detection
------------------------

```python
class ExpensiveComputationHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=3, window=3600, action="throttle")
    async def get(self) -> None:
        self.write({"result": "computed_data"})


class SearchHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=100, window=3600, action="alert")
    async def get(self) -> None:
        self.write({"results": "search_data"})
```

___

Return Pattern Monitoring
-------------------------

Detect when the same IP receives specific responses too frequently:

. Win/Success Pattern Detection
----------------------------

```python
import random


class LotteryHandler(SecurityHandler):
    @guard_deco.return_monitor("win", max_occurrences=2, window=86400, action="ban")
    async def post(self) -> None:
        result = random.choice(["win", "lose", "lose", "lose"])
        self.write({"result": result, "prize": 1000 if result == "win" else 0})
```

. Reward System Protection
------------------------

```python
class SpinHandler(SecurityHandler):
    @guard_deco.return_monitor(
        "rare_item", max_occurrences=3, window=86400, action="ban"
    )
    async def get(self) -> None:
        items = ["common", "common", "rare_item", "common"]
        result = random.choice(items)
        self.write(
            {
                "item": result,
                "rarity": "rare" if result == "rare_item" else "common",
            }
        )
```

. JSON Path Pattern Matching
--------------------------

```python
class BattleHandler(SecurityHandler):
    @guard_deco.return_monitor(
        "json:result.outcome==victory",
        max_occurrences=10,
        window=3600,
        action="alert",
    )
    async def post(self) -> None:
        self.write(
            {
                "result": {
                    "outcome": "victory",
                    "experience": 100,
                    "loot": ["sword", "gold"],
                }
            }
        )
```

. Regex Pattern Detection
----------------------

```python
class ContestHandler(SecurityHandler):
    @guard_deco.return_monitor(
        "regex:(success|winner|prize)",
        max_occurrences=5,
        window=86400,
        action="ban",
    )
    async def get(self) -> None:
        self.write({"status": "success", "message": "Contest entry submitted"})
```

___

Frequency Detection
-------------------

Detect suspiciously high request frequencies:

. Slow Operations Protection
--------------------------

```python
class ReportGenerateHandler(SecurityHandler):
    @guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="ban")
    async def post(self) -> None:
        self.write({"status": "Report generation started"})


class BackupCreateHandler(SecurityHandler):
    @guard_deco.suspicious_frequency(max_frequency=0.017, window=3600, action="ban")
    async def post(self) -> None:
        self.write({"status": "Backup initiated"})
```

. API Scraping Prevention
----------------------

```python
class ProductDetailsHandler(SecurityHandler):
    @guard_deco.suspicious_frequency(max_frequency=2.0, window=300, action="alert")
    async def get(self, product_id: str) -> None:
        self.write({"product": f"Product {product_id}", "price": 99.99})
```

___

Complex Behavioral Analysis
---------------------------

Combine multiple behavioral rules for comprehensive protection:

. Multi-Rule Analysis
-------------------

```python
rules = [
    BehaviorRule("usage", threshold=20, window=3600, action="alert"),
    BehaviorRule(
        "return_pattern",
        threshold=5,
        pattern="win",
        window=86400,
        action="ban",
    ),
    BehaviorRule("frequency", threshold=60, window=300, action="throttle"),
]


class CasinoHandler(SecurityHandler):
    @guard_deco.behavior_analysis(rules)
    async def post(self) -> None:
        self.write({"result": "win", "amount": 500})
```

. Gaming Platform Protection
--------------------------

```python
class GameActionHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=100, window=3600, action="alert")
    @guard_deco.return_monitor(
        "critical_hit", max_occurrences=10, window=3600, action="ban"
    )
    @guard_deco.suspicious_frequency(max_frequency=5.0, window=60, action="throttle")
    async def post(self) -> None:
        self.write({"action": "attack", "result": "critical_hit", "damage": 150})
```

. Financial API Protection
------------------------

```python
class TradingHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
    @guard_deco.return_monitor(
        "profit", max_occurrences=20, window=86400, action="alert"
    )
    @guard_deco.suspicious_frequency(max_frequency=1.0, window=60, action="ban")
    async def post(self) -> None:
        self.write({"status": "executed", "result": "profit", "amount": 1000})
```

___

Action Types
------------

Different actions can be taken when behavioral thresholds are exceeded:

. Ban Action
----------

```python
class BehaviorBanHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=5, window=3600, action="ban")
    async def get(self) -> None:
        self.write({"data": "strictly protected"})
```

. Alert Action
------------

```python
class BehaviorAlertHandler(SecurityHandler):
    @guard_deco.return_monitor(
        "suspicious_pattern", max_occurrences=3, window=3600, action="alert"
    )
    async def get(self) -> None:
        self.write({"status": "monitored"})
```

. Throttle Action
---------------

```python
class BehaviorThrottleHandler(SecurityHandler):
    @guard_deco.suspicious_frequency(max_frequency=2.0, window=300, action="throttle")
    async def get(self) -> None:
        self.write({"data": "throttled access"})
```

. Log Action
----------

```python
class BehaviorLogHandler(SecurityHandler):
    @guard_deco.usage_monitor(max_calls=100, window=3600, action="log")
    async def get(self) -> None:
        self.write({"data": "logged access"})
```

___

Advanced Pattern Formats
------------------------

. Status Code Monitoring
----------------------

```python
class BehaviorReturnMonitorHandler(SecurityHandler):
    @guard_deco.return_monitor(
        "status:200", max_occurrences=1000, window=3600, action="alert"
    )
    async def get(self) -> None:
        self.write({"status": "success"})
```

. Complex JSON Patterns
---------------------

```python
class LevelUpHandler(SecurityHandler):
    @guard_deco.return_monitor(
        "json:user.level>50",
        max_occurrences=5,
        window=86400,
        action="ban",
    )
    async def get(self) -> None:
        self.write({"user": {"level": 55, "experience": 10000}})


class HighValueTransactionHandler(SecurityHandler):
    @guard_deco.return_monitor(
        "json:transaction.amount>10000",
        max_occurrences=3,
        window=86400,
        action="alert",
    )
    async def post(self) -> None:
        self.write({"transaction": {"amount": 15000, "currency": "USD"}})
```

___

Combined Rules via behavior_analysis
------------------------------------

The `behavior_analysis` decorator accepts a list of `BehaviorRule` objects to apply several rules in a single decorator call:

```python
class BehaviorComplexHandler(SecurityHandler):
    @guard_deco.behavior_analysis(
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
        self.write({"message": "Complex behavior analysis active"})
```

___

Best Practices
--------------

. Set Realistic Thresholds
---------------------------

Base thresholds on legitimate user behavior:

```python
# Good: Based on actual usage patterns
@guard_deco.usage_monitor(max_calls=50, window=3600, action="alert")  # 50/hour is reasonable

# Avoid: Too restrictive for normal users
# @guard_deco.usage_monitor(max_calls=3, window=3600, action="ban")  # Too strict
```

. Use Graduated Responses
-----------------------

Start with monitoring, then escalate to blocking:

```python
# Progressive enforcement
@guard_deco.usage_monitor(max_calls=20, window=3600, action="log")      # Log at 20
@guard_deco.usage_monitor(max_calls=50, window=3600, action="alert")    # Alert at 50
@guard_deco.usage_monitor(max_calls=100, window=3600, action="ban")     # Ban at 100
```

. Monitor Valuable Operations
---------------------------

Focus on endpoints that provide value to attackers:

```python
# High-value endpoints
@guard_deco.return_monitor("rare_reward", max_occurrences=2, window=86400, action="ban")

# Financial operations
@guard_deco.usage_monitor(max_calls=10, window=3600, action="ban")

# Data extraction points
@guard_deco.suspicious_frequency(max_frequency=1.0, window=60, action="throttle")
```

. Consider Time Windows Carefully
-------------------------------

Match windows to expected usage patterns:

```python
# Daily limits for once-per-day operations
@guard_deco.usage_monitor(max_calls=1, window=86400, action="ban")

# Hourly limits for regular operations
@guard_deco.usage_monitor(max_calls=50, window=3600, action="alert")

# Short-term frequency detection
@guard_deco.suspicious_frequency(max_frequency=2.0, window=300, action="throttle")
```

___

Integration with Redis
---------------------

For distributed applications, ensure Redis is configured:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://localhost:6379",
    redis_prefix="tornadoapi_guard:",
)

# Behavioral tracking will use Redis for distributed state
guard_deco = SecurityDecorator(config)
```

___

Error Handling
--------------

Behavioral decorators integrate with middleware error handling:

- **403 Forbidden**: When action is "ban"
- **429 Too Many Requests**: When action is "throttle"
- **Logging**: When action is "log" or "alert"

. Custom Error Messages
---------------------

```python
config = SecurityConfig(
    custom_error_responses={
        403: "Behavioral analysis detected suspicious activity",
        429: "Request frequency too high - throttled",
    }
)
```

___

Monitoring and Debugging
------------------------

Enable detailed logging to monitor behavioral analysis:

```python
config = SecurityConfig(
    log_suspicious_level="DEBUG",
    log_request_level="INFO",
)

# Logs will include:
# - Behavioral rule violations
# - Pattern matching results
# - Action execution details
```

___

Testing Behavioral Rules
-----------------------

Test your behavioral decorators with `AsyncHTTPTestCase`:

```python
from tornado.testing import AsyncHTTPTestCase


class BehaviorTests(AsyncHTTPTestCase):
    def get_app(self):
        return build_application()

    def test_usage_monitor(self):
        for _ in range(5):
            response = self.fetch("/api/monitored")
            self.assertEqual(response.code, 200)

        response = self.fetch("/api/monitored")
        self.assertEqual(response.code, 403)
```

___

Next Steps
----------

Now that you understand behavioral analysis decorators, explore other security features:

- **[Advanced Decorators](advanced.md)** - Time windows and detection controls
- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Content Filtering](content-filtering.md)** - Request validation and filtering
- **[Rate Limiting Decorators](rate-limiting.md)** - Traditional rate limiting

For complete API reference, see the [Behavioral Analysis API Documentation](../../api/decorators.md#behavioralmixin).
