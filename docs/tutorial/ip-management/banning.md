---

title: IP Banning - TornadoAPI Guard
description: Implement automatic and manual IP banning in Tornado applications using TornadoAPI Guard's IPBanManager
keywords: ip banning, ip blocking, security middleware, tornado security
---

IP Banning
==========

TornadoAPI Guard provides powerful IP banning capabilities through the `IPBanManager`.

___

Automatic IP Banning
---------------------

Configure automatic IP banning based on suspicious activity:

```python
config = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds (1 hour)
)
```

___

Manual IP Banning
------------------

You can also manually ban IPs using the `IPBanManager`:

```python
from tornadoapi_guard import SecurityHandler
from guard_core.handlers.ipban_handler import ip_ban_manager_for

# The module-level objects are the default app's. Take the ones of the app
# you act on with the config that app was built with.
bans = ip_ban_manager_for(config)


class BanIPHandler(SecurityHandler):
    async def post(self, ip: str) -> None:
        duration = int(self.get_argument("duration", "3600"))
        await bans.ban_ip(ip, duration)
        self.write({"message": f"IP {ip} banned for {duration} seconds"})
```

Register as `(r"/admin/ban/([^/]+)", BanIPHandler)` in your `tornado.web.Application`.

___

Checking Ban Status
-------------------

Check if an IP is currently banned:

```python
class CheckBanHandler(SecurityHandler):
    async def get(self, ip: str) -> None:
        is_banned = await bans.is_ip_banned(ip)
        self.write({"ip": ip, "banned": is_banned})
```

Register as `(r"/admin/check/([^/]+)", CheckBanHandler)` in your `tornado.web.Application`.

___

Reset All Bans
--------------

Clear all active IP bans:

```python
class ResetBansHandler(SecurityHandler):
    async def post(self) -> None:
        await bans.reset()
        self.write({"message": "All IP bans cleared"})
```

Register as `(r"/admin/reset", ResetBansHandler)` in your `tornado.web.Application`.
