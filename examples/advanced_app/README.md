# TornadoAPI Guard advanced example

Production-shaped topology mirroring the ecosystem's other advanced examples:
an nginx edge in front of the Tornado app, Redis-backed guard state, and
orchestration-friendly health endpoints.

## Topology

- `nginx` (host port 80): connection shedding (`limit_req`), forwarded-header
  normalization, proxying to the app.
- `app`: the Tornado application with `SecurityMiddleware` wired; trusts a
  single proxy hop, so real client IPs come from `X-Forwarded-For`.
- `redis`: guard rate-limit, ban, and cache state.

## Routes

| Route | Behavior |
| --- | --- |
| `GET /` | Service index |
| `GET /health`, `GET /ready` | Guard-excluded liveness/readiness for orchestration |
| `GET /rate/strict` | Route-scoped rate limit (5 requests / 60s) |
| `GET /admin/check` | Requires the `X-Admin-Token` header |
| any `?debug=true` | Blocked by the custom request check (403) |

## Run

```bash
docker compose up --build
curl -sS http://localhost/
curl -sS -H "X-Admin-Token: admin-token-change-me" http://localhost/admin/check
curl -sS http://localhost/rate/strict
```

Configuration is environment-driven (`REDIS_URL`, `REDIS_PREFIX`,
`IPINFO_TOKEN`, `ADMIN_TOKEN`, `RATE_LIMIT`, `RATE_LIMIT_WINDOW`,
`AUTO_BAN_THRESHOLD`, `AUTO_BAN_DURATION`); see `docker-compose.yml`.
