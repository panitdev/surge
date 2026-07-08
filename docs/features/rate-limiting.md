---
description: Built-in rate limiting for authentication endpoints, configurable per-IP and per-username.
---

# Rate Limiting

Surge includes a windowed rate limiter backed by Postgres, applied to authentication-sensitive endpoints like login and registration.

## What gets rate-limited

Rate limiting is applied to authentication-sensitive endpoints — the operations an attacker would target for credential stuffing, brute force, or account enumeration:

| Endpoint | Protected operation |
|---|---|
| Password submission (`POST /v1/flows/{id}/password`) | Login attempts within a flow |
| Registration (`POST /v1/flows/{id}/register`) | Account creation within a flow |
| Direct authentication (`POST /v1/authenticate/password`) | Programmatic password auth |

These are the only endpoints with rate limiting enabled. Session verification, identity lookups, and profile reads are not rate-limited — they don't carry the same abuse potential.

## Rate limit dimensions

Rate limits are tracked along two independent dimensions:

| Dimension | Key | Purpose |
|---|---|---|
| **Per-IP** | Client IP address | Prevents a single machine from flooding the auth endpoint |
| **Per-username** | Username string from the request (authenticate only) | Prevents targeted attacks against a specific account |

Both dimensions are checked on every rate-limited request where applicable. If **either** limit is exceeded, the request is rejected. Registration is rate-limited by IP only (username-based registration limiting is not applied).

## Windowed counter design

Rate limits use **fixed-window bucketing** backed by Postgres via `surge_engine::counter`:

```
┌──────────────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐
│  Window (e.g., 900s authenticate)          │
│  ┌───┬───┬───┬───┐                         │
│  │ 3 │ 1 │ 0 │ 4 │  ← 8 attempts so far    │
│  └───┴───┴───┴───┘                         │
│  Max: 10 per 900s                          │
└──────────────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
```

The window is fixed in time — old counters age out naturally once the window boundary passes. The `retry_after` hint in the error tells the client how long until the window resets.

### Configuration

Rate limits are configured via `RateLimitConfig` with per-action policies:

| Action | Window | Max attempts |
|---|---|---|
| `authenticate` | 900 seconds (15 min) | 10 |
| `register` | 3600 seconds (1 hour) | 5 |
| `flow_submit` | 600 seconds (10 min) | 20 |

```rust
RateLimitConfig::default() // matches the table above
// authenticate: 10 per 15 minutes
// register:     5 per hour
// flow_submit:  20 per 10 minutes
```

Each action has its own independent window and threshold — more sensitive operations (registration) get stricter limits than flow submissions.

## Enforcement

When a limit is exceeded, Surge responds with **HTTP 429 Too Many Requests**:

```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": "rate_limited",
  "message": "Too many authentication attempts. Try again in 30 seconds."
}
```

The response deliberately does not reveal which dimension (IP or username) was exceeded, to avoid giving attackers information about which vector to rotate.

Rate limit rejections are **not** recorded in the audit log — the audit trail only covers successful authentication and identity events (see [Audit Logging](/features/audit-logging)). Counters themselves are Postgres-backed, so they're durable across server restarts and shared across all instances in a multi-node deployment — no Redis required.

**Related:** [Login Flows](/features/login-flows), [Audit Logging](/features/audit-logging)
