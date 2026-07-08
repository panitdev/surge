---
description: Complete a login flow by submitting a password — authenticates the user and issues a session.
---

# Flow Complete

`POST /v1/flows/{id}/password`

Submits a password credential into an active login flow. On success, the flow completes and a session cookie is set.

## Authentication

This endpoint is accessed as part of an active login flow. No session cookie or Bearer token is required — authentication is handled by the flow's internal state and CSRF token submitted in the request body.

## Request

```bash
curl -X POST http://localhost:3000/v1/flows/aeg_f_3k7m9p2q5r8t1v4w6x/password \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "correct-horse-battery-staple", "csrf_token": "aopX8kLm3..."}'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `username` | `string` | Yes | The user's username |
| `password` | `string` | Yes | The user's plaintext password. Compared against the stored Argon2id + pepper hash |
| `csrf_token` | `string` | Yes | The CSRF token returned by `GET /v1/login` in the inline response body or passed through the auth UI |

### Path parameter

| Parameter | Type | Description |
|---|---|---|
| `flow_id` | `string` | The flow ID returned by `GET /v1/login`, prefixed `aeg_f_` |

### CSRF token

The CSRF token is submitted in the request body as the `csrf_token` field, not as a header. It must match the token associated with the flow at creation time. It is flow-scoped — valid only for the specific flow it was issued with. Missing or mismatched tokens are rejected immediately with a `401 Unauthorized`.

## Response — `200 OK`

On success, the user is authenticated and a session is issued:

```json
{
  "return_to": "https://app.example.com/dashboard",
  "session": {
    "id": "018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c3",
    "identity": {
      "id": "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
      "username": "alice",
      "display_name": "Alice",
      "avatar_url": null,
      "state": "active",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    },
    "issued_at": "2026-07-08T12:00:00Z",
    "expires_at": "2026-07-11T12:00:00Z",
    "authenticated_via": "password"
  }
}
```

The response also includes:

```
Set-Cookie: surge_session=aeg_s_1a2b3c4d5e6f7g8h9i0j; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=.example.com
```

The `Set-Cookie` header instructs the browser to store the session token as an HTTP-only cookie. The `return_to` field contains the URL the client should navigate to after successful authentication — this is the URL provided as the `return_to` query parameter at flow init.

## What happens on completion

1. The flow is retrieved and validated (must be in "created" state)
2. The CSRF token in the request body is validated against the flow state
3. Rate limiting is checked (per-IP for flow submission, per-IP + per-username for authentication)
4. The username is parsed and validated; on failure, records a flow error and returns `401`
5. The password is verified against the stored Argon2id hash (with secret pepper applied first)
6. On success, the flow is marked **completed** — it cannot be reused
7. A new session is minted with the configured TTL (`SURGE_SESSION_TTL_HOURS`, default 72h)
8. The session token is hashed (SHA-256) and stored; the raw token is returned only in the `Set-Cookie` header

Once completed, submitting to the same flow again returns `401 Unauthorized`.

## Rate limiting

Password submissions are rate-limited on two independent dimensions (either alone can trigger the limit):

| Dimension | How it works |
|---|---|
| **Per-IP** | Counts all flow submissions from the same IP address |
| **Per-username** | Counts authentication attempts targeting the same username |

When either threshold is exceeded, Surge returns `429 Too Many Requests`.

## Errors

| Status | Type | Condition |
|---|---|---|
| `401` | `invalid_credentials` | Wrong password. Same response whether the user exists or not — timing-safe comparison prevents username enumeration |
| `401` | `invalid_token` | Missing or mismatched CSRF token, or flow already completed |
| `429` | `rate_limited` | Too many password attempts |

### Invalid credentials

```json
{ "error": "invalid_credentials" }
```

On failure, the flow remains open for retry (subject to rate limits and attempt caps). Show a generic error message — don't distinguish between wrong password and non-existent user.

### Rate limited

```json
{ "error": "rate_limited", "retry_after": 30 }
```

Implement a client-side cooldown or exponential backoff, using `retry_after` for the suggested wait time.

**Related:** [Flow Init](/api/browser/flow-init), [Login Flows](/features/login-flows)
