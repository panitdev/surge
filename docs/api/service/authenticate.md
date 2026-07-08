---
description: Authenticate a user by password directly (service-to-service) and receive a session token.
---

# Authenticate

`POST /v1/authenticate/password`

Authenticates a user by username and password directly through the service API. Returns a session token for programmatic use.

## Authentication

Requires a service token with the `direct_auth` grant:

```bash
Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j
```

Without `direct_auth`, the request is rejected with `403 Forbidden` — even if the service has other grants like `identity_read` or `introspect`. The `direct_auth` grant is specifically scoped to password authentication.

## Request

```bash
curl -X POST http://localhost:3000/v1/authenticate/password \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "correct-horse-battery-staple"}'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `username` | `string` | Yes | Case-folded to lowercase before lookup |
| `password` | `string` | Yes | Compared against stored hash |

## Response — `200 OK`

```json
{
  "session": {
    "id": "018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c3",
    "identity": {
      "id": "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
      "username": "alice",
      "display_name": "Alice",
      "avatar_url": null,
      "state": "active"
    },
    "issued_at": "2026-07-08T12:00:00Z",
    "expires_at": "2026-07-11T12:00:00Z",
    "authenticated_via": "password"
  },
  "token": "aeg_s_1a2b3c4d5e6f7g8h9i0j"
}
```

The `token` is the **raw session token** — not the service token. Store it immediately; it won't be shown again.

## Timing-safe comparison

Surge prevents username enumeration via timing attacks. When the username doesn't exist, the engine still runs a full password hash comparison against a fixed dummy hash, so the response time is identical whether the username exists or not. `invalid_credentials` could mean wrong username, wrong password, or both — an attacker can't distinguish them by timing or by response shape.

## Errors

| Status | Type | Condition |
|---|---|---|
| `401` | `invalid_credentials` | Wrong username or password |
| `403` | `identity_disabled` | Identity is `Disabled` — active accounts only |
| `429` | `rate_limited` | Too many attempts |

### Invalid credentials

```json
{ "error": "invalid_credentials" }
```

No distinction between wrong username and wrong password. Show a generic "invalid credentials" message to users — don't specify which field is wrong.

### Disabled account

```json
{ "error": "identity_disabled" }
```

Disabled identities cannot authenticate. An admin must re-enable the account via `surge-server identity enable <username>`.

### Rate limited

```json
{ "error": "rate_limited", "retry_after": 30 }
```

Implement exponential backoff or show a cooldown timer, using `retry_after` for the suggested wait time in seconds.

## When to use this endpoint

This is for service-to-service or backend-driven authentication where there's no browser to redirect: server-side login, CLI tools, automated tests, or a mobile app that collects credentials natively and forwards them to your backend.

For browser-based login where users interact with an auth UI, use the [browser flow API](/api/browser/flow-init) instead — it handles CSRF protection, cookies, and redirects automatically.

**Related:** [Register (Service)](/api/service/register), [Password Authentication](/features/password-authentication)
