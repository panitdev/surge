---
description: Return the current session — used to check authentication state.
---

# Whoami

`GET /v1/whoami`

Returns the current session and its identity. Used by frontends to check if a user is authenticated and load their profile.

## Authentication

Whoami is a cookie-based endpoint. The browser automatically sends the `surge_session` cookie with every request to Surge's origin:

```bash
curl http://localhost:3000/v1/whoami \
  -H "Cookie: surge_session=aeg_s_..."
```

No `Authorization` header or CSRF token is needed — this is a read-only endpoint that inspects the session cookie.

## Response — Authenticated (`200 OK`)

When the session is valid (not revoked, not expired, identity active), Surge returns the full session, including the identity:

```json
{
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
```

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Session UUID |
| `identity` | `object` | The identity — `id`, `username` (always lowercase), `display_name`, `avatar_url`, `state`, `created_at`, `updated_at` |
| `issued_at` / `expires_at` | `string` | Session lifetime, ISO 8601 |
| `authenticated_via` | `string` | The method used to authenticate this session, currently always `"password"` |

## Response — Unauthenticated (`401 Unauthorized`)

When no valid session cookie is present, Surge returns:

```json
{ "error": "invalid_token" }
```

The frontend should treat any `401` from this endpoint as "user is not logged in" and redirect to the login flow.

## CORS behavior

`GET /v1/whoami` is in the **session-management** CORS zone. Cross-origin requests from origins configured in `SURGE_SESSION_CORS_ORIGINS` are allowed with credentials:

```bash
# Cross-origin whoami call from a configured frontend
curl http://localhost:3000/v1/whoami \
  -H "Cookie: surge_session=aeg_s_..." \
  -H "Origin: https://app.example.com"
```

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
```

The browser sends the session cookie because the frontend JS uses `fetch(url, { credentials: "include" })` or equivalent.

### Frontend example

```javascript
// Typical SPA auth check on page load
const response = await fetch("https://auth.example.com/v1/whoami", {
  credentials: "include",
});

if (response.ok) {
  const { identity } = await response.json();
  // identity.id, identity.username, identity.display_name
} else {
  // Redirect to login
}
```

Surge does not set `Cache-Control` or `ETag` headers on this endpoint — every request performs a fresh verification, so revoked sessions and disabled accounts are detected immediately.

**Related:** [Session Management](/features/session-management), [Logout](/api/browser/logout)
