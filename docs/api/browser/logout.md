---
description: Revoke the current session and clear the session cookie.
---

# Logout

`POST /v1/logout`

Revokes the current session and clears the session cookie. After logout, the session token is no longer valid.

## Authentication

Logout reads the session from the `surge_session` cookie. There is no Bearer-token variant of this endpoint — it's a same-origin, cookie-based operation only.

```bash
curl -X POST http://localhost:3000/v1/logout \
  -H "X-Surge-CSRF: 1" \
  -b "surge_session=aeg_s_..."
```

## CSRF protection

Logout is a state-changing operation and requires the `X-Surge-CSRF` header on every request, with the literal value `1`:

```bash
X-Surge-CSRF: 1
```

The header's presence, combined with the cookie's `SameSite=Lax` restriction, is what prevents cross-site requests from triggering a logout. If the header is missing, the request is rejected before the handler runs.

## Response — `204 No Content`

```
HTTP/1.1 204 No Content
Set-Cookie: surge_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Domain=.example.com
```

The `Set-Cookie` header with `Max-Age=0` instructs the browser to remove the session cookie immediately. There is no JSON response body.

`POST /v1/logout` always returns `204`, whether or not a session cookie was present or the session was already invalid — logout is idempotent and never reveals session state to the caller.

## What happens during logout

1. The session token is read from the `surge_session` cookie, if present
2. If present and valid, the corresponding session is revoked
3. The cookie is cleared in the response regardless

After logout, the session token is permanently invalid — even if the raw token is captured, it will fail subsequent verification.

## Revoking a single session vs. all sessions

`POST /v1/logout` revokes only the **current** session — the one identified by the cookie. Other sessions belonging to the same identity remain active.

For bulk session revocation (e.g., "log out everywhere"), use the service API:

```bash
# Revoke ALL sessions for identity 018f9a1b-...
curl -X POST http://localhost:3000/v1/identities/018f9a1b-.../revoke-sessions \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json"
```

This requires a service token with the `revoke` grant. See [Session Revoke](/api/service/session-revoke) for details.

## Errors

| Status | Condition |
|---|---|
| `401` | Missing or invalid `X-Surge-CSRF` header — returned as a plain-text body, not JSON |

There is no error for a missing or already-revoked session; the endpoint returns `204` in all of those cases.

## CORS behavior

`POST /v1/logout` is in the **session-management** CORS zone, which accepts requests from all origins configured in `SURGE_SESSION_CORS_ORIGINS`. Cross-origin logout from a configured origin will include credentials and the `X-Surge-CSRF` header after a preflight `OPTIONS` request.

**Related:** [Whoami](/api/browser/whoami), [Session Management](/features/session-management)
