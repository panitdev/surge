---
description: How Surge handles user login flows — redirect-based, inline, CSRF protection, and registration modes.
---

# Login Flows

Surge provides a stateful login flow system for browser-based authentication. A flow is created, the user authenticates into it, and the flow completes by issuing a session.

## Flow lifecycle

A login flow moves through a structured lifecycle managed by the Surge engine:

```
Create → Submit credentials → Complete → Session issued
         ↑                    ↓
         └── Retry ←─── Error ──┘
```

1. **Create**: A flow is initiated via `GET /v1/login`
2. **Submit**: The user provides credentials (password login or registration)
3. **Complete**: On success, the engine issues a session and the flow is marked complete
4. **Error**: On failure, the flow remains open for retry (subject to rate limits and attempt caps)

A flow is single-use — once completed or expired, it cannot be reused.

## Flow ID format

Each flow is identified by a `FlowId`:

```rust
// 128-bit random → base62-encoded → "aeg_f_" prefix
let flow_id = FlowId::generate();
// Example: "aeg_f_3k7m9p2q5r8t1v4w6x"
```

| Property | Value |
|---|---|
| Entropy | 128 bits |
| Encoding | Base62 |
| Prefix | `aeg_f_` |

The `aeg_f_` prefix distinguishes flow IDs from session tokens (`aeg_s_`) and service tokens (`aeg_svc_`).

## Redirect mode

Redirect mode is the default for browser requests. The user's browser is redirected through a login UI:

```bash
# Request from browser (no special Accept header)
curl http://localhost:3000/v1/login
```

```
HTTP/1.1 302 Found
Location: https://auth.example.com/login?flow=aeg_f_3k7m9p2q5r8t1v4w6x
```

The flow:
1. `GET /v1/login` → 302 redirect to the auth UI, passing the flow ID
2. The auth UI renders a login form
3. The user submits credentials → `POST /v1/flows/{id}/password`
4. On success → 302 redirect to the configured post-login URL with a session cookie
5. On failure → 302 redirect back to the login form with an error parameter

This is the integration pattern when you run Surge as a standalone server with its own auth UI.

## Inline mode

Inline mode is for SPAs and JavaScript-driven frontends. Set the `Accept` header to request JSON:

```bash
curl http://localhost:3000/v1/login \
  -H "Accept: application/json"
```

```json
{
  "flow_id": "aeg_f_3k7m9p2q5r8t1v4w6x",
  "csrf_token": "aeg_csrf_...",
  "registration_mode": "open"
}
```

The flow:
1. `GET /v1/login` with `Accept: application/json` → 200 JSON with `flow_id`, `csrf_token`, and `registration_mode`
2. The frontend renders its own login form (no redirect)
3. Submit password → `POST /v1/flows/{id}/password` with `csrf_token` in the request body
4. Submit registration → `POST /v1/flows/{id}/register` with `csrf_token` in the request body
5. On success → JSON response with `return_to` + session data + `Set-Cookie` header

Inline mode gives you full control over the login UI while Surge manages the security-critical flow state.

## CSRF protection

Every flow includes a CSRF token, returned at flow creation (either in the JSON response body for inline mode, or embedded in the flow state via the auth UI). The token must be included as the `csrf_token` field in the request body of every flow submission:

```bash
# Password submission with CSRF token in the body
curl -X POST http://localhost:3000/v1/flows/aeg_f_3k7m9p2q5r8t1v4w6x/password \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "correct-horse-battery-staple", "csrf_token": "aeg_csrf_..."}'
```

The CSRF token is flow-scoped — it's only valid for the specific flow it was issued with. If the token is missing or invalid, Surge rejects the request with `401 Unauthorized`. This prevents cross-site request forgery attacks where a malicious site tricks a user's browser into submitting a login form.

## Flow completion

On successful password submission or registration, the engine:

1. Checks the flow is in "created" state (not already completed or expired)
2. Validates the CSRF token in the request body
3. Checks rate limits (per-IP flow submit, plus per-IP and per-username for authenticate/register)
4. Verifies credentials (or creates the identity for registration)
5. Marks the flow as **completed**
6. Issues a session and sets the `Set-Cookie` header
7. Returns the `return_to` URL and session data

```bash
# Successful password submission
curl -X POST http://localhost:3000/v1/flows/aeg_f_.../password \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "correct-horse-battery-staple", "csrf_token": "aeg_csrf_..."}'
```

```json
{
  "return_to": "https://app.example.com/dashboard",
  "session": {
    "id": "018f9a1b-...",
    "identity": { "id": "018f9a1b-...", "username": "alice", "display_name": "Alice" },
    "issued_at": "2026-07-08T12:00:00Z",
    "expires_at": "2026-07-11T12:00:00Z"
  }
}
```

The `Set-Cookie` header is included, so the browser automatically stores the session cookie for subsequent requests.

## Registration within a flow

If the registration mode is `open` (see [Registration Modes](/integration/registration-modes)), a flow can be used to create a new identity:

```bash
curl -X POST http://localhost:3000/v1/flows/aeg_f_.../register \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "correct-horse-battery-staple", "display_name": "Bob", "csrf_token": "aeg_csrf_..."}'
```

The registration endpoint creates the identity within the flow context, applies username and password validation rules, and on success proceeds directly to flow completion — issuing a session for the newly created identity. The response returns `201 Created` with the same `{ return_to, session }` structure as password completion.

**Note:** Invite-based registration (`SURGE_REGISTRATION=invite`) is not yet implemented. It returns a `500 Internal Server Error`.

## Flow expiry and garbage collection

Flows have a limited lifetime. If a flow is not completed within the expiry window, it becomes invalid. When a client submits to an expired or already-completed flow, the engine returns `401 Unauthorized` with `invalid_token`.

Expired flows and completed flows are cleaned up by the engine's maintenance sweep, which runs periodically to remove stale flow state from the database.

## Error states

### Invalid credentials

```
HTTP/1.1 401 Unauthorized

{
  "error": "invalid_credentials",
  "message": "Invalid credentials."
}
```

Error responses deliberately avoid distinguishing between "user not found" and "wrong password" — the same error is returned for both to prevent username enumeration. If the credentials fail, the flow records the error but remains open for retry (subject to rate limits).

### Rate limited

```
HTTP/1.1 429 Too Many Requests

{
  "error": "rate_limited",
  "message": "Too many attempts. Try again later."
}
```

### Flow expired or already completed

```
HTTP/1.1 401 Unauthorized

{
  "error": "invalid_token",
  "message": "Invalid or expired token."
}
```

A flow that has expired, already been completed, or has an invalid CSRF token all return `401 Unauthorized`. Each login attempt should start with a fresh flow from `GET /v1/login`.

**Related:** [Registration Modes](/integration/registration-modes), [Session Management](/features/session-management)
