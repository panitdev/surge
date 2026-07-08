---
description: Register a new user within a login flow — creates an identity and issues a session.
---

# Register (Browser)

`POST /v1/flows/{id}/register`

Registers a new identity within an active login flow. On success, the flow completes and a session cookie is set.

## Authentication

This endpoint is accessed as part of an active login flow. No session cookie or Bearer token is required — the flow's internal state and CSRF token submitted in the request body handle authentication.

## Request

```bash
curl -X POST http://localhost:3000/v1/flows/aeg_f_3k7m9p2q5r8t1v4w6x/register \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "correct-horse-battery-staple", "display_name": "Bob", "csrf_token": "aopX8kLm3..."}'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `username` | `string` | Yes | Must be unique. Case-folded to lowercase on storage (3-32 chars, lowercase, digits, hyphens) |
| `password` | `string` | Yes | Plaintext password. Hashed with Argon2id + secret pepper before storage. Must pass validation (8-256 chars, not a common password) |
| `display_name` | `string` | Yes | The user's display name (can be empty string for no display name) |
| `csrf_token` | `string` | Yes | The CSRF token returned by `GET /v1/login` in the inline response or passed through the auth UI |

### Path parameter

| Parameter | Type | Description |
|---|---|---|
| `flow_id` | `string` | The flow ID returned by `GET /v1/login`, prefixed `aeg_f_` |

### CSRF token

The CSRF token is submitted in the request body as the `csrf_token` field, not as a header. It must match the token associated with the flow at creation time. It is flow-scoped — valid only for the specific flow it was issued with.

## Response — `201 Created`

On success, a new identity is created and a session is issued immediately:

```json
{
  "return_to": "https://app.example.com/dashboard",
  "session": {
    "id": "018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c3",
    "identity": {
      "id": "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
      "username": "bob",
      "display_name": "Bob",
      "avatar_url": null,
      "state": "active",
      "created_at": "2026-07-08T12:00:00Z",
      "updated_at": "2026-07-08T12:00:00Z"
    },
    "issued_at": "2026-07-08T12:00:00Z",
    "expires_at": "2026-07-11T12:00:00Z",
    "authenticated_via": "password"
  }
}
```

The response also includes a `Set-Cookie` header with the session cookie:

```
Set-Cookie: surge_session=aeg_s_1a2b3c4d5e6f7g8h9i0j; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=.example.com
```

The `return_to` field contains the URL the client should navigate to after registration — this is the URL provided at flow init. The user is logged in immediately — no separate password submission is needed.

## Registration mode enforcement

Registration is gated by the deployment's registration mode, set via `SURGE_REGISTRATION`. The mode is checked early in the request pipeline:

| Mode | Behavior |
|---|---|
| `open` | Registration proceeds normally — anyone can create an account |
| `invite` | Not yet implemented. Returns a `500 Internal Server Error` |
| `closed` | Registration is rejected with `403 Forbidden` before any credential processing |

The frontend learns the mode from the flow init response's `registration_mode` field and should hide or disable the register link when `invite` or `closed`.

## Rate limiting

Registration is rate-limited on `flow_submit` (per-IP, across all flow submissions) and `register` (per-IP, across all registrations). When a threshold is exceeded, Surge returns `429 Too Many Requests` with a `retry_after` field.

## Errors

| Status | Type | Condition |
|---|---|---|
| `422` | `validation_error` | Username or password fails validation rules |
| `401` | `invalid_token` | Missing/mismatched CSRF token, or flow already completed |
| `403` | `forbidden` | Registration mode is `closed` |
| `409` | `username_taken` | The username already exists |
| `429` | `rate_limited` | Too many registration attempts |

### Username taken

```json
{ "error": "username_taken" }
```

Usernames are case-folded to lowercase before storage — `"Alice"` and `"alice"` are the same username. Show a "this username is taken" message to the user.

### Registration closed

```json
{ "error": "forbidden" }
```

### Validation error

```json
{ "error": "validation_error", "message": "password must be at least 8 characters" }
```

**Related:** [Flow Init](/api/browser/flow-init), [Registration Modes](/integration/registration-modes)
