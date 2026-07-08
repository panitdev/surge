---
description: Register a new identity directly through the service API, optionally creating an initial session.
---

# Register (Service API)

`POST /v1/register` — create a new identity

`POST /v1/register-and-authenticate` — create identity and return a session

## Authentication

Both endpoints require a service token with the `direct_auth` grant. Send it in the `Authorization` header:

```bash
Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j
```

These endpoints don't check the deployment's registration mode at all — they create identities regardless of whether browser registration is `open`, `invite`, or `closed`. This makes them the way to provision accounts on a `closed` deployment without opening public sign-up.

If the token is missing, invalid, or lacks `direct_auth`, you'll get a `401 Unauthorized` or `403 Forbidden`.

## Register only (`/v1/register`)

Creates an identity without issuing a session. Use this when you want to create a user account but don't need to authenticate them immediately — for example, batch importing users or pre-creating accounts.

### Request

```bash
curl -X POST http://localhost:3000/v1/register \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "correct-horse-battery-staple",
    "display_name": "Alice"
  }'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `username` | `string` | Yes | Must pass validation (length, allowed chars) |
| `password` | `string` | Yes | Must pass password validation rules |
| `display_name` | `string` | Yes | Display name for UI |

### Response — `201 Created`

```json
{
  "id": "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
  "username": "alice",
  "display_name": "Alice",
  "avatar_url": null,
  "state": "active",
  "created_at": "2026-07-08T12:00:00Z",
  "updated_at": "2026-07-08T12:00:00Z"
}
```

| Field | Description |
|---|---|
| `id` | UUID v7 — globally unique, time-sortable |
| `state` | Always `"active"` for new identities |

The identity is created immediately — no email verification step.

### Errors

| Status | Type | Cause |
|---|---|---|
| `422` | `validation_error` | Username or password fails validation rules |
| `409` | `username_taken` | Username is already taken |

## Register and authenticate (`/v1/register-and-authenticate`)

Creates an identity **and** an initial session in a single atomic operation. The identity, password, and session are all committed in one database transaction — either everything succeeds or nothing is persisted.

### Request

```bash
curl -X POST http://localhost:3000/v1/register-and-authenticate \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "correct-horse-battery-staple",
    "display_name": "Alice"
  }'
```

Same body as `/register`.

### Response — `201 Created`

```json
{
  "session": {
    "id": "018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c3",
    "identity": {
      "id": "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
      "username": "alice",
      "display_name": "Alice",
      "avatar_url": null,
      "state": "active",
      "created_at": "2026-07-08T12:00:00Z",
      "updated_at": "2026-07-08T12:00:00Z"
    },
    "issued_at": "2026-07-08T12:00:00Z",
    "expires_at": "2026-07-11T12:00:00Z",
    "authenticated_via": "password"
  },
  "token": "aeg_s_1a2b3c4d5e6f7g8h9i0j"
}
```

| Field | Description |
|---|---|
| `session` | Full session object with embedded identity |
| `token` | Raw session token — **shown once, store it** |
| `authenticated_via` | Always `"password"` — the auth method recorded |

The `token` field is the plaintext session token. It is only returned here — Surge stores only its SHA-256 hash. If you lose it, revoke the session and create a new one.

### Errors

Same as `/register` plus any session creation failures (unlikely — handled atomically in the transaction).

## Choosing between the two endpoints

| Use case | Endpoint |
|---|---|
| Pre-create accounts for later use | `/register` |
| Create an account and immediately issue a session | `/register-and-authenticate` |
| Batch import users | `/register` — loop through records |
| Admin creates a user and logs them in | `/register-and-authenticate` |
| Automated onboarding with redirect to app | `/register-and-authenticate` — return token to client |

**Related:** [Authenticate](/api/service/authenticate), [Identity Management](/features/identity-management)
