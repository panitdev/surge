---
description: Revoke a session token — single session or all sessions for an identity.
---

# Session Revoke

`POST /v1/sessions/revoke` — revoke a single session

`POST /v1/identities/{id}/revoke-sessions` — revoke all sessions for an identity

Revokes one or all sessions for an identity. Once revoked, the session token can no longer be verified.

## Authentication

Both endpoints require a service token with the `revoke` grant:

```bash
Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j
```

Without `revoke`, requests return `403 Forbidden`. This grant should be scoped tightly — only services that truly need session revocation capability (e.g., an admin dashboard backend, a logout service).

## Single session revoke

Revokes one specific session by its token. The token is hashed and matched against the `session` table — the matching session gets `revoked_at = now()`.

### Request

```bash
curl -X POST http://localhost:3000/v1/sessions/revoke \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"token": "aeg_s_1a2b3c4d5e6f7g8h9i0j"}'
```

| Field | Type | Required |
|---|---|---|
| `token` | `string` | Yes — the session token to revoke |

### Response — `204 No Content`

Empty body. HTTP 204 indicates the revocation succeeded. If the token was already revoked or doesn't exist, the response is still 204 — the operation is idempotent.

### Errors

| Status | Type | Condition |
|---|---|---|
| `401` | `invalid_token` | Token prefix is not `aeg_s_` |

## Bulk session revoke

Revokes **all active sessions** for an identity. Uses the identity's UUID as a path parameter — the engine sets `revoked_at = now()` on every unrevoked session belonging to that identity.

### Request

```bash
curl -X POST http://localhost:3000/v1/identities/018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3/revoke-sessions \
  -H "Authorization: Bearer aeg_svc_..."
```

No request body — the identity ID comes from the URL path.

### Response — `200 OK`

```json
{ "revoked": 3 }
```

| Field | Description |
|---|---|
| `revoked` | Number of sessions that were revoked. Zero means no active sessions existed for that identity — including if the identity ID doesn't exist. |

This endpoint doesn't check whether the identity exists; it simply revokes whatever active sessions match the ID, so an unknown ID returns `{"revoked": 0}` rather than a `404`.

**Related:** [Session Verify](/api/service/session-verify), [Service Authentication](/features/service-authentication)
