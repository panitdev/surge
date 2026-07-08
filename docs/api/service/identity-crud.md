---
description: Look up and manage identities — by ID, by username, update profile, enable/disable.
---

# Identities (Service API)

`GET /v1/identities/{id}` — get identity by ID

`GET /v1/identities?username={username}` — find identity by username

`PATCH /v1/identities/{id}/profile` — update display name or avatar

> **Note:** Disabling and enabling identities is done via the CLI (`surge-server identity disable/enable`), not through the service API.

## Authentication

All endpoints require a valid service token. The grant required depends on the operation:

| Grant | Operations |
|---|---|
| `identity_read` | `GET` — lookup by ID or username |
| `identity_write` | `PATCH` profile |

Services without the right grant receive `403 Forbidden` (`{"error": "forbidden"}`).

```bash
# All requests share this header:
Authorization: Bearer aeg_svc_...
```

## Get identity by ID

Looks up an identity by its UUID. Fast, direct lookup — use this when you already have the identity ID (e.g., from a session verify response).

### Request

```bash
curl -X GET http://localhost:3000/v1/identities/018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3 \
  -H "Authorization: Bearer aeg_svc_..."
```

### Response — `200 OK`

```json
{
  "id": "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
  "username": "alice",
  "display_name": "Alice",
  "avatar_url": null,
  "state": "active",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

| Field | Description |
|---|---|
| `id` | UUID v7 |
| `username` | Unique username |
| `display_name` | Human-readable name for UI |
| `avatar_url` | Avatar URL or `null` |
| `state` | `"active"` or `"disabled"` |
| `created_at` / `updated_at` | ISO 8601 timestamps |

### Errors

| Status | Type | Condition |
|---|---|---|
| `404` | `not_found` | No identity with that UUID |

## Get identity by username

Looks up an identity by username via query parameter. Use this when you have a username but not the UUID — e.g., a user has typed their username.

### Request

```bash
curl -X GET "http://localhost:3000/v1/identities?username=alice" \
  -H "Authorization: Bearer aeg_svc_..."
```

Note the query parameter: `?username=alice`.

### Response — `200 OK`

Same shape as the get-by-ID response. Includes the full identity object.

### Audit logging

Each username lookup is recorded in the audit log with the action `identity_lookup` and the queried username. This provides a trail of when services searched by username.

### Errors

| Status | Type | Condition |
|---|---|---|
| `404` | `not_found` | No identity with that username |

## Update profile

Updates the display name and/or avatar URL for an identity. This is a **partial update** — only send the fields you want to change. Fields not included in the request are left unchanged.

### Request

```bash
curl -X PATCH http://localhost:3000/v1/identities/018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3/profile \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice Johnson", "avatar_url": "https://example.com/avatars/alice.png"}'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `display_name` | `string` | No | New display name (omit to keep current) |
| `avatar_url` | `string` | No | New avatar URL (omit to keep current) |

Only the fields present in the request body are applied — omitted fields are left untouched.

### Response — `200 OK`

Returns the updated full identity object:

```json
{
  "id": "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
  "username": "alice",
  "display_name": "Alice Johnson",
  "avatar_url": "https://example.com/avatars/alice.png",
  "state": "active",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-07-08T12:00:00Z"
}
```

### Partial update example

Only updating the display name, keeping the avatar unchanged:

```bash
curl -X PATCH http://localhost:3000/v1/identities/{id}/profile \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice J."}'
```

### Errors

| Status | Type | Condition |
|---|---|---|
| `404` | `not_found` | Identity UUID doesn't exist |

**Related:** [Identity Management](/features/identity-management), [Service Authentication](/features/service-authentication)
