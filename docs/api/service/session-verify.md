---
description: Verify a session token — returns the associated identity and session metadata.
---

# Session Verify

`POST /v1/sessions/verify`

Verifies a session token and returns the associated identity. Used by backend services to validate sessions presented by users.

## Authentication

Requires a service token with the `introspect` grant:

```bash
Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j
```

The `introspect` grant allows a service to verify session tokens and look up identity state. Without it, requests return `403 Forbidden`.

## Request

```bash
curl -X POST http://localhost:3000/v1/sessions/verify \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"token": "aeg_s_1a2b3c4d5e6f7g8h9i0j"}'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `token` | `string` | Yes | Must start with `aeg_s_` — other prefixes are rejected as `invalid_token` |

## Response — `200 OK`

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

| Field | Description |
|---|---|
| `id` | Session UUID |
| `identity` | Embedded identity object — the user who owns this session |
| `issued_at` | When the session was created |
| `expires_at` | When the session will expire (`issued_at` + TTL) |
| `authenticated_via` | How this session was created — currently always `"password"` |

## What verification checks

A token is valid only if all three of these hold:

1. **Not revoked** — the session hasn't been individually or bulk-revoked.
2. **Not expired** — the current time is before `expires_at`.
3. **Identity active** — the owning identity isn't `Disabled`.

If any condition fails, the token is rejected. The response doesn't distinguish *why* it was rejected — this prevents information leakage about whether a session was revoked vs. expired vs. the account was disabled.

## Errors

| Status | Type | Condition |
|---|---|---|
| `401` | `invalid_token` | Token doesn't start with `aeg_s_`, or hash not found (wrong token, revoked, or expired) |
| `403` | `identity_disabled` | Identity is disabled |

Disabled identities will fail verification even if the session token is otherwise valid. Re-enable the identity first to allow verification.

```bash
# Disabled identity
curl -X POST http://localhost:3000/v1/sessions/verify \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"token": "aeg_s_..."}'
```

```json
{ "error": "identity_disabled" }
```

## Audit logging

Each successful verification is recorded in the audit log with the action `verify_session` and the session ID.

## Caching

`RemoteProvider` (the client used by `surge::remote` integrations) caches verification results in memory for a configurable TTL, so repeated verification of the same token within that window is served without a round-trip to the auth server. See [Embedding](/integration/embedding) for configuring `cache_ttl`.

**Related:** [Session Revoke](/api/service/session-revoke), [Service Authentication](/features/service-authentication)
