---
description: Common API error responses, error types, and how to handle them.
---

# Errors

Surge returns structured JSON error responses. This page documents common error types across all endpoints.

## Error response shape

Errors are a flat JSON object with a machine-readable `error` code. Some error types add extra fields alongside it.

```json
{ "error": "invalid_credentials" }
```

```json
{ "error": "validation_error", "message": "password must be at least 8 characters" }
```

```json
{ "error": "rate_limited", "retry_after": 30 }
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `error` | `string` | Machine-readable error code — use this for branching logic |
| `message` | `string` | Present only on `validation_error` — human-readable field-level detail |
| `retry_after` | `number` | Present only on `rate_limited` — seconds until the next request is allowed |

The `error` code is stable across releases; don't parse `message` for control flow.

## Error types

### `invalid_service_token`

The `Authorization: Bearer` header is present but the token hash doesn't match any registered service. The token may have been revoked, typed incorrectly, or never existed.

**HTTP**: `401 Unauthorized`

```bash
curl -X POST http://localhost:3000/v1/sessions/verify \
  -H "Authorization: Bearer aeg_svc_bad_token" \
  -H "Content-Type: application/json" \
  -d '{"token": "aeg_s_..."}'
```

```json
{ "error": "invalid_service_token" }
```

### `missing_service_token`

No `Authorization` header was provided on a service endpoint that requires one.

**HTTP**: `401 Unauthorized`

```json
{ "error": "missing_service_token" }
```

### `invalid_credentials`

The username or password is incorrect. Surge uses timing-safe comparison — unknown usernames and wrong passwords take the same time to reject, preventing username enumeration through response timing.

**HTTP**: `401 Unauthorized`

```json
{ "error": "invalid_credentials" }
```

### `session_expired`

The session has exceeded its TTL (default 72 hours). Verification checks `expires_at > now()` and rejects expired sessions. The client must re-authenticate.

**HTTP**: `401 Unauthorized`

```json
{ "error": "session_expired" }
```

### `invalid_token`

The provided token has the wrong prefix or format. Session tokens must start with `aeg_s_` — anything else is rejected before it reaches storage. This also covers service tokens accidentally sent to session endpoints.

**HTTP**: `401 Unauthorized`

```json
{ "error": "invalid_token" }
```

### `identity_disabled`

The identity's state is `Disabled`. Disabled accounts can't create sessions or verify tokens.

**HTTP**: `403 Forbidden`

```json
{ "error": "identity_disabled" }
```

### `forbidden`

The service token doesn't have the grant required for the operation.

**HTTP**: `403 Forbidden`

```json
{ "error": "forbidden" }
```

### `rate_limited`

Too many requests from this source. Surge applies per-route rate limits configured via environment variables. `retry_after` gives the number of seconds to wait.

**HTTP**: `429 Too Many Requests`

```json
{ "error": "rate_limited", "retry_after": 30 }
```

### `validation_error`

Input failed validation — username too short/long, password doesn't meet requirements, or required fields are missing. `message` describes the specific failure.

**HTTP**: `422 Unprocessable Entity`

```json
{ "error": "validation_error", "message": "password must be at least 8 characters" }
```

### `not_found`

The requested resource (identity, session, or flow) doesn't exist.

**HTTP**: `404 Not Found`

```json
{ "error": "not_found" }
```

### `username_taken`

The requested username is already in use by another identity.

**HTTP**: `409 Conflict`

```json
{ "error": "username_taken" }
```

### `unavailable`

A dependency the request needed (e.g. the database) is temporarily unreachable.

**HTTP**: `503 Service Unavailable`

```json
{ "error": "unavailable" }
```

### `timeout`

The request took too long to complete against a downstream dependency.

**HTTP**: `504 Gateway Timeout`

```json
{ "error": "timeout" }
```

## HTTP status code mapping

| Status | Code | Error types |
|---|---|---|
| `401` | Unauthorized | `invalid_service_token`, `missing_service_token`, `invalid_credentials`, `invalid_token`, `session_expired` |
| `403` | Forbidden | `forbidden`, `identity_disabled` |
| `404` | Not Found | `not_found` |
| `409` | Conflict | `username_taken` |
| `422` | Unprocessable Entity | `validation_error` |
| `429` | Too Many Requests | `rate_limited` |
| `503` | Service Unavailable | `unavailable` |
| `504` | Gateway Timeout | `timeout` |

## Error handling

Branch on `error`, not on `message` — the code is stable, the message text isn't. Retry with backoff on `rate_limited` (respecting `retry_after`) or `unavailable`/`timeout`; all other errors indicate a condition the client must resolve before retrying (wrong credentials, expired session, missing permission).

**Related:** Each endpoint page lists its specific error responses.
