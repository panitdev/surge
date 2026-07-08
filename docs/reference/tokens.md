---
description: Token format specification, prefix registry, and hash mechanics for all Surge token types.
---

# Tokens

Surge uses prefixed token strings for sessions, service authentication, login flows, and resets. Each token type has a distinct prefix and format.

| Prefix | Type | Description | Example |
|---|---|---|---|
| `aeg_s_` | Session token | Identifies a user session; returned once on login | `aeg_s_3k7m9p2q5r8t1v4w6x` |
| `aeg_svc_` | Service token | Authenticates a backend service; returned once on `svc create` | `aeg_svc_1a2b3c4d5e6f7g8h9i0j` |
| `aeg_f_` | Flow ID | Identifies a login flow; not secret, used in URLs | `aeg_f_7h2k9m4p6r8t1w3v5` |
| `aeg_r_` | Reset token | Authorizes a password reset; **type exists in the engine but is not yet wired to any API endpoint** | `aeg_r_9x2y4z6a8b0c1d2e3f` |

## Token generation

All secret tokens (session, service, reset) share the same generation process: 128 bits of random entropy, base62-encoded, then zero-padded on the left to a fixed 22-character body, with the type prefix prepended.

| Property | Value |
|---|---|
| Entropy | 128 bits (cryptographically secure, from `rand::rng()`) |
| Encoding | Base62 (`[0-9a-zA-Z]`) — URL-safe, no special characters |
| Body length | 22 characters after the prefix (left-padded with `0` if the encoded value is shorter) |
| Total length | prefix length + 22 |

The 128-bit entropy provides `2^128` possible values — well beyond practical brute-force range. Base62 encoding keeps tokens compact and URL-safe (no `+`, `/`, or `=` like base64).

### Flow IDs

Flow IDs use the same generation algorithm but are **not secrets**. They appear as URL path parameters and query string values. Unlike session and service tokens, flow IDs are stored as plaintext (not hashed) in the database because they don't grant access on their own — the CSRF token and flow state control authorization.

## Hash storage

Secret tokens are never stored as plaintext in the database. Each token is hashed with SHA-256 before storage:

```
Raw token:        aeg_s_3k7m9p2q5r8t1v4w6x
SHA-256 hash:     e3b0c44298fc1c14... (32 bytes)
DB column:        BYTEA (Postgres)
```

When a token is submitted for verification, Surge:
1. Extracts the token from the cookie/header
2. Hashes it with SHA-256
3. Looks up the hash in the database with an indexed query

The raw token is only shown **once** — when it's generated:

| Token type | When shown |
|---|---|
| Session (`aeg_s_`) | In the `Set-Cookie` header on login/register |
| Service (`aeg_svc_`) | Printed to stdout on `surge-server svc create` |
| Reset (`aeg_r_`) | Not applicable — no endpoint currently issues reset tokens |

After that initial exposure, the raw token cannot be recovered. If lost, the only option is to create a new token and revoke the old one.

### Verification

```bash
# A session token is verified by hashing and querying
let hash = sha256(raw_token.as_bytes());
let session = db.query("SELECT ... FROM session WHERE hash = $1", &hash);
```

The hash column has a database index for fast lookups. Verification is a single indexed query — no scanning.

## Prefix stability guarantee

Token prefixes are a **stability guarantee**:

> Once a prefix is accepted into the codebase, it will remain accepted as long as live tokens with that prefix exist.

This means you can safely hardcode prefix checks in your routing logic:

```rust
// Safe to do — prefix is stable
match token {
    t if t.starts_with("aeg_s_") => handle_session(t),
    t if t.starts_with("aeg_svc_") => handle_service(t),
    _ => reject(t),
}
```

Prefixes are not versioned or deprecated while live tokens exist. If a prefix format changes, it would be via a new prefix coexisting with the old one during a migration window.

## Token validation

When parsing a token from a request, Surge validates:

1. **Prefix check**: The token must start with a recognized prefix (`aeg_s_`, `aeg_svc_`, `aeg_f_`, `aeg_r_`) and have at least one character after it
2. **Hash lookup** (secret tokens only): The SHA-256 hash of the token body must exist in the database
3. **State check**: The associated record must be valid (session not revoked/expired, flow not completed/expired, etc.)

There is no strict length or charset check beyond the prefix — a malformed but correctly-prefixed string simply fails the hash lookup in step 2.

Tokens that fail any step are rejected as invalid. The specific failure reason is not surfaced in the error response — this prevents information leakage about which tokens exist.

## Storing tokens in your application

```bash
# Environment variable (recommended for service tokens)
export SURGE_SERVICE_TOKEN="aeg_svc_3k7m9p2q5r8t1v4w6x"

# Secrets manager (production)
aws secretsmanager get-secret-value --secret-id surge/service-token

# Session tokens — only in cookies, never in localStorage
Set-Cookie: surge_session=aeg_s_...; HttpOnly; Secure; SameSite=Lax
```

**Never** store session tokens in `localStorage` or `sessionStorage` — this makes them accessible to JavaScript and vulnerable to XSS. Session tokens should always be `HttpOnly` cookies.

**Service tokens** should be stored as environment variables or in a secrets manager. They grant API access and should be treated with the same care as database credentials.

**Related:** [Service Authentication](/features/service-authentication), [Session Management](/features/session-management)
