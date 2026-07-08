---
description: Service-to-service authentication using Bearer tokens with grant-based permissions.
---

# Service Authentication

Backend services authenticate to Surge using Bearer tokens prefixed with `aeg_svc_`. Each token carries a set of grants that control which operations the service can perform.

## Service token lifecycle

Service tokens authenticate backend services to Surge. Each token carries grants that scope what the service can do. Tokens follow the same security pattern as session tokens: they're shown once at creation and stored as SHA-256 hashes.

### Creating tokens

Use the CLI to create a service token:

```bash
cargo run -p surge-server -- svc create --name my-service
```

Output:

```
Service token: aeg_svc_1a2b3c4d5e6f7g8h9i0j
```

The plaintext token is displayed **once**. Copy it immediately — if you lose it, you must revoke and recreate. Service tokens can only be created and revoked via the CLI; there is no HTTP endpoint for managing them.

### Listing tokens

```bash
cargo run -p surge-server -- svc list
```

Shows all registered services with their grants, without exposing token values (only SHA-256 hashes are stored).

### Revoking tokens

```bash
cargo run -p surge-server -- svc revoke my-service
```

Revoking a token immediately invalidates it. Any service using that token will receive authentication errors on their next request.

## Token format

Service tokens are generated the same way as session tokens — 128-bit random, base62-encoded — but with a different prefix:

| Property | Value |
|---|---|
| Entropy | 128 bits |
| Encoding | Base62 |
| Prefix | `aeg_svc_` |
| Storage | SHA-256 hash |

The `aeg_svc_` prefix distinguishes service tokens from session tokens (`aeg_s_`) and flow IDs (`aeg_f_`) in logs and traffic.

## How services present tokens

Services authenticate by sending the token in the `Authorization` header:

```bash
curl -X POST http://localhost:3000/v1/sessions/verify \
  -H "Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j" \
  -H "Content-Type: application/json" \
  -d '{"token": "aeg_s_..."}'
```

Every request to the Surge service API is authenticated the same way: the `Bearer` token is hashed and looked up against stored service tokens, and the request is rejected if the token is missing, malformed, or revoked.

## Grants

Grants are fine-grained permissions attached to service tokens. When you create a token, you specify which grants it needs; each endpoint requires one specific grant, and a request without it is rejected.

### Available grants

| Grant | Allows |
|---|---|
| `introspect` | Verify sessions; look up identity state |
| `identity_read` | Read identity profiles |
| `identity_write` | Update identity profiles |
| `direct_auth` | Register and authenticate identities directly (password auth) |
| `revoke` | Revoke sessions |

### Scoping tokens

Create a token with specific grants — not every service needs full access:

```bash
# Read-only introspection service
cargo run -p surge-server -- svc create --name auth-gateway --grant introspect

# Identity management service  
cargo run -p surge-server -- svc create --name user-admin --grant identity_read --grant identity_write
```

Services that attempt an operation without the required grant receive an HTTP 403 Forbidden response.

## RemoteProvider client

Rust services can use the `RemoteProvider` client instead of constructing HTTP requests manually. It wraps the Surge API and includes built-in caching:

```rust
use surge::{RemoteConfig, RemoteProvider};
use std::sync::Arc;
use std::time::Duration;

let provider = Arc::new(RemoteProvider::new(RemoteConfig {
    base_url: "https://auth.example.com".parse()?,
    service_token: "aeg_svc_1a2b3c4d5e6f7g8h9i0j".into(),
    cache_ttl: Duration::from_secs(30),
    cache_max_entries: 10_000,
    timeout: Duration::from_secs(5),
})?);

// Verify a session — result is cached via moka
let result = provider.verify_session("aeg_s_...").await?;
```

The `RemoteProvider` uses **[moka](https://crates.io/crates/moka)** for in-memory caching of verification results, reducing load on the auth server for repeated lookups of the same session token. Cache entries have a short TTL aligned with your session verification patterns.

**Related:** [Configuration](/integration/configuration), [API Reference](/api/service/session-verify)
