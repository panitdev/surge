---
description: Run surge-server as a standalone service and connect your applications via RemoteProvider.
---

# Running as a Server

Run `surge-server` as a standalone authentication service. Your applications connect over HTTP using Bearer tokens via the `RemoteProvider` client.

## Building and starting the server

Build the server binary from source:

```bash
cargo build -p surge-server
```

Or run directly:

```bash
cargo run -p surge-server -- serve
```

The binary is also available as a pre-built Docker image — see [Docker](/deployment/docker).

## Required environment variables

At minimum, two variables must be set:

```bash
export DATABASE_URL="postgres://localhost/surge"
export SURGE_PEPPER="dev-pepper-change-me"  # change this in production
```

All other settings fall back to defaults. For the full list, see [Configuration](/integration/configuration).

## The `serve` subcommand

The `serve` subcommand starts the HTTP server. It accepts an optional `--bind` flag that overrides `SURGE_BIND`:

```bash
# Default: reads SURGE_BIND or falls back to 0.0.0.0:3000
surge-server serve

# Explicit bind address (takes precedence over env)
surge-server serve --bind 127.0.0.1:8080
```

On startup, the server:
1. Parses environment configuration (`ServerConfig::from_env()`)
2. Creates an embedded provider (runs database migrations)
3. Assembles the browser and service-facing API routers
4. Runs startup coherence checks
5. Begins listening and accepting traffic

## Startup coherence checks

Before accepting traffic, the server validates that the configuration is internally consistent:

```rust
fn check_startup_coherence(config: &ServerConfig, return_origins: &[String]) -> anyhow::Result<()> {
    // Warn if no return_origins are registered — every GET /login redirect will fail
    if return_origins.is_empty() { /* warn */ }

    // Bail if CORS origins are set but don't include the auth UI origin
    if !config.session_cors_origins.is_empty()
        && !config.session_cors_origins.iter().any(|o| o == &config.auth_ui_origin)
    { /* bail */ }

    // Warn if served+inline is enabled — the operator should understand the tradeoff
    if config.allow_served_inline { /* warn */ }

    Ok(())
}
```

These checks catch misconfigurations at boot rather than letting them surface as cryptic runtime errors during a real login attempt.

## Health check

The server exposes a `GET /health` endpoint that returns `204 No Content` when the database is reachable:

```bash
curl -i http://localhost:3000/health
```

```
HTTP/1.1 204 No Content
```

Use this for container health checks, load balancer probes, and monitoring. See [Health Checks](/deployment/health-checks) for details on Kubernetes probes and container orchestration.

## Connecting client applications

### RemoteProvider (Rust)

Applications connect to surge-server over HTTP using `RemoteProvider`, available from the `surge` crate with the `remote` feature:

```toml
[dependencies]
surge = { version = "0.1", features = ["remote"] }
```

```rust
use std::sync::Arc;
use std::time::Duration;
use surge::{RemoteConfig, RemoteProvider, AuthProvider};

let provider: Arc<dyn AuthProvider> = Arc::new(
    RemoteProvider::new(RemoteConfig {
        base_url: "https://auth.example.com".parse()?,
        service_token: SecretString::from("aeg_svc_...".to_string()),
        cache_ttl: Duration::from_secs(60),
        cache_max_entries: 10_000,
        timeout: Duration::from_secs(5),
    })?
);
```

`RemoteConfig` fields:

| Field | Purpose |
|---|---|
| `base_url` | URL of the surge-server instance |
| `service_token` | Bearer token with appropriate grants |
| `cache_ttl` | How long session verifications are cached (moka in-memory cache) |
| `cache_max_entries` | Maximum number of cached session entries |
| `timeout` | HTTP request timeout |

### Moka caching

`RemoteProvider` uses the [moka](https://crates.io/crates/moka) crate for in-memory caching of session verifications. When your service calls `verify_session()`, the result is cached for `cache_ttl`. Subsequent calls for the same session within that window skip the network round trip entirely.

The cache key is a byte hash of the session token — tokens are never stored in plaintext in the cache. Cache eviction follows a TTL-based policy, not LRU.

### Browser-facing apps: cross-origin with CORS

When your frontend runs on a different origin than surge-server, you need to configure the cross-origin session-management zone:

```bash
# Allow your apps to call /v1/whoami and /v1/logout from their own origins
export SURGE_SESSION_CORS_ORIGINS="https://auth.panit.dev,https://app.example.com"
```

The credential-entry zone (`/v1/login`, `/v1/flows/*`) is always restricted to the auth UI origin — cross-origin credential submission is never allowed.

### Browser-facing apps: same-origin via proxy

If you want to avoid CORS entirely, proxy requests to surge-server from your application server. Your frontend calls `/api/auth/v1/whoami` on your domain, your server forwards to `https://auth.internal:3000/v1/whoami`. Everything is same-origin — no CORS configuration needed.

## Service token management

Manage service tokens via the CLI:

```bash
# Create a service with grants
surge-server svc create \
  --name my-app \
  --grant introspect \
  --grant identity_read \
  --origin https://app.example.com

# Output:
# Service created:
#   ID:     018f9a1b-...
#   Name:   my-app
#   Grants: ["introspect", "identity_read"]
#   Token:  aeg_svc_1a2b3c4d5e6f7g8h9i0j
#
# Store this token securely — it cannot be retrieved again.

# List all registered services
surge-server svc list

# Revoke a service token
surge-server svc revoke my-app
```

Available grants:

| Grant | Allows |
|---|---|
| `introspect` | Verify sessions and get session metadata |
| `identity_read` | Look up identities by ID or username |
| `identity_write` | Create and update identities |
| `direct_auth` | Authenticate users by password |
| `revoke` | Revoke sessions |

The `--origin` flag registers return origins for redirect-mode login flows. Each service that participates in browser login redirects should register its origin.

## Identity management via CLI

The CLI manages existing identities but does not create them — in closed registration mode, identity creation happens only through the service API (`identity_write` grant; see [Registration Modes](/integration/registration-modes)).

```bash
# Generate and print a random temporary password, revoking all sessions
surge-server identity reset-password alice

# Enable/disable an identity (also revokes sessions on disable)
surge-server identity enable alice
surge-server identity disable alice

# Rename an identity (does not update downstream systems automatically)
surge-server identity rename alice alice2
```
