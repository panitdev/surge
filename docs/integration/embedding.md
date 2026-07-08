---
description: Embed Surge directly into your Axum application using EmbeddedProvider and BrowserRouter.
---

# Embedding in Axum

Add Surge as a dependency in your Rust application and mount its router at a path of your choice. Surge runs in your process, shares your database, and handles all auth routes without a separate server.

## Dependency setup

Add the `surge` crate with the `embedded` and `router` features:

```toml
[dependencies]
surge = { version = "0.1", features = ["embedded", "router"] }
```

- `embedded` — brings in `EmbeddedProvider` and `EmbeddedConfig` for in-process auth
- `router` — brings in `BrowserRouter` for mounting browser-facing auth routes in your Axum app

## Creating the Engine

At the heart of an embedded deployment is an `Engine`, which wraps your database pool and runs all auth operations. Construct it through `EmbeddedProvider::new()`:

```rust
use std::sync::Arc;
use std::time::Duration;
use secrecy::SecretString;
use surge::{EmbeddedConfig, EmbeddedProvider};

let provider = EmbeddedProvider::new(EmbeddedConfig {
    database_url: SecretString::from(
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/surge".into()),
    ),
    pepper: SecretString::from(
        std::env::var("SURGE_PEPPER")
            .unwrap_or_else(|_| "dev-pepper-change-me".into()),
    ),
    session_ttl: Duration::from_secs(72 * 3600),
})
.await?;
```

`EmbeddedProvider::new()` does three things:
1. Builds an `Engine` with your database URL, pepper, and session TTL
2. Runs pending Diesel migrations against your database
3. Returns an `EmbeddedProvider` that implements `AuthProvider`

Both `database_url` and `pepper` are `SecretString` — they never leak into logs.

### EngineConfig for fine-tuning

If you need more control, construct the `Engine` directly with `EngineConfig`:

```rust
use std::collections::HashMap;
use surge_engine::{Engine, EngineConfig, PepperConfig};

let mut peppers = HashMap::new();
peppers.insert(1u8, SecretString::from("my-pepper".to_string()));

let engine = Engine::new(EngineConfig {
    database_url: SecretString::from("postgres://localhost/surge".into()),
    pepper: PepperConfig {
        current_version: 1,
        peppers,
    },
    session_ttl: Duration::from_secs(72 * 3600),
})
.await?;

engine.run_migrations().await?;
```

`PepperConfig` supports multiple pepper versions — useful for key rotation without invalidating all existing credentials at once. Version `1` is the default; set `current_version` to whichever version you want new credentials to use.

## Wrapping in EmbeddedProvider

`EmbeddedProvider` wraps the engine and provides access through two interfaces:

```rust
// AuthProvider trait — for your application code
let provider: Arc<dyn AuthProvider> = Arc::new(provider);

// Direct engine access — for the router perimeter
let engine: Arc<Engine> = provider.engine();
```

The `AuthProvider` trait is what your service code uses to verify sessions, look up identities, and authenticate passwords. The `Engine` handle is what the `BrowserRouter` needs — it gives the router direct access to login flow state and the counter store, neither of which belongs on the `AuthProvider` trait.

## Mounting the BrowserRouter

Create a `BrowserRouter` and mount it at a path in your Axum app:

```rust
use surge::router::{browser, BrowserRouterConfig, PostgresRateLimiter, RateLimitConfig};
use surge::router::RegistrationMode;

let engine = provider.engine();

let browser_router = browser(BrowserRouterConfig {
    engine: Arc::clone(&engine),
    provider: Arc::clone(&provider) as Arc<dyn AuthProvider>,
    rate_limiter: Arc::new(PostgresRateLimiter::new(
        Arc::clone(&engine),
        RateLimitConfig::default(),
    )),
    cookie_domain: ".example.com".to_string(),
    session_ttl: Duration::from_secs(72 * 3600),
    auth_ui_origin: "https://auth.example.com".to_string(),
    session_cors_origins: vec![],
    return_origins: vec!["https://app.example.com".to_string()],
    registration: RegistrationMode::Open,
    allow_inline: true,  // safe in embedded mode
});

// Axum router
let app = Router::new()
    .nest("/api/surge", browser_router.into_axum())
    // ... your other routes
    ;
```

`BrowserRouterConfig` fields:

| Field | Description |
|---|---|
| `engine` | Direct `Engine` access for flow state and counters |
| `provider` | `AuthProvider` for credential verification and session operations |
| `rate_limiter` | Per-IP and per-username rate limiter (use `PostgresRateLimiter` for Postgres-backed counters) |
| `cookie_domain` | Domain for session cookies (e.g. `.example.com`) |
| `session_ttl` | Session lifetime |
| `auth_ui_origin` | Where the auth UI is served (used for redirect mode) |
| `session_cors_origins` | Origins allowed for cross-origin session management (leave empty for same-origin) |
| `return_origins` | Allowed `return_to` targets after login |
| `registration` | `Open`, `Invite`, or `Closed` |
| `allow_inline` | Enable content-negotiated inline flow-init (`Accept: application/json`) |

In embedded mode, set `allow_inline: true` unconditionally — there's no coarsened rate-limiting tradeoff when Surge runs in your process.

## Background maintenance

The `BrowserRouter` owns periodic maintenance tasks. Spawn them with a configurable interval:

```rust
// Run session GC and flow expiry sweeping every 15 minutes
browser_router.spawn_maintenance(Duration::from_secs(15 * 60));
```

This spawns a background task that calls `provider.run_maintenance()` on the configured interval, which in turn:
- Garbage-collects expired sessions (`engine.gc_expired_sessions()`)
- Sweeps expired login flows (`engine.gc_expired_login_flows()`)

If you skip maintenance, expired sessions and flows accumulate in the database — they won't cause correctness issues (the engine rejects them regardless), but they'll bloat storage over time.

## Full example: minimal Axum app

```rust
use std::sync::Arc;
use std::time::Duration;
use axum::{Router, routing::get};
use secrecy::SecretString;
use surge::{
    router::{browser, BrowserRouterConfig, PostgresRateLimiter, RateLimitConfig, RegistrationMode},
    AuthProvider, EmbeddedConfig, EmbeddedProvider,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Create the embedded provider (runs migrations)
    let provider = EmbeddedProvider::new(EmbeddedConfig {
        database_url: SecretString::from("postgres://localhost/surge".into()),
        pepper: SecretString::from("dev-pepper-change-me".into()),
        session_ttl: Duration::from_secs(72 * 3600),
    })
    .await?;

    let engine = provider.engine();
    let auth: Arc<dyn AuthProvider> = Arc::new(provider);

    // 2. Build the browser router
    let browser_router = browser(BrowserRouterConfig {
        engine: Arc::clone(&engine),
        provider: Arc::clone(&auth),
        rate_limiter: Arc::new(PostgresRateLimiter::new(
            Arc::clone(&engine),
            RateLimitConfig::default(),
        )),
        cookie_domain: "localhost".to_string(),
        session_ttl: Duration::from_secs(72 * 3600),
        auth_ui_origin: "http://localhost:3000".to_string(),
        session_cors_origins: vec![],
        return_origins: vec!["http://localhost:3000".to_string()],
        registration: RegistrationMode::Open,
        allow_inline: true,
    });

    browser_router.spawn_maintenance(Duration::from_secs(15 * 60));

    // 3. Mount everything
    let app = Router::new()
        .route("/", get(|| async { "Hello" }))
        .merge(browser_router.into_axum());

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

This gives you:
- `GET /v1/login` — login flow initiation
- `POST /v1/flows/{id}/password` — password submission
- `POST /v1/flows/{id}/register` — registration (if mode allows)
- `GET /v1/whoami` — session introspection
- `POST /v1/logout` — session revocation
- Background session GC and flow expiry sweeping

## Embedding vs. served: when to use which

| | Embedded | Served (SSO) |
|---|---|---|
| Infrastructure | Your process only | Separate server process |
| Latency | Zero network hop | HTTP round trip per auth call |
| Session cookies | Set on your domain | Set on Surge's domain |
| Browser flow | Inline in your app | Redirect to/from auth UI |
| Best for | Single service | Multi-service user base |

You can even mix both: embed Surge in your primary service while other services connect to the same database via `RemoteProvider`. All sessions land in the same database — a session minted by an embedded provider is valid when verified through a remote one.
