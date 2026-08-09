---
description: Embed Surge directly into your Axum application using EmbeddedProvider.
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
- `router` — enables `browser_router()` on providers for mounting browser-facing auth routes in your Axum app

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

The `AuthProvider` trait is what your service code uses to verify sessions, look up identities, and authenticate passwords.

## Mounting the browser router

Call `browser_router()` on your provider to get an `axum::Router`:

```rust
use surge::router::{BrowserRouterConfig, PostgresRateLimiter, RateLimitConfig};
use surge::router::RegistrationMode;

let provider = Arc::new(provider);
let engine = provider.engine();

let browser_router = Arc::clone(&provider).browser_router(BrowserRouterConfig {
    cookie_domain: ".example.com".to_string(),
    session_ttl: Duration::from_secs(72 * 3600),
    auth_ui_origin: "https://auth.example.com".to_string(),
    session_cors_origins: vec![],
    rate_limiter: Some(Arc::new(PostgresRateLimiter::new(
        Arc::clone(&engine),
        RateLimitConfig::default(),
    ))),
    return_origins: Some(vec!["https://app.example.com".to_string()]),
    registration: Some(RegistrationMode::Open),
    factor_policy: Some(surge::router::FactorPolicy::None),
    allow_inline: Some(true),  // safe in embedded mode
    oauth_bridge: None,
    maintenance_interval: None,  // default: sweep every 15 minutes
});

// Axum router
let app = Router::new()
    .merge(browser_router)
    // ... your other routes
    ;

// Rate limiting keys on the client address, which is only available when
// the server is bound this way:
axum::serve(
    listener,
    app.into_make_service_with_connect_info::<SocketAddr>(),
).await?;
```

You may mount the router under a prefix of your own — `.nest("/api/surge", browser_router)` — as long as your frontend's `baseUrl` matches. The prefix is local addressing; in remote mode the proxy strips it before forwarding upstream.

`BrowserRouterConfig` fields:

| Field | Description |
|---|---|
| `cookie_domain` | Domain for session cookies (e.g. `.example.com`) |
| `session_ttl` | Session lifetime |
| `auth_ui_origin` | Where the auth UI is served (used for redirect mode) |
| `session_cors_origins` | Origins allowed for cross-origin session management (leave empty for same-origin) |
| `rate_limiter` | Per-IP and per-username rate limiter — embedded only (use `PostgresRateLimiter` for Postgres-backed counters) |
| `return_origins` | Allowed `return_to` targets after login — embedded only |
| `registration` | `Open`, `Invite`, or `Closed` — embedded only |
| `factor_policy` | Soft factor-enrollment policy surfaced to the frontend — embedded only |
| `allow_inline` | Enable content-negotiated inline flow-init (`Accept: application/json`) — embedded only |
| `oauth_bridge` | Opt-in Hydra login/consent bridge — embedded only |
| `maintenance_interval` | Background sweep cadence. `None` = every 15 minutes; `Duration::ZERO` = you drive it — embedded only |

The `Option` fields are required for `EmbeddedProvider` (panics if `rate_limiter` is `None`) and ignored by `RemoteProvider` — the remote surge-server handles those settings itself.

In embedded mode, set `allow_inline: Some(true)` unconditionally — there's no coarsened rate-limiting tradeoff when Surge runs in your process.

## Background maintenance

Mounting an embedded browser router starts the sweep for you: a background task calls `provider.run_maintenance()` every `maintenance_interval`, which in turn:
- Garbage-collects expired sessions (`engine.gc_expired_sessions()`)
- Sweeps expired login flows (`engine.gc_expired_login_flows()`)

Without it, expired sessions and flows accumulate in the database — they won't cause correctness issues (the engine rejects them regardless), but they'll bloat storage over time.

To drive the cadence yourself, or to run a provider with no router mounted on it, opt out and call it directly:

```rust
use surge::router::spawn_maintenance;

// in BrowserRouterConfig: maintenance_interval: Some(Duration::ZERO)
spawn_maintenance(provider as Arc<dyn AuthProvider>, Duration::from_secs(5 * 60));
```

`RemoteProvider` ignores this setting — the upstream surge-server sweeps its own tables.

## Remote mode: the browser perimeter is a proxy

`RemoteProvider::browser_router()` returns a reverse proxy onto the remote surge-server's own perimeter, because the policy that perimeter enforces (rate limits, flow state, CSRF) needs the database.

That makes your service part of upstream's trust boundary rather than an anonymous client of it. The proxy authenticates each forwarded request with your service token and states the end user's address in `X-Surge-Client-Ip`, so upstream keys rate limits on the actual user instead of on your service — without it, `authenticate`'s 10-per-15-minutes-per-IP budget covers your entire user base at once, and a handful of failed logins locks everyone out.

Two requirements:

1. Your service token needs the `browser_proxy` grant:
   ```
   surge-server svc create --name web --grant introspect --grant browser_proxy
   ```
2. Serve with `into_make_service_with_connect_info::<SocketAddr>()`, or the proxy has no address to state. It logs a warning once if this is missing.

Upstream rejects an `X-Surge-Client-Ip` that isn't accompanied by a valid `browser_proxy` token, so a browser cannot spoof its way into a different rate-limit bucket. The proxy also narrows what crosses the boundary: only `surge_`-prefixed cookies are forwarded, and `X-Surge-Client-Ip` / `X-Surge-Service-Token` arriving from the browser are stripped rather than passed on.

## Full example: minimal Axum app

```rust
use std::sync::Arc;
use std::time::Duration;
use axum::{Router, routing::get};
use secrecy::SecretString;
use surge::{
    router::{BrowserRouterConfig, PostgresRateLimiter, RateLimitConfig, RegistrationMode,
             FactorPolicy},
    AuthProvider, EmbeddedConfig, EmbeddedProvider,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Create the embedded provider (runs migrations)
    let provider = Arc::new(
        EmbeddedProvider::new(EmbeddedConfig {
            database_url: SecretString::from("postgres://localhost/surge".into()),
            pepper: SecretString::from("dev-pepper-change-me".into()),
            session_ttl: Duration::from_secs(72 * 3600),
        })
        .await?,
    );

    let engine = provider.engine();

    // 2. Build the browser router
    let browser_router = Arc::clone(&provider).browser_router(BrowserRouterConfig {
        cookie_domain: "localhost".to_string(),
        session_ttl: Duration::from_secs(72 * 3600),
        auth_ui_origin: "http://localhost:3000".to_string(),
        session_cors_origins: vec![],
        rate_limiter: Some(Arc::new(PostgresRateLimiter::new(
            Arc::clone(&engine),
            RateLimitConfig::default(),
        ))),
        return_origins: Some(vec!["http://localhost:3000".to_string()]),
        registration: Some(RegistrationMode::Open),
        factor_policy: Some(FactorPolicy::None),
        allow_inline: Some(true),
        oauth_bridge: None,
        // Session GC and flow expiry sweep every 15 minutes, started by
        // mounting the router below.
        maintenance_interval: None,
    });

    // 3. Mount everything
    let app = Router::new()
        .route("/", get(|| async { "Hello" }))
        .merge(browser_router);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    // `into_make_service_with_connect_info` is what makes the client
    // address visible to rate limiting.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

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
