---
description: Use TestProvider for development and testing — every request is authenticated with a fixed identity, no database required.
---

# Test Provider

During development you often iterate on features unrelated to auth. Standing up a database, registering a user, and logging in on every cycle slows you down. `TestProvider` removes that friction: it implements `AuthProvider` with a single fixed identity, authenticates requests with or without a session token, and needs no database or network.

::: danger Production warning
`TestProvider` authenticates **every** request unconditionally. It must never be used in production. It is gated behind the `test-provider` Cargo feature to prevent accidental inclusion.
:::

## Setup

Add the `surge` crate with the `test-provider` feature:

```toml
[dependencies]
surge = { version = "0.1", features = ["test-provider"] }
```

## Creating the provider

```rust
use std::sync::Arc;
use surge::{AuthProvider, TestConfig};

let provider: Arc<dyn AuthProvider> = surge::test(TestConfig::default())?;
```

That's it — no database URL, no pepper, no migrations. The provider is ready immediately.

A warning is logged at construction so you'll always know when it's active:

```
WARN surge::test_provider: TestProvider active -- every request is authenticated as this identity. DO NOT use in production. username=test-user
```

### Custom identity

Override the defaults by passing your own `TestConfig`:

```rust
let provider = surge::test(TestConfig {
    username: "dev-alice".into(),
    display_name: "Alice (dev)".into(),
})?;
```

The username must pass Surge's standard validation (3–32 lowercase alphanumeric characters and single hyphens).

## Behavior

| Method | Behavior |
|---|---|
| `verify_session` | Accepts `Some`(any `aeg_s_*` token) or `None`. Always returns the fixed identity. |
| `authenticate_password` | Always succeeds, ignoring username and password. |
| `register` | Returns the fixed identity without creating anything. |
| `register_and_authenticate` | Returns the fixed identity with a session token. |
| `identity` / `identity_by_username` | Returns the fixed identity regardless of arguments. |
| `update_profile` | Applies the patch in memory; subsequent calls reflect the change. |
| `revoke_session` / `revoke_all_sessions` | No-ops — the provider stays "always authenticated". |
| `browser_router` | Serves `GET /v1/whoami` only. Every other perimeter route returns `501`. |

## Browser router

`TestProvider` mounts a read-only perimeter, so a frontend can answer "am I logged in, and who am I?" without a database:

```rust
let app = Router::new()
    .merge(Arc::clone(&provider).browser_router(BrowserRouterConfig {
        cookie_domain: "localhost".into(),
        session_ttl: Duration::from_secs(3600),
        auth_ui_origin: "http://localhost:5173".into(),
        session_cors_origins: vec![],
        // Embedded-only fields are ignored — no rate limiter needed.
        rate_limiter: None,
        return_origins: None,
        registration: None,
        factor_policy: None,
        allow_inline: None,
        oauth_bridge: None,
        maintenance_interval: None,
    }));
```

`GET /v1/whoami` returns the same session JSON as the real perimeter ([Whoami](/api/browser/whoami)), always `200` — there is no unauthenticated state to represent. It carries no `policy` block, since the fixed identity enrolls no factors.

Everything else — `/v1/login`, the flow routes, `/v1/logout`, the factor routes — answers `501 not_implemented`. The identity is fixed, so there is no credential to submit and no session to revoke; returning `501` surfaces that instead of faking success. If your frontend calls `logout()`, expect it to fail under `TestProvider` and branch accordingly.

## Using with the AuthSession extractor

`TestProvider` works with the standard `AuthSession` extractor. The extractor reads and parses the token from a `surge_session` cookie or `Authorization: Bearer` header, then calls `verify_session`. A missing or malformed carrier is passed as `None`; the test provider always succeeds, so no cookie or header is required.

Your service code needs no changes:

```rust
use surge::AuthSession;

async fn dashboard(AuthSession(session): AuthSession) -> String {
    format!("Hello, {}", session.identity.display_name)
}
```

Requests may omit authentication entirely. They can also provide any validly-prefixed token:

```bash
curl http://localhost:3000/dashboard \
  -H "Authorization: Bearer aeg_s_anything"
```

## Switching providers by environment

A common pattern is to select the provider at startup based on an environment variable:

```rust
let provider: Arc<dyn AuthProvider> = if cfg!(feature = "test-provider")
    && std::env::var("SURGE_TEST_PROVIDER").as_deref() == Ok("true")
{
    surge::test(TestConfig::default())?
} else {
    surge::embedded(EmbeddedConfig { /* ... */ }).await?
};
```

This keeps production builds clean — when `test-provider` isn't in your feature set, the branch compiles away entirely.
