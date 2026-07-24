---
description: Use TestProvider for development and testing — every request is authenticated with a fixed identity, no database required.
---

# Test Provider

During development you often iterate on features unrelated to auth. Standing up a database, registering a user, and logging in on every cycle slows you down. `TestProvider` removes that friction: it implements `AuthProvider` with a single fixed identity, accepts any session token, and needs no database or network.

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
| `verify_session` | Accepts any `aeg_s_*` token. Always returns the fixed identity. |
| `authenticate_password` | Always succeeds, ignoring username and password. |
| `register` | Returns the fixed identity without creating anything. |
| `register_and_authenticate` | Returns the fixed identity with a session token. |
| `identity` / `identity_by_username` | Returns the fixed identity regardless of arguments. |
| `update_profile` | Applies the patch in memory; subsequent calls reflect the change. |
| `revoke_session` / `revoke_all_sessions` | No-ops — the provider stays "always authenticated". |

## Using with the AuthSession extractor

`TestProvider` works with the standard `AuthSession` extractor. The extractor reads the token from a `surge_session` cookie or `Authorization: Bearer` header, then calls `verify_session` — which the test provider always succeeds.

Your service code needs no changes:

```rust
use surge::AuthSession;

async fn dashboard(AuthSession(session): AuthSession) -> String {
    format!("Hello, {}", session.identity.display_name)
}
```

Requests just need any validly-prefixed token:

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
