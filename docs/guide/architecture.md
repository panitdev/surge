---
description: How Surge switches between embedded and SSO modes, the AuthProvider seam, and the session stability guarantee.
---

# Architecture

Surge is designed around one idea: **your application code should not care whether auth runs in-process or as a remote SSO server.** The switch is a startup choice, not an architectural commitment.

## The provider seam

Every auth operation — verify a session, look up an identity, authenticate a password — goes through the `AuthProvider` trait. There are two implementations:

| Provider | Behavior |
|---|---|
| `EmbeddedProvider` | All auth logic runs in your process, directly against your database. No network hop. |
| `RemoteProvider` | Calls forward to a remote `surge-server` over HTTP, with a built-in cache to reduce round trips. |

Your application code works with `Arc<dyn AuthProvider>` — it never knows which implementation is behind the trait.

## Modes at a glance

| | Embedded | Served (SSO) |
|---|---|---|
| Where auth runs | In your process | On a central `surge-server` |
| Where browser login lives | Mounted on your app at your chosen path | On `surge-server`, with redirects to/from your app |
| Where your frontend calls `whoami` | Your own app | Your own app (same-origin, via your mount) or `surge-server` (cross-origin with CORS) |
| Database | Shared | Shared |
| Sessions | Written directly | Written via `surge-server` |
| Best for | Single service, zero extra infrastructure | Multiple services sharing a user base (SSO) |

## How browser login works in each mode

In both modes, you call `provider.browser_router(config)` and get back an `axum::Router`. The provider decides what happens internally:

**Embedded** (`EmbeddedProvider`): handlers run in your process. Users visit `your-app.com/api/surge/v1/login`, complete the flow, and receive a session cookie set on your domain. Everything — credential verification, session minting, `whoami`, logout — runs locally against your database.

**Served** (`RemoteProvider`): the router acts as a reverse proxy, forwarding browser requests to the remote `surge-server` (which already serves all the same endpoints). Cookie domains are rewritten to your local domain. Your app's consumers see identical routes — they never know whether auth is local or proxied.

The proxy is inside `surge-server`'s trust boundary, not an anonymous client of it: it authenticates with your service token (which needs the `browser_proxy` grant) and states the end user's address in `X-Surge-Client-Ip`, so rate limits are keyed on the actual user rather than collapsing your whole user base into your service's one address. `surge-server` rejects that header unless a valid `browser_proxy` token accompanies it. See [Embedding → Remote mode](/integration/embedding#remote-mode-the-browser-perimeter-is-a-proxy).

Your app uses the same `AuthProvider` methods to check sessions and look up identities. The browser routing is mode-agnostic — it's a deployment choice, not a code change.

## Switching between modes

```rust
// Embedded: Surge runs in your process
let provider = Arc::new(
    EmbeddedProvider::new(EmbeddedConfig {
        database_url:  "...",
        pepper:        "...",
        session_ttl:   Duration::from_secs(72 * 3600),
    }).await?
);

// Served: Surge runs on a central server
let provider = Arc::new(
    RemoteProvider::new(RemoteConfig {
        base_url:       "https://auth.example.com".parse()?,
        service_token:  "...",
        cache_ttl:      Duration::from_secs(60),
        cache_max_entries: 10_000,
        timeout:        Duration::from_secs(5),
    })?
);
```

Switching modes is a matter of swapping which `AuthProvider` you construct at startup — the rest of your application code, including how it calls `whoami`, verifies sessions, or looks up identities, is unchanged.

## Mixed mode

One service can embed Surge directly (zero-latency auth for its own routes) while other services connect to the same `surge-server` via `RemoteProvider`. All sessions land in the same database — a session minted by an embedded provider is valid when verified by a remote-connected service.

## Session stability guarantee

Once a session is minted, it is valid until it expires or is explicitly revoked. Surge version upgrades do not invalidate existing sessions. This holds regardless of provider type (embedded or remote), deployed API version, and whether your services are all on the same version or on different ones.

## Security boundaries

- **Passwords**: hashed with Argon2id + a site-wide secret pepper (`SURGE_PEPPER`). The pepper lives in your environment, never in the database.
- **Session tokens**: prefixed (`aeg_s_…`), hashed at rest, shown once on creation.
- **Service tokens**: same pattern (`aeg_svc_…`), with grant-based permissions scoping what each service can do.
- **Login flows**: stateful, per-flow CSRF tokens verified in constant time.
- **Rate limiting**: windowed counters (per-IP, per-username) applied to authentication endpoints, independent of provider mode.

## Data model

All modes share a single Postgres schema (`surge`) with these core tables:

| Table | Purpose |
|---|---|
| `identity` | User accounts (username, display name, avatar, state) |
| `credential_password` | Password hashes (Argon2id, versioned for algorithm upgrades) |
| `session` | Active sessions (hashed token, identity, expiry, metadata) |
| `login_flow` | In-progress login flows (state, CSRF token, attempt tracking) |
| `service` | Service tokens and their grants |
| `audit_log` | Structured security event trail |
| `rate_limit_window` | Windowed rate limit counters |

Migrations run at startup — automatically when using `EmbeddedProvider`, or when `surge-server` starts in served mode. You own the database; Surge manages the schema.
