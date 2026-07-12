---
description: Complete reference of Surge environment variables, their defaults, and purposes.
---

# Configuration

Surge is configured through environment variables. This page lists every variable, its default, and what it controls.

## How configuration is loaded

Surge reads every setting from environment variables via `ServerConfig::from_env()`. There are no config files — everything is an env var with a sensible default.

Here is the complete reference:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgres://localhost/surge` | Postgres connection string |
| `SURGE_PEPPER` | `dev-pepper-change-me` | Secret pepper for Argon2id |
| `SURGE_BIND` | `0.0.0.0:3000` | Listen address and port |
| `SURGE_COOKIE_DOMAIN` | `.panit.dev` | Domain for session cookies |
| `SURGE_AUTH_UI_ORIGIN` | `https://auth.panit.dev` | Origin for the auth UI redirect |
| `SURGE_SESSION_TTL_HOURS` | `72` | Session time-to-live in hours |
| `SURGE_REGISTRATION` | `open` | Registration mode (`open`, `invite`, `closed`) |
| `SURGE_SESSION_CORS_ORIGINS` | empty | Comma-separated origins for credentialed CORS |
| `SURGE_ALLOW_SERVED_INLINE` | `false` | Allow inline flow-init on served deployments |
| `SURGE_HYDRA_ADMIN_URL` | (unset) | Ory Hydra admin API base URL; setting this enables the Hydra login/consent bridge |
| `SURGE_HYDRA_BRIDGE_ORIGIN` | (required if `SURGE_HYDRA_ADMIN_URL` is set) | This server's own public origin for the bridge's `return_to` callback |
| `SURGE_HYDRA_ADMIN_TIMEOUT_SECS` | `10` | Timeout in seconds for Hydra admin API requests |

## Database connection

`DATABASE_URL` is a standard Postgres connection string. Surge uses it for Diesel migrations (run automatically at startup) and all runtime queries.

```bash
# Local development
export DATABASE_URL="postgres://localhost/surge"

# Production with credentials
export DATABASE_URL="postgres://user:$password@prod-db.internal:5432/surge"
```

The value is wrapped in `SecretString` internally — it never appears in logs or debug output.

## Pepper (`SURGE_PEPPER`)

The pepper is a secret applied before Argon2id hashing for every password credential. It lives in your environment, never in the database. If an attacker dumps your database but doesn't have the pepper, password hashes are not crackable.

```bash
# Generate a strong pepper (do this once per environment)
export SURGE_PEPPER="$(openssl rand -base64 48)"

# WARNING: the dev default must never be used in production
export SURGE_PEPPER="dev-pepper-change-me"  # ← development only
```

**Changing the pepper invalidates all existing password credentials.** Rotate it only in coordination with a forced password reset on all identities.

## Bind address (`SURGE_BIND`)

Controls the address and port `surge-server` listens on. In the standalone server, this can be overridden directly on the CLI:

```bash
# Via env
export SURGE_BIND="0.0.0.0:3000"

# Via CLI (takes precedence over env)
surge-server serve --bind 127.0.0.1:8080
```

In embedded mode, this setting is irrelevant — your Axum application manages its own listener.

## Cookie domain (`SURGE_COOKIE_DOMAIN`)

Sets the `Domain` attribute on Surge session cookies. The leading dot (`.panit.dev`) scopes the cookie to the domain and all subdomains:

| Value | Cookies valid for |
|---|---|
| `.panit.dev` | `panit.dev`, `app.panit.dev`, `*.panit.dev` |
| `auth.panit.dev` | `auth.panit.dev` only |

Use the subdomain-scoped form when you have a single-domain app. Use the leading-dot form when you share sessions across subdomains (e.g. `app.panit.dev` and `api.panit.dev`).

## Auth UI origin (`SURGE_AUTH_UI_ORIGIN`)

The origin where your login UI is served. In served (SSO) mode, `GET /v1/login` redirects unauthenticated users here with the flow ID appended. This must be a full origin — scheme, host, and port if non-standard:

```bash
export SURGE_AUTH_UI_ORIGIN="https://auth.example.com"
```

This origin is also the default allowed origin for the session-management CORS zone when `SURGE_SESSION_CORS_ORIGINS` is empty. At startup, Surge checks that if `SURGE_SESSION_CORS_ORIGINS` is set, it includes `SURGE_AUTH_UI_ORIGIN` — otherwise the auth UI would be locked out of its own session endpoints.

## Session TTL (`SURGE_SESSION_TTL_HOURS`)

Session lifetime in hours. The default is 72 hours (3 days). Internally, this is converted to a `Duration`:

```rust
pub fn session_ttl(&self) -> Duration {
    Duration::from_secs(self.session_ttl_hours * 3600)
}
```

Tune this based on your security posture:

```bash
# Short-lived sessions for sensitive environments
export SURGE_SESSION_TTL_HOURS=8

# Long-lived sessions for consumer apps
export SURGE_SESSION_TTL_HOURS=168  # 7 days
```

Expired sessions are removed by the background garbage collector, which runs every 15 minutes.

## Registration mode (`SURGE_REGISTRATION`)

Controls how new identities are created. Parsing is case-sensitive and follows a default-to-Open pattern:

```rust
match value.as_str() {
    "invite" => RegistrationMode::Invite,
    "closed" => RegistrationMode::Closed,
    _        => RegistrationMode::Open,  // default for anything else
}
```

```bash
# Open registration (default)
export SURGE_REGISTRATION=open

# Invite-only
export SURGE_REGISTRATION=invite

# No self-service registration
export SURGE_REGISTRATION=closed
```

See [Registration Modes](/integration/registration-modes) for how each mode affects the login flow and API behavior.

## Session CORS origins (`SURGE_SESSION_CORS_ORIGINS`)

A comma-separated list of origins allowed to make credentialed cross-origin requests to session-management endpoints (`/v1/whoami`, `/v1/logout`). When empty (the default), only same-origin requests are allowed.

```bash
# Allow the auth UI and two applications to call /me and /logout
export SURGE_SESSION_CORS_ORIGINS="https://auth.example.com,https://app.example.com,https://admin.example.com"
```

This is the opt-in browser-to-Surge CORS zone. Leave it empty if your frontends call session endpoints through a proxy (same-origin), or if you're in embedded mode where everything is same-origin anyway.

## Served inline flow-init (`SURGE_ALLOW_SERVED_INLINE`)

Controls whether `GET /v1/login` supports content-negotiated inline flow initiation (via `Accept: application/json`) in served mode. **Boolean parsing uses `== "1"`, not `== "true"`:**

```rust
let allow_served_inline = std::env::var("SURGE_ALLOW_SERVED_INLINE")
    .map(|v| v == "1")
    .unwrap_or(false);
```

```bash
# Enable inline flow-init on a served deployment
export SURGE_ALLOW_SERVED_INLINE=1

# Disable (default)
export SURGE_ALLOW_SERVED_INLINE=0
# or simply don't set the variable
```

When enabled on a served deployment, credential entry is proxied through the consuming service's origin — Surge sees that service's IP, not the browser's. This coarsens per-IP rate limiting. Embedded consumers can enable this unconditionally (there is no such tradeoff when Surge runs in-process).

## Hydra OAuth bridge (`SURGE_HYDRA_ADMIN_URL`, `SURGE_HYDRA_BRIDGE_ORIGIN`, `SURGE_HYDRA_ADMIN_TIMEOUT_SECS`)

The Hydra login/consent bridge connects Surge to Ory Hydra as an OAuth 2.1 authorization server. It is opt-in — setting `SURGE_HYDRA_ADMIN_URL` is the on-switch; when unset, no bridge routes are mounted and Hydra is never contacted.

```bash
# Enable the bridge (all three are needed together)
export SURGE_HYDRA_ADMIN_URL="http://hydra:4434"
export SURGE_HYDRA_BRIDGE_ORIGIN="https://auth.example.com"
export SURGE_HYDRA_ADMIN_TIMEOUT_SECS=10
```

`SURGE_HYDRA_ADMIN_URL` must point at Hydra's admin API (typically port `4434`, not the public port `4433`). `SURGE_HYDRA_BRIDGE_ORIGIN` is this server's own public origin — it must match a registered return origin or startup coherence will reject it with a hard error. `SURGE_HYDRA_ADMIN_TIMEOUT_SECS` controls the timeout for outbound requests to Hydra (default 10 seconds).

The bridge mounts two routes:
- `GET /v1/oauth/login` — handles Hydra login challenges
- `GET /v1/oauth/consent` — handles Hydra consent challenges (auto-accepted for first-party clients)

## Embedded config conversion

`ServerConfig` provides an `embedded_config()` method that extracts the subset of settings relevant to an embedded provider:

```rust
pub fn embedded_config(&self) -> EmbeddedConfig {
    EmbeddedConfig {
        database_url: self.database_url.clone(),
        pepper: self.pepper.clone(),
        session_ttl: self.session_ttl(),
    }
}
```

This lets you load configuration once via `ServerConfig::from_env()` and construct both embedded and served providers from the same configuration source.

## Full example: production `.env`

```bash
DATABASE_URL="postgres://surge:${DB_PASSWORD}@db.internal:5432/surge"
SURGE_PEPPER="${SURGE_PEPPER}"           # from secrets manager
SURGE_BIND="0.0.0.0:3000"
SURGE_COOKIE_DOMAIN=".example.com"
SURGE_AUTH_UI_ORIGIN="https://auth.example.com"
SURGE_SESSION_TTL_HOURS=72
SURGE_REGISTRATION=open
SURGE_SESSION_CORS_ORIGINS="https://auth.example.com,https://app.example.com"
SURGE_ALLOW_SERVED_INLINE=0
SURGE_HYDRA_ADMIN_URL="http://hydra:4434"
SURGE_HYDRA_BRIDGE_ORIGIN="https://auth.example.com"
SURGE_HYDRA_ADMIN_TIMEOUT_SECS=10
```

**Related:** [Deployment: Docker](/deployment/docker), [Registration Modes](/integration/registration-modes), [Health Checks](/deployment/health-checks)
