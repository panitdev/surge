---
description: Per-environment configuration templates for development, staging, and production deployments.
---

# Environment Templates

Recommended configuration sets for different deployment environments.

## Development

A development environment runs on your local machine with permissive settings for fast iteration. Use the default Postgres connection and dev pepper — these are fine for local work but must never reach production.

### `.env` for development

```bash
# Database — local Postgres with default database name
DATABASE_URL="postgres://localhost/surge"

# Pepper — the dev default is fine for local work
SURGE_PEPPER="dev-pepper-change-me"

# Listen on all interfaces, standard port
SURGE_BIND="0.0.0.0:3000"

# Cookie domain — localhost doesn't need subdomain scope
SURGE_COOKIE_DOMAIN="localhost"

# Auth UI — serve from localhost during development
SURGE_AUTH_UI_ORIGIN="http://localhost:3000"

# Sessions — shorter TTL in dev makes it easier to test expiry behavior
SURGE_SESSION_TTL_HOURS=24

# Registration — permissive for testing
SURGE_REGISTRATION=open

# CORS — leave empty for same-origin development
SURGE_SESSION_CORS_ORIGINS=""

# Inline flow-init — safe to enable for local dev
SURGE_ALLOW_SERVED_INLINE=1

# Hydra OAuth bridge — unset for local dev unless you run Hydra locally
# SURGE_HYDRA_ADMIN_URL="http://localhost:4434"
# SURGE_HYDRA_BRIDGE_ORIGIN="http://localhost:3000"
# SURGE_HYDRA_ADMIN_TIMEOUT_SECS=10
```

### Development workflow

```bash
# Start Postgres (Docker)
docker run --name surge-pg -e POSTGRES_DB=surge -p 5432:5432 -d postgres:16

# Start Surge
cargo run -p surge-server -- serve

# Or with explicit env
source .env
cargo run -p surge-server -- serve
```

In development, inline flow-init is safe to enable (`SURGE_ALLOW_SERVED_INLINE=1`) because there's no proxy layer between the browser and Surge. The rate limiter sees real client IPs.

## Staging

Staging mirrors production infrastructure but against a separate database. Use staging to test upgrades, configuration changes, and integration behavior before deploying to production.

### `.env` for staging

```bash
# Database — separate staging instance
DATABASE_URL="postgres://surge:${STAGING_DB_PASSWORD}@staging-db.internal:5432/surge"

# Pepper — unique to staging, stored in vault
SURGE_PEPPER="${STAGING_PEPPER}"

SURGE_BIND="0.0.0.0:3000"
SURGE_COOKIE_DOMAIN=".staging.example.com"
SURGE_AUTH_UI_ORIGIN="https://auth.staging.example.com"
SURGE_SESSION_TTL_HOURS=72
SURGE_REGISTRATION=open

# CORS — staging apps
SURGE_SESSION_CORS_ORIGINS="https://auth.staging.example.com,https://app.staging.example.com"

# Inline flow-init — test with same settings as production
SURGE_ALLOW_SERVED_INLINE=0

# Hydra OAuth bridge — enable on staging to test the login/consent round-trip
SURGE_HYDRA_ADMIN_URL="http://hydra:4434"
SURGE_HYDRA_BRIDGE_ORIGIN="https://auth.staging.example.com"
SURGE_HYDRA_ADMIN_TIMEOUT_SECS=10
```

### Staging checklist

Before pushing to production, verify on staging:

- [ ] Startup coherence checks pass (no warnings, no errors)
- [ ] `GET /health` returns 204
- [ ] Browser login flow works end-to-end (redirect and inline)
- [ ] Service-to-service auth works with staging tokens
- [ ] Session cookies are set on the correct domain
- [ ] CORS headers allow staging app origins
- [ ] Audit log captures all operations
- [ ] Cross-version canary test passes

## Production

Production configuration locks down every security-relevant setting. The pepper and database password come from a secrets manager — never from a `.env` file committed to the repository.

### `.env` for production

```bash
# Database — credentials from vault
DATABASE_URL="postgres://surge:${DB_PASSWORD}@prod-db.internal:5432/surge"

# Pepper — unique, strong, from vault
SURGE_PEPPER="${SURGE_PEPPER}"

SURGE_BIND="0.0.0.0:3000"

# Cookie domain — scoped to your root domain with subdomain support
SURGE_COOKIE_DOMAIN=".example.com"

# Auth UI — served at a dedicated subdomain
SURGE_AUTH_UI_ORIGIN="https://auth.example.com"

# Session TTL — tune based on security requirements
SURGE_SESSION_TTL_HOURS=72

# Registration — match your policy
SURGE_REGISTRATION=open

# CORS — explicitly list every origin that calls /me or /logout
SURGE_SESSION_CORS_ORIGINS="https://auth.example.com,https://app.example.com,https://admin.example.com"

# Inline flow-init — disabled on served deployments
SURGE_ALLOW_SERVED_INLINE=0

# Hydra OAuth bridge — admin URL from vault, bridge origin matches auth UI
SURGE_HYDRA_ADMIN_URL="http://hydra:4434"
SURGE_HYDRA_BRIDGE_ORIGIN="https://auth.example.com"
SURGE_HYDRA_ADMIN_TIMEOUT_SECS=10
```

### Production hardening

| Concern | Setting | Rationale |
|---|---|---|
| Pepper strength | 48+ bytes, base64-encoded | Makes brute-force infeasible after a DB dump |
| Cookie domain | Leading dot for subdomains | Share sessions across `*.example.com` |
| Session TTL | 72 hours default; lower for sensitive apps | Balance UX against session hijack window |
| CORS origins | Explicit whitelist | Never use wildcards on credentialed endpoints |
| Served inline | `false` | Keep credential entry on Surge's origin, not the app's |
| Bind address | `0.0.0.0:3000` behind a reverse proxy | Reverse proxy handles TLS termination |
| Hydra bridge origin | Registered as a `return_origin` | Startup coherence check rejects requests if `SURGE_HYDRA_BRIDGE_ORIGIN` isn't in the allowlist |
| Hydra admin timeout | 10 seconds | Tune for your network; timeout prevents hung login challenges |

Never run production with `SURGE_PEPPER="dev-pepper-change-me"` — it is a public, well-known value, and Surge does not detect or warn about it at startup, so this is on you to enforce in your deployment pipeline.

## Factor policy

`SURGE_FACTOR_POLICY` sets the server-wide expectation for second-factor enrollment. It is a **soft recommendation** — it never blocks login or registration. Surge surfaces it in the `policy` block of login/register/`whoami` responses so the frontend can prompt the user to enroll.

| Value | Meaning |
|---|---|
| `none` (default) | Password only; no factor is expected. |
| `totp` | Users should enroll a TOTP authenticator. |
| `passphrase` | Users should set a recovery passphrase. |
| `both` | Users should enroll TOTP **and** a passphrase. Login still needs only one factor beyond the password. |

Independently of this policy, **a user who has a confirmed TOTP must present it at login** (after the password), and the **passphrase can log in on its own**, bypassing password and TOTP. TOTP secrets are encrypted at rest with a key derived from `SURGE_PEPPER` — no additional secret is required.

## Secret management

### Database URL

`DATABASE_URL` contains credentials. Never log it, commit it, or expose it in error messages.

In Kubernetes, store it as a Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: surge-db
type: Opaque
stringData:
  url: "postgres://surge:password@postgres:5432/surge"
---
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: surge-db
        key: url
```

### Pepper

The pepper must be the same across all Surge instances sharing a database. Generate it once per environment and distribute it through your secrets infrastructure:

```bash
# Generate once
openssl rand -base64 48

# Store in your vault / secrets manager
# HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, etc.
```

In Docker Compose, use an environment file excluded from version control:

```bash
# .env.secrets (in .gitignore)
SURGE_PEPPER="aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldA=="
```

```yaml
# docker-compose.yml
services:
  surge:
    env_file:
      - .env.secrets
```

### Service tokens

Service tokens are created via CLI and displayed exactly once — they're not stored in plaintext by Surge. After creation, only the SHA-256 hash is retained. Treat the plaintext token as a secret:

```bash
# Create and immediately store in vault
SURGE_SVC_TOKEN=$(surge-server svc create --name my-app --grant introspect | grep Token | cut -d: -f2)
vault kv put secret/surge/my-app token="$SURGE_SVC_TOKEN"
```

## Config validation at startup

Surge validates configuration before accepting traffic. These checks run on every boot:

```rust
// check_startup_coherence() verifies:
// 1. return_origins covers all configured consumer origins
// 2. CORS allowlist includes the auth UI origin (if CORS is enabled)
// 3. Registration mode is parseable
// 4. Pepper is not the dev default in production (warn)
// 5. Served inline is acknowledged by the operator (warn)
// 6. Hydra bridge origin (if set) is among registered return_origins (error)
```

Failing checks either abort startup (hard errors) or log warnings (soft issues). Hard errors prevent Surge from starting — fix them before the server can accept traffic. Warnings are informational but should be addressed before production deployment.

Example startup output with warnings:

```
INFO  surge_server > surge-server listening on 0.0.0.0:3000
WARN  surge_server::api > no redirect-mode consumer return_origins are registered; \
       every GET /login redirect will fail return_to validation until one is
```

If you see warnings at startup, create services with `--origin` flags and restart:

```bash
surge-server svc create --name my-app --grant introspect --origin https://app.example.com
```
