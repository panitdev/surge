---
description: Version history, per-release changes, and migration notes.
---

# Changelog

## Unreleased

### OAuth 2.1 / OIDC authorization server

Surge can now issue audience-scoped OAuth tokens itself, rather than delegating to Ory Hydra. Opt-in via `SURGE_OAUTH_ISSUER`; unset, nothing changes. See [OAuth Authorization Server](/features/oauth-authorization-server).

- **Authorization code flow with mandatory PKCE `S256`** at `/oauth2/authorize` and `/oauth2/token`, plus JWKS, RFC 8414 discovery, RFC 7662 introspection, RFC 7009 revocation, OIDC ID tokens and `userinfo`. No implicit, client-credentials or password grant.
- **Audience-restricted tokens** (RFC 8707). A `resource` parameter is valid only if it resolves to a registered audience owned by a registered service, and a token minted for one resource does not validate at another.
- **A real consent screen for third-party clients**, with `/v1/oauth/consent/{flow_id}` for the auth UI and `/v1/account/connections` for "show me every app connected to my account" — including disconnect, which revokes the consent and its refresh tokens together.
- **Dynamic client registration** (RFC 7591) at `/oauth2/register`, off by default, rate-limited, scope-capped, and unable to produce anything but an untrusted third-party client.
- **Refresh-token rotation with reuse detection**: replaying a consumed token revokes its whole family.
- **ES256 signing keys encrypted under the pepper**, rotated by the background sweep, with retired keys published until the tokens they signed expire.
- **`surge::resource`** (feature `resource-server`) ships the resource-server half: RFC 9728 metadata, the `WWW-Authenticate` challenge MCP clients discover the AS through, and an offline bearer-token guard.
- **New grant `oauth_admin`** and new CLI group `surge-server oauth {client,resource,key}`.
- **New token prefixes** `aeg_cid_`, `aeg_cs_`, `aeg_ac_`, `aeg_rt_`.

Behaviour change worth noting: `revoke_all_sessions` now also revokes that identity's OAuth refresh tokens. "Log this person out everywhere" would otherwise leave their connected apps refreshing.

The Hydra bridge still works and both can run at once during a cutover — `sub` is the identity UUID in both. See the [migration steps](/integration/hydra-oauth-bridge).

## 0.1.0

Initial release of Surge — a standalone authentication server with browser-facing and service-facing APIs.

### New features

- **Password authentication** with Argon2id + secret pepper. Passwords are never stored in plaintext or as reversible hashes. A deployment-wide pepper is applied before the Argon2id hash, providing an additional layer of protection against database-only leaks.
- **Session management** — mint, verify, revoke, and garbage-collect sessions. Sessions have a configurable TTL (default 72 hours). Revoked and expired sessions are cleaned up by a background garbage collector.
- **Login flows** with CSRF protection — supports redirect mode (browser navigation via 302 to auth UI) and inline mode (JSON responses for SPAs). Flows carry a per-flow CSRF token which must be submitted on all mutating requests.
- **Service-to-service auth** with Bearer tokens and grant-based permissions. Five grants (`introspect`, `identity_read`, `identity_write`, `direct_auth`, `revoke`) follow least-privilege design. Service tokens are created via CLI and shown only once.
- **Identity management** — CRUD operations, enable/disable, username search. Supports display names and avatar URLs. Disabled identities are immediately locked out of sessions and authentication.
- **Rate limiting** — per-IP and per-username, with windowed counters. Applied to login flows, registration, and password authentication to prevent brute-force and enumeration attacks.
- **Audit logging** — structured event trail for all state-changing operations. Each event includes timestamp, actor (user or service), action type, and target resource.
- **Registration modes** — `open` (anyone can register) and `closed` (no self-service registration) are implemented; `invite` is reserved via `SURGE_REGISTRATION` but not yet functional.
- **Two-zone CORS model** — credential-entry endpoints (login, register) get a narrow origin policy; session-management endpoints (whoami, logout) accept a configurable set of origins.
- **Embedding in Axum** — Surge can be mounted as an Axum router inside an existing application, or run as a standalone server.
- **Docker support** — multi-stage Docker build, published to `ghcr.io`.
- **Health checks** and startup coherence validation — a liveness endpoint plus configuration-consistency checks that run before the server starts accepting traffic.
- **CLI tooling** — `surge-server serve` for the server, `surge-server identity` for user management, `surge-server svc` for service token management.
