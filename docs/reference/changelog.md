---
description: Version history, per-release changes, and migration notes.
---

# Changelog

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
