---
description: What Surge is, what it does for your application, and how to use it.
---

# What is Surge

Surge is an authentication engine you embed into your Rust web application or run as a standalone server. It handles user login flows, session management, password authentication, and service-to-service auth — so you don't have to build it yourself.

## How you use it

There are two ways to integrate Surge into your stack:

**Embedded** — Add Surge as a dependency in your Axum application. Surge runs in the same process, sharing your database, and you mount its routes at a path of your choice. No separate deployment, no network hop for auth.

**Server** — Run `surge-server` as a standalone service. Your applications connect via HTTP using service tokens (Bearer auth). The server manages sessions and identities centrally.

Both modes use the same database and the same session model. You can even mix them — embed Surge in one service while other services talk to the central server.

## What Surge handles

| Capability | Description |
|---|---|
| Login flows | Redirect-based and inline login with CSRF protection |
| Session management | Cookie-based sessions with mint, verify, revoke, expiry, and garbage collection |
| Service auth | Bearer token auth for backend-to-backend calls, with grant-based permissions |
| Password auth | Argon2id hashing with secret pepper, validation rules, timing-safe comparisons |
| Identity management | Create, update profile, enable/disable accounts, search by username |
| Rate limiting | Per-IP and per-username windowed counters (Postgres-backed) |
| Audit logging | Structured event trail for security and compliance |
| Registration modes | Open registration, invite-only, or closed |

## The stability guarantee

Once Surge mints a session or token, that session or token means the same thing for its entire lifetime. Future versions of Surge may change API shapes, paths, or response formats, but they will never break the meaning of an already-minted credential. This guarantee holds regardless of which API version minted it.

## Next steps

- [Quickstart](/guide/quickstart) — get Surge running in five minutes
- [Architecture](/guide/architecture) — how the stability guarantee works
- [Login Flows](/features/login-flows) — how users sign in and register
