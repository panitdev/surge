---
description: Get Surge running and protect your first route in under five minutes.
---

# Quickstart

This guide walks you through running Surge, configuring it, and using it to authenticate a request — all from scratch.

## 1. Start the server

```bash
# Clone and build (first build compiles all crates)
git clone https://github.com/panitdev/surge
cd surge
cargo build -p surge-server
```

Set required environment variables and start:

```bash
# Point to a Postgres database Surge should manage
export DATABASE_URL=postgres://localhost/surge
# A secret pepper for password hashing (change in production!)
export SURGE_PEPPER=dev-pepper-change-me

cargo run -p surge-server -- serve
```

On first run, Surge automatically runs its schema migrations. You'll see:

```
2026-07-08T12:00:00.123456Z  INFO surge_server::cli::serve_cmd: surge-server listening addr=0.0.0.0:3000
```

## 2. Create a service token

Service tokens let backend services call Surge's API. Create one:

```bash
cargo run -p surge-server -- svc create my-service
```

Output:

```
Service token: aeg_svc_1a2b3c4d5e6f7g8h9i0j
```

Save this — it's shown only once. The service will send it as a `Bearer` token.

## 3. Register a user

```bash
curl -X POST http://localhost:3000/v1/register \
  -H "Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "correct-horse-battery-staple", "display_name": "Alice"}'
```

Response:

```json
{
  "id": "018f9a1b-...",
  "username": "alice",
  "display_name": "Alice",
  "avatar_url": null,
  "state": "active"
}
```

## 4. Authenticate and get a session

```bash
curl -X POST http://localhost:3000/v1/authenticate/password \
  -H "Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "correct-horse-battery-staple"}'
```

Response:

```json
{
  "session": { "id": "...", "issued_at": "...", "expires_at": "..." },
  "token": "aeg_s_..."
}
```

## 5. Verify the session

```bash
curl -X POST http://localhost:3000/v1/sessions/verify \
  -H "Authorization: Bearer aeg_svc_1a2b3c4d5e6f7g8h9i0j" \
  -H "Content-Type: application/json" \
  -d '{"token": "aeg_s_..."}'
```

A successful verify returns the identity and session metadata. An expired or revoked token returns an error.

## What's next?

- **Browser login flows** → See [Login Flows](/features/login-flows) for redirect-based and inline login
- **Embedding in your app** → See [Embedding in Axum](/integration/embedding)
- **Full configuration reference** → See [Configuration](/integration/configuration)
