---
description: Configuring CORS policies for browser-facing endpoints in Surge.
---

# CORS

Surge applies two distinct CORS zones for browser-facing endpoints: one for credential-entry endpoints (login, register) and one for session-management endpoints (whoami, logout).

## Two-zone CORS model

Surge serves browser-facing endpoints (login, register, whoami, logout) under its mount path. Since these endpoints have different security profiles, Surge applies **two distinct CORS zones**:

| Zone | Endpoints | Policy | Purpose |
|---|---|---|---|
| **Credential-entry** | `/login`, `/register`, flow endpoints | Narrow — single origin | Restrict where credentials can be submitted |
| **Session-management** | `/whoami`, `/logout`, profile endpoints | Union of origins or same-origin | Allow session management from multiple frontends |

### Why two zones?

Credential-entry endpoints (where users submit passwords or create accounts) are the highest-value targets for CSRF and phishing attacks. Restricting these to a single origin narrows the attack surface significantly.

Session-management endpoints need to be accessible from any frontend that holds the session cookie — which in an SSO setup may be multiple applications. The union-of-origins policy enables this without weakening credential-entry security.

## Configuration

CORS origins are configured via the `SURGE_SESSION_CORS_ORIGINS` environment variable:

```bash
# Single origin
export SURGE_SESSION_CORS_ORIGINS="https://app.example.com"

# Multiple origins (comma-separated)
export SURGE_SESSION_CORS_ORIGINS="https://app.example.com,https://admin.example.com"
```

### Same-origin fallback

When `SURGE_SESSION_CORS_ORIGINS` is empty (or unset), all browser endpoints default to **same-origin only**:

```bash
# No cross-origin access — most embeddings use this
export SURGE_SESSION_CORS_ORIGINS=""
```

This is the most common configuration for embedded deployments. If your application and Surge share the same origin (e.g., both served from `https://app.example.com`), you don't need to configure CORS at all.

## Credentialed requests

All Surge browser endpoints send `Access-Control-Allow-Credentials: true`. This tells the browser to include cookies and the `Authorization` header in cross-origin requests.

Because credentials are allowed, **wildcard origins are explicitly disallowed**:

```
Access-Control-Allow-Origin: *       ← NEVER sent by Surge
Access-Control-Allow-Origin: https://app.example.com  ← Always specific
```

This is a browser-enforced constraint: the `credentials: true` flag and wildcard origins are mutually exclusive per the Fetch standard. Surge enforces this at the configuration level by rejecting patterns like `*` in `SURGE_SESSION_CORS_ORIGINS`.

## Deployment patterns

### Same-origin (most common)

If Surge is embedded in your application or deployed behind the same domain, CORS is a non-issue. The browser sends requests to the same origin that served the page, and no preflight checks are triggered.

```
User → https://app.example.com (your app + Surge mount)
      Same origin for everything — no CORS config needed
```

### Cross-origin (standalone Surge)

If Surge runs as a standalone server on a different domain, configure the frontend origins:

```bash
# Frontend on app.example.com, Surge on auth.example.com
export SURGE_SESSION_CORS_ORIGINS="https://app.example.com"
```

The browser will send a preflight `OPTIONS` request before each credentialed POST. Surge handles these preflight checks automatically for allowed origins.

### Multi-frontend SSO

When multiple applications share the same Surge server:

```bash
export SURGE_SESSION_CORS_ORIGINS="https://app.example.com,https://dashboard.example.com"
```

All listed origins can manage sessions. Credential-entry endpoints remain restricted to the first origin for security.

## When you need CORS

| Setup | Config needed? |
|---|---|
| Embedded, same origin | No — same-origin by default |
| Embedded, different subdomain (cookie shared) | Yes — list the subdomain origin |
| Standalone Surge, single frontend | Yes — list the frontend origin |
| Standalone Surge, multiple frontends | Yes — list all frontend origins |
| API-only (no browser endpoints) | No — CORS only applies to browser endpoints |

**Related:** [Integration: Running as a Server](/integration/running-as-server), [Login Flows](/features/login-flows)
