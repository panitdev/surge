---
description: Service token grants reference — what each grant allows and which endpoints require it.
---

# Service Grants

Service tokens carry grants that control which API operations the service can perform. This page lists every grant and its scope.

| Grant | Allows |
|---|---|
| `introspect` | Verify and inspect sessions and tokens |
| `identity_read` | Read identity data (lookup by ID, search by username) |
| `identity_write` | Update identities (profile update, enable/disable) |
| `direct_auth` | Authenticate users directly (password verification) |
| `revoke` | Revoke sessions and tokens |
| `browser_proxy` | Front the browser perimeter on behalf of end users |
| `external_auth` | Sign users in through an external provider (email, OAuth), creating the identity on first sight |
| `external_link` | Attach an external provider account to an existing identity, or detach one |

## Grant-to-endpoint mapping

Each grant unlocks a specific set of service API endpoints:

| Grant | Endpoints unlocked |
|---|---|
| `introspect` | `POST /v1/sessions/verify` — verify a session token; inspect session metadata |
| `identity_read` | `GET /v1/identities/{id}` — get identity by UUID; `GET /v1/identities?username=...` — search by username; `GET /v1/identities/{id}/links` — list linked provider accounts |
| `identity_write` | `PATCH /v1/identities/{id}` — update profile fields |
| `direct_auth` | `POST /v1/authenticate/password` — authenticate with username + password; `POST /v1/register` — create an identity directly |
| `revoke` | `POST /v1/sessions/revoke` — revoke a single session; `POST /v1/identities/{id}/revoke-sessions` — revoke all sessions for an identity |
| `browser_proxy` | The browser endpoints (`/v1/login`, `/v1/flows/...`, `/v1/whoami`, ...) — permits stating the end user's address in `X-Surge-Client-Ip` |
| `external_auth` | `POST /v1/authenticate/link` — resolve a `(provider, subject)` pair to a session, creating the identity if the link is new |
| `external_link` | `POST /v1/identities/{id}/links` — attach or confirm a link; `DELETE /v1/identities/{id}/links` — detach one |

A request to an endpoint without the required grant returns `403 Forbidden`:

```json
{
  "error": {
    "type": "forbidden",
    "message": "service token does not have the required grant: identity_write",
    "details": {}
  }
}
```

## Grant design: least privilege

Grants follow the principle of least privilege. A service token should carry only the grants it needs for its specific role. If a service only verifies sessions, give it `introspect` — not `identity_write` or `direct_auth`.

A compromised token with only `introspect` can verify sessions; one with `identity_write` and `revoke` can disable accounts and force-logout every user. Grant scope accordingly.

### The `browser_proxy` grant

`browser_proxy` is what `RemoteProvider::browser_router()` uses. It does not unlock any privileged operation directly — the browser endpoints are public. What it authorizes is the *statement* a proxy makes about who its request is for: with it, `X-Surge-Client-Ip` becomes the key rate limiting is applied under.

A compromised `browser_proxy` token can therefore pick which bucket its requests count against, evading per-IP rate limits on login. Give it only to services that actually mount a remote-mode browser router.

### The external grants assert proof of control

Surge stores links — `("email", "alice@example.com")`, `("google", "117...")` — but it never talks to a provider itself. It sends no mail and performs no OAuth code exchange, so it cannot check that the person in front of your service actually controls the subject being claimed. The `external_auth` grant *is* that assertion: holding it means the service has already completed the handshake before calling.

`POST /v1/authenticate/link` therefore mints a session from a `(provider, subject)` pair with no secret in the request — for the email provider, the subject is the user's public address. A compromised `external_auth` token can sign in as any identity with a verified link, so it belongs only on the service that terminates the provider handshake, and nowhere else.

`external_link` is separate because attaching a subject to an *existing* identity is account-binding: a service able to link `google:attacker@example.com` to someone else's identity could then sign in as them. Signing users in through a provider does not require binding new providers to established accounts, so the two capabilities stay apart.

`direct_auth` remains scoped to password authentication and unlocks neither.

### Verified and unverified links

A link carries a `verified_at` timestamp, and **only a verified link can authenticate**. An unverified link is a pending claim — an address someone typed into account settings that nobody has proven control of — and `POST /v1/authenticate/link` will not resolve it.

That distinction is what makes the two-step email flow safe to build:

```bash
# 1. User adds an address in settings. Nothing is proven yet, so verified=false.
curl -X POST http://localhost:3000/v1/identities/$ID/links \
  -H "Authorization: Bearer aeg_svc_..." \
  -d '{"provider": "email", "subject": "alice@example.com", "verified": false}'

# 2. Your service mails a token. When it comes back, re-post the same link
#    with verified=true — the call is idempotent and only refreshes the flag.
curl -X POST http://localhost:3000/v1/identities/$ID/links \
  -H "Authorization: Bearer aeg_svc_..." \
  -d '{"provider": "email", "subject": "alice@example.com", "verified": true}'
```

Between those two calls the address is inert: it cannot sign anyone in, and it cannot be used to recover the account. Re-posting a subject that is already linked to a *different* identity fails rather than moving it.

### The `revoke` grant is the most sensitive

The `revoke` grant allows a service to revoke any session and all sessions for any identity. A compromised token with `revoke` can force-logout every user. Treat this grant as high-privilege and apply it sparingly.

## Assigning grants

Grants are assigned at token creation time via the CLI and cannot be changed after creation:

```bash
# Create a token with specific grants
surge-server svc create --name "my-gateway" --grant introspect --grant identity_read
```

If a service's role changes and it needs different grants, create a new token with the updated grant set and revoke the old one:

```bash
# Old gateway needs identity_write now
surge-server svc create --name "my-gateway-v2" --grant introspect --grant identity_read --grant identity_write
surge-server svc revoke my-gateway
```

Grants are not mutable because changing them would change the semantics of an already-deployed token — safer to rotate.

## Combining grants for specific service roles

Common service roles and their grant sets:

| Role | Grants needed | Why |
|---|---|---|
| **API gateway (verify-only)** | `introspect` | Verify session tokens from incoming requests, nothing more |
| **API gateway (with identity)** | `introspect`, `identity_read` | Verify sessions and enrich requests with user profile data |
| **User management service** | `identity_read`, `identity_write` | Look up, create, update, and disable identities |
| **Admin panel** | `identity_read`, `identity_write`, `revoke` | Full identity management plus session revocation |
| **Auth proxy** | `direct_auth` | Accept username/password and return session tokens |
| **Remote-mode web app** | `introspect`, `browser_proxy` | Verify sessions, and reverse-proxy the browser perimeter for its own users |
| **OAuth / email sign-in service** | `external_auth` | Terminates the provider handshake, then resolves the resulting `(provider, subject)` to a session |
| **Account settings service** | `identity_read`, `external_link` | Lets a signed-in user list, attach, and disconnect provider accounts |
| **Full-access system service** | All of them | Internal service that needs everything — use with extreme caution |

### Example: API gateway with session verification and user enrichment

```bash
surge-server svc create --name "api-gateway" --grant introspect --grant identity_read
```

This service can:
1. Call `POST /v1/sessions/verify` to validate incoming session tokens
2. Call `GET /v1/identities/{id}` to get the user's display name and avatar

It cannot create, disable, or revoke anything.

### Example: Internal admin service

```bash
surge-server svc create --name "admin-cli" --grant identity_read --grant identity_write --grant revoke
```

This service can:
1. Look up identities
2. Disable and enable user accounts
3. Revoke sessions

It cannot authenticate users (`direct_auth`) or verify sessions (`introspect`) — those aren't part of its responsibility.

## Audit trail

Every action performed with a service token is recorded in the audit log with the service's name and ID. This creates an accountability trail:

```json
{
  "action": "identity_disable",
  "service_name": "admin-cli",
  "service_id": "018f9a1b-...",
  "target_identity": "018f9a1b-...",
  "timestamp": "2026-07-08T12:00:00Z"
}
```

**Related:** [Service Authentication](/features/service-authentication), [CLI](/reference/cli)
