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

## Grant-to-endpoint mapping

Each grant unlocks a specific set of service API endpoints:

| Grant | Endpoints unlocked |
|---|---|
| `introspect` | `POST /v1/sessions/verify` — verify a session token; inspect session metadata |
| `identity_read` | `GET /v1/identities/{id}` — get identity by UUID; `GET /v1/identities?username=...` — search by username |
| `identity_write` | `PATCH /v1/identities/{id}` — update profile fields |
| `direct_auth` | `POST /v1/authenticate/password` — authenticate with username + password; `POST /v1/register` — create an identity directly |
| `revoke` | `POST /v1/sessions/revoke` — revoke a single session; `POST /v1/identities/{id}/revoke-sessions` — revoke all sessions for an identity |

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
| **Full-access system service** | All five | Internal service that needs everything — use with extreme caution |

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
