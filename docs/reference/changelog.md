---
description: Version history, per-release changes, and migration notes.
---

# Changelog

## Unreleased

### OAuth 2.1 / OIDC authorization server

Surge can now issue audience-scoped OAuth tokens. Enable the authorization server by setting `SURGE_OAUTH_ISSUER`. See [OAuth Authorization Server](/features/oauth-authorization-server).

- **Authorization code flow with mandatory PKCE `S256`** at `/oauth2/authorize` and `/oauth2/token`, plus JWKS, RFC 8414 discovery, RFC 7662 introspection, RFC 7009 revocation, OIDC ID tokens and `userinfo`. No implicit, client-credentials or password grant.
- **Audience-restricted tokens** (RFC 8707). A `resource` parameter is valid only if it resolves to a registered audience owned by a registered service, and a token minted for one resource does not validate at another.
- **A real consent screen for third-party clients**, with `/v1/oauth/consent/{flow_id}` for the auth UI and `/v1/account/connections` for "show me every app connected to my account" — including disconnect, which revokes the consent and its refresh tokens together.
- **Dynamic client registration** (RFC 7591) at `/oauth2/register`, off by default, rate-limited, scope-capped, and unable to produce anything but an untrusted third-party client.
- **Refresh-token rotation with reuse detection**: replaying a consumed token revokes its whole family.
- **ES256 signing keys encrypted under the pepper**, rotated by the background sweep, with retired keys published until the tokens they signed expire.
- **`surge::resource`** (feature `resource-server`) ships the resource-server half: RFC 9728 metadata, the `WWW-Authenticate` challenge MCP clients discover the AS through, and an offline bearer-token guard.
- **Per-resource DCR opt-in and scope ceilings.** Anonymous registration defaults and caps use only service scopes and those of DCR-opted-in delegated resources, so delegated scope names are not leaked. `oauth_client.scope_ceiling_explicit` (migration 17; existing rows are backfilled `true`) records whether registration asked for scopes: explicit ceilings are intersected with the resource's current scopes at authorize, consent, code and refresh, while omitted-scope dynamic clients follow the target. `SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION` is now a kill switch: with it off, existing dynamic clients are refused everywhere and their grants end at next use.
- **One audience eligibility rule** applied at authorize, consent completion, code redemption and refresh. Explicit client audience lists restrict every resource, an empty list grants nothing, and delegated resources require a binding, an allowed CIMD client ID or a DCR opt-in. Ineligible targets return `invalid_target`. Issuer discovery lists only scopes defined by service resources. See [Audience and scope policy](/features/oauth-authorization-server#audience-and-scope-policy).
- **Resource servers now require `typ: at+jwt`**, both in `surge::resource` and at `userinfo`/introspection.
- **New grant `oauth_admin`** and new CLI group `surge-server oauth {client,resource,key}`.
- **Platform registration grants** `oauth_resource_register` and `oauth_client_register` let a Platform create delegated resources and third-party clients without `oauth_admin`. Request bodies of `POST /v1/oauth/resources` and `POST /v1/oauth/clients` now reject unknown fields with HTTP 422 instead of ignoring them.
- **Resource lifecycle.** `PATCH` and `DELETE /v1/oauth/resources/{uri}` (canonical URI percent-encoded as one segment) let an administrator, or the registrar that created a delegated resource, change scopes, descriptions, the exact CIMD allowlist and the DCR opt-in, or delete it. Scope removal, CIMD removal and DCR disablement trim or end the affected grants (refresh families revoked, consents, codes and flows removed); description edits preserve them. Deletion ends all grants atomically and reserves the URI for the longest access-token lifetime ever configured (persisted high-water mark, never lowered automatically) plus 60 seconds (new migrations `00000000000014` and `00000000000015`, HTTP 409 `resource_reserved` with `reserved_until`); a registrar's delete must carry a `registration_id` precondition. Policy changes are serialized with issuance and refresh rotation by a row lock on the registration. Create, update and delete are audited with actor and registration identity, and the CLI deletes through the same logic (`oauth resource delete [--registration-id]`).
- **Client ID metadata documents (CIMD).** Discovery advertises `client_id_metadata_document_supported`. An HTTPS metadata URL admitted by the target resource's CIMD policy is resolved at authorize: the document is validated (exact `client_id`, name, redirect URIs, `token_endpoint_auth_method: none`), fetched without redirects, through public-address-only connections pinned to the validated addresses, with time, size, per-host rate limit, bounded cache and negative caching. Consent-flow creation upserts one untrusted, public, never-first-party `cimd` client row (new migration `00000000000016`); revoked rows stay tombstones, idle unreferenced rows are swept, and code redemption and refresh use the stored row and current policy without fetching. Confidential CIMD authentication is not supported. See [Client ID metadata documents](/features/oauth-authorization-server#client-id-metadata-documents).
- **Opt-in open CIMD.** Administrators and delegated resource registrars can enable `cimd_open` to admit valid public CIMD clients. Migration 18 defaults existing registrations to exact allowlist enforcement. Closing open CIMD ends excluded grants, and outbound metadata requests share a resolver-wide rate limit.
- **Rollout note.** Do not grant `oauth_client_register` until every node runs this release: older binaries read a `platform` client as `admin` and do not enforce audience eligibility.
- **New token prefixes** `aeg_cid_`, `aeg_cs_`, `aeg_ac_`, `aeg_rt_`.

Behaviour change worth noting: `revoke_all_sessions` now also revokes that identity's OAuth refresh tokens. "Log this person out everywhere" would otherwise leave their connected apps refreshing.

The Hydra login and consent bridge has been removed. Surge ignores the old `SURGE_HYDRA_*` settings. To migrate a bridge deployment, register clients and resources in Surge and authorize those clients again against the Surge issuer. See [OAuth Authorization Server setup](/features/oauth-authorization-server#setup).

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
