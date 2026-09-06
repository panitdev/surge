---
description: Surge as a native OAuth 2.1 / OIDC authorization server — clients, audiences, consent, token issuance, and the resource-server side.
---

# OAuth Authorization Server

Surge can act as an OAuth 2.1 / OIDC authorization server: third-party clients obtain audience-scoped access tokens for resources exposed by services registered in Surge. The first target is MCP — arbitrary MCP clients (Claude, editors, agent runtimes) connecting to a service you run.

This is opt-in. Setting `SURGE_OAUTH_ISSUER` is the on-switch: unset, no `/oauth2/*` routes are mounted, no signing key is ever generated, and nothing about the deployment changes.

## Why this lives inside Surge

Surge previously delegated authorization-server work to [Ory Hydra through a bridge](/integration/hydra-oauth-bridge). That decision was reversed, and the reason is worth stating because it also explains the data model.

What an MCP token must be scoped to is a **resource server**, and Surge already holds the registry of those: the `service` table. In the Hydra split, Hydra owned clients, scopes and audiences while Surge owned services and identities — and the mapping between them lived in nobody's schema. Consent ("let this client read your Dispatch resources"), revocation ("show me every app connected to my account") and audience validation ("is this `resource` a service I know?") each need both halves in one query. Internalizing the authorization server is what collapses that seam.

The bridge still works and both can run at once during a cutover; `sub` is the identity UUID in both, so the two issuers name the same subject.

## What the MCP spec pins

These are requirements, not choices:

| Requirement | Spec | How Surge satisfies it |
|---|---|---|
| Authorization code + PKCE; no implicit, no password grant | OAuth 2.1 | `S256` only — `plain` and an absent challenge are both refused |
| AS metadata discovery | RFC 8414 | `GET /.well-known/oauth-authorization-server` |
| Protected resource metadata | RFC 9728 | Served by the resource server; `surge::resource` ships it |
| Resource indicators | RFC 8707 | `resource` on authorize and token; tokens are audience-restricted |
| Dynamic client registration | RFC 7591 | `POST /oauth2/register`, off by default, rate-limited |
| `WWW-Authenticate` carrying `resource_metadata` | RFC 9728 §5.1 | `surge::resource`'s challenge |

## These paths are not versioned

Every other browser route in Surge lives under `/v1`. The OAuth surface does not, and that is deliberate:

- `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` are **fixed at the origin root** by RFC 8414 and RFC 9728. They cannot live under a version prefix.
- Every other endpoint's path is discovered *from* that metadata document, so versioning them buys nothing — the document already is the indirection a `/vN` prefix would provide. A client never hardcodes `/oauth2/token`; it reads `token_endpoint`.

**The OAuth spec version, not Surge's `/vN`, is the compatibility contract for this surface.** The substrate invariant is untouched: an access token is a new kind of credential, and once minted it means one thing forever, exactly like a session.

The consent screen's own API (`/v1/oauth/consent/{flow_id}`) and account connections (`/v1/account/connections`) *are* under `/v1`, because they are Surge's own browser API consumed by Surge's own auth UI — not part of the OAuth wire protocol.

### Only central mounts it

An authorization server has exactly one issuer identity, so `RemoteProvider` never proxies `/oauth2/*`; it logs a warning and ignores `oauth_as` if set. A service answering `/oauth2/token` on its own origin would be minting tokens under central's `iss`, and the client-side issuer check would fail quietly, in ways that look like clock skew.

## Setup

Three things must exist before anything can authorize: a service, an audience owned by it, and a client.

```bash
# 1. The resource server, if it isn't registered already. The issuer must be
#    among the return origins — the authorize endpoint bounces through
#    GET /v1/login, and an unregistered issuer would fail that check.
surge-server svc create --name dispatch \
  --grant introspect --grant oauth_admin \
  --origin https://auth.example.com

# 2. The audience. Scopes are defined here, by the resource — never by clients.
surge-server oauth resource create \
  --uri https://dispatch.example.com/mcp \
  --service dispatch \
  --scope mcp:read --scope mcp:write \
  --describe "mcp:read=Read your Dispatch data" \
  --describe "mcp:write=Create and change your Dispatch data"

# 3. A client. Public (PKCE-only) is the normal case for native and MCP
#    clients; --confidential issues a secret instead.
surge-server oauth client create \
  --name "Dispatch Desktop" \
  --redirect-uri https://dispatch.example.com/oauth/callback \
  --scope mcp:read --scope mcp:write
```

Then start the server with the AS enabled:

```bash
export SURGE_OAUTH_ISSUER="https://auth.example.com"
surge-server serve
```

Startup refuses to proceed if the issuer is not a registered return origin, or if it is not `https` on a non-loopback bind. It warns if no resources are registered (every authorize would fail audience validation) or if the Hydra bridge is enabled at the same time.

## Endpoints

| Endpoint | Notes |
|---|---|
| `GET /oauth2/authorize` | Code flow. Validates the client and exact-matches `redirect_uri` **before** anything is redirected anywhere. Requires PKCE `S256`, resolves `resource` against the audience registry, and bounces to `GET /v1/login` when there is no session. |
| `POST /oauth2/token` | `authorization_code` and `refresh_token` only. No client credentials, no password grant. |
| `GET /oauth2/jwks.json` | Public keys — active plus retiring. Cacheable. |
| `POST /oauth2/introspect` | RFC 7662, authenticated by a **service token** with the `introspect` grant, and scoped to that service's own audiences. |
| `POST /oauth2/revoke` | RFC 7009, client-authenticated. Revokes a refresh token and its whole family. |
| `GET /oauth2/userinfo` | OIDC claims for a token carrying `openid` or `profile`. |
| `POST /oauth2/register` | RFC 7591 dynamic registration. Off unless enabled. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata. Also served at `/.well-known/openid-configuration` when OIDC is on. |

## Tokens and keys

**Access tokens are ES256-signed JWTs.** A resource server verifies them offline against JWKS; an MCP server is the audience for every request on a connection and should not need a network hop per call. Claims: `iss`, `sub` (identity UUID), `aud` (the single resource URI), `client_id`, `scope`, `sid`, `jti`, `iat`, `exp`. The header carries `typ: at+jwt` (RFC 9068), so a resource server can refuse an ID token presented as an access token.

ES256 rather than EdDSA because JWT support for Ed25519 is still uneven across the client ecosystems that will consume these. The algorithm is a database column, not a constant, so revisiting it is a data change.

**Refresh tokens are opaque, hashed at rest, and rotated on every use.** Prefix `aeg_rt_`.

**Signing keys are encrypted under the pepper.** The private key sits in the database as `v{pepper_version}$hex(nonce||ciphertext)`, encrypted with XChaCha20-Poly1305 under an HKDF-derived key — the same envelope TOTP seeds use, with a different domain separator. There is no new secret to manage, and key rotation follows pepper rotation.

> A database leak alone therefore does not let anyone forge tokens. The flip side is that **a pepper leak is now also a token-forgery event**, which it was not before this feature existed. Treat the pepper accordingly.

Keys rotate on the background sweep once the active key exceeds `SURGE_OAUTH_KEY_ROTATION_DAYS`. The previous key is retired but stays published in JWKS until every token it signed has expired.

## Consent

A **first-party** client (`--first-party`, admin-registered only) skips the consent screen. Everything else gets one.

The round trip is shaped exactly like a login flow: authorize creates a server-side consent flow and redirects the browser to `{auth_ui_origin}/consent?consent_flow=<id>`, carrying only the id. The auth UI then:

```
GET  /v1/oauth/consent/{flow_id}   -> client, resource, scopes with descriptions, csrf_token
POST /v1/oauth/consent/{flow_id}   -> {approve, scopes?, csrf_token} -> {redirect_to}
```

The GET response includes `client.dynamically_registered`. **The UI must render that distinction.** A dynamically registered client's `client_name` and `logo_uri` are attacker-supplied text and an attacker-supplied image; a screen that presents them the same way it presents a verified first-party client trains people to approve anything. This is the most likely place for the design to fail in practice, and it is a security control rather than polish.

Approval writes a consent record and mints the code; denial returns `access_denied` to the client's redirect URI. The flow is single-use either way — an approval that could be replayed would be a code-minting oracle.

### Account connections

```
GET    /v1/account/connections              -> every client this identity has approved
DELETE /v1/account/connections/{client_id}  -> disconnect
```

Disconnecting revokes the consent *and* every refresh token issued under it, in one transaction. "Show me every app connected to my account" is the reason third-party OAuth is tolerable for the person whose account it is; issuing tokens without it is not an option.

## Session coupling and revocation

Surge's guarantee is that a minted session stays valid until it expires or is revoked. OAuth adds a credential that can outlive the session it came from, and a signed JWT cannot be recalled mid-flight. The resolution, stated plainly:

- **Access tokens are short — 10 minutes by default.** For a resource server that verifies offline, that lifetime *is* the revocation window. `SURGE_OAUTH_ACCESS_TTL_SECS` is a security parameter, not a performance knob.
- **Grants are bound to the identity, not the session.** `sid` is recorded and carried in the token for audit, but refresh checks identity state rather than session liveness. Binding to the session would mean every MCP client silently breaking whenever the 72-hour browser session it was born from expired — an outage, not a security property.
- **Explicit revocation still cascades.** `revoke_all_sessions` ("log this person out everywhere") revokes the identity's refresh tokens in the same transaction. So does disconnecting the app, and so does revoking the client.
- **Introspection is authoritative.** A resource server that cannot tolerate the 10-minute window calls `/oauth2/introspect`, which checks the current state directly and answers `active: false` for anything revoked, disabled, or minted for an audience the asking service does not own.
- **Refresh rotation with reuse detection.** Every refresh mints a successor in the same family and consumes the parent. Presenting a consumed token revokes the whole family — the thief and the legitimate client cannot both hold the newest token, so a replay ends the grant and forces a re-authorization.

## Dynamic client registration

`POST /oauth2/register` is unauthenticated by specification, which makes it the largest abuse surface here. It is off unless `SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION=1`, and everything it can produce is bounded:

- rate-limited per IP through the existing limiter;
- registered clients are always `registration_source=dynamic`, `trust_state=untrusted`, and `first_party=false` — the database refuses any other combination, so no code path can promote one;
- scope is capped by what registered resources declare: a client can ask for an existing scope, never invent one;
- redirect URIs must be `https`, or `http` on a loopback host (`127.0.0.1`, `::1`, `localhost`, any port) for native clients. No wildcards, no plain `http` on a public host;
- registrations that never complete an authorization are swept after `SURGE_OAUTH_DCR_TTL_DAYS`.

There is no registration access token and no RFC 7592 configuration endpoint: a dynamic client that wants different metadata registers again.

**Never enable dynamic registration without a working consent screen.** DCR without one means anyone can register a client and obtain tokens silently.

## The resource-server side

A service exposing MCP needs to publish RFC 9728 metadata, answer unauthenticated calls with a challenge pointing at it, and validate bearer tokens. All three are the same code in every service, so `surge` ships them behind the `resource-server` feature:

```rust
use surge::resource::{ResourceServer, ResourceServerConfig, ScopeGuard};

let server = ResourceServer::new(ResourceServerConfig {
    issuer: "https://auth.example.com".into(),
    resource_uri: "https://dispatch.example.com/mcp".into(),
    required_scopes: vec!["mcp:read".into()],
    jwks_cache_ttl: std::time::Duration::from_secs(300),
})?;

// The guard goes on the protected routes only — never over the metadata
// document, which a client fetches before it has a token.
let protected = axum::Router::new()
    .route("/mcp", axum::routing::post(handler))
    .layer(axum::middleware::from_fn_with_state(
        ScopeGuard::new(&server, ["mcp:read"]),
        surge::resource::require_scope,
    ));

let app = axum::Router::new()
    .merge(server.router())   // /.well-known/oauth-protected-resource/...
    .merge(protected);
```

The guard validates the JWT against cached JWKS — checking `iss`, `aud`, `exp` and scope — and returns the RFC 9728 `WWW-Authenticate` challenge on failure, which is how an MCP client discovers where to authorize. Handlers read the verified claims with the `AccessToken` extractor. This mirrors what `AuthProvider` does for sessions: the service holds a config object and never learns the protocol.

Note the metadata path. A resource URI with a path is described at `https://host/.well-known/oauth-protected-resource/mcp`, **not** at `https://host/mcp/.well-known/...` (RFC 9728 §3). `ResourceServer::router()` mounts the right one; getting this backwards by hand is the most common way a resource server ends up undiscoverable.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SURGE_OAUTH_ISSUER` | (unset) | On-switch. This server's public origin; becomes `iss`. |
| `SURGE_OAUTH_ACCESS_TTL_SECS` | `600` | Access-token lifetime = the offline revocation window. |
| `SURGE_OAUTH_REFRESH_TTL_DAYS` | `30` | Refresh lifetime, renewed on each rotation. |
| `SURGE_OAUTH_KEY_ROTATION_DAYS` | `90` | Signing-key rotation cadence. |
| `SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION` | `0` | Opens `POST /oauth2/register`. |
| `SURGE_OAUTH_REQUIRE_RESOURCE` | `1` | Reject authorize without a resolvable `resource`. |
| `SURGE_OAUTH_DEFAULT_RESOURCE` | (unset) | Audience assumed when `REQUIRE_RESOURCE=0` and none was sent. |
| `SURGE_OAUTH_DCR_TTL_DAYS` | `30` | Sweep dynamic clients that never authorized. |
| `SURGE_OAUTH_ENABLE_OIDC` | `1` | ID tokens, `userinfo`, and `/.well-known/openid-configuration`. |

**Related:** [Hydra OAuth Bridge](/integration/hydra-oauth-bridge), [Service Grants](/reference/grants), [Tokens](/reference/tokens), [CLI](/reference/cli), [Session Management](/features/session-management)
