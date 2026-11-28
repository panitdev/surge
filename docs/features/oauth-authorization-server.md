---
description: Surge as a native OAuth 2.1 / OIDC authorization server — clients, audiences, consent, token issuance, and the resource-server side.
---

# OAuth Authorization Server

Surge can act as an OAuth 2.1 / OIDC authorization server: third-party clients obtain audience-scoped access tokens for resources exposed by services registered in Surge. The first target is MCP — arbitrary MCP clients (Claude, editors, agent runtimes) connecting to a service you run.

This is opt-in. Setting `SURGE_OAUTH_ISSUER` is the on-switch: unset, no `/oauth2/*` routes are mounted, no signing key is ever generated, and nothing about the deployment changes.

## Why this lives inside Surge

An MCP token is scoped to a **resource server**. Surge stores resource audiences alongside the services and identities that own or authorize access to them. Keeping clients, scopes, and audiences in the same database lets Surge validate the requested audience, show what a client will gain access to, and revoke that access from the user's account settings.

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

- `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` are **fixed at the origin root** by RFC 8414 and RFC 9728 for an issuer with no path, which is the only kind Surge accepts (startup refuses a path-ful `SURGE_OAUTH_ISSUER`). They cannot live under a version prefix.
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
  --grant introspect \
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

Startup requires a registered return origin for the issuer and requires `https` on a non-loopback bind. It warns when no resources are registered or when dynamic registration is enabled.

## Audience and scope policy

One rule decides whether a client may be issued tokens for a resource, and it is applied to current state at every point a token can come into being: `GET /oauth2/authorize`, consent completion, code redemption and refresh. A grant that was eligible on the day of consent is checked again each time. Ineligible requests fail with `invalid_target`, and the error never says whether the resource exists.

1. **A CIMD client** (`registration_source` `cimd`; its client ID is an `https` URL, see [Client ID metadata documents](#client-id-metadata-documents)) may use a resource if the resource enables `cimd_open` or lists its exact client ID in `allowed_cimd_client_ids`.
2. **A client with an explicit audience list is restricted to it, for every resource, service or delegated.** An empty list grants nothing. The list names registrations, not URIs, so it does not survive the resource being deleted and registered again.
3. **A registrar client** (created by a service holding `oauth_client_register`) always has an explicit list, limited to delegated registrations its registrar created, so rule 2 governs it and it never receives the no-list or DCR access in rules 3 and 4.
4. **A client with no list (the default for existing clients) keeps its access to service resources.** It has none to delegated resources, with the exception in rule 5.
5. **A dynamically registered client without a list** may use a delegated resource that has set `dcr_enabled`. A dynamic client's explicit list is honoured for a delegated resource only if that resource has also opted in, so an anonymous registration cannot bind itself to someone else's resource.

## Client ID metadata documents

A client may identify itself by the HTTPS URL of a JSON document it publishes (CIMD) instead of registering. Discovery advertises `client_id_metadata_document_supported: true`. Both service and delegated resources default to requiring an exact `allowed_cimd_client_ids` entry. Set `cimd_open: true` to admit valid public CIMD clients for that resource. Existing sign-in, consent, scope and audience rules apply.

**The client ID.** It must be exactly the canonical form of an `https` URL with a path, a public DNS host (no IP literal, `localhost`, single-label or `.local`/`.internal` name), the default port, and no userinfo or fragment. Anything the URL parser would rewrite (dot segments, an upper-case host, an explicit `:443`) is refused, so one document has one ID.

**The document.** It must repeat the exact client ID as `client_id`, carry a `client_name`, valid `redirect_uris` (the same rules as any client: `https`, or `http` on loopback, no wildcards or fragments), and offer public-client token exchange. When `token_endpoint_auth_methods_supported` is present, it must be an array of method names that includes `"none"`, which Surge selects for token exchange. Otherwise, the document must declare `token_endpoint_auth_method: "none"`. Surge rejects published client secrets and unsupported grant or response types. An optional `scope` is a ceiling on what the client may request; without one, the resource's scopes are the range. Documents are limited to 32 KiB. PKCE `S256` is required as for every client. Confidential CIMD authentication is not supported in this release.

**Fetching.** The authorize endpoint checks resource admission and client revocation before fetching a document. The fetch:

- does not follow redirects and ignores proxy settings;
- resolves the host through a resolver that refuses the whole lookup if any address is not publicly routable (loopback, private, link-local, CGNAT, unique-local, multicast, unspecified, documentation, benchmarking, reserved, and every IPv6 form that embeds IPv4: mapped, compatible, NAT64, 6to4, Teredo), and connects only to the addresses it returned, with TLS verified against the original host name;
- uses `https` only, a 3 s connect and 5 s total timeout, requires status 200 and a JSON content type, and reads at most 32 KiB;
- is rate limited to 10 fetches per host per minute, 120 fetches across all hosts and resources per minute per resolver instance, and 16 in flight, answering `temporarily_unavailable` on a cache miss beyond those limits;
- is cached for the origin's `Cache-Control: max-age` (clamped to 1 hour; 5 minutes if absent; `no-store` and `no-cache` are not cached), and failures, including invalid documents, are cached for 60 seconds. The cache holds at most 1024 documents.

Because the document is untrusted until it is fetched and checked, every failure before the redirect URI is verified is an error page, not a redirect.

**Stored client.** Nothing is written when a document is fetched. After the session, document and eligibility checks pass, creating the consent flow upserts one shared client row in the same transaction (under the resource's lock): `registration_source=cimd`, `trust_state=untrusted`, `first_party=false`, public (`none`, no secret). The database refuses any other combination. Concurrent requests converge on one row, and each upsert refreshes the name, URIs and redirect URIs from the document it validated. A revoked row is a tombstone: it is never refreshed or resurrected, authorize refuses it before any fetch, and the sweep never deletes it. Consent shows a CIMD client as `dynamically_registered: true`, because its name and logo are self-declared. It displays the validated metadata URL hostname as the publisher alongside the application name.

Code redemption and refresh never fetch. They use the stored row and the resource's *current* policy, so closing open CIMD ends grants for clients excluded by the resulting allowlist. Access tokens verified offline can remain usable until expiry.

**Cleanup.** The background sweep deletes a `cimd` row that has been idle for `SURGE_OAUTH_DCR_TTL_DAYS` (measured from its last completed authorization, or creation) and is referenced by no consent, refresh token, code, consent flow or pending account choice. A deleted client returns on its next authorization.

**Authorize and token errors.** At authorize and consent, an unknown resource and an ineligible one return the identical `invalid_target` error. At the token endpoint a refresh whose registration no longer exists returns `invalid_grant`, while one the client may no longer use returns `invalid_target`. The refresh is judged inside the rotation transaction, under the registration's lock: if it fails the eligibility check, the presented token is not spent and every refresh family the client holds at that resource is revoked, so no live refresh token remains and introspection stops reporting the earlier access tokens as active.

**Registration errors.** Dynamic registration answers an unknown resource and a non-opted-in one with the same `invalid_client_metadata` message. Operator and service registration paths give the detail.

**Scope ceilings.** What a client may be granted at a resource is the resource's *current* scopes, narrowed by the client's own list unless that list is only a snapshot. A client registered with an explicit scope list (every admin and registrar client, a dynamic client that sent `scope`, and every client that predates the `scope_ceiling_explicit` column, whose provenance is unknown) is held to `client scopes ∩ resource scopes`: adding `write` to a resource never expands a client that registered for `read`. A dynamic client that registered without resource scopes may use whatever the target currently permits. Its stored list is a snapshot of the defaults offered at registration. A CIMD document that omits `scope` also follows the current resource scopes, with the omitted ceiling recorded separately from its empty stored scope list. The same ceiling is re-judged under the registration's lock at consent completion, code redemption and refresh (against the refresh token's own scopes), and a refresh may only narrow the grant, so it cannot widen.

Scopes are then narrowed per resource, so two resources that both define `mcp:read` stay separate: consent, codes, refresh tokens and the access token's `aud` are all bound to one registration.

Clients receive a list when they are registered: `--resource` on `surge-server oauth client create`, `resources` in the `POST /v1/oauth/clients` body, and `resources` in a `POST /oauth2/register` body. Each URI must resolve to a current registration the client is eligible for, or registration fails. Omit the field for no list. A registrar service holding `oauth_client_register` may bind a client only to delegated registrations it created itself; any other resource, or an empty list, is refused with HTTP 403 or 422 ([Client registration](../api/service/oauth-resources.md#register-a-client)).

**Lifecycle changes and serialization.** A registration's scopes, CIMD allowlist, DCR opt-in and existence can change after grants exist (`PATCH` and `DELETE` on `/v1/oauth/resources/{uri}`, see [Resource registration API](../api/service/oauth-resources.md#change-or-delete-a-registration)). Policy changes take `FOR UPDATE` on the `oauth_resource` row; every write that creates or extends a grant (consent flow, code and consent, first refresh token, refresh rotation) takes `FOR SHARE` on it first, re-checks eligibility and scopes against what it locked, and writes in the same transaction. A change therefore either sees and ends what an issuance wrote, or the issuance is judged by the new policy; none can leave a live grant that violates it. Lock order is registration first, then flow, code and token rows. A deleted URI is reserved until the access-token lifetime plus clock skew has elapsed.

**Discovery.** `/.well-known/oauth-authorization-server` advertises the union of scopes defined by *service* resources. A scope that only delegated resources define is omitted, including when the resource enables DCR. A resource advertises its own scopes in its RFC 9728 metadata (`scopes_supported`). **Introspection** answers only for service registrations assigned to the calling service, and an `active: false` for everything else.

## Validating access tokens offline

A resource server that verifies tokens itself (`surge::resource` does all of this) must check, in this order, and reject on any failure:

1. **Issuer.** `iss` equals the configured issuer exactly. Fetch the JWKS URI from the issuer's `/.well-known/oauth-authorization-server`, not from the token.
2. **Signature.** Verify against the key in that JWKS whose `kid` the token header names. Refuse a token with no `kid`: every token Surge mints carries one. Permit `ES256` only, and never take the algorithm from the token header.
3. **Type.** The JOSE header `typ` is `at+jwt` (RFC 9068). This refuses ID tokens, which this issuer also signs.
4. **Expiry.** `exp` is in the future (allow a small clock skew), and `iat` is not.
5. **Audience.** `aud` equals this resource's canonical URI exactly. No prefix or substring match, and no accepting a token minted for a sibling resource that shares scopes.
6. **Scopes.** `scope` contains every scope the route requires. Treat it as a space-separated list.

Offline checks cannot see revocation. The access-token lifetime is the revocation window; a service that cannot accept that calls introspection, which is only available for service resources it owns.

## Endpoints

| Endpoint | Notes |
|---|---|
| `GET /oauth2/authorize` | Code flow. Validates the client and exact-matches `redirect_uri` **before** anything is redirected anywhere. Requires PKCE `S256`, resolves `resource` against the audience registry, and bounces to `GET /v1/login` when there is no session. |
| `POST /oauth2/token` | `authorization_code` and `refresh_token` only. No client credentials, no password grant. |
| `GET /oauth2/jwks.json` | Public keys — active plus retiring. Cacheable. |
| `POST /oauth2/introspect` | RFC 7662, authenticated by a **service token** with the `introspect` grant, and scoped to that service's own audiences. |
| `POST /oauth2/revoke` | RFC 7009, client-authenticated. Revokes a refresh token and its whole family. |
| `GET /oauth2/userinfo` | OIDC claims for an access token minted for `urn:surge:oauth:userinfo` with the `openid` scope. |
| `POST /oauth2/register` | RFC 7591 dynamic registration. Off unless enabled. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata. Also served at `/.well-known/openid-configuration` when OIDC is on. |

With OIDC enabled, registered clients can send `scope=openid` and omit
`resource` for sign-in. Surge uses its built-in `urn:surge:oauth:userinfo`
audience for the access token, and only a token with that audience is
answered at `userinfo`. A grant that pairs `openid` with a `resource` still
gets an ID token, but its access token belongs to that resource and is
refused at `userinfo`. Requests for API scopes follow the resource
indicator policy. Clients using Client ID Metadata Documents follow the
resource indicator and eligibility policies.

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
- scope is capped by what service resources and DCR-opted-in delegated resources declare: a client can ask for a scope that is open to it, never invent one. Scope names defined only by other delegated resources are neither returned as defaults nor distinguishable from nonexistent ones in errors. Whether the registration asked for scopes is recorded: a registration that did is an explicit ceiling, one that did not follows the target resource (see [Scope ceilings](#audience-and-scope-policy));
- an optional `resources` list binds the client to specific audiences and restricts it to them; each must be a registered resource the client is eligible for (see [Audience and scope policy](#audience-and-scope-policy));
- redirect URIs must be `https`, or `http` on a loopback host (`127.0.0.1`, `::1`, `localhost`, any port) for native clients. No wildcards, no plain `http` on a public host;
- registrations that never complete an authorization are swept after `SURGE_OAUTH_DCR_TTL_DAYS`.

There is no registration access token and no RFC 7592 configuration endpoint: a dynamic client that wants different metadata registers again.

Disabling DCR on a delegated resource (`dcr_enabled: false`) ends every grant, consent, flow and code its dynamic clients hold there, through the same lifecycle change as removing a CIMD client. **The global switch is a kill switch.** `SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION` controls the endpoint and the `registration_endpoint` in metadata, and it is also part of the eligibility rule: with it off, every dynamically registered client is ineligible for every resource, service or delegated, at authorize, consent, code redemption and refresh. Nothing is deleted at restart; each affected grant ends at its next use. A refresh fails with `invalid_target` and revokes every refresh family the client holds at that registration, exactly as for any other ineligible client, and the client's consents, pending flows and codes are refused at their next step. Turning the switch back on restores no ended grant. A resource's own `dcr_enabled` opt-in only matters while the global switch is on. The setting is read from the running server's configuration, so changing it takes a restart.

A registration that names no resource scope (empty or whitespace `scope`, or only `openid`, `profile` or `offline_access`) counts as omitting scopes.

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

The guard validates the JWT against cached JWKS — checking `typ`, `iss`, `aud`, `exp` and scope — and returns the RFC 9728 `WWW-Authenticate` challenge on failure, which is how an MCP client discovers where to authorize. Handlers read the verified claims with the `AccessToken` extractor. This mirrors what `AuthProvider` does for sessions: the service holds a config object and never learns the protocol.

Note the metadata path. A resource URI with a path is described at `https://host/.well-known/oauth-protected-resource/mcp`, **not** at `https://host/mcp/.well-known/...` (RFC 9728 §3). `ResourceServer::router()` mounts the right one; getting this backwards by hand is the most common way a resource server ends up undiscoverable.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SURGE_OAUTH_ISSUER` | (unset) | On-switch. This server's public origin, with no path; becomes `iss` (trailing slash dropped). |
| `SURGE_OAUTH_ACCESS_TTL_SECS` | `600` | Access-token lifetime = the offline revocation window. |
| `SURGE_OAUTH_REFRESH_TTL_DAYS` | `30` | Refresh lifetime, renewed on each rotation. |
| `SURGE_OAUTH_KEY_ROTATION_DAYS` | `90` | Signing-key rotation cadence. |
| `SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION` | `0` | Opens `POST /oauth2/register`. Also a kill switch: when off, existing dynamic clients are ineligible everywhere. |
| `SURGE_OAUTH_REQUIRE_RESOURCE` | `1` | Require a resolvable `resource` except for `openid`-only sign-in when OIDC is enabled. |
| `SURGE_OAUTH_DEFAULT_RESOURCE` | (unset) | Audience assumed when `REQUIRE_RESOURCE=0` and none was sent. |
| `SURGE_OAUTH_DCR_TTL_DAYS` | `30` | Sweep dynamic clients that never authorized, and idle unreferenced CIMD clients. |
| `SURGE_OAUTH_ENABLE_OIDC` | `1` | ID tokens, `userinfo`, and `/.well-known/openid-configuration`. |

**Related:** [Service Grants](/reference/grants), [Tokens](/reference/tokens), [CLI](/reference/cli), [Session Management](/features/session-management)
