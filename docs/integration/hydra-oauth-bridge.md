---
description: How Surge integrates with Ory Hydra to provide OAuth 2.1 / OIDC authorization-server capability without becoming an authorization server itself.
---

# Hydra OAuth Bridge

Surge is an authentication engine, not an OAuth 2.1 / OIDC authorization server. When a consumer needs full AS capability — authorization code flow with PKCE, dynamic client registration, JWKS with key rotation, token introspection, refresh token rotation, and RFC 8414 discovery — Surge does not grow that surface itself. Instead it connects to [Ory Hydra](https://www.ory.sh/hydra/) through a small, opt-in bridge that handles only the login and consent handoff between the two systems.

This page documents the bridge: why it exists, how the request flow works end to end, how to configure and deploy it, and the guarantees it does and doesn't make.

## Why Hydra stays, and what the bridge is for

Authentication and authorization-server work are different jobs. Authentication answers "who is this" — that's Surge's job, via its flow-based browser API and the `surge_session` cookie. Authorization-server work answers "here is a signed token this client may present elsewhere" — PKCE verifier binding, redirect-URI exact matching, signing-key rotation, and code-exchange replay protection are all places where subtle bugs turn into live security incidents, not cleanup items. Hydra already gets these right, so Surge does not reimplement them.

The two systems are not peers being integrated as equals; the bridge is the one seam where their worlds touch. Hydra remains the OAuth 2.1 authorization server. Surge remains the identity/session engine. The bridge translates between "Hydra needs to know who this browser is" and "Surge already knows, via `surge_session`."

The bridge is entirely **opt-in**. Setting `SURGE_HYDRA_ADMIN_URL` is the on-switch — when it's unset, no `/v1/oauth/*` routes are mounted, `HydraAdmin` is never constructed, and Hydra is never contacted. Deployments that don't need OAuth-client support run Surge exactly as before.

## How Hydra delegates to the bridge

Hydra is headless on login and consent — it never renders any UI itself. When an OAuth client hits Hydra's `/oauth2/auth` endpoint:

1. Hydra parks the authorization request and redirects the browser to its configured `URLS_LOGIN`, appending a `login_challenge` query parameter.
2. Whatever is at `URLS_LOGIN` — the bridge, in this integration — must resolve who the user is and tell Hydra via its **admin API**, not the browser-facing API.
3. Once login is resolved, Hydra performs the same dance for consent: redirect to `URLS_CONSENT` with a `consent_challenge`.
4. Once both challenges are accepted, Hydra completes the authorization code flow and redirects back to the OAuth client with a code.

`URLS_LOGIN` and `URLS_CONSENT` in your Hydra deployment should point at Surge's bridge routes: `GET /v1/oauth/login` and `GET /v1/oauth/consent`.

## Request flow

### Login challenge

`GET /v1/oauth/login?login_challenge=...`

1. The bridge looks for a `surge_session` cookie and, if present, verifies it against the configured `AuthProvider` (embedded or remote — the bridge doesn't care which).
2. **Valid session:** the bridge resolves the session's identity, then calls `PUT /admin/oauth2/auth/requests/login/accept` on Hydra's admin API with `subject` set to the identity's internal ID. Hydra returns a `redirect_to` URL, and the bridge redirects the browser there — no UI is ever shown for an already-authenticated user.
3. **No valid session** (missing, expired, or otherwise invalid): rather than trusting any Hydra-side "remember me" signal, the bridge always re-derives the session from scratch. It builds a self-referential URL back to `GET /v1/oauth/login?login_challenge=...` and redirects into Surge's existing flow-based login (`GET /v1/login?return_to=<that self-URL>`). Once the user authenticates and `surge_session` is set, the standard flow-completion redirect lands back on the bridge's login-challenge handler, which now finds a valid session and proceeds as in step 2.

This re-check happens on **every** login challenge, not just the first one for a given browser. That's a deliberate choice: if `surge_session` is sliding-expiry while Hydra-issued refresh tokens are longer-lived, skipping the check on repeat visits could let a Hydra-issued token remain valid after Surge would consider the underlying session dead. Re-validating every time keeps token issuance honest about current session state.

### Consent challenge

`GET /v1/oauth/consent?consent_challenge=...`

The bridge fetches the requested scope and audience from Hydra's admin API (`GET /admin/oauth2/auth/requests/consent`), then immediately accepts the same scope and audience via `PUT /admin/oauth2/auth/requests/consent/accept` with `remember: false`. No consent screen is rendered.

**This auto-accept is a first-party-only shortcut.** It exists because Dispatch MCP (Surge's original consumer for this bridge) is a first-party client — the user never meaningfully "chooses" what to grant, since the client is one Surge's operator controls. There is currently no support for rendering a real consent screen for third-party clients; if you register a client that isn't first-party, every consent request for it will be silently auto-approved with the full requested scope. Don't point non-first-party OAuth clients at a Surge-backed Hydra deployment until this is revisited.

### Sequence diagram

```
 Browser              OAuth Client           Hydra                  Surge Bridge           Surge Core
   |                        |                   |                        |                     |
   |--GET /oauth2/auth----->|                   |                        |                     |
   |                        |--redirect-------->|                        |                     |
   |<--302 to URLS_LOGIN----------------------- |                        |                     |
   |                                             |                        |                     |
   |--GET /v1/oauth/login?login_challenge=X------------------------------>|                     |
   |                                                                      |--verify_session----->|
   |                                                                      |<--no valid session---|
   |<--302 to /v1/login?return_to=self-URL-------------------------------|                     |
   |                                                                      |                     |
   |--GET /v1/login-------------------------------------------------------------------------->  |
   |<--flow-init / credential exchange (existing Surge login flow) ------------------------->   |
   |                                                                      |                     |
   |--GET /v1/oauth/login?login_challenge=X (return_to re-entry)--------->|                     |
   |                                                                      |--verify_session----->|
   |                                                                      |<--valid session------|
   |                                                                      |--PUT .../login/accept (admin API)-->  Hydra
   |                                                                      |<--redirect_to---------------------   Hydra
   |<--302 to URLS_CONSENT-------------------------------------------------|                     |
   |                                                                      |                     |
   |--GET /v1/oauth/consent?consent_challenge=Y--------------------------->|                     |
   |                                                                      |--GET .../consent (admin API)------->  Hydra
   |                                                                      |--PUT .../consent/accept (admin API)>  Hydra
   |<--302 to OAuth client with auth code-----------------------------------|                     |
```

## Subject identity and cookie separation

Two invariants are load-bearing for this integration and must not drift:

**Subject identity is stable and permanent.** The `subject` passed to Hydra's `accept_login` call is always the internal identity ID (the Postgres user-row ID) — never anything derived from session state, such as a session token or its expiry. Every token Hydra issues downstream carries this subject, so it has to remain valid for the lifetime of the identity, independent of any particular session.

**Hydra's cookies and `surge_session` are separate concerns and are never unified.** Hydra sets its own hostname-scoped cookies (e.g. `login_csrf`) to protect its own challenge/response CSRF handling — that protects the challenge dance itself. `surge_session` is what identifies the user to Surge. The bridge is the only place these two cookie jars are read in the same request; nothing merges them.

## Configuration

Three environment variables control the bridge. See the [Configuration Reference](/integration/configuration#hydra-oauth-bridge-surge-hydra-admin-url-surge-hydra-bridge-origin-surge-hydra-admin-timeout-secs) for the authoritative list; summarized here:

| Variable | Default | Purpose |
|---|---|---|
| `SURGE_HYDRA_ADMIN_URL` | (unset) | Hydra's **admin** API base URL (typically port `4434`, not the public `4433`). Setting this is the bridge's on-switch. |
| `SURGE_HYDRA_BRIDGE_ORIGIN` | (required if the above is set) | This Surge server's own public origin, used to build the bridge's self-referential `return_to` callback. |
| `SURGE_HYDRA_ADMIN_TIMEOUT_SECS` | `10` | Timeout for outbound requests to Hydra's admin API. |

```bash
export SURGE_HYDRA_ADMIN_URL="http://hydra:4434"
export SURGE_HYDRA_BRIDGE_ORIGIN="https://auth.example.com"
export SURGE_HYDRA_ADMIN_TIMEOUT_SECS=10
```

### Startup coherence check

`SURGE_HYDRA_BRIDGE_ORIGIN` must be registered as one of the deployment's known return origins (via `surge-server svc create --origin`), or Surge refuses to start:

```
SURGE_HYDRA_ADMIN_URL is set but SURGE_HYDRA_BRIDGE_ORIGIN (https://auth.example.com) is not
among registered return_origins; the bridge's own return_to callback would be rejected by
GET /v1/login's origin check, silently breaking every login challenge. Register it with
`surge-server svc create --origin`.
```

This check exists because the bridge's login-challenge handler re-enters `GET /v1/login` with `return_to` pointing at itself. If that origin isn't registered, `GET /v1/login`'s existing origin validation silently rejects the round-trip — the failure mode would otherwise surface as a mysterious broken login loop rather than a clear startup error.

### Configuring Hydra

Point Hydra's login/consent URLs at the bridge routes, and its admin API at wherever Surge can reach it:

```yaml
# hydra config (relevant excerpt)
urls:
  login: https://auth.example.com/v1/oauth/login
  consent: https://auth.example.com/v1/oauth/consent
```

The admin API (`SURGE_HYDRA_ADMIN_URL`) should be reachable from Surge but does not need to be publicly exposed — it's an internal, trusted call from the bridge to Hydra, typically over a private network or service mesh.

### Mounted routes

When the bridge is enabled, two routes are mounted under the browser router:

- `GET /v1/oauth/login` — handles Hydra login challenges.
- `GET /v1/oauth/consent` — handles Hydra consent challenges (auto-accepted for first-party clients; see above).

## Failure handling

Both Hydra admin-API calls and session verification can fail. The bridge distinguishes the two:

- Session-verification failures use Surge's existing `AuthError` → `ApiError` path, same as any other endpoint.
- Hydra admin-API failures (`HydraError`) — network errors, non-2xx responses from Hydra's admin API — surface as `502 Bad Gateway` with an `upstream_oauth_error` body, since from Surge's perspective these are failures of an upstream dependency:

```json
{
  "error": "upstream_oauth_error",
  "message": "hydra admin error (410): request_expired (login challenge already used or expired)"
}
```

## Non-goals

- **Not a general-purpose authorization server.** The bridge exists to serve Hydra one specific admin-API contract; it does not implement token issuance, JWKS, introspection, or discovery — Hydra does all of that.
- **No third-party client support.** `skip_consent` unconditionally grants the requested scope without a real consent screen. This is only safe for first-party clients. Supporting third-party clients requires building an actual consent UI first.
- **No cookie unification.** Hydra's CSRF cookies and `surge_session` are and remain separate; the bridge does not attempt to merge or bridge their semantics beyond reading both where needed.

## When to revisit internalizing OIDC into Surge

The current design is deliberately narrow: one bridge endpoint pair rather than a general-purpose authorization server, because there's exactly one consumer (Dispatch MCP) today. Reconsider that decision only if at least one of these becomes true:

- Multiple first-party or third-party MCP integrators need AS capability at real scale.
- Dynamic client registration becomes a standing operational concern rather than a one-off setup step.
- Running Hydra (extra Postgres schema, extra deploy target, extra patching surface) demonstrably costs more than maintaining the bridge.

None of these hold today — see `rfc.md` in the repository root for the full design rationale.

**Related:** [Configuration Reference](/integration/configuration), [Deployment: Docker](/deployment/docker), [Environment Templates](/deployment/environment)
