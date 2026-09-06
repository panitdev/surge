---
description: surge-server CLI commands — serve, identity management, and service token management.
---

# CLI

The `surge-server` binary provides commands for running the server and managing identities and service tokens.

The `surge-server` binary is a single entry point with four subcommand groups. Every subcommand connects to the same Postgres database (via `DATABASE_URL`) and shares the same configuration surface.

## `surge-server serve` — Start the HTTP server

Starts the Surge HTTP server on the configured bind address.

```bash
surge-server serve
```

Most configuration is read from environment variables:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://localhost/surge` | Postgres connection string |
| `SURGE_PEPPER` | `dev-pepper-change-me` | Secret pepper applied before Argon2id hashing |
| `SURGE_BIND` | `0.0.0.0:3000` | Listen address and port |
| `SURGE_COOKIE_DOMAIN` | `.panit.dev` | Domain for session `Set-Cookie` headers |
| `SURGE_AUTH_UI_ORIGIN` | `https://auth.panit.dev` | Origin URL for the auth UI (used in redirect mode) |
| `SURGE_SESSION_TTL_HOURS` | `72` | Session lifetime in hours |
| `SURGE_REGISTRATION` | `open` | Registration mode: `open`, `invite`, or `closed` |
| `SURGE_SESSION_CORS_ORIGINS` | (empty) | Comma-separated origins for CORS session-management zone |
| `SURGE_ALLOW_SERVED_INLINE` | `false` | Allow inline flow-init responses on served deployments |
| `SURGE_HYDRA_ADMIN_URL` | (unset) | Ory Hydra admin API base URL (e.g. `http://hydra:4434`); setting this enables the Hydra login/consent bridge |
| `SURGE_HYDRA_BRIDGE_ORIGIN` | (required if `SURGE_HYDRA_ADMIN_URL` is set) | This server's own public origin for the bridge's `return_to` callback (e.g. `https://auth.example.com`) |
| `SURGE_HYDRA_ADMIN_TIMEOUT_SECS` | `10` | Timeout in seconds for Hydra admin API requests |
| `SURGE_OAUTH_ISSUER` | (unset) | This server's public origin; setting it enables the native OAuth 2.1 / OIDC authorization server |
| `SURGE_OAUTH_ACCESS_TTL_SECS` | `600` | Access-token lifetime — also the offline revocation window |
| `SURGE_OAUTH_REFRESH_TTL_DAYS` | `30` | Refresh-token lifetime, renewed on each rotation |
| `SURGE_OAUTH_KEY_ROTATION_DAYS` | `90` | Signing-key rotation cadence |
| `SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION` | `0` | Opens the unauthenticated `POST /oauth2/register` (RFC 7591) |
| `SURGE_OAUTH_REQUIRE_RESOURCE` | `1` | Reject `authorize` without a resolvable `resource` (RFC 8707) |
| `SURGE_OAUTH_DEFAULT_RESOURCE` | (unset) | Audience assumed when `REQUIRE_RESOURCE=0` and the client sent none |
| `SURGE_OAUTH_DCR_TTL_DAYS` | `30` | Sweep dynamically registered clients that never authorized |
| `SURGE_OAUTH_ENABLE_OIDC` | `1` | ID tokens, `userinfo`, and `/.well-known/openid-configuration` |

### Minimal start

```bash
DATABASE_URL="postgres://user:pass@localhost/surge" \
SURGE_PEPPER="$(openssl rand -hex 32)" \
  surge-server serve
```

Only `DATABASE_URL` and `SURGE_PEPPER` are strictly required for operation. All other variables have production-safe defaults.

### Flags

| Flag | Description |
|---|---|
| `--bind <addr>` | Listen address and port; overrides `SURGE_BIND` |
| `--help`, `-h` | Print help and exit |
| `--version`, `-V` | Print version and exit |

## `surge-server identity` — Manage user identities

Administrative operations on user identities. These commands operate directly against the database, not through the HTTP API — no session or Bearer token is needed.

All `identity` commands take a plain username as a positional argument — there is no `--id`/UUID lookup.

### `reset-password`

Generates a new random temporary password for a user, sets it, and revokes all of that user's existing sessions.

```bash
surge-server identity reset-password alice
```

```
Temporary password for alice: xK3mQp9...
All existing sessions revoked.
Deliver this password to the user out-of-band.
The user should change it after login.
```

There is no flag to supply your own password — the command always generates one and prints it once. It is not stored or logged in plaintext.

### `disable`

Disables an identity, preventing login and session verification, and revokes all existing sessions.

```bash
surge-server identity disable alice
```

Disabled identities:
- Cannot complete login flows
- Existing sessions are revoked immediately
- Are not deleted — all data is preserved

### `enable`

Re-enables a previously disabled identity.

```bash
surge-server identity enable alice
```

Enabling restores full access. Existing sessions from before the disable are still revoked — the user must log in again.

### `rename`

Changes an identity's username.

```bash
surge-server identity rename oldname newname
```

Renaming does not affect the identity's ID or any other stored data. Any downstream system that references the old username directly (rather than the identity ID) must be updated separately — the CLI does not do this for you.

## `surge-server svc` — Manage service tokens

Service tokens authenticate backend services to Surge's service API. Each token carries a set of grants that control what the service can do.

### `create`

Creates a new service token and prints it **exactly once**.

```bash
surge-server svc create --name "my-api-gateway" --grant introspect --grant identity_read --origin https://app.example.com
```

```
Service created:
  ID:     018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c3
  Name:   my-api-gateway
  Grants: ["introspect", "identity_read"]
  Token:  aeg_svc_3k7m9p2q5r8t1v4w6x

Store this token securely — it cannot be retrieved again.
```

| Flag | Required | Description |
|---|---|---|
| `--name` | Yes | Human-readable name for the service (used in audit logs) |
| `--grant` | Yes | Repeatable flag for each grant: `introspect`, `identity_read`, `identity_write`, `direct_auth`, `revoke`, `browser_proxy`, `external_auth`, `external_link` |
| `--origin` | No | Repeatable flag; registers a return origin the service can redirect browser logins back to |

The raw token is printed to stdout once. Store it immediately in a secrets manager or environment variable. The token hash is stored in the database — the raw token cannot be recovered.

### `list`

Lists all registered services with their names, IDs, grants, and return origins. Tokens are **never** shown.

```bash
surge-server svc list
```

```
my-api-gateway (018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c3): grants=["introspect", "identity_read"] origins=["https://app.example.com"]
admin-service (018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c4): grants=["identity_write", "revoke"] origins=[]
```

### `revoke`

Permanently revokes a service token by its name.

```bash
surge-server svc revoke my-api-gateway
```

After revocation, the service token is immediately invalid. Any request using the revoked token will receive `401 Unauthorized`. This is irreversible — to restore access, create a new token with `svc create`.

## Global options

All `surge-server` subcommands support:

| Flag | Description |
|---|---|
| `--help`, `-h` | Print help for the current command or subcommand |
| `--version`, `-V` | Print the surge-server version |

**Related:** [Configuration](/integration/configuration), [Service Authentication](/features/service-authentication)

## `surge-server oauth` — OAuth authorization server

Manages the [native authorization server](/features/oauth-authorization-server)'s clients, audiences and signing keys. These are CLI actions rather than API ones because `--first-party` skips the consent screen — the privilege that must never be reachable from an unauthenticated endpoint.

### `oauth resource create`

Registers an audience: one resource server, owned by one registered service. **A `resource` parameter is valid only if it resolves to one of these**, so nothing can authorize until at least one exists.

```bash
surge-server oauth resource create \
  --uri https://dispatch.example.com/mcp \
  --service dispatch \
  --scope mcp:read --scope mcp:write \
  --describe "mcp:read=Read your Dispatch data" \
  --describe "mcp:write=Create and change your Dispatch data"
```

| Flag | Description |
|---|---|
| `--uri` | Canonical audience URI. Normalized (trailing slash stripped); no query string or fragment |
| `--service` | Name of the registered service that owns this resource server |
| `--scope` | A scope this resource defines. Repeatable. Scopes belong to resources, never to clients |
| `--describe` | `scope=human sentence`, rendered on the consent screen. Repeatable |

`oauth resource list` and `oauth resource delete <uri>` round out the group.

### `oauth client create`

```bash
# Public client — the normal case for native and MCP clients, safe because
# PKCE is mandatory.
surge-server oauth client create \
  --name "Dispatch Desktop" \
  --redirect-uri https://dispatch.example.com/oauth/callback \
  --scope mcp:read --scope mcp:write
```

| Flag | Description |
|---|---|
| `--name` | Shown on the consent screen |
| `--redirect-uri` | Exact-matched at authorize. Repeatable. `https`, or `http` on loopback. No wildcards |
| `--scope` | The maximum this client may ever be granted; narrowed further per resource |
| `--confidential` | Issue a client secret (`aeg_cs_…`), shown once |
| `--first-party` | Skip the consent screen. Only for clients you operate |
| `--client-uri`, `--logo-uri` | Optional, rendered on the consent screen |

`oauth client list` shows every live client with its registration source. `oauth client revoke <client_id>` revokes the client **and its outstanding refresh tokens** in one transaction — a client that could no longer authorize but whose tokens kept working would not be revoked in any sense a user would recognize.

### `oauth key`

```bash
surge-server oauth key list     # active plus retiring keys
surge-server oauth key rotate   # generate and activate a new key now
```

Keys rotate on their own with the background sweep; `rotate` forces it, for instance after a suspected exposure. The previous key stays published in JWKS until its retirement grace closes, so tokens signed a moment earlier keep verifying until they expire.
