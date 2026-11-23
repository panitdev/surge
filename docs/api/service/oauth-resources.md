# Register and manage OAuth resources

`POST /v1/oauth/resources` requires a bearer service token with either the `oauth_admin` or the `oauth_resource_register` grant. The two have different authority.

| | `oauth_admin` | `oauth_resource_register` (Platform) |
| --- | --- | --- |
| Default `registration_source` | `service` | `delegated` |
| Service registrations and `owner_service_id` | Yes, for any existing service | No (HTTP 403) |
| Delegated registrations | Yes | Yes. They have no owner. |
| `GET /v1/oauth/resources` | Every registration | Only delegated registrations it created |
| `GET /v1/oauth/resources/{registration_id or uri}` | Any registration, including legacy ones with an unknown registrar | Only its own. Any other returns HTTP 404. |
| `PATCH` / `DELETE /v1/oauth/resources/{uri}` | Any registration | Only its own. Any other returns HTTP 404. |

The registrar is always the authenticated service. It cannot be supplied in the request. Registrations with an unknown registrar, such as those that predate registrar tracking or were created with the CLI, are visible and manageable only with `oauth_admin`.

```json
{
  "resource_uri": "https://example.com/mcp",
  "scopes": ["mcp:read"],
  "scope_descriptions": {"mcp:read": "Read your data"},
  "owner_service_id": "1e39e144-4377-49ea-af2f-f49d81f2d7e2"
}
```

`scope_descriptions`, `owner_service_id` and `registration_source` (`service` or `delegated`) are optional. For an `oauth_admin` caller the source defaults to `service` and the owner to the authenticated service. A `delegated` registration has no owner, so supplying `owner_service_id` with it is rejected: HTTP 422 for an administrator, HTTP 403 for a Platform credential. Unknown fields are rejected with HTTP 422. A successful request returns HTTP 201 with the registration:

| Field | Meaning |
| --- | --- |
| `registration_id` | Immutable identity of this registration. Consents, codes and refresh tokens are bound to it. |
| `resource_uri` | The canonical URI. Clients request it, and access tokens carry it as `aud`. |
| `registration_source` | `service` for a resource owned by a registered service, `delegated` for one registered on a developer's behalf. |
| `service_id` | The owner's UUID. Only the owner can introspect tokens for this audience. `null` for a delegated registration. |
| `registrar_service_id` | The authenticated service that made the request. `null` for registrations that predate registrar tracking or were created with the CLI. |
| `scopes`, `scope_descriptions` | As supplied. |
| `allowed_cimd_client_ids` | Exact CIMD client IDs allowed to use the resource. Empty by default. |
| `dcr_enabled` | Whether dynamically registered clients can use the resource without an audience binding. `false` by default. |
| `created_at` | Creation time. |

If the same URI is registered again, the new registration gets a new `registration_id` and inherits none of the old consents, tokens or client approvals.

## Change or delete a registration

Both calls address the registration by its **canonical URI, percent-encoded as one path segment**: `/v1/oauth/resources/https%3A%2F%2Fexample.com%2Fmcp`. The URI is canonicalized as at creation, so a trailing slash makes no difference. A URI that carries a query or fragment (encoded into the segment) is refused with HTTP 422, an unencoded URI does not route (HTTP 404), and a registration ID in the path is refused with HTTP 422. The caller must hold `oauth_admin`, or `oauth_resource_register` for a registration it created; any other registration looks missing (HTTP 404).

**Precondition.** Name the registration you mean with `?registration_id=<uuid>` or `If-Match: "<uuid>"` (if both are given they must agree). If the URI now holds a different registration the call fails with HTTP 412 (`precondition_failed`) and changes nothing. It is optional for `oauth_admin` and for `PATCH`, and **required for a registrar's `DELETE`** (HTTP 422 without it), so a retried deletion can never remove a successor registered at the same URI, even after the reuse window below.

### `PATCH`

```json
{
  "scopes": ["mcp:read"],
  "scope_descriptions": {"mcp:read": "Read your data"},
  "allowed_cimd_client_ids": ["https://app.example/client.json"],
  "dcr_enabled": true
}
```

All fields are optional but at least one is required. Each field replaces the stored value. Scopes are non-empty printable tokens without spaces (not `openid`, `profile` or `offline_access`); CIMD entries are exact `https` URLs with a path and no userinfo or fragment, stored as given; `dcr_enabled` applies to delegated registrations only. The response is the updated registration. A change that alters nothing writes and audits nothing.

What a change does to existing grants (all in one transaction, serialized against issuance):

| Change | Effect |
| --- | --- |
| Description only, or adding scopes, CIMD entries or enabling DCR | Nothing. Grants are preserved. |
| Removing a scope | Saved consents lose the scope and are deleted if left empty. Every refresh family that carries it is revoked. Unredeemed codes and pending consent flows that carry it are deleted. |
| Removing a CIMD client ID, or disabling DCR | For each affected client (the removed CIMD client, or each client the new policy no longer admits): its refresh families at this registration are revoked and its consents, pending flows, codes and pending account choices are deleted. |

Revoking refresh families is what makes introspection report earlier access tokens as inactive. Access tokens already issued remain valid at resource servers that verify offline until they expire. Restoring a scope, a CIMD entry or the DCR opt-in restores nothing: the client must authorize again.

### `DELETE`

Returns HTTP 204. In one transaction it deletes the registration and with it every consent, flow, code, refresh token and client approval bound to it. Other audiences are unaffected. Retrying with the same `registration_id` after a success also returns 204 and does nothing.

**URI reservation.** Access tokens already issued for the URI verify offline until they expire, so the URI cannot be registered again until the maximum access-token lifetime (`SURGE_OAUTH_ACCESS_TTL_SECS`) plus 60 seconds of accepted clock skew has passed. `POST` for a reserved URI returns HTTP 409 (`resource_reserved`), for administrators too. The window uses the access-token lifetime configured at deletion time; lowering the lifetime later does not shorten reservations already made, but tokens issued under a longer, earlier setting are not accounted for.

### Audit

`create_oauth_resource`, `update_oauth_resource` and `delete_oauth_resource` are recorded in the same transaction as the change. The entry carries the actor (the authenticated service, or the operator for the CLI), the `registration_id`, `resource_uri`, `registration_source`, owner and registrar, and, in the detail, what changed and how many grants were ended (an update) or the `reserved_until` time (a delete).

A caller holding neither grant, or a Platform credential asking for a service registration or an owner, receives HTTP 403. An unknown owner receives HTTP 404. An already registered URI receives HTTP 409 (`resource_already_registered`) and keeps its original registration, owner, registrar and scopes, whoever asks and whichever form of the URI they use.

## Register a client

`POST /v1/oauth/clients` is open to `oauth_admin` and, with limits, to `oauth_client_register`. Unknown body fields are rejected with HTTP 422.

| Field | Meaning |
| --- | --- |
| `client_name`, `redirect_uris` | Required. |
| `client_uri`, `logo_uri`, `scopes`, `confidential` | Optional. `confidential: true` is allowed for both grants and returns `client_secret` once. |
| `first_party` | Optional, `oauth_admin` only. |
| `resources` | Optional list of resource URIs the client is approved for. Absent means no list. |

`oauth_admin` may pass any registered `resources`. The client is recorded with `registration_source` `admin` and no registrar.

`oauth_client_register` is a separate grant from `oauth_resource_register`. A holder can only create third-party clients, and `resources` is required and non-empty. Every resource must be a delegated registration that same service created. The check and the binding happen in one transaction, so a URI that is deleted and registered again by someone else cannot be bound. `first_party: true`, a missing grant, and any resource that is unknown, operator-registered, or registered by another service (including an administrator) return HTTP 403. A missing or empty `resources` returns HTTP 422. The grant does not allow listing or revoking clients.

The client is recorded with `registration_source` `platform` and `registrar_service_id` set to the authenticated service, and the response carries both, along with `audiences` (the canonical URIs bound). Consent and the connections list mark it `dynamically_registered: true`, meaning its name and logo are supplied by a developer and are untrusted, as for a dynamically registered client. Unlike dynamic clients, platform clients are not removed by the unused-client sweep (`SURGE_OAUTH_DCR_TTL_DAYS`); an administrator revokes them. (Registrar-scoped listing and revocation of its own clients are not implemented yet.)

The audit entry `create_oauth_client` records the client, `registration_source`, `registrar_service_id` and the requested `resources` for both grants.

Restricting a client to its `resources` is enforced when tokens are issued. That enforcement ships in the same release as this endpoint, so treat `resources` as the stored approval list until you deploy that release.
