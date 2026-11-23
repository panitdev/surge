# Register an OAuth resource

`POST /v1/oauth/resources` requires a bearer service token with either the `oauth_admin` or the `oauth_resource_register` grant. The two have different authority.

| | `oauth_admin` | `oauth_resource_register` (Platform) |
| --- | --- | --- |
| Default `registration_source` | `service` | `delegated` |
| Service registrations and `owner_service_id` | Yes, for any existing service | No (HTTP 403) |
| Delegated registrations | Yes | Yes. They have no owner. |
| `GET /v1/oauth/resources` | Every registration | Only delegated registrations it created |
| `GET /v1/oauth/resources/{registration_id}` | Any registration, including legacy ones with an unknown registrar | Only its own. Any other returns HTTP 404. |

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

Deleting a registration removes every grant bound to it. If the same URI is registered again, the new registration gets a new `registration_id` and inherits none of the old consents, tokens or client approvals.

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

The client is recorded with `registration_source` `platform` and `registrar_service_id` set to the authenticated service, and the response carries both, along with `audiences` (the canonical URIs bound). Consent and the connections list mark it `dynamically_registered: true`, meaning its name and logo are supplied by a developer and are untrusted, as for a dynamically registered client. Unlike dynamic clients, platform clients are not removed by the unused-client sweep (`SURGE_OAUTH_DCR_TTL_DAYS`); the registrar manages their lifecycle.

The audit entry `create_oauth_client` records the client, `registration_source`, `registrar_service_id` and the requested `resources` for both grants.

Restricting a client to its `resources` is enforced when tokens are issued. That enforcement ships in the same release as this endpoint, so treat `resources` as the stored approval list until you deploy that release.
