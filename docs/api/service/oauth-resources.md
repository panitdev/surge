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

`scope_descriptions`, `owner_service_id` and `registration_source` (`service` or `delegated`) are optional. For an `oauth_admin` caller the source defaults to `service` and the owner to the authenticated service. A `delegated` registration has no owner, so supplying `owner_service_id` with it is rejected: HTTP 400 for an administrator, HTTP 403 for a Platform credential. Unknown fields are rejected. A successful request returns HTTP 201 with the registration:

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

## Register a client as a Platform

`POST /v1/oauth/clients` also accepts a service holding `oauth_client_register`, a separate grant from `oauth_resource_register`. It can only create third-party clients, and each request must list `audiences`, every one a delegated registration that same service created. `first_party: true` and any other audience return HTTP 403. This grant does not allow listing or revoking clients.
