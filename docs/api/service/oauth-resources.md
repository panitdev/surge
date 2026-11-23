# Register an OAuth resource

`POST /v1/oauth/resources` requires a bearer service token with the `oauth_admin` grant. Admins can assign an audience to any existing service. A platform registering audiences for developers should verify control of the target service before making this request.

```json
{
  "resource_uri": "https://example.com/mcp",
  "scopes": ["mcp:read"],
  "scope_descriptions": {"mcp:read": "Read your data"},
  "owner_service_id": "1e39e144-4377-49ea-af2f-f49d81f2d7e2"
}
```

Both `scope_descriptions` and `owner_service_id` are optional. The owner defaults to the authenticated service. A successful request returns HTTP 201 with the registration:

| Field | Meaning |
| --- | --- |
| `registration_id` | Immutable identity of this registration. Consents, codes and refresh tokens are bound to it. |
| `resource_uri` | The canonical URI. Clients request it, and access tokens carry it as `aud`. |
| `registration_source` | `service` for a resource owned by a registered service. |
| `service_id` | The owner's UUID. Only the owner can introspect tokens for this audience. |
| `registrar_service_id` | The authenticated service that made the request. `null` for registrations that predate registrar tracking or were created with the CLI. |
| `scopes`, `scope_descriptions` | As supplied. |
| `allowed_cimd_client_ids` | Exact CIMD client IDs allowed to use the resource. Empty by default. |
| `dcr_enabled` | Whether dynamically registered clients can use the resource without an audience binding. `false` by default. |
| `created_at` | Creation time. |

Deleting a registration removes every grant bound to it. If the same URI is registered again, the new registration gets a new `registration_id` and inherits none of the old consents, tokens or client approvals.

A caller missing `oauth_admin` receives HTTP 403. An unknown owner receives HTTP 404. An already registered URI receives HTTP 409 (`resource_already_registered`) and keeps its original owner and scopes.
