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

Both `scope_descriptions` and `owner_service_id` are optional. The owner defaults to the authenticated service. A successful request returns HTTP 201 with the canonical resource URI, the owner's UUID in `service_id`, scopes, scope descriptions, and creation time.

A caller missing `oauth_admin` receives HTTP 403. An unknown owner receives HTTP 404. An already registered URI receives HTTP 409 (`resource_already_registered`) and keeps its original owner and scopes.
