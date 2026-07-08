---
description: Start a login flow — returns a redirect to the auth UI or JSON with flow ID and CSRF token.
---

# Flow Init

`GET /v1/login`

Starts a new login flow. Behaves differently depending on the `Accept` header and the server's `allow_inline` configuration.

## Two response modes

`/v1/login` inspects the request's `Accept` header to choose between two response modes. The behavior is the same in both — a new flow is created — but the delivery mechanism differs.

### Redirect mode (default)

Redirect mode is the default, and the only mode available unless the deployment has `allow_inline` enabled. Surge responds with a `302 Found` redirect to the configured auth UI:

```bash
curl -v "http://localhost:3000/v1/login?return_to=https://app.example.com/dashboard"
```

```
HTTP/1.1 302 Found
Location: https://auth.example.com/login?flow=aeg_f_3k7m9p2q5r8t1v4w6x
Set-Cookie: ...
```

The `Location` URL includes the flow ID (prefixed `aeg_f_`) as the `flow` query param. `return_to` is not repeated in the redirect — it's tracked server-side against the flow and applied by the completion endpoints. The auth UI reads the `flow` param and uses it to complete the flow after the user submits credentials. Redirect mode is the integration pattern when you run Surge as a standalone server with its own auth UI at `SURGE_AUTH_UI_ORIGIN`.

### Inline mode (Accept: application/json)

When `allow_inline` is enabled on the server **and** the request includes `Accept: application/json`, Surge returns the flow data directly as JSON — no redirect:

```bash
curl "http://localhost:3000/v1/login?return_to=https://app.example.com/dashboard" \
  -H "Accept: application/json"
```

```json
{
  "flow_id": "aeg_f_3k7m9p2q5r8t1v4w6x",
  "csrf_token": "aopX8kLm3...",
  "registration_mode": "open"
}
```

| Field | Type | Description |
|---|---|---|
| `flow_id` | `string` | The flow ID, prefixed `aeg_f_`. Pass this as a path parameter to `/v1/flows/{id}/password` and `/v1/flows/{id}/register`. |
| `csrf_token` | `string` | A one-time CSRF token scoped to this flow. Include it as the `csrf_token` field in the request body on all flow submissions. |
| `registration_mode` | `string` | One of `open`, `invite`, or `closed`. Use this to decide whether to show a registration link in your UI. |

Inline mode is for SPAs and JavaScript-driven frontends that manage their own login forms. It requires the operator to explicitly opt in via server config (`allow_inline`) — plain browser navigation without that flag always gets the redirect regardless of `Accept`. See [Running as Server](/integration/running-as-server) for the served+inline combination.

## Query parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `return_to` | `string` | Yes | An absolute URL to redirect to after successful login. Surge validates the URL's origin against the return origins registered for services via `svc create --origin` (see [Reference: CLI](/reference/cli)) to prevent open redirect attacks. |

The `return_to` is passed through the flow and used by the completion endpoints to set the post-login redirect target.

## Registration mode in the response

The `registration_mode` field tells the frontend whether the current deployment allows self-service registration. This lets the UI conditionally show or hide a register link without a separate API call:

| Mode | Frontend behavior |
|---|---|
| `open` | Show the register link — anyone can create an account |
| `invite` | Show the register link only if the user has an invite code (prompted during registration) |
| `closed` | Hide the register link entirely — only existing users can log in |

The mode is set via the `SURGE_REGISTRATION` environment variable. See [Registration Modes](/integration/registration-modes) for details on each mode.

## Errors

| Status | Type | Condition |
|---|---|---|
| `422` | `validation_error` | `return_to` is missing, isn't a valid absolute URL, or its origin isn't registered for any service |

```json
{ "error": "validation_error", "message": "invalid URL" }
```

Surge validates `return_to`'s origin against the set of registered return origins to prevent open redirect attacks — arbitrary external URLs are rejected.

### CORS behavior

`GET /v1/login` is in the **credential-entry** CORS zone with a narrow origin policy. Cross-origin requests from origins not in the credential-entry allowlist will fail with a CORS error. For inline mode from a different origin, make sure the frontend origin is configured in `SURGE_SESSION_CORS_ORIGINS`.

**Related:** [Login Flows](/features/login-flows), [Flow Complete](/api/browser/flow-complete)
