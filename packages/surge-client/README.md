# @panitdev/surge-client

Browser client for the [Surge](https://docs.surge.panit.dev) authentication API. Covers the full browser-facing v1 surface: login flows (init, inspect, password, register) and session management (whoami, logout).

The service API (`Authorization: Bearer aeg_svc_...` endpoints) is intentionally not included — service tokens must never be shipped to a browser.

## Install

```bash
bun add @panitdev/surge-client
```

## Usage

```ts
import { SurgeClient, SurgeError } from "@panitdev/surge-client";

const surge = new SurgeClient({ baseUrl: "https://auth.example.com" });
```

All requests use `credentials: "include"` so the browser sends and stores the `surge_session` cookie. For cross-origin calls, your frontend's origin must be in the server's `SURGE_SESSION_CORS_ORIGINS`.

### Check authentication state

```ts
const session = await surge.whoami(); // Session | null
if (session) {
  console.log(session.identity.username);
}
```

### Redirect-mode login (default)

Navigate the browser to the login endpoint; Surge redirects to the auth UI:

```ts
window.location.assign(surge.loginUrl("https://app.example.com/dashboard"));
```

### Inline-mode login (SPAs, requires `allow_inline` on the server)

```ts
const flow = await surge.initLoginFlow("https://app.example.com/dashboard");

const { return_to } = await surge.submitPassword(flow.flow_id, {
  username: "alice",
  password: "correct-horse-battery-staple",
  csrf_token: flow.csrf_token,
});

window.location.assign(return_to); // session cookie is already set
```

### Auth UI (redirect target)

An auth UI receiving `?flow=aeg_f_...` can load the flow's CSRF token and state:

```ts
const flow = await surge.getFlow(new URLSearchParams(location.search).get("flow")!);
if (flow.state !== "created") {
  // flow already completed or expired — restart login
}
```

### Registration

```ts
if (flow.registration_mode === "open") {
  const { return_to } = await surge.register(flow.flow_id, {
    username: "bob",
    password: "correct-horse-battery-staple",
    display_name: "Bob",
    csrf_token: flow.csrf_token,
  });
}
```

### Logout

```ts
await surge.logout(); // revokes the session, clears the cookie; idempotent
```

## Error handling

Every non-2xx response throws a `SurgeError` with the server's stable machine-readable `code` (plus `status`, and `retryAfter` on `rate_limited`):

```ts
try {
  await surge.submitPassword(flowId, body);
} catch (e) {
  if (e instanceof SurgeError) {
    switch (e.code) {
      case "invalid_credentials": // wrong username or password — show a generic message
      case "rate_limited":        // wait e.retryAfter seconds
      case "invalid_token":       // flow expired or already completed — restart login
    }
    if (e.isRetryable) {
      // rate_limited / unavailable / timeout — safe to retry with backoff
    }
  }
}
```

Exception: `whoami()` returns `null` on 401 instead of throwing, since "not logged in" is an expected state.

## Development

```bash
bun install
bun test          # unit tests (mocked fetch)
bun run build     # emits dist/ (ESM + .d.ts)
```
