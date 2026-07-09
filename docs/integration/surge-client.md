---
description: Using the @panit/surge-client browser package to integrate Surge authentication into frontend applications.
---

# Surge Client (Browser)

`@panit/surge-client` is the official browser package for the Surge authentication API. It covers the full browser-facing v1 surface — login flows (init, inspect, password, register) and session management (whoami, logout) — all using cookie-based sessions with `credentials: "include"`.

The service API (`Authorization: Bearer aeg_svc_...` endpoints) is intentionally not included. Service tokens must never be shipped to a browser.

## Install

```bash
bunx jsr add @panit/surge-client
# or
npx jsr add @panit/surge-client
```

## Setup

Import the client and point it at your Surge server:

```ts
import { SurgeClient, SurgeError } from "@panit/surge-client";

const surge = new SurgeClient({
  baseUrl: "https://auth.example.com",
});
```

Every request uses `credentials: "include"`, so the browser sends and stores the `surge_session` cookie automatically. For cross-origin deployments, the frontend's origin must be listed in the server's `SURGE_SESSION_CORS_ORIGINS` (session endpoints) and inline flow init requires `allow_inline` on the server.

## Redirect-mode login

The simplest login flow — navigate the browser to Surge's login endpoint and let Surge handle the redirect to the auth UI:

```ts
window.location.assign(
  surge.loginUrl("https://app.example.com/dashboard"),
);
```

Surge redirects to the auth UI, and after the user authenticates, it redirects back to the provided `return_to` URL. The return-to origin must be registered on the server.

## Inline-mode login (SPAs)

For single-page applications, use inline mode to drive login without full-page navigations. Requires `allow_inline` on the server.

```ts
import { SurgeClient, SurgeError } from "@panit/surge-client";

const surge = new SurgeClient({ baseUrl: "https://auth.example.com" });

// 1. Initiate a login flow
const flow = await surge.initLoginFlow("https://app.example.com/dashboard");
// → { flow_id: "aeg_f_...", csrf_token: "...", registration_mode: "open" }

// 2. Submit password credentials
const { return_to } = await surge.submitPassword(flow.flow_id, {
  username: "alice",
  password: "correct-horse-battery-staple",
  csrf_token: flow.csrf_token,
});

// 3. Session cookie is already set — navigate to the return URL
window.location.assign(return_to);
```

### Handling the auth UI redirect target

When the auth UI redirects back to your app with `?flow=aeg_f_...`, load the flow to inspect its state and CSRF token:

```ts
const params = new URLSearchParams(location.search);
const flowId = params.get("flow");

if (flowId) {
  const flow = await surge.getFlow(flowId);
  // flow.state === "created" → flow is still open for submissions
  // flow.state !== "created" → already completed or expired
}
```

## Registration

If the deployment allows registration (`registration_mode === "open"`), users can create an account inline:

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

Registration immediately logs the user in — the session cookie is set, and no separate password submission is needed.

## Check authentication state

```ts
const session = await surge.whoami();
// → Session | null

if (session) {
  console.log(session.identity.username);  // "alice"
  console.log(session.expires_at);          // ISO 8601
} else {
  // Not authenticated — no cookie, expired, or revoked
}
```

`whoami` returns `null` on 401 (unauthenticated) instead of throwing, since "not logged in" is an expected state in most apps.

## Logout

```ts
await surge.logout();  // revokes session, clears cookie
```

Logout is idempotent — it succeeds whether or not a valid session was present.

## Error handling

Every non-2xx response throws a `SurgeError` with the server's stable machine-readable `code`. The most common codes:

| Code | Meaning |
|---|---|
| `invalid_credentials` | Wrong username or password — show a generic message |
| `rate_limited` | Back off — check `e.retryAfter` for seconds |
| `invalid_token` | Flow expired or already completed — restart login |
| `unexpected_response` | Expected inline JSON but got a redirect — check `allow_inline` |

```ts
try {
  await surge.submitPassword(flowId, body);
} catch (e) {
  if (e instanceof SurgeError) {
    switch (e.code) {
      case "invalid_credentials":
        // show generic "wrong username or password"
        break;
      case "rate_limited":
        // wait e.retryAfter seconds before retrying
        break;
      case "invalid_token":
        // flow expired — restart login
        break;
    }
    if (e.isRetryable) {
      // rate_limited / unavailable / timeout — safe to retry with backoff
    }
  }
}
```

## Development

```bash
bun install
bun test          # unit tests (mocked fetch)
bun run build     # emits dist/ (ESM + .d.ts)
```

### TypeScript

The package is written in TypeScript and ships its own `.d.ts` declarations. All response shapes are exported as types:

```ts
import type {
  Flow, FlowInit, FlowResult,
  Session, Identity,
  PasswordSubmit, RegisterSubmit,
  SurgeErrorCode,
} from "@panit/surge-client";
```
