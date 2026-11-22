# Surge demo

The demo has one shared Axum UI and two provider binaries:

- `common` owns the HTML, sign-up, sign-in, session cookie, and sign-out routes.
- `embedded` runs Surge in-process and defaults to `127.0.0.1:3100`.
- `served` connects to `surge-server` and defaults to `127.0.0.1:3200`.

Both modes require PostgreSQL.

## Embedded mode

Create a database, then run:

```sh
createdb surge_demo_embedded
DATABASE_URL=postgres://localhost/surge_demo_embedded \
  SURGE_PEPPER=replace-this-for-real-use \
  cargo run -p surge-demo-embedded
```

Open <http://127.0.0.1:3100>.

## Served mode

Start the auth server and create a service token with the grants used by the demo:

```sh
createdb surge_demo_served
export DATABASE_URL=postgres://localhost/surge_demo_served
export SURGE_PEPPER=replace-this-for-real-use
cargo run -p surge-server -- svc create \
  --name demo \
  --grant introspect direct_auth revoke
cargo run -p surge-server -- serve
```

In another shell, copy the token printed by `svc create` and run:

```sh
SURGE_URL=http://127.0.0.1:3000 \
  SURGE_SERVICE_TOKEN=aeg_svc_REPLACE_ME \
  cargo run -p surge-demo-served
```

Open <http://127.0.0.1:3200>.

The demo uses a host-only, HTTP-only, `SameSite=Lax` cookie so it works on localhost.
Production deployments should add `Secure`, CSRF protection, TLS, and explicit cookie-domain policy.

## First-party browser app

Run `bun demo/browser/server.ts` to serve the client-side picker at
`http://127.0.0.1:3300`. Set `SURGE_URL` to the browser-reachable Surge origin
(default `http://127.0.0.1:3000`). Enable multi-account sessions and configure the hosted auth UI
on that deployment, allow the demo origin for session CORS, and register
it with `surge-server svc create --name browser-demo --grant account_list --origin http://127.0.0.1:3300`.
Use identities already registered in that deployment.

Open the demo in two tabs, add an account, and choose a different identity in
each. Refresh either tab or paste its address into a new tab. “Make default”
changes which identity opens at the root URL. Signing out of this account
uses the selector from the tab URL.

To try OAuth from a pinned tab, register a public OAuth client with redirect
URI `http://127.0.0.1:3300/oauth/callback`. Supply its `OAUTH_CLIENT_ID`,
`OAUTH_RESOURCE` and optional space-delimited `OAUTH_SCOPE` when starting the
demo. “Authorize application” sends the route's account selector on a
top-level authorization request and exchanges the resulting code using PKCE.
The client's first-party consent setting is configured independently.

The Chromium integration test in `browser/tests/oauth.mjs` creates two users
on a disposable open-registration deployment and checks the third-party
callback and token. Install Playwright and Chromium, then run
`node demo/browser/tests/oauth.mjs` with `SURGE_URL`, `SURGE_AUTH_UI_ORIGIN`,
`OAUTH_CLIENT_ID`, `OAUTH_RESOURCE` and `OAUTH_REDIRECT_URI`. Register that
exact callback on a separate host for a public client requiring consent.
`PLAYWRIGHT_MODULE` and `CHROMIUM_PATH` can select an existing installation.

For the two-tab rollout test, run `node demo/browser/tests/two-tabs.mjs` with
the same OAuth and Chromium settings and an `APP_API_URL` pointing to the
embedded browser API. Repeat with the remote proxy as `APP_API_URL`, keeping
`SURGE_URL` pointed at the issuer. The test creates disposable accounts,
changes their passwords, completes a pending consent after changing the
default in another tab, and checks a removed pin while the default is live.
