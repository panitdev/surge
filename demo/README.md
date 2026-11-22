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
