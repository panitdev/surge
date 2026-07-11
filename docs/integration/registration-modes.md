---
description: Open, invite-only, and closed registration modes in Surge.
---

# Registration Modes

Surge supports three registration modes that control how new user accounts can be created.

## Overview

Surge supports three registration modes that control how new identities are created. The mode is set via the `SURGE_REGISTRATION` environment variable and applies globally to all browser and service endpoints.

```bash
export SURGE_REGISTRATION=open    # default
export SURGE_REGISTRATION=invite
export SURGE_REGISTRATION=closed
```

The mode parsed at startup:

```rust
match value.as_str() {
    "invite" => RegistrationMode::Invite,
    "closed" => RegistrationMode::Closed,
    _        => RegistrationMode::Open,
}
```

Any value other than `"invite"` or `"closed"` — including unset, typos, and empty strings — defaults to `Open`.

## Open

Anyone can register through the login flow without any prior authorization.

**When to use:** public-facing applications, consumer SaaS, or any scenario where self-service sign-up is desired.

### Browser flow

The `GET /v1/login` response (both redirect and inline modes) includes `"registration_mode": "open"`. The frontend should render a registration option alongside the login form.

```json
{
  "flow_id": "aeg_f_3k7m9p2q5r8t1v4w6x",
  "csrf_token": "aeg_csrf_...",
  "registration_mode": "open"
}
```

Registration within a flow:

```bash
curl -X POST http://localhost:3000/v1/flows/aeg_f_.../register \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "correct-horse-battery-staple", "display_name": "Bob", "csrf_token": "aeg_csrf_..."}'
```

On success, an identity is created and a session is issued immediately.

### Service API

Services with `direct_auth` grant can create identities directly via the service API regardless of registration mode, but in `open` mode the browser flow also works.

## Invite

**Not yet implemented.** Setting `SURGE_REGISTRATION=invite` is accepted at startup, but the browser registration endpoint currently rejects it: attempting to register returns an error stating invite-based registration is not yet implemented. There is no invite-code creation surface (CLI or API) yet.

If you need controlled sign-up today, use [Closed](#closed) mode and provision identities through the service API.

## Closed

Registration is disabled entirely through the browser login flow. Identities are created only via the service API (`direct_auth` or `identity_write` grants).

**When to use:** enterprise deployments where users are provisioned by an external system (HRIS, IdP, admin tooling), or when all user creation is done out-of-band.

### Browser flow

When `SURGE_REGISTRATION=closed`, the `GET /v1/login` response returns `"registration_mode": "closed"`. The frontend should render only a login form — no registration option, no invite-code prompt.

```json
{
  "flow_id": "aeg_f_...",
  "csrf_token": "aeg_csrf_...",
  "registration_mode": "closed"
}
```

Attempting to call `POST /v1/flows/{id}/register` when registration is closed returns:

```
HTTP/1.1 403 Forbidden

{
  "error": "registration_disabled",
  "message": "Registration is currently disabled."
}
```

### Service API

The service API remains the only path for identity creation:

```bash
curl -X POST http://localhost:3000/v2/register \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "correct-horse-battery-staple", "display_name": "Bob"}'
```

## Migration between modes

Switching registration modes is safe and immediate — it doesn't affect existing identities or sessions. The change only impacts how new identities are created:

```bash
# Switch from open to invite — existing users are unaffected
export SURGE_REGISTRATION=invite

# Switch from closed to open — new registrations are immediately available
export SURGE_REGISTRATION=open
```

After restarting (or reloading config), the new mode takes effect. No database migration is needed.

Note: invite codes aren't creatable yet (see [Invite](#invite)), so there's nothing to migrate around for `invite` mode today.

## How modes affect the login flow UI

The flow-init response always includes `registration_mode`, which tells the frontend what to display:

| Mode | Flow init value | Frontend shows |
|---|---|---|
| `open` | `"registration_mode": "open"` | Login form + "Sign up" link |
| `invite` | `"registration_mode": "invite"` | Login form + gated "Sign up (invite required)" — mode is accepted, but registration isn't yet functional (see [Invite](#invite)) |
| `closed` | `"registration_mode": "closed"` | Login form only |

The frontend is responsible for reading this value and rendering the appropriate UI. Surge doesn't serve UI — it only exposes the data that tells the UI what to render.
