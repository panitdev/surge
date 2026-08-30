---
description: Sign users in through an external provider (email, OAuth) and manage the links between provider accounts and Surge identities.
---

# Identity Links (Service API)

`POST /v1/authenticate/link` — sign in through a provider, creating the identity on first sight

`POST /v1/identities/{id}/links` — attach a provider account to an identity, or confirm one

`GET /v1/identities/{id}/links` — list an identity's linked accounts

`DELETE /v1/identities/{id}/links` — detach one

## What a link is

A link binds a subject in some external namespace to a Surge identity:

| `provider` | `subject` |
|---|---|
| `email` | `alice@example.com` |
| `google` | `117482910294857` |
| `github` | `1423097` |

Both columns are opaque — Surge stores and matches them but never parses either, which is why one mechanism covers email, OAuth, SAML, or anything you invent. A single identity may hold many links; a given `(provider, subject)` pair belongs to exactly one identity.

## Surge does not verify anything itself

Surge sends no mail and performs no OAuth code exchange. It cannot tell whether the person in front of your service controls the subject being claimed, so **your service establishes proof of control and Surge trusts it to have done so.** That trust is what the `external_auth` grant represents.

This is the standard shape for a delegated-auth backend, but it means the security boundary lives in your callback handler. Give `external_auth` only to the service that terminates the provider handshake.

## Sign in

`POST /v1/authenticate/link` — requires `external_auth`.

An OAuth callback doesn't know whether it is looking at a new user or a returning one, so this endpoint doesn't ask. It resolves the link; if nothing matches, it creates an identity from `seed` and links it. `seed` is ignored entirely when the link already exists, so you can pass the same value on every callback.

```bash
curl -X POST http://localhost:3000/v1/authenticate/link \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "subject": "117482910294857",
    "seed": {"username": "alice", "display_name": "Alice"}
  }'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `provider` | `string` | Yes | 1–255 bytes |
| `subject` | `string` | Yes | 1–255 bytes |
| `seed.username` | `string` | Yes | Used only when the link is new; must be unique |
| `seed.display_name` | `string` | Yes | Used only when the link is new |

**Response — `200 OK`** for a returning user, **`201 Created`** when the identity was created. The body carries `created` as well, so you can branch on either.

```json
{
  "session": { "id": "018f9a1b-...", "identity": { "username": "alice", ... } },
  "token": "aeg_s_1a2b3c4d5e6f7g8h9i0j",
  "created": true
}
```

Links created this way are verified by construction — reaching this endpoint is the assertion that you checked.

Two concurrent callbacks for the same new subject produce one identity, not two: one wins the insert and the other resolves to it. A `seed.username` that is already taken returns `username_taken`, and the caller picks another.

## Attach or confirm a link

`POST /v1/identities/{id}/links` — requires `external_link`.

For a user who already has an account and is adding a provider to it.

```bash
curl -X POST http://localhost:3000/v1/identities/018f9a1b-.../links \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"provider": "email", "subject": "alice@example.com", "verified": false}'
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `provider` | `string` | Yes | 1–255 bytes |
| `subject` | `string` | Yes | 1–255 bytes |
| `verified` | `boolean` | No | Defaults to `false` |

**Only a verified link can authenticate.** An unverified link is a pending claim: it appears in listings, but `POST /v1/authenticate/link` will not resolve it and it cannot be used to recover an account. Re-posting the same link with `verified: true` is how a mailed confirmation token completes the flow — the call is idempotent and only refreshes the flag.

Posting a subject already linked to a *different* identity fails with a validation error rather than moving it. Silently reassigning would hand the second identity a working login for the first.

**Response — `201 Created`:**

```json
{
  "provider": "email",
  "subject": "alice@example.com",
  "identity_id": "018f9a1b-...",
  "verified_at": null,
  "linked_at": "2026-07-08T12:00:00Z"
}
```

## List links

`GET /v1/identities/{id}/links` — requires `identity_read`. Returns an array of link objects ordered by `linked_at`, oldest first. This is what an account-settings page renders.

## Detach a link

`DELETE /v1/identities/{id}/links` — requires `external_link`. Takes `provider` and `subject` in the body and returns `204 No Content`. Scoped to the identity in the path: a link belonging to someone else returns `not_found` rather than being removed.

Surge does not stop you from removing an identity's last sign-in method. If your deployment requires one to remain, check before calling.

## Account recovery

Recovery is not an endpoint — it is a lookup plus whatever reset you implement. A verified `("email", address)` link resolves to the identity that proved control of that address, including identities that also carry a password. That is the whole point of modelling email as a link rather than as a column on the identity: password users and OAuth users recover through the same mechanism.

Surge issues no reset tokens and sends no mail; that half is yours.

**Related:** [Grants](/reference/grants), [Authenticate](/api/service/authenticate), [Register](/api/service/register)
