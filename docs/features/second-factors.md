---
description: TOTP and passphrase factors — enrollment, the mandatory TOTP login step, standalone passphrase login, step-up authorization, and password recovery.
---

# Second Factors: TOTP and Passphrase

Beyond the password, Surge supports two additional factors:

- **TOTP** (RFC 6238) — an *enhancing second factor* for the password. Optional to enroll, but once a user has a confirmed TOTP, login requires the password **then** the TOTP code.
- **Passphrase** — a server-generated 6-word [Diceware](https://www.eff.org/dice) passphrase (~77 bits of entropy). It is the *standalone strongest factor and recovery anchor*: it can log a user in on its own, bypassing the password and TOTP, and it is the credential that authorizes sensitive account changes.

Both are entirely optional per user. A server-wide [`SURGE_FACTOR_POLICY`](/deployment/environment#factor-policy) expresses a *soft* recommendation for which factors users should have — it never blocks login; it is surfaced to the frontend as a compliance block.

## The `policy` block

Login-success, registration, and `whoami` responses carry a `policy` object so the frontend can prompt for enrollment:

```json
{
  "required":  { "totp": true,  "passphrase": false },
  "has":       { "totp": false, "passphrase": false },
  "compliant": false
}
```

`required` reflects `SURGE_FACTOR_POLICY`; `has` reflects the user's actual enrollment (TOTP counts only once confirmed); `compliant` is true when every required factor is enrolled.

## Login flows

The password step no longer always issues a session:

```
POST /v1/flows/{id}/password
  ├─ user has no TOTP  → session issued (cookie set), { return_to, session, policy }
  └─ user has TOTP     → { status: "totp_required", return_to }   (no cookie)
                          → POST /v1/flows/{id}/totp { code, csrf_token } → session issued
```

Two alternative entry points from a fresh flow:

- `POST /v1/flows/{id}/passphrase` — `{ username, passphrase, csrf_token }`. Standalone login that bypasses password and TOTP.
- `POST /v1/flows/{id}/recover` — `{ username, passphrase, new_password, csrf_token }`. Unauthenticated password recovery authorized by the passphrase (for when both the password and the TOTP device are lost).

## Managing factors (authenticated)

These endpoints require a valid `surge_session` and the `X-Surge-CSRF: 1` header on mutations.

| Method & path | Purpose |
|---|---|
| `GET /v1/factors` | Read `{ policy }` for the current user. |
| `POST /v1/factors/totp/enroll` | Begin enrollment → `{ otpauth_uri, secret }`. |
| `POST /v1/factors/totp/confirm` | Confirm with one code → activates TOTP. |
| `DELETE /v1/factors/totp` | Remove TOTP. |
| `POST /v1/factors/passphrase` | Begin enrollment → returns the passphrase **once**. Rerollable before confirm. |
| `POST /v1/factors/passphrase/confirm` | Confirm enrollment → `{ passphrase }`. Activates the passphrase. |
| `DELETE /v1/factors/passphrase` | Remove the passphrase. |
| `POST /v1/account/password` | Change the password. |

## Step-up authorization

Every sensitive action above (password change, TOTP enroll/remove, passphrase enroll/remove) requires a **step-up proof** supplied per request as `step_up`:

- If the user **has a passphrase**, `step_up` must be the passphrase.
- Otherwise it falls back to the **current password**.

This is stateless — there is no elevated session to track. The frontend knows which to prompt from `GET /v1/factors` (`has.passphrase`). Confirming a pending enrollment (TOTP or passphrase) needs only the session, since the enrollment itself was already step-up-gated.

## Security notes

- **TOTP secrets are encrypted at rest** (XChaCha20-Poly1305) under a key derived via HKDF-SHA256 from the versioned pepper — a database leak alone does not expose them. Key rotation follows [pepper rotation](/deployment/environment#pepper).
- **Replay is prevented** by recording the last accepted TOTP step; a code cannot be reused within its ±1-step validity window.
- **Passphrases are one-way hashed** with the same peppered-Argon2 machinery as passwords, and revealed only once at generation.
- **Rate limiting** on the TOTP/passphrase/recover steps is keyed per-identity, not just per-IP — the per-flow attempt cap alone would be bypassable by opening fresh flows.
- Second-factor use is recorded in the [audit log](/features/audit-logging); the session's `authenticated_via` stays `password` to keep the introspection contract append-only.
