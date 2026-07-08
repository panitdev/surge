---
description: User identity model, profile management, account states, and username rules.
---

# Identity Management

Surge maintains a user identity store with profile fields, account state (active/disabled), and username validation rules.

## Identity model

Each user in Surge is represented by an identity record:

| Field | Type | Description |
|---|---|---|
| `id` | `IdentityId` (UUID v7) | Time-sortable unique identifier |
| `username` | `Username` | Unique, validated username |
| `display_name` | `String` | Human-readable name (optional) |
| `avatar_url` | `String` | URL to avatar image (optional) |
| `state` | `IdentityState` | `Active` or `Disabled` |

Identities use **UUID v7**, which embeds a timestamp in the UUID. This gives you time-sortable IDs that are also globally unique — useful for pagination and ordering without a separate `created_at` column.

## Username rules

The `Username` type enforces validation at construction time via `Username::new()`:

| Rule | Description |
|---|---|
| Length | 3–32 characters |
| Character set | Lowercase letters, digits, and hyphens only (uppercase input is folded to lowercase) |
| Format | Cannot start or end with a hyphen, and cannot contain consecutive hyphens |
| Reserved names | A fixed list of operational names (`admin`, `root`, `support`, etc.) is rejected |
| Uniqueness | Checked at the database level |

```rust
use surge_engine::identity::Username;

// Valid usernames
Username::new("alice")?;        // plain alpha
Username::new("user-42")?;      // with digits and hyphen

// Invalid — rejected at construction
Username::new("ab")?;           // Error: too short (min 3)
Username::new("-user")?;        // Error: starts with hyphen
Username::new("al--ice")?;      // Error: consecutive hyphens
Username::new("admin")?;        // Error: reserved name
```

Uppercase input is not rejected — it's folded to lowercase instead (`Username::new("Alice")` succeeds and stores `"alice"`). A short list of reserved names (`admin`, `root`, `support`, `webmaster`, and similar operational/support addresses) is also rejected regardless of case or hyphenation.

## Creating identities

Identities are created through the registration flow (see [Login Flows](/features/login-flows)) or by a service with the `direct_auth` grant:

```bash
# Service-initiated identity creation
curl -X POST http://localhost:3000/v1/register \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "correct-horse-battery-staple"}'
```

Registration flows handle CSRF protection and rate limiting automatically; the direct API path does not, so it should only be exposed to trusted internal services.

## Looking up identities

### By ID

```bash
curl http://localhost:3000/v1/identities/018f9a1b-... \
  -H "Authorization: Bearer aeg_svc_..."
```

Requires `identity_read` grant. Returns the full identity record including state.

### By username

```bash
curl "http://localhost:3000/v1/identities?username=alice" \
  -H "Authorization: Bearer aeg_svc_..."
```

Also requires `identity_read`. Returns the matching identity or a not-found error.

## Profile updates

The display name and avatar URL can be updated with a PATCH request. Requires `identity_write` grant:

```bash
curl -X PATCH http://localhost:3000/v1/identities/018f9a1b-.../profile \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice J.", "avatar_url": "https://cdn.example.com/alice.png"}'
```

Only the fields you include are updated — omit a field to leave it unchanged. The username cannot be changed via this endpoint.

## Account states

Identities have two states:

| State | Meaning |
|---|---|
| `Active` | Normal state — can authenticate, holds valid sessions |
| `Disabled` | Cannot authenticate; existing sessions are rejected at verification |

Disabling and re-enabling accounts is **CLI-only** — there is no HTTP endpoint for it, on either the browser or service API.

### Disabling an account

```bash
cargo run -p surge-server -- identity disable alice
```

This transitions the identity to `Disabled` state and immediately revokes all of its existing sessions.

### Re-enabling an account

```bash
cargo run -p surge-server -- identity enable alice
```

Returns the identity to `Active`. Sessions issued before the disable are gone (they were revoked); the user needs to log in again.

## Deletion policy

Surge does not support hard deletion of identities. Instead, disable the account via the CLI — this is a **soft-disable** that preserves the identity record and its relationships (audit log entries, past sessions, etc.) while preventing the account from being used. A disabled identity can always be re-enabled.

**Related:** [Password Authentication](/features/password-authentication), [Login Flows](/features/login-flows)
