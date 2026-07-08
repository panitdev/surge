---
description: Password hashing with Argon2id, secret pepper, validation rules, and timing-safe verification.
---

# Password Authentication

Surge handles password hashing and verification using Argon2id with a site-wide secret pepper. It includes built-in password validation and timing-safe verification against unknown usernames.

## Password validation

Every password Surge accepts goes through a validation pipeline. Invalid passwords are rejected before they ever touch the hasher.

### Length

Passwords must be between **8 and 256 characters**. Shorter passwords are rejected with a `PasswordError::Length` error. The 256-character upper bound prevents DoS via oversized inputs while accommodating passphrase-based strategies.

### NFKC normalization

Passwords are normalized using **Unicode NFKC** (`unicode_normalization` crate) before hashing. This ensures that visually identical Unicode forms produce the same hash — a password typed with composed characters matches the same password typed with decomposed characters.

```rust
// Surge normalizes internally — you don't need to do this yourself
let normalized = password.nfkc();  // NFC → NFKC
```

### Common password blacklist

A built-in blacklist of **20 common passwords** (e.g., `password`, `12345678`, `qwerty123`) is checked at validation time. If the password matches, it's rejected with `PasswordError::Common`. This isn't a replacement for user education, but it stops the most obvious choices.

### The `Password` type

Passwords are wrapped in `Password(SecretString)`. The `Debug` implementation redacts the value — you'll never accidentally log a password in plaintext.

```rust
use surge_engine::types::Password;

let password = Password::new("correct-horse-battery-staple".into())?;
// Debug output: Password(***)
```

## Hashing

### Argon2id

Surge uses **Argon2id** for password hashing, combining the side-channel resistance of Argon2i with the GPU-resistance of Argon2d. It's the OWASP-recommended default for general-purpose password hashing.

Hash parameters are set to balanced defaults suitable for server-side hashing. The hash output includes the algorithm version, allowing future upgrades without breaking existing credentials.

### Secret pepper

A **site-wide secret pepper** is appended to the password before hashing. This is configured via the `SURGE_PEPPER` environment variable:

```bash
export SURGE_PEPPER=$(openssl rand -hex 32)
```

The pepper is **not a salt** — it's the same for every password in the system. Its purpose is to protect against database-only compromise: even if an attacker exfiltrates the password hashes, they cannot crack them without the pepper. The pepper lives in your environment or secret manager, never in the database.

| Mechanism | Per-user? | Stored in DB? | Protects against |
|---|---|---|---|
| Salt (Argon2id built-in) | Yes | Yes (in hash) | Rainbow tables, identical passwords |
| Pepper (`SURGE_PEPPER`) | No | No | Database-only compromise |

Peppers are versioned internally, so rotating `SURGE_PEPPER` doesn't invalidate credentials hashed under a previous pepper.

## Verification

### Timing-safe comparison

Password verification uses constant-time comparison. The time it takes to reject an incorrect password does not reveal how many bytes matched — preventing timing side-channel attacks.

### Unknown username handling

When a login attempt uses a username that doesn't exist, Surge performs a **dummy hash** against a synthetic comparison rather than returning immediately. This makes it impossible for an attacker to determine whether a username exists by measuring response times.

```rust
// Internally (you don't call this directly):
// For a known user: hash(pw + pepper) == stored_hash
// For an unknown user: dummy comparison takes same wall-clock time
```

## Password credential model

Password hashes are stored in the `credential_password` table with a version field. Each hash row records:

| Column | Purpose |
|---|---|
| `identity_id` | The owning identity |
| `hash` | Argon2id hash output (includes salt, params, version) |
| `version` | Algorithm version for future upgrades |
| `created_at` | When this hash was set |

This versioned design means Surge can introduce new hashing algorithms (Argon2id v2, or a successor algorithm) without breaking existing credentials. Old hashes verify at their original version; new passwords use the latest version.

## Setting and changing passwords

Passwords are set through the registration flow or via direct API by a service with `direct_auth` grant:

```bash
# Set a password during browser registration (CSRF token in body)
curl -X POST http://localhost:3000/v1/flows/{flow_id}/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "correct-horse-battery-staple", "display_name": "Alice", "csrf_token": "..."}'
```

Service-initiated password changes are handled through the engine directly by privileged services — see [Service Authentication](/features/service-authentication) for grant requirements.

**Related:** [Identity Management](/features/identity-management), [Configuration](/integration/configuration)
