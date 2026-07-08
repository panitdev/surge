---
description: Structured audit trail recording authentication and identity events for security and compliance.
---

# Audit Logging

Surge records a structured audit trail of authentication events, identity changes, and service actions. Each entry identifies the actor (user, service, or operator) and the action performed.

## Audit event schema

Every audit entry records **who** did **what** to **whom** and **when**:

| Field | Type | Description |
|---|---|---|
| `actor` | `AuditActor` (JSON) | Who performed the action |
| `action` | String | What happened (e.g., `verify_session`) |
| `subject` | JSON | What was affected (e.g., identity ID) |
| `detail` | JSON (optional) | Additional structured context |
| `at` | Timestamp | When the event occurred |

### Actor types

Surge distinguishes three categories of actors:

```rust
enum AuditActor {
    Identity { id: String },               // A logged-in user
    Service { id: String, name: String },  // A service token
    Operator { name: String },             // CLI / admin action
}
```

The `Operator` actor type is used for administrative actions performed via CLI — it carries the OS username of whoever ran the command, not an identity or service token.

## What gets logged

Events are recorded via `engine.audit(actor, action, subject, detail)` and written to the `audit_log` table. `subject` is required structured context (e.g. which identity was affected); `detail` is optional additional context:

```rust
engine.audit(
    AuditActor::Identity { id: user_id.to_string() },
    "authenticate",
    json!({"identity_id": user_id.to_string()}),
    None,
).await?;
```

### Logged events

| Action | Actor | When |
|---|---|---|
| `verify_session` | Service | Every session verification request |
| `identity_lookup` | Service | Identity lookup by ID or username |
| `register` | Identity | New identity created |
| `register_and_authenticate` | Identity | Identity created and session issued in one call |
| `authenticate` | Identity | Successful password authentication |
| `create_service` | Operator | Service token created via CLI |
| `revoke_service` | Operator | Service token revoked via CLI |
| `reset_password` | Operator | Password reset via CLI |
| `disable_identity` | Operator | Account disabled via CLI |
| `enable_identity` | Operator | Account re-enabled via CLI |
| `rename_identity` | Operator | Username changed via CLI |

## Querying the audit log

There is no built-in query API — audit data is accessed via **direct SQL** against the `audit_log` table:

```sql
-- Recent successful authentications for a specific identity
SELECT actor, action, subject, at
FROM surge.audit_log
WHERE subject ->> 'identity_id' = '018f9a1b-...'
  AND action = 'authenticate'
ORDER BY at DESC
LIMIT 50;

-- All events performed by CLI operators in the last hour
SELECT *
FROM surge.audit_log
WHERE actor ->> 'type' = 'operator'
  AND at > now() - interval '1 hour'
ORDER BY at DESC;
```

Note that failed authentication attempts are **not** audited — only successful `authenticate`/`register` events are recorded. Track failed attempts via the rate limiter (see [Rate Limiting](/features/rate-limiting)) instead.

For production monitoring, you can expose audit data through your own API or stream it to your observability stack using a background reader.

## Retention and pruning

Audit logs grow unboundedly by default. You control retention with a periodic pruning job:

```sql
-- Prune events older than 90 days (run as a cron job)
DELETE FROM surge.audit_log
WHERE timestamp < now() - interval '90 days';
```

Choose a retention window that balances your compliance requirements against storage costs. Authentication-heavy deployments generate thousands of events per day.

## Privacy considerations

Audit logging is designed to be **safe by default** for security-sensitive data:

- **Passwords are never logged** — the `Password` type's `Debug` impl redacts the value, and the audit system never accepts password values.
- **Session tokens are never logged** — only session IDs (internal UUIDs) or hashed references appear in the audit trail.
- **Service token values are never logged** — only the service name and internal ID.

**Related:** [Service Authentication](/features/service-authentication), [Identity Management](/features/identity-management)
