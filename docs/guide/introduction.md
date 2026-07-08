---
description: What Surge is, the two surfaces it exposes, and who each one is for.
---

# What is Surge

Surge is an authentication engine. It exposes two surfaces that share a process and a database, but not a caller population, an auth mechanism, or a versioning strategy:

| | Browser-facing | Service-facing |
| --- | --- | --- |
| Caller | SPA frontend (login/registration UI) | Backend services |
| Auth | Session cookie | Bearer service token |
| Path shape | `{mount}/v1/…`, `{mount}/v2/…` — multiple versions live at once | `/v1/…`, one version compiled into the caller |

These are two different answers to two different problems, not two maturity levels of the same idea.

## The one invariant that spans both

**Surface may break across versions. Behavior may not, ever.**

A session or token is a set of truths the engine makes true — an identity is bound to this cookie, this session exists. Once minted, on either surface, at any version, every reader owes that session the same truth. The substrate grows only by nullable, additive change; it never gets redefined out from under a caller.

See [Architecture](/guide/architecture) for how each surface implements this.
