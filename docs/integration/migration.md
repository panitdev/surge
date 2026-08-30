---
description: Upgrading between Surge versions — what changes, what doesn't, and how to migrate safely.
---

# Migration

Guidance for upgrading Surge across versions. The core guarantee: existing sessions and tokens continue to work across version boundaries.

## The stability guarantee

Surge's core guarantee is: **a session or token minted under version N is valid under version N+1.** You can upgrade Surge and all previously-issued sessions, service tokens, and credentials continue to work without interruption.

This applies regardless of:
- **Provider type** — embedded or served, sessions are portable across the boundary
- **Surface** — a session minted on the browser surface is introspectable through the service surface, and vice versa

`/v1` is currently the only mounted API version, so there is no cross-version
path to exercise today. The guarantee is about the credential store, which is
version-independent: sessions live in `surge.session` and are resolved the same
way by every surface.

```bash
# Session minted through the browser surface
curl -X POST http://localhost:3000/v1/flows/aeg_f_.../password \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "...", "csrf_token": "aeg_csrf_..."}'
# → session cookie returned

# The same session verifies through the service surface
curl -X POST http://localhost:3000/v1/sessions/verify \
  -H "Authorization: Bearer aeg_svc_..." \
  -H "Content-Type: application/json" \
  -d '{"token": "aeg_s_1a2b3c4d5e6f7g8h9i0j"}'
# → 200 OK — session recognized
```

## Surface vs. behavior

Every release tags changes as either **surface** or **behavior**:

| Category | What changes | What you need to do |
|---|---|---|
| **Surface** | API paths, request/response shapes, header requirements | Update your integration code |
| **Behavior** | Internal semantics, performance, error handling | Nothing — existing callers are unaffected |

When scanning a new release's [changelog](/reference/changelog), look for surface changes first — those are what might break your integration.

Examples of surface changes:
- A new required header on an endpoint
- A response field renamed or restructured
- An endpoint path changing (e.g. `/v1/foo` → `/v2/foo`)

Examples of behavior changes:
- Rate limit window tuning
- Session GC interval adjustment
- Improved error messages on auth failures

## Browser-facing: versions live side by side

Surge's browser router is built to nest API versions side by side. Today it
mounts `/v1` alone; when v2 ships, it exists alongside v1 rather than replacing
it:

```rust
// Inside the browser router returned by provider.browser_router()
Router::new()
    .nest("/v1", v1_router)
    // Future:
    // .nest("/v2", v2_router)
```

This means:
- **No forced migration deadline** — v1 callers continue working as long as v1 is shipped
- **Gradual adoption** — when a new version is added, your frontend can move to it at its own pace
- **Coexistence** — different parts of your app can use different versions simultaneously

Versions grow additively in minor releases (new version added, old one kept) and shrink in major releases (old version removed). When a version is removed, sessions and tokens minted under that version are still honored — removal only affects the API surface, never the credential store.

## Service-facing: staged rollouts

The service-facing API is mounted at `/v1`. When a future release adds a second
version, upgrade your services in stages:

1. **Deploy surge-server** with the new version. Old endpoints remain available.
2. **Update one service** at a time to use the new API paths.
3. **Verify** session introspection works across old and new service versions.
4. **Remove old version** when all services have migrated (major release).

During such a transition, services on different versions share the same session
store — a session verified by a service on one version is equally valid when
verified by a service on another.

## Database migrations

Surge runs Diesel migrations automatically at startup — both in embedded mode (`EmbeddedProvider::new()`) and in served mode (`surge-server serve`). You don't need to run migration commands manually.

```rust
// This call runs pending migrations
EmbeddedProvider::new(EmbeddedConfig {
    database_url: "...",
    pepper: "...",
    session_ttl: Duration::from_secs(72 * 3600),
})
.await?;
// → database schema is now up to date
```

Migrations are additive — new columns, new tables, new indexes. Surge never drops columns or tables in a minor release. If you run multiple Surge instances, migrations are safe to run from any instance (Diesel tracks which migrations have been applied in a `__diesel_schema_migrations` table).

**Rollback:** Surge does not support automatic migration rollback. Test upgrades against a staging database before applying to production.

## Testing your integration: cross-version canary

Surge includes a cross-version canary test that verifies the stability guarantee across surfaces and versions:

```bash
DATABASE_URL=postgres://localhost/surge_canary_test \
  cargo test -p surge-server --test cross_version_canary -- --ignored
```

The canary tests three patterns:

1. **Browser-to-browser**: mint a session on the browser surface, introspect on the browser surface — across versions
2. **Service-to-service**: mint a session on the service surface, introspect on the service surface — across versions
3. **Cross-surface**: mint on one surface, introspect on the other, in both directions — this catches gaps that single-surface tests miss

Run this test suite against a disposable Postgres (never a shared or production instance) before deploying to staging. Each test creates randomly-named services and identities so runs don't collide, but the tests never drop or truncate tables.

```rust
// Pattern from the canary:
// 1. Stand up an embedded provider (simulates one version)
let provider = EmbeddedProvider::new(EmbeddedConfig { ... }).await?;

// 2. Create a service and identity through one surface
engine.create_service(&svc_name, token.hash(), vec!["introspect".into()], vec![]).await?;

// 3. Verify the same credentials work through the other surface
let response = app
    .oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/sessions/verify")
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({"token": session_token}).to_string()))
            .unwrap(),
    )
    .await?;
assert_eq!(response.status(), StatusCode::OK);
```

## Deprecation and sunset policy

| Release type | What happens | Impact |
|---|---|---|
| **Minor** (0.N → 0.N+1) | New versions added, old versions kept | API surface grows; no breakage |
| **Major** (M → M+1) | Old API versions may be removed | Callers on removed versions must update |

The sunset timeline:
1. **Announce** deprecation in the changelog for one minor release before removal
2. **Remove** in the next major release — but credentials from removed versions are still honored

There is currently no runtime deprecation signal (e.g. a response header) on deprecated endpoints — check the changelog before upgrading across a major version.
