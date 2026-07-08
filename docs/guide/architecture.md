---
description: How Surge's browser-facing and service-facing surfaces version independently while sharing one session substrate.
---

# Architecture

Surge exposes two surfaces from one process and one database of record.

## Browser-facing: one router, nested, always live

The browser-facing router nests every currently-live API version internally (`/v1`, `/v2`, …) and is mounted once by each consumer — at root for the primary deployment, or under a sub-path by an embedding service. No consumer selectively mounts a single version; callers pick the version by which path they call.

This shape is forced by embedding: a consuming service runs one engine instance against one database. If that service's own frontend needs to serve both a v1-pinned caller and a v2-pinned caller at the same moment, there is exactly one engine available to answer both — so the multiplexing has to live inside one router, over one shared state.

There is no implicit default version. A version list only grows (additive, minor) when a version ships, and shrinks (major bump) when one is sunset — and even then, sessions minted under a removed version continue to be honored, because behavior doesn't break, only surface does.

## Service-facing: no embedding constraint

The service-facing API has exactly one version live at a time; backend callers compile in the version they target. Because there's no embedding requirement forcing multiple versions to coexist behind one mount, this surface doesn't need the nested-router mechanism the browser-facing side does.

## The shared substrate

Both surfaces read and write the same session/token substrate. It doesn't matter which surface minted a session — once minted, every reader on either surface, at any version, owes it the same truth. Practically, this means:

- The substrate grows only by nullable, read-and-ignore addition — never by redefinition.
- A new field needed only by a newer version belongs in that version's *projection* of the session, not in the stored truth older versions also read.
- Any change should pass this test: would a caller that completely ignores the change still end up in the same state of the world? Yes → surface, ship it per-version. No → behavior, stop and reconsider.
