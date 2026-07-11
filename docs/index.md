---
layout: home
description: Surge is an authentication engine you embed into your Rust app or run as a standalone SSO server — handling login, sessions, and service auth so you don't have to build it yourself.
hero:
  name: Surge
  text: Authentication engine
  tagline: Login flows, sessions, and service-to-service auth for your Rust app — embedded in-process or run centrally as SSO.
  actions:
    - theme: brand
      text: Introduction
      link: /guide/introduction
    - theme: alt
      text: Quickstart
      link: /guide/quickstart
features:
  - title: Embed it, or run it centrally
    details: Add Surge as a dependency in your Axum app with zero extra infrastructure, or run surge-server as a shared SSO service for multiple applications. Same database, same session model, either way.
  - title: Handles the hard parts
    details: Login flows, cookie-based sessions, Argon2id password hashing, service tokens, rate limiting, and audit logging — built in, not bolted on.
  - title: Sessions that don't break
    details: Once Surge mints a session or token, it keeps meaning the same thing for its lifetime. Upgrading Surge never invalidates credentials already issued.
---
