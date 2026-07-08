---
layout: home
description: Surge is an authentication engine with a browser-facing router and a service-facing API, sharing one session substrate.
hero:
  name: Surge
  text: Authentication engine
  tagline: A shared session substrate exposed through a browser-facing router and a service-facing API.
  actions:
    - theme: brand
      text: Introduction
      link: /guide/introduction
    - theme: alt
      text: Architecture
      link: /guide/architecture
features:
  - title: Two surfaces, one substrate
    details: A browser-facing router for SPA frontends and a service-facing API for backend callers, both reading and writing the same session/token substrate.
  - title: Versioned without breaking behavior
    details: Surface (paths, shapes) may change across versions. Behavior — what a session or token means once minted — never does.
  - title: Built for embedding
    details: Consuming services can mount the same router at their own path and run one engine instance against one database of record.
---
