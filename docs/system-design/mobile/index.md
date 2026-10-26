# Mobile Applications

Design of systems where the client is a long-lived, intermittently connected, battery-constrained device running a version you cannot force to update. Docs in this section follow the [system design doc shape](../../adr/0004-system-design-doc-shape.md).

## Planned docs

| Planned doc | Focus |
|---|---|
| Offline-first sync and conflict resolution | Local store as source of truth, sync protocols, last-writer-wins against CRDTs and operational transforms, and conflict surfacing |
| Push delivery | APNs and FCM semantics, delivery guarantees, token lifecycle, collapse and priority, and designing for dropped pushes |
| Client caching | HTTP caching, normalized client stores, invalidation, staleness budgets, and cache size and eviction on constrained storage |
| Battery and flaky networks | Retry with backoff and jitter, request batching, radio wake cost, background execution limits, and graceful degradation |
| API versioning for old app builds | Supporting a long tail of client versions: additive evolution, version negotiation, deprecation windows, and force-upgrade gates |
| Release and kill switches | Staged rollout, feature flags, remote config, server-side kill switches, and the limits of rolling back a shipped binary |

## Cross-links to existing docs

[Authentication](../../96-authentication.md) and [Session Management](../../101-session-management.md) cover the mobile security side of token storage and session continuity.
