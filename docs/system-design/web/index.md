# Web Systems

Design of large-scale server-side systems: the building blocks first, then the classic designs that compose them. Docs in this section follow the [system design doc shape](../../adr/0004-system-design-doc-shape.md).

## Planned docs: building blocks

| Planned doc | Focus |
|---|---|
| Storage engines | B-tree against LSM-tree: write and read amplification, compaction, and when each wins |
| Replication and consistency | Leader-follower, multi-leader, leaderless; replication lag, read-your-writes, quorums, and the consistency models worth naming precisely |
| Partitioning | Range, hash, and consistent hashing; hot keys, rebalancing, and secondary indexes across partitions |
| Consensus | Raft and Paxos at the level of invariants: leader election, log replication, membership change, and what consensus is and is not used for |
| Caching | Cache-aside, write-through, write-back; invalidation, stampedes, hot keys, and multi-tier layouts |
| Queues and streams | Queue against log semantics, delivery guarantees, ordering, partitioned consumers, backpressure, and exactly-once claims |
| Rate limiting | Token bucket, sliding window, and distributed counters; where to enforce and how limits degrade under failure |
| Capacity math | Back-of-envelope estimation: QPS, storage, bandwidth, and memory, with the latency numbers worth memorizing |

## Planned docs: classic designs

| Planned doc | Focus |
|---|---|
| Distributed key-value store | Dynamo-style partitioning, replication, and tunable consistency, versus a consensus-backed store |
| News feed | Fan-out on write against fan-out on read, the celebrity problem, ranking, and cache layout |
| Chat | Connection management, message ordering and delivery, presence, group fan-out, and history storage |
| Payments ledger | Double-entry model, idempotency, exactly-once effects, reconciliation, and audit; links to [Money-Movement Authorization](../../92-money-movement-authz.md) |

## Cross-links to existing docs

[API Security](../../29-api-security.md), [Webhooks](../../95-webhooks.md), and [Multi-Tenancy and Isolation](../../102-multi-tenancy-isolation.md) cover the security side of several topics above.
