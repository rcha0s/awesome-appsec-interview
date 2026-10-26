# System Design

Principal-level system design revision notes. Like the rest of this site, a revision aid, not a tutorial: it assumes you already know the building blocks and reloads the trade-offs, the numbers, and the failure behavior that separate a mid-level design from a principal-level one.

The track has three sections, each with its own index and planned docs.

| Section | What it covers |
|---|---|
| [Web Systems](web/index.md) | Storage engines, replication and consistency, partitioning, consensus, caching, queues and streams, rate limiting, capacity math, and the classic designs built from them |
| [Mobile Applications](mobile/index.md) | Offline-first sync and conflict resolution, push delivery, client caching, battery and flaky networks, API versioning for old app builds, release control and kill switches |
| [Agentic Applications](agentic/index.md) | LLM serving, RAG at scale, agent orchestration and memory, eval pipelines, guardrails and tool trust boundaries, cost and latency budgets |

## Doc shape

System design docs have no attacker, so they do not use the attack-shaped section order. Each one follows the system design doc shape locked in [ADR-0004](../adr/0004-system-design-doc-shape.md):

| Section | Contents |
|---|---|
| Mental model | One blockquote paragraph stating the tension that drives the design |
| Requirements and scale | Functional scope, non-functional targets, capacity math with assumptions shown |
| Core design | The architecture that meets the requirements, with diagrams |
| Quick reference | A concrete example plus an invariants table (Invariant, Where enforced, How violated, Source) |
| Design decisions | Numbered; each states the options, the choice, the cost accepted, and what would flip it |
| Failure modes and operability | What breaks, how it is detected, how it degrades or recovers |
| Evolution | Optional: the design at 10x and 100x, or under a changed requirement |
| Interviewer probes | 5-8 Q&A pairs, each with a mid-level answer and the principal-level answer |
| Sources | Cited references |

Each doc also carries an **Interview frequency** tag (Core, Common, Situational, Niche), the same as every other doc here.

## How to use this track

Start each doc at the mental model and the capacity table: if you can state the tension and do the arithmetic, the design follows. Use the Design decisions section to rehearse the "what would make you choose differently" follow-up, and the probes to check the principal-level answers.

Where a topic overlaps a security doc elsewhere on this site (rate limiting and [API Security](../29-api-security.md), RAG and [RAG Architecture & Attacks](../58-rag-architecture-attacks.md), guardrails and [Guardrail Systems](../61-guardrail-systems.md)), the design doc covers the architecture and links to the security doc for the attack surface.

## Status

The track is a skeleton. Each section index lists the planned docs with a title and one line; docs are added one at a time and linked from the index when written.
