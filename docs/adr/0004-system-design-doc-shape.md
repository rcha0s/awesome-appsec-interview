# A doc shape for system design

ADR-0001 and ADR-0002 lock a section order built around an adversary: How it works, Quick reference, Attack techniques, Defense (Real fix / Defense in depth), Detection. ADR-0003 adds a second shape for design-checklist docs over one security decision. Neither fits a system design revision doc. A question like "design a distributed key-value store" has no attacker to enumerate, no Real fix versus Defense in depth split, and it is not a comparison of options for one decision. It is a sequence of constraints, a design that satisfies them, and a set of trade-offs that flip when the constraints change.

Forcing it through `## Attack techniques` would turn design decisions into fake attacks. Forcing it through the architectural control shape would lose the single worked system that a design question is actually about.

We are locking a third doc shape, the **system design doc** (see the `CONTEXT.md` glossary entry). It keeps everything that is not shape-specific: the blockquote mental model, the Interview frequency tag, the Quick reference contract (a concrete example plus a 3-8 row invariants table), the Interviewer probes format with Mid and Principal answers, `<sup>[[N]](#refN)</sup>` citations resolving to an anchored numbered Sources list, and the style rules. The section order is:

1. `#` Title.
2. Blockquote mental-model paragraph: the one tension that drives the design (for example, consistency against availability under partition, or freshness against read cost), stated so an interviewer can quote it back.
3. `## Requirements and scale`: functional scope, the non-functional targets that decide the design (latency percentiles, availability, durability, consistency), and a capacity-math table with the assumptions shown. Runs first because every later choice is justified against it.
4. `## Core design`: the architecture that satisfies the requirements, with diagrams (mermaid, per the existing diagram rules). Uses `###` sub-headings per component or data path.
5. `## Quick reference`: a concrete wire-level or data-level example (a request, a record layout, a log entry) and the invariants table. For this shape the "How violated" column names the failure that breaks the invariant, not an attack.
6. `## Design decisions`: numbered `### N. <decision>` items. Each states the options, the choice, the cost accepted, and the constraint change that would flip it. This section replaces Attack techniques as the numbered core of the doc.
7. `## Failure modes and operability`: what breaks, how it is detected, how it degrades or recovers, and the metrics and alerts that matter. Replaces Defense and Detection and telemetry.
8. `## Evolution` (optional): how the design changes at 10x and 100x scale or under a changed requirement. Omitted when the decisions section already covers it.
9. `## Interviewer probes`: 5-8 Q&A pairs, each with Mid and Principal answers. Probes target trade-offs, capacity math, and failure behavior.
10. `## Sources`: global numbered list with HTML anchors.

`## How it works`, `## Attack techniques`, `## Defense`, and `## War story` do not appear. An incident, when one fits, is cited inside Failure modes and operability.

Section placement: system design docs live under one nav section, System Design, split into three subsections (web systems, mobile applications, agentic applications). Each subsection has an index page carrying the planned-docs table for that subsection. A planned doc is listed by title and one line, unlinked, with no number. The number is assigned from the next free `NN` when the doc is written, and the same commit that adds the file links it from the subsection index, `README.md`, and `mkdocs.yml`, per the existing repo rules.

Where a system design topic touches a security topic already covered here (rate limiting and API security, RAG and the RAG attack surface, guardrails and guardrail systems), the system design doc links to the existing deep dive and the deep dive links back. It does not repeat the security treatment.

The tests in `tests/` check build integrity, nav hygiene, and diagram rendering, not section structure, so no test change is needed for the new shape. If structure linting is added later, it must treat the three shapes as separate cases rather than relax the existing one.
