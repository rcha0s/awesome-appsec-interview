# Agentic Applications

Design of systems built around language models: serving them, grounding them, orchestrating them, and bounding what they cost and what they can do. Docs in this section follow the [system design doc shape](../../adr/0004-system-design-doc-shape.md).

## Planned docs

| Planned doc | Focus |
|---|---|
| LLM serving | Batching, KV cache, prefill against decode, speculative decoding, routing across models, and throughput against latency |
| RAG at scale | Ingestion, chunking, indexing, hybrid retrieval, reranking, freshness, and access control that survives retrieval |
| Agent orchestration and memory | Control loops, planner and worker splits, state and checkpointing, short-term and long-term memory, and failure recovery |
| Eval pipelines | Offline and online evals, regression suites, judge reliability, dataset curation, and gating releases on measured quality |
| Guardrails and tool trust boundaries | Where input, output, and tool-call checks sit, privilege per tool, human approval points, and what a guardrail cannot promise |
| Cost and latency budgets | Token accounting, caching and routing to cheaper models, tail latency across multi-step calls, and per-request budgets |

## Cross-links to existing docs

Several planned docs have a security counterpart already on this site: [Model Serving & Inference API](../../60-model-serving-attacks.md), [RAG Architecture & Attacks](../../58-rag-architecture-attacks.md), [Guardrail Systems](../../61-guardrail-systems.md), [Memory Poisoning](../../44-memory-poisoning.md), [Excessive Agency](../../39-excessive-agency.md), and [Unbounded Consumption](../../43-unbounded-consumption.md).
