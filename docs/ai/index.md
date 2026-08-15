# AI & LLM Security

LLM security is a distinct attack surface: the model is a component in a larger system, and the attacks exploit the gap between what the developer intended the model to do and what an adversary can cause it to do by controlling its inputs.

Start with the three hub docs to orient, then work through the OWASP LLM Top 10 in order, then the agent-specific attack classes, then the protocol deep dives.

## Hubs

| Doc | Purpose |
|---|---|
| [Web LLM Attacks](../30-web-llm-attacks.md) | Entry point — maps the attack surface of LLMs integrated into web apps |
| [MCP Protocol Security](../31-mcp-protocol-security.md) | Model Context Protocol threat model |
| [Agentic AI Threats](../32-agentic-ai-threats.md) | Threat taxonomy for autonomous agent systems |

## OWASP LLM Top 10

| # | Doc |
|---|---|
| LLM01a | [Direct Prompt Injection](../33-direct-prompt-injection.md) |
| LLM01b | [Indirect Prompt Injection](../34-indirect-prompt-injection.md) |
| LLM02 | [Sensitive Information Disclosure](../35-sensitive-info-disclosure.md) |
| LLM03 | [LLM Supply Chain](../36-llm-supply-chain.md) |
| LLM04 | [Data & Model Poisoning](../37-data-and-model-poisoning.md) |
| LLM05 | [Improper Output Handling](../38-improper-output-handling.md) |
| LLM06 | [Excessive Agency](../39-excessive-agency.md) |
| LLM07 | [System Prompt Leakage](../40-system-prompt-leakage.md) |
| LLM08 | [Vector & Embedding Weaknesses](../41-vector-embedding-weaknesses.md) |
| LLM09 | [Misinformation & Hallucination](../42-misinformation-and-hallucination.md) |
| LLM10 | [Unbounded Consumption](../43-unbounded-consumption.md) |

## Agent-specific attacks

| Doc | Attack class |
|---|---|
| [Memory Poisoning](../44-memory-poisoning.md) | Persistent injection via long-term memory |
| [Plan & Goal Hijacking](../45-plan-goal-hijacking.md) | Loop-level objective rewrite |
| [Cascading Hallucination](../46-cascading-hallucination.md) | Cross-agent privilege laundering |
| [HITL Bypass](../47-hitl-bypass.md) | Approval fatigue, spoofed UI |
| [Cross-Agent Trust & A2A Injection](../48-cross-agent-trust.md) | Unauthenticated semantic content |
| [Tool-Schema Confusion](../49-tool-schema-confusion.md) | Typed-argument violations |
| [Credential Passthrough](../50-credential-passthrough.md) | Over-broad scopes, RFC 8707 violations |
| [Sandbox Escape via Composition](../51-sandbox-escape-via-composition.md) | Composition-level escape |
| [MCP Cross-Server Shadowing](../52-mcp-cross-server-shadowing.md) | Tool-description hijack |
| [Rug Pull & Tool-Definition Drift](../53-rug-pull-tool-drift.md) | Metadata-plane supply chain |
| [Orchestrator Prompt Injection](../54-orchestrator-prompt-injection.md) | Unescaped template variables |

## Protocols & architecture

[MCP Deep Dive](../55-mcp-protocol-deep.md) · [A2A Protocol](../56-a2a-protocol.md) · [Function-Calling Protocols](../57-function-calling-protocols.md) · [RAG Architecture](../58-rag-architecture-attacks.md) · [Vector Stores](../59-vector-stores.md) · [Model Serving](../60-model-serving-attacks.md) · [Guardrail Systems](../61-guardrail-systems.md) · [Model File Formats](../62-model-file-formats.md)

## Defenses

[AI & Agent Defenses](../65-ai-agent-defenses.md) · [Spotlighting](../66-spotlighting.md)
