# Awesome AppSec Interview

Expert-level revision notes for **web application security** interviews (senior and staff security engineer). Each document is one topic, written as *answers to the rabbit-hole follow-ups* an interviewer asks, without the questions themselves. The content is grounded in real industry sources (PortSwigger Web Security Academy, OWASP cheat sheets and Top 10s, the relevant RFCs and protocol specs, and named public research), and each doc cites what it drew from.

This is a **revision aid, not a tutorial**. It assumes deep prior knowledge and reloads the technique-level detail fast: protocol breakdowns, concrete payloads, blind and out-of-band variants, escalation to RCE or account takeover, and the mitigations that actually hold.

## Every doc follows the same shape

- **Mental model**: the one-paragraph root cause.
- **How it works**: the protocol or technology breakdown (wire format, headers, spec behaviors) where relevant.
- **Attack techniques**: enumerated, each with the mechanism, a real payload or wire example, blind/OOB variants, how you confirm it, and why it works. Named techniques, CVEs, and researchers where sourced.
- **Defense**: specific and ordered by effectiveness, separating the real fix from defense-in-depth.
- **Interview-grade nuances**: the subtle senior-vs-junior points and common wrong answers.
- **Sources**: the real references used.

## Index

### Server-side and injection

| # | Topic | Focus |
|---|-------|-------|
| 01 | [SQL injection](docs/01-sql-injection.md) | UNION/error/boolean/time/OOB, per-DBMS metadata, binary-search extraction, file/RCE, WAF bypass |
| 20 | [NoSQL injection](docs/20-nosql-injection.md) | Operator vs syntax injection, `$ne`/`$gt`/`$regex`/`$where`, auth bypass, blind extraction |
| 05 | [OS command injection](docs/05-command-injection.md) | Shell vs argv sinks, blind time/OOB, argument injection, filter/space bypass |
| 11 | [Path traversal & file inclusion](docs/11-path-traversal-lfi.md) | Encoding bypass, PHP wrappers, log/session poisoning, LFI to RCE |
| 06 | [XXE injection](docs/06-xxe.md) | In-band/blind OOB, XXE to SSRF, SVG/OOXML vectors, per-parser hardening |
| 07 | [SSTI](docs/07-ssti.md) | Engine fingerprinting, object-graph to RCE per engine, sandbox escapes |
| 08 | [Insecure deserialization](docs/08-insecure-deserialization.md) | Gadget chains, ysoserial/phpggc, polymorphic JSON typing, allowlists |
| 04 | [SSRF](docs/04-ssrf.md) | Cloud metadata, gopher/Redis, DNS rebinding, parser bypass, IMDSv2 |
| 10 | [File upload](docs/10-file-upload.md) | Extension/content-type bypass, polyglots, SVG/XXE, Zip Slip, upload to RCE |

### Access control, authentication, and logic

| # | Topic | Focus |
|---|-------|-------|
| 15 | [Access control & IDOR](docs/15-access-control-idor.md) | IDOR/BOLA/BFLA, mass assignment, multi-tenant, two-account testing |
| 12 | [Authentication & session](docs/12-authentication-session.md) | Stuffing/spraying, MFA bypass, reset poisoning, fixation, cookie security |
| 16 | [Business logic & race conditions](docs/16-business-logic-race-conditions.md) | TOCTOU, limit-overrun, single-packet attack, workflow abuse |
| 21 | [Information disclosure](docs/21-information-disclosure.md) | Verbose errors, `.git`/`.env`, source maps, introspection, discovery |

### Client-side

| # | Topic | Focus |
|---|-------|-------|
| 02 | [Cross-site scripting (XSS)](docs/02-cross-site-scripting.md) | Reflected/stored/DOM/mXSS, self-XSS escalation, CSP bypass, impact |
| 03 | [CSRF](docs/03-csrf.md) | SameSite nuance, token failures, login/logout CSRF, XSS x CSRF chain |
| 18 | [CORS misconfiguration](docs/18-cors.md) | Reflected/null origin, weak validation, credentialed read exploit |
| 22 | [Clickjacking](docs/22-clickjacking.md) | UI redress, drag-and-drop, framebusting bypass, frame-ancestors |
| 23 | [WebSockets](docs/23-websockets.md) | Handshake internals, CSWSH, message injection, Origin validation |
| 24 | [Prototype pollution](docs/24-prototype-pollution.md) | `__proto__`/constructor vectors, client gadgets, server RCE, defenses |

### HTTP, caching, and protocol attacks

| # | Topic | Focus |
|---|-------|-------|
| 09 | [HTTP request smuggling](docs/09-http-request-smuggling.md) | CL.TE/TE.CL/TE.TE, HTTP/2 downgrade, client-side desync, impact |
| 25 | [HTTP Host header attacks](docs/25-http-host-header.md) | Reset poisoning, routing SSRF, cache poisoning, vhost access |
| 26 | [Web cache poisoning](docs/26-web-cache-poisoning.md) | Unkeyed inputs, gadgets, cache-key flaws, param cloaking |
| 27 | [Web cache deception](docs/27-web-cache-deception.md) | Path confusion, delimiter/normalization discrepancies, defenses |

### Identity, tokens, and APIs

| # | Topic | Focus |
|---|-------|-------|
| 14 | [OAuth 2.0 & OIDC](docs/14-oauth-oidc.md) | Grant types, `redirect_uri`/state/PKCE, scope upgrade, id_token validation |
| 13 | [JWT attacks](docs/13-jwt-token-security.md) | alg=none, RS256 to HS256 confusion, kid/jku injection, claim validation |
| 28 | [GraphQL](docs/28-graphql.md) | Introspection, resolver-level authz, batching abuse, query-depth DoS |
| 29 | [API security (REST)](docs/29-api-security.md) | OWASP API Top 10 2023, BOLA/BFLA/BOPLA, SSPP, mass assignment |

### AI and agent security — overview and umbrella docs

| # | Topic | Focus |
|---|-------|-------|
| 30 | [Web LLM attacks](docs/30-web-llm-attacks.md) | Hub: OWASP LLM Top 10 (2025) landing, links to deep dives 33–43 |
| 31 | [MCP protocol security](docs/31-mcp-protocol-security.md) | Hub: MCP overview, links to deep dive 55 and attacks 52/53 |
| 32 | [Agentic AI threats and mitigations](docs/32-agentic-ai-threats.md) | Hub: agent architecture, control loop, threat model across 44–54 |

### OWASP LLM Top 10 (2025) — one doc per class

| # | Topic | Focus |
|---|-------|-------|
| 33 | [Direct prompt injection](docs/33-direct-prompt-injection.md) | LLM01a: role-token unreliability, jailbreak templates, universal adversarial suffixes, encoding evasion |
| 34 | [Indirect prompt injection](docs/34-indirect-prompt-injection.md) | LLM01b: retrieved-content injection, ASCII smuggling, markdown-image exfil, EchoLeak |
| 35 | [Sensitive information disclosure](docs/35-sensitive-info-disclosure.md) | LLM02: training-data extraction, PII regurgitation, embedding inversion, RAG source leak |
| 36 | [LLM supply chain](docs/36-llm-supply-chain.md) | LLM03: model/tokenizer/dataset supply chain, HuggingFace hub, poisoned fine-tunes |
| 37 | [Data and model poisoning](docs/37-data-and-model-poisoning.md) | LLM04: training-time poisoning, instruction-tuning backdoors, sleeper agents, RLHF poisoning |
| 38 | [Improper output handling](docs/38-improper-output-handling.md) | LLM05: markdown-image exfil, SSRF via LLM-emitted URLs, XSS via chat rendering, sink recycling |
| 39 | [Excessive agency](docs/39-excessive-agency.md) | LLM06: excessive functionality/permissions/autonomy, confused deputy in tool calls |
| 40 | [System prompt leakage](docs/40-system-prompt-leakage.md) | LLM07: extraction techniques, "secret system prompt" anti-pattern, credentials-in-prompt |
| 41 | [Vector and embedding weaknesses](docs/41-vector-embedding-weaknesses.md) | LLM08: embedding poisoning, embedding inversion, cross-tenant retrieval bleed |
| 42 | [Misinformation and hallucination grounding](docs/42-misinformation-and-hallucination.md) | LLM09: package hallucination (slopsquatting), code-suggestion hallucination, verifier LLMs |
| 43 | [Unbounded consumption (denial of wallet)](docs/43-unbounded-consumption.md) | LLM10: fan-out loops, token amplification, per-user budgets, cost anomaly detection |

### Agent-specific attack classes

| # | Topic | Focus |
|---|-------|-------|
| 44 | [Memory poisoning](docs/44-memory-poisoning.md) | Persistent injection via long-term memory, cross-session persistence, cross-tenant memory bleed |
| 45 | [Plan and goal hijacking](docs/45-plan-goal-hijacking.md) | Loop-level objective rewrite, multi-turn priming, two-shot elicitation |
| 46 | [Cascading hallucination](docs/46-cascading-hallucination.md) | Multi-agent orchestration, cross-agent privilege laundering, weakest-agent exploitation |
| 47 | [Human-in-the-loop bypass](docs/47-hitl-bypass.md) | Approval fatigue, spoofed UI, auto-approve escape hatches, batch approval |
| 48 | [Cross-agent trust and A2A injection](docs/48-cross-agent-trust.md) | Unauthenticated semantic content, agent registration abuse, shared-channel poisoning |
| 49 | [Tool-schema confusion](docs/49-tool-schema-confusion.md) | Typed-argument violations, semantic vs shape gap, sink recycling into 05/11/01/04 |
| 50 | [Credential passthrough and token scoping](docs/50-credential-passthrough.md) | Over-broad scopes, RFC 8707 audience-binding violations, refresh-token leak via logs |
| 51 | [Sandbox escape via tool composition](docs/51-sandbox-escape-via-composition.md) | Composition-level escape, shared workspaces, network egress through helper tools |
| 52 | [MCP cross-server shadowing and tool poisoning](docs/52-mcp-cross-server-shadowing.md) | Tool-description hijack across servers, rogue registry servers |
| 53 | [Rug pull and tool-definition drift](docs/53-rug-pull-tool-drift.md) | Metadata-plane supply chain, hash pinning at approval, manifest tables |
| 54 | [Orchestrator prompt injection (template escape)](docs/54-orchestrator-prompt-injection.md) | Unescaped template variables, GitLab Duo MR-title, Notion AI title-field |

### AI/agent protocols and architectures

| # | Topic | Focus |
|---|-------|-------|
| 55 | [Model Context Protocol (MCP) deep dive](docs/55-mcp-protocol-deep.md) | JSON-RPC transport, capability negotiation, sampling, resource indicators, session semantics |
| 56 | [A2A protocol](docs/56-a2a-protocol.md) | Agent card discovery, task lifecycle, principal-and-authority binding, streaming updates |
| 57 | [Function-calling protocols](docs/57-function-calling-protocols.md) | OpenAI tools, Anthropic tool-use, Gemini function-calling, schema semantics vs shape |
| 58 | [RAG architecture and attack surface](docs/58-rag-architecture-attacks.md) | Ingestion/retrieval/generation stage-by-stage, chunker, reranker, prompt-assembly |
| 59 | [Vector stores](docs/59-vector-stores.md) | pgvector, Pinecone, Weaviate, Milvus, multi-tenancy, key scoping, RLS |
| 60 | [Model serving and inference-API attacks](docs/60-model-serving-attacks.md) | vLLM, TGI, TensorRT-LLM, Triton, KV-cache side channels, batch timing |
| 61 | [Guardrail systems](docs/61-guardrail-systems.md) | Rebuff, Lakera, PromptGuard, LlamaGuard, NeMo Guardrails, Azure AI Content Safety, honest limits |
| 62 | [Model file formats and loaders](docs/62-model-file-formats.md) | pickle RCE, safetensors, GGUF, ONNX, Fickling, allowlist safe formats |

### AI/agent defenses

| # | Topic | Focus |
|---|-------|-------|
| 65 | [AI/agent defenses reference](docs/65-ai-agent-defenses.md) | Least-privilege tool scoping, HITL, trust tiering, structured output, egress allowlists, audit |
| 66 | [Spotlighting](docs/66-spotlighting.md) | Delimiting, datamarking, encoding variants, invariant enforced, residuals |

### Cross-cutting

| # | Topic | Focus |
|---|-------|-------|
| 17 | [Cryptographic failures](docs/17-cryptographic-failures.md) | KDF tuning, padding oracle, IV/nonce reuse, length extension, AEAD |
| 19 | [Security misconfiguration & headers](docs/19-security-misconfiguration-headers.md) | Debug-to-RCE, exposed surfaces, the full security-header suite |

## Suggested revision order

If you are cramming, prioritise by interview frequency: **XSS, SQLi, access control/IDOR, SSRF, CSRF, auth/session, JWT, OAuth**, then request smuggling and the caching/host-header trio, then the AI/agent docs if the role touches LLM or MCP integrations.

For AI/agent-heavy roles: start at hubs 30 → 31 → 32, then walk the OWASP LLM Top 10 series 33–43 in order, then agent-specific attacks 44–54, then protocol deep dives 55–62, then defenses 65–66.

## Global reference libraries

These span almost every topic here and are worth bookmarking:

- PortSwigger Web Security Academy (all topics): https://portswigger.net/web-security/all-topics
- PortSwigger Research (original technique write-ups): https://portswigger.net/research
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- OWASP Web Security Testing Guide (WSTG): https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10 (2021): https://owasp.org/Top10/
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/llm-top-10/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.xyz/

---

*Scope: web application security, plus the adjacent AI/agent surface (LLM integrations and MCP). Defensive and educational revision material.*
