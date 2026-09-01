# Awesome AppSec Interview

Expert-level revision notes for **web application security** interviews (senior and staff security engineer). Each document is one topic, written as *answers to the rabbit-hole follow-ups* an interviewer asks, without the questions themselves. The content is grounded in real industry sources (PortSwigger Web Security Academy, OWASP cheat sheets and Top 10s, the relevant RFCs and protocol specs, and named public research), and each doc cites what it drew from.

This is a **revision aid, not a tutorial**. It assumes deep prior knowledge and reloads the technique-level detail fast: protocol breakdowns, concrete payloads, blind and out-of-band variants, escalation to RCE or account takeover, and the mitigations that actually hold.

## Every doc follows the same shape

- **Mental model**: the one-paragraph root cause.
- **How it works**: the protocol or technology breakdown (wire format, headers, spec behaviors) where relevant.
- **Attack techniques**: enumerated, each with the mechanism, a real payload or wire example, blind/OOB variants, how you confirm it, and why it works. Named techniques, CVEs, and researchers where sourced.
- **Defense**: specific and ordered by effectiveness, separating the real fix from defense-in-depth.
- **Interviewer probes**: 5-8 Q&A pairs, each with a mid-level answer and the principal-level answer that distinguishes it.
- **Sources**: the real references used.

Each doc also carries an **Interview frequency** tag: Core (near-certain in any senior/staff appsec interview), Common (comes up often, not universal), Situational (depends on the role/domain matching), or Niche (real depth, rarely the actual focus). The Freq column below mirrors it.

One exception to the shape above: the **Architectural controls** docs (first section in the index below) are design checklists over one security-architecture decision, not one system. They fork by deployment context, compare realistic options in tables, and link out to the deep-dive docs instead of carrying their own How it works, Attack techniques, or Defense sections. See `docs/adr/0003-architectural-control-doc-shape.md` for the shape.

## Index

### Architectural controls

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 96 | [Authentication](docs/96-authentication.md) | Core | Design checklist forked by web/mobile/desktop/service-to-service: realistic options, modern defaults, and the sub-feature gaps each drags along (reset, remember-me, MFA recovery, deep-link interception, credential rotation) |
| 97 | [Authorization](docs/97-authorization.md) | Core | RBAC vs ABAC vs ReBAC, Zanzibar, OPA/Cedar policy engines, PDP/PEP placement, break-glass and policy-drift design considerations |
| 98 | [Secrets, Keys, and Data Protection](docs/98-secrets-keys-data-protection.md) | Core | The credential escalation ladder, HSM/TPM/TEE, envelope encryption/crypto-shredding, and the bearer-vs-proof-of-possession axis that decides when eliminating a secret beats storing it better |
| 99 | [Privacy Engineering and Data Protection](docs/99-privacy-engineering.md) | Common | Data minimization, de-identification (Safe Harbor/Expert Determination/k-anonymity), LINDDUN's linkability/identifiability/inference, consent, retention-vs-deletion |
| 100 | [Audit Logging and Non-repudiation](docs/100-audit-logging.md) | Core | What must be logged, tamper-evidence, keeping sensitive data out of the log while auditing access to it, break-glass review |
| 101 | [Session Management](docs/101-session-management.md) | Core | Where the continuity proof lives per surface and how it's actually revoked, deeper than Authentication's brief treatment |
| 102 | [Multi-Tenancy and Isolation](docs/102-multi-tenancy-isolation.md) | Core | Why application-layer tenant checks fail silently and data-layer isolation (RLS, per-tenant schemas, vector-store scoping) fails loudly instead |

### Server-side and injection

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 01 | [SQL injection](docs/01-sql-injection.md) | Core | UNION/error/boolean/time/OOB, per-DBMS metadata, binary-search extraction, file/RCE, WAF bypass |
| 20 | [NoSQL injection](docs/20-nosql-injection.md) | Situational | Operator vs syntax injection, `$ne`/`$gt`/`$regex`/`$where`, auth bypass, blind extraction |
| 05 | [OS command injection](docs/05-command-injection.md) | Common | Shell vs argv sinks, blind time/OOB, argument injection, filter/space bypass |
| 11 | [Path traversal & file inclusion](docs/11-path-traversal-lfi.md) | Common | Encoding bypass, PHP wrappers, log/session poisoning, LFI to RCE |
| 06 | [XXE injection](docs/06-xxe.md) | Common | In-band/blind OOB, XXE to SSRF, SVG/OOXML vectors, per-parser hardening |
| 07 | [SSTI](docs/07-ssti.md) | Common | Engine fingerprinting, object-graph to RCE per engine, sandbox escapes |
| 08 | [Insecure deserialization](docs/08-insecure-deserialization.md) | Common | Gadget chains, ysoserial/phpggc, polymorphic JSON typing, allowlists |
| 04 | [SSRF](docs/04-ssrf.md) | Core | Cloud metadata, gopher/Redis, DNS rebinding, parser bypass, IMDSv2 |
| 10 | [File upload](docs/10-file-upload.md) | Common | Extension/content-type bypass, polyglots, SVG/XXE, Zip Slip, upload to RCE |

### Access control, authentication, and logic

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 15 | [Access control & IDOR](docs/15-access-control-idor.md) | Core | IDOR/BOLA/BFLA, mass assignment, multi-tenant, two-account testing |
| 12 | [Authentication & session](docs/12-authentication-session.md) | Core | Stuffing/spraying, MFA bypass, reset poisoning, fixation, cookie security |
| 16 | [Business logic & race conditions](docs/16-business-logic-race-conditions.md) | Common | TOCTOU, limit-overrun, single-packet attack, workflow abuse |
| 21 | [Information disclosure](docs/21-information-disclosure.md) | Common | Verbose errors, `.git`/`.env`, source maps, introspection, discovery |

### Client-side

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 02 | [Cross-site scripting (XSS)](docs/02-cross-site-scripting.md) | Core | Reflected/stored/DOM/mXSS, self-XSS escalation, CSP bypass, impact |
| 03 | [CSRF](docs/03-csrf.md) | Core | SameSite nuance, token failures, login/logout CSRF, XSS x CSRF chain |
| 18 | [CORS misconfiguration](docs/18-cors.md) | Common | Reflected/null origin, weak validation, credentialed read exploit |
| 22 | [Clickjacking](docs/22-clickjacking.md) | Common | UI redress, drag-and-drop, framebusting bypass, frame-ancestors |
| 23 | [WebSockets](docs/23-websockets.md) | Situational | Handshake internals, CSWSH, message injection, Origin validation |
| 24 | [Prototype pollution](docs/24-prototype-pollution.md) | Situational | `__proto__`/constructor vectors, client gadgets, server RCE, defenses |

### HTTP, caching, and protocol attacks

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 09 | [HTTP request smuggling](docs/09-http-request-smuggling.md) | Common | CL.TE/TE.CL/TE.TE, HTTP/2 downgrade, client-side desync, impact |
| 25 | [HTTP Host header attacks](docs/25-http-host-header.md) | Common | Reset poisoning, routing SSRF, cache poisoning, vhost access |
| 26 | [Web cache poisoning](docs/26-web-cache-poisoning.md) | Common | Unkeyed inputs, gadgets, cache-key flaws, param cloaking |
| 27 | [Web cache deception](docs/27-web-cache-deception.md) | Common | Path confusion, delimiter/normalization discrepancies, defenses |

### Identity, tokens, and APIs

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 14 | [OAuth 2.0 & OIDC](docs/14-oauth-oidc.md) | Core | Grant types, `redirect_uri`/state/PKCE, scope upgrade, id_token validation |
| 13 | [JWT attacks](docs/13-jwt-token-security.md) | Core | alg=none, RS256 to HS256 confusion, kid/jku injection, claim validation |
| 28 | [GraphQL](docs/28-graphql.md) | Situational | Introspection, resolver-level authz, batching abuse, query-depth DoS |
| 29 | [API security (REST)](docs/29-api-security.md) | Common | OWASP API Top 10 2023, BOLA/BFLA/BOPLA, SSPP, mass assignment |

### Authentication protocols and federated identity

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 67 | [Single Sign-On (SSO)](docs/67-sso.md) | Common | Trust delegation pattern, SP- vs IdP-initiated, SLO, IdP-compromise blast radius, Golden SAML |
| 68 | [SAML 2.0](docs/68-saml.md) | Situational | Bindings, assertion signing, XSW, comment truncation, InResponseTo binding, IdP-initiated CSRF |
| 69 | [mTLS and client-certificate auth](docs/69-mtls.md) | Situational | TLS 1.2 vs 1.3 handshake, SAN/CN matching, revocation, TLS-terminator header trust |
| 70 | [WebAuthn, passkeys, and FIDO2](docs/70-webauthn-passkeys.md) | Common | Registration/assertion ceremonies, RP ID + origin binding, attestation formats, sync passkeys vs device-bound |
| 72 | [Session management deep dive](docs/72-session-management.md) | Common | Cookie flags, __Host- prefix, rotation, sliding vs absolute expiry, revocation model, hijacking vectors |
| 73 | [MFA and step-up authentication](docs/73-mfa-step-up.md) | Common | TOTP/HOTP, push-fatigue, WebAuthn as MFA, acr/amr claims, step-up flows, MFA-bombing |
| 75 | [Password authentication in 2026](docs/75-password-authentication.md) | Common | Argon2id/scrypt/bcrypt tuning, NIST 800-63B rev4, breach-list checks, credential stuffing defenses |
| 77 | [OpenID Connect deep dive](docs/77-oidc-deep.md) | Situational | id_token verification, nonce, discovery, RP-initiated + back-channel logout, PAR, JAR, FAPI |
| 78 | [Token exchange and delegation](docs/78-token-exchange.md) | Niche | RFC 8693, on-behalf-of, actor/may_act claims, RFC 8707 audience binding, downscoping |
| 81 | [SPIFFE and SPIRE](docs/81-spiffe-spire.md) | Niche | Workload identity, X.509 SVID, JWT SVID, workload attestation, federation, service-mesh mTLS |
| 82 | [OpenID Federation](docs/82-openid-federation.md) | Niche | Entity statements, trust chain to trust anchor, trust marks, automatic client registration |

### AI and agent security — overview and umbrella docs

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 30 | [Web LLM attacks](docs/30-web-llm-attacks.md) | Situational | Hub: OWASP LLM Top 10 (2025) landing, links to deep dives 33–43 |
| 31 | [MCP protocol security](docs/31-mcp-protocol-security.md) | Situational | Hub: MCP overview, links to deep dive 55 and attacks 52/53 |
| 32 | [Agentic AI threats and mitigations](docs/32-agentic-ai-threats.md) | Situational | Hub: agent architecture, control loop, threat model across 44–54 |

### OWASP LLM Top 10 (2025) — one doc per class

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 33 | [Direct prompt injection](docs/33-direct-prompt-injection.md) | Situational | LLM01a: role-token unreliability, jailbreak templates, universal adversarial suffixes, encoding evasion |
| 34 | [Indirect prompt injection](docs/34-indirect-prompt-injection.md) | Situational | LLM01b: retrieved-content injection, ASCII smuggling, markdown-image exfil, EchoLeak |
| 35 | [Sensitive information disclosure](docs/35-sensitive-info-disclosure.md) | Situational | LLM02: training-data extraction, PII regurgitation, embedding inversion, RAG source leak |
| 36 | [LLM supply chain](docs/36-llm-supply-chain.md) | Niche | LLM03: model/tokenizer/dataset supply chain, HuggingFace hub, poisoned fine-tunes |
| 37 | [Data and model poisoning](docs/37-data-and-model-poisoning.md) | Niche | LLM04: training-time poisoning, instruction-tuning backdoors, sleeper agents, RLHF poisoning |
| 38 | [Improper output handling](docs/38-improper-output-handling.md) | Situational | LLM05: markdown-image exfil, SSRF via LLM-emitted URLs, XSS via chat rendering, sink recycling |
| 39 | [Excessive agency](docs/39-excessive-agency.md) | Situational | LLM06: excessive functionality/permissions/autonomy, confused deputy in tool calls |
| 40 | [System prompt leakage](docs/40-system-prompt-leakage.md) | Situational | LLM07: extraction techniques, "secret system prompt" anti-pattern, credentials-in-prompt |
| 41 | [Vector and embedding weaknesses](docs/41-vector-embedding-weaknesses.md) | Niche | LLM08: embedding poisoning, embedding inversion, cross-tenant retrieval bleed |
| 42 | [Misinformation and hallucination grounding](docs/42-misinformation-and-hallucination.md) | Niche | LLM09: package hallucination (slopsquatting), code-suggestion hallucination, verifier LLMs |
| 43 | [Unbounded consumption (denial of wallet)](docs/43-unbounded-consumption.md) | Situational | LLM10: fan-out loops, token amplification, per-user budgets, cost anomaly detection |

### Agent-specific attack classes

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 44 | [Memory poisoning](docs/44-memory-poisoning.md) | Niche | Persistent injection via long-term memory, cross-session persistence, cross-tenant memory bleed |
| 45 | [Plan and goal hijacking](docs/45-plan-goal-hijacking.md) | Niche | Loop-level objective rewrite, multi-turn priming, two-shot elicitation |
| 46 | [Cascading hallucination](docs/46-cascading-hallucination.md) | Niche | Multi-agent orchestration, cross-agent privilege laundering, weakest-agent exploitation |
| 47 | [Human-in-the-loop bypass](docs/47-hitl-bypass.md) | Situational | Approval fatigue, spoofed UI, auto-approve escape hatches, batch approval |
| 48 | [Cross-agent trust and A2A injection](docs/48-cross-agent-trust.md) | Niche | Unauthenticated semantic content, agent registration abuse, shared-channel poisoning |
| 49 | [Tool-schema confusion](docs/49-tool-schema-confusion.md) | Niche | Typed-argument violations, semantic vs shape gap, sink recycling into 05/11/01/04 |
| 50 | [Credential passthrough and token scoping](docs/50-credential-passthrough.md) | Situational | Over-broad scopes, RFC 8707 audience-binding violations, refresh-token leak via logs |
| 51 | [Sandbox escape via tool composition](docs/51-sandbox-escape-via-composition.md) | Niche | Composition-level escape, shared workspaces, network egress through helper tools |
| 52 | [MCP cross-server shadowing and tool poisoning](docs/52-mcp-cross-server-shadowing.md) | Niche | Tool-description hijack across servers, rogue registry servers |
| 53 | [Rug pull and tool-definition drift](docs/53-rug-pull-tool-drift.md) | Niche | Metadata-plane supply chain, hash pinning at approval, manifest tables |
| 54 | [Orchestrator prompt injection (template escape)](docs/54-orchestrator-prompt-injection.md) | Niche | Unescaped template variables, GitLab Duo MR-title, Notion AI title-field |

### AI/agent protocols and architectures

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 55 | [Model Context Protocol (MCP) deep dive](docs/55-mcp-protocol-deep.md) | Niche | JSON-RPC transport, capability negotiation, sampling, resource indicators, session semantics |
| 56 | [A2A protocol](docs/56-a2a-protocol.md) | Niche | Agent card discovery, task lifecycle, principal-and-authority binding, streaming updates |
| 57 | [Function-calling protocols](docs/57-function-calling-protocols.md) | Niche | OpenAI tools, Anthropic tool-use, Gemini function-calling, schema semantics vs shape |
| 58 | [RAG architecture and attack surface](docs/58-rag-architecture-attacks.md) | Situational | Ingestion/retrieval/generation stage-by-stage, chunker, reranker, prompt-assembly |
| 59 | [Vector stores](docs/59-vector-stores.md) | Niche | pgvector, Pinecone, Weaviate, Milvus, multi-tenancy, key scoping, RLS |
| 60 | [Model serving and inference-API attacks](docs/60-model-serving-attacks.md) | Niche | vLLM, TGI, TensorRT-LLM, Triton, KV-cache side channels, batch timing |
| 61 | [Guardrail systems](docs/61-guardrail-systems.md) | Situational | Rebuff, Lakera, PromptGuard, LlamaGuard, NeMo Guardrails, Azure AI Content Safety, honest limits |
| 62 | [Model file formats and loaders](docs/62-model-file-formats.md) | Niche | pickle RCE, safetensors, GGUF, ONNX, Fickling, allowlist safe formats |

### AI/agent defenses

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 65 | [AI/agent defenses reference](docs/65-ai-agent-defenses.md) | Situational | Least-privilege tool scoping, HITL, trust tiering, structured output, egress allowlists, audit |
| 66 | [Spotlighting](docs/66-spotlighting.md) | Niche | Delimiting, datamarking, encoding variants, invariant enforced, residuals |

### Cross-cutting

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 17 | [Cryptographic failures](docs/17-cryptographic-failures.md) | Common | KDF tuning, padding oracle, IV/nonce reuse, length extension, AEAD |
| 19 | [Security misconfiguration & headers](docs/19-security-misconfiguration-headers.md) | Common | Debug-to-RCE, exposed surfaces, the full security-header suite |
| 83 | [Zero Trust Architecture](docs/83-zero-trust.md) | Situational | NIST SP 800-207 tenets, PE/PA/PEP, 800-207A cloud-native workload identity, 1800-35 implementation, CISA ZTMM v2.0, deployment variants, ZT for AI agents |

### Container and orchestration

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 85 | [Kubernetes security](docs/85-kubernetes.md) | Situational | 4 Cs model, API server / kubelet / etcd, RBAC and service-account tokens, Pod Security Admission (PSA), NetworkPolicy, admission control (Kyverno/Gatekeeper), workload identity |
| 86 | [Container escape](docs/86-container-escape.md) | Situational | Namespaces + cgroups + capabilities as the boundary, privileged/hostPath escapes, runc/CRI-O CVEs (2019-5736, 2024-21626, 2022-0847 Dirty Pipe), cgroup release_agent, gVisor / kata isolation |

### Payments and money-movement

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 87 | [Payment and PII tokenization](docs/87-tokenization.md) | Situational | PSP / network (VTS/MDES) / device tokens, PCI DSS 4.0.1 scope de-scoping, token vault attacks, FPE weaknesses (FF1/FF3), keyed hashing for stored PAN |
| 92 | [Money-movement authorization and idempotency](docs/92-money-movement-authz.md) | Situational | Per-object authz + idempotency-key replay-detection, dynamic linking (amount+payee) under PSD2 SCA, race-condition double-spend, refund/hold-vs-capture abuse, velocity limits |

### Async and event-driven

| # | Topic | Freq | Focus |
|---|-------|------|-------|
| 95 | [Webhooks](docs/95-webhooks.md) | Common | HMAC-SHA256 vs JWT-signed vs mTLS webhooks, timestamp binding to prevent replay, constant-time compare, SSRF via webhook dispatch, at-least-once delivery + receiver-side idempotency |

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

## Contributing

Docs follow a locked format: see [CONTEXT.md](CONTEXT.md) for the section order and writing rules, and [docs/adr/](docs/adr/) for the ADRs that shaped it. A new topic can be authored with the `/add-appsec-topic` skill, which enforces the shape and runs a correctness/interviewer/sources review pass before writing anything to disk.

Before adding a new doc:

- **Check for an existing home first.** Search the [Index](#index) and grep `docs/` for the topic. If it substantially overlaps an existing doc, extend that doc (a new attack technique, a new probe, an added source, a new diagram) instead of forking a near-duplicate. Two docs each covering 80% of the same ground is worse than one doc that covers it fully; it splits the reader's attention and the two copies drift out of sync over time.
- **Cross-link both directions.** If the new topic relates to an existing one (a shared mechanism, a prerequisite, an attack that chains into another), link it from both sides: the new doc references the existing one, and the existing one gets updated to reference the new doc back. A one-way link is a dead end for a reader who lands on the older doc first; this repo already has a few of those to clean up as you touch adjacent docs.
- **Update the README in the same commit.** A doc that exists on disk but is not in the Index below is invisible to a reader browsing the repo. This is enforced, not optional.

Open a PR. Small, focused changes (one new doc, one fix, one pass of cross-links) review faster than bundled ones.

---

*Scope: web application security, plus the adjacent AI/agent surface (LLM integrations and MCP). Defensive and educational revision material.*
