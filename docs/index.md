# Awesome AppSec Interview

Expert-level revision notes for **web application security** interviews at the senior and staff security engineer level. Each document is one topic, written as answers to the rabbit-hole follow-ups an interviewer asks.

Content assumes deep prior knowledge and reloads technique-level detail fast: protocol breakdowns, concrete payloads, blind and out-of-band variants, escalation paths, and the mitigations that actually hold.

---

## How to use this site

Every doc follows the same fixed shape (see below), specifically so you don't have to read one top to bottom.

**If you already know a topic cold**, skip the mental model and How it works section and go straight to **Attack techniques**, **Defense**, and **Interviewer probes**. That's where a mid-level answer and a principal-level answer actually diverge, and it's the fastest way to find the gaps worth closing before an interview.

**If a topic is new to you**, start at the mental model (one paragraph, states the root cause) and How it works (the protocol or mechanism), then move through Attack techniques and Defense in order before you look at the probes.

**Search** (top bar) finds text across all 80+ docs instantly. Each doc also carries an **Interview frequency** tag, Core, Common, Situational, or Niche, so you can triage what's worth your time before you open it. Core means near-certain in any senior/staff interview; Niche means real depth that's rarely the actual focus even when the domain matches.

**Architectural Controls** (the first section below) is a different shape, deliberately. Instead of one system's mental model, How it works, and Attack techniques, each doc there is a design checklist over one security-architecture decision, broken down by context, with tables of options and the second-order gaps each one drags along, linking out to the deep-dive docs rather than repeating them. Start there if you're prepping for an architecture-review-style interview loop; start in the topic sections below if you're prepping for a per-vulnerability deep-dive loop.

## What "invariant" means in these docs

An invariant is the specific property that has to hold for a system to be safe, stated precisely enough that you can point at the exact moment it breaks. "Validate input" is not an invariant. "The resource server rejects any access token whose `aud` does not equal its own canonical identifier" is.

The word does real work across every doc:

- **Real fix** defenses enforce an invariant. They change what an attacker can reach, closing the attack class off structurally.
- **Defense in depth** items don't enforce an invariant. They raise attacker cost or narrow blast radius while the underlying gap still exists.
- **Interviewer probes** exist to test whether you can name the invariant an attack breaks, not just the attack's name. "It's a CSRF vulnerability" is a mid-level answer. "The login endpoint has no CSRF protection because it's treated as a safe action instead of a state-changing one" names the invariant.

If you can consistently say which invariant is being enforced, violated, or only partially covered by a given defense, you're answering at the level these docs are written for.

## Suggested revision order

If you are cramming, prioritise by interview frequency: **XSS, SQLi, access control/IDOR, SSRF, CSRF, auth/session, JWT, OAuth**, then request smuggling and the caching/host-header trio, then the AI/agent docs if the role touches LLM or MCP integrations.

For AI/agent-heavy roles: start at the three hubs (Web LLM Attacks, MCP Protocol Security, Agentic AI Threats), then the OWASP LLM Top 10, then agent-specific attacks, then protocol deep dives, then defenses.

## Topics

| Section | What it covers |
|---|---|
| [Architectural Controls](architecture-controls/index.md) | Design checklists over one security decision (Authentication, Authorization, Secrets Management, ...), broken down by context, linking out to the deep dives below |
| [Injection](injection/index.md) | SQLi, command injection, XXE, SSTI, deserialization, SSRF, file upload, path traversal, NoSQLi |
| [Authentication & Identity](authn/index.md) | Auth/session, JWT, OAuth/OIDC, SAML, SSO, WebAuthn, MFA, password auth, federated identity |
| [Access Control](15-access-control-idor.md) | IDOR/BOLA/BFLA, business logic and race conditions, information disclosure |
| [Client-Side](client-side/index.md) | XSS, CSRF, CORS, clickjacking, WebSockets, prototype pollution |
| [HTTP & Protocol](http/index.md) | Request smuggling, host header attacks, cache poisoning and deception |
| [Cryptography & Secrets](17-cryptographic-failures.md) | Crypto failures, payment/PII tokenization, money-movement authorization |
| [Misconfiguration](19-security-misconfiguration-headers.md) | Security headers, misconfiguration, GraphQL, REST API security |
| [Infrastructure](85-kubernetes.md) | Kubernetes, container escape, zero trust architecture |
| [AI & LLM Security](ai/index.md) | Prompt injection, agent threats, MCP/A2A protocols, RAG, guardrails, the OWASP LLM Top 10 |

## Document shape

Every doc follows the same structure:

| Section | Contents |
|---|---|
| Mental model | One blockquote paragraph stating the root cause |
| Quick reference | Wire-level example + invariants table |
| How it works | Protocol or technology breakdown |
| Attack techniques | Enumerated, each with mechanism, payload, confirmation, escalation |
| Defense | Real fix (enforces an invariant) then defense in depth (raises cost, doesn't close the gap), ordered by effectiveness |
| Detection and telemetry | Log fields, alerts, canary shapes |
| Interviewer probes | 5-8 Q&A pairs, each with a mid-level answer and the principal-level answer next to it |
| Sources | Cited references |

## Global references

- [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-topics)
- [PortSwigger Research](https://portswigger.net/research)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
