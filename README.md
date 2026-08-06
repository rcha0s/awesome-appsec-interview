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

### AI and agent security

| # | Topic | Focus |
|---|-------|-------|
| 30 | [Web LLM attacks](docs/30-web-llm-attacks.md) | Direct/indirect prompt injection, excessive agency, insecure output handling |
| 31 | [MCP protocol security](docs/31-mcp-protocol-security.md) | Tool poisoning, rug pulls, cross-server shadowing, token passthrough |

### Cross-cutting

| # | Topic | Focus |
|---|-------|-------|
| 17 | [Cryptographic failures](docs/17-cryptographic-failures.md) | KDF tuning, padding oracle, IV/nonce reuse, length extension, AEAD |
| 19 | [Security misconfiguration & headers](docs/19-security-misconfiguration-headers.md) | Debug-to-RCE, exposed surfaces, the full security-header suite |

## Suggested revision order

If you are cramming, prioritise by interview frequency: **XSS, SQLi, access control/IDOR, SSRF, CSRF, auth/session, JWT, OAuth**, then request smuggling and the caching/host-header trio, then the AI/agent docs if the role touches LLM or MCP integrations.

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
