# Awesome AppSec Interview

Expert-level revision notes for **web application security** interviews at the senior and staff security engineer level. Each document is one topic, written as answers to the rabbit-hole follow-ups an interviewer asks.

Content assumes deep prior knowledge and reloads technique-level detail fast: protocol breakdowns, concrete payloads, blind and out-of-band variants, escalation paths, and the mitigations that actually hold.

---

## How to use this site

**Search** (top bar) finds text across all 80+ docs instantly.

**Navigation tabs** group topics by domain. Injection techniques, authentication and identity, client-side attacks, HTTP and protocol attacks, cryptography, infrastructure, and the full AI/LLM security surface each have their own section.

**Suggested revision order** for a general appsec role: XSS → SQLi → Access Control / IDOR → SSRF → CSRF → Auth & Session → JWT → OAuth/OIDC → HTTP Request Smuggling → Cache Poisoning → Host Header.

For an AI/agent-heavy role: start at the three hubs (30, 31, 32) → OWASP LLM Top 10 (33–43) → Agent-specific attacks (44–54) → Protocol deep dives (55–62) → Defenses (65–66).

---

## Document shape

Every doc follows the same structure:

| Section | Contents |
|---|---|
| Mental model | One blockquote paragraph stating the root cause |
| Quick reference | Wire-level example + invariants table |
| How it works | Protocol or technology breakdown |
| Attack techniques | Enumerated, each with mechanism, payload, confirmation, escalation |
| Defense | Ordered by effectiveness, real fix first |
| Interview-grade nuances | Senior vs junior distinction points |
| Sources | Cited references |

---

## Global references

- [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-topics)
- [PortSwigger Research](https://portswigger.net/research)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
