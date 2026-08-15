# HTTP & Protocol Attacks

These attacks exploit ambiguity or discrepancy in how HTTP is parsed, routed, cached, or forwarded — not application logic. The target is the gap between what the developer assumes the server does and what the actual wire behaviour is.

## Topics in this section

| Doc | The gap exploited |
|---|---|
| [HTTP Request Smuggling](../09-http-request-smuggling.md) | Front-end and back-end disagree on where one request ends and the next begins |
| [HTTP Host Header Attacks](../25-http-host-header.md) | Application trusts the Host header for routing, password-reset links, or cache keys |
| [Web Cache Poisoning](../26-web-cache-poisoning.md) | Unkeyed input taints a cached response served to all users |
| [Web Cache Deception](../27-web-cache-deception.md) | Path confusion tricks the cache into storing a private response as public |
| [GraphQL](../28-graphql.md) | Introspection exposure, batching abuse, field-level authz gaps, IDOR via node IDs |
| [API Security](../29-api-security.md) | OWASP API Top 10 — excessive data exposure, broken object-level authz, mass assignment |
| [Webhooks](../95-webhooks.md) | HMAC replay, SSRF via callback URL, at-least-once delivery and receiver idempotency |

## Interview anchor

Request smuggling and cache poisoning are James Kettle research areas — interviewers who follow PortSwigger research ask about them at depth. Knowing the CL.TE/TE.CL/HTTP2-downgrade distinction and the unkeyed-input concept in cache poisoning puts you in the top tier for these topics.
