# Client-Side Attacks

Client-side attacks run code or trigger actions in the victim's browser rather than on the server. The browser's trust model — same-origin policy, cookie scope, and the ambient authority of the authenticated session — is what attackers abuse.

## Topics in this section

| Doc | Core mechanism |
|---|---|
| [XSS](../02-cross-site-scripting.md) | Attacker-controlled script executes in the victim's origin |
| [CSRF](../03-csrf.md) | Victim's browser sends an authenticated request the victim did not intend |
| [CORS Misconfiguration](../18-cors.md) | Credentialed cross-origin read permitted to an untrusted origin |
| [Clickjacking](../22-clickjacking.md) | Transparent overlay redirects clicks to a hidden privileged frame |
| [WebSockets](../23-websockets.md) | Handshake hijack (CSWSH) or message injection via missing origin check |
| [Prototype Pollution](../24-prototype-pollution.md) | `__proto__` modification poisons shared object properties; client gadgets to XSS, server gadgets to RCE |

## Chaining

XSS bypasses CSRF tokens (script can read and send them). Prototype pollution provides XSS gadgets in frameworks that sink polluted properties into `innerHTML` or `eval`. CORS misconfiguration lets an XSS on a subdomain read credentialed responses from the main origin.
