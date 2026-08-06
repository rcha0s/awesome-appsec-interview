# Cross-Site Request Forgery (CSRF)

> CSRF exploits ambient authority: the browser automatically attaches the victim's credentials (session cookies, HTTP Basic auth, TLS client certificates) to every request bound for a site, no matter which page triggered the request. If the server authorizes a state change on the strength of that ambient credential alone, an attacker-controlled page can compose a request the victim's browser will send fully authenticated, and the server cannot tell the difference. The fix is never "check the cookie harder," it is "require a proof of intent that a cross-site attacker cannot supply," which is a value tied to the session that the attacker cannot read or predict, or a browser signal (SameSite, custom header, Fetch Metadata) that only same-origin code can produce.

## How it works

Three conditions must all hold for classic CSRF, and each one is simultaneously a mitigation lever:

1. **A relevant state-changing action** the attacker wants to induce: change email or password, transfer funds, grant a role, weaken a security setting.
2. **Cookie-based (ambient) session handling**: performing the action relies solely on a cookie (or other browser-attached credential) to identify the user, with no additional per-request proof. Token-in-header schemes (`Authorization: Bearer ...`) are not auto-attached cross-site, so they are largely immune to classic CSRF.
3. **No unpredictable request parameter**: the attacker can determine or guess every value needed. If changing the password requires knowing the current password, that endpoint is not CSRF-able.

The canonical vulnerable request and its forgery. Given:

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```

The attacker hosts an auto-submitting form. The victim's browser attaches the `session` cookie automatically:

```html
<form action="https://vulnerable-website.com/email/change" method="POST">
  <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>document.forms[0].submit();</script>
```

Once the email is changed, the attacker triggers a password reset to that address and takes over the account. This is why "change email" and "change password" are the endpoints that matter most: they are the pivot to full account takeover.

Why the browser cooperates: cookies were designed as ambient, origin-bound (not initiator-bound) credentials. The request to `vulnerable-website.com` carries its cookies regardless of whether the initiating page was `vulnerable-website.com` or `evil.com`. CSRF is the abuse of that design decision. Note that CSRF also applies to any auto-attached credential, so HTTP Basic auth and certificate auth are equally exposed, not just cookies.

## Attack techniques

### 1. GET-based delivery (self-contained, no attacker site needed)

If the state change is reachable by GET, a single tag fires it with no form and no JavaScript:

```html
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```

Mechanism: the browser issues a credentialed GET for the image source. Detection: check whether a normally-POST endpoint also accepts GET (many frameworks route both). Why it works: no origin proof is required, and SameSite=Lax still sends the cookie on top-level GET navigations.

### 2. POST-based delivery (auto-submitting form)

The form in "How it works" above. HTML forms can only send three content types: `application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain`. That constraint is the seam most other techniques probe.

### 3. JSON endpoints and the simple-request boundary

If the endpoint strictly requires `Content-Type: application/json` and rejects the three form-legal types, a plain HTML form cannot forge it, because a form cannot emit `application/json`. This is a real (if accidental) defense. Bypass attempts:

- Send `text/plain` shaped to resemble JSON where the server is lenient about content type:

```html
<form action="https://vulnerable-website.com/api/transfer" method="POST" enctype="text/plain">
  <input name='{"amount":1000,"to":"attacker","ignore":"' value='"}'>
</form>
```

This produces a body of `{"amount":1000,"to":"attacker","ignore":"="}` sent as `text/plain`. It works only if the server parses the body as JSON despite the content type.

- Use `fetch` from the attacker origin to set a real `application/json` header. But a custom or non-simple content type triggers a CORS preflight, and the browser will not expose the credentialed response (and will not even send the unsafe request) unless the server's CORS policy allows the attacker origin. This is precisely why a permissive CORS policy undermines CSRF defenses: it re-enables cross-origin credentialed requests that the simple-request rules were blocking.

### 4. HTTP method override

If the app honors an override parameter or header, a POST form can reach a PUT/DELETE/PATCH handler. Symfony's `_method` field is the textbook case:

```html
<form action="https://vulnerable-website.com/account/transfer-payment" method="GET">
  <input type="hidden" name="_method" value="POST">
  <input type="hidden" name="recipient" value="hacker">
  <input type="hidden" name="amount" value="1000000">
</form>
```

Other frameworks honor `X-HTTP-Method-Override`. This also doubles as a SameSite=Lax bypass: the outer request is a top-level GET navigation (cookie sent), while the server routes it as a POST.

### 5. Bypassing broken CSRF token validation

Real targets usually have some token, so the technique is finding the validation flaw (all documented by PortSwigger):

- **Validation tied to method**: token checked on POST but skipped on GET. Switch to GET.
- **Validation tied to token presence**: token checked when present, skipped when absent. Delete the whole parameter, not just its value:

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

email=pwned@evil-user.net
```

- **Token not tied to the session**: the server keeps a global pool and accepts any issued token. Log in as yourself, harvest a valid token, feed it to the victim.
- **Token tied to a non-session cookie**: two frameworks (one for sessions, one for CSRF) that are not integrated. If the attacker can set the `csrfKey` cookie in the victim's browser (via a sibling-domain injection point), they pair their own token with their own key.
- **Token simply duplicated in a cookie (naive double-submit)**: the server only checks that the request parameter equals the cookie. If the attacker can set cookies on the domain, they invent a token, set it as the cookie, and submit the matching value. No server-side token store means no way to detect the forgery.

### 6. Bypassing SameSite restrictions

- **Lax bypass via GET**: servers often accept GET for POST endpoints; a top-level GET navigation still carries a Lax cookie (see technique 1 and 4).
- **Strict bypass via on-site gadget**: a client-side (DOM-based) open redirect on the target site issues a *same-site* secondary request that carries even Strict cookies, because the browser sees a standalone same-site request, not a cross-site one. Server-side redirects do not work for this, because the browser remembers the original cross-site initiator.
- **Sibling-domain compromise**: SameSite is site-scoped (eTLD+1), so an XSS or open redirect on `sub.example.com` counts as same-site to `app.example.com` and defeats site-based defenses. Cross-site WebSocket hijacking (CSWSH) is the WebSocket-handshake variant.
- **The Lax-plus-POST two-minute window (historical)**: when Chrome applies Lax *by default* (cookie set without an explicit `SameSite`), it does not enforce the restriction on top-level POST navigations for the first 120 seconds, to avoid breaking SSO. If the attacker can force a fresh cookie (for example by driving the victim through an OAuth login in a popup opened from an `onclick`), they refresh the cookie and then fire a cross-site top-level POST inside the window. This grace does **not** apply to cookies set with an explicit `SameSite=Lax`.

### 7. Login and logout CSRF

- **Login CSRF**: the attacker forges a login using their *own* credentials, so the victim is silently authenticated into the *attacker's* account. Anything the victim then saves (payment card, address, search history, uploaded documents) lands in the attacker's account for later retrieval. Login CSRF is also the delivery mechanism that turns self-XSS into real XSS: force-log the victim into an attacker account that already carries a stored payload. Defense: the login form needs a pre-session (anonymous) CSRF token too.
- **Logout CSRF**: on its own a nuisance, but it chains (force logout, then force login into the attacker's account).

### 8. The XSS times CSRF chain (both directions)

- **XSS defeats CSRF tokens**: script running in the origin simply reads the token out of the DOM or a same-origin response and includes it in the forged request. "We have CSRF tokens" is not a valid response to an XSS finding.
- **CSRF delivers XSS**: CSRF plants a stored-XSS payload into the victim's own account data, or force-logs them into a poisoned account, converting an unexploitable self-XSS into stored/reflected XSS in the victim's session.
- **Full chain**: CSRF a payload into a stored field, victim renders it, stored XSS runs, the script reads the CSRF token and performs privileged actions, resulting in account takeover. Being able to name each link and why it is needed is the senior-level answer.

## Defense

Ordered by effectiveness, real fix before defense-in-depth.

1. **Use the framework's built-in CSRF protection, validated per request and bound to the session.** Do not hand-roll. The **synchronizer token pattern** is OWASP's primary recommendation: the server generates a cryptographically strong, per-session (optionally per-request) token, embeds it in the form or exposes it for the client to attach, and validates it server-side on every state-changing request. Validate on *every* mutating request, reject when the token is missing (not only when present), and bind it to the authenticated session so a token minted for one user is useless for another.

2. **If you need to be stateless, use the signed double-submit cookie, not the naive one.** OWASP explicitly recommends the *signed* variant: the token is an HMAC computed over the server-side session ID (which never leaves the server in plaintext) plus a random value, delivered both as a cookie and echoed back in a header/field, and verified by recomputing the HMAC. Binding to the session defeats the cookie-injection attack that breaks the naive pattern. The naive double-submit (compare cookie to parameter with no signature) is discouraged because anyone who can write a cookie on the domain (vulnerable sibling subdomain, DNS takeover, plaintext-HTTP injection on a non-`__Host-` cookie) forges both halves. Do not put timestamps in the token for expiry: a CSRF token is not an access token, a new session should mint a new token.

3. **Require a custom request header for APIs and AJAX endpoints.** A header such as `X-CSRF-Token` (Rails, Laravel, Django), `X-XSRF-Token` (Angular), or even `X-Requested-With` cannot be set by a cross-site HTML form, and setting it from `fetch`/XHR forces a CORS preflight the server can reject. If the server *requires* the header, a browser could only have sent it after a successful preflight, which proves same-origin (or explicitly allowed) initiation. Pair this with a CORS policy that does not reflect arbitrary origins with credentials, otherwise the preflight guarantee is void.

4. **Adopt Fetch Metadata as a modern origin check where available.** Browsers send `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and `Sec-Fetch-Dest`; rejecting state-changing requests whose `Sec-Fetch-Site` is `cross-site` (fail-safe on absence for sensitive endpoints) is a robust, low-friction defense. Go's standard library ships this as `net/http.CrossOriginProtection` since Go 1.25.

5. **Set SameSite on the session cookie as defense-in-depth.** `SameSite=Lax` (now Chrome's default when unset) kills most cross-site form-POST CSRF for free; `SameSite=Strict` for high-value apps that can tolerate the UX cost of cross-site navigations arriving unauthenticated. SameSite is not a complete fix on its own: it does not cover GET-based state changes, is undermined by same-site subdomains, has the historical Lax-plus-POST grace window, and varies by browser version. Also avoid scoping a session cookie to a parent `Domain`, which shares it with every subdomain (including CNAMEs you do not control); prefer the `__Host-` prefix.

6. **Re-authenticate or step up on the most sensitive actions.** A password or MFA re-prompt (or transaction signing) on change-password, change-email, and money movement defeats CSRF regardless of token handling, because the attacker cannot supply the fresh secret.

7. **Never perform state changes over GET.** Closes the SameSite=Lax gap and the `<img>`/link delivery vector at the design level.

8. **Fix XSS.** Every control above assumes the origin is not executing attacker script. XSS reads the token and nullifies the entire list, so an XSS bug is also a CSRF bug.

## Interview-grade nuances

- SameSite=Lax-by-default is a mitigation, not a substitute for tokens: GET state changes, `SameSite=None` cookies, and same-site subdomain compromise all slip past it.
- Referer-based validation is weaker than tokens: it fails open when the header is stripped (many apps skip the check if `Referer` is absent, which the attacker arranges with `<meta name="referrer" content="no-referrer">`) and the matching logic is often bypassable.
- "Same-site" (eTLD+1, scheme-aware) is not "same-origin" (scheme, host, and port): a cross-origin request can still be same-site, which is exactly why a sibling-subdomain XSS defeats SameSite. `http` to `https` on the same host is cross-site because the scheme differs.
- CORS does not protect against CSRF, and a permissive CORS policy makes CSRF worse by re-enabling cross-origin credentialed requests and letting the attacker read the response.
- The `Vary` header does not affect CSRF decisions: it is a response header applied after the allow/deny decision, so it is operational (caching), not defensive.
- Token in the URL leaks via Referer, browser history, logs, and shared links: transmit tokens in a hidden field or header, never the query string.
- HttpOnly on the session cookie does not help against CSRF (the attacker never needs to read the cookie, the browser attaches it automatically); its value is against XSS cookie theft.

## Sources

- PortSwigger, CSRF: https://portswigger.net/web-security/csrf
- PortSwigger, Bypassing SameSite cookie restrictions: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
- PortSwigger, Bypassing CSRF token validation: https://portswigger.net/web-security/csrf/bypassing-token-validation
- OWASP, CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- MDN, Set-Cookie SameSite: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
- Go, net/http CrossOriginProtection (Go 1.25): https://pkg.go.dev/net/http@go1.25#CrossOriginProtection
