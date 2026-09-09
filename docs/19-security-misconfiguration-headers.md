# Security Misconfiguration and HTTP Security Headers

> Perfect application code still gets breached when the deployment around it is wrong: a default password nobody rotated, a debug console left reachable, a management endpoint with no auth, a storage bucket set to public, a missing response header that would have blunted an otherwise-successful XSS or clickjacking attempt. A05:2021 is the "everything about how it runs" category, and it is common precisely because modern stacks are highly configurable and ship with permissive, convenient defaults. The root-cause mental model is twofold: reduce attack surface (turn off, remove, or lock down anything you are not deliberately using) and instruct the client's browser to enforce your security intent (the header suite). The reason headers get asked so heavily in interviews is that each one is concrete, testable in one `curl`, and maps to a specific attack it mitigates, so knowing the mapping cold demonstrates you understand the attacks, not just the config.

**Interview frequency:** Common

*See also: [File Upload and Storage Security](103-file-upload-storage-security.md) for Content-Type/nosniff enforcement and origin isolation applied to user-uploaded and served files specifically.*

## How it works

Security misconfiguration spans the whole stack, and the exploitable classes recur:

- Default credentials and sample content: `admin/admin`, unchanged database/JMX/actuator/broker passwords, shipped demo apps and admin consoles, default cloud IAM roles. OWASP Scenario #1<sup>[[1]](#ref1)</sup> is literally a sample admin app plus an unchanged default password equals full takeover.
- Verbose errors and debug mode: stack traces, framework debug pages, and version banners leak internal paths, dependency versions, and SQL fragments. The severe form is a debug console that executes code: Flask/Werkzeug's interactive debugger runs arbitrary Python in the server process when `debug=True`, and Django's `DEBUG=True` page dumps settings and environment. "Informative error" and "remote code execution" are the same finding at different depths.
- Exposed management and metadata surfaces: Spring Boot Actuator (`/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, Jolokia), Prometheus `/metrics`, admin dashboards (Kibana, Grafana, Kubernetes dashboard), and cloud instance metadata (IMDS at 169.254.169.254) reachable from the app. `/heapdump` alone can leak in-memory secrets and session tokens.
- Files that should never be web-served: `.git/` and `.svn/` (reconstructable into full source with git-dumper), `.env` (database creds, API keys), `.bak`/`~`/`.old` backups, editor swap files, exposed source maps, Swagger/OpenAPI on production.
- Directory listing enabled: an index of a directory lets an attacker enumerate and download compiled classes or artifacts, decompile, and find further flaws (OWASP Scenario #2<sup>[[1]](#ref1)</sup>).
- Unnecessary HTTP methods: `PUT`/`DELETE` where not intended, and `TRACE`, which enables Cross-Site Tracing (XST, Jeremiah Grossman, 2003) to echo back headers including cookies that script cannot otherwise read.
- Cloud and storage misconfiguration: world-readable S3 buckets or blobs, over-permissive security groups, unauthenticated internal services bound to public interfaces (Redis, Elasticsearch, MongoDB, memcached).
- Outdated components: unpatched server software and known-CVE dependencies (this bleeds into A06:2021 Vulnerable and Outdated Components).
- Permissive defaults: CORS reflecting any origin or `Access-Control-Allow-Origin: *` on authenticated endpoints, cookies without flags, no rate limiting, TLS left at defaults.

The second half of the model is the response-header suite. Headers are hardening directives the server sends and the browser enforces; each targets a specific attack.

## Quick reference

```
# Reachable Werkzeug debug console: attacker types Python directly into the browser page
__import__('os').popen('id').read()
# One line of input into an unauthenticated debug endpoint is remote code execution.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Debug consoles and admin/management endpoints never sit on an unauthenticated production network path | Deployment config, network segmentation, Actuator/debug auth gating | A reachable Werkzeug debugger executes arbitrary Python, and unauthenticated `/actuator/env` plus `/actuator/restart` mutate config and restart into RCE | <sup>[[1]](#ref1)</sup> |
| Every response, on every route, carries the full hardening header suite by default | Global security-headers middleware (helmet, django-csp, Spring Security, secure_headers) | A header applied per-route instead of globally is silently missing on the one route that gets forgotten, reopening whichever attack it was blunting | <sup>[[9]](#ref9)</sup> |
| A page can only be framed by an origin the app explicitly allows | CSP `frame-ancestors` (primary), `X-Frame-Options` (legacy fallback) | Clickjacking: the page loads in a transparent/positioned iframe on an attacker site and the victim's click lands on a hidden sensitive control | <sup>[[5]](#ref5)</sup> |
| Inline and injected script cannot execute even if HTML injection succeeds | `Content-Security-Policy` (nonce + `strict-dynamic`, `object-src 'none'`, `base-uri 'none'`) | No CSP, or one permitting `unsafe-inline`, lets an injected `<script>` run unmodified | <sup>[[3]](#ref3)</sup> |
| HSTS protection applies from the first connection onward, not just after one HTTPS visit | `Strict-Transport-Security` header plus browser HSTS preload list | A domain that has not submitted to the preload list is still downgradable on a user's very first connection, before the header has ever been seen | <sup>[[4]](#ref4)</sup> |
| Response headers never volunteer server software name or version | Reverse proxy / framework config stripping `Server`, `X-Powered-By`, `X-AspNet-Version` | `Server: Apache/2.4.49` hands attackers the exact version to match against a known CVE and public exploit | <sup>[[2]](#ref2)</sup> |
| Header, TLS, and IaC posture are verified continuously in CI, across every response path, not just the homepage once | Header/TLS scanners and IaC policy scanners wired into CI | A scan of only the homepage over HTTPS misses headers stripped on error, redirect, or CDN-fronted responses | <sup>[[6]](#ref6)</sup> |

## Attack techniques

### 1. Default-credential and sample-app takeover

Attackers hit well-known admin paths (`/manager/html`, `/admin`, `/actuator`) with vendor default passwords. Confirmation: the endpoint exists and default creds authenticate. Why it works: "install then harden later" leaves a fully privileged door open.

### 2. Debug console to RCE

Reaching a Werkzeug debugger (Flask) exposes an interactive evaluator; historically unauthenticated, later gated by a PIN that is derivable when the machine ID and a module path leak (which verbose errors provide). Realistic probe:

```
# A reachable Werkzeug debugger renders a traceback with an interactive
# console; the attacker types Python directly into the browser page:
__import__('os').popen('id').read()

# Spring Actuator env manipulation chained to Jolokia for code execution:
POST /actuator/env  {"name":"...", "value":"..."}   # mutate config
POST /actuator/restart                              # apply, often -> RCE
```

Confirmation: the debug page renders and evaluates input, or `/actuator/env` accepts writes. Why it works: developer-productivity features were never meant to face untrusted networks, and "internal only" boundaries erode.

### 3. Content discovery of exposed files

Automated wordlist scans (feroxbuster, ffuf) plus targeted pulls (`git-dumper` against `/.git/`, a direct GET of `/.env`, `/config.php.bak`) harvest source and secrets. Confirmation: `GET /.git/HEAD` returns a ref, `/.env` returns key=value pairs. Why it works: the web root includes VCS metadata, backups, or dotfiles the server happily serves as static content.

### 4. Cross-Site Tracing (XST) via TRACE

If `TRACE` is enabled, an attacker uses it to reflect request headers, historically to exfiltrate `HttpOnly` cookies that JavaScript could not read directly. Confirmation: `curl -X TRACE` echoes the request. Why it works: TRACE is a diagnostic loopback that was never needed on production.

### 5. Clickjacking (UI redress)

The target page is loaded in a transparent or carefully positioned `iframe` on an attacker site; the victim believes they are clicking the attacker page but their click lands on a sensitive control (transfer funds, change email, grant OAuth) in the framed, authenticated app. Confirmation: the page frames successfully (no `frame-ancestors`/`X-Frame-Options`) and performs state change on click. Why it works: the browser sends the victim's cookies with the framed request, and nothing forbids framing.

### 6. MIME-sniffing content confusion

Without `nosniff`, a browser may ignore a declared `Content-Type` and sniff bytes, so a user-uploaded file served as `text/plain` but containing HTML/JS gets interpreted as an executable document (stored XSS), or a polyglot is treated as script. Confirmation: upload a file whose content sniffs as HTML and observe script execution. Why it works: legacy sniffing heuristics override the server's stated type.

### 7. Referer leakage of secrets

If a page URL or a same-origin link contains a token (password-reset token, session ID, invite code) and the page links off-site, the browser's default `Referer` can carry that URL to third parties (analytics, ads, the linked site). Confirmation: inspect outbound requests for a `Referer` containing sensitive path/query. Why it works: the default referrer policy is looser than most apps assume.

### 8. Cross-origin leaks (XS-Leaks / Spectre-class)

Cross-origin documents sharing a browsing context group or process can be probed via side channels (timing, frame counting, cache) to infer cross-site state. Confirmation: the site is embeddable/openable cross-origin without isolation headers. Why it works: without COOP/COEP/CORP the browser keeps cross-origin resources reachable inside the attacker's process.

### 9. Version-banner reconnaissance

`Server: Apache/2.4.49`, `X-Powered-By: PHP/5.6`, and `X-AspNet-Version` hand attackers the exact software and version to match against known CVEs (for example the Apache 2.4.49 path traversal CVE-2021-41773). Confirmation: read the response headers. Why it works: fingerprinting is free when the server volunteers it.

## Defense

Ordered by leverage within each group. The header suite is table stakes, but disabling surfaces and hardening by default removes whole attack classes.

### Real fix

1. Harden by default, repeatably, as code. A documented, automated baseline (IaC modules, hardened base images, config management) so every environment (dev, QA, prod) is provisioned identically with different secrets and no manual snowflakes. Ship a global security-headers middleware (helmet for Express, django-csp/SecurityMiddleware, Spring Security, secure_headers for Rails) so headers cannot be forgotten per route.

2. Disable and remove what you do not use. Turn debug/verbose errors off in production and return generic error pages (map to custom 4xx/5xx). Remove sample apps and default accounts, rotate all default credentials. Disable directory listing. Restrict HTTP methods to those you serve (drop `TRACE`, `PUT`, `DELETE` unless required). Close unused ports and services.

3. Lock down management and metadata surfaces. Authenticate and network-restrict Actuator/admin/metrics/dashboards (bind to localhost or a management VLAN, require auth, expose the minimum endpoints). Block the web server from serving `.git`, dotfiles, and backups. Restrict egress to cloud metadata (IMDSv2 with hop limits) so an SSRF or injected request cannot reach it. IMDSv2 requires a two-step, session-oriented flow: the caller must first `PUT /latest/api/token` with a `X-aws-ec2-metadata-token-ttl-seconds` header to receive a session token, then include that token via `X-aws-ec2-metadata-token` on the actual `GET /latest/meta-data/...` request. This defeats the common SSRF primitive where an attacker forces the app to `GET http://169.254.169.254/...` because most SSRF vectors cannot issue a `PUT` with a custom header and capture the response body to reuse it. Set the instance metadata hop limit to 1 (`--http-put-response-hop-limit 1`) so a container on the host cannot reach IMDS via a second network hop, and disable IMDSv1 entirely (`HttpTokens=required`). This does not replace least-privilege on the instance role; a stolen role is still a stolen role, but it removes the drive-by SSRF path.

4. Set the full response-header suite, mapping each to the attack it blunts<sup>[[2]](#ref2)</sup>.

   - `Content-Security-Policy`<sup>[[3]](#ref3)</sup>: the primary defense-in-depth against XSS and injection. Prefer a nonce-based strict policy: `script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. `object-src 'none'` kills plugin/`<object>` vectors; `base-uri 'none'` stops a `<base>` injection from redirecting relative script loads and bypassing the nonce; `frame-ancestors` handles clickjacking. Avoid `unsafe-inline`, `unsafe-eval`, and host allowlists (bypassable via JSONP/open redirects). Roll out with `Content-Security-Policy-Report-Only` first.
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`: forces HTTPS in the browser, defeating SSL-strip/downgrade MITM and cookie-over-HTTP leaks; `includeSubDomains` closes subdomain cookie attacks, `preload` (after submitting to hstspreload.org<sup>[[4]](#ref4)</sup>) covers the very first visit. HSTS is only honored over HTTPS. Note `preload` is effectively permanent, so commit to HTTPS everywhere first.
   - `X-Content-Type-Options: nosniff`: stops MIME sniffing (content-confusion XSS, user-upload execution). Pair with `Content-Disposition: attachment` and `Content-Type: application/octet-stream` for user file downloads.
   - `Referrer-Policy: strict-origin-when-cross-origin` (or stricter `no-referrer`): prevents token/PII leakage through the `Referer` header.
   - `Permissions-Policy: geolocation=(), camera=(), microphone=()` (add `interest-cohort=()`): disables powerful features the app does not need, so an injection cannot silently turn on the camera/mic/geolocation.
   - `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-site`: process isolation against Spectre-class and XS-Leaks; COOP+COEP together enable cross-origin isolation (required for high-resolution timers/SharedArrayBuffer).
   - `Cache-Control: no-store` on responses carrying sensitive data (and `Clear-Site-Data` at logout): keeps secrets out of shared caches and browser history. On a modern HTTP/1.1+ stack `no-store` is sufficient; the old `no-cache, no-store, must-revalidate` + `Pragma` + `Expires: 0` stack adds nothing.
   - `Set-Cookie` attributes: `HttpOnly` (script cannot read the cookie, blunting XSS cookie theft), `Secure` (HTTPS-only, no cleartext leak), `SameSite=Lax`/`Strict` (CSRF reduction; `None` requires `Secure`). Prefer the `__Host-` prefix: the browser only accepts a `__Host-` cookie if it is `Secure`, has no `Domain` attribute (host-locked, not shared to subdomains), and `Path=/`. `__Secure-` requires the `Secure` flag. These prefixes are enforced by the browser, so a subdomain or a network attacker on `http://` cannot overwrite them (cookie tossing/fixation). SameSite has nuances that trip teams up: Chrome (80+) treats cookies without a `SameSite` attribute as `Lax` by default, which silently changed behavior for many legacy apps. `SameSite=Lax` still sends the cookie on top-level GET navigations (typing a URL, clicking a link), so it does not block a CSRF that is a full page navigation, only cross-site subresource requests and cross-site POSTs; `Strict` blocks even the top-level navigation, which typically breaks link-in-email login flows. Chrome also historically shipped a "Lax+POST" two-minute grace window where cross-site POSTs within two minutes of cookie set were allowed for SSO compatibility. Treat SameSite as CSRF risk reduction, not a replacement for anti-CSRF tokens (still required for state-changing endpoints), and remember that same-site is not same-origin: `evil.example.com` and `app.example.com` are same-site, so a compromised subdomain can still ride the cookie. `SameSite=None` requires `Secure` and is the only value that works in cross-site iframes (embedded auth, third-party widgets).

   ```
   Content-Security-Policy: script-src 'nonce-r4Nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
   Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
   X-Content-Type-Options: nosniff
   Referrer-Policy: strict-origin-when-cross-origin
   Permissions-Policy: geolocation=(), camera=(), microphone=(), interest-cohort=()
   Cross-Origin-Opener-Policy: same-origin
   Cross-Origin-Embedder-Policy: require-corp
   Cross-Origin-Resource-Policy: same-site
   Cache-Control: no-store
   Set-Cookie: __Host-session=...; Secure; HttpOnly; SameSite=Lax; Path=/
   ```

5. Remove version-disclosing and deprecated headers. Strip or blank `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`. Explicitly disable `X-XSS-Protection` (`X-XSS-Protection: 0`): the legacy auditor is deprecated and could itself introduce vulnerabilities; rely on CSP. Drop `Public-Key-Pins`/HPKP (removed from browsers) and `Expect-CT` (obsolete); rely on Certificate Transparency and CAA DNS records instead.

6. Clickjacking defense specifics<sup>[[5]](#ref5)</sup>. Primary control is CSP `frame-ancestors 'none'` (or `'self'`), which supersedes `X-Frame-Options: DENY`/`SAMEORIGIN`; send `X-Frame-Options` too only for old browsers that lack `frame-ancestors`. Add `SameSite` cookies so framed cross-site requests are not authenticated, and require re-authentication or confirmation on sensitive actions. Legacy framebusting JavaScript is at best a defense-in-depth fallback, not the control.

### Defense in depth

1. Least privilege and segmentation. Minimal cloud IAM, private-by-default storage, tight security groups, network segmentation so the app cannot reach internal services or metadata it does not need.

2. Patch management and continuous verification. Inventory components (SBOM), track CVEs, and patch on a cadence (ties to A06). Verify continuously: header scanners (securityheaders.com<sup>[[6]](#ref6)</sup>, Mozilla Observatory<sup>[[7]](#ref7)</sup>), CSP evaluators, TLS scanners (SSL Labs, `testssl.sh`<sup>[[8]](#ref8)</sup>), and IaC/cloud policy scanners (Checkov, tfsec, ScoutSuite, Prowler) in CI, plus content discovery for exposed `.git`/`.env`/actuator/backups. Treat configuration as code that gets reviewed, tested, and fails the pipeline on regression.

3. Trusted Types against DOM XSS. Invariant enforced: no DOM sink (`innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string, ...)`, `Element.setAttribute` on `src`/`href` for scripts) accepts a raw string; it must receive a `TrustedHTML`, `TrustedScript`, or `TrustedScriptURL` produced by a registered `TrustedTypePolicy`. Enable with `Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default myPolicy`. Why it works: DOM XSS is normally a whack-a-mole audit of every sink; Trusted Types converts it into a policy-enforced funnel where only code paths that explicitly built a trusted value can reach a sink, and everything else throws at runtime (catchable in `Report-Only` and CSP reports). It complements a nonce/strict-dynamic policy (which handles injected `<script>` tags) by handling injected sink writes. Common wrong implementation: registering a permissive `default` policy that just returns the input string unchanged, which defeats the enforcement entirely; the correct pattern is to funnel through framework sanitizers (for example DOMPurify returning `TrustedHTML`) and reject anything not going through them. Rollout: `Report-Only` first, fix violations, then enforce. Browser support is Chromium-only today, so it is defense-in-depth, not a portable primary control.

4. Subresource Integrity for pinned third-party assets. Invariant enforced: a `<script>` or `<link rel="stylesheet">` from a third-party origin refuses to execute unless the fetched bytes hash to a value the page pinned in advance: `<script src="https://cdn.example/lib.js" integrity="sha384-..." crossorigin="anonymous">`. Why it works: this is the control against a compromised or swapped CDN asset (attacker replacing `lib.js`, a supply-chain compromise of a shared bucket) that a `script-src` allowlist alone cannot detect. SRI requires CORS (the `crossorigin` attribute and a permissive `Access-Control-Allow-Origin` on the CDN response) because the browser must read the bytes to hash them. Common wrong implementation: trying to apply SRI to dynamically-loaded chunks whose contents change per deploy (webpack output, tag-manager injections), where the hash cannot be pinned ahead of time; treat SRI as protection for pinned vendor libraries and pair it with a CSP `script-src` that limits which origins can load at all. Regenerating and shipping hashes on every deploy is a CI step, not a manual one.

## Interviewer probes

Mid: "You've added a strict CSP and SameSite cookies. Does that mean XSS and CSRF are fixed?"

Principal: No, and claiming a header "fixes" either bug is the tell of a shallow answer. CSP mitigates XSS by constraining what an injected script can do, but the real fix is contextual output encoding at the point data is rendered; CSP is the safety net for when encoding is missed somewhere. SameSite mitigates CSRF by withholding the cookie on cross-site requests, but the primary fix is still anti-CSRF tokens on state-changing endpoints, because SameSite has gaps (same-site isn't same-origin, and `Lax` still allows top-level GET navigations). A strong answer names both layers, the header and the actual fix underneath it, and doesn't stop at the header.

Mid: "We just added HSTS with preload. Are we now protected against SSL-stripping on every visit?"

Principal: Not the very first one. HSTS only kicks in once the browser has seen the header at least once over HTTPS, so a user's first-ever connection to your domain is still vulnerable to a downgrade before that header ever arrives, unless you've submitted the domain to the HSTS preload list baked into browsers themselves. And `preload` is close to irreversible in practice: once you're in browser preload lists, getting removed takes a long time and affects every subdomain under `includeSubDomains`, so it's a durable commitment to HTTPS everywhere, not a quick toggle you flip and walk back.

Mid: "Should we set `X-XSS-Protection: 1` to enable the browser's built-in XSS filter?"

Principal: No, that instinct is backwards. The legacy `X-XSS-Protection` auditor is deprecated in modern browsers and has itself been implicated in vulnerabilities, its filtering behavior could in some cases be abused to infer page content. The correct setting is `X-XSS-Protection: 0`, explicitly disabling it, and relying on CSP as the actual mitigation layer. A candidate who reflexively wants to "turn on" a security-sounding header without knowing what it currently does is exactly the gap this question is designed to surface.

Mid: "The response has `Cache-Control: no-cache` on a page with sensitive account data. Is that sufficient?"

Principal: No, and that's a common mix-up. `no-cache` does not mean "do not cache," it means "revalidate with the server before reusing a cached copy," so the sensitive response can still sit in a cache or browser history, it just can't be served again without a round-trip check. `no-store` is the directive that actually forbids storage entirely, which is what you want for anything sensitive. Confusing the two leaves a sensitive response sitting somewhere it can potentially be retrieved from, cache or disk, even though the name "no-cache" sounds like the stricter option.

Mid: "What actually stops an attacker on a subdomain, or an on-path HTTP attacker, from overwriting our session cookie?"

Principal: The `__Host-` cookie prefix, and it's worth being precise about why it works: this is browser-enforced integrity, not obscurity. A browser only accepts a `Set-Cookie` with the `__Host-` prefix if it carries `Secure`, has no `Domain` attribute at all (so it's locked to the exact host, never shared to subdomains), and `Path=/`. Any `Set-Cookie` claiming that prefix without meeting all three is rejected outright by the browser itself, which is what stops cookie tossing from a compromised or malicious subdomain, or fixation from a network attacker sitting on plain HTTP. The security guarantee comes from browser enforcement of the naming convention, not from the name being hard to guess.

Mid: "The Actuator endpoint and the debug console are only reachable from our internal network. Is that acceptable in production?"

Principal: No, "it's internal" is not a control on its own. Werkzeug and Django/Flask debug consoles are remote code execution, not just information disclosure, and actuator endpoints like `/heapdump` can leak in-memory secrets and session tokens outright. Internal-only placement is routinely defeated by SSRF (the app itself becomes the internal caller), request misrouting, or a single misconfigured ingress rule, any of which hands an external attacker a path to something that was only ever supposed to be reachable from inside. Debug and management surfaces get disabled or authenticated in production regardless of where they sit on the network, because network placement is not the security boundary people assume it is.

Mid: "A stack trace leaked a dependency version and an internal file path, but no credentials. Is that a real finding?"

Principal: Yes, treat it as one, not as noise. An informative error is a partial exploit: the version string lets an attacker match it against known CVEs directly, and the internal path or SQL fragment tells them exactly what technology and structure they're up against, accelerating whatever comes next. It's not the whole breach, but it's the reconnaissance step that makes the rest of the attack faster and more targeted, which is exactly why generic error pages paired with detailed server-side logging, not "no credentials leaked, so we're fine", is the correct pattern.

Mid: "Our security-headers scan against the homepage came back clean. Are we covered everywhere?"

Principal: Only if you actually verified every response, not just the happy path on origin. A header set only via an nginx `add_header` without `always`, or an Apache directive scoped to `onsuccess` rather than `always`, silently disappears on error and redirect responses, leaving exactly the pages an attacker is most likely to interact with unprotected. CDNs and reverse proxies compound this: they can strip or override headers between your origin and the browser, so a header present at origin isn't proof it reaches the client. Verify at the actual edge the browser sees, across 200s, 4xx, 5xx, and redirects, not just a single scan of the homepage.

## Sources

<a id="ref1"></a>[1] OWASP Top 10 A05:2021, "Security Misconfiguration". Retrieved 2026. https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/

<a id="ref2"></a>[2] OWASP, "HTTP Security Response Headers Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

<a id="ref3"></a>[3] OWASP, "Content Security Policy Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

<a id="ref4"></a>[4] OWASP, "HTTP Strict Transport Security Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

<a id="ref5"></a>[5] OWASP, "Clickjacking Defense Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

<a id="ref6"></a>[6] securityheaders.com, HTTP header scanner. Retrieved 2026. https://securityheaders.com/

<a id="ref7"></a>[7] Mozilla Observatory, HTTP header and TLS scanner. Retrieved 2026. https://observatory.mozilla.org/

<a id="ref8"></a>[8] testssl.sh, TLS/SSL configuration scanner. Retrieved 2026. https://testssl.sh/

<a id="ref9"></a>[9] OWASP, "Secure Headers Project". Retrieved 2026. https://owasp.org/www-project-secure-headers/
