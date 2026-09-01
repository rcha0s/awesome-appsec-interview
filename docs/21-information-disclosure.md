# Information Disclosure

> Information disclosure (information leakage) is when an application unintentionally reveals data to someone who should not have it: other users' data, business secrets, or technical detail about the stack, filesystem, and internal architecture. The root-cause mental model is that a response is a side channel: beyond the intended body, an application leaks through error verbosity, headers, timing, response-length and status deltas, forgotten files, and content it never meant to publish. Most single leaks are low severity on their own; their real danger is compounding. Leaked technical detail (a framework name and version, a directory layout, a stack trace, a snippet of source) is the reconnaissance that turns a blind guess into a targeted exploit, mapping a fingerprint to a known CVE or handing an attacker the exact parameter names, table names, and file paths needed to drive SQL injection, deserialization, or path traversal. The senior skill is not "find a leak" but judging which leak is actually sensitive and demonstrating how it feeds a concrete follow-on attack.

**Interview frequency:** Common

*See also: [Privacy Engineering and Data Protection](99-privacy-engineering.md) for data minimization, de-identification, and LINDDUN's linkability and identifiability categories behind many disclosure risks.*

## How it works / Where it arises

PortSwigger groups the origins into three buckets<sup>[[1]](#ref1)</sup>:

- Failure to remove internal content from public content: developer comments left in markup, debug endpoints shipped to production, internal hostnames in config, TODO notes hinting at hidden functionality.
- Insecure configuration of the site and its third-party technologies: verbose error pages left on, directory listing enabled, diagnostic methods like TRACE enabled, default pages and default credentials, dangerous defaults in a framework whose options nobody fully understood.
- Flawed design and behavior: responses that differ measurably between two internal states (valid versus invalid username, authorized versus forbidden versus nonexistent resource), turning the application itself into an oracle.

The consequence is that the same HTTP exchange carries more than the intended answer. A 500 with a stack trace names the template engine and its version. A response that is 4 bytes longer for a valid username than an invalid one enumerates accounts. A `Server` banner and an `X-Powered-By` header fingerprint the stack. A `.git` directory served as static files hands over the whole revision history. None of these required breaking anything; the application volunteered them.

Severity is contextual and this is the part interviewers probe. Leaking customer credit-card numbers is high severity by itself. Leaking "we run nginx" is near-zero unless it is old and vulnerable. The discipline is to treat technical disclosure as a lead, not a finding: it matters when you can show it enables something harmful (a version that maps to a public exploit, a table name that unblocks blind SQLi, a hardcoded key that unlocks another endpoint). The obvious exception is when the leaked data is so sensitive that exposure alone is the impact.

## Quick reference

```
POST /login  username=alice&password=x   -> "Invalid password"     (user exists)
POST /login  username=zzzzz&password=x   -> "Invalid username"      (user does not)
# Identical-looking error flows still leak: the choice of which message fires
# (or a few bytes of Content-Length, or response time) enumerates valid accounts.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Error responses never differ between two internal states that should look identical from the outside | Centralized error handling, uniform 404/response policy | "File not found" versus "access denied", or a valid versus invalid username, produce measurably different text, status, length, or timing, turning the app into an oracle | <sup>[[3]](#ref3)</sup> |
| Stack traces, SQL text, and framework debug output never reach the client | Centralized exception handling with server-side correlation-ID logging | An unhandled exception on a type-violating input returns a raw stack trace naming the language, ORM, database, and internal file paths | <sup>[[3]](#ref3)</sup> |
| Debug consoles and diagnostic toggles are off in production and cannot be re-enabled via any request parameter | Release-gate checklist / framework debug-mode flag | Django `DEBUG=True`, Werkzeug's interactive console, or a `?debug=true` parameter renders settings, environment variables, and a live Python evaluator | <sup>[[1]](#ref1)</sup> |
| VCS metadata, dotfiles, backups, and temp files are never deployed into the web root | Build pipeline (`.gitignore`/`.dockerignore`) plus edge denial (WAF/CDN) | `.git/HEAD` and `.git/config` served as static files let `git-dumper` reconstruct the full source and commit history; `index.php~`/`config.php.bak` served as plaintext exposes the source the executed file would normally hide | <sup>[[1]](#ref1)</sup> |
| A disclosed version string is treated as a lead, not a finding, until it maps to an unpatched CVE | Severity-triage discipline / patch cadence | `Server: Apache/2.4.49` names an exact, unpatched version with a public path-traversal exploit | <sup>[[2]](#ref2)</sup> |
| API schema and introspection are disabled or authenticated in production | GraphQL introspection flag / Swagger-OpenAPI publication gate | An introspection query or a public `/swagger.json` hands over every route, parameter, type, and hidden admin operation in a single request | <sup>[[4]](#ref4)</sup> |

## Attack techniques

### 1. Verbose error messages and stack traces

Force an error and read what the framework volunteers. Send a wrong type, an over-long value, a malformed parameter, or a missing field and watch for an unhandled exception. A stack trace typically names the language, framework, template engine, ORM, database, library versions, absolute file paths, and sometimes SQL fragments or class names.

```
GET /product?productId=x' HTTP/2      # non-numeric where an int is expected
-> 500: java.sql.SQLException: ... at com.shop.ProductDao.load(ProductDao.java:88)
   org.postgresql.util.PSQLException: ERROR: invalid input syntax for type integer
```

Why it works: the app has no generic error handler, so the runtime's default debug output reaches the client. Detection: fuzz each parameter with type-violating and boundary inputs (Burp Intruder with grep-match rules for `error`, `SQL`, `SELECT`, `Exception`, `at `, `Traceback`) and compare which error case you hit; even the choice of error is information.

### 2. Debug pages and diagnostic consoles

Frameworks ship debug UIs that must never reach production: Django `DEBUG=True` renders settings, installed apps, and a full traceback with local variables; Flask/Werkzeug's interactive debugger exposes a Python console (RCE) if the PIN is bypassed or disabled; Spring Boot Actuator endpoints (`/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`) leak environment variables, secrets, and route maps; Rails leaks routes and exception detail. Probe for them directly:

```
GET /actuator/env HTTP/2
GET /actuator/heapdump HTTP/2        # binary heap dump, grep it for secrets/tokens
GET /debug HTTP/2
GET /?debug=true HTTP/2              # some apps toggle verbosity on a parameter
```

These leak session-variable values you can influence via input, back-end hostnames and credentials, on-disk file and directory names, and keys used to encrypt client-transmitted data.

### 3. Technology fingerprinting via banners and headers, mapped to CVEs

Read `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, framework-specific cookies (`JSESSIONID`, `PHPSESSID`, `laravel_session`, `csrftoken`), and characteristic 404/error markup. A precise version is the pivot: look it up against public advisories and, if unpatched, apply a documented exploit.

```
HTTP/2 200
Server: Apache/2.4.49 (Unix)          # CVE-2021-41773 path traversal / RCE
X-Powered-By: PHP/5.6.40
X-Generator: Drupal 7 (https://www.drupal.org)
```

Why it matters: disclosure that "a website is using a particular framework version is of limited use if that version is fully patched" but becomes significant on an old, known-vulnerable version, at which point exploitation can be as simple as running a public PoC<sup>[[2]](#ref2)</sup>. Confirmation: cross-check several signals (banner, cookie name, error page, static asset paths) since any one can be spoofed.

### 4. Source maps and client-side source recovery

Production JavaScript bundles often ship (or reference) `.map` files that reconstruct original, unminified source, comments, internal API routes, feature flags, and sometimes secrets. Look for a `//# sourceMappingURL=` trailer or just append `.map`:

```
GET /static/js/main.4f2a.js.map HTTP/2
-> full original TypeScript/React source, internal endpoint names, hidden admin routes
```

This is a fast route to hidden endpoints and to understanding client-side auth logic you can then bypass server-side.

### 5. Exposed version-control directories (`.git`, `.svn`, `.hg`)

When a repo is deployed and the VCS metadata is served as static files, the entire history is recoverable. Even without directory listing, `.git` has a known internal structure you can walk (`/.git/HEAD`, `/.git/config`, `/.git/index`, packed objects), and tools like git-dumper reassemble the working tree offline.

```
GET /.git/config HTTP/2       # confirms exposure, may leak remote URLs/creds
GET /.git/HEAD HTTP/2
# then: git-dumper http://target/.git ./loot  -> full source + commit diffs
```

The diff between commits leaks small code snippets and, frequently, secrets that were committed and later "removed" but remain in history.

### 6. Environment and config file exposure (`.env`, `web.config`, `application.yml`, `wp-config.php~`)

Deployment mistakes leave secrets-bearing config readable:

```
GET /.env HTTP/2
-> DB_PASSWORD=..., AWS_SECRET_ACCESS_KEY=..., STRIPE_SECRET_KEY=..., JWT_SECRET=...
```

These are often the single highest-impact leak because the data is directly sensitive (credentials, signing keys) rather than merely a lead.

### 7. Backup and temporary files, and source disclosure by extension trick

Editors and deploy scripts create siblings: `index.php~`, `config.php.bak`, `app.js.old`, `login.jsp.orig`, `.swp`, `db.sql`, archive dumps (`backup.zip`, `www.tar.gz`). When a server executes `.php` but serves `.php~` or `.php.bak` as plain text, requesting the backup returns the source code the executed file would normally hide.

```
GET /cgi-bin/loadProduct.php~ HTTP/2   # served as text, not executed -> reveals source + hardcoded creds
```

Source access is a force multiplier: it exposes hardcoded API keys and DB credentials and makes otherwise near-impossible bugs (like insecure deserialization) tractable.

### 8. Directory listing

A directory with no index page can be configured to list its contents, letting an attacker enumerate resources and jump straight to sensitive files (temp files, crash dumps, backups) that were never linked. Listing is not itself a vulnerability, it becomes one when combined with missing access control on the files it reveals.

```
GET /uploads/ HTTP/2    -> Index of /uploads: invoice_0912.pdf, db_backup.sql, .env.bak
```

### 9. Developer comments and metadata

HTML/JS comments, though not rendered, are trivially read in the response or via Burp's Find comments engagement tool. They hint at hidden directories, disabled features, credentials, or application logic. Metadata is the broader family: EXIF geolocation in uploaded images, author/path data in generated PDFs and Office documents, internal hostnames in email headers, and build identifiers.

```html
<!-- TODO: remove before prod. Admin panel moved to /internal/admin-v2 -->
<!-- default creds still admin:Passw0rd! on staging -->
```

### 10. API schema over-exposure: Swagger/OpenAPI and GraphQL introspection

A published spec or an introspectable GraphQL endpoint hands an attacker the full attack surface: every route, parameter, type, and sometimes internal/admin operations not exposed in the UI.

```
GET /swagger.json HTTP/2
GET /api/openapi.json HTTP/2
GET /v2/api-docs HTTP/2

POST /graphql  {"query":"{__schema{types{name fields{name}}}}"}   # full introspection
```

Why it matters: it converts blind API guessing into a complete map, including mutations and fields the front end never calls.

### 11. Response-differential and enumeration oracles (verbose diff between valid and invalid)

The application need not print a secret to leak one; a measurable difference between two internal states is enough. Different responses for "file not found" versus "access denied" reveal which resources exist (and the directory structure) even though the user was never supposed to know. Different login responses (message text, status code, response length, or timing) for a valid versus invalid username enumerate accounts. This is the same oracle mechanic that powers boolean-blind SQL injection and username enumeration.

```
POST /login  username=alice&password=x   -> "Invalid password"     (user exists)
POST /login  username=zzzzz&password=x   -> "Invalid username"      (user does not)
# even identical text can differ in Content-Length or response time
```

Detection: with Burp Intruder, diff status, length, and time across a username list; a consistent delta is the leak.

### 12. Timing side channels

When content does not differ but processing time does, time is the oracle. A password check that returns faster for a nonexistent user (skips the hash), a lookup that is slower when a record exists, or a non-constant-time token comparison all leak boolean state through latency. Baseline the endpoint, then measure many samples to separate signal from jitter.

### 13. TRACE, OPTIONS, and other diagnostic methods

TRACE, if enabled, echoes the exact received request, which can reveal internal headers a reverse proxy injects (for example an internal auth header or a real-client-IP header), disclosing the trusted-header names an attacker might later spoof. OPTIONS enumerates allowed methods and can surface unexpected verbs (PUT, DELETE, PATCH, WebDAV methods) that widen the attack surface.

```
TRACE / HTTP/1.1
Host: target
-> 200, echoes request including "X-Internal-Auth: ..." added by the proxy

OPTIONS /api/orders HTTP/2  -> Allow: GET, POST, PUT, DELETE
```

### 14. Cache and infrastructure header leakage

Response headers leak internal topology and behavior: `X-Cache`/`Age`/`X-Served-By` reveal CDN/cache tiers, `Via` and `X-Forwarded-*` reflections expose proxy chains and internal IPs, `X-Backend-Server` names origin hosts, and detailed `Set-Cookie` attributes or framework cookies fingerprint the stack. Caching misconfiguration is also a disclosure vector: a `Cache-Control: public` on an authenticated, user-specific response can cause a shared cache to serve one user's data to another.

### 15. User-account and object endpoints that leak across the trust boundary

A profile page keyed on a `user` parameter (`GET /user/personal-info?user=carlos`) may block loading another user's whole page yet still render an individual field (email, phone, API key) without checking the parameter matches the session, leaking that field for arbitrary users. This is the seam where information disclosure meets access control / IDOR.

## Defense

### Real fix

1. Return generic errors through centralized handling. The real fix for the largest source of leakage: catch exceptions in one place, log full detail server-side with a correlation ID, and return a generic message plus that ID to the user. Never let stack traces, SQL text, or framework debug output reach the client. Make error handling consistent so that "file not found" and "access denied" cannot be distinguished (fail closed, and prefer a uniform 404 for both nonexistent and forbidden resources where that fits the model). OWASP's core point: a documented error-handling policy, applied uniformly, that gives the user a helpful-but-opaque message, the maintainer diagnostics, and the attacker nothing<sup>[[3]](#ref3)</sup>.

2. Disable debug and diagnostic features in production. Turn off framework debug modes (`DEBUG=False`, no Werkzeug/Whoops/Symfony profiler), lock down or remove Spring Boot Actuator and similar consoles behind auth or entirely, disable TRACE and unneeded HTTP methods, and confirm none of it is toggleable via a request parameter. Treat "is debug off in prod" as a release-gate checklist item.

3. Block VCS metadata, dotfiles, backups, and temp files at the edge. Deny access to `.git`, `.svn`, `.hg`, `.env`, `*.bak`, `*.old`, `*~`, `*.orig`, `*.swp`, and archive/dump extensions at the web server or WAF/CDN, and better, do not deploy them at all (build artifacts only, `.gitignore`/`.dockerignore` discipline, no editor backups on the server). Serve unknown extensions as downloads or 404 rather than as plain text so the backup-file source trick fails.

4. Remove internal content from public output as a build step. Automate stripping of HTML/JS comments and dead debug code in the build/QA pipeline, scrub metadata from uploaded and generated files (EXIF, document properties), and scan for secrets in code and history (pre-commit hooks, CI secret scanning) so keys never ship in source or `.git`.

5. Minimize API schema and introspection exposure. Disable GraphQL introspection in production, do not serve Swagger/OpenAPI specs publicly (or gate them behind auth), and ensure documented-but-internal operations are also authorization-enforced, since hiding the spec is not access control.

6. Close differential and timing oracles. Return identical responses (text, status, and length) for valid and invalid usernames and for existent versus forbidden resources; use constant-time comparisons for secrets and tokens; and add uniform artificial work or rate limiting where a timing gap is unavoidable. Set correct cache headers (`Cache-Control: private, no-store` on authenticated responses) and a `Vary` policy so shared caches never serve user-specific data to the wrong user.

### Defense in depth

1. Strip version banners and client-exposed source. Remove or genericize `Server`, `X-Powered-By`, `X-AspNet-Version`, and similar headers; do not publish source maps to production (or restrict them to authenticated internal use); and keep the underlying software patched, because the durable defense against fingerprint-to-CVE is not hiding the version but not being vulnerable at that version. Obscuring the banner is defense in depth, not a fix.

2. Enforce least privilege and access control on the data itself. Even with generic errors, an unauthenticated `/.env` or an IDOR-leaked field is the real problem, so authorize every field-level fetch against the session, apply least-privilege DB accounts so a leaked credential is bounded, and monitor for repeated error-inducing or enumeration-style probing (few apps detect web attacks at all, so this materially improves detection).

## Interviewer probes

**You found the app exposes its `Server` header with a version number. Is that a finding?**

Mid: Log it and check whether the version is current. If it's outdated it's worth flagging, but a fully patched version by itself usually isn't a real finding.

Principal: Only conditionally, and stating it as a bare finding is the junior tell. Treat technical disclosure as a lead, not a finding: the disclosure of technical information is often only of interest if you can demonstrate how an attacker could do something harmful with it. A version number matters only if it's unpatched and maps to a public exploit; a table or column name matters because it unblocks blind SQL injection; a stack trace matters because it names the deserialization library in use. Report the impact and exploitability chain, not the mere presence of a banner.

**How do you decide severity when triaging a pile of disclosure findings?**

Mid: I look at whether the exposed data is sensitive on its own, like credentials or personal data, versus just technical metadata like a framework name, and rate the former much higher.

Principal: Split by whether the data is directly or indirectly sensitive. Directly-sensitive data (PII, card numbers, credentials, private keys, session tokens) is high severity on exposure alone, no follow-on required. Indirectly-sensitive data (framework/version, directory layout, internal hostnames, parameter names) is a lead whose value depends entirely on what it enables. Don't inflate the second class into a critical finding on its own, but don't dismiss it either. It's frequently the missing puzzle piece for a high-severity chain elsewhere in the assessment.

**Walk me through a real disclosure-to-exploit chain, start to finish.**

Mid: A verbose error message can leak a table or column name that you then use to build a more targeted SQL injection payload against that endpoint.

Principal: A verbose SQL error names table and column names, which turns blind SQL injection into targeted injection. A backup file or an exposed `.git` directory hands over source code, which surfaces hardcoded API keys and a roadmap into a deserialization bug that would otherwise be near-impossible to find black-box. A source map hands over hidden admin routes, which becomes an access-control test. A banner and error page fingerprint a framework version, which maps to a CVE and a public PoC. None of those individual leaks is exploitation on its own; the chain is the finding.

**The app returns a generic error message on every failure path. Is it safe from information disclosure?**

Mid: Generic error text is a good sign since it means stack traces and internals aren't leaking, but I'd still want to confirm the status codes are consistent across cases too.

Principal: Not necessarily. Even identical-looking error text can leak through the choice of which error case fired: distinct 404-versus-403 behavior, or a difference of a few bytes in response length, or timing, is itself an oracle. The fact that one error case was encountered instead of another is useful in itself, the same mechanic as boolean-blind injection and username enumeration. Fixing the message text isn't enough; the fix is consistency, fail closed, and uniform responses across both the true and false case.

**What's the modern leak junior testers consistently miss?**

Mid: Source maps. A lot of testers forget to check for exposed `.js.map` files, which can reveal the original, unminified frontend source.

Principal: Source maps and GraphQL introspection. Both hand over the full internal map in a single request: a `.js.map` file reconstructs original unminified source, internal API routes, and feature flags; a GraphQL introspection query returns every type, field, and mutation, including ones the front end never calls. Either one converts black-box guessing into white-box targeting immediately, which is why they're worth checking on every engagement even when nothing else looks promising.

**Is caching itself an information-disclosure risk, or just a performance concern?**

Mid: Mostly performance, but headers like `X-Cache` or `Via` can leak some infrastructure details, so it's worth glancing at during recon.

Principal: Both directions matter. Cache and infrastructure headers (`X-Cache`, `Age`, `X-Served-By`, `Via`) leak internal topology, proxy chains, and internal IPs on their own. Separately, a `Cache-Control: public` on an authenticated, user-specific response can cause a shared cache to serve one user's data to another, which is the boundary case with web cache deception. Set correct cache headers (`private, no-store` on authenticated responses) and treat the header surface itself as something an attacker fingerprints during reconnaissance.

## Sources

<a id="ref1"></a>[1] PortSwigger Web Security Academy, "Information disclosure vulnerabilities". Retrieved 2026. https://portswigger.net/web-security/information-disclosure

<a id="ref2"></a>[2] PortSwigger Web Security Academy, "How to find and exploit information disclosure vulnerabilities". Retrieved 2026. https://portswigger.net/web-security/information-disclosure/exploiting

<a id="ref3"></a>[3] OWASP, "Improper Error Handling". Retrieved 2026. https://owasp.org/www-community/Improper_Error_Handling

<a id="ref4"></a>[4] OWASP Web Security Testing Guide, "Testing for Error Handling and Information Leakage". Retrieved 2026. https://owasp.org/www-project-web-security-testing-guide/
