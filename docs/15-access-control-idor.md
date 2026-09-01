# Broken Access Control and IDOR

> Authentication answers "who are you"; access control answers "are you allowed to perform this action, on this specific object, in this state". Broken access control is the application enforcing the first question and skipping, fumbling, or trusting the client for the second. The root cause is almost always the same shape: an authorization decision that depends on data the attacker controls (an ID in the path, a role in a cookie, a claim in a JWT, the fact that a URL "isn't linked anywhere") instead of a server-side check that binds the authenticated principal to the requested resource and operation. It is OWASP Top 10 A01:2021, the category with the most occurrences in the contributed dataset (over 318,000 across 34 mapped CWEs and roughly 19,000 CVEs), and it is invisible to scanners that do not know the application's intended policy. The durable fix is invariant: deny by default, enforce server-side, authorize per object and per function on every request.

**Interview frequency:** Core

*See also: [Authorization](97-authorization.md) for the RBAC/ABAC/ReBAC model families and PDP/PEP placement behind the ownership checks this doc requires, and [Multi-Tenancy and Isolation](102-multi-tenancy-isolation.md) for the data-layer backstop against cross-tenant IDOR when application checks are skipped.*

*See also: [File Upload and Storage Security](103-file-upload-storage-security.md) for presigned-URL and object-store access-control design specifically, direct object reference applied to stored files rather than database rows.*

## How it works

Access control sits on top of two other mechanisms and fails when either is trusted to do authorization's job. PortSwigger frames the dependency precisely<sup>[[1]](#ref1)</sup>: authentication confirms the user is who they claim, session management identifies which subsequent requests come from that same user, and access control decides whether that user may carry out the attempted action. When the third layer is missing or leaky, an authenticated (or even anonymous) user reaches data and functions outside their intended permissions.

There are three families of controls, and the vocabulary matters in interviews.

- **Vertical access controls**: restrict sensitive functionality to specific privilege tiers (an admin can delete any account, an ordinary user cannot). Breaking these is **vertical privilege escalation**.
- **Horizontal access controls**: restrict resources of the same type to their owner (you see your own bank transactions, not another customer's). Breaking these is **horizontal privilege escalation**.
- **Context-dependent (state-based) controls**: enforce ordering and state (you cannot edit a cart after payment, cannot reach step 3 of a workflow without completing steps 1 and 2).

Precise terms for the same underlying defect across web and API worlds:

- **IDOR (Insecure Direct Object Reference)**: user-supplied input is used to access an object directly and the app authorizes on authentication alone, not ownership. The term was popularized by the OWASP 2007 Top Ten. It is one instance of a broader access-control failure, most often horizontal, sometimes vertical.
- **BOLA (Broken Object Level Authorization)**: the API name for IDOR and API1:2023<sup>[[2]](#ref2)</sup>, rated widespread prevalence and easy exploitability. The authorization violation happens at the object level by manipulating an ID.
- **BFLA (Broken Function Level Authorization)**: API5:2023<sup>[[3]](#ref3)</sup>, a missing check on the function/endpoint itself (a regular user invoking an admin-only action). BOLA is "wrong object, allowed function"; BFLA is "wrong function entirely".
- **BOPLA (Broken Object Property Level Authorization)**: API3:2023, which merged the old Excessive Data Exposure and Mass Assignment into one root cause: missing authorization at the property level, letting an attacker read fields they should not see or write fields they should not set.

The canonical vulnerable pattern is a query keyed directly on client input with no ownership predicate:

```java
// A01:2021 example: 'acct' comes straight from the request, no ownership check
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();
// GET https://example.com/app/accountInfo?acct=notmyacct  -> any account
```

```sql
-- Vulnerable: scoped only by the client-supplied id
SELECT * FROM invoices WHERE id = :id;

-- Correct: scoped to the authenticated principal as well
SELECT * FROM invoices WHERE id = :id AND owner_id = :current_user_id;
```

The mental shortcut for reviewing any endpoint: find the object being touched, then ask "where is the line of code that proves this principal owns or is permitted this object for this verb". If that line does not exist, or it checks only `isAuthenticated()`, it is broken.

## Quick reference

```
GET /customer_account?customer_number=132355   -> change to 132356
# The session proves who you are; the ID alone is trusted to prove you're
# allowed to see this record. Increment it and you're reading someone
# else's account with no ownership check performed.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Every request re-derives permission from the server-side principal, never from the mere fact of being authenticated | Central, mandatory authorization check invoked from every business function | A valid session plus a valid object ID is treated as sufficient; no line of code ever checks ownership (direct object reference swap) | <sup>[[1]](#ref1)</sup> |
| Object access is scoped by ownership (`resource.owner == currentUser`) or an ABAC/ReBAC policy, never by the difficulty of guessing the identifier | Domain-model / policy check at the point of access | Switching sequential IDs to GUIDs raises guessing cost but the object is still returned with no ownership check once a GUID leaks (unpredictable IDs are not authorization) | <sup>[[2]](#ref2)</sup> |
| Data-layer queries carry an `owner_id`/`tenant_id` predicate, not just an application-layer `if` check | Persistence-layer query (`WHERE owner_id = :currentUser AND tenant_id = :currentTenant`) | A query scoped only by a client-supplied tenant/shop identifier returns another tenant's data (cross-tenant IDOR) | <sup>[[2]](#ref2)</sup> |
| Request bodies bind only to an allowlisted DTO, never directly to the persistence model | Controller/serialization layer (strong params, `@InitBinder` allowlist, `$fillable`) | Extra JSON fields (`isAdmin`, `role`, `balance`) get silently persisted because the controller autobinds straight to the domain model (mass assignment / BOPLA) | <sup>[[4]](#ref4)</sup> |
| Function-level (role) gating is enforced centrally and applies uniformly across verbs, paths, and encodings | Admin abstract controller / centralized middleware, path-normalized before matching | HTTP verb tampering, method-override headers, and path-normalization discrepancies let a request reach an admin route the front-end control never matched | <sup>[[3]](#ref3)</sup> |
| The authorization check and the state-changing write happen in a single atomic transaction, not a separate preflight read | `SELECT ... FOR UPDATE` or a conditional `UPDATE ... WHERE owner_id=:u AND status='paid'`, treating zero affected rows as denial | A permission read and a later write are separated by a window a concurrent request can race through (TOCTOU) | <sup>[[6]](#ref6)</sup> |
| Object-level checks run per array/batch item, not once for the whole request | Batch/GraphQL resolver-level authorization, re-checked per item or field | Batch endpoints and GraphQL aliases authorize only the top-level operation, so mixing your own IDs with victim IDs slips unauthorized items through the loop | <sup>[[2]](#ref2)</sup> |

## Attack techniques

### 1. Direct object reference swap (horizontal IDOR / BOLA)

The endpoint exposes an object identifier and returns or mutates that object with no ownership check. Increment, decrement, or substitute the ID.

```http
GET /customer_account?customer_number=132355 HTTP/1.1
Host: shop.example.com
Cookie: session=<your-own-valid-session>
```

Change `customer_number` to `132356` and read another customer's record. The same applies to static files behind an incrementing name (`/static/12144.txt` for chat transcripts) and to any query-string, path, body, JSON field, cookie, or custom header carrying the reference. **Why it works**: the server treats the ID as both the locator and the authorization token, so possession of a valid session plus a valid ID equals access. Detection: two-account differential testing (below); a `200` with someone else's data confirms it.

### 2. Unpredictable IDs are not authorization (GUIDs, hashes)

Switching sequential integers to GUIDs raises guessing cost but is security by obscurity, not access control. Other users' GUIDs frequently leak through messages, reviews, audit trails, `included` relationships in JSON:API responses, email footers, or a separate listing endpoint. Once leaked, the object is accessed exactly as in technique 1. Also watch the redirect-with-body pattern: the server detects the violation and returns a 302 to the login page, but the response body still contains the target user's data before the redirect is honored.

### 3. Blind IDOR (write-only actions confirmed by side effect)

Actions that mutate but return nothing sensitive (delete, add-collaborator, transfer, invite) are still IDOR; you confirm via side effects, not response body.

```http
POST /graphql HTTP/1.1
Content-Type: application/json

{"operationName":"deleteReports",
 "variables":{"reportKeys":["<VICTIM_DOCUMENT_ID>"]},
 "query":"mutation deleteReports($reportKeys:[String]!){ deleteReports(reportKeys:$reportKeys) }"}
```

If the victim's document disappears with no further permission check, it is BOLA. **Confirmation without a body**: observe the effect out-of-band (the object 404s afterward, an email fires, a counter changes), diff a follow-up read as the victim, or time the response.

### 4. Second-order and chained IDOR

An identifier returned by one endpoint (which you are allowed to call) is fed into a second endpoint that forgot the check. Example: a batch-status endpoint hands you internal job IDs across tenants, and a details endpoint resolves any job ID without scoping. Horizontal IDOR can also be escalated to vertical: read or reset a more privileged user's account via `?id=456`, and if 456 is an administrator you inherit admin capability (horizontal-to-vertical escalation).

### 5. Mass assignment / autobinding / object injection (property-level, BOPLA)

Frameworks that auto-bind request bodies to model fields let an attacker set properties the UI never exposed. Alternative names by ecosystem: **Mass Assignment** (Rails, Node.js), **Autobinding** (Spring MVC, ASP.NET MVC), **Object injection** (PHP), mapped to CWE-915.

```http
POST /api/users/me HTTP/1.1
Content-Type: application/json

{"username":"alice","email":"alice@x.com","isAdmin":true,"balance":999999,"role":"admin","emailVerified":true}
```

The server binds `isAdmin`, `role`, `balance`, and `emailVerified` because the controller bound straight to the persistence model. **Exploitability** (per OWASP)<sup>[[4]](#ref4)</sup> rises when the attacker can guess common sensitive field names or read the model source, and when the object has an empty constructor. **Real case**: in 2012 GitHub was compromised via mass assignment<sup>[[5]](#ref5)</sup>; a user added their public key to an arbitrary organization, gaining commit access to its repositories. Detection: submit extra fields (`isAdmin`, `verified`, `owner_id`, `tenant_id`, primary keys) and diff the resulting object; success is a privilege or ownership field that changed.

### 6. Forced browsing to unprotected functionality (vertical)

Sensitive functionality protected only by not linking it. `/admin` is reachable directly; the URL may leak in `robots.txt`, in JavaScript that conditionally renders an admin link, or via wordlist content discovery even when obfuscated (`/administrator-panel-yb556`).

```javascript
// Leaks the admin URL to every user regardless of role
var isAdmin = false;
if (isAdmin) { adminPanelTag.setAttribute('href','https://site/administrator-panel-yb556'); }
```

**Why it works**: "the menu does not show it" is client-side hiding, not server-side authorization. CWE-425 (Direct Request / Forced Browsing).

### 7. Parameter-based role trust (vertical)

The app determines the role at login and stores it somewhere the user controls: a hidden field, a cookie, a preset query parameter, or a JWT/other claim the client can alter.

```http
GET /login/home.jsp?admin=true HTTP/1.1
GET /login/home.jsp?role=1 HTTP/1.1
```

Set `admin=true`, `role=admin`, `isAdmin: true` in a cookie, or flip a `role` claim (JWT alg confusion, weak secret, or a server that trusts an unsigned header like `X-Original-Role`). Client-supplied privilege is escalation by definition.

### 8. HTTP verb tampering and method override (vertical / platform)

Platform rules often bind to a specific method and path, for example `DENY: POST, /admin/deleteUser, managers`. If the app still performs the action for another method, or honors an override header, the gate is bypassed.

```http
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
X-HTTP-Method-Override: DELETE
```

Some frameworks honor `X-Original-URL` and `X-Rewrite-URL` to rewrite the path the front-end control matched, or perform a `GET`-style read of a `POST`-gated action. Also test the plain method swap: an endpoint checked for `GET` but not `PUT`/`DELETE` (A01: "accessing API with missing access controls for POST, PUT and DELETE").

### 9. URL-matching and path-normalization discrepancies (vertical / platform)

The authorization layer and the routing layer disagree on what path a request maps to.

```http
GET /ADMIN/DELETEUSER            # case: gateway blocks /admin, app matches case-insensitively
GET /admin/deleteUser/           # trailing slash treated as a distinct, ungated route
GET /admin/deleteUser.anything   # Spring useSuffixPatternMatch (default before 5.3): .ext still maps
GET /admin/%2e/deleteUser        # encoded dot-segment normalized differently by proxy vs app
GET /public/..;/admin/deleteUser # Tomcat path-parameter (;) segment bypasses a prefix rule
```

**Why it works**: front-end/gateway path matching normalizes (or fails to normalize) case, suffixes, trailing slashes, `%2e`, and `;`-parameters differently from the application router, so a request the gateway believes is `/public/...` reaches `/admin/...` in the app. This is the confused-deputy shape (CWE-441) applied to routing.

### 10. Referer-based and location-based gates

If sub-pages under `/admin` are gated only by trusting the `Referer` header, forge it.

```http
GET /admin/deleteUser HTTP/1.1
Referer: https://site.example.com/admin
```

`Referer` is fully attacker-controlled, so the gate is decorative. Location-based controls (geofencing for banking or media) are circumvented with a VPN, proxy, or by manipulating client-side geolocation.

### 11. Multi-step process step-skipping (context-dependent)

A workflow enforces access control on steps 1 and 2 but assumes anyone reaching step 3 already passed them. Submit the step-3 request directly with the required parameters (a confirmation/commit endpoint) and skip the guarded steps entirely.

### 12. Cross-tenant IDOR (multi-tenant SaaS)

Access tenant B's data with tenant A's valid session because a query is scoped by a client-supplied tenant/org ID instead of the server-side tenant binding. BOLA scenario from OWASP<sup>[[2]](#ref2)</sup>: `/shops/{shopName}/revenue_data.json`, where enumerating shop names from another endpoint yields the sales data of thousands of stores. Tenant bleed also hides in shared caches, exported reports, webhooks, search indexes, and background jobs that drop the tenant filter.

### 13. Batch and bulk endpoint IDOR (array parameters, GraphQL aliases, JSON:API includes)

Many APIs accept arrays of identifiers in a single call: `POST /messages/read {ids:[...]}`, `POST /invoices/export {ids:[...]}`, `DELETE /files {keys:[...]}`, or GraphQL `nodes(ids:[...])`. The authorization check runs once at the endpoint level (the caller has a valid session and the right scope), then the handler iterates the array and processes each item without a per-element ownership check. Mixing your own IDs with victim IDs (`[myId1, victimId1, myId2, victimId2]`) is the classic bypass: the request looks legitimate on the outside, and the batch loop happily reads or mutates the other-tenant items alongside yours.

Related shapes show up across API styles. GraphQL aliases let one request fire N object fetches (`a: user(id:1) b: user(id:2) c: user(id:3)`), each of which bypasses per-request rate limits and per-request authorization middleware that only inspects the top-level operation. The Relay global-object interface, `node(id:)`, resolves any type by opaque ID and is a common single-line IDOR because resolvers assume the top-level auth already ran. JSON:API `include=` and GraphQL nested fields pull relationships across ownership boundaries when field-level resolvers do not re-authorize (a document you own including its `author` including that author's `privateNotes`).

The fix is to authorize each item in the batch against the principal, not the batch as a whole. Cap the number of items per request (both for security and to bound the auth-check work), rate-limit total objects touched per unit time rather than only requests per second, and treat every GraphQL resolver as its own authorization boundary. If the batch handler cannot cheaply re-check ownership per item, scope the underlying query with the principal's ID as an additional predicate so unauthorized items are filtered by the database rather than by application code that might forget.

### 14. TOCTOU races on authorization decisions

Time-of-check-to-time-of-use bugs appear when the authorization check reads state, the handler acts on it in a separate transaction, and an attacker races a concurrent state transition through the window between them. Classic shapes: refund or transfer an order that is being simultaneously cancelled; redeem a coupon after it has been revoked; accept a workspace invite that was just rescinded; withdraw from a balance twice by racing two `POST /withdraw` requests before the first debit commits; complete a multi-step workflow across a role change so step 3 executes with the pre-change permissions the middleware already cached.

Attackers widen the window with concurrent requests. Burp's Turbo Intruder "single packet attack" sends multiple HTTP/2 requests in the same TCP packet so they arrive within microseconds, and h2 concurrent streams let a single connection race dozens of in-flight requests. Server-side, common contributing factors are eventually consistent replicas serving the check while the write hits the primary, cache reads for the permission decision that lag the source of truth, and workflows that recompute permissions per step without a serialization guarantee across steps.

The fix is to make authorization a property of the write, not a preflight. Perform the check and the mutation in a single database transaction, taking row-level locks on the authorization-relevant rows (`SELECT ... FOR UPDATE`) or expressing the check as part of the write itself (`UPDATE orders SET status='refunded' WHERE id=:id AND owner_id=:u AND status='paid'` and treating an affected-row count of zero as a denial). Optimistic concurrency with version columns makes a lost race fail closed. For distributed state, use a coordinator (Redis lock, transactional outbox, workflow engine with idempotency keys) so the check-and-act pair is atomic across services.

### Detection methodology: two-account differential testing

The gold standard, and the answer expected for "how would you test authorization":

- Provision at least two accounts per privilege tier (userA, userB at the same level; a low-priv and a high-priv account; and an unauthenticated client).
- Capture userA's full request set. Replay each request with userB's session and userA's object IDs (cross-user read/write), then swap IDs both directions.
- Replay privileged requests with the low-priv session and with no session (vertical + unauthenticated).
- Confirm the server returns a hard denial (403/404 with no leaked body), not a 302-with-data or a silent success.
- Layer in content discovery for hidden endpoints, alternate verbs, method-override headers, path-encoding variants, and extra body fields for mass assignment. In GraphQL, test at resolver/field and `node(id:)` level, and abuse aliases/batching to bypass per-request checks.

Automated scanners are weak here because they do not know the intended policy; access control is a manual, logic-driven, code-review-heavy domain.

## Defense

Ordered by effectiveness within each group.

### Real fix

1. **Deny by default and enforce server-side on every request.** Except for intentionally public resources, deny. Make the authorization check mandatory and central, invoked from every business function, in trusted server-side or serverless code the attacker cannot modify. Validate permissions on every request regardless of source (AJAX, server-render, internal). A single missed check is a breach: "validating on the majority of requests is insufficient" (Authorization Cheat Sheet)<sup>[[6]](#ref6)</sup>.

2. **Authorize by ownership/policy, not by reference secrecy.** Enforce record ownership in the domain model: check `resource.owner == currentUser` (or an ABAC/ReBAC rule) rather than assuming an unguessable ID protects the object. Comparing the JWT user ID to the request's ID param covers only a small subset of cases; real authorization considers the user's policies and hierarchy (OWASP BOLA guidance)<sup>[[2]](#ref2)</sup>. Prefer not exposing identifiers at all: derive the object from the session/JWT where possible, or use per-user indirect references. Map to CWE-639 (Authorization Bypass Through User-Controlled Key)<sup>[[7]](#ref7)</sup>.

3. **Scope every data-layer query to the principal and tenant.** Add `WHERE owner_id = :currentUser` (and `AND tenant_id = :currentTenant` in multi-tenant systems) at the persistence layer, not just in a controller `if`. This makes cross-user and cross-tenant IDOR structurally impossible for that query even if a check is forgotten upstream.

4. **Centralize the mechanism; implement once, reuse everywhere.** Use one application-wide enforcement point rather than scattered per-endpoint checks: Jakarta EE / Spring Security filters, Django middleware, ASP.NET Core authorization filters/policies, Laravel middleware. Make administrative controllers inherit from an admin abstract controller that enforces role checks, so a new admin action cannot ship without authorization. Do not assume an endpoint is regular or admin from its URL path.

5. **Kill mass assignment with allowlists / DTOs (property-level authorization).** Bind requests to Data Transfer Objects that contain only user-editable fields; never bind straight to the domain/persistence model. Framework specifics:

   - Spring MVC: `@InitBinder` with `binder.setAllowedFields("userid","password","email")` (allowlist) or `setDisallowedFields("isAdmin")` (blocklist; allowlist preferred).
   - Rails: strong parameters (`params.require(:user).permit(:email, :name)`).
   - Laravel Eloquent: `$fillable = [...]` (allowlist) or `$guarded = ['isAdmin']` (blocklist).
   - Node.js + Mongoose: pick only safe fields, for example `_.pick(req.body, User.safeFields)`.

   Also enforce the read direction (serialize DTOs, not raw models) to prevent Excessive Data Exposure.

6. **Consistent enforcement across verbs, paths, formats, and static assets.** Apply the same authorization to every HTTP method; normalize and canonicalize paths before matching (mind case, suffix matching, trailing slashes, `%2e`, `;`-parameters); re-check at resolver/field level in GraphQL; minimize and lock down CORS (A01<sup>[[8]](#ref8)</sup> explicitly lists permissive CORS as broken access control). Do not forget static resources and cloud object storage (S3/GCS/Azure buckets): incorporate them into the access-control policy, do not leave them public by default.

### Defense in depth

1. **Least privilege, separation of duties, and step-up.** Grant the minimum roles/attributes; separate admin surfaces with independent authorization; require re-authentication or step-up for sensitive actions and after risk events. Prefer ABAC/ReBAC over pure RBAC for fine-grained, multi-tenant, object-level decisions (RBAC suffers role explosion and models ownership poorly; ReBAC, as in Google Zanzibar, natively expresses "owner of this object may edit it").

2. **Exit safely, log, alert, and rate-limit.** Fail closed on any authorization error (CWE-280), centralize failure handling, and never leak sensitive detail in the error. Log access-control failures and alert on repeated denials/enumeration (A01<sup>[[8]](#ref8)</sup> and A09). Rate-limit object access to slow ID sweeping. Invalidate server-side sessions on logout; keep stateless JWTs short-lived or follow OAuth revocation.

3. **Test authorization as first-class policy in CI.** Write unit and integration tests that assert deny-by-default, ownership enforcement, and role matrices, and fail the build when they fail. Reference OWASP ASVS V4 (Access Control), WSTG 4.5 (Authorization Testing), and Proactive Controls C7 (Enforce Access Controls). Do not deploy changes that break the authorization tests (OWASP BOLA guidance)<sup>[[2]](#ref2)</sup>.

## Interviewer probes

Mid: "We switched from sequential integer IDs to UUIDs on our object endpoints. Doesn't that close the IDOR risk?"

Principal: No, unpredictability is not authorization. OWASP recommends random GUIDs as hardening in addition to per-object checks, never as a replacement for them. Other users' GUIDs leak constantly through messages, reviews, audit trails, JSON:API `included` relationships, email footers, and separate listing endpoints, and once a GUID leaks the object is accessed exactly like a sequential ID: the request still has no ownership check behind it. The fix is still `resource.owner == currentUser` at the point of access, not the shape of the identifier.

Mid: "The endpoint checks that the caller is logged in and even compares the session's user ID to the ID in the request. Is that sufficient authorization?"

Principal: It's necessary but not sufficient, and conflating the two is the most common tell of a weak answer. Authentication confirms who the user is; it says nothing about whether that user is permitted for this object or this function. Comparing the session-user-ID to the request's ID param covers the narrow "is this my own record" case, but it misses shared objects, delegated access, org hierarchies, and role-based object permissions. Real authorization consults a policy considering the user's roles and hierarchy, not a single equality check, which is exactly why ABAC/ReBAC rules are preferred over ad hoc ID comparisons.

Mid: "What's the actual difference between BOLA and BFLA? Isn't that just API terminology for the same bug?"

Principal: It's a real distinction with different fixes, not pedantry. BOLA is "wrong object, allowed function": the caller is legitimately allowed to hit the endpoint, but the bug is that ownership of the specific object was never checked, so manipulating the ID reaches someone else's data. BFLA is "wrong function entirely": the caller should never have reached the endpoint at all, regardless of which object they name, because it's an admin or privileged action reachable by a normal user. BOLA is fixed with object-scoped ownership checks; BFLA is fixed with function or role gating, like making admin controllers inherit from an abstract controller that enforces role checks so a new admin action can't ship unauthorized. Naming which one you found, and why the fix differs, signals depth.

Mid: "You find an admin action reachable by a regular user. Whose bug is that, the application's or the platform's?"

Principal: Often it's a platform or routing bug wearing an application-security costume. URL-matching and path-normalization discrepancies (case sensitivity, trailing slashes, `%2e`, `;`-parameters) let a gateway or WAF believe a request maps to a safe path while the application router resolves it to the admin route underneath, and override headers like `X-Original-URL`, `X-Rewrite-URL`, and `X-HTTP-Method-Override` let an attacker bypass a front-end rule that only matched one method and path. The senior answer is to normalize the path once and authorize in the application tier itself, rather than trusting an edge WAF rule that a routing quirk can slip past.

Mid: "Mass assignment sounds like an input-validation bug, sending fields the API wasn't expecting. Why do you file it under broken access control?"

Principal: Because field-level validation of the fields you declared does nothing about the fields you didn't, and the ORM writes them anyway if the controller binds straight to the persistence model. Sending `isAdmin`, `role`, or `balance` in the request body isn't malformed input, it's a well-formed request for a property the UI never exposed, and the framework happily sets it. That's an access-control failure at the property level (BOPLA), not an input-shape problem, which is why the fix is an allowlist DTO, never binding directly to the domain model, rather than a smarter validator. The 2012 GitHub incident, where a user added their own public key to an arbitrary organization via mass assignment and gained commit access to its repositories, is the canonical case for why this is a privilege-escalation bug, not a hygiene nitpick.

Mid: "When a user tries to access an object they're not authorized for, should the server return 403 or 404?"

Principal: It depends on what you're protecting against, and picking one globally is the wrong answer. A 403 confirms the object exists but the caller isn't permitted, which is honest and good for audit logs, but it's also an oracle: an attacker can enumerate which IDs are real by watching for 403 versus 404. A 404 for both nonexistent and unauthorized-but-existing objects removes that oracle at the cost of debuggability. The senior split is per surface: unauthenticated callers and cross-tenant boundaries get a uniform 404 with rate-limiting on repeated 404s, while same-tenant peer denials can safely use 403. What you must never do is return 200 with an empty body or a 302-to-login with the object already serialized in the pre-redirect response, and response timing has to match between the two branches or the timing itself becomes the oracle.

Mid: "Your app authenticates and authorizes the WebSocket handshake before upgrading the connection. Are you done?"

Principal: No, that only covers the connection's opening moment. Long-lived streaming connections, WebSocket, SSE, gRPC streaming, MQTT, typically authorize once at connect and then keep the socket open for minutes or hours while message-level authorization is skipped entirely. A client can send subscribe or publish frames for other users' topics after connect, since topic names like `user:456:notifications` are IDOR keys in their own right, and a role or token revoked mid-session is still honored until the socket happens to close. The fix is to authorize every inbound frame against the principal and the requested topic, bind the connection to a short-lived token that forces reconnect on expiry or role change, and have server-side hooks consume revocation events to drop live connections.

Mid: "The request carries a valid OAuth token with an `invoices:read` scope, and it's hitting `GET /invoices/{id}`. Is that enough to authorize the read?"

Principal: No, and treating scope as authorization is a common wrong answer. Scopes are coarse capability grants: they gate which endpoints a client application is allowed to call on a user's behalf, but they say nothing about which specific objects that user owns. `invoices:read` still needs an ownership predicate binding the token's subject to that specific invoice ID, the same gap machine-to-machine API keys have ("the key has admin scope" says nothing about tenant) and delegated or impersonation tokens have (you must record and enforce the acting user, not just the principal). Real authorization consumes scope, principal, and resource together in one policy decision, not scope alone.

## Sources

<a id="ref1"></a>[1] PortSwigger Web Security Academy, "Access control vulnerabilities and privilege escalation". Retrieved 2026. https://portswigger.net/web-security/access-control

<a id="ref2"></a>[2] OWASP, "API1:2023 Broken Object Level Authorization (BOLA)". OWASP API Security Top 10. Retrieved 2026. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

<a id="ref3"></a>[3] OWASP, "API5:2023 Broken Function Level Authorization (BFLA)". OWASP API Security Top 10. Retrieved 2026. https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/

<a id="ref4"></a>[4] OWASP, "Mass Assignment Cheat Sheet". OWASP Cheat Sheet Series. Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

<a id="ref5"></a>[5] GitHub, "Public Key Security Vulnerability and Mitigation" (2012 mass assignment incident). GitHub Blog. 2012-03-04. https://blog.github.com/2012-03-04-public-key-security-vulnerability-and-mitigation/

<a id="ref6"></a>[6] OWASP, "Authorization Cheat Sheet". OWASP Cheat Sheet Series. Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

<a id="ref7"></a>[7] MITRE, "CWE-639: Authorization Bypass Through User-Controlled Key". MITRE CWE. Retrieved 2026. https://cwe.mitre.org/data/definitions/639.html

<a id="ref8"></a>[8] OWASP, "A01:2021 Broken Access Control". OWASP Top 10. Retrieved 2026. https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/
