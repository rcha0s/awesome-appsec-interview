# Broken Access Control and IDOR

> Authentication answers "who are you"; access control answers "are you allowed to perform this action, on this specific object, in this state". Broken access control is the application enforcing the first question and skipping, fumbling, or trusting the client for the second. The root cause is almost always the same shape: an authorization decision that depends on data the attacker controls (an ID in the path, a role in a cookie, a claim in a JWT, the fact that a URL "isn't linked anywhere") instead of a server-side check that binds the authenticated principal to the requested resource and operation. It is OWASP Top 10 A01:2021, the category with the most occurrences in the contributed dataset (over 318,000 across 34 mapped CWEs and roughly 19,000 CVEs), and it is invisible to scanners that do not know the application's intended policy. The durable fix is invariant: deny by default, enforce server-side, authorize per object and per function on every request.

## How it works

Access control sits on top of two other mechanisms and fails when either is trusted to do authorization's job. PortSwigger frames the dependency precisely: authentication confirms the user is who they claim, session management identifies which subsequent requests come from that same user, and access control decides whether that user may carry out the attempted action. When the third layer is missing or leaky, an authenticated (or even anonymous) user reaches data and functions outside their intended permissions.

There are three families of controls, and the vocabulary matters in interviews.

- **Vertical access controls**: restrict sensitive functionality to specific privilege tiers (an admin can delete any account, an ordinary user cannot). Breaking these is **vertical privilege escalation**.
- **Horizontal access controls**: restrict resources of the same type to their owner (you see your own bank transactions, not another customer's). Breaking these is **horizontal privilege escalation**.
- **Context-dependent (state-based) controls**: enforce ordering and state (you cannot edit a cart after payment, cannot reach step 3 of a workflow without completing steps 1 and 2).

Precise terms for the same underlying defect across web and API worlds:

- **IDOR (Insecure Direct Object Reference)**: user-supplied input is used to access an object directly and the app authorizes on authentication alone, not ownership. The term was popularized by the OWASP 2007 Top Ten. It is one instance of a broader access-control failure, most often horizontal, sometimes vertical.
- **BOLA (Broken Object Level Authorization)**: the API name for IDOR and API1:2023, rated widespread prevalence and easy exploitability. The authorization violation happens at the object level by manipulating an ID.
- **BFLA (Broken Function Level Authorization)**: API5:2023, a missing check on the function/endpoint itself (a regular user invoking an admin-only action). BOLA is "wrong object, allowed function"; BFLA is "wrong function entirely".
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

The server binds `isAdmin`, `role`, `balance`, and `emailVerified` because the controller bound straight to the persistence model. **Exploitability** (per OWASP) rises when the attacker can guess common sensitive field names or read the model source, and when the object has an empty constructor. **Real case**: in 2012 GitHub was compromised via mass assignment; a user added their public key to an arbitrary organization, gaining commit access to its repositories. Detection: submit extra fields (`isAdmin`, `verified`, `owner_id`, `tenant_id`, primary keys) and diff the resulting object; success is a privilege or ownership field that changed.

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

Access tenant B's data with tenant A's valid session because a query is scoped by a client-supplied tenant/org ID instead of the server-side tenant binding. BOLA scenario from OWASP: `/shops/{shopName}/revenue_data.json`, where enumerating shop names from another endpoint yields the sales data of thousands of stores. Tenant bleed also hides in shared caches, exported reports, webhooks, search indexes, and background jobs that drop the tenant filter.

### Detection methodology: two-account differential testing

The gold standard, and the answer expected for "how would you test authorization":

- Provision at least two accounts per privilege tier (userA, userB at the same level; a low-priv and a high-priv account; and an unauthenticated client).
- Capture userA's full request set. Replay each request with userB's session and userA's object IDs (cross-user read/write), then swap IDs both directions.
- Replay privileged requests with the low-priv session and with no session (vertical + unauthenticated).
- Confirm the server returns a hard denial (403/404 with no leaked body), not a 302-with-data or a silent success.
- Layer in content discovery for hidden endpoints, alternate verbs, method-override headers, path-encoding variants, and extra body fields for mass assignment. In GraphQL, test at resolver/field and `node(id:)` level, and abuse aliases/batching to bypass per-request checks.

Automated scanners are weak here because they do not know the intended policy; access control is a manual, logic-driven, code-review-heavy domain.

## Defense

Ordered by effectiveness. The first three are the real fix; the rest are defense in depth.

1. **Deny by default and enforce server-side on every request.** Except for intentionally public resources, deny. Make the authorization check mandatory and central, invoked from every business function, in trusted server-side or serverless code the attacker cannot modify. Validate permissions on every request regardless of source (AJAX, server-render, internal). A single missed check is a breach: "validating on the majority of requests is insufficient" (Authorization Cheat Sheet).

2. **Authorize by ownership/policy, not by reference secrecy.** Enforce record ownership in the domain model: check `resource.owner == currentUser` (or an ABAC/ReBAC rule) rather than assuming an unguessable ID protects the object. Comparing the JWT user ID to the request's ID param covers only a small subset of cases; real authorization considers the user's policies and hierarchy (OWASP BOLA guidance). Prefer not exposing identifiers at all: derive the object from the session/JWT where possible, or use per-user indirect references. Map to CWE-639 (Authorization Bypass Through User-Controlled Key).

3. **Scope every data-layer query to the principal and tenant.** Add `WHERE owner_id = :currentUser` (and `AND tenant_id = :currentTenant` in multi-tenant systems) at the persistence layer, not just in a controller `if`. This makes cross-user and cross-tenant IDOR structurally impossible for that query even if a check is forgotten upstream.

4. **Centralize the mechanism; implement once, reuse everywhere.** Use one application-wide enforcement point rather than scattered per-endpoint checks: Jakarta EE / Spring Security filters, Django middleware, ASP.NET Core authorization filters/policies, Laravel middleware. Make administrative controllers inherit from an admin abstract controller that enforces role checks, so a new admin action cannot ship without authorization. Do not assume an endpoint is regular or admin from its URL path.

5. **Kill mass assignment with allowlists / DTOs (property-level authorization).** Bind requests to Data Transfer Objects that contain only user-editable fields; never bind straight to the domain/persistence model. Framework specifics:

   - Spring MVC: `@InitBinder` with `binder.setAllowedFields("userid","password","email")` (allowlist) or `setDisallowedFields("isAdmin")` (blocklist; allowlist preferred).
   - Rails: strong parameters (`params.require(:user).permit(:email, :name)`).
   - Laravel Eloquent: `$fillable = [...]` (allowlist) or `$guarded = ['isAdmin']` (blocklist).
   - Node.js + Mongoose: pick only safe fields, for example `_.pick(req.body, User.safeFields)`.

   Also enforce the read direction (serialize DTOs, not raw models) to prevent Excessive Data Exposure.

6. **Consistent enforcement across verbs, paths, formats, and static assets.** Apply the same authorization to every HTTP method; normalize and canonicalize paths before matching (mind case, suffix matching, trailing slashes, `%2e`, `;`-parameters); re-check at resolver/field level in GraphQL; minimize and lock down CORS (A01 explicitly lists permissive CORS as broken access control). Do not forget static resources and cloud object storage (S3/GCS/Azure buckets): incorporate them into the access-control policy, do not leave them public by default.

7. **Least privilege, separation of duties, and step-up.** Grant the minimum roles/attributes; separate admin surfaces with independent authorization; require re-authentication or step-up for sensitive actions and after risk events. Prefer ABAC/ReBAC over pure RBAC for fine-grained, multi-tenant, object-level decisions (RBAC suffers role explosion and models ownership poorly; ReBAC, as in Google Zanzibar, natively expresses "owner of this object may edit it").

8. **Exit safely, log, alert, and rate-limit.** Fail closed on any authorization error (CWE-280), centralize failure handling, and never leak sensitive detail in the error. Log access-control failures and alert on repeated denials/enumeration (A01 and A09). Rate-limit object access to slow ID sweeping. Invalidate server-side sessions on logout; keep stateless JWTs short-lived or follow OAuth revocation.

9. **Test authorization as first-class policy in CI.** Write unit and integration tests that assert deny-by-default, ownership enforcement, and role matrices, and fail the build when they fail. Reference OWASP ASVS V4 (Access Control), WSTG 4.5 (Authorization Testing), and Proactive Controls C7 (Enforce Access Controls). Do not deploy changes that break the authorization tests (OWASP BOLA guidance).

## Interview-grade nuances

- **"We use UUIDs, so no IDOR."** Wrong answer. Unpredictability is not authorization; leaked or referenced GUIDs are exploited identically. OWASP recommends random GUIDs as a hardening measure, explicitly *in addition to* per-object checks, never instead of them.
- **"We check the user is logged in."** Authentication is not authorization. Logged in does not mean permitted for *this* object or *this* function. The strongest candidates separate the three layers (authn, session, authz) crisply.
- **BOLA vs BFLA is a real distinction, not pedantry.** BOLA: you are allowed to call the endpoint, the bug is object ownership (manipulate the ID). BFLA: you should not be able to call the function at all (an admin action reachable by a normal user). Fixes differ: object-scoped ownership checks vs function/role gating and admin controller inheritance.
- **Comparing session-user-ID to the ID param feels like a fix but is not the general one.** It handles "is this my own record" but misses shared objects, delegated access, org hierarchies, and role-based object permissions. Real authorization consults a policy, not just equality.
- **Vertical escalation is frequently a platform/routing bug, not app code.** URL-match discrepancies, verb tolerance, and override headers (`X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`) bypass front-end gates while the app happily serves the action. Senior answer: normalize once, authorize in the app tier, do not rely on an edge WAF path rule.
- **Mass assignment is an access-control bug wearing an input-binding costume.** Field-level validation of the fields you care about does nothing about the fields you did not declare; the framework writes them. It is BOPLA, and the 2012 GitHub incident is the canonical war story.
- **Scanners cannot own this.** Broken access control is the most prevalent A01 category yet among the hardest to automate because it is policy-specific. The credible plan is two-account differential testing plus code review plus authorization tests in CI, not "run the DAST".
- **The redirect-with-body trap.** A 302 to `/login` is not proof of enforcement; check whether the pre-redirect response already leaked the protected data.
- **RBAC vs ABAC/ReBAC tradeoff.** RBAC is simple to start and easy to reason about at small scale, but role explosion, header-size limits from too many roles, and poor fit for object-level and multi-tenant decisions make ABAC/ReBAC the better default for anything nontrivial. Naming Zanzibar/ReBAC for "owner-of-object" semantics signals depth.

## Sources

- OWASP Top 10 A01:2021 Broken Access Control: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP API1:2023 Broken Object Level Authorization (BOLA): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP API5:2023 Broken Function Level Authorization (BFLA): https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Mass Assignment Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- PortSwigger Web Security Academy, Access control vulnerabilities and privilege escalation: https://portswigger.net/web-security/access-control
- PortSwigger Web Security Academy, Insecure direct object references (IDOR): https://portswigger.net/web-security/access-control/idor
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-285 Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
- GitHub public key security vulnerability (2012 mass assignment): https://blog.github.com/2012-03-04-public-key-security-vulnerability-and-mitigation/
