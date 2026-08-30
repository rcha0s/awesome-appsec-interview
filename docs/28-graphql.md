# GraphQL API Vulnerabilities

> GraphQL exposes one endpoint and a typed schema through which a client asks for exactly the fields it wants. That flexibility moves two things client-side that REST kept implicit: the client chooses the shape of the response (so a single endpoint fans out to arbitrarily many backend resolvers) and the client can pack many operations into one HTTP request (via aliases and batching). Almost every GraphQL bug follows from those two facts plus a third: developers put authorization at the HTTP/route layer where GraphQL has only one route, instead of at each field resolver where the real data access happens. The result is schema disclosure via introspection, object- and function-level access-control gaps at the resolver, rate-limit and 2FA brute-force bypass via aliasing/batching, denial of service via deeply nested queries, injection through argument values, and CSRF when the endpoint accepts non-JSON requests.

## How it works

One endpoint, typically `POST /graphql`, accepts a JSON body with a `query` string and optional `variables` and `operationName`. The operation type and name in the query, not the URL or HTTP method, decide what runs. Three operation types exist:

- Query: reads data (roughly a REST GET).
- Mutation: writes data (roughly POST/PUT/DELETE).
- Subscription: a long-lived push channel, usually over WebSocket.

The schema is a typed contract in Schema Definition Language. Types are objects, scalars (`ID`, `String`, `Int`, `Boolean`, `Float`), enums, unions, interfaces, and inputs. `!` means non-nullable.

```graphql
type Product {
  id: ID!
  name: String!
  price: Int
}

type Query {
  products: [Product!]!
  product(id: ID!): Product
}
```

A query and its JSON response mirror each other in shape:

```graphql
query getProduct {
  product(id: 123) {
    name
    price
  }
}
```

```json
{ "data": { "product": { "name": "Juice Extractor", "price": 1999 } } }
```

Wire format of the request:

```http
POST /graphql HTTP/1.1
Host: example.com
Content-Type: application/json

{"query":"query($id: ID!){ product(id:$id){ name price } }","variables":{"id":123}}
```

Key syntax that becomes attack surface:

- Arguments: values passed to a field (`product(id: 123)`). If they select objects directly, they are an IDOR vector.
- Variables: typed placeholders (`$id: ID!`) filled from the `variables` dictionary; enables reusing one query shape.
- Aliases: rename fields so the same field can appear many times in one operation. `a: product(id:1){name} b: product(id:2){name}`. This bypasses the "no duplicate field name" rule and is the primitive behind alias-based batching.
- Fragments: reusable field sets (`...productInfo`); introspection queries rely on them heavily.

Introspection is a built-in meta-API: querying `__schema` and `__type` returns the entire schema, including every type, field, argument, and description. Every endpoint also answers `__typename`. Resolvers are the per-field functions that actually fetch data; authorization must live here because the endpoint and method are the same for everything.

```mermaid
flowchart TD
  C[Client] -->|"POST /graphql, query"| EP["/graphql endpoint"]
  EP --> P[Parse operation type and name]
  P --> R1[Resolver, product by id]
  P --> R2[Resolver, user by id]
  R1 --> DB[(Underlying data sources)]
  R2 --> DB

  Atk[Attacker] -->|"POST /graphql, query __schema"| EP
  EP --> INTRO[__schema meta-resolver]
  INTRO --> SCHEMA[Full schema: types, fields, args, hidden mutations]
  SCHEMA -->|reveals promoteToAdmin, deleteUser| Atk

  classDef atk fill:#fee,stroke:#900
  class Atk,INTRO,SCHEMA atk
```

## Attack techniques

1. Finding the endpoint and fingerprinting the engine.

GraphQL reuses one path, so locate it first. Send the universal query to candidate paths:

```json
{"query":"{__typename}"}
```

A GraphQL service returns `{"data":{"__typename":"Query"}}` (or `"query"`). Common paths: `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`, often with a `/v1` suffix. Non-GraphQL errors like "query not present" also indicate a GraphQL handler. Try alternate methods (GET, or POST with `application/x-www-form-urlencoded`) if JSON POST does not respond. `graphw00f` fingerprints the server implementation (Apollo, graphql-java, Hasura, etc.), which tells you which defenses and quirks apply.

2. Introspection disclosure.

If introspection is enabled in production (it should not be), one request dumps the schema. Probe cheaply first:

```json
{"query":"{__schema{queryType{name}}}"}
```

Then run the full introspection query (requesting `types`, `fields`, `args`, `inputFields`, `enumValues`, `directives`, using the `FullType`/`InputValue`/`TypeRef` fragments). If it errors, remove the `onOperation`, `onFragment`, `onField` directives, which many servers reject. Visualize the result with the GraphQL Visualizer or InQL to map hidden mutations and admin types. Why it matters: introspection reveals the exact mutations, arguments, and field names an attacker needs, and `description` fields often leak internal notes.

3. Bypassing introspection defenses.

Developers frequently "disable" introspection with a naive regex blocking `__schema`. GraphQL ignores insignificant whitespace and commas, so inserting a newline, space, or comma the regex did not account for slips through:

```json
{"query":"query{__schema\n{queryType{name}}}"}
```

If introspection is blocked over POST, retry over GET with URL-encoding:

```http
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

4. Schema recovery via suggestions (when introspection is truly off).

Apollo and others return "Did you mean" suggestions on near-miss field names (`There is no entry for 'productInfo'. Did you mean 'productInformation'?`). Each suggestion leaks a valid schema token. Clairvoyance (nikitastupin) automates this to reconstruct much of the schema without introspection. Fix in Apollo Server v4+: `hideSchemaDetailsFromClientErrors: true`.

5. Broken object-level authorization (BOLA / IDOR) at the resolver.

If a field takes an object id and the resolver does not check ownership, supply another user's id. GraphQL makes enumeration obvious: a `products` list returns ids 1, 2, 4, so query the missing id directly.

```graphql
query { product(id: 3) { id name listed } }
```

This returns the delisted product 3 that the list omitted. The same pattern hits `user(id:)`, `order(id:)`, `message(id:)`. Why it works: authorization was assumed at the list level, but the object-fetch resolver is a separate, unguarded entry point.

6. Broken function-level authorization (BFLA) via hidden mutations.

Introspection (or suggestions) reveals privileged mutations a normal user's UI never calls, for example `deleteUser`, `promoteToAdmin`, `updateUserRole`. Because every operation shares one endpoint, there is no per-route gate; if the resolver does not check the caller's role, invoking it succeeds.

```graphql
mutation { updateUser(id: 5, input: { role: "ADMIN" }) { id role } }
```

This is OWASP API5 (BFLA) expressed in GraphQL. Object-property-level gaps (OWASP API3/BOPLA) also appear: over-requesting fields (`recentLocation`, `email`) that the schema exposes but the caller should not read, and mass-assignment-style writes of internal properties (`blocked`, `total_stay_price`) via mutation input objects.

7. Batching to bypass rate limits and brute-force (aliases and array batching).

Many rate limiters count HTTP requests, not GraphQL operations. Aliases let one request execute the same field hundreds of times:

```graphql
query bruteforce($code: Int) {
  c1: isValidDiscount(code: 1111) { valid }
  c2: isValidDiscount(code: 2222) { valid }
  c3: isValidDiscount(code: 3333) { valid }
}
```

Applied to authentication, this is a 2FA/OTP brute force: alias `login`/`verifyOtp` N times in one HTTP request and the per-request throttle never trips.

```graphql
mutation {
  a1: verifyOtp(user:"victim", code:"000000"){ token }
  a2: verifyOtp(user:"victim", code:"000001"){ token }
  a3: verifyOtp(user:"victim", code:"000002"){ token }
}
```

Array-based batching is the sibling technique: send a JSON array of independent operations in one body (`[{"query":"..."},{"query":"..."}]`) where the server supports it. Both defeat naive request-count limiting.

8. Denial of service via deeply nested / circular queries.

Cyclic relationships in the schema (Post has an author, author has posts) let a small query force exponential resolver work:

```graphql
query {
  posts { author { posts { author { posts { author { id } } } } } }
}
```

Each level multiplies resolver calls and DB hits; unbounded depth is a cheap DoS. Aliased field duplication and huge query bodies compound it. This is OWASP API4 (Unrestricted Resource Consumption) in GraphQL form.

9. Injection through argument values.

Argument values flow into resolvers and then into backend queries. If a resolver concatenates an argument into SQL/NoSQL/OS commands, GraphQL is just the delivery vehicle for classic injection.

```graphql
query { users(filter: "1=1 OR ''='") { id email } }
```

The GraphQL layer validates types, not the safety of values reaching the backend, so parameterization at the resolver still matters.

10. CSRF over GraphQL.

If the endpoint accepts requests a browser can send cross-site (GET, or POST with `Content-Type: application/x-www-form-urlencoded` or `text/plain`) and relies only on ambient cookies, an attacker page can forge state-changing mutations. A JSON-only endpoint that validates `Content-Type: application/json` is safe from classic form-based CSRF because browsers cannot send that content type cross-origin via a simple form.

```html
<form action="https://target/graphql" method="POST" enctype="text/plain">
  <input name='{"query":"mutation{updateEmail(email:\"attacker@evil.com\"){ok}}","variables":{}}//' value="">
</form>
<script>document.forms[0].submit()</script>
```

Why it works: the endpoint processed a browser-forgeable request under the victim's session with no CSRF token and no content-type enforcement.

11. Alias-based race conditions (single-packet attacks against non-atomic resolvers).

Aliases are also a race-condition primitive, not just a rate-limit bypass. Aliased fields inside one operation execute in parallel on many GraphQL servers, and one HTTP request means one TCP write, so the aliased mutations hit the server as close to simultaneously as any single-packet attack. A mutation guarded by a non-atomic check-then-write is trivially raced.

Classic targets: redeeming a single-use coupon N times, draining a balance by triggering N concurrent `transfer` mutations that each pass the `balance >= amount` check before any decrement lands, or reusing a one-time OTP/token in parallel `verifyOtp` calls that all consume the same not-yet-invalidated code.

```graphql
mutation {
  r1: redeemCoupon(code: "SAVE50") { credit }
  r2: redeemCoupon(code: "SAVE50") { credit }
  r3: redeemCoupon(code: "SAVE50") { credit }
  r4: redeemCoupon(code: "SAVE50") { credit }
}
```

GraphQL amplifies this over REST because you do not need N connections and do not need HTTP/2 last-byte-sync tricks; one JSON body with aliases collapses the timing window. The defense is at the resolver: wrap the check-and-write in a DB transaction with SERIALIZABLE isolation, or use `SELECT ... FOR UPDATE`, an optimistic-lock version column, or a unique constraint on the invariant (one redemption per code, monotonic balance). Alias caps help but do not fix a resolver that races itself with two aliases.

12. Pre-execution DoS via directive overloading and fragment amplification.

Two DoS patterns operate before resolvers execute and slip past cost/complexity analyzers that run post-parse. The first is directive overloading, where a field is stacked with thousands of `@skip(if:false)` / `@include(if:true)` / custom directives (`field @a @a @a ... @a`), forcing the parser and validator to walk each occurrence and blowing CPU/memory during validation. The document is small on the wire but expensive to validate.

The second is fragment amplification. Many small fragments reference each other so the expanded document is exponential in size even though the wire payload stays tiny:

```graphql
query { ...A }
fragment A on Query { ...B ...B ...B ...B ...B ...B ...B ...B }
fragment B on Query { ...C ...C ...C ...C ...C ...C ...C ...C }
fragment C on Query { ...D ...D ...D ...D ...D ...D ...D ...D }
fragment D on Query { __typename }
```

The GraphQL spec forbids cyclic fragments, but non-cyclic fan-out is legal and lethal: each additional layer multiplies the expanded AST. Cost analysis that runs after parsing may still reject it, but only after the server has already paid the parse/validate cost, which is exactly what the attacker wanted. Defenses: reject documents exceeding a max directive-per-field count, a max fragment-spread count, and a max token/AST-node count before validation; enforce a request byte-size cap early; and prefer persisted-query allowlists, which nullify both attacks because unregistered documents never parse.

Tooling summary: InQL (Doyensec, Burp extension) for introspection parsing and query generation, Clairvoyance for suggestion-based schema recovery, graphw00f for engine fingerprinting, graphql-cop for a quick misconfiguration audit, GraphQL Visualizer for schema mapping, and Burp Scanner (raises "GraphQL endpoint found", "GraphQL introspection enabled", "GraphQL suggestions enabled").

## Defense

Ordered by impact.

1. Enforce authorization in every resolver, at object and field granularity. This is the load-bearing control: because one endpoint serves all operations, route-level checks do nothing. Every resolver that reads or writes an object must verify the authenticated principal is allowed that specific object (ownership/tenant check) and that specific operation (role check). Field-level authz gates sensitive properties. Do not rely on the UI never calling a mutation; assume every schema element is directly reachable. This closes BOLA, BFLA, and BOPLA.

2. Disable introspection in production for non-public APIs. In Apollo Server set `introspection: false`. Use an allowlist/regex only as defense in depth and account for whitespace/commas and GET so the block cannot be trivially bypassed. If the API must be public, review the schema so no private field (email, internal ids, admin mutations) is exposed, and disable suggestions (`hideSchemaDetailsFromClientErrors: true` in Apollo v4+).

3. Limit query cost, depth, complexity, and size. Cap query depth (for example 7 to 10 levels) to stop nested/circular DoS. Apply operation limits (max unique fields, max aliases, max root fields) and a maximum request byte size. Add query cost/complexity analysis (`graphql-cost-analysis`, `graphql-depth-limit`, Apollo operation limits, or a persisted-query allowlist) so expensive queries are rejected before execution. Persisted (allowlisted) queries are the strongest form: the server only runs pre-registered operations, which eliminates arbitrary introspection, ad hoc nesting, and unexpected aliasing in one move.

4. Constrain batching and aliasing for security-sensitive operations. Disable array batching if unused, or cap batch size. Cap the number of aliases per operation so a single request cannot become a brute-force engine. Critically, rate-limit and lock by operation count and by business action (OTP attempts per user), not by HTTP request count, so aliasing/batching cannot bypass the limiter. Enforce OTP/2FA attempt counters server-side per account.

5. Prevent CSRF: accept mutations only over JSON POST and validate `Content-Type: application/json`; reject GET and form-encoded requests for state changes. Add a CSRF token (or rely on `SameSite` cookies plus content-type enforcement). Do not put mutations behind GET.

6. Treat all arguments as untrusted input at the resolver: parameterize backend queries, validate and allowlist argument values, and apply the same injection defenses (SQLi, NoSQLi, command, SSRF) you would in REST. Type validation by GraphQL is not value sanitization.

7. Return generic errors: strip stack traces and internal details from error messages so error content does not leak schema or backend structure.

8. Make state-changing resolvers atomic against alias/batch races. Invariant: any mutation that enforces a uniqueness or capacity constraint (one redemption per coupon, non-negative balance, one-time-use token) must resolve its check-and-write as a single atomic step, not as separate `read then write` calls. Enforce with a DB transaction at SERIALIZABLE isolation, `SELECT ... FOR UPDATE` on the row, an optimistic-lock version column, or a `UNIQUE` constraint that turns the second write into a violation. Common wrong implementation: `if (coupon.usesLeft > 0) { coupon.usesLeft -= 1; grantCredit() }` at read-committed isolation with no row lock, which two aliased calls in one document happily double-spend. Alias caps are a partial mitigation; the resolver is the root fix.

9. Bound parse/validate cost before execution. Invariant: no document reaches the resolver phase without passing structural limits on request byte size, directive count per field, fragment-spread count, and total AST-node count. Why it works: directive overloading and fragment amplification blow up during parse/validate, so post-parse cost analysis is too late; capping the AST size shape upstream keeps the server from spending CPU on documents it will reject anyway. Common wrong implementation: relying only on `graphql-depth-limit` and a per-field cost estimator, both of which run after the document has been parsed and (for fragments) fully expanded. Persisted-query allowlists sidestep the entire problem because unregistered documents never parse.

## Interview-grade nuances

- The single most important sentence: "GraphQL authorization must be enforced at the resolver, per object and per field, because the endpoint and HTTP method are identical for every operation, so there is nowhere else to put it." Candidates who answer "add auth middleware on the route" have missed the model.

- Introspection off is not access control. Suggestions (Clairvoyance) and error messages leak the schema; a determined attacker reconstructs it. Disabling introspection reduces convenience for the attacker, it does not protect vulnerable resolvers, so never treat it as a security boundary on its own.

- Aliases vs array batching: aliases multiply one operation's fields inside a single document; array batching sends multiple documents in one HTTP body. Both defeat per-request rate limits, but they are mitigated differently (alias caps and complexity limits for the former, disabling/capping batch arrays for the latter). Knowing the distinction signals depth.

- Why JSON-only genuinely stops classic CSRF: browsers cannot set `Content-Type: application/json` on a cross-site simple request, and forms only produce `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. If the server strictly requires JSON, the forgeable content types are rejected. The bug is accepting the forgeable ones.

- Depth limiting vs cost analysis: depth limits are a blunt instrument (a shallow but wide query with thousands of aliases still hurts); cost/complexity analysis assigns weights per field and is the more complete answer for DoS. Mention both, prefer persisted queries where feasible.

- BOLA is the most common and highest-impact GraphQL bug in practice (mirrors OWASP API1); the object-fetch-by-id resolver is the classic hole because list-level filtering lulls developers into assuming the object resolver is also guarded.

- Subscriptions over WebSocket are an often-forgotten attack surface: authz and rate limiting frequently do not extend to the subscription transport, and long-lived connections are a resource-exhaustion vector.

## Interviewer probes

Q: How does GraphQL turn aliases into a race-condition primitive, and how would you fix a coupon-redemption resolver that is vulnerable to it?

Mid: Aliases send many copies of the same mutation in one request so they arrive together and race the resolver; fix it with a database transaction or a lock.

Principal: On most GraphQL servers, sibling fields inside one operation resolve in parallel, and one HTTP request is one TCP write, so aliased mutations reach the server with a timing spread narrower than anything you can achieve with N REST connections. It is effectively a single-packet attack without needing HTTP/2 last-byte sync. A coupon resolver written as `read usesLeft; if (usesLeft > 0) { decrement; grantCredit; }` at read-committed isolation is trivially raced: four aliased calls all read `usesLeft = 1`, all pass the check, all grant credit. The fix is at the resolver, not the alias cap. Make check-and-write atomic: SERIALIZABLE isolation plus retry on serialization failure, or `SELECT ... FOR UPDATE` on the coupon row inside the transaction, or an optimistic-lock version column, or (cleanest) model the invariant as a database constraint (a `UNIQUE (coupon_id, user_id)` row on redemption so the second insert fails). Alias caps and complexity limits are defense in depth; a resolver that races itself between two aliases will race itself between two REST requests with a bit more effort. The same pattern applies to balance transfers, single-use OTP consumption, and gift-card redemption.

Q: A team disabled introspection, added a query-depth limit of 10, and enabled `graphql-cost-analysis`. Is that enough to stop DoS, and what would you still worry about?

Mid: No, aliases can still fan out a shallow query into thousands of resolver calls; also disable batching and cap aliases.

Principal: Those three controls are the classic checklist and they miss the two DoS classes that run before resolvers do. Directive overloading (`field @skip(if:false) @skip(if:false) ... x1000`) makes the parser and validator walk every occurrence, burning CPU and memory during validation with a document that is small on the wire and shallow in depth. Fragment amplification exploits legal non-cyclic fan-out (`A -> B B B ... -> C C C ... -> ...`), producing an expanded AST that is exponential in the number of fragments even though the raw document is a few hundred bytes; cost analysis running post-expansion may reject the query, but the server already paid the parse-and-expand cost the attacker wanted it to pay. The right answer is to bound the document structurally before parse/validate finishes: cap request byte size, directives-per-field, fragment-spread count, and total AST-node count, and reject early. Separately, persisted-query allowlists remove the entire class because arbitrary documents never parse in production. I would also make sure the depth limit accounts for width, not just height, because a shallow query with thousands of aliased root fields can still DoS a naive resolver that fires a DB query per field.

## Sources

- PortSwigger Web Security Academy, "GraphQL API vulnerabilities": https://portswigger.net/web-security/graphql
- PortSwigger, "What is GraphQL?": https://portswigger.net/web-security/graphql/what-is-graphql
- PortSwigger, "Finding GraphQL endpoints" (within the GraphQL topic): https://portswigger.net/web-security/graphql
- OWASP, "GraphQL Cheat Sheet": https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Clairvoyance (schema recovery via suggestions): https://github.com/nikitastupin/clairvoyance
- InQL (Doyensec Burp extension): https://github.com/doyensec/inql
- graphw00f (engine fingerprinting): https://github.com/dolevf/graphw00f
- Apollo Server security docs (introspection, operation limits, hideSchemaDetailsFromClientErrors): https://www.apollographql.com/docs/apollo-server/security/authentication/
- Apollo blog, "Why you should disable GraphQL introspection in production": https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/
