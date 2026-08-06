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

## Interview-grade nuances

- The single most important sentence: "GraphQL authorization must be enforced at the resolver, per object and per field, because the endpoint and HTTP method are identical for every operation, so there is nowhere else to put it." Candidates who answer "add auth middleware on the route" have missed the model.

- Introspection off is not access control. Suggestions (Clairvoyance) and error messages leak the schema; a determined attacker reconstructs it. Disabling introspection reduces convenience for the attacker, it does not protect vulnerable resolvers, so never treat it as a security boundary on its own.

- Aliases vs array batching: aliases multiply one operation's fields inside a single document; array batching sends multiple documents in one HTTP body. Both defeat per-request rate limits, but they are mitigated differently (alias caps and complexity limits for the former, disabling/capping batch arrays for the latter). Knowing the distinction signals depth.

- Why JSON-only genuinely stops classic CSRF: browsers cannot set `Content-Type: application/json` on a cross-site simple request, and forms only produce `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. If the server strictly requires JSON, the forgeable content types are rejected. The bug is accepting the forgeable ones.

- Depth limiting vs cost analysis: depth limits are a blunt instrument (a shallow but wide query with thousands of aliases still hurts); cost/complexity analysis assigns weights per field and is the more complete answer for DoS. Mention both, prefer persisted queries where feasible.

- BOLA is the most common and highest-impact GraphQL bug in practice (mirrors OWASP API1); the object-fetch-by-id resolver is the classic hole because list-level filtering lulls developers into assuming the object resolver is also guarded.

- Subscriptions over WebSocket are an often-forgotten attack surface: authz and rate limiting frequently do not extend to the subscription transport, and long-lived connections are a resource-exhaustion vector.

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
