# Multi-Tenancy and Isolation

> Multi-tenant isolation is enforced at a specific layer, and every layer fails differently when it's skipped. An application-layer check, a forgotten `WHERE tenant_id = :current` clause, fails silently. The query still runs, still returns rows, and nothing in the response tells anyone it just handed back another tenant's data. Data-layer isolation, row-level security, a per-tenant schema, a per-tenant database, is a structural backstop that fails loudly instead. A policy violation raises a query error rather than quietly leaking a row. Application-layer authorization alone is insufficient because every new code path is a new chance to forget it, so real isolation needs a backstop closer to the data, underneath the application check rather than instead of it. The single biggest thing a Staff reviewer checks in this design is where the isolation boundary actually lives, not whether a `tenant_id` column exists on the table.

**Interview frequency:** Core

*See also: [Authorization](97-authorization.md) for the access-control model families this doc's application layer draws on, especially ReBAC, which for many systems is the tenant-isolation mechanism itself.*

## Where this decision forks

The axis is isolation layer, because the realistic isolation primitive and its operational cost differ sharply depending on where in the stack the boundary sits.<sup>[[5]](#ref5)</sup> The data layer (relational tables and, just as often forgotten, vector and AI retrieval stores) gets structural backstops like RLS and per-tenant schemas or databases. The compute layer (containers, VMs, shared inference infrastructure) gets namespace, cluster, or sandbox boundaries. The application layer gets the authorization checks themselves, treated here as the weakest and most-skippable layer rather than the primary mechanism, because it's the one every other layer exists to backstop. A design that only ever discusses the application layer hasn't actually made an isolation decision yet.

### Data layer (relational and vector/AI retrieval)

This is where the fail-loud-versus-fail-silent distinction is sharpest, because a database can enforce a boundary the application code has no way to enforce on its own. It also has two sub-surfaces most teams treat unevenly. Relational tables get RLS or schema separation as a matter of course, but a vector store bolted on for RAG typically gets a `tenant_id` metadata field and an assumption that filtering it is someone else's problem.

A consumer analytics SaaS on shared Postgres tables and a healthcare records platform both store relational tenant data, but they land on different defaults. The analytics product ships RLS on shared tables, because the marginal isolation gain of a full schema or database split doesn't justify the operational cost for tenants whose data has no regulatory weight behind it. The healthcare platform justifies database-per-tenant for its highest-sensitivity tenants, because a business-associate agreement requires isolation an external auditor can verify directly, not a policy definition nobody outside the engineering team can independently confirm is actually enforced.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Row-level security (RLS) on a shared table | The default for most SaaS products, policy-enforced filtering at the lowest per-tenant operational cost, real in Postgres via a policy checked against `SET LOCAL app.tenant_id` per transaction<sup>[[1]](#ref1)</sup> | The app talks to the database through a connection pooler running in session-pooling mode with no reset query on checkout | Preferred | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Schema-per-tenant | Mid-tier isolation, tenants who want their data physically separated without the cost of a full database per tenant | Tenant count is large enough that per-schema migrations and connection routing become their own maintenance burden | Still common | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Database-per-tenant | Regulated or highest-value tenants demanding contractual or compliance-driven physical isolation | The tenant base is large and mostly self-serve, where per-database patching and monitoring cost scales linearly with tenant count | Niche-but-required | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Namespace/partition-scoped vector-store isolation (pgvector RLS, Pinecone namespaces<sup>[[8]](#ref8)</sup>, Weaviate multi-tenancy classes<sup>[[7]](#ref7)</sup>, Milvus partition keys<sup>[[9]](#ref9)</sup><sup>[[19]](#ref19)</sup>) | Any RAG or retrieval path touching tenant data, because AI retrieval is a data layer too and is the one most teams forget to scope as carefully as their relational tables | The vector store is single-tenant by design, or every tenant genuinely shares one corpus | Preferred | [Vector Stores (pgvector, Pinecone, Weaviate, Milvus)](59-vector-stores.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| RLS bypass via superuser, table ownership, or session-pooled connection reuse | Superuser roles and `BYPASSRLS` grants skip policies outright, and in Postgres the table owner is exempt from its own RLS policies by default unless `FORCE ROW LEVEL SECURITY` is set, so the application's own migration role often owns the tables it created; a pooler in session-pooling mode with no reset query on checkout can also hand a new client a connection still carrying a prior session's tenant setting<sup>[[15]](#ref15)</sup> | Application roles never use `BYPASSRLS` or own the tables they query, every RLS-protected table gets `FORCE ROW LEVEL SECURITY`, and the pooler resets session state on every checkout | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Pre- versus post-filter in retrieval and search paths | Filtering after ANN ranking can return raw candidates before the tenant filter ever runs, leaking existence through a "filtered" versus "no results" distinction even when content stays withheld<sup>[[21]](#ref21)</sup> | Push the tenant predicate into the index traversal itself (per-tenant partial index<sup>[[10]](#ref10)</sup>, native multi-tenancy mode), never filter client-side after fetch | [Vector Stores (pgvector, Pinecone, Weaviate, Milvus)](59-vector-stores.md) |
| Query and result caching keyed without tenant identity | A cache keyed only on query text serves one tenant's cached results to another, and the cache often sits entirely outside the store's authorization layer | Cache key includes tenant identity plus filter, never text alone, and negative results aren't cached where a negative reveals absence in a target tenant | [Vector Stores (pgvector, Pinecone, Weaviate, Milvus)](59-vector-stores.md) |
| Cross-tenant negative-path testing in CI | Code review catches an obviously missing check far less reliably than a test that actually queries as tenant B and asserts tenant A's fixture data never comes back | Seed two tenants with deterministic fixtures and run a cross-tenant read/write assertion against every new endpoint before merge | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Encryption-key scoping per tenant | A single data-at-rest key shared across every tenant means one key-management failure exposes every tenant at once, not just the affected one | Scope encryption keys per tenant (or per isolation tier) so a compromised key's blast radius matches the isolation boundary already chosen above it | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Canary or honey-record per tenant boundary | A record that should never be reachable outside its tenant is a detective control that catches an isolation failure in production, not just in review | Seed a unique, high-entropy record per tenant and alert on any read of it from a different tenant's authenticated context | [Vector Stores (pgvector, Pinecone, Weaviate, Milvus)](59-vector-stores.md) |
| Tenant offboarding and provable data erasure | Deletion cost and auditability scale inversely with how cheap the isolation tier was; RLS on a shared table turns erasure into a cascade that also has to reach vector indexes, derived embeddings, search caches, and every backup or PITR window still holding the rows, while database-per-tenant makes deletion a drop plus an auditable attestation | Define an erasure path per isolation tier before onboarding a tenant, and include vector/derived data and backups, not just the primary table | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Tenant-scoped database roles as defense in depth alongside RLS | An application connecting as one shared database role has no independent boundary if the RLS policy itself has a bug or gets dropped during a migration | Pair RLS with per-tier database roles carrying the minimum grants that tier needs, so a policy gap isn't the only thing standing between a query and another tenant's rows | [Broken Access Control and IDOR](15-access-control-idor.md) |

Also worth a mention: schema drift across per-tenant schemas as migrations fall out of sync ([Broken Access Control and IDOR](15-access-control-idor.md)), index bloat from per-tenant partial indexes at high tenant counts, RLS policy coverage gaps on newly added tables with no default-enabled policy, client-supplied tenant identifiers trusted without server-side verification (see application layer below).

### Compute layer

Compute isolation decides how much of the surrounding infrastructure a compromised or misbehaving tenant workload can reach, independent of whatever the data layer enforces underneath it. Shared inference infrastructure adds a wrinkle relational and vector stores don't have, because cross-tenant leakage there can happen through timing and cache side channels rather than a missing filter.

A project-management SaaS running every customer's workload in one Kubernetes cluster and an AI-code-execution product running arbitrary tenant-submitted code both need compute isolation, but they land on very different defaults. The project-management product is well served by namespace-plus-RBAC isolation with a default-deny NetworkPolicy underneath it, because nothing it runs executes tenant-controlled code directly. The code-execution product has to sandbox every tenant's job at the kernel boundary, because the workload itself is the threat model, not just the data it touches.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Shared cluster with namespace + RBAC isolation | Most SaaS workloads, the common case at a fraction of the operational cost of per-tenant infrastructure, the pattern Kubernetes's own multi-tenancy working group treats as the baseline<sup>[[12]](#ref12)</sup> | A namespace boundary alone is asked to stand in for network isolation too, without a default-deny NetworkPolicy underneath it | Preferred | [Kubernetes Security](85-kubernetes.md) |
| Dedicated cluster or VPC per tenant | Regulated or highest-value tenants whose contract requires physical infrastructure separation, matching the same tier that justifies database-per-tenant | The tenant base is large and self-serve, where per-tenant infrastructure cost and patch surface scale linearly with tenant count | Niche-but-required | [Kubernetes Security](85-kubernetes.md) |
| Sandboxed per-tenant execution (running tenant-supplied code, or model inference on tenant data) | Anything executing untrusted tenant input directly, code execution products, and shared model-serving infrastructure where KV-cache and prefix-cache state can leak across a session boundary<sup>[[11]](#ref11)</sup> | The workload is trusted, first-party code with no tenant-supplied execution surface, where the extra sandboxing overhead buys nothing | Emerging | [Model Serving and Inference-API Attacks](60-model-serving-attacks.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Tenant context propagation across service boundaries | A downstream service call that drops the tenant claim the original request carried defaults to some ambient or system-level identity instead of failing closed | Propagate tenant scope as a signed claim on every internal call, and reject a call that arrives without one rather than assuming a default | [Kubernetes Security](85-kubernetes.md) |
| Namespace/RBAC over-permissioning as a lateral-movement path | A `ClusterRole` bound broadly across namespaces turns a single compromised tenant workload into a cross-tenant read primitive<sup>[[22]](#ref22)</sup> | Scope roles to the single namespace they need, and treat any cluster-scoped grant as requiring its own review | [Kubernetes Security](85-kubernetes.md) |
| KV-cache and prefix-cache leakage on shared model-serving infrastructure | Caches keyed on token hash alone, with no tenant or session component, can leak prompt content across tenants through measurable time-to-first-token differences<sup>[[11]](#ref11)</sup> | Key any prefix or KV cache on tenant/session identity, or disable shared caching entirely on multi-tenant serving tiers | [Model Serving and Inference-API Attacks](60-model-serving-attacks.md) |
| Noisy-neighbor resource isolation | One tenant's load starving another's is primarily a reliability problem, but the same exhaustion path is a usable cross-tenant denial-of-service primitive<sup>[[14]](#ref14)</sup> | ResourceQuota and LimitRange per namespace<sup>[[23]](#ref23)</sup>, plus per-tenant rate limits on any shared inference endpoint | [Kubernetes Security](85-kubernetes.md) |
| Sandboxed execution escape for tenant-supplied code | A container-level sandbox that isn't actually isolated at the kernel boundary lets one tenant's "code" step outside its own compute allocation | Use a hardened sandbox (gVisor or Kata-class isolation, not a bare container with a seccomp profile)<sup>[[16]](#ref16)</sup><sup>[[17]](#ref17)</sup> for anything running arbitrary tenant input | [Model Serving and Inference-API Attacks](60-model-serving-attacks.md) |
| Admission-webhook failure-open gaps during an outage | A security policy webhook set to fail open admits the exact manifest it was meant to block the moment it becomes unreachable, which an attacker can trigger deliberately | Security-relevant admission webhooks fail closed (`failurePolicy: Fail`), layered with Pod Security Admission at the namespace level<sup>[[13]](#ref13)</sup>, with HA replicas so a legitimate outage doesn't also become a bypass window | [Kubernetes Security](85-kubernetes.md) |
| Tenant-scoped logging and trace attribution | A shared observability backend with no tenant scoping is itself an unscoped cross-tenant read path, and request logs with no reliable tenant identifier make "which tenants were affected, for how long" unanswerable during an incident | Every request log and trace carries a tenant identifier, and the observability backend enforces its own access control rather than treating logs as low-sensitivity | [Kubernetes Security](85-kubernetes.md) |
| Canary namespace or honey secret per tenant boundary | A secret that should be unreachable outside its namespace is a detective control that fires on the actual attempt, not just the policy gap that allowed it | Seed a plausible-looking honey secret per tenant namespace and alert on any cross-namespace read attempt | [Kubernetes Security](85-kubernetes.md) |

Also worth a mention: image provenance and tag immutability per tenant-facing service ([Kubernetes Security](85-kubernetes.md)), egress filtering blocking a compromised tenant workload from reaching another tenant's internal endpoints, dedicated node pools for the highest-sensitivity tenants beyond namespace isolation alone.

### Application layer

This layer is the one every engineer touches on every feature, which is exactly why it's the weakest backstop rather than the primary one. It's necessary, an explicit tenant check at the point of use catches business-logic authorization decisions RLS can't express, but it's insufficient alone because it depends on every developer remembering it on every code path forever.

A greenfield product built with a shared authorization middleware from day one and a five-year-old codebase with checks scattered across hundreds of hand-written handlers both sit in this context, and the difference between them is exactly the difference this fork is about. The greenfield product's middleware makes a forgotten check structurally impossible, because a route that can't reach the database without passing through it can't skip the check. The legacy codebase's per-handler checks are only as strong as the least-reviewed handler in the system, which is why it's the one still finding cross-tenant IDOR findings in pen tests years after the "add a tenant check" ticket was closed.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Per-request explicit tenant-scoping checks | Business-logic authorization decisions a data-layer policy can't express on its own, layered on top of a data-layer backstop rather than replacing it | It's presented as the whole isolation story with no data-layer policy underneath it | Still common | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Shared authorization middleware every request is routed through | The structural fix to the forgotten-code-path problem, because a route that can't skip the middleware can't skip the check | A new route or transport (a background job, a webhook handler, an admin script) is added outside the framework's normal request path and quietly bypasses it | Preferred | [Broken Access Control and IDOR](15-access-control-idor.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| A new code path skipping the tenant check entirely | This is the failure mode the whole layer is weak against: nothing errors, the wrong tenant's row just comes back<sup>[[18]](#ref18)</sup> | Route every data-touching path, including background jobs and webhook handlers, through the same middleware rather than trusting each handler to remember | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Tenant identifier trusted from a client-supplied field instead of the session | A request body or header naming the tenant is exactly as trustworthy as any other client input, which is to say not at all<sup>[[3]](#ref3)</sup> | Resolve tenant scope from the authenticated session or token claim server-side, treat any client-supplied tenant field as advisory at best<sup>[[20]](#ref20)</sup> | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Batch and bulk endpoints re-checking scope per item | An endpoint that authorizes the batch request once and then iterates client-supplied IDs can return or mutate objects from other tenants inside the batch | Re-validate tenant ownership per item inside the loop, not once for the request as a whole | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Admin and internal-support tooling with legitimate cross-tenant access | A support console needs to see across tenants by design, which makes it the one place the middleware's default-deny has to be deliberately, narrowly overridden | Give cross-tenant tooling its own audited, break-glass-style access path rather than a blanket exemption from the shared middleware | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Cross-tenant negative-path testing in CI | The same regression risk as the data layer, an application-layer check regresses silently and only a test that actually attempts the cross-tenant read catches it before production | Run the same two-tenant negative-path suite against the application layer that the data layer gets, treating it as one shared test surface | [Broken Access Control and IDOR](15-access-control-idor.md) |
| GraphQL and JSON:API batch-alias endpoints as a variant of the bulk-endpoint gap | Aliased queries and `includes` parameters let a caller request many objects by ID in one round trip, and a middleware written for single-object routes can miss the aliased path entirely<sup>[[2]](#ref2)</sup> | Authorize every object in an aliased or included response individually, not just the top-level query the middleware saw | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Second-order IDOR through a reused identifier | An ID returned from one legitimate call (a search result, an export job) gets reused unchecked in a later call, so the first check's tenant scope doesn't carry forward to the second | Treat every ID as untrusted at the point it's used, not just at the point it was issued, and re-check tenant ownership on each use | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Forced browsing to admin or cross-tenant functionality hidden only in the UI | A route with no server-side check, gated only by a hidden menu item, is reachable by anyone who guesses or finds the URL, tenant scoping included | Every route enforces its own authorization server-side; UI-level hiding is a usability choice, never a security control | [Broken Access Control and IDOR](15-access-control-idor.md) |

Also worth a mention: HTTP verb-tampering bypassing a route-level check that only guarded one method ([Broken Access Control and IDOR](15-access-control-idor.md)), parameter-based role trust where a client-supplied role field overrides the session's actual role.

## Recommended defaults by context

| Context | Recommended default | Why |
| --- | --- | --- |
| Relational data | RLS on shared tables via `SET LOCAL app.tenant_id` per transaction, schema-per-tenant or database-per-tenant reserved for regulated or highest-value tenants | Cheapest operationally while still a structural, fail-loud backstop; escalate isolation only where the compliance or blast-radius case justifies the cost |
| Vector/AI retrieval | Server-enforced namespace or partition isolation (pgvector RLS with per-tenant partial indexes, Weaviate multi-tenancy class, Milvus partition key), never a client-supplied namespace field | Same failure mode as relational RLS, but retrieval paths are the ones teams routinely forget to scope this carefully |
| Compute | Shared cluster with namespace + RBAC + default-deny NetworkPolicy for most tenants, dedicated cluster or VPC only for the tier that also gets database-per-tenant | Namespace isolation covers the common case at a fraction of dedicated infrastructure's operational cost |
| Shared inference infrastructure | Sandboxed per-tenant execution with tenant-scoped KV/prefix caching, or caching disabled outright on multi-tenant serving tiers | Shared GPU serving leaks state through timing and cache side channels that RBAC alone never touches |
| Application layer | Shared authorization middleware every request is routed through, with per-request checks as a second layer, not the only one | A per-request check alone is one forgotten code path away from a silent leak |

## Migration path

Most systems start with application-layer-only tenant scoping, a `WHERE tenant_id = :current` clause added by hand wherever a developer remembered to add it, because it's the fastest thing to ship and the gap doesn't show up until an incident or a pen test finds it. The first migration step in every context below is adding a data- or compute-layer backstop underneath the existing application checks rather than replacing them, because removing the application-layer check before the new layer is proven correct just moves the single point of failure instead of removing it.

For relational data, the safe sequence is enabling RLS policies in a permissive or audit-only mode first, logging what would have been blocked without actually blocking it, before flipping to enforced. Flipping straight to enforced RLS on a live shared table breaks any query path that never set the session's tenant context correctly, and that gap is usually invisible until enforcement finds it. Schema-per-tenant and database-per-tenant migrations are rarely a clean cutover. They require a backfill, a connection-routing change, and often a new connection-pooling story, because one connection per tenant schema multiplies pool size in a way platform teams push back on hard. DBAs are the other predictable pushback, over the query-planning overhead RLS policies add, especially before per-tenant partial indexes are in place to make the filtered plan cheap again.

Background jobs, cron tasks, and admin scripts that connect to the database with their own connection outside the normal request path usually never set `app.tenant_id` in the first place, because nobody wrote it that way, and enforced RLS turns every one of those into a hard failure the moment it flips. Teams find this out by staging the enforcement flip behind a per-table feature flag and watching error rates before going wider, rather than flipping every table's policy from permissive to enforced on the same day.

For vector stores, the common starting point is a shared collection with a metadata `tenant_id` field filtered client-side after retrieval, which is exactly the post-filter pattern that leaks. Migrating to server-enforced isolation means moving the filter into the index traversal, a per-tenant partial HNSW index or the store's native multi-tenancy mode, and re-indexing existing data under the new scheme rather than just changing the query. Retrieval teams push back here because reindexing at scale has a real latency and cost line item, and the fix is easy to defer until an incident or an audit forces the timeline. If the rollout has to stage, doing it corpus-by-corpus rather than all at once lets the team validate recall didn't regress under the new per-tenant partial index before committing the rest of the fleet to it.

For compute, teams generally start on a shared cluster with namespaces but no enforced NetworkPolicy, treating RBAC as the whole isolation story. The first real step is a default-deny NetworkPolicy on every namespace before anything else, because it's additive and low-risk compared to standing up dedicated infrastructure. Dedicated clusters or VPCs come later, and only for the tenant tier whose contract or regulatory posture justifies the ongoing cost, because running that infrastructure for every tenant rarely clears a cost-benefit bar. Platform teams push back on the operational multiplication of dedicated infrastructure; the tenants asking for it are usually the ones whose contract requires it regardless of the internal cost argument. Moving shared model-serving infrastructure off cross-tenant KV-cache sharing is its own smaller migration inside this one, usually the fastest of the compute-layer changes to ship because it's a serving-framework config flag rather than an infrastructure redesign.

Sandboxed execution for tenant-supplied code or inference is usually the last compute-layer migration a team takes on, because it's only urgent once the product actually starts running untrusted tenant input rather than trusted first-party code against tenant data. The staged path is a bare container with a tightened seccomp and AppArmor profile first, because that's a fast, low-risk hardening step, followed by a real sandbox boundary (gVisor or Kata-class isolation<sup>[[16]](#ref16)</sup><sup>[[17]](#ref17)</sup>) once the product's roadmap commits to running arbitrary tenant code as a durable feature rather than an experiment. Performance is usually what breaks here. A kernel-boundary sandbox adds real latency and memory overhead per invocation, and engineering pushes back hard on that cost until a red-team exercise or a customer security questionnaire makes the current container-only posture concrete rather than theoretical.

The application-layer middleware migration is the one most teams underestimate. Moving from scattered per-handler checks to a single shared middleware means auditing every route, including background jobs, webhook handlers, and admin scripts, that might bypass the framework's normal request path, because those are exactly the paths that get missed when the middleware is added after the fact rather than from day one. The audit itself is often the longest part of the migration, longer than writing the middleware, because it requires someone to enumerate every entry point into the system rather than just the ones the router already knows about.

A tiered isolation offering is the common end state rather than a single answer for every tenant, mirroring the tiering cloud providers themselves document for SaaS isolation strategy.<sup>[[4]](#ref4)</sup> Most SaaS products settle on RLS plus shared-cluster compute as the default tier, schema-per-tenant or a dedicated namespace as a mid tier sold to larger customers, and database-per-tenant plus dedicated compute as a top tier reserved for regulated or contractually demanding accounts. Sales and product usually want that top tier available before security does, because it closes deals with security-conscious enterprise buyers. Security's pushback is rarely against offering it; it's against offering it before the operational tooling, per-tenant patching, monitoring, and incident response, actually scales to support more than a handful of tenants on it.

Tooling matters as much as sequencing here. Every migration above goes smoother when the new and old mechanisms are both selectable behind a per-tenant or per-service feature flag rather than shipped as one global cutover, because a flag lets a team roll back one affected tenant or service without an emergency deploy across the whole system. Ownership matters just as much. The migrations that stall are usually the ones with no single team accountable for finishing them, because isolation work touches every product team's data access pattern but belongs fully to none of them without an explicit platform-security owner driving the cutover date.

Across every context, the rollback shape stays the same. Keep the legacy path, application-only checks, the old shared collection, the old namespace-only cluster, live and monitored until the new layer has run through at least one full production cycle with zero cross-tenant findings from the negative-path test suite, and gate the cutover behind a flag scoped per tenant or per service rather than a single global switch. A full cycle of the negative-path test suite passing clean against production traffic, plus zero canary or honey-record reads from the wrong tenant, is the signal that a migration is ready to complete.

## Interviewer probes

**Why isn't a correctly-written application-layer tenant check enough, even if every current code path gets it right today?**

Mid: Because a new code path is a new place to forget it, and nothing about the application layer forces the next engineer to remember.

Principal: The failure mode is the whole argument. A missing `WHERE tenant_id` predicate in application code doesn't throw. It returns a row that happens to belong to the wrong tenant, and every future code reviewer has to catch that omission by inspection alone, with no structural help. RLS converts the same class of mistake into a query error at write time, which is why it's called a backstop rather than a redundant second copy of the same check.<sup>[[2]](#ref2)</sup>

**When does RLS stop being sufficient, and a team needs schema-per-tenant or database-per-tenant instead?**

Mid: When a tenant's contract or regulatory posture requires physical separation that a shared table can't demonstrate.

Principal: RLS depends on tenant context being set correctly on every transaction, and two configuration mistakes quietly disable it even though every policy still looks correct in the schema. A pooler running in session-pooling mode without a reset query on checkout can hand a new client a connection still carrying a previous session's tenant setting, and in Postgres the table owner, often the same role migrations run as, bypasses RLS entirely by default unless the table is altered with `FORCE ROW LEVEL SECURITY`.<sup>[[1]](#ref1)</sup> Schema-per-tenant and database-per-tenant remove that dependency entirely by using distinct credentials or physical boundaries instead of transaction-scoped state, which is exactly the guarantee a regulated or contractually isolated tenant is paying for. The honest tradeoff to name is that this buys assurance an external auditor can verify directly, at a patching and monitoring cost that scales with tenant count rather than staying flat.

**How does the pre-filter versus post-filter distinction in vector search create a cross-tenant leak even when the document's contents never render?**

Mid: Filtering after the ANN search returns its top-k candidates means the unfiltered results, or the fact that a match exists at all, are visible before the filter ever runs.

Principal: The vulnerable pattern is a shared, non-multi-tenant class filtered by a `tenant_id` metadata property at query time, where the filter is a predicate applied to candidates the search already touched rather than an authorization boundary baked into the index. Even when the filtered-out content never renders, a caller can still infer that a matching document exists in another tenant through a "filtered" versus "no results" distinction, or through response timing.<sup>[[21]](#ref21)</sup> Weaviate's actual tenant boundary is its native multi-tenancy class, which shards data per tenant rather than filtering a shared collection after the fact.<sup>[[7]](#ref7)</sup> The fix is choosing an isolation primitive that makes the boundary structural, a per-tenant shard, partition, or namespace, rather than trusting a filter clause layered on top of shared storage.

**You inherit a Kubernetes cluster running every tenant in one namespace with RBAC as the stated isolation story. What's missing?**

Mid: RBAC controls who can call the API server, it doesn't stop lateral network movement between pods sharing the same namespace.

Principal: Namespace plus RBAC without a default-deny NetworkPolicy on top means any pod in that namespace can reach any other pod's service ports directly, regardless of what the API-level authorization allows, so the namespace boundary is enforcing an authorization story while leaving a network-level path wide open underneath it.<sup>[[6]](#ref6)</sup> A default-deny NetworkPolicy finishes the layer teams often assume RBAC alone already covers, so it's additive and low-risk enough that a maturing platform team usually ships it fast once someone actually draws the boundary out and notices the gap.

**Give an example of tenant context getting lost across a service boundary, and explain why a shared authorization middleware doesn't automatically prevent it.**

Mid: A downstream call from service A to service B that doesn't forward the tenant claim from the original request, so service B falls back to some default or system identity.

Principal: Middleware enforces the boundary at the edge where a request enters a service, but it has no visibility into what that service does with the claim once it's inside, including whether an outbound call to another service carries it forward. This is the same class of gap that shows up as token audience confusion in multi-tenant token validation, a token minted for one tenant's API validated loosely enough to also work against a sibling tenant's, so the fix is an explicit, signed tenant claim propagated and re-verified at every hop, not an assumption that one edge check covers the whole call chain.

**How do you actually catch a cross-tenant isolation regression before it reaches production, rather than relying on code review to notice a missing check?**

Mid: A negative-path test that authenticates as tenant B and asserts tenant A's seeded fixture data never comes back.

Principal: Seed two tenants with deterministic fixture IDs in every test environment and run that cross-tenant assertion as a CI gate against every new endpoint, not as a one-time audit. Code review reliably catches a check that's wrong; it's much weaker at catching a check that's simply absent from a code path nobody thought to look at, which is exactly the gap a running assertion closes and a manual review can't. Pair it with a production-side canary or honey record, because CI proves the code path was tested, not that the same path stays correct after the next unrelated refactor.

**When is database-per-tenant worth its operational cost, given that most SaaS products never reach it?**

Mid: The highest-value or most heavily regulated tenants, where the contract or compliance regime specifically demands physical isolation.

Principal: The cost scales linearly with tenant count, every database needs its own patching, migration, and monitoring, which is why it's used as a top tier layered on top of an RLS-backed shared infrastructure for everyone else rather than as the universal default. A specific tenant's contract or a specific regulator most often drives the decision, requiring demonstrable physical separation that a policy on a shared table can't provide no matter how well-audited that policy is.

**What's the security-adjacent argument for caring about noisy-neighbor resource isolation, beyond it being a reliability concern?**

Mid: One tenant's resource exhaustion degrading availability for others is a shared-fate dependency, which is a blast-radius problem even without a data leak involved.

Principal: The same exhaustion path that causes an accidental noisy-neighbor incident is a usable deliberate cross-tenant denial-of-service primitive, an oversized request against a shared inference endpoint with no per-request token cap can stall every co-tenant's requests on the same server. ResourceQuota and LimitRange at the compute layer, paired with per-tenant rate limits at the application layer, are the same isolation argument this whole doc makes, applied to availability instead of confidentiality.

## Sources

<a id="ref1"></a>[1] PostgreSQL Global Development Group. Row Security Policies. PostgreSQL Documentation. Retrieved 2026-08. https://www.postgresql.org/docs/current/ddl-rowsecurity.html

<a id="ref2"></a>[2] OWASP. API1:2023 Broken Object Level Authorization (BOLA). OWASP API Security Top 10. Retrieved 2026. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

<a id="ref3"></a>[3] MITRE. CWE-639: Authorization Bypass Through User-Controlled Key. https://cwe.mitre.org/data/definitions/639.html

<a id="ref4"></a>[4] Amazon Web Services. SaaS Tenant Isolation Strategies. AWS Whitepaper. Retrieved 2026-08. https://docs.aws.amazon.com/whitepapers/latest/saas-tenant-isolation-strategies/welcome.html

<a id="ref5"></a>[5] NIST. Special Publication 800-144: Guidelines on Security and Privacy in Public Cloud Computing. December 2011. https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-144.pdf

<a id="ref6"></a>[6] Kubernetes. Network Policies. Kubernetes Documentation. Retrieved 2026-08. https://kubernetes.io/docs/concepts/services-networking/network-policies/

<a id="ref7"></a>[7] Weaviate. Multi-tenancy concepts and configuration. Weaviate Documentation. 2024. https://weaviate.io/developers/weaviate/concepts/data#multi-tenancy

<a id="ref8"></a>[8] Pinecone. Use namespaces. Pinecone Documentation. Retrieved 2026-08. https://docs.pinecone.io/guides/indexes/use-namespaces

<a id="ref9"></a>[9] Milvus. Multi-Tenancy Strategies. Milvus Documentation. Retrieved 2026-08. https://milvus.io/docs/multi_tenancy.md

<a id="ref10"></a>[10] pgvector. Filtering with HNSW and iterative index scans. pgvector README. 2024. https://github.com/pgvector/pgvector#filtering

<a id="ref11"></a>[11] vLLM Project. Automatic Prefix Caching design. vLLM Documentation. Current. https://docs.vllm.ai/en/latest/design/automatic_prefix_caching.html

<a id="ref12"></a>[12] Kubernetes SIG Multi-Tenancy. Multi-Tenancy Working Group. Retrieved 2026-08. https://github.com/kubernetes-sigs/multi-tenancy

<a id="ref13"></a>[13] Kubernetes. Pod Security Standards. Kubernetes Documentation. Retrieved 2026-08. https://kubernetes.io/docs/concepts/security/pod-security-standards/

<a id="ref14"></a>[14] MITRE. CWE-668: Exposure of Resource to Wrong Sphere. https://cwe.mitre.org/data/definitions/668.html

<a id="ref15"></a>[15] PgBouncer. Features: session, transaction, and statement pooling modes. PgBouncer Documentation. Retrieved 2026-08. https://www.pgbouncer.org/features.html

<a id="ref16"></a>[16] Google. gVisor: Application Kernel for Containers. gVisor Documentation. Retrieved 2026-08. https://gvisor.dev/docs/

<a id="ref17"></a>[17] Kata Containers. Kata Containers Documentation. Retrieved 2026-08. https://katacontainers.io/

<a id="ref18"></a>[18] MITRE. CWE-284: Improper Access Control. https://cwe.mitre.org/data/definitions/284.html

<a id="ref19"></a>[19] Milvus. Users and Roles: RBAC. Milvus Documentation. 2024. https://milvus.io/docs/rbac.md

<a id="ref20"></a>[20] Pinecone. Security overview. Pinecone Documentation. 2024. https://docs.pinecone.io/guides/production/security-overview

<a id="ref21"></a>[21] OWASP GenAI Security Project. LLM08:2025 Vector and Embedding Weaknesses. OWASP Top 10 for LLM Applications. 2025. https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/

<a id="ref22"></a>[22] Kubernetes. Controlling Access to the Kubernetes API. Kubernetes Documentation. Retrieved 2026-08. https://kubernetes.io/docs/concepts/security/controlling-access/

<a id="ref23"></a>[23] Kubernetes. Resource Quotas. Kubernetes Documentation. Retrieved 2026-08. https://kubernetes.io/docs/concepts/policy/resource-quotas/
