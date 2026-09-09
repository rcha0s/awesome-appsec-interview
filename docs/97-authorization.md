# Authorization

> Authorization decisions choose among role-based (RBAC), attribute-based (ABAC), and relationship-based (ReBAC, the model Google's Zanzibar system popularized for expressing "owner of this object may edit it" as a graph rather than a role)<sup>[[2]](#ref2)</sup> access-control model families, each evaluated somewhere in an architecture that separates the policy decision point (PDP), the component that answers allow or deny, from the policy enforcement point (PEP), the component sitting in the request path that actually blocks or permits the call<sup>[[1]](#ref1)</sup>. This doc compares which model answers "can this actor perform this action on this resource" for a given system, and where the PDP sits relative to the PEP enforcing its answer. The decision forks by actor type, because a human clicking through a UI and a workload calling an API hand the model different inputs: a human's authorization usually rests on slowly-changing roles and resource-ownership relationships, while a workload's authorization is scoped, short-lived, and re-derived on every call with no person around to notice a wrong answer. The single biggest thing a Principal reviewer checks is whether the same actor-resource pair produces the same answer everywhere it's asked, because a model that looks correct in isolation but gets enforced inconsistently across services is the pattern behind most real-world access-control failures<sup>[[10]](#ref10)</sup>. Every model also drags along secondary features, self-service role or policy grants, break-glass access, policy drift between environments, that fail independently of whether the core model choice was right.

**Interview frequency:** Core

*See also: [Authentication](96-authentication.md) for what proves an actor's identity in the first place, and [Multi-Tenancy and Isolation](102-multi-tenancy-isolation.md) for the closely related case where the authorization model, especially ReBAC, is the tenant-isolation mechanism itself.*

## Where this decision forks

Actor type, a human acting through a UI versus a workload calling another service, is the axis this topic's security profile diverges across. It predicts which failure surfaces first: a human-facing model that's wrong tends to produce an IDOR-shaped bug someone eventually notices in the UI, while a workload-facing model that's wrong tends to produce silent over-permission nobody notices until an audit or an incident. Teams that reuse one context's answer in the other, RBAC roles bolted onto service accounts, or a ReBAC graph built for a sharing UI reused as the enforcement layer for machine-to-machine calls, end up with a model that fits neither, because the input shape (a stable human identity plus slow-changing relationships versus a short-lived credential re-evaluated per call) doesn't transfer. Authentication (see [Authentication](96-authentication.md)) answers who is making the call; every fork below assumes that question is already settled and asks only what the caller may then do.

### Human-facing authorization

A human's session already carries an identity, so authorization here is mostly about mapping that identity, plus the resources they own or are shared with, into an allow or deny per UI action. Multi-tenant SaaS and collaboration products push hardest toward relationship-based models, because who can see or edit a document depends on sharing, org membership, and inheritance, not a static role. Enterprise and workforce apps add a second wrinkle: role and group membership often live in an external IdP (Okta, Entra) and arrive as claims or SCIM-provisioned entitlements, so the app's authorization model has to treat an external directory as the source of truth rather than owning role assignment itself. Coarse admin panels and internal tools with a small, stable permission surface are often still fine on plain RBAC, and forcing a ReBAC graph onto them adds modeling cost with no payoff.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| RBAC | Coarse-grained, stable permission surfaces: internal tools, admin panels, a small number of roles | Multi-tenant apps needing per-object ownership or sharing, because role count explodes trying to model it | Still common | [Broken Access Control and IDOR](15-access-control-idor.md) |
| ABAC | Attribute-rich, relationship-poor domains: clearance level, department, time-of-day or geo rules<sup>[[3]](#ref3)</sup> | The access model is really about who owns or is shared a resource, where ABAC policies get combinatorially complex faking relationships with attributes | Still common | [Broken Access Control and IDOR](15-access-control-idor.md) |
| ReBAC (Zanzibar-style relationship graph) | Fine-grained, multi-tenant, relationship-heavy products: shared docs, folders, orgs, nested groups<sup>[[2]](#ref2)</sup> | A small app with few resource types and no sharing model, where the graph infrastructure buys nothing | Preferred | [Broken Access Control and IDOR](15-access-control-idor.md) |
| PBAC / policy-engine-driven (OPA/Rego, AWS Cedar) | Centralizing complex business-rule policy as versioned, testable code across many UI surfaces<sup>[[4]](#ref4)</sup> <sup>[[5]](#ref5)</sup> | No policy-testing discipline exists yet, where an unreviewed policy bundle carries the same risk as unreviewed code with production access | Preferred | [API Security (REST)](29-api-security.md) |
| Centralized PDP / authorization service | Products with several UI surfaces, web, mobile, partner portal, needing the same authorization answer for the same resource | A single app with one enforcement point already, where a network hop to a separate service buys nothing | Preferred | [API Security (REST)](29-api-security.md) |
| Inline per-service or per-controller checks (hand-rolled) | A single small service with one enforcement point and no shared resource model | More than one surface touches the same resource, where the same actor-resource pair silently gets different answers in different code paths | Legacy | [Broken Access Control and IDOR](15-access-control-idor.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Privilege escalation via self-granted roles | A user with any role-management UI access can grant themselves a broader role if the grant path isn't itself authorization-checked<sup>[[9]](#ref9)</sup> | Require a second approver, or a separate elevated permission, for any grant at or above the grantor's own level | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Break-glass and emergency access | Support staff needs temporary elevated access to fix a live customer issue, and an ungoverned "just make me admin" path is what attackers and auditors both find first | Time-boxed elevation through a separate approval workflow, logged and auto-expired, never a standing admin credential kept around for emergencies | [Money-Movement Authorization and Idempotency](92-money-movement-authz.md) |
| Delegated or impersonation access | An admin "logging in as" a customer to debug an issue is a real support need and a real audit gap when it isn't distinguished from the customer's own actions | Impersonation sessions carry a distinct identity claim and generate their own audit trail, separate from the user's normal session log | [Token Exchange and Delegation](78-token-exchange.md) |
| PEP placement (gateway vs service vs data layer) | The gateway can enforce coarse authn and scope, but it has no ownership graph, so it can't make an object-level decision without duplicating a stale copy of it | Coarse checks at the gateway, object-level decisions in the service layer where the ownership model lives, tenant/owner predicates enforced again at the data layer as the backstop | [API Security (REST)](29-api-security.md) |
| ReBAC read consistency (the "new enemy" problem) | A revocation and a subsequent read can be observed out of order, so a user just removed from an ACL can still get served the object the graph hasn't caught up on yet<sup>[[2]](#ref2)</sup> | Evaluate reads against a snapshot token or a bounded staleness guarantee tied to the write that revoked access, not a plain TTL | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Tenant-scoped policy evaluation | The same policy engine serving many tenants leaks a cross-tenant answer if tenant isn't a hard boundary inside every policy lookup, not just a filter applied after the fact | Scope every policy evaluation to a tenant ID the enforcement layer supplies from the verified credential, never one the caller passes | [Vector Stores (pgvector, Pinecone, Weaviate, Milvus)](59-vector-stores.md) |
| Authorization caching and staleness | A cached "allow" from five minutes ago is still cached after the role behind it gets revoked, so the UI keeps letting the user through a door that closed | Bound cache TTL to the org's acceptable revocation delay, and invalidate explicitly on role or policy change rather than relying on TTL alone | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Cross-service authorization consistency | A web app, a mobile API, and a partner-facing API can each implement their own check on the same resource and quietly diverge<sup>[[10]](#ref10)</sup> | Route every surface through the same PDP or the same shared policy library, not three reimplementations of "can this user see this document" | [API Security (REST)](29-api-security.md) |

Also worth checking: transaction-scoped authorization, binding the check to full transaction semantics rather than a static permission ([Money-Movement Authorization and Idempotency](92-money-movement-authz.md)); BOLA/BFLA, the mechanism-level API failure a wrong model produces<sup>[[8]](#ref8)</sup> ([API Security (REST)](29-api-security.md)); IdP-driven role sourcing and SCIM deprovisioning lag, where the directory is the source of truth and the app's cache of it can outlive an offboarding ([Broken Access Control and IDOR](15-access-control-idor.md)).

### Service-to-service (workload) authorization

A workload has no session to carry forward and often no person to eyeball whether an answer looks right, so authorization here has to be re-derivable from the caller's credential and the target resource on every call. Service meshes and microservice fleets push hardest toward a centralized PDP, because the alternative, many services each hand-rolling the same ownership or scope check, drifts the moment one service's check falls behind a policy change. Multi-tenant platforms carry an extra edge here: the PDP itself often serves policy decisions for every tenant's workloads, so isolation has to hold inside the authorization service, not just inside the data layer it protects.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| RBAC (Kubernetes-style, coarse service roles) | Namespace- or cluster-scoped access between workloads and infrastructure APIs, a small number of well-understood roles<sup>[[6]](#ref6)</sup> | Fine-grained per-resource decisions between application services, where a Role binding can't express "may read only its own tenant's rows" | Preferred | [Kubernetes Security](85-kubernetes.md) |
| ABAC | Environment- or classification-driven rules: this workload may call this API only from this environment or below this data-sensitivity tier<sup>[[3]](#ref3)</sup> | The decision really depends on a relationship between two specific resources, which ABAC attributes approximate poorly at scale | Still common | [Broken Access Control and IDOR](15-access-control-idor.md) |
| ReBAC (Zanzibar-style relationship graph) | Platforms exposing the same fine-grained resource graph to both human and machine callers, one graph, two enforcement paths | A pure machine-to-machine mesh with no shared resource graph, where the graph's consistency guarantees buy nothing a scope claim doesn't already give | Emerging | [Broken Access Control and IDOR](15-access-control-idor.md) |
| PBAC / policy-engine-driven (OPA/Rego, AWS Cedar) sidecar or library | Per-call policy evaluation embedded at the PEP, low-latency, versioned as code, testable in CI<sup>[[4]](#ref4)</sup> <sup>[[5]](#ref5)</sup> | The org has no policy CI pipeline yet, where a policy bundle pushed straight to production is an unreviewed authorization change | Preferred | [API Security (REST)](29-api-security.md) |
| Centralized PDP / authorization service (network call per decision) | Fleets needing one auditable source of truth for authorization across many services and languages | The call path is latency-sensitive and the PDP isn't co-located, where a network round trip on every request becomes a new availability dependency | Preferred | [API Security (REST)](29-api-security.md) |
| Credential-scoped inline checks (token audience/scope only, no PDP) | Simple point-to-point calls where the token's own scope claim is the entire authorization decision<sup>[[7]](#ref7)</sup> | The scope claim needs to reflect a relationship or attribute that changes faster than tokens are reissued | Still common | [Token Exchange and Delegation](78-token-exchange.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Latency cost of a centralized PDP | Every call blocking on a network round trip to a separate authorization service turns a policy dependency into an availability dependency | Co-locate the PDP as a sidecar or embed the policy engine as a library, reserve a remote-call PDP for decisions that can tolerate the round trip | [API Security (REST)](29-api-security.md) |
| PDP unavailable: fail-open vs fail-closed | Fail-closed turns an authorization outage into a full outage; fail-open turns it into a silent authorization bypass exactly when nobody is watching | Fail closed by default, with a last-known-good cached policy bundle bounded by an explicit staleness budget as the practical middle ground | [API Security (REST)](29-api-security.md) |
| Policy testing and drift in CI/CD | A policy pushed straight to production with no test suite is an authorization change nobody reviewed, and staging and production policy bundles drift apart silently | Test policies against fixture cases in CI before deploy, and diff the deployed policy bundle against the reviewed one on a schedule | [API Security (REST)](29-api-security.md) |
| Cross-service authorization consistency | A service mesh where each service caches or re-derives its own answer for the same actor-resource pair produces different answers depending on which service is asked<sup>[[10]](#ref10)</sup> | Every service in the call path enforces against the same PDP or the same policy library version, not its own local copy | [Broken Access Control and IDOR](15-access-control-idor.md) |
| Privilege escalation via policy self-grant | A CI/CD pipeline or a service identity that can modify its own policy bindings can grant itself broader access than any human ever reviewed<sup>[[9]](#ref9)</sup> | Policy-authoring credentials stay separate from the identities the policies govern, with a review step neither side can bypass alone | [Kubernetes Security](85-kubernetes.md) |
| Tenant-scoped policy evaluation | A shared PDP serving many tenants' workloads leaks a cross-tenant answer if a tenant boundary isn't enforced inside the policy engine itself | Pass tenant identity from the verified credential, not a caller-supplied parameter, and scope every policy lookup to it | [Vector Stores (pgvector, Pinecone, Weaviate, Milvus)](59-vector-stores.md) |
| Authorization caching and staleness | A workload caching a PDP decision keeps calling with a revoked scope until the cache expires, invisible to whoever thought they'd already revoked it | Bound cache TTL to the org's acceptable revocation delay, and invalidate explicitly on scope or role change rather than relying on TTL alone | [API Security (REST)](29-api-security.md) |
| Delegated authorization through agentic tool calls | An agent or automation calling downstream tools on a user's behalf can silently inherit or widen the calling credential's scope at each hop | Narrow the credential's scope at every hop the call makes, never pass the original broad credential straight through | [Credential Passthrough and Token Scoping in Tool Calls](50-credential-passthrough.md) |

Also worth checking: workload RBAC role sprawl mirroring human role sprawl, over-permissioned service accounts nobody prunes ([Kubernetes Security](85-kubernetes.md)); multi-hop delegation, narrowing scope at each hop instead of propagating one broad token end to end ([Token Exchange and Delegation](78-token-exchange.md)).

## Recommended defaults by context

| Context | Recommended default | Why |
| --- | --- | --- |
| Human-facing, multi-tenant / relationship-heavy product | ReBAC (Zanzibar-style) for the resource graph, RBAC for coarse admin roles layered on top | Sharing, ownership, and org hierarchy are relationships, not attributes, and ReBAC expresses "owner of this object may edit it" natively |
| Human-facing, small internal tool or admin panel | Plain RBAC | The permission surface is small and stable, so a relationship graph's operational cost buys nothing |
| Service-to-service, single cluster or mesh | PBAC (OPA/Cedar) embedded at the PEP as a sidecar or library | Keeps policy centrally authored and testable without adding a network hop to every call |
| Service-to-service, multi-tenant platform serving external workloads | Centralized PDP with tenant identity carried in the verified credential | Per-tenant policy authorship and an auditable decision log for every tenant in one place, and one tenant's policy bundle never evaluated inside another tenant's process |

## Migration path

Most human-facing systems arrive at this decision already carrying RBAC role sprawl: roles named after the person who requested them, permission checks scattered through controller code, and a few roles nobody remembers granting. The right first stage is inventory, mapping every existing role to the resource relationships it's actually standing in for, before any ReBAC schema gets written. Teams that skip inventory and design the relationship graph from a whiteboard instead of the real permission surface end up rebuilding it a second time once production traffic surfaces the relationships the whiteboard missed.

The second stage runs the ReBAC check in shadow mode, alongside the existing RBAC checks, logging where the two disagree without letting the new model make a live decision yet. High-value resource types, documents, shared folders, org membership, migrate first, because that's where sharing and ownership actually matter and where the legacy RBAC model was already straining hardest. Coarse admin surfaces can stay on RBAC indefinitely, because moving them buys nothing.

Every UI code path with a hardcoded role check (`if user.role == 'admin'`) has to be replaced with a call into the new policy layer, and that replacement is invasive precisely because those checks are usually the least tested code in the app. QA needs new negative test cases the old role-based suite never had, because "can user A see a document shared by user B in a different org" is a relationship question the old tests never asked. Query latency at the graph layer is the other real risk, because a naive relationship lookup on a hot path can be slower than the role check it replaces, and the shadow-mode stage exists partly to catch that before it's user-facing.

If shadow results disagree with the legacy RBAC answer on a meaningful slice of traffic, rollback is trivial as long as the legacy checks stayed live and load-bearing throughout shadow mode rather than getting deleted early, so cutting back over needs no data restore. Engineering pushes back on the graph query latency and the schema-design work; product pushes back on redesigning the permissions UI around relationships instead of roles; security usually pushes for the migration after an IDOR-shaped incident makes the RBAC gap concrete rather than theoretical.

Service-to-service migration starts from a different problem: too many independent, hand-rolled checks, one per service, each reimplementing "does this caller own this resource" slightly differently. The first stage extracts those checks into a shared, in-process policy library so every service calls the same code, without yet introducing a network-based PDP or an external policy language. The second stage externalizes that shared library into an actual policy engine, OPA or Cedar, with policies authored as versioned files and tested in CI before any service picks up a new bundle. A remote, centralized PDP is a later stage still, adopted once the service count and the cross-language footprint justify the operational cost of running it, or once a multi-tenant platform needs isolation enforced inside the authorization service itself.

Services in different languages need either a policy-engine SDK for each language or a common protocol to a sidecar, so a polyglot fleet either standardizes on one policy engine early or accepts running two. Teams see the added latency of a network-hop PDP immediately in their p99 and push back hardest there, which is why the embedded-library and sidecar stages exist before a remote PDP becomes the default. Engineers writing Rego or Cedar for the first time need real ramp-up time, and a rushed rollout without that investment produces exactly the kind of unreviewed policy bundle the migration was meant to prevent.

A workload-authorization rollback needs the old inline checks kept live and monitored until the new policy path has run through at least one full deploy cycle with policy changes flowing through CI, because that's where new-path bugs are most likely to surface. Routing decisions through the new path behind a per-service feature flag, rather than one global cutover, lets a team roll back a single affected service without an emergency deploy across the fleet.

The signal that either migration is safe to complete comes from usage data: shadow-mode disagreement rate trending to near zero, added-latency budget staying inside SLO, and support or on-call ticket volume tied to the new path staying flat. A legacy path with near-zero traffic and no open tickets against it is the signal to retire it.

## Interviewer probes

**When would you choose ReBAC over RBAC for a new product's authorization model?**

Mid: When access depends on relationships, ownership, sharing, org membership, rather than a fixed set of roles, because RBAC has to fake those relationships with an exploding number of roles.

Principal: RBAC models "what kind of user is this," which works when the permission surface is coarse and stable, but it models "who can see this specific object" poorly, because expressing per-object sharing in RBAC means minting a role per object or per share, and role count explodes with usage<sup>[[2]](#ref2)</sup>. ReBAC expresses ownership and sharing as edges in a graph, "user is editor of document," "document is child of folder," and evaluates access by walking that graph, which is the model Google built Zanzibar around specifically because role-based systems couldn't scale to Google Docs-style sharing<sup>[[2]](#ref2)</sup>. The tradeoff is real: a relationship graph is more infrastructure than a roles table, so a small app with no sharing model gets nothing back for adopting it.

**RBAC vs ABAC vs ReBAC, when do you pick each?**

Mid: RBAC for coarse, stable roles, ABAC for attribute-rich rules with few relationships, ReBAC for fine-grained, relationship-heavy, multi-tenant systems.

Principal: The fastest way to tell them apart is asking what the policy actually needs to reference. If the answer is "the user's job function," RBAC fits. If it's "the user's department, the resource's classification, and the time of day," that's ABAC<sup>[[3]](#ref3)</sup>, and it stays tractable as long as the number of attribute combinations that matter stays small. If the answer is "whether this specific user has been granted this specific object by this specific other user," that's a relationship, and forcing it through ABAC means encoding relationships as attributes, which is where ABAC policies get unreadable at scale. Most real systems end up layering two of the three, ReBAC for the resource graph and RBAC for coarse admin roles that sit outside it, rather than picking exactly one.

**What's commonly missed when a team moves from inline per-service checks to a centralized PDP?**

Mid: The latency and availability cost, every request now depends on a service that didn't exist as a dependency before.

Principal: Teams model the consistency win, one source of truth for every service, and skip modeling the new failure mode: the PDP going down or getting slow now takes every dependent service down or slow with it, where before each service's local check failed independently. The fix isn't skipping centralization, it's co-locating the decision point, a sidecar or an embedded policy engine evaluating a locally cached policy bundle, so the network dependency is on policy distribution rather than on every single authorization call<sup>[[4]](#ref4)</sup>. Teams that centralize without that step usually end up decentralizing the evaluation again within a year while keeping the policy authoring centralized, which is the shape most mature setups land on anyway.

**When the centralized PDP is unreachable, should the system fail open or fail closed?**

Mid: Fail closed by default, because a silent authorization bypass is worse than a hard outage on the affected path.

Principal: Fail-open is occasionally defensible on a narrow, low-privilege read path where availability genuinely outranks the small risk window, but it needs to be a named, reviewed exception, not the default anyone reaches for under incident pressure. The practical middle ground most fleets land on is a last-known-good policy bundle cached locally with a bounded staleness budget, so the PEP keeps enforcing a slightly stale but real policy instead of choosing between total outage and total bypass. Teams that never think this through end up deciding it during an actual incident, under pressure, which is how a "temporary" fail-open flag becomes the permanent default nobody remembers turning on.

**What's the biggest risk in a self-service role- or policy-management UI?**

Mid: A user with grant permissions can grant themselves a broader role than they were meant to have, if the grant path isn't itself authorization-checked.

Principal: This is privilege escalation via improper privilege management, and the gap is almost always in the grant code path, not the access-control model itself<sup>[[9]](#ref9)</sup>. GitHub's 2012 mass-assignment vulnerability is the canonical public example: a request parameter that was never meant to be user-settable let a user add their own public key to an arbitrary organization, granting commit access nobody had approved, because the attribute-binding code trusted client-supplied fields the authorization layer never independently checked<sup>[[12]](#ref12)</sup>. The fix is treating grant paths as sensitive as the resources they protect: require a second approver for any grant at or above the grantor's own privilege level, and audit-log every grant with who granted it and who approved it.

**How do you handle break-glass access without leaving a standing backdoor?**

Mid: A separate, time-boxed elevation workflow that auto-expires and gets logged, never a standing admin credential kept around "just in case."

Principal: The tension is real: an incident where support genuinely needs elevated access right now is exactly the moment nobody wants to wait for a normal approval flow, which is why break-glass paths tend to get built without one and then never get revisited. The right shape separates the two failure modes it has to guard against, an attacker abusing the path and a legitimate responder needing speed, by making the elevation itself fast (self-serve, no multi-day approval) while making the audit trail unavoidable (every use generates an incident ticket and an automatic time-bound expiry, reviewed after the fact rather than gated before). A break-glass path with no expiry and no post-use review is functionally a standing admin account with extra steps.

**What's commonly missed when authorization is delegated through an agent or automation calling tools on a user's behalf?**

Mid: The agent inheriting the user's full credential scope instead of a narrowed one, so a compromised or misdirected tool call can do anything the original user could.

Principal: The natural implementation path is passing the calling user's token straight through to whatever tool or downstream service the agent invokes, because it's the path of least resistance and it works in a demo. It also means every tool the agent calls gets the same blast radius as the original credential, so a prompt-injection-driven or buggy tool call inherits far more authority than that specific action needed. The fix is narrowing scope at each hop, minting a token scoped to exactly what this call needs rather than propagating the broad one, the same pattern OAuth token exchange formalizes for human delegation<sup>[[7]](#ref7)</sup>.

**Why does a cross-service authorization inconsistency matter more than a single service's bug?**

Mid: Because the same actor-resource pair getting different answers from different services means an attacker only has to find the most permissive path in, not break any single check.

Principal: A wrong-but-consistent check is a bounded bug; a right-in-one-service, wrong-in-another check is an attacker's menu, because the attacker doesn't need to find a flaw in the strict service, only route the same request through whichever service evaluates it more loosely. Capital One's 2019 breach is the widely cited example of the underlying pattern, even though the specific vector was an overprivileged IAM role rather than a policy check: a service was granted broader access than its actual function needed, and that gap between granted and needed access was exactly what got exploited through an unrelated request-forgery flaw<sup>[[11]](#ref11)</sup>. The fix is routing every surface through the same PDP or the same shared policy library version, so "which service answered" stops being a variable in the authorization outcome at all.

## Sources

<a id="ref1"></a>[1] NIST. Special Publication 800-207: Zero Trust Architecture (policy decision point and policy enforcement point definitions). August 2020. https://csrc.nist.gov/pubs/sp/800/207/final

<a id="ref2"></a>[2] Zanzibar: Google's Consistent, Global Authorization System. USENIX Annual Technical Conference, 2019. https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/

<a id="ref3"></a>[3] NIST. Special Publication 800-162: Guide to Attribute Based Access Control (ABAC) Definition and Considerations. https://csrc.nist.gov/pubs/sp/800/162/final

<a id="ref4"></a>[4] Open Policy Agent (Styra / CNCF). Documentation: policy-as-code with Rego. https://www.openpolicyagent.org/docs/latest/

<a id="ref5"></a>[5] Amazon Web Services. Cedar policy language documentation. https://docs.cedarpolicy.com/

<a id="ref6"></a>[6] Kubernetes. Using RBAC Authorization. Kubernetes documentation. https://kubernetes.io/docs/reference/access-authn-authz/rbac/

<a id="ref7"></a>[7] IETF. RFC 8693: OAuth 2.0 Token Exchange. January 2020. https://www.rfc-editor.org/rfc/rfc8693

<a id="ref8"></a>[8] OWASP. API Security Top 10 2023, API1 Broken Object Level Authorization and API5 Broken Function Level Authorization. https://owasp.org/API-Security/editions/2023/en/0x00-header/

<a id="ref9"></a>[9] MITRE. Common Weakness Enumeration CWE-269: Improper Privilege Management. https://cwe.mitre.org/data/definitions/269.html

<a id="ref10"></a>[10] MITRE. Common Weakness Enumeration CWE-863: Incorrect Authorization. https://cwe.mitre.org/data/definitions/863.html

<a id="ref11"></a>[11] U.S. Department of Justice. Seattle Tech Worker Arrested for Wire Fraud and Computer Intrusions in Connection with Capital One Breach. Press release. July 2019. https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-wire-fraud-and-computer-intrusions-connection-capital-one

<a id="ref12"></a>[12] GitHub. Public Key Security Vulnerability and Mitigation. GitHub Blog. March 2012. https://github.blog/2012-03-04-public-key-security-vulnerability-and-mitigation/
