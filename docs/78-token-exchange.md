# Token Exchange and Delegation

> Token exchange is the moment a service that holds a caller's token asks the authorization server for a different token to call a downstream API, and the safety of the whole chain collapses to whether the AS enforces four constraints on that request: the subject token is valid, the actor is authorized to act for that subject, the new audience is a resource the caller may reach, and the new scope is a subset of what the subject consented to. RFC 8693 defines the request and response shape (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `actor_token`, `requested_token_type`, `audience`, `resource`, `scope`), and RFC 8707 defines how the `resource` parameter binds the resulting token's audience so it cannot be replayed against another API. When services skip audience binding or actor validation, they collapse delegation into impersonation and give any compromised middle tier a universal token. The distinction matters because `act` and `may_act` claims (RFC 8693 section 4.1) exist precisely so the downstream can see the full chain and refuse when the actor was never granted delegation rights. Doc 55 (MCP) and doc 50 (credential passthrough) both trace to the same root cause: a token minted for audience A being accepted at audience B.

**Interview frequency:** Niche

## Quick reference

```http
POST /oauth2/token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&resource=https%3A%2F%2Fbackend.example.com%2Fapi
&audience=urn:example:backend
&scope=read:orders
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&subject_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwic3ViIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL21pZC5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZDpvcmRlcnMgd3JpdGU6b3JkZXJzIiwiZXhwIjoxNzMxNTAwMDAwfQ.SIG
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwic3ViIjoibWlkLXRpZXItc3ZjIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlLmNvbSJ9.SIG
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

Response:

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwic3ViIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJhdWQiOiJ1cm46ZXhhbXBsZTpiYWNrZW5kIiwic2NvcGUiOiJyZWFkOm9yZGVycyIsImV4cCI6MTczMTUwMDMwMCwiYWN0Ijp7InN1YiI6Im1pZC10aWVyLXN2YyJ9fQ.SIG",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "read:orders"
}
```

The issued token's payload includes `"sub":"alice@example.com"`, `"aud":"urn:example:backend"`, `"scope":"read:orders"`, and `"act":{"sub":"mid-tier-svc"}`. That `act` claim is the delegation receipt: the backend sees Alice as subject but knows mid-tier-svc performed the call.

| Invariant | Where enforced | How violated | Source |
| --- | --- | --- | --- |
| Issued token audience is bound to a specific resource | AS token endpoint, downstream RS validator | AS omits `aud` or grants a wildcard, RS accepts any `aud` | RFC 8693 §2.2.1, RFC 8707 §2 |
| Actor is authorized to act for the subject (`may_act`) | AS policy engine | AS mints without checking `may_act` claim on subject token | RFC 8693 §4.1 |
| Issued scope is a subset of the subject token's consented scope | AS downscoping logic | AS copies `scope` from client request without intersection | RFC 8693 §2.1 |
| Subject token signature, issuer, expiry, revocation are validated | AS token endpoint | AS trusts a JWT purely because it parses | RFC 8693 §2.1, RFC 7519 §7 |
| Delegation chain (`act` nesting) is preserved and visible to RS | AS mint, RS authorization | AS strips `act`, or RS ignores nested actor | RFC 8693 §4.1 |
| Client is authenticated with a strong method (mTLS, private_key_jwt) | AS client auth layer | Public client or shared secret exposed in mobile app | RFC 8693 §2.1, RFC 8705 §2 |
| Refresh tokens issued via exchange are sender-constrained or short-lived | AS refresh policy | Long-lived refresh returned, then passed to a low-trust downstream | RFC 8693 §2.1, RFC 6749 §6 |
| Cross-domain exchange is gated by trust domain policy | AS federation policy | AS mints for any `resource` a client requests | RFC 8693 §1.3 |

## How it works

### The exchange request

RFC 8693 defines a new grant type (`urn:ietf:params:oauth:grant-type:token-exchange`) at the standard token endpoint. The client presents a `subject_token` (the identity being carried forward), optionally an `actor_token` (the identity of the calling service when the caller is not the subject), and requests a new token bound to a specific `audience` and/or `resource` with a specific `scope`. The `requested_token_type` names the shape of the return: an access token, a refresh token, an ID token, a generic JWT, a SAML 1.1 or SAML 2.0 assertion. The AS returns the exchanged token plus `issued_token_type`, so a caller who asked for `access_token` but got `refresh_token` back knows to switch handling.

### Impersonation vs delegation

Impersonation means the downstream sees only the subject and cannot tell that a middle tier made the call. Delegation means the downstream sees both: `sub` is the end user, `act` names the acting service, and the RS can apply policy that differs between "Alice logged in" and "mid-tier-svc acting for Alice." RFC 8693 section 4.1 encodes this with the `act` claim, which may itself contain a nested `act` when the chain is longer than two hops. The mirror-image claim is `may_act`, minted into the subject token by the AS to declare which principals are authorized to delegate for that subject. Without `may_act` enforcement, any service that captures a subject token can obtain a delegated token for itself.

### Audience binding via RFC 8707

RFC 8707 (Resource Indicators for OAuth 2.0) adds the `resource` parameter to authorization and token requests. The AS records the resource on the issued token as `aud`, and the resource server rejects tokens whose `aud` does not match its identifier. This is the mechanism that prevents the token-passthrough class of bug documented in [50-credential-passthrough.md](./50-credential-passthrough.md) and [55-mcp-protocol-deep.md](./55-mcp-protocol-deep.md): a token minted for the MCP server cannot be replayed against a downstream Gmail or Slack API because those APIs check `aud` and refuse. Without `resource`, the AS defaults to whatever audience the client is registered for, which for a coarse client is often "any first-party API."

### Downscoping

The `scope` parameter in a token exchange request must be a subset of the subject token's scope. A gateway holding `read:orders write:orders admin:orders` calling a reporting service should request only `read:orders`, so a compromise of the reporting service cannot pivot to writes. The AS enforces subset semantics; a client asking for a superscope receives `invalid_scope`. Correct downscoping combined with resource indicators produces tokens that are single-purpose, short-lived, and cheap to revoke by audience.

### Full flow

```mermaid
sequenceDiagram
    autonumber
    participant User as End User (Alice)
    participant Front as Frontend / Gateway
    participant Mid as Middle Tier (mid-tier-svc)
    participant AS as Authorization Server
    participant Back as Backend API (urn:example:backend)

    User->>Front: interactive login (auth code + PKCE)
    Front->>AS: code exchange, resource=https://mid.example.com
    AS-->>Front: subject_token aud=mid.example.com, may_act={mid-tier-svc}
    Front->>Mid: request with subject_token
    Note over Mid: Middle tier now holds Alice's token, needs to call backend on her behalf
    Mid->>AS: POST /token grant_type=token-exchange<br/>subject_token=(Alice's), actor_token=(mid-tier-svc mTLS-authed),<br/>resource=https://backend.example.com/api, scope=read:orders
    Note over AS: 1. Validate subject_token sig+exp+revocation. 2. Check may_act allows mid-tier-svc. 3. Intersect requested scope with subject scope. 4. Bind aud to backend resource. 5. Attach act={sub:mid-tier-svc}
    AS-->>Mid: access_token aud=urn:example:backend, act={mid-tier-svc}, scope=read:orders, exp=300
    Mid->>Back: GET /orders Authorization: Bearer <exchanged>
    Note over Back: Validate iss, aud=urn:example:backend, exp, sig, scope contains read:orders, optionally enforce policy on act.sub
    Back-->>Mid: 200 OK (orders for Alice)
    Mid-->>Front: response
    Front-->>User: rendered result

    rect rgba(255,180,180,0.35)
      Note over Mid,AS: Attack surface: unbounded audience, missing may_act check, scope copy-through, public client on token endpoint
    end
    rect rgba(255,180,180,0.35)
      Note over Mid,Back: Attack surface: RS ignores aud, RS ignores act, RS accepts any issuer
    end
```

### Azure AD On-Behalf-Of as a concrete implementation

Microsoft's OBO flow predates RFC 8693 and uses `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with `requested_token_use=on_behalf_of` and an `assertion` (the incoming user token) plus client credentials for the middle tier. Semantically it matches the 8693 exchange: the middle tier authenticates itself, presents the user's token, and asks for a token to a specific downstream `scope` (Microsoft encodes the audience in the scope string, for example `https://graph.microsoft.com/User.Read`). The issued token's `aud` is the downstream API and the `xms_st.sub` (or `azp` on newer tokens) identifies the middle tier. The failure modes documented for OBO (skipped conditional access, missing audience validation on downstream, refresh token propagation across trust boundaries) match the 8693 attack list one-for-one.

## Attack techniques

### 1. Unbounded audience token passthrough

A gateway is registered as a confidential client with a coarse audience "first-party APIs" and requests tokens without `resource` or `audience`. The AS issues tokens whose `aud` claim is the AS itself or a generic scope string. Every downstream API sees a validly signed token from the trusted AS and, absent strict `aud` checking, accepts it. The middle tier is now a universal identity: any service it can reach with the network path also trusts its token.

A payload looks like a normal token exchange with the `resource` parameter omitted: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=...&scope=read`. The returned access token carries `"aud":"https://api.example.com"` or worse `"aud":"api://default"`. Present that token to a completely different backend and it validates the signature, sees a plausible `aud`, and authorizes the call. This is the exact class of finding traced in [55-mcp-protocol-deep.md](./55-mcp-protocol-deep.md) where MCP servers accepted Anthropic-issued OAuth tokens that were minted for the LLM host.

Black-box detection: request a token via the gateway, decode the returned JWT (or introspect if opaque), and inspect `aud`. If it is a wildcard, empty, or matches a service other than the intended downstream, the AS is not enforcing audience binding. Blind confirmation without direct token access: send the same session cookie into two backends that should require independent authorization, and observe whether both accept the same underlying bearer.

Escalation is horizontal across every service that trusts the AS. Because token exchange typically preserves user identity, the attacker inherits the caller's permissions on each service rather than a service-account subset. A single compromise of the middle tier becomes cross-domain compromise of every trust-related backend<sup>[[1]](#ref1)</sup><sup>[[2]](#ref2)</sup>.

### 2. Missing `may_act` check enabling delegation elevation

A middle tier captures a subject token intended for a different downstream (via SSRF against the gateway, a leaky log, or a shared cache) and calls the token endpoint with that token as `subject_token` and its own credentials as `actor_token`. If the AS mints an exchanged token without checking whether the actor is listed in the subject token's `may_act` claim (or a policy equivalent), any service holding a subject token can delegate for that subject.

The exchange call is unmodified from the legitimate shape: `subject_token=<stolen>&actor_token=<attacker service's real credentials>&resource=<target>`. The attacker's service is a real, registered client; the AS authenticates it and issues an exchanged token whose `sub` is the victim user and `act.sub` is the attacker service. The `act` claim is the forensic evidence but only helps after the fact.

Black-box: pull a subject token issued for one downstream (via cooperative testing or a low-privilege account), then attempt exchange from an unrelated tenant client. If the exchange succeeds without a `may_act` error, delegation is unauthorized. Blind confirmation is trickier because success or failure comes back over the same channel; issue an exchange in a QA tenant with logging enabled and inspect the AS decision.

Escalation is vertical inside the subject's permission set. If the subject is an administrator, the attacker service gets an administrator-scoped token bound to a downstream of its choice. The attack is stealthy because the RS sees a valid delegation and, absent strict `act.sub` allow-listing, will authorize the call<sup>[[1]](#ref1)</sup><sup>[[3]](#ref3)</sup>.

### 3. Scope copy-through on exchange

A middle tier holds a subject token with scope `read:orders write:orders admin:billing`. It requests exchange for a reporting backend with `scope=admin:billing`, a scope the reporting service happens to accept for a different code path. If the AS does not enforce that the exchanged scope is a subset of what the subject consented to for the middle tier (or, in stricter policy, a subset of what the middle tier is allowed to request per its client policy), the middle tier now has an admin scope on a service it was never intended to administer.

The attack is trivial: any scope in the subject token is fair game. Payload: `subject_token=<held>&resource=<target>&scope=admin:billing`. The response contains a token that the target RS validates and authorizes for admin actions.

Black-box: enumerate subject-token scopes, exchange with each in turn, and observe which come back. Any scope that returns without downscoping enforcement is a policy gap. Blind detection through the RS: perform an admin action with the exchanged token and check for 200 vs 403.

Escalation is horizontal across scope families and often across services, because scope strings that were meaningful in the original client's context (`admin:billing` for the payments UI) get interpreted by whatever RS happens to parse them<sup>[[1]](#ref1)</sup>.

### 4. Refresh token minted via exchange, then leaked downstream

A client requests `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token` and receives a refresh token bound to the exchanged audience. If that refresh token is long-lived, not sender-constrained (no mTLS binding, no DPoP), and gets stored in a downstream service or logged, an attacker who captures it can mint fresh access tokens for the target audience indefinitely.

Payload: an ordinary exchange call with `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token`. The AS returns a refresh token in the response body. The middle tier stores it in a downstream cache to save round trips. Cache read access, log access, or database access now equals long-term impersonation.

Black-box: issue the exchange, decode or introspect the returned token, check for the presence of a refresh token and whether it is bound (`cnf.x5t#S256` for mTLS binding, `cnf.jkt` for DPoP). Blind: attempt to reuse the refresh token from a different network path or client cert and see if it succeeds.

Escalation is time: without binding, the refresh token converts a one-time compromise into persistence measured in days or weeks. See [13-jwt-token-security.md](./13-jwt-token-security.md) for the `cnf` claim mechanics and [14-oauth-oidc.md](./14-oauth-oidc.md) for sender-constrained token patterns<sup>[[4]](#ref4)</sup><sup>[[5]](#ref5)</sup>.

### 5. Chained exchange to strip actor identity

A three-hop chain (frontend, service A, service B) exchanges the subject token twice. If service A performs an exchange that omits its `actor_token` or the AS silently drops the existing `act` chain when re-minting, service B receives a token that appears to come directly from the user with no intermediary. Auditing and policy that depends on the `act` chain fails open.

Payload: service A performs exchange with `subject_token=<user token>` and no `actor_token`, or with an actor token that does not chain onto the existing `act`. The AS mints a new token with `sub=user` and either no `act` or `act={service A}` without the prior chain. Service B, applying policy of the form "only allow `act.sub=serviceA` for this operation," authorizes an action that should have required "act chain contains frontend."

Black-box: exchange twice through the chain in a test environment and decode the final `act` structure. If it is a single-level `{sub: serviceA}` rather than `{sub: serviceA, act: {sub: frontend}}`, chain preservation is broken.

Escalation is policy bypass: any RS decision that depended on chain shape (for example "service B may only be called on behalf of a user when the frontend was in the chain") is defeated. The `act` claim is the primary forensic mechanism for delegation<sup>[[1]](#ref1)</sup>.

### 6. Cross-domain exchange to unlisted resource

An AS federated across two trust domains accepts subject tokens issued by domain X and, on exchange, mints tokens for resources in domain Y. If the federation policy allows any `resource` value that the client is permitted to reach without enforcing which domains that client is allowed to bridge, a compromised client in one domain becomes an identity bridge into the other.

Payload: a token exchange call with `subject_token=<domain X user>` and `resource=<domain Y sensitive API>`. The AS mints a token whose `iss` is the local AS but whose subject came from domain X.

Black-box: enumerate `resource` values across domain boundaries. Blind: correlate audit logs across domains and look for exchanges whose `subject_token` iss and `aud` cross trust boundaries without an explicit federation entry.

Escalation is lateral across organizations. A partner integration that was scoped to a small set of APIs becomes a general-purpose account bridge<sup>[[1]](#ref1)</sup><sup>[[6]](#ref6)</sup>.

## Defense

### Real fix

1. **Enforce `resource` and audience binding on every exchange.** Configure the AS to require `resource` (RFC 8707) on token exchange requests and to reject exchanges whose resource is not on the client's per-client allow list. Set `aud` on the issued token to the exact resource identifier. On resource servers, validate `aud` as an exact string match against the RS's own identifier (see [17-cryptographic-failures.md](./17-cryptographic-failures.md) for JWT validation pitfalls). Wrong implementation: treating `aud` as a substring match or accepting an `aud` claim that lists more than one resource. Source: RFC 8693 §2.2.1, RFC 8707 §2<sup>[[1]](#ref1)</sup><sup>[[2]](#ref2)</sup>.

2. **Enforce `may_act` (or equivalent AS-side actor policy) before minting.** Subject tokens issued to any principal that will later be delegated by another service must carry `may_act` naming the authorized actors. On exchange, the AS resolves the actor (from client authentication plus optional `actor_token`) and refuses the exchange if the actor is not in `may_act`. Wrong implementation: relying on the client being confidential as a proxy for "allowed to delegate," so any confidential client can delegate for any subject. Source: RFC 8693 §4.1<sup>[[1]](#ref1)</sup>.

3. **Enforce scope subset semantics on exchange.** The AS computes `issued_scope = requested_scope ∩ subject_scope ∩ client_allowed_scope` and rejects with `invalid_scope` when the intersection is empty. Downscoping is one-way: an exchanged token cannot regain scope. Wrong implementation: copying the client's requested `scope` verbatim, or intersecting only with `client_allowed_scope` while ignoring the subject's consent. Source: RFC 8693 §2.1<sup>[[1]](#ref1)</sup>.

4. **Authenticate the exchanging client with mTLS or `private_key_jwt`.** The token endpoint's client authentication is the linchpin for delegation policy. Use RFC 8705 mTLS or `private_key_jwt` (RFC 7523) so client identity is provable and the resulting access token can be sender-constrained via `cnf.x5t#S256`. Wrong implementation: `client_secret_basic` for a client running in a mobile app or browser (which makes the "confidential" designation fictional). Source: RFC 8705 §2, RFC 7523 §2.2<sup>[[7]](#ref7)</sup><sup>[[8]](#ref8)</sup>.

5. **Preserve and enforce the `act` chain.** On each exchange the AS must nest the current actor over any existing `act` claim, producing `act: {sub: currentActor, act: {sub: priorActor, ...}}`. Resource servers apply policy against the full chain, not just the top-level actor. Wrong implementation: overwriting `act` with only the immediate caller, or dropping `act` when the RS's local token model has no field for it. Source: RFC 8693 §4.1<sup>[[1]](#ref1)</sup>.

### Defense in depth

1. **Sender-constrain access tokens issued by exchange.** Bind the exchanged token to the caller's mTLS certificate (`cnf.x5t#S256`) or DPoP key (`cnf.jkt`), so a stolen token from a downstream cache cannot be replayed from a different network path. Combine with RFC 8707 audience binding, and the token becomes worthless outside its intended (caller, resource) pair. Wrong implementation: sender-constraining the initial user token but not the exchanged token. Source: RFC 8705 §3, RFC 9449 §6<sup>[[7]](#ref7)</sup><sup>[[9]](#ref9)</sup>.

2. **Keep exchanged access tokens short (≤5 min) and avoid issuing refresh tokens on exchange.** Short access tokens with re-exchange each time limit blast radius when a downstream leaks. If a refresh token is genuinely required (long-running batch), bind it via `cnf` and store it in a service that treats it as high-value. Wrong implementation: setting refresh token TTL equal to the user session TTL. Source: RFC 6749 §6, RFC 8693 §2.1<sup>[[5]](#ref5)</sup><sup>[[1]](#ref1)</sup>.

3. **Per-resource client policy at the AS.** Register each middle-tier client with an explicit allow list of `resource` values it may exchange into, plus per-resource scope allow lists. This is the AS-level control that makes "unbounded audience" impossible even if the RS validator is wrong. Wrong implementation: a single "internal APIs" allow value that matches every backend by string prefix. Source: OAuth 2.1 §4.3<sup>[[10]](#ref10)</sup>.

4. **RS-side `act.sub` allow lists for privileged operations.** Resource servers apply operation-level policy against `act` (and its nested `act`s), for example "delete requires act.sub in {frontend-web, admin-console}." This catches missing `may_act` enforcement at the AS by rejecting delegated tokens the RS did not expect. Wrong implementation: policy that ignores `act` and only reads `sub`. Source: RFC 8693 §4.1<sup>[[1]](#ref1)</sup>.

5. **Log every exchange with subject, actor, resource, scope, and client auth method.** Central telemetry lets a detection layer identify novel (actor, resource) pairs, spikes in exchanges from a single client, and exchanges whose subject came from an unusual iss. Wrong implementation: logging only success or failure without the exchange parameters. Source: NIST SP 800-63C §5<sup>[[11]](#ref11)</sup>.

6. **Federation-aware policy for cross-domain exchange.** When the AS bridges trust domains, exchanges whose `subject_token.iss` and requested `resource` belong to different domains must go through an explicit federation policy that names allowed subject-issuer to resource-domain pairs. Wrong implementation: trust every subject issuer the AS's federation config lists, without pinning which resources each may reach. Source: RFC 8693 §1.3<sup>[[1]](#ref1)</sup>.

## Detection and telemetry

Log every token exchange with structured fields: `client_id`, `client_auth_method`, `subject_iss`, `subject_sub`, `subject_aud`, `actor_sub`, `requested_resource`, `requested_scope`, `issued_scope`, `issued_aud`, `issued_token_type`, `chain_depth` (nesting level of the resulting `act`), decision (`success`, `denied_may_act`, `denied_scope`, `denied_resource`), and correlation ID. On the resource server, log `aud`, `act.sub` (and each nested `act.sub` up the chain), the `iss`, and the operation category.

Alert on: an exchange whose `issued_aud` differs from the client's usual set (new-resource-for-client anomaly), rate spikes in exchanges from a single `client_id` (credential theft or scripted abuse), any exchange whose `subject_iss` is external and `requested_resource` is internal-sensitive (cross-domain bridge), any RS request whose `aud` does not match its own identifier (misdirected token), and any RS request whose `act` chain does not contain an expected upstream service for a privileged operation.

Canary tokens are useful here: mint exchanged tokens for a fake resource identifier that no legitimate service serves. Any request whose bearer resolves to that canary aud is either a scanner or a passthrough bug. A second canary: register a `may_act` claim naming a non-existent actor, and alert if an exchange succeeds naming that actor (indicates `may_act` is not being read).

Correlate exchange logs with downstream RS logs on the exchanged token's `jti`. A token minted for resource A that then appears at resource B is a passthrough violation and the strongest single signal that either audience binding or RS `aud` validation is broken.

## Interviewer probes

**Q1. Distinguish impersonation from delegation in RFC 8693 and explain why the distinction is enforceable.**

Mid: Impersonation replaces the caller with the subject, delegation preserves both via the `act` claim.

Principal: The subject token exchange produces a token whose `sub` is the end user in both models; the difference is what other identity survives. In impersonation the AS returns a token with no `act`, and the downstream cannot distinguish the middle tier from Alice logging in directly. In delegation the AS attaches `act: {sub: middleTier}`, chained on any prior `act`. Enforceability comes from three places: the AS decides which form to emit based on the exchange request and client policy, the RS reads `act` (single-level or nested) to apply operation policy that differs by caller, and the `may_act` claim in the subject token is what authorizes an actor to request delegation. Without `may_act` enforcement, the distinction is decorative because any actor can request delegation for any subject.

**Q2. Why is RFC 8707 (Resource Indicators) the essential companion to RFC 8693?**

Mid: Because it binds the exchanged token to a specific audience, so it cannot be replayed elsewhere.

Principal: RFC 8693 by itself defines the request shape but says the AS may choose the audience. In practice ASes default to whatever coarse audience the client is registered for, and downstream services trust the AS enough that the token validates. RFC 8707 supplies the `resource` parameter that the client uses to name the intended downstream, and the AS sets `aud` on the issued token to match. The RS then enforces `aud == self` (exact string match), which fails safely when a middle tier tries to replay a token minted for one backend against another. This is the exact remediation for the MCP passthrough class in doc 55 and the credential passthrough class in doc 50: without audience binding, delegation collapses into a universal bearer.

**Q3. Walk through the Azure AD OBO flow and map it to 8693 terms. Where does OBO diverge?**

Mid: OBO uses `jwt-bearer` grant with `requested_token_use=on_behalf_of`, semantically equivalent to 8693 exchange.

Principal: The middle tier authenticates with its own client credentials, sends the user's access token as `assertion`, and asks for a token to a specific downstream identified by `scope` (Microsoft encodes audience via the scope's resource prefix). The issued token has `aud` set to the downstream API, `sub` to the user's object ID, and `azp`/`xms_st.sub` naming the middle tier. Divergences: OBO predates 8693 and uses a JWT-bearer flavor rather than the 8693 grant type, scopes carry audience information rather than a separate `resource` parameter, and there is no first-class `may_act` claim (Azure enforces delegation via app permissions and admin consent rather than a subject-token claim). The failure modes are the same: skipped audience validation on downstream, refresh token propagation across app boundaries, and consent that grants a middle tier ambient permissions its callers never intended.

**Q4. How would you catch an "unbounded audience" bug in a production AS as a defender who does not own the AS?**

Mid: Decode issued tokens and check `aud`; if it is a wildcard or generic value, flag it.

Principal: I would start with black-box probes from a test client: perform a normal exchange, capture the returned token, and inspect `aud` and `azp` against the intended downstream. If `aud` matches a coarse value (like the AS itself or an "any" string), that is a static finding. Next I would use an audit log correlation: pull every token minted in a window, join with RS access logs on `jti`, and identify tokens whose RS-of-arrival differs from the `resource` requested at mint time. A third technique is canary resources: register a fake RS identifier, direct exchange traffic at it, and watch for tokens with that `aud` showing up at real backends (indicates RS ignores `aud`). Detection improves further with sender constraints: enforce `cnf.x5t#S256` and any replay from an unexpected TLS cert fails at the RS.

**Q5. Explain what `may_act` is, where it lives, and what breaks if it is absent.**

Mid: A claim on the subject token that names who is allowed to delegate for that subject; without it, any actor can delegate.

Principal: `may_act` (RFC 8693 §4.1) is a claim the AS embeds in the subject token at issuance, structurally similar to `act` but pointing forward: it names one or more principals authorized to later present this token as `subject_token` in an exchange and receive a delegated token. On exchange, the AS resolves the actor's identity from client authentication plus optional `actor_token`, matches it against `may_act`, and refuses when the actor is not listed. If `may_act` is absent or the AS does not check it, delegation authorization degrades to "any client that can authenticate to the token endpoint," which is a much weaker gate than intended. The consequence is horizontal privilege gain: a compromised confidential client can request delegated tokens for any user whose subject token it can obtain, capturing the user's full scope on any downstream.

**Q6. A middle tier needs to call ten different downstreams for a single user request. What is the correct exchange pattern?**

Mid: Perform one exchange per downstream with the appropriate `resource` and scope.

Principal: Ten exchanges, one per downstream, each specifying `resource=<that downstream>` and `scope=<subset needed for that call>`. Each returned token has `aud` bound to one target and scope narrowed to what that call requires. This looks expensive but is fine at scale: exchange calls are cheap, the AS can cache subject-token validation, and the tokens are short-lived so revocation and rotation are trivial. The wrong pattern is one exchange with a wildcard audience or with the union of all needed scopes, because it recreates the universal-bearer failure mode. A common mistake is caching one exchanged token per user and reusing it across downstreams; the invariant "one token, one resource" breaks the moment you do that.

**Q7. What does the `act` chain look like across three hops, and why does the RS care?**

Mid: `act: {sub: hop2, act: {sub: hop1}}`; the RS uses it for policy on delegated operations.

Principal: The frontend obtains a subject token for Alice. Middle-tier-A exchanges it and receives `act: {sub: A}`. Middle-tier-B exchanges the A-issued token and the AS attaches the current actor: `act: {sub: B, act: {sub: A}}`. If a fourth hop exists, the chain nests one deeper. The RS cares because privileged operations often should only be reachable via specific paths: a "delete customer" endpoint might require `act.sub == admin-console` or the chain to contain `admin-console`. Without chain preservation, an intermediate hop can strip the actor history and present a shorter chain than actually occurred, defeating the policy. Chain preservation is an AS obligation; RS enforcement of chain policy is defense in depth.

**Q8. Why is issuing refresh tokens via `requested_token_type=refresh_token` on exchange a foot-gun?**

Mid: Because refresh tokens are long-lived and often not sender-constrained, so a leak grants persistent access.

Principal: Access tokens issued via exchange are typically short (minutes) and audience-bound, so a leak is bounded in time and scope. A refresh token minted via exchange, absent sender constraints, is a bearer credential that mints fresh access tokens for the same audience for as long as it lives. If the exchanging service caches or logs it (a common pattern to save token endpoint round trips), the effective lifetime of a compromise extends from minutes to days or weeks. The mitigation is to sender-constrain the refresh token via `cnf` (mTLS or DPoP) so only the original caller's key material can redeem it, or to avoid refresh tokens on exchange entirely and re-run the exchange each time. When a batch job genuinely needs long-running access, the refresh token stays inside a dedicated credentials service and never crosses into general-purpose downstreams.

## War story

In September 2022, a security review of the Microsoft Teams desktop client documented that OAuth access tokens issued for the Teams client were being stored on disk in cleartext SQLite databases and accessible by any process with the user's file permissions. The tokens included refresh tokens with broad scope across Microsoft 365 (mail, files, calendar) minted through a flow that, by design, allowed the Teams middle tier to obtain user-context tokens for downstream Microsoft Graph APIs. Because the tokens were bearer, not sender-constrained, and their audience allowed calls into general-purpose Graph endpoints, extraction produced tokens that could read the victim's mail and files without further interaction. The finding surfaced two invariants missing at once: sender constraint on the exchanged tokens (which would have made file exfiltration insufficient without also stealing the client's key material), and narrower audience or scope binding on the exchanged tokens (which would have limited the blast radius even if extraction succeeded). Microsoft's response acknowledged the storage issue and pointed to platform-level protections; the token model itself remained bearer-based<sup>[[12]](#ref12)</sup>.

## Sources

<a id="ref1"></a>[1] RFC 8693: OAuth 2.0 Token Exchange. IETF. January 2020. https://www.rfc-editor.org/rfc/rfc8693

<a id="ref2"></a>[2] RFC 8707: Resource Indicators for OAuth 2.0. IETF. February 2020. https://www.rfc-editor.org/rfc/rfc8707

<a id="ref3"></a>[3] OAuth 2.0 Token Exchange: Delegation and Impersonation Semantics. IETF Datatracker (RFC 8693 §4). January 2020. https://www.rfc-editor.org/rfc/rfc8693#section-4

<a id="ref4"></a>[4] RFC 7519: JSON Web Token (JWT). IETF. May 2015. https://www.rfc-editor.org/rfc/rfc7519

<a id="ref5"></a>[5] RFC 6749: The OAuth 2.0 Authorization Framework. IETF. October 2012. https://www.rfc-editor.org/rfc/rfc6749

<a id="ref6"></a>[6] OAuth 2.0 Security Best Current Practice. IETF draft-ietf-oauth-security-topics. 2024. https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics/

<a id="ref7"></a>[7] RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens. IETF. February 2020. https://www.rfc-editor.org/rfc/rfc8705

<a id="ref8"></a>[8] RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants. IETF. May 2015. https://www.rfc-editor.org/rfc/rfc7523

<a id="ref9"></a>[9] RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP). IETF. September 2023. https://www.rfc-editor.org/rfc/rfc9449

<a id="ref10"></a>[10] The OAuth 2.1 Authorization Framework (draft-ietf-oauth-v2-1). IETF. 2024. https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/

<a id="ref11"></a>[11] NIST SP 800-63C: Digital Identity Guidelines, Federation and Assertions. NIST. 2017 (rev. 4 draft 2024). https://pages.nist.gov/800-63-4/sp800-63c.html

<a id="ref12"></a>[12] Microsoft Teams Stores Auth Tokens as Cleartext. Vectra AI Research. September 2022. https://www.vectra.ai/blog/undermining-microsoft-teams-security-by-mining-tokens

<a id="ref13"></a>[13] Microsoft identity platform and OAuth 2.0 On-Behalf-Of flow. Microsoft Learn. 2024. https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow
