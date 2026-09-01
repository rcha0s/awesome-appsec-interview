# Single Sign-On (SSO)

> SSO is not a protocol, it is a trust delegation pattern that hands identity assertion to a central Identity Provider (IdP) so a user proves themselves once and rides that proof into many Service Providers (SPs). The pattern is implemented over OIDC (JSON, JWT-bearer), SAML (XML, signed assertions), header-based reverse proxy (Cloudflare Access, OAuth2-Proxy), LDAP passthrough, or Kerberos IWA, and every one of them boils down to the SP verifying a cryptographic assertion that names an audience, an issuer, a subject, and a time window. The root cause of nearly every SSO breach is that the SP relaxed one of those four checks, or accepted an unsolicited assertion, or forgot that the local SP session outlives the IdP session. IdP compromise is the defining blast radius: a stolen signing key or admin console lets the attacker mint valid identities into every downstream SP, and this is what Golden SAML (CyberArk Labs, 2017; observed in the SolarWinds intrusion, 2020) exploited. Single Logout (SLO) is the mirror problem: even when logout at the IdP works, SPs frequently keep issuing local session cookies until they expire on their own.

**Interview frequency:** Common

*See also: [Authentication](96-authentication.md) for how this fits into the broader authentication architecture decision across web, mobile, desktop, and service-to-service contexts.*

## Quick reference

Wire-level shape of a SAML SP-initiated flow (POST binding, abbreviated):

```
# 1. User hits SP protected resource. SP redirects to IdP with AuthnRequest.
POST /idp/sso HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded

SAMLRequest=<base64 deflated AuthnRequest>&RelayState=/dashboard

# AuthnRequest (decoded, key fields):
<samlp:AuthnRequest ID="_a7b3..." Version="2.0"
  IssueInstant="2026-08-08T14:12:03Z"
  Destination="https://idp.example.com/sso"
  AssertionConsumerServiceURL="https://sp.example.com/acs"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>

# 2. IdP authenticates user, POSTs signed Response back to ACS URL.
POST /acs HTTP/1.1
Host: sp.example.com
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<base64 signed Response>&RelayState=/dashboard

# Response Assertion (decoded, key fields):
<samlp:Response InResponseTo="_a7b3...">        # binds to SP request
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>...</ds:Signature>              # covers Assertion
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>alice@example.com</saml:NameID>
      <saml:SubjectConfirmationData
        Recipient="https://sp.example.com/acs"  # audience-like check
        NotOnOrAfter="2026-08-08T14:17:03Z"
        InResponseTo="_a7b3..."/>
    </saml:Subject>
    <saml:Conditions NotBefore="..." NotOnOrAfter="...">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>
```

Invariants the SP must enforce on any SSO assertion (SAML or OIDC):

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Signature verifies against pinned IdP key | SP ACS / OIDC token endpoint | Trust store accepts any issuer, or XML signature wrapping bypass | SAML 2.0 Core §5, OIDC Core §2 |
| Audience matches this SP | SP assertion validator | `aud` / `<Audience>` unchecked, or trusts wildcard | OIDC Core §3.1.3.7, SAML 2.0 Core §2.5.1.4 |
| Issuer matches expected IdP entity ID | SP assertion validator | Multiple IdPs share trust store with no per-tenant pin | OIDC Core §3.1.3.7 |
| InResponseTo / nonce binds to a live SP request | SP session store | Unsolicited (IdP-initiated) flow accepts any assertion | SAML 2.0 Prof §4.1.5, OIDC Core §15.5.2 |
| Assertion within NotBefore / NotOnOrAfter window | SP clock + assertion validator | Clock skew tolerance too wide, or window unchecked | SAML 2.0 Core §2.5.1 |
| Assertion / token replay defense | SP replay cache keyed by assertion ID | No cache, or cache scoped per instance in a farm | NIST SP 800-63C-4 §4 |
| Logout propagates to SP session store | SP back-channel logout endpoint | SLO not implemented, or session cookie outlives IdP session | OIDC Back-Channel Logout §2.6 |

## How it works

SSO decouples authentication (done at the IdP, once) from authorization at the SP (done many times, based on identity claims). The SP maintains its own session cookie after the assertion is consumed. That local session is not the IdP session and does not automatically die when the IdP session dies. Any SSO deployment therefore has three moving pieces: the assertion flow, the SP local session, and the logout propagation channel.

### Taxonomy of SSO implementations

- **OIDC-based SSO.** The SP is an OIDC Relying Party. It receives an `id_token` (JWT) plus optionally an `access_token`. Federation with the enterprise IdP (Okta, Entra, Auth0, Google Workspace) is by trusting an OIDC issuer URL and its JWKS. Deep coverage lives in [14-oauth-oidc.md](./14-oauth-oidc.md) and [77-oidc-deep.md](./77-oidc-deep.md).
- **SAML-based SSO.** The SP consumes signed XML `<saml:Response>` assertions posted to an Assertion Consumer Service (ACS). Common in enterprise B2B, government, and legacy apps. Deep coverage lives in [68-saml.md](./68-saml.md).
- **Header-based reverse-proxy SSO.** A proxy (OAuth2-Proxy, Cloudflare Access, Pomerium, Ambassador) authenticates the user upstream, then injects `X-Forwarded-User`, `X-Auth-Request-Email`, or a signed JWT header into the upstream request. The SP trusts the header. If any request path bypasses the proxy, the header trust becomes a full-auth bypass.
- **LDAP passthrough.** The SP takes username and password, binds to an LDAP directory. Not federated SSO in the strict sense, but sold as SSO because the credential store is central. Weakness: password reaches every SP, and MFA has to be re-invented per SP.
- **Kerberos / Integrated Windows Authentication (IWA).** The browser hands a Kerberos ticket (SPNEGO) to the SP. Domain-joined machines only. Legacy but still huge in on-prem Windows environments; see [69-mtls.md](./69-mtls.md) for the adjacent hardware-bound story.

### SP-initiated vs IdP-initiated

An SP-initiated flow starts because the user hit the SP first. The SP generates a request ID (SAML `AuthnRequest ID`, OIDC `state` + `nonce`), stores it in a cookie or session, redirects to the IdP, and the IdP echoes that ID back in `InResponseTo` or `nonce`. The SP verifies the echo before accepting the assertion. This binds each assertion to one live request and defeats CSRF into the ACS endpoint.

An IdP-initiated flow starts because the user clicked "Launch this app" in an IdP dashboard. There is no prior SP request. The assertion arrives at the ACS with no `InResponseTo` (SAML) or a `nonce` the SP never issued (OIDC). Any code path that accepts these is vulnerable to unsolicited assertion injection, and losing the request binding also loses CSRF protection on the ACS.

```mermaid
sequenceDiagram
  autonumber
  participant U as User Browser
  participant SP as Service Provider
  participant IdP as Identity Provider

  Note over U,IdP: SP-initiated (secure)
  U->>SP: GET /dashboard
  SP->>U: 302 to IdP + AuthnRequest ID=_a7b3, state cookie
  U->>IdP: SAMLRequest / OIDC authz request
  IdP->>IdP: authenticate user (password + MFA)
  IdP->>U: signed Response, InResponseTo=_a7b3
  U->>SP: POST /acs (Response, RelayState)
  Note over SP: verify signature, aud, issuer, InResponseTo matches stored ID, window, not-replayed
  SP->>U: Set-Cookie: sp_session=...; redirect /dashboard

  Note over U,IdP: IdP-initiated (dangerous surface)
  U->>IdP: click "Launch App" tile
  IdP->>U: signed Response, NO InResponseTo
  U->>SP: POST /acs (unsolicited)
  Note over SP: if SP accepts, attacker can inject stolen or replayed assertions
```

### Session model after successful SSO

The assertion is consumed once and discarded. From that moment the SP issues its own session (cookie, JWT, opaque token), governed by SP policy: TTL, sliding vs absolute, revocation store, cookie flags. The IdP has no knowledge of that SP session. If the user logs out at the IdP, or the IdP admin disables the user, the SP session keeps working until (a) it expires by TTL, (b) the SP re-checks with the IdP, or (c) SLO is wired up.

This is the single most common SSO governance failure. Enterprises assume "we cut Alice off in Okta, she's gone." Alice is only gone from new logins. Every SP where she has a live cookie can be used until the cookie dies. See [72-session-management.md](./72-session-management.md) for the session lifecycle side.

### Single Logout mechanisms

- **SAML SLO.** Symmetric of SSO. Either party (SP or IdP) sends a `<LogoutRequest>` to the other, the other returns `<LogoutResponse>`. Two bindings: front-channel (browser redirect chain through every SP) and back-channel (server-to-server SOAP). Front-channel breaks if any SP is offline or slow. Back-channel needs mTLS or signed SOAP.
- **OIDC RP-initiated logout.** The RP redirects the user to the OP's `end_session_endpoint` with an `id_token_hint` and `post_logout_redirect_uri`. The OP terminates its session and redirects back. Does not by itself notify other RPs.
- **OIDC front-channel logout.** The OP puts iframes in the logout page, one per RP with a registered `frontchannel_logout_uri`. Each iframe hits the RP with the browser cookies, so the RP can clear its session. Fragile: iframe blocking, third-party cookie policies (Safari ITP, Chrome partitioning) break it.
- **OIDC back-channel logout.** The OP POSTs a signed `logout_token` (JWT with `events` and `sid`) directly to each RP's registered back-channel endpoint. RP looks up the SP session by `sid` claim and revokes it. Robust to browser policy, requires the RP to store `sid` at login time.

## Attack techniques

### 1. Unsolicited assertion injection via IdP-initiated flow

An SP that accepts IdP-initiated SAML has no per-request state to bind against, so any signed assertion that names it as audience is accepted regardless of who delivered it. An attacker who obtains a valid assertion (from a phished user, a shared computer's browser history, or a leaked capture) can POST it to the SP's ACS in their own browser. The SP verifies the signature, sees an audience match, and mints a session cookie for the victim's identity.

Sample malicious request: `POST /acs HTTP/1.1` with `SAMLResponse=<captured base64>` and no `RelayState`. Testing is direct: capture a legit SSO response with a proxy, log out, wait for the local SP session to die, then replay the raw `SAMLResponse` form field to the ACS from a clean browser. If a new SP session cookie appears, the SP is not enforcing `InResponseTo` and not tracking assertion IDs in a replay cache<sup>[[1]](#ref1)</sup>.

Escalation is direct account takeover of whatever identity the assertion names. A common escalation is grabbing an admin's assertion off a corporate loaner laptop that browser-restored the SAML POST body. Fix is to disable IdP-initiated at the SP or require the SP to seed a fake `AuthnRequest ID` and cookie even for IdP-initiated (some SDKs do this).

### 2. Audience confusion across SPs sharing an IdP

When an IdP serves many SPs, some SDKs treat `aud` / `<Audience>` as advisory. An assertion minted for `sp-a.example.com` gets replayed against `sp-b.example.com` in the same tenant, and if SP-B does not compare `aud` to its own entity ID, it accepts. The attacker only needs to induce login at SP-A (public marketing app) to harvest a token that unlocks SP-B (internal admin console).

Payload is trivial: sign in at the low-value SP, intercept the OIDC `id_token`, POST it into the high-value SP's callback with a matching `state` (or force IdP-initiated). Testing is best done by decoding an issued JWT, noting `aud`, and hitting a different SP's callback with the same token; a 200 with a session cookie confirms. Escalation depends on privilege gap between the two SPs<sup>[[2]](#ref2)</sup>.

### 3. IdP metadata poisoning and unpinned key rotation

SAML SPs typically fetch IdP metadata (a signed XML doc listing entity ID, endpoints, signing certs) from an HTTPS URL at deploy time. If the SP re-fetches on a schedule without pinning, an attacker who can MITM the metadata URL, or who compromises the metadata hosting bucket, can swap in an attacker-controlled signing cert. Every subsequent assertion signed by the attacker is trusted. OIDC has the same shape via unpinned JWKS URIs.

Example: a metadata endpoint served from an S3 bucket that later loses its bucket policy, or a JWKS served over a CDN with a wildcard cert. Testing is auditing the SP config: is the metadata URL fetched at runtime, is the resulting cert compared against a pinned thumbprint, is metadata itself signed and verified<sup>[[3]](#ref3)</sup>? Escalation is universal impersonation, indistinguishable from IdP compromise from the SP's view.

### 4. Broken Single Logout leaving live SP sessions

The user clicks logout at the IdP. The IdP kills its session and, if wired, sends SLO calls to registered SPs. If any SP does not implement SLO, or implements front-channel SLO that silently fails because a third-party cookie was blocked, or implements back-channel SLO but stores `sid` unmapped, the SP session cookie in the browser stays valid until TTL. An attacker who already stole the SP cookie (XSS, malware, shoulder-surfing) still has full access after the user believed they logged out.

Payload is the SP session cookie captured before logout. Testing: capture SP cookie, log out at IdP, replay cookie at SP, check whether it still authenticates. Escalation is timing: SP session TTLs of eight hours give hours of unrecoverable exposure post-revocation<sup>[[4]](#ref4)</sup>.

### 5. RelayState / redirect_uri as open redirect and session fixation

`RelayState` (SAML) and `redirect_uri` (OIDC) round-trip through the IdP unmodified. Some SPs treat the returned value as a trusted post-login redirect target without allowlisting. An attacker crafts an SP-initiated login URL where `RelayState=https://evil.example/steal`, sends it to a victim, and after successful SSO the SP redirects the authenticated browser to the attacker page. Combined with a browser autofill or a same-domain phishing lure, this is a plausible credential theft chain, or in older SPs a session fixation via a pre-set cookie carried through the login.

Testing is direct: submit any external URL as `RelayState`, see if the SP follows it after login. Escalation is a phishing amplifier: the redirect happens from the trusted SP origin, so URL-based indicators do not warn the user<sup>[[5]](#ref5)</sup>.

### 6. Reverse-proxy header injection when a request bypasses the proxy

Header-based SSO (OAuth2-Proxy, ambassador filters, nginx auth-request) works by the proxy stripping any inbound `X-Forwarded-User` and setting the trusted value only after auth. If the backend is reachable on any path that bypasses the proxy (an internal service mesh port, a legacy debug listener, a Kubernetes NodePort, a `kubectl port-forward`), the attacker sends `X-Forwarded-User: alice@example.com` directly and the app trusts it.

Payload: `curl -H "X-Forwarded-User: admin@corp" http://backend:8080/admin`. Testing is a port scan of the backend from a peer pod, or checking network policies for any allow rule that lets non-proxy traffic reach the app. Escalation is arbitrary identity spoofing, including admin, because the app has no independent signature check<sup>[[6]](#ref6)</sup>.

### 7. Cross-protocol confusion between OIDC and SAML for the same identity

A user has both an OIDC and a SAML integration at the same IdP for the same SP (rare but seen during migrations). The SP normalizes both to a local user record keyed on email. Attacker signs into a low-assurance OIDC path (public IdP, self-service signup with an unverified email that happens to match a corporate email) and lands on the same local account as the SAML path used by the real employee.

Testing is inventorying every login path that resolves to the same internal user ID and asking whether all paths enforce equivalent verification (email verified claim, tenant-restricted IdP, MFA). Escalation is stealing the account with the strongest privileges via the weakest login path<sup>[[7]](#ref7)</sup>.

### 8. IdP compromise and Golden SAML

The defining SSO risk. If the attacker steals the IdP's private signing key (SAML token-signing cert, OIDC JWKS private key), or gains admin control of the IdP tenant, they mint assertions for any user for any SP. No SP-side check helps: signatures verify, audiences match, issuers match, timestamps are fresh. Golden SAML, coined by CyberArk Labs in 2017 and observed in the wild during the SolarWinds intrusion in 2020, is exactly this pattern: an implant on the AD FS server exfiltrated the token-signing key, then assertions were minted offline and posted directly to cloud SPs.

Detection depends on the SP: unusually high assertion issuance rates, assertions with `AuthnInstant` that does not correspond to any real IdP login event, or assertions signed by a key seen for the first time. Escalation ceiling is the union of all connected SPs<sup>[[8]](#ref8)</sup><sup>[[12]](#ref12)</sup>.

## Defense

### Real fix

1. **Enforce SP-initiated flow with per-request binding.** Every SSO SDK path that consumes an assertion must require a matching `InResponseTo` (SAML) or `nonce` (OIDC) that was minted by this SP for this browser within the last five minutes. Store the request ID in a signed cookie or a server-side session before redirecting. Reject any assertion whose `InResponseTo` is empty, unknown, or already consumed. Common wrong implementation: setting `allow_idp_initiated: true` in the SDK config to make integration tests pass, then never removing it. Source: SAML 2.0 Web SSO Profile<sup>[[1]](#ref1)</sup>.

2. **Verify signature, audience, issuer, and time window against per-tenant pinned trust.** The SP must call the assertion validator with (a) the pinned certificate thumbprint or JWKS key ID for this exact IdP tenant, (b) its own entity ID / OIDC `client_id` as the required `aud`, (c) its own ACS URL as the required `Recipient`, (d) clock skew tolerance of one to two minutes maximum. Common wrong implementation: trusting any cert chained to a public CA (SAML certs are self-signed by design; a public CA chain is a red flag not a green one). Source: OIDC Core §3.1.3.7, SAML 2.0 Core §5.4<sup>[[2]](#ref2)</sup><sup>[[9]](#ref9)</sup>.

3. **Pin IdP metadata and rotate through a signed, dual-key window.** Do not re-fetch metadata on each login. Snapshot the metadata at onboarding, pin the signing certificate's SubjectKeyIdentifier, and require a signed metadata blob for any refresh. Support two active signing keys during rotation so cutover does not require simultaneous SP redeploys. Common wrong implementation: `md.fetch_url(url, verify=False)` in Python SAML libraries. Source: SAML Metadata Interop Profile<sup>[[3]](#ref3)</sup>.

4. **Implement OIDC back-channel logout or SAML back-channel SLO, plus short SP session TTL as a floor.** On login, store the `sid` claim (OIDC) or `SessionIndex` (SAML) with the SP session record. On receiving a back-channel logout POST, verify its signature and revoke every SP session with that `sid`. Do not rely on front-channel iframes: Safari ITP and Chrome partitioning break them silently. Common wrong implementation: implementing back-channel but skipping `logout_token` signature verification, so anyone can log everyone out (or worse, replay a stale token to keep resetting sessions). Source: OpenID Connect Back-Channel Logout 1.0 §2.6 Logout Token Validation<sup>[[4]](#ref4)</sup>.

5. **Strip client-supplied SSO headers at the trust boundary.** For header-based reverse-proxy SSO, the proxy must unconditionally clear all `X-Forwarded-User`, `X-Auth-*`, and equivalent headers from inbound requests before the auth check, then set them itself. The backend must not be reachable except through the proxy (network policies, mesh sidecar, mTLS from proxy only). Common wrong implementation: relying on the proxy to strip but leaving a debug port open on the backend pod. Source: OAuth2-Proxy security notes<sup>[[6]](#ref6)</sup>.

6. **Allowlist RelayState / redirect_uri.** Post-login redirect targets must match an exact-string or path-prefix allowlist scoped to the SP's own origin. Reject any absolute URL, any `//` scheme-relative URL, any URL with a different host. Common wrong implementation: `if url.startswith("https://sp.example.com")` which allows `https://sp.example.com.evil.com`. Source: OWASP ASVS §5.1.5<sup>[[10]](#ref10)</sup>.

### Defense in depth

1. **Short SP session TTL with periodic re-validation against IdP.** Cap SP sessions at one to four hours absolute, sliding no more than fifteen minutes. Optionally re-query the IdP userinfo or introspection endpoint on privileged actions to catch IdP-side disable events even without SLO. This narrows the post-revocation window when SLO fails<sup>[[11]](#ref11)</sup>.

2. **Just-in-time provisioning with claim allowlists.** When an SP auto-creates users on first login, allowlist which claims can populate which fields. `email_verified: true` is required. Group memberships must come from an IdP-signed claim, not from a user-supplied header or a self-service group join. Prevents cross-protocol confusion because low-assurance login paths cannot escalate group membership.

3. **Step-up authentication at the SP for sensitive actions.** Even with SSO, ask for a fresh factor (WebAuthn per [70-webauthn-passkeys.md](./70-webauthn-passkeys.md), FIDO2 security key, TOTP) for admin operations. Limits blast radius of a stolen SP cookie or a replayed assertion.

4. **Hardware-key-protected break-glass local accounts.** Every SP must have at least one local admin account not federated to the IdP, protected by a WebAuthn resident credential stored in a safe. Without this, IdP compromise plus SP admin lockout leaves no recovery path. Also gives an out-of-band admin identity to disable the SSO integration entirely if the IdP is misbehaving.

5. **Detect impossible-travel and out-of-band assertion issuance.** SIEM rule: assertion `AuthnInstant` and SP-observed source IP geo do not match the IdP-side login geo, or assertion is minted at a time when the IdP logged no interactive user session. Golden SAML shows up here because the attacker mints offline and posts from their own infrastructure<sup>[[8]](#ref8)</sup>.

6. **mTLS between SP and IdP back-channel endpoints.** SAML back-channel SOAP and OIDC back-channel logout benefit from mutual TLS ([69-mtls.md](./69-mtls.md)) to prevent an attacker who reaches the SP's logout endpoint from resetting sessions at will.

## Detection and telemetry

Log every assertion consumption event at the SP with these fields: `assertion_id`, `issuer`, `audience_seen`, `subject`, `authn_instant`, `not_before`, `not_on_or_after`, `in_response_to`, `request_id_matched` (bool), `signature_key_thumbprint`, `sp_session_id_issued`. Alert on any assertion consumed where `request_id_matched=false` (IdP-initiated leakage if you meant to disable it) or where `signature_key_thumbprint` is not in the pinned set (metadata poisoning or rotation event). Track a counter of assertion consumptions per `signature_key_thumbprint` per hour; a new thumbprint appearing at high volume is Golden SAML or a legitimate but uncoordinated rotation.

For logout: log every logout event with source (`user_clicked_sp_logout`, `back_channel_logout_received`, `session_ttl_expired`) and count SP sessions terminated. If back-channel logout is wired and you receive zero `back_channel_logout` events per day while your IdP shows thousands of interactive logouts, SLO is broken. Canary account: enroll a synthetic user that signs in every hour and logs out at the IdP; alert if the SP session for that user is still valid five minutes after the scripted logout.

For header-based SSO, log the value of `X-Forwarded-User` as observed by the backend before the proxy overwrites it. Any non-empty value on inbound requests is either a misconfigured client library or an attacker probing for header injection.

## Interviewer probes

**Q: Why is IdP-initiated SSO more dangerous than SP-initiated, and can it be made safe?**

Mid: it has no per-request state so replayed assertions are accepted. Principal: SP-initiated binds every assertion to a request ID the SP just minted and stored in a cookie, closing the CSRF and replay windows on the ACS. IdP-initiated has no such state, so the SP has to fall back to weaker checks (audience, time window, replay cache) that leak if any of them is misconfigured. It can be made tolerable by (a) requiring a synthetic per-user `RelayState` token issued by the SP tile launcher, (b) implementing a strict assertion replay cache with monotonic assertion IDs across the SP farm, and (c) capping the assertion age at one minute. Most shops just disable it.

**Q: Walk me through the security-relevant differences between the four OIDC logout modes.**

Mid: RP-initiated tells the OP to log out, back-channel tells the RP to log out via server POST, front-channel tells the RP via iframe. Principal: RP-initiated only affects the OP session, not other RPs, and needs `id_token_hint` for the OP to know which session to kill. Front-channel is a browser-side broadcast via iframes; it fails silently under Safari ITP, third-party cookie partitioning, and any RP whose iframe fails to load. Back-channel is server-to-server with a signed `logout_token` carrying `sid` and `events`; robust to browser policy but requires the RP to have stored `sid` at login and to verify the token signature. In production, wire back-channel as primary and treat front-channel as best-effort.

**Q: The IdP admin disables Alice at 09:00. When is she actually locked out of SP X?**

Mid: whenever her SP session cookie expires. Principal: three possible answers. If SLO is wired via back-channel and Alice's session had `sid` stored, she is out within the propagation window (seconds). If SLO is not wired, she is out when the SP session TTL fires (hours). If SP does short-lived access tokens with refresh against the IdP, she is out at next refresh (minutes) because the IdP will refuse to re-issue. The interviewer wants you to say "it depends on SLO and session refresh policy, and this is why disable-in-Okta is not a security control on its own."

**Q: How would Golden SAML defeat every SP-side check, and what actually helps?**

Mid: the attacker has the signing key so signatures verify. Principal: with the token-signing cert exfiltrated from the IdP host, the attacker mints assertions offline with any subject, correct issuer, correct audience, fresh timestamps, unique IDs, and a valid signature. Every SP invariant passes. What helps at the SP: detect assertion issuance that does not correspond to an interactive IdP login (SIEM correlation between assertion audit at SP and login audit at IdP), require step-up MFA at the SP for privileged actions so the assertion alone is insufficient, and rotate the IdP signing key on a schedule with dual-key windows. What helps at the IdP: HSM-back the signing key so it cannot be exfiltrated as a file.

**Q: I'm running OAuth2-Proxy in front of a Kubernetes service. What is the failure mode I should worry about most?**

Mid: someone bypasses the proxy. Principal: the proxy trusts you because it authenticated you, then injects `X-Auth-Request-Email` into the upstream request. If any network path lets a pod, a NodePort, a port-forward, or a mesh sibling reach the backend without going through the proxy, that path can spoof arbitrary identity by setting the header directly. Fix is defense in depth: proxy strips inbound headers, backend network policy allows ingress only from the proxy identity (SPIFFE or mesh mTLS), and the backend also verifies a signed JWT header (`Authorization: Bearer`) rather than a plain string header. Bare header trust is not sufficient in a multi-tenant cluster.

**Q: What's the difference between `Audience` in SAML and `aud` in OIDC, and why does it matter for multi-SP tenants?**

Mid: same idea, different syntax. Principal: both name the intended consumer. SAML `<AudienceRestriction><Audience>` is a URI (usually the SP entity ID). OIDC `aud` is a string or array of client IDs. Multi-SP failure: an IdP tenant that issues tokens to twenty SPs must include only the target SP in `aud`, and each SP must verify `aud` contains its own client ID and nothing else it does not trust. Some SDKs (older node-oidc-provider consumers, some legacy Ruby SAML gems) treat missing audience as pass rather than fail. Sharing an audience across SPs, or wildcarding it, converts an assertion for one SP into a universal key.

**Q: You're auditing an SP that trusts IdP metadata from a public HTTPS URL. What should you check?**

Mid: the URL uses TLS. Principal: (1) whether the metadata blob itself is XML-signed and the SP verifies that signature against a pinned root, (2) whether the SP re-fetches on schedule and swaps trust automatically or requires a signed operator action, (3) whether the signing certificate has a pinned thumbprint the SP compares each fetch, (4) whether the URL sits on infrastructure with the same blast radius as the SP itself or on shared third-party infra (S3 bucket, CDN with wildcard cert). Unpinned metadata behind a wildcard TLS cert with auto-refresh is one takeover-of-the-hosting-account away from a signed-assertion forgery capability.

**Q: When would you deliberately not use SSO?**

Mid: for break-glass admin accounts. Principal: break-glass local admin credentials guarded by WebAuthn, disaster recovery service accounts, air-gapped or offline systems, and any surface where IdP outage would cause life-safety impact (medical, industrial control). SSO concentrates blast radius; the mitigating pattern is a small, audited set of non-federated identities on hardware-key MFA, with alerts on any use.

## War story

Golden SAML in the SolarWinds intrusion (2020). Attackers compromised on-prem AD FS servers via the SolarWinds Orion backdoor, then exported the AD FS token-signing certificate and its private key. With the key in hand they minted SAML assertions offline for arbitrary users into cloud SPs (Microsoft 365, Azure AD). SP-side signature verification passed because the key was genuine, audience and issuer matched, and timestamps were freshly stamped. Detection took months and hinged on correlating SP-side assertion audit logs with IdP-side login audit logs: assertions consumed at SPs with no matching interactive login at the IdP. The lasting industry response was to HSM-back or Azure Key Vault-back IdP signing keys, tighten AD FS access, and add step-up MFA at cloud SPs for privileged operations so a raw assertion is not a full skeleton key<sup>[[8]](#ref8)</sup><sup>[[12]](#ref12)</sup>.

## Sources

<a id="ref1"></a>[1] Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0, Web Browser SSO Profile §4.1. OASIS Standard. March 2005. https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf

<a id="ref2"></a>[2] OpenID Connect Core 1.0, §3.1.3.7 ID Token Validation. OpenID Foundation. November 2014 (errata set 2 2023). https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

<a id="ref3"></a>[3] SAML V2.0 Metadata Interoperability Profile Version 1.0. OASIS Committee Specification. August 2009. https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop.html

<a id="ref4"></a>[4] OpenID Connect Back-Channel Logout 1.0, §2.6 Logout Token Validation. OpenID Foundation. September 2022. https://openid.net/specs/openid-connect-backchannel-1_0.html

<a id="ref5"></a>[5] OAuth 2.0 Security Best Current Practice (RFC 9700), §4 Attacks and Mitigations (open redirection subsection). IETF. January 2025. https://datatracker.ietf.org/doc/html/rfc9700

<a id="ref6"></a>[6] OAuth2 Proxy Configuration and Security. oauth2-proxy project docs. https://oauth2-proxy.github.io/oauth2-proxy/configuration/security

<a id="ref7"></a>[7] Digital Identity Guidelines: Federation and Assertions (NIST SP 800-63C-4, 2nd Public Draft), §4 Assertions. NIST. 2024. https://pages.nist.gov/800-63-4/sp800-63c.html

<a id="ref8"></a>[8] Detecting Abuse of Authentication Mechanisms (Golden SAML). NSA Cybersecurity Advisory U/OO/198854-20. December 2020. https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF

<a id="ref9"></a>[9] Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0, §5.4 XML Signature Profile. OASIS Standard. March 2005. https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

<a id="ref10"></a>[10] OWASP Application Security Verification Standard v4.0.3, §5.1 Input Validation Requirements. OWASP Foundation. October 2021. https://owasp.org/www-project-application-security-verification-standard/

<a id="ref11"></a>[11] OpenID Connect Session Management 1.0. OpenID Foundation. September 2022. https://openid.net/specs/openid-connect-session-1_0.html

<a id="ref12"></a>[12] Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps. CyberArk Labs. November 2017. https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps

Cross-links: [14-oauth-oidc.md](./14-oauth-oidc.md), [68-saml.md](./68-saml.md), [69-mtls.md](./69-mtls.md), [70-webauthn-passkeys.md](./70-webauthn-passkeys.md), [72-session-management.md](./72-session-management.md), [77-oidc-deep.md](./77-oidc-deep.md).
