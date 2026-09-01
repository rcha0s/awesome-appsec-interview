# Authentication

> This decision is about how a system proves an actor is who it claims to be, and what credential that proof hands back for use on every request after. It forks hard by deployment surface because each surface controls a different trust anchor: a browser can hold an HttpOnly cookie the page's own JavaScript never touches, a mobile app has a biometric-backed OS keystore, a CLI often has neither a browser nor a keystore worth trusting, and a service has no human around to redirect to a login page in the first place. Reusing a web pattern outside its surface goes wrong in predictable ways, a client secret embedded in a decompilable mobile binary, a bearer token dropped in `localStorage` where any injected script can read it, a session cookie assumed on a headless service that never sends one. The single biggest thing a Staff reviewer checks is whether a credential's lifetime and storage location match its blast radius, because a long-lived, broadly-scoped credential sitting somewhere an attacker can read it is the recurring root cause underneath most authentication incidents, regardless of surface. Every mechanism below also drags a set of secondary flows along with it, password reset, remember-me, MFA recovery, that get their own line in the design-considerations tables because they fail independently of the primary mechanism, and a review that only checks the primary login path misses most of the real incidents.

**Interview frequency:** Core

## Where this decision forks

Authentication's security profile forks by deployment surface, not by industry or by application type, because the surface determines what trust anchors and storage primitives are even available to the design. A web app gets a same-origin cookie jar and CSRF exposure; a mobile app gets an OS keystore and biometric hardware but no reliable cookie story across app-to-app redirects; a desktop or native app gets full OS keychain access plus the option of running headless; a service has no user to authenticate at all and instead authenticates a workload or a client application. This is the same axis this repo already uses for authentication and session management topics, and it holds up here because the realistic option set and the sub-feature gaps genuinely differ across each context rather than converging on a shared answer. A team that picks one mechanism and applies it everywhere, session cookies for a mobile app's API calls, a shared static secret between microservices, is usually reproducing a web-shaped or a service-shaped answer in the wrong context rather than making a deliberate choice. The options tables below separate the primary credential from the continuity and storage layer wherever a context conflates them, because interview answers that name only one and skip the other miss half the design. Assurance level, how confident the system is in the claimed identity, is a real secondary axis layered onto a mechanism within a context<sup>[[10]](#ref10)</sup>, but it doesn't replace deployment surface as the primary fork, because a mobile app and a web app can both target the same assurance tier through completely different storage and redirect mechanics.

The four contexts also differ in who reviews the design. A web login gets scrutinized by whoever owns the browser-facing app; a service-to-service credential often gets provisioned by whoever stood up the pipeline, with no security review at all until an audit or an incident forces one, which is part of why static API keys persist so much longer in that context than anywhere else.

*Diagram: omitted. A single request-flow diagram would need to show a browser redirect, a mobile app-to-IdP handoff through an external user agent, an OS-keychain-gated native flow, and a workload-to-workload mTLS handshake in the same picture, four structurally different flows that don't compress into one annotated diagram without becoming either too abstract to clarify anything or too cluttered to read. The options tables below carry the comparison instead.*

### Web applications

The browser is both the strongest and the most exposed client here. It gets first-party storage the app's own JavaScript can be locked out of (`HttpOnly` cookies)<sup>[[8]](#ref8)</sup>, but it also runs third-party and first-party script side by side, so anything readable by JS is one XSS bug away from theft.

Federation matters more in this context than any other, because most orgs run many web properties and want one login across all of them, and the login surface itself is the most public-facing, most attacked entry point in the whole system, because it's reachable by anyone with a browser and no prior foothold.

A consumer fintech signup flow and an internal admin console both live in this context but land on different defaults: the fintech app leans hardest on passkeys and step-up because the account guards money, and the admin console leans on OIDC SSO because centralized revocation across every internal tool matters more than any single login's friction.

The web context is also where the credential and the continuity layer are most often confused with each other. A passkey or an OIDC assertion proves who the user is at one moment; the session cookie or BFF-issued cookie that follows is what keeps that proof usable across subsequent requests, and the two need separate rows below rather than one row standing in for both decisions.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Server-side session cookie | Any web app's continuity layer after login, composes with a password, OIDC, or a passkey as the credential underneath it rather than competing with them | An SPA calling a separate token-based API directly from the browser, where a BFF should hold the token instead | Preferred | [Authentication and Session Management](12-authentication-session.md) |
| Backend-for-frontend (BFF) token handler | An SPA calling a separate token-based API, holding tokens server-side and exposing only an HttpOnly session cookie to the browser<sup>[[21]](#ref21)</sup> | A traditional server-rendered app with no separate API to protect, where a plain session cookie already answers the whole question | Preferred | [Authentication and Session Management](12-authentication-session.md) |
| OAuth/OIDC-backed SSO | Multiple applications, enterprise or consumer federation, delegated identity across properties<sup>[[11]](#ref11)</sup> <sup>[[18]](#ref18)</sup> | A single simple app with no federation need, where the extra moving parts buy nothing | Preferred | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| WebAuthn/passkeys as primary login | Phishing-resistant, passwordless sign-in for consumer and workforce apps alike<sup>[[5]](#ref5)</sup> <sup>[[6]](#ref6)</sup> | The user base genuinely can't reach a compatible authenticator (kiosk, shared terminal, very old browser) | Preferred | [WebAuthn, Passkeys, and FIDO2](70-webauthn-passkeys.md) |
| Passwordless email link / OTP | Low-friction signup for low-stakes consumer apps with no password to manage | The account guards anything sensitive, because email-account compromise becomes full account takeover | Still common | [Password Authentication in 2026](75-password-authentication.md) |
| SAML 2.0-based SSO | Enterprise B2B customers whose IdP only speaks SAML, common in large regulated buyers | Consumer apps or greenfield systems where OIDC is simpler to implement and debug | Still common | [SAML 2.0](68-saml.md) |
| Risk-based / adaptive step-up layered on any option above | Apps wanting continuous risk signals, device, geography, velocity, to decide when to demand a stronger factor | The org has no fraud or risk signal pipeline to feed it, because a risk engine fed bad signals just adds friction without stopping anything | Still common | [MFA and Step-Up Authentication](73-mfa-step-up.md) |
| Bearer JWT stored client-side (`localStorage`/JS-readable) | Rarely: legacy SPA/API split built before same-site cookies or BFFs were viable | Any app with a plausible XSS surface, which is nearly all of them, because the token is unrevocable once issued | Legacy | [JWT and Token Security](13-jwt-token-security.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Password reset / forgot-password | Weak reset tokens are a full account-takeover path, and a chatty error response is an enumeration oracle<sup>[[9]](#ref9)</sup> | Single-use token, short TTL (~15 min), identical response and timing whether or not the account exists | [Password Authentication in 2026](75-password-authentication.md) |
| Remember-me / persistent login | A convenience feature that quietly becomes the longest-lived credential in the system if it isn't designed as its own object | Separate long-lived token (selector/validator pair), rotated on each use, revocable independent of the active session | [Authentication and Session Management](12-authentication-session.md) |
| MFA enrollment and account recovery | SMS OTP inherits SIM-swap risk, and recovery codes are the fallback attackers target when the primary factor is hardened<sup>[[10]](#ref10)</sup> | Authenticator app or passkey over SMS by default<sup>[[19]](#ref19)</sup>, recovery codes hashed at rest and shown once | [MFA and Step-Up Authentication](73-mfa-step-up.md) |
| CSRF and session fixation | Cookie-based auth reintroduces cross-site request forgery that a bearer-token-in-header design sidesteps | `SameSite=Lax` or `Strict` plus an explicit anti-CSRF token on state-changing requests, session ID rotated on privilege change | [Authentication and Session Management](12-authentication-session.md) |
| Sender-constrained (proof-of-possession) tokens | A stolen bearer token is replayable by anyone who holds it until it expires, no matter how it was stolen | DPoP-bound access tokens behind the BFF once token theft is a realistic threat model, not only mTLS-only environments | [JWT and Token Security](13-jwt-token-security.md) |
| Step-up authentication for sensitive in-session actions | A session good enough to browse isn't automatically good enough to change an email address or move money | Require a fresh authenticator interaction, not just an active session, before high-risk actions | [MFA and Step-Up Authentication](73-mfa-step-up.md) |
| Logout and session invalidation everywhere | Clearing the client-side cookie doesn't revoke a still-valid server-side session or any other device's active session | Server-side session invalidation on logout, plus a "log out everywhere" control that revokes every issued session and refresh token | [Authentication and Session Management](12-authentication-session.md) |
| Account linking between social login and a local account | A user who signed up locally and later clicks "Sign in with Google" with the same email can be silently merged into, or take over, the wrong account | Require proof of the existing account, a password or an active session, before linking a new federated identity to it | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |

Also worth checking: login-endpoint credential stuffing (progressive delay or CAPTCHA after N failures), federated identity key rotation (automated JWKS rollover), ID token and SAML assertion validation (blocks cross-app or cross-tenant replay), breached-password screening at signup and reset (now baseline hygiene, not defense in depth), idle vs. absolute session timeout, cookie domain scope (avoid over-broad `Domain=`), discoverable vs. non-discoverable passkey credentials, third-party OAuth app consent and connected-app review, rate-limiting on the token and introspection endpoints (often left unmonitored while the login form gets all the attention), a verification loop for a newly added recovery email, account deletion tearing down every stored credential and session, just-in-time account provisioning via SSO (stale IdP group risk), consistent logout across a federated and a local session, delegated admin access without credential sharing, timing-safe secret comparison, post-authentication continuous risk scoring on live sessions. See [Authentication and Session Management](12-authentication-session.md) and [Password Authentication in 2026](75-password-authentication.md).

### Mobile applications

The app can't lean on a same-origin cookie jar the way a browser tab can, and anything shipped in the binary, including a client secret, is recoverable by anyone who decompiles the APK or IPA. The platform gives back something a browser doesn't, though, a hardware-backed keystore and, on modern OS versions, a biometric authenticator the app never has to see raw.

Native OAuth for mobile has its own IETF guidance precisely because the naive web pattern fails here<sup>[[1]](#ref1)</sup>: a public client can't hold a secret, and the redirect back into the app is a place an attacker's app can try to insert itself.

A banking app and a habit-tracker app both ship as native mobile clients, but the banking app pairs PKCE with a passkey and step-up before a transfer, while the habit tracker can reasonably stop at OS-keystore-backed tokens and a lighter login, because the blast radius of a stolen session differs by orders of magnitude between the two.

Recovery deserves the same weight here as enrollment. A mobile-first user who loses their phone loses the passkey, the authenticator app, and the OS keystore all at once, so the recovery path has to survive total device loss, not just a forgotten password.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| OAuth Authorization Code + PKCE | Any mobile app doing federated or delegated login, the baseline for native OAuth absent a specific reason<sup>[[1]](#ref1)</sup> <sup>[[2]](#ref2)</sup> | Almost never | Preferred | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| Passkeys via platform authenticator | Primary login, replacing the password entirely, biometric-backed and synced through the platform's credential manager | Workforce apps needing centralized cross-platform revocation the platform ecosystems don't yet unify well | Emerging | [WebAuthn, Passkeys, and FIDO2](70-webauthn-passkeys.md) |
| OS keystore-backed refresh token storage | Persisting a session across app restarts without writing tokens to plaintext files, baseline hygiene regardless of the primary login mechanism above | Never | Preferred | [JWT and Token Security](13-jwt-token-security.md) |
| Native platform sign-in (Sign in with Apple / Google) | Fast consumer signup where the platform account is already trusted and available | Enterprise apps that need organization-level identity control rather than a personal platform account | Preferred | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| QR-code cross-device sign-in (scan-to-login) | Signing into a mobile app quickly using an already-authenticated device to scan a code, common in messaging apps | The QR code isn't bound to a short-lived, single-use challenge, because a static or long-lived code invites an attacker's own code to be scanned instead (quishing) | Still common | [WebAuthn, Passkeys, and FIDO2](70-webauthn-passkeys.md) |
| Embedded WebView login | Nothing today, historically used for social login before dedicated system browser tabs existed | Always: the app can read form fields and cookies inside its own WebView, defeating the isolation OAuth for native apps depends on<sup>[[1]](#ref1)</sup> | Legacy | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| OAuth implicit grant | Nothing today, historically the pre-PKCE way to get a token straight into a public client without a code exchange | Always: the token lands in a redirect URI or fragment with no client authentication, and the OAuth Security BCP deprecates it for exactly this reason<sup>[[17]](#ref17)</sup> | Legacy | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Deep-link / custom-URL-scheme interception | A second app registering the same custom scheme can receive the OAuth redirect and steal the authorization code | Prefer claimed HTTPS redirects (App Links/Universal Links)<sup>[[12]](#ref12)</sup> <sup>[[23]](#ref23)</sup> over bare custom schemes, and always pair with PKCE<sup>[[2]](#ref2)</sup> so a stolen code alone isn't redeemable | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| MFA enrollment and recovery on mobile | SIM-swap defeats SMS OTP silently, and a lost device with no bootstrapped backup factor locks the user out entirely | Authenticator app or passkey as the enrolled factor, recovery-code bootstrap offered at enrollment time, not only after lockout | [MFA and Step-Up Authentication](73-mfa-step-up.md) |
| Sender-constrained (proof-of-possession) tokens | A refresh token copied out of the OS keystore is a usable bearer credential anywhere else unless it's bound to the client that requested it | DPoP-bind access and refresh tokens to the app's own key pair so a copied token alone isn't redeemable elsewhere | [JWT and Token Security](13-jwt-token-security.md) |
| Client credential exposure in the binary | A "client secret" in a public mobile client isn't a secret, static analysis or a rooted device recovers it | Treat the mobile app as a public OAuth client with no secret, rely on PKCE for proof of possession instead<sup>[[2]](#ref2)</sup> | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| App attestation as a companion signal | Knowing a request came from a genuine, unmodified app build catches abuse that user authentication alone can't, like a scripted client replaying a stolen token | Layer Play Integrity or DeviceCheck attestation alongside user auth for sensitive endpoints, treat it as a signal, not a substitute for authenticating the user | [JWT and Token Security](13-jwt-token-security.md) |
| Certificate pinning for the API channel | TLS alone doesn't stop a malicious profile or a compromised device CA store from putting a trusted-looking proxy in the middle of API calls | Pin the API's certificate or public key with a safe rotation plan, and alert on pin-validation failures rather than failing silently | [mTLS and Client-Certificate Authentication](69-mtls.md) |
| Push-notification MFA fatigue | Attackers who already have the password spam approval push prompts hoping for one accidental or exhausted tap | Number-matching or context (location, app name) shown in the push challenge, plus rate-limiting repeated prompts to the same user | [MFA and Step-Up Authentication](73-mfa-step-up.md) |

Also worth checking: session/token continuity across restart and backgrounding, biometric fallback to PIN/passcode (must re-gate the same keystore item, not bypass it), jailbreak or root posture weakening keystore trust, a shared credential across an app suite (widens blast radius via a shared keychain group), token refresh races on flaky networks, screen recording and screenshot exposure of enrollment secrets, silent re-authentication after a backend-forced logout, background refresh renewing tokens without user presence, third-party auth SDK supply-chain trust, magic links opening in the wrong app or browser, shared login across app extensions and widgets, biometric enrollment scope (per-app vs. per-device binding), in-app biometric prompt spoofing via overlay attacks, anonymous or guest sessions upgrading to a full account, push-notification MFA delivered to the same device as the login, clipboard exposure of OTP codes copied for autofill, app-clip or instant-app authentication scope. See [Authentication and Session Management](12-authentication-session.md), [WebAuthn, Passkeys, and FIDO2](70-webauthn-passkeys.md), and [MFA and Step-Up Authentication](73-mfa-step-up.md).

### Desktop and native applications

Desktop apps sit between mobile and service-to-service: full OS access like mobile, but often no biometric hardware guaranteed, and frequently no browser to redirect through at all, because a CLI tool has no embedded user agent. Enterprise-managed fleets add a wrinkle mobile mostly doesn't have, device-issued client certificates and domain-joined identity as anchors independent of any user credential.

A CLI or headless service also has to authenticate a human at some point without ever running a browser itself, which is exactly the gap the OAuth device authorization grant was standardized to close<sup>[[3]](#ref3)</sup>.

A CLI deployment tool used by a platform team and a consumer-facing desktop email client both run as native apps, but the CLI tool is the one that actually exercises the device authorization flow day to day, because a headless CI runner has no browser to redirect through at all.

The desktop context also carries an assumption mobile and web reviewers rarely have to question: that the machine itself is single-user and trusted. Shared lab machines, kiosk deployments, and imaged fleets break that assumption routinely, which is why several of the design-consideration rows below are about isolation between users and processes rather than about the login mechanism itself.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| OS keychain-backed token storage | Any native app that needs to persist a session between launches, baseline hygiene independent of the login mechanism it pairs with | The target OS genuinely lacks a secure storage API, which is now rare outside embedded/IoT | Preferred | [Authentication and Session Management](12-authentication-session.md) |
| OAuth device authorization flow | CLIs, headless servers, TVs, and any app without an embedded or system browser to redirect through<sup>[[3]](#ref3)</sup> | The app already has full browser capability, where authorization code + PKCE gives a better UX than device-code polling | Preferred | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| Windows Integrated Auth / Kerberos SSO | Domain-joined corporate fleets logging into internal apps without a separate prompt<sup>[[15]](#ref15)</sup> | BYOD or non-domain-joined machines, or any client outside the Kerberos realm | Still common | [Single Sign-On (SSO)](67-sso.md) |
| SSH key or hardware-token auth for engineering tooling | Engineer-facing CLI and git tooling authenticating to internal systems, where a phishing-resistant hardware key is a realistic ask | Consumer-facing desktop apps with a non-technical user base that can't be expected to manage a hardware key | Still common | [mTLS and Client-Certificate Authentication](69-mtls.md) |
| Certificate-based authentication | Enterprise-managed endpoints and high-assurance B2B desktop software where device identity matters as much as user identity | Consumer apps with no certificate provisioning or enrollment infrastructure behind them | Niche-but-required | [mTLS and Client-Certificate Authentication](69-mtls.md) |
| Smart-card / PIV authentication | Government and highly regulated environments with a mandated PIV or CAC credential | The org has no smart-card issuance and reader infrastructure already in place | Niche-but-required | [mTLS and Client-Certificate Authentication](69-mtls.md) |
| Embedded browser/WebView login | Nothing today, same legacy pattern as mobile | Always: the same isolation-defeating problem as the mobile case | Legacy | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Device-code phishing | The device authorization flow needs no bug to abuse, an attacker tricks a target into approving the attacker's own device code on the real IdP login page and receives the resulting token<sup>[[22]](#ref22)</sup> | Short code TTL, show the requesting client and location context on the approval screen, restrict the grant via conditional access to devices that genuinely need it | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| MFA enrollment bootstrap on first desktop login | Desktop is frequently the first device a new employee authenticates from, so recovery-code issuance has to happen here safely | Issue recovery codes at enrollment, not retrofitted after a lockout ticket, and require a second verified channel before enrollment completes | [MFA and Step-Up Authentication](73-mfa-step-up.md) |
| Offline or intermittently connected authentication | A laptop that's offline can't reach the IdP, but the app still has to decide whether the cached session is trustworthy | Cache a short-lived proof of prior auth with its own expiry, and force re-authentication once connectivity returns and the cache is stale | [Authentication and Session Management](12-authentication-session.md) |
| Device credential revocation on offboarding | A certificate or long-lived token bound to a laptop that's been wiped or reissued is a standing access path if nobody revokes it | Device-bound credentials get revoked as part of the offboarding runbook, not left to expire on their own schedule | [mTLS and Client-Certificate Authentication](69-mtls.md) |
| Multi-user shared workstation credential isolation | A kiosk or fast-user-switching machine can leak one user's cached credential into the next user's session if storage isn't scoped per OS profile | Bind every stored credential to the OS user profile, never a machine-wide location, and clear on profile switch for shared or kiosk devices | [Authentication and Session Management](12-authentication-session.md) |
| Conditional access tied to device posture | A managed-device-only access policy is only as strong as the posture check behind it, and a stale or spoofable posture signal defeats the policy silently | Tie conditional access to an attested, regularly refreshed device-health signal, not a one-time enrollment flag | [mTLS and Client-Certificate Authentication](69-mtls.md) |

Also worth checking: OS-level biometric or PIN unlock gating the keychain (don't just check device-unlock state), long-lived refresh token storage on a shared or managed machine, local privilege separation from the OS account, idle timeout and auto-lock revalidating a cached session, cross-platform secure-storage fallback behavior (fail closed, never plaintext), credential leakage via shell history and process listings, password-manager autofill trust boundary, elevation prompts piggybacking on an active auth session, credential-helper file permissions, cached credentials baked into a shared corporate image, session tokens surviving an app uninstall, local network service discovery exposing an unauthenticated admin endpoint, time synchronization dependency for local TOTP generation, auto-update channel authentication independent of user login, a local privilege boundary between a helper process and the interactive session, portable or USB-run application credential persistence, session sharing between a GUI app and its companion CLI. See [Authentication and Session Management](12-authentication-session.md) and [mTLS and Client-Certificate Authentication](69-mtls.md).

### Service-to-service (machine) authentication

There's no human to redirect to a consent screen and no browser to hold a session cookie. The identity being authenticated is a workload or a client application, not a person, and the credential has to be something automation can mint, rotate, and present without a human in the loop.

This is also where static long-lived secrets do the most damage when they leak, because nobody notices a machine credential go stale the way a person notices a session logging them out, and a key sitting in a repository or a log line can sit undetected for a long time before anyone rotates it.

A payments microservice mesh and a marketing-automation platform calling a single third-party email API both do service-to-service auth, but the mesh justifies SPIFFE/SPIRE's operational cost at its service count, while the marketing platform is well served by a scoped OAuth client-credentials grant against the email vendor's token endpoint.

This context is also the one where the credential and the identity it represents are least separable. A human can reset a password and keep the same account, but a workload's credential and its identity are usually minted together, so revoking one commonly means retiring the other, which is why rotation and decommissioning show up as design considerations rather than as afterthoughts.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Cloud-provider IAM role assumption | Workloads running inside a single cloud provider that can assume a role through the platform's metadata service without ever handling a long-lived credential at all | The workload runs outside that cloud provider's own metadata service, where the assume-role mechanism doesn't apply | Preferred | [SPIFFE and SPIRE](81-spiffe-spire.md) |
| mTLS | East-west traffic inside a trusted network boundary needing strong mutual authentication | Fine-grained per-call authorization claims are needed beyond "which workload is this," or the org has no cert automation yet | Preferred | [mTLS and Client-Certificate Authentication](69-mtls.md) |
| Workload identity via SPIFFE/SPIRE | Multi-cluster or multi-cloud fleets needing automated, short-lived workload identity issuance at scale<sup>[[7]](#ref7)</sup> | A small single-cluster shop where the operational overhead of running SPIRE outweighs what it buys | Preferred | [SPIFFE and SPIRE](81-spiffe-spire.md) |
| OAuth 2.0 client credentials grant | A service calling a third-party or external API, standard machine-to-machine over existing OAuth infrastructure | Purely internal mesh traffic, where mTLS or workload identity is simpler and doesn't need a token endpoint round trip | Preferred | [OAuth 2.0 and OpenID Connect (OIDC)](14-oauth-oidc.md) |
| Private-key JWT client authentication | OAuth client authentication without a shared secret, where the client signs its own assertion with a private key<sup>[[13]](#ref13)</sup> | The org has no key-management maturity to issue and rotate the signing keys safely | Emerging | [JWT and Token Security](13-jwt-token-security.md) |
| Static API keys | Low-stakes, read-only third-party integrations or legacy systems with no OAuth support | Any credential that needs scoping, short expiry, or clean revocation, because API keys are usually long-lived, broadly scoped, and end up in logs and repositories, a related pattern CWE-798 tracks<sup>[[16]](#ref16)</sup>, and inertia keeps them common well past the point they're the right choice | Legacy | [JWT and Token Security](13-jwt-token-security.md) |
| HTTP Basic auth over TLS | Nothing today except talking to very old internal systems that predate any token-based option | Almost always: the credential is static, sent on every request, and functionally an API key with worse ergonomics and no scoping | Legacy | [JWT and Token Security](13-jwt-token-security.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Credential rotation at scale and secret sprawl | Manually rotated static secrets don't get rotated, and a leaked one has no expiry to bound the damage | Automate short-lived credential issuance (SPIFFE SVIDs, OAuth token TTLs) so rotation is the default behavior, not an on-call task | [SPIFFE and SPIRE](81-spiffe-spire.md) |
| Blast radius of a compromised CI/CD pipeline | A pipeline typically holds the broadest, longest-lived service credentials in the org because it deploys everything, making it the single highest-value target in this category | OIDC-federated, keyless short-lived credential exchange with the cloud provider as the target state, per-environment static-key scoping only as a fallback where the provider doesn't support it | [SPIFFE and SPIRE](81-spiffe-spire.md) |
| Multi-hop delegation ("on-behalf-of" calls) | Re-minting a broad service credential at every hop widens the blast radius of any single compromised service | Use token exchange<sup>[[4]](#ref4)</sup> to mint a narrowly scoped downstream token per hop rather than propagating one broad credential | [Token Exchange and Delegation](78-token-exchange.md) |
| Cross-trust-domain workload identity | Workloads in different clouds or orgs need to authenticate each other without sharing a private CA or a common IdP | Federate trust at the identity-provider layer instead of distributing shared secrets across the boundary<sup>[[14]](#ref14)</sup> | [OpenID Federation](82-openid-federation.md) |
| Non-human identity ownership and governance | A service account or workload identity with no named human owner is the credential nobody notices when it should be decommissioned | Every machine identity has a tracked owner and a review cadence, the same way a human account gets an access review | [SPIFFE and SPIRE](81-spiffe-spire.md) |
| Break-glass access when the identity provider is unavailable | An outage in the workload identity system or OIDC provider can take down every service that depends on it for auth, including the tools needed to fix the outage | A narrowly scoped, heavily audited emergency credential exists outside the normal identity path, used only during a declared incident | [SPIFFE and SPIRE](81-spiffe-spire.md) |
| Token audience confusion in multi-tenant platforms | A token minted for one tenant's API but validated loosely enough to also work against a sibling tenant's API is a cross-tenant authentication bypass | Every token carries, and every verifier checks, an explicit audience claim scoped to the specific tenant and service | [JWT and Token Security](13-jwt-token-security.md) |
| Long-lived Kubernetes ServiceAccount tokens as a default | Legacy-style ServiceAccount tokens mounted into every pod by default are effectively long-lived static credentials, widening blast radius if any one pod is compromised | Use bound, time-limited, audience-scoped ServiceAccount tokens rather than the legacy long-lived default<sup>[[20]](#ref20)</sup> | [SPIFFE and SPIRE](81-spiffe-spire.md) |

Also worth checking: leaked secrets in source control and logs, clock skew and token replay windows, zero-trust assumptions versus implicit perimeter trust, test and staging credential separation from production, service-mesh sidecar identity versus application-level identity, wildcard or overly broad certificate SANs for mTLS, standing OAuth grants held by third-party SaaS integrations, service-account reuse across unrelated applications, denial-of-service via expensive per-request authentication checks, bootstrap trust for a brand-new workload, observability and audit trail for machine-identity usage, retry storms amplifying authentication load during an IdP outage, emergency credential revocation at fleet scale, API keys that remain in production despite the legacy status, decommissioning a retired service's credentials and trust entries, credential-verification drift across a polyglot service fleet, a shared secret reused for authentication and payload signing. See [SPIFFE and SPIRE](81-spiffe-spire.md), [JWT and Token Security](13-jwt-token-security.md), and [mTLS and Client-Certificate Authentication](69-mtls.md).

## Recommended defaults by context

The table below is the fast-skim answer to "what would you actually ship." Every row trades a little more setup cost, federation metadata, a keystore integration, an attested workload identity, for a credential that expires on its own rather than one that has to be remembered, guarded, or manually rotated by a person.

| Context | Recommended default | Why |
| --- | --- | --- |
| Web applications | OIDC-backed SSO for federation, WebAuthn/passkeys for primary login, a BFF or server-side session for state | Passkeys close the phishing gap passwords can't, and keeping tokens server-side closes the XSS-theft gap `localStorage` opens |
| Mobile applications | OAuth Authorization Code + PKCE, passkeys via the platform authenticator, refresh token in the OS keystore | PKCE removes the public-client-secret problem, and biometric-backed passkeys beat password entry on a phone keyboard |
| Desktop / native applications | OS keychain-backed tokens, OAuth device flow for headless, certificate-based auth for managed fleets | Keeps secrets out of plaintext config and gives CLI tools a flow that doesn't need an embedded browser |
| Service-to-service | Cloud-provider workload identity for a single cloud, SPIFFE/SPIRE for multi-cloud or multi-cluster fleets, OAuth client credentials for external M2M | None of the three requires the workload to ever hold a long-lived static secret |

## Migration path

Web apps moving off password-plus-session usually add WebAuthn/passkeys as an additional first-class option before removing the password, because a same-day cutover locks out every user who hasn't enrolled a passkey yet. Enterprises adding OIDC-backed SSO on top of an existing local-login system run both in parallel and need an account-linking step, otherwise a user with a pre-existing local account and a freshly federated identity ends up with two unmerged accounts.

If passkey enrollment stalls or the account-linking step for OIDC SSO breaks access for a meaningful slice of users, the rollback is simple as long as the legacy password login was disabled per-user rather than deleted outright, so re-enabling it for affected accounts doesn't require a data restore.

The friction point in both cases is account recovery: a passkey-only account needs a recovery path that doesn't just reintroduce a weaker fallback, because an emailed magic link with no second check re-opens the phishing gap the passkey was added to close. Security and product usually push in the same direction here, because passwordless is both stronger and lower-friction to log into. Support and account-recovery teams are the ones who push back, because they own the harder recovery flow that comes with removing the password fallback.

Mobile apps still using an embedded WebView for OAuth login move first to a system browser tab (`ASWebAuthenticationSession`, Custom Tabs) with PKCE, because that's a fast, low-risk swap that closes the WebView credential-interception problem without touching the rest of the login UX. Passkeys layer on after that as the primary factor, with password or OTP kept as a fallback during the transition.

What breaks on mobile: users on an old app version built against the WebView flow need a forced update or a dual code path server-side during rollout, and teams that reused one custom URL scheme across multiple apps discover the collision only when the App Links migration forces them to look.

If a PKCE or passkey rollout breaks login for a meaningful slice of the installed base, the safer rollback is a server-side feature flag gating which flow the token endpoint accepts per client version, rather than an emergency app-store release that won't reach every user for hours or days.

Desktop and CLI tools moving off plaintext token files adopt an OS-keychain wrapper library first, which is a drop-in storage change with no UX impact. The device authorization flow for interactive CLI login comes next, once the keychain migration has landed and token storage is no longer the weakest link.

What breaks on desktop: teams that built pure automation, CI pipelines, cron jobs, around a static long-lived API token push back hard on being routed through an interactive device-code flow, so those paths need a separate service-account or client-credentials story rather than being forced through a human-facing flow.

Because the keychain migration and the device-flow rollout are additive rather than destructive to the old plaintext-token path until the very last stage, rollback is simply re-enabling the legacy code path server-side, which is why that path stays live and tested until usage data justifies removing it.

Service-to-service migration off static API keys and shared secrets is the slowest of the four because it requires rotation automation to exist before the old keys can be turned off. The typical staged path is mTLS or OAuth client credentials with short token TTLs first, then SPIFFE/SPIRE for fleet-wide workload identity once the service count justifies the operational investment, or cloud-provider workload identity directly where the whole fleet lives inside one cloud.

What breaks in service-to-service migrations: legacy vendors and partners that only support a static API key on their side need a bridge, a gateway that presents a key externally while minting scoped short-lived tokens internally, so the internal migration doesn't stall on an external dependency nobody controls. Platform teams tend to push back on the operational cost of running SPIRE; security teams push for it once a secret-sprawl incident, a long-lived key found in a log or a public repository, makes the static-key cost concrete rather than theoretical.

A workload-identity rollback needs the old static-key or mTLS path kept warm and monitored, not deleted, until the new path has run through at least one full credential-rotation cycle in production, because the rotation cycle itself is where new-path bugs are most likely to surface.

Tooling matters as much as sequencing. Every migration above goes smoother when the new and old mechanisms are both selectable behind a per-user or per-service feature flag rather than shipped as one global cutover, because a flag lets a team roll back one affected segment without an emergency deploy across the whole system.

Ownership matters just as much. The migrations that stall are usually the ones with no single team accountable for finishing them, because identity work touches every product team's login flow but belongs fully to none of them without an explicit platform-identity owner driving the cutover date.

The end state across all four contexts is the same shape even though the mechanics differ, a short-lived credential, bound to a hardware- or platform-backed store, issued and revoked by automation rather than a person, with the legacy long-lived alternative switched off only once nobody is measurably still using it.

The signal that a migration is safe to complete is rarely a calendar date, it's usage data. Track passkey or SSO enrollment rate against total active users, fallback-path usage (how often the old password or static key still gets used once the new option exists), and support-ticket volume tied to the new flow specifically. A legacy path with near-zero usage and a flat support-ticket trend is the actual signal to retire it, not a quarter-end deadline picked before the rollout started.

## Interviewer probes

The questions below mix tradeoff framing, when would you choose X over Y, with gap-probing framing, what's commonly missed, because a Staff-level review of an authentication design tests both: whether the primary mechanism fits the context, and whether the secondary flows riding along with it were designed at all.

**When would you choose a server-side session cookie or BFF over a JWT bearer token stored in the browser?**

Mid: A session cookie or BFF when the frontend needs the credential to be closed off from JavaScript, because a bearer JWT in `localStorage` is one XSS bug away from theft.

Principal: Revocation is possible for a JWT too, a denylist, or a short access-token TTL paired with refresh-token rotation, but every one of those reintroduces the shared server-side state lookup the stateless design was chosen to avoid, so you pay the session store's cost without keeping the simplicity. A first-party web app or an SPA behind a BFF that already needs that state gets nothing back for taking on the extra complexity. `HttpOnly` cookies are also the one storage location genuinely closed off from JavaScript-based theft<sup>[[8]](#ref8)</sup>, which a JWT sitting in `localStorage` is not.

**What's commonly missed when adding passkeys to an existing password-based login flow?**

Mid: The recovery path when the user loses every device that held a synced passkey.

Principal: Teams ship the happy path, enroll a passkey, log in with it, and only later realize the recovery flow has to be at least as strong as the passkey itself or it becomes the new weakest link. A password-reset-style "email a link" fallback undoes the phishing resistance the passkey was added for, because now an attacker who compromises the email account gets in the same way they always could. The right shape ties recovery to a second enrolled factor or an out-of-band identity check, not to email alone, and NIST's digital identity guidelines treat recovery as part of the enrollment design, not an afterthought<sup>[[10]](#ref10)</sup>.

**Why is OAuth client credentials usually a better default than a static API key for service-to-service auth in 2026, and when would you still choose the key?**

Mid: Client credentials issues a short-lived bearer token from a scoped grant instead of a permanent secret that never expires; a static key is still fine for a low-stakes legacy partner integration that genuinely has no OAuth support.

Principal: API keys fail in a specific, repeatable way, they end up in logs, CI config, and committed `.env` files because nothing about their design forces short lifetime or narrow scope, and a leaked one keeps working until someone notices and rotates it by hand. Client credentials tokens carry an expiry and an audience by construction, so a leaked token has a bounded lifetime even if nobody catches the leak immediately. The honest case for a key today is a legacy counterparty with no OAuth support, and even then it should sit behind a gateway that can revoke or rotate it without touching the partner relationship, treated as a bridge rather than an endpoint.

**What's commonly missed in mobile OAuth redirect handling?**

Mid: Using a bare custom URL scheme for the redirect instead of a verified App Link or Universal Link.

Principal: A custom scheme like `myapp://callback` can be registered by any app on the device, including a malicious one, which can then receive the authorization code meant for the legitimate app<sup>[[1]](#ref1)</sup>. PKCE blunts this by making the code alone unredeemable without the original code verifier<sup>[[2]](#ref2)</sup>, but it doesn't stop the interception itself, so it's a mitigation for the theft, not a fix for the exposure. Claimed HTTPS redirects, Universal Links on iOS, App Links on Android, close the exposure at the OS level, because the OS verifies domain ownership before routing the redirect to any app<sup>[[12]](#ref12)</sup> <sup>[[23]](#ref23)</sup>.

**How do you handle password reset without creating an account-enumeration oracle?**

Mid: Return the exact same response whether or not the submitted email matches an account.

Principal: The response body is the obvious leak, but the subtler one is timing and side effects, a reset email sent only on a match creates a timing difference an attacker can measure even with an identical response body. The token itself needs to be single-use and short-TTL independent of the enumeration question, because a long-lived reset token is a separate account-takeover path even for accounts an attacker already knows exist<sup>[[9]](#ref9)</sup>.

**mTLS versus SPIFFE/SPIRE versus cloud-provider IAM for service-to-service auth, when do you pick each?**

Mid: Cloud IAM role assumption when the whole fleet lives in one cloud, plain mTLS for a small number of directly-paired services, SPIFFE/SPIRE once you need fleet-wide automated identity across many services and clusters.

Principal: Cloud-provider role assumption is the simplest answer when it applies, because the workload never handles a credential at all, the platform's metadata service issues short-lived credentials on request. Plain mTLS with a private CA works fine at a scale where a human can reasonably reason about which certificate belongs to which service, but it breaks down operationally past a few dozen services because issuance and rotation become manual bottlenecks. SPIRE adds dynamic workload attestation, verifying a workload's identity from its runtime environment rather than a manually provisioned cert, and issues short-lived SVIDs automatically<sup>[[7]](#ref7)</sup>, which is why its adopters skew toward organizations running many services across multiple clusters or clouds.

**Why does "remember me" need different security treatment from a normal session?**

Mid: It's a much longer-lived credential, so it needs its own storage and revocation story instead of just a longer session TTL.

Principal: Extending the session cookie's TTL to cover "remember me" means the same credential that's active during a normal browsing session is now also the thing sitting in browser storage for weeks, so stealing it once buys an attacker weeks of access instead of hours. The standard fix is a separate long-lived token built as a selector/validator pair, stored hashed server-side, rotated on every use so a stolen-and-reused token is detectable, and revocable independently without killing the user's current active session.

**What's the biggest thing people miss when they adopt the OAuth device authorization flow for a CLI or headless client?**

Mid: That the flow is phishable, an attacker can get a victim to approve the attacker's own device code on the real login page.

Principal: The device flow needs no bug to abuse, it works exactly as designed and still hands the attacker a valid token, because the human enters a code shown to them by whatever asked for it, not necessarily the legitimate CLI. Enterprise-targeted campaigns in 2025 used exactly this pattern to phish Microsoft 365 accounts, directing targets to the real login page with an attacker-supplied device code<sup>[[22]](#ref22)</sup>. The fix is a short code TTL, showing the requesting client and location on the approval screen, and restricting the grant via conditional access to devices and users that actually need it, not a code patch, since there's no flaw to fix.

## Sources

<a id="ref1"></a>[1] IETF. RFC 8252: OAuth 2.0 for Native Apps. October 2017. https://www.rfc-editor.org/rfc/rfc8252

<a id="ref2"></a>[2] IETF. RFC 7636: Proof Key for Code Exchange by OAuth Public Clients (PKCE). September 2015. https://www.rfc-editor.org/rfc/rfc7636

<a id="ref3"></a>[3] IETF. RFC 8628: OAuth 2.0 Device Authorization Grant. August 2019. https://www.rfc-editor.org/rfc/rfc8628

<a id="ref4"></a>[4] IETF. RFC 8693: OAuth 2.0 Token Exchange. January 2020. https://www.rfc-editor.org/rfc/rfc8693

<a id="ref5"></a>[5] W3C. Web Authentication: An API for accessing Public Key Credentials (WebAuthn Level 3) specification. https://www.w3.org/TR/webauthn-3/

<a id="ref6"></a>[6] FIDO Alliance. FIDO2: WebAuthn and CTAP overview, passkeys specifications. https://fidoalliance.org/fido2/

<a id="ref7"></a>[7] SPIFFE Project (Cloud Native Computing Foundation). SPIFFE and SPIRE specifications, SVID format. https://spiffe.io/docs/latest/spiffe-about/overview/

<a id="ref8"></a>[8] OWASP. Session Management Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

<a id="ref9"></a>[9] OWASP. Forgot Password Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html

<a id="ref10"></a>[10] NIST. Special Publication 800-63-4: Digital Identity Guidelines. 2025. https://pages.nist.gov/800-63-4/

<a id="ref11"></a>[11] OpenID Foundation. OpenID Connect Core 1.0 specification. https://openid.net/specs/openid-connect-core-1_0.html

<a id="ref12"></a>[12] Apple. Supporting Associated Domains and Universal Links. Developer documentation. https://developer.apple.com/documentation/xcode/supporting-associated-domains

<a id="ref13"></a>[13] IETF. RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants. May 2015. https://www.rfc-editor.org/rfc/rfc7523

<a id="ref14"></a>[14] OpenID Foundation. OpenID Federation 1.0 specification. https://openid.net/specs/openid-federation-1_0.html

<a id="ref15"></a>[15] IETF. RFC 4120: The Kerberos Network Authentication Service (V5). July 2005. https://www.rfc-editor.org/rfc/rfc4120

<a id="ref16"></a>[16] MITRE. Common Weakness Enumeration CWE-798: Use of Hard-coded Credentials. https://cwe.mitre.org/data/definitions/798.html

<a id="ref17"></a>[17] IETF. RFC 9700: Best Current Practice for OAuth 2.0 Security. January 2025. https://www.rfc-editor.org/rfc/rfc9700

<a id="ref18"></a>[18] IETF. RFC 6749: The OAuth 2.0 Authorization Framework. October 2012. https://www.rfc-editor.org/rfc/rfc6749

<a id="ref19"></a>[19] CISA. Implementing Phishing-Resistant MFA. Fact sheet. https://www.cisa.gov/resources-tools/resources/fact-sheet-implementing-phishing-resistant-mfa

<a id="ref20"></a>[20] Kubernetes. Configure Service Accounts for Pods: bound, time-limited tokens. Kubernetes documentation. https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/

<a id="ref21"></a>[21] IETF. OAuth 2.0 for Browser-Based Applications (draft-ietf-oauth-browser-based-apps), backend-for-frontend pattern for token-based APIs. Internet-Draft. https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps

<a id="ref22"></a>[22] Microsoft Threat Intelligence. Storm-2372 conducts device code phishing campaign. February 2025. https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

<a id="ref23"></a>[23] Android Developers. Verify Android App Links. https://developer.android.com/training/app-links/verify-android-applinks
