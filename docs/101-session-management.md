# Session Management

> A session is the mechanism that lets one act of authentication keep proving identity across many later requests, and it decomposes into two properties that get sized and reviewed independently. The first is where the proof lives, either server-side state referenced by an opaque ID so revocation is a database delete, or client-held self-contained state like a JWT so revocation needs a short TTL or an explicit denylist because the server never has to be asked. The second is how long that proof stays valid, an idle timeout, an absolute lifetime, or explicit revocation, and a design that implements only one of the first two fails in a predictable direction, either letting scripted activity keep a session alive indefinitely or logging out a user who is still actively engaged. This doc governs which storage model and which lifetime controls a system commits to, and it forks hard by deployment surface because the realistic storage primitive differs sharply, a browser's cookie jar, a mobile keystore, a machine credential with no human session at all. The single biggest thing a Staff reviewer checks is whether the system can actually revoke a session immediately, because that is exactly where server-side and client-held designs diverge, and a design that can't answer "how fast can you kill this" under questioning hasn't actually made the decision yet.

**Interview frequency:** Core

## Where this decision forks

Deployment surface is the axis, because it determines which storage primitive is realistically available to hold the continuity proof at all. A browser gets a cookie jar the page's own JavaScript can be excluded from reading, and every state-changing request implicitly carries that cookie along, which is exactly what opens the CSRF exposure that cookie-based sessions have to design around. A mobile or desktop app has no cookie jar and no ambient credential; it gets an OS-backed keystore instead, so continuity becomes a token storage problem rather than a session problem in the browser sense. A service calling another service has no human session to speak of, just a credential with its own TTL, and giving it a session-shaped feature, an idle timeout, a listable "device," is usually a sign the design borrowed a web mental model where an issuer-and-re-issuer model fits better.

### Web applications

The cookie jar is the one storage location a browser page's own script can be locked out of, which is why every option below gets judged first on whether it keeps the continuity proof out of JavaScript's reach<sup>[[1]](#ref1)</sup>. That same cookie jar is what makes CSRF a structural risk unique to this context: the browser attaches the cookie to a state-changing request no matter which site triggered it, so cookie-based designs need an explicit defense the other two contexts don't<sup>[[2]](#ref2)</sup>. See [Authentication and Session Management](12-authentication-session.md) for the credential-versus-continuity split within login itself; this section assumes login already happened and covers what keeps that proof alive afterward.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Server-side session with opaque cookie | Any web app that needs revocation to be immediate and unconditional | No shared session store exists yet — it becomes a hard dependency on every authenticated request, and its outage means a fleet-wide forced logout, not a degraded read | Preferred | [Session Management Deep Dive](72-session-management.md) |
| Stateless JWT held in a cookie | Deployments avoiding a shared session store, multi-region reads with no round trip to a central store | Revocation has to be immediate, because an issued JWT stays valid until it expires regardless of what the server decides afterward<sup>[[3]](#ref3)</sup> | Still common | [JWT and Token Security](13-jwt-token-security.md) |
| Backend-for-frontend (BFF) holding the token server-side | An SPA calling a separate token-based API, wanting a JavaScript-inaccessible session on the browser side and a real token on the API side<sup>[[4]](#ref4)</sup> | A traditional server-rendered app with no separate API, where a plain session cookie already answers the question | Preferred | [Authentication and Session Management](12-authentication-session.md) |
| Sender-constrained token (DPoP)<sup>[[12]](#ref12)</sup> | High-value actions where a stolen bearer cookie or token must not work from another machine | No client-side capability to hold and prove possession of the binding key | Emerging | [JWT and Token Security](13-jwt-token-security.md) |

Binding and revocation are independent controls. DPoP or mTLS stop a stolen credential from working somewhere else, while the mechanisms below stop it from working at all, once the server decides to end the session.

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Idle timeout vs. absolute session lifetime | A session with only one of the two fails predictably: idle-only lets scripted or background activity keep it alive indefinitely, absolute-only logs out a user still actively engaged<sup>[[5]](#ref5)</sup> | Set both, sized independently, idle timeout short enough to bound an unattended device, absolute lifetime long enough not to interrupt normal use | [Session Management Deep Dive](72-session-management.md) |
| Logout and invalidation everywhere | Clearing the client-side cookie doesn't revoke a still-valid server-side session, and it does nothing to any other device's active session | Logout invalidates the server-side session record, and a separate "log out everywhere" control revokes every session tied to the account | [Session Management Deep Dive](72-session-management.md) |
| Session fixation on login and privilege change | An attacker who plants a known session ID before login inherits the authenticated session the moment the victim logs in<sup>[[6]](#ref6)</sup> | Regenerate the session identifier on login and again on any privilege change, never reuse a pre-auth ID post-auth | [Session Management Deep Dive](72-session-management.md) |
| CSRF exposure for cookie-based designs | The browser attaches the session cookie to any state-changing request a victim's browser is tricked into sending, cookie presence alone isn't proof of intent | `SameSite=Lax` or `Strict` plus an explicit anti-CSRF token on state-changing requests, layered rather than either alone | [Authentication and Session Management](12-authentication-session.md) |
| Revocation latency for the stateless JWT option | A short access-token TTL bounds how long a stolen token works, but that's a mitigation, not the same guarantee as revoking a server-side session on demand<sup>[[7]](#ref7)</sup> | Treat TTL as a blast-radius control, and add a real kill switch: a per-user token-version or valid-after timestamp checked against `iat`, a short-lived `jti` denylist, or introspection | [JWT and Token Security](13-jwt-token-security.md) |
| Concurrent-session policy | Whether a new login ends other active sessions, and whether the user finds out, is a decision teams often leave to default framework behavior instead of making deliberately | Decide explicitly per risk tier: multiple concurrent sessions with visibility, or ending prior sessions on new login for high-risk accounts | [Authentication and Session Management](12-authentication-session.md) |
| Device and session listing with remote sign-out | Teams that get logout-everywhere right still often give the user no visibility into what "everywhere" currently includes | Expose a list of active sessions or devices with last-seen metadata and a per-session revoke action, not just an all-or-nothing logout | [Session Management Deep Dive](72-session-management.md) |
| Server-initiated invalidation on credential events | A password reset, MFA change, or detected compromise means little if the attacker's existing session survives the very action meant to evict them | Password reset, MFA enrollment change, and recovery-address change all revoke every existing session, not just issue a new one | [Session Management Deep Dive](72-session-management.md) |

Also worth checking: cookie attribute hardening, `HttpOnly`/`Secure`/`Path` scoping (narrows cookie leak paths)<sup>[[8]](#ref8)</sup>, reauthentication before step-up actions (active session isn't a fresh one), cross-subdomain cookie scope (broad `Domain` widens theft surface), session ID entropy (guessable ID skips fixation entirely).

### Mobile and desktop applications

Neither surface has a cookie jar, so there's no ambient credential a request quietly carries along, which is exactly why CSRF as a category doesn't apply here the way it does on web. Continuity instead becomes a token storage problem: an OS-backed keystore holds a refresh token the app never has to persist in plaintext, and the operating system, not a cookie's flags, is the trust boundary<sup>[[9]](#ref9)</sup>. The design questions that matter most mirror web's, timeout sizing and revocation latency, but they attach to a token pair instead of a session record. See [Authentication](96-authentication.md) for how this same storage boundary shapes primary login on these surfaces; this section covers what keeps that login's proof alive afterward.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| OS-keystore-backed refresh token | The baseline continuity mechanism for any native app, hardware-backed storage instead of a plaintext file | Never, this is baseline hygiene regardless of the primary login mechanism | Preferred | [JWT and Token Security](13-jwt-token-security.md) |
| Session-cookie equivalent held by an embedded HTTP client | Rare: a native app wrapping a full HTTP client with its own cookie store instead of using the platform's token flow | Almost always, a modern OAuth-capable native stack exists and the keystore-backed refresh token fits better | Legacy | [Authentication and Session Management](12-authentication-session.md) |
| Sender-constrained token bound to a keystore key (DPoP) | Native apps wanting a stolen refresh token to stay unusable off the device it was issued to | The proving-key handshake adds complexity that isn't worth it for a low-risk app | Emerging | [JWT and Token Security](13-jwt-token-security.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Idle timeout vs. absolute token lifetime | The same two-control gap as web applies to the refresh token: idle-only never expires an install that periodically refreshes, absolute-only logs out an actively used app<sup>[[10]](#ref10)</sup> | Cap the refresh token's absolute lifetime independent of how often it's silently renewed, and re-require interactive login past that cap | [JWT and Token Security](13-jwt-token-security.md) |
| Logout and invalidation everywhere | Deleting the keystore entry on-device ends that one install's access, but a still-valid refresh token issued to another install of the same account keeps working | Logout revokes the refresh token server-side, not just the local keystore entry, and a separate control revokes every device's token on request | [Authentication and Session Management](12-authentication-session.md) |
| Refresh-token rotation with reuse detection | Without rotation, a stolen refresh token is indistinguishable from a legitimate one for its entire remaining lifetime | Rotate the refresh token on every use; a reused, already-rotated token revokes the whole token family and raises an alert | [JWT and Token Security](13-jwt-token-security.md) |
| Revocation latency for the token pair | A short access-token TTL limits how long a stolen access token works, but the refresh token behind it is the credential that actually needs to be revocable | Keep access-token TTLs short and treat refresh-token revocation, not access-token expiry, as the real revocation control | [JWT and Token Security](13-jwt-token-security.md) |
| Concurrent-session policy across devices | A new install on a second phone silently keeping the first phone's token alive is rarely a deliberate choice, usually just unexamined default behavior | Decide explicitly whether a new device login ends other devices' tokens for high-risk accounts, and surface that choice in account settings | [Authentication and Session Management](12-authentication-session.md) |
| Device and session listing with remote sign-out | A lost or stolen phone is the most common real-world trigger for needing remote revocation, and most apps have no user-facing way to do it | Expose a device list with last-seen data and a per-device revoke action, reachable without needing the lost device itself | [JWT and Token Security](13-jwt-token-security.md) |
| Server-initiated invalidation on credential events | A password reset or MFA change made from one device should end sessions on every other device, not just the one that made the change | Credential-change endpoints revoke every outstanding refresh token for the account server-side, not just the current session | [Authentication and Session Management](12-authentication-session.md) |

Also worth checking: keystore compromise on a rooted or jailbroken device (undermines the storage trust boundary), biometric re-gate on resume (shouldn't stay authenticated forever), deep-link and redirect interception (mobile's analog to CSRF).

### Service-to-service (machine) authentication

There's usually no session concept here at all, just a credential with its own TTL that gets re-issued per call or per short window, because no human is around to log in, sit idle, or log out<sup>[[11]](#ref11)</sup>. A team that builds a "service session," a longer-lived token meant to persist the way a user session does, is usually reproducing the web mental model in a context that doesn't need it, and that pattern is worth naming as a smell rather than a legitimate third option. See [Authentication](96-authentication.md) for how the credential itself gets minted and rotated across these contexts; this section is narrowly about whether anything session-shaped belongs on top of it.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Short-lived credential re-issued per call or window | Any workload with an automated issuer already in place, cloud IAM role assumption, SPIFFE/SPIRE, an OAuth token endpoint | No issuer exists yet and nothing automates re-issuance, where standing that up is the prerequisite, not a reason to skip it | Preferred | [Authentication](96-authentication.md) |
| Longer-lived service-level "session" token | Nothing today, a legacy shim bridging an old session-shaped internal API onto machine-to-machine calls mid-migration | Almost always: the credential outlives any legitimate reason to stay valid, and it's the pattern worth flagging in review rather than shipping deliberately | Legacy | [JWT and Token Security](13-jwt-token-security.md) |
| mTLS-bound credential (RFC 8705)<sup>[[13]](#ref13)</sup> | Service mesh or SPIFFE/SPIRE environments that already terminate mutual TLS between workloads | No mesh or mTLS infrastructure exists to bind the credential to | Niche-but-required | [JWT and Token Security](13-jwt-token-security.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Credential TTL sizing | This context's stand-in for idle versus absolute lifetime, too long and a leaked credential stays useful for a long window, too short and re-issuance load or clock-skew failures start to dominate | Size the TTL to the automated issuer's re-issuance cost, minutes to low hours, not to a human session's expectations | [Authentication](96-authentication.md) |
| Revocation latency | A short TTL bounds how long a leaked credential works, the same distinction that applies to a stateless JWT, but it's still not an on-demand kill switch | Pair short TTLs with an issuer-side ability to stop minting new credentials for a specific workload identity immediately | [JWT and Token Security](13-jwt-token-security.md) |
| Rotation and re-issuance automation | The service-to-service analog of logout-everywhere: killing a compromised credential across every workload holding it, not just the one call that leaked it | Automate rotation so it's the default behavior, not an on-call task triggered only after an incident | [Authentication](96-authentication.md) |
| Session-shaped state as a design smell | A team that gives a machine credential idle timeouts, a listable "device," or user-facing sign-out is usually solving a problem this context doesn't have | Treat any session-like feature request here as a signal to re-examine whether a human-facing concept crept into a machine-to-machine design | [Authentication](96-authentication.md) |
| Audit visibility into live credential issuance | The service-to-service analog of device listing: knowing which workload currently holds a live credential is what most fleets can't answer mid-incident | Log every issuance with the requesting workload identity, and keep that log queryable during incident response, not just retained for compliance | [Authentication](96-authentication.md) |

Also worth checking: credential audience scoping per downstream service (replayable against a sibling service), clock skew tolerance on TTL validation (too tight breaks legitimate calls), break-glass access when the issuer is unavailable (issuer outage shouldn't lock everyone out).

## Recommended defaults by context

| Context | Recommended default | Why |
| --- | --- | --- |
| Web applications | Server-side session or BFF-held token, both idle and absolute lifetime enforced, session ID regenerated on login | Keeps revocation immediate and keeps the continuity proof out of JavaScript's reach |
| Mobile and desktop applications | OS-keystore-backed refresh token, short access-token TTL, refresh token rotated and revocable server-side | Matches the platform's own trust boundary instead of reimplementing a cookie jar badly |
| Service-to-service | Short-lived credential re-issued per call or window through an automated issuer | Bounds leak blast radius by construction and needs no human-facing session concept at all |

## Migration path

The legacy default across all three contexts is usually a long-lived credential issued once with no clean revocation path, a JWT with a multi-day expiry on web, a refresh token with no server-side kill switch on mobile, or a static service credential with no TTL at all. Moving off it follows the same shape everywhere, add the revocable mechanism alongside the old one, verify it under real traffic, then retire the old path once usage data shows nobody's still depending on it.

Web apps carrying a long-lived client-side JWT move to a BFF or a server-side session as the fast path, because it's a deployment change behind the existing login UI rather than a rewrite of the login flow itself. What breaks: any code that read claims directly out of the JWT client-side now has to call an endpoint instead, which is often a bigger refactor than the session-storage change itself. Security pushes for the change once a token that can't be revoked shows up as an incident finding; frontend teams push back on the added network hop a BFF introduces on every authenticated request.

Mobile apps storing a refresh token in plaintext or app-private storage with no revocation move to the OS keystore first, a drop-in storage change with no login-flow impact, then add server-side refresh-token revocation and rotation once the keystore migration has landed. What breaks: an app version still holding a plaintext token doesn't recognize a server-side revoke until it's forced to re-authenticate, so a staged rollout needs a grace period rather than an instant cutover on the server side.

Service-to-service migration off a static, non-expiring credential is usually the slowest of the three, because an automated issuer has to exist before the static credential can be turned off, and nothing forces that work until a leaked-key incident makes the cost concrete. The staged path is a short-TTL credential issued through the platform's existing OAuth or workload-identity infrastructure first, with the static credential kept live and monitored until the new path has run through at least one full rotation cycle in production.

The signal that any of these three migrations is safe to complete is usage data on the legacy path rather than a calendar date. Track how often the old long-lived credential still gets presented once the new one exists, and retire it once that number is flat and near zero.

## Interviewer probes

**Why do you need both an idle timeout and an absolute session lifetime instead of just one?**

Mid: Idle-only lets scripted or background activity keep a session alive indefinitely; absolute-only logs out someone still actively working.

Principal: The two controls guard against opposite failure modes, so neither substitutes for the other. An attacker with a foothold who periodically pings a keepalive keeps an idle-only session alive forever, while a user mid-way through a long task gets logged out under an absolute-only design tuned too short<sup>[[5]](#ref5)</sup>. A banking app commonly pairs a short idle timeout, on the order of minutes, with a much longer absolute session length, because the two are sized against different threats and neither number tells you the other.

**When would you choose a BFF over a plain server-side session cookie?**

Mid: A BFF when there's a separate token-based API behind the frontend that needs a real bearer token, not just a session flag.

Principal: A plain session cookie is enough when the server rendering the page is also the server checking the session. Once an SPA calls a separately deployed API that expects a token in an `Authorization` header, issuing that token to browser JavaScript defeats the point of keeping it `HttpOnly`, so the BFF holds the token server-side and exposes only a session cookie to the browser, combining the revocation ease of server-side state with the token shape the downstream API actually needs, the pattern current OAuth security guidance recommends for browser-based apps<sup>[[4]](#ref4)</sup>.

**What's the difference between a short JWT TTL and actual revocation, and why does that distinction matter in an interview answer?**

Mid: A short TTL bounds how long a stolen token keeps working; it doesn't let you kill a specific token on demand.

Principal: If an account is compromised and access needs to end right now, a 15-minute access-token TTL still leaves up to 15 minutes of attacker access after detection, while a server-side session or a refresh-token revoke ends access immediately. Most systems calling themselves "stateless" actually keep a small amount of state for exactly this reason, a `jti` denylist held only until natural expiry, a per-user token-version or valid-after timestamp compared against `iat` on every request, resource-server introspection against the issuer<sup>[[7]](#ref7)</sup>, or key rotation as a blunt mass-revocation tool of last resort. Naming which of those mechanisms a design actually uses, rather than conflating TTL with revocation in the abstract, is usually what separates a mid-level answer from a Principal one here.

**Why doesn't CSRF show up as a concern for a mobile app's refresh-token design?**

Mid: There's no cookie jar and no ambient credential a forged cross-origin request could ride along with.

Principal: CSRF specifically exploits a browser automatically attaching cookies to a request regardless of which site triggered it. A mobile app presents its token explicitly, in a header the app's own code controls, so there's no equivalent cross-origin trigger surface for that particular attack class. That doesn't mean mobile continuity is CSRF-safe by default in every sense, it means the attack shape is different, deep-link and redirect interception replace it as the analogous concern, not CSRF itself.

**What's commonly missed when a team implements session fixation prevention?**

Mid: Regenerating the session ID on login but forgetting to regenerate it again on privilege change.

Principal: Frameworks that regenerate the ID on their built-in login hook still miss the case where a role-elevation or step-up flow bypasses that hook entirely, carrying the pre-elevation session ID straight into a higher-privilege context. If that ID was fixated before login, an attacker who planted it now inherits the elevated privileges too, not just the original authenticated session<sup>[[6]](#ref6)</sup>. Regeneration belongs on every privilege boundary, not only the one the framework happens to wire up by default.

**Should a new login from a second device end the user's other active sessions?**

Mid: It depends on risk tier, there's no universal right answer.

Principal: A consumer streaming app intentionally allows many concurrent sessions as a product feature, while a banking app or an admin console often ends other sessions on a new login as a deliberate security control. Either choice is defensible, but leaving it as unexamined default framework behavior isn't, and whichever way a team decides, the user needs to see it happen, because an unexpected session ending without explanation reads as a bug or a break-in rather than a policy working as designed.

**What's the biggest gap teams building service-to-service auth for the first time miss?**

Mid: Treating the machine credential like a user session, giving it a long lifetime and no rotation story.

Principal: A static API key or long-lived service token that leaks into a log or a repository has no expiry forcing a limit on the damage, and because no human notices a machine credential "logging them out," the leak can go unnoticed far longer than a stolen user session would. The fix isn't a session-shaped feature at all, it's automated short-TTL re-issuance through a workload identity or OAuth client-credentials flow, so a leaked credential ages out on its own instead of staying valid until someone happens to find it.

**A password reset just happened. What has to be true for that reset to actually contain a compromise, not just add a new credential?**

Mid: Every existing session tied to the account has to be invalidated, not just the password value changed.

Principal: A password reset that leaves an attacker's already-established session alive doesn't evict them, it just makes the account harder for the legitimate user to reason about going forward. The reset endpoint has to trigger the same server-initiated invalidation as a "log out everywhere" action, and the same is true for MFA enrollment changes and recovery-address changes, because each of those is a moment a legitimate user believes they've locked an intruder out. A design that treats credential rotation and session invalidation as two separate, independently-triggered actions is the gap that turns a short compromise into a persistent one.

## Sources

<a id="ref1"></a>[1] OWASP. Session Management Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

<a id="ref2"></a>[2] OWASP. Cross-Site Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

<a id="ref3"></a>[3] IETF. RFC 7519: JSON Web Token (JWT). May 2015. https://www.rfc-editor.org/rfc/rfc7519

<a id="ref4"></a>[4] IETF. RFC 9700: Best Current Practice for OAuth 2.0 Security. January 2025. https://www.rfc-editor.org/rfc/rfc9700

<a id="ref5"></a>[5] NIST. Special Publication 800-63-4 (Second Public Draft): Digital Identity Guidelines. August 2024. https://pages.nist.gov/800-63-4/

<a id="ref6"></a>[6] MITRE. Common Weakness Enumeration CWE-384: Session Fixation. https://cwe.mitre.org/data/definitions/384.html

<a id="ref7"></a>[7] IETF. RFC 7009: OAuth 2.0 Token Revocation. August 2013. https://www.rfc-editor.org/rfc/rfc7009

<a id="ref8"></a>[8] IETF. RFC 6265: HTTP State Management Mechanism. April 2011. https://www.rfc-editor.org/rfc/rfc6265

<a id="ref9"></a>[9] IETF. RFC 8252: OAuth 2.0 for Native Apps. October 2017. https://www.rfc-editor.org/rfc/rfc8252

<a id="ref10"></a>[10] MITRE. Common Weakness Enumeration CWE-613: Insufficient Session Expiration. https://cwe.mitre.org/data/definitions/613.html

<a id="ref11"></a>[11] SPIFFE Project (Cloud Native Computing Foundation). SPIFFE specification. https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md

<a id="ref12"></a>[12] IETF. RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP). September 2023. https://www.rfc-editor.org/rfc/rfc9449

<a id="ref13"></a>[13] IETF. RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens. February 2020. https://www.rfc-editor.org/rfc/rfc8705
