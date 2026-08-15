# Authentication & Identity

Authentication answers "who are you?" Identity protocols answer "how do I prove it to a third party?" The attacks in this section exploit weaknesses in how that proof is established, transmitted, stored, or verified.

## Topics in this section

| Doc | Focus |
|---|---|
| [Authentication & Session](../12-authentication-session.md) | Credential stuffing, spraying, MFA bypass, reset poisoning, fixation |
| [JWT Token Security](../13-jwt-token-security.md) | Algorithm confusion (RS256→HS256), none alg, key confusion |
| [OAuth 2.0 & OIDC](../14-oauth-oidc.md) | State parameter CSRF, redirect_uri abuse, implicit flow leakage |
| [OIDC Deep Dive](../77-oidc-deep.md) | ID token validation, nonce binding, hybrid flow |
| [SAML](../68-saml.md) | XML signature wrapping, XXE via assertion, replay |
| [SSO](../67-sso.md) | Cross-domain trust abuse, federation misconfig |
| [WebAuthn & Passkeys](../70-webauthn-passkeys.md) | Ceremony flow, origin binding, attestation |
| [MFA & Step-Up Auth](../73-mfa-step-up.md) | OTP bypass, SIM swap, push fatigue |
| [Password Authentication](../75-password-authentication.md) | KDF selection, timing attacks, reset flows |
| [Session Management](../72-session-management.md) | Fixation, hijacking, cookie attributes |
| [Token Exchange](../78-token-exchange.md) | RFC 8693, scope reduction, impersonation |
| [mTLS](../69-mtls.md) | Certificate binding, header spoofing in proxied flows |
| [SPIFFE & SPIRE](../81-spiffe-spire.md) | Workload identity, SVID issuance, attestation |
| [OpenID Federation](../82-openid-federation.md) | Trust chain, metadata endpoints, key rollover |

## The core invariant

Proof of identity must be bound to a specific session, audience, and time window. Any token or credential that travels without audience binding, expiry, or channel binding can be replayed by a different principal against a different resource.
