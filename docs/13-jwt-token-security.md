# JWT and Token Security

> A JWT (almost always a JWS, a signed token) is a self-contained, stateless credential: the server keeps no record of what it issued, so trust rests entirely on the recipient re-deriving and verifying the signature over the exact bytes it received. Every high-impact JWT bug is a failure of that verification step: the server either does not check the signature, checks it with an attacker-influenced algorithm or key, or checks the signature correctly but never validates the claims (exp, aud, iss). Because the token is the identity, forging one is instant privilege escalation or account takeover, and because it is stateless, revoking a leaked one is the hard problem.

**Interview frequency:** Core

*See also: [Authentication](96-authentication.md) for how this fits into the broader authentication architecture decision across web, mobile, desktop, and service-to-service contexts.*

*See also: [Secrets, Keys, and Data Protection](98-secrets-keys-data-protection.md) for the credential escalation ladder and HSM/TPM/TEE key-custody options behind JWT signing keys, and [Session Management](101-session-management.md) for how the stateless-revocation problem is solved when a JWT is used as the session bearer.*

## How it works

A JWS is three base64url segments joined by dots: `header.payload.signature`. Base64url (RFC 4648 section 5) uses `-` and `_` instead of `+` and `/` and strips `=` padding, so the token is URL-safe and header-safe. Only the signature is cryptographic; the header and payload are encoded, not encrypted, and anyone holding the token can read them.

```
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTkiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIn0.SYZBPIBg2CRjXAJ...
```

Header (JOSE header): metadata telling the verifier how to check the token.

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "9136ddb3-cb0a-4a19-a07e-eadf5a44c8b5"
}
```

Payload: the claims. Registered claims are defined by RFC 7519<sup>[[1]](#ref1)</sup>: `iss` (issuer), `sub` (subject), `aud` (audience), `exp` (expiry, NumericDate), `nbf` (not before), `iat` (issued at), `jti` (unique token id).

```json
{
  "iss": "https://auth.example.com",
  "sub": "carlos",
  "aud": "api.example.com",
  "exp": 1648037164,
  "iat": 1648033564,
  "role": "blog_author"
}
```

Signature: `Sign(base64url(header) + "." + base64url(payload), key)`. The algorithm family in `alg` decides what "sign" and "key" mean:

- HS256 / HS384 / HS512: HMAC with SHA-2. Symmetric. One shared secret both signs and verifies. `signature = HMAC-SHA256(header + "." + payload, secret)`.
- RS256 / RS384 / RS512: RSASSA-PKCS1-v1_5 with SHA-2. Asymmetric. Private key signs, public key verifies.
- PS256 family: RSASSA-PSS. ES256 / ES384 / ES512: ECDSA on P-256 / P-384 / P-521. EdDSA: Ed25519 / Ed448.

The distinction that drives most attacks: with HMAC the verification key is a secret; with RSA/ECDSA the verification key is public. Terminology per RFC 7515 (JWS)<sup>[[2]](#ref2)</sup>, RFC 7517 (JWK)<sup>[[3]](#ref3)</sup>, RFC 7518 (JWA)<sup>[[4]](#ref4)</sup>, RFC 7519 (JWT)<sup>[[1]](#ref1)</sup>. A JWT can also be a JWE (RFC 7516)<sup>[[5]](#ref5)</sup>, where the payload is encrypted; "JWT" in interviews almost always means JWS.

Wire delivery is usually an `Authorization: Bearer <jwt>` header or a cookie. A JWK Set (public keys for RS/ES verification) is commonly published at `/.well-known/jwks.json`:

```json
{ "keys": [ { "kty": "RSA", "kid": "9136ddb3", "e": "AQAB", "n": "o-yy1wpYmffgXBxhAUJz..." } ] }
```

```mermaid
sequenceDiagram
  participant C as Client
  participant S as Server, issuer and verifier
  participant Atk as Attacker

  C->>S: Authenticate (login)
  S->>S: Sign header.payload.signature with RS256 private key
  S-->>C: JWT (header.payload.signature)
  C->>S: API request, Authorization Bearer JWT
  S->>S: Read alg from header, verify signature with matching key
  S-->>C: 200 OK

  Note over Atk,S: RS256 to HS256 algorithm confusion
  Atk->>S: GET /.well-known/jwks.json
  S-->>Atk: RSA public key
  Atk->>Atk: Forge token, header alg=HS256, sign HMAC-SHA256(data, RSA public key bytes)
  Atk->>S: API request, Authorization Bearer forged JWT
  S->>S: Reads alg=HS256, verifies using RSA public key as HMAC secret, signature matches
  S-->>Atk: 200 OK, forged token accepted
```

## Quick reference

```
# alg:none bypass: strip the signature, keep the trailing dot
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.
# header: {"alg":"none"}  payload: {"sub":"admin","exp":9999999999}  signature: (empty)
# If the verifier accepts this, every claim is forgeable with no key at all.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Verifier accepts only a pinned algorithm, never the token's own `alg` header | Verifier config (explicit `algorithms` allowlist) | Generic `verify(token, key)` dispatches on the attacker-controlled `alg`, enabling `alg:none` and RS256-to-HS256 confusion | <sup>[[16]](#ref16)</sup> |
| One key is usable under exactly one algorithm family | Key management / verifier config | An RSA public key gets accepted as an HMAC secret because nothing separates asymmetric verification keys from symmetric ones | <sup>[[16]](#ref16)</sup> |
| Every inbound token goes through the verifying call, never the decode-only call | Application auth middleware | A non-verifying `decode()` call is used for authorization instead of `verify()` | <sup>[[16]](#ref16)</sup> |
| `exp`, `iss`, and `aud` are all validated after the signature check | Application claim-validation logic | Missing `aud` lets a token minted for one service authenticate to another; missing `exp` lets stolen tokens live forever | <sup>[[16]](#ref16)</sup> |
| Access tokens carry `typ: at+jwt`; ID tokens are never accepted as API credentials | Resource server token-type check | The resource server skips `typ`, accepts an OIDC ID token as a bearer access token | <sup>[[14]](#ref14)</sup> |
| `kid`, `jwk`, `jku`, `x5u` header values are untrusted input, never trusted key material | Key resolution logic | `kid` fed unsanitized into a file/DB lookup; `jwk`/`jku` trusted as the verification key itself | <sup>[[16]](#ref16)</sup> |
| The token alone does not authenticate a request; possession of a bound key does | Resource server proof-of-possession check | Bearer semantics: any holder of the token bytes is treated as authenticated, so a leaked token is immediately usable | <sup>[[18]](#ref18)</sup> |

## Attack techniques

### 1. Unverified signature (decode instead of verify)

Libraries expose both a verifying call and a non-verifying decode. In Node `jsonwebtoken`, `jwt.verify(token, key)` checks the signature and `jwt.decode(token)` does not. Developers who route inbound tokens through `decode()` accept any signature. Confirmation: take a valid token, flip a claim (`"role":"admin"`), leave the signature untouched or garbage, and see if access is granted. Why it works: the server never re-derives the MAC/signature, so the payload is fully attacker-controlled.

### 2. `alg: none` (unsecured JWS)

RFC 7519 defines an "unsecured" JWT where `alg` is `none` and the signature segment is empty<sup>[[1]](#ref1)</sup>. Set the header to `{"alg":"none"}`, tamper the payload, and send `header.payload.` (trailing dot required, signature empty).

```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.
```

Servers commonly reject the literal string `none`, so bypass the string filter with case and encoding tricks: `None`, `NONE`, `nOnE`. Tim McLean's 2015 disclosure documented libraries that treated `none` as a verified signature<sup>[[7]](#ref7)</sup>; CVE-2015-9235 covers this in Node `jsonwebtoken` before 4.2.2. Why it works: the `alg` value is attacker-controlled input read before any trust is established.

### 3. Weak HMAC secret (offline brute force)

If HS256 is used with a guessable or default secret (a copy-pasted `secret`, `changeme`, a framework placeholder), capture one valid token and crack it offline. No requests hit the server, so it is fast and silent.

```
hashcat -a 0 -m 16500 <jwt> jwt.secrets.list
# 16500 = JWT (JWS HMAC). Output: <jwt>:<recovered-secret>
```

`jwt_tool`<sup>[[8]](#ref8)</sup> and John the Ripper do the same, and hashcat mode 16500 targets JWT HMAC directly<sup>[[9]](#ref9)</sup>. Wallarm publishes a well-known-secrets wordlist. Once the secret is known, forge any header/payload and re-sign with valid HS256. Why it works: HMAC security collapses to the entropy of the secret, and cracking is entirely local.

### 4. RS256 to HS256 algorithm confusion (key confusion)

The server intends RS256 and calls an algorithm-agnostic verify with its RSA public key<sup>[[10]](#ref10)</sup>. If the attacker submits a token whose header says `alg: HS256`, the library treats the RSA public key bytes as an HMAC secret. Since the public key is public, the attacker signs the forged token with `HMAC-SHA256(data, publicKeyPEM)` and verification passes.

Steps:

- Obtain the public key: fetch `/.well-known/jwks.json` or `/jwks.json`, or derive it from two captured tokens with `silentsignal/rsa_sign2n`<sup>[[11]](#ref11)</sup> (`docker run --rm -it portswigger/sig2n <token1> <token2>`), which computes candidate `n` values and emits a forged token per candidate; only the server-accepted one is correct.
- Convert JWK to the exact PEM the server holds (X.509 SubjectPublicKeyInfo PEM is typical). Byte-for-byte identity matters: same PEM format, same trailing newline. In Burp JWT Editor<sup>[[12]](#ref12)</sup>, import the JWK as an RSA key, export PEM, base64-encode it, then paste that as the `k` value of a new symmetric (HMAC) key.
- Set `alg` to `HS256`, tamper the payload, sign with the symmetric key whose `k` is the base64 of the PEM.

```json
Header: {"alg":"HS256"}
Payload: {"sub":"admin","role":"admin","exp":9999999999}
Signature: HMACSHA256(b64url(header)+"."+b64url(payload), <server RSA public key PEM bytes>)
```

Why it works: one generic `verify(token, key)` dispatches on the untrusted `alg` header, so the same key material is interpreted under two incompatible algorithms.

### 5. Header-parameter injection: embedded `jwk`

JWS allows an inline public key in the `jwk` header. A misconfigured server verifies using whatever key is embedded rather than a pinned allowlist. Generate your own RSA keypair, embed the public key in `jwk`, sign with your private key.

```json
{
  "alg": "RS256",
  "kid": "attacker-key",
  "jwk": { "kty":"RSA", "e":"AQAB", "kid":"attacker-key", "n":"<attacker-modulus>" }
}
```

Burp JWT Editor's "Embedded JWK" attack automates this and syncs `kid`<sup>[[12]](#ref12)</sup>. Real case: CVE-2018-0114 in Cisco's `node-jose` accepted an embedded JWK and verified against it. Why it works: the token carries its own trust anchor.

### 6. Header-parameter injection: `jku` / `x5u` (attacker JWK Set / cert URL)

`jku` points the server at a JWK Set URL; `x5u` at an X.509 cert URL. If the host allowlist is missing or bypassable, point it at attacker-controlled infrastructure hosting your public key<sup>[[16]](#ref16)</sup>.

```json
{ "alg":"RS256", "kid":"attacker-key", "jku":"https://trusted.example.com.attacker.net/jwks.json" }
```

Bypass weak host filtering with the same URL-parsing and SSRF tricks used elsewhere (`@`, embedded credentials, open redirect on the trusted host, DNS games). Why it works: the server fetches key material from an untrusted, attacker-influenced location.

### 7. Header-parameter injection: `kid` path traversal, SQLi, and static-file signing

`kid` selects a key by an arbitrary developer-defined string (file path, DB row)<sup>[[16]](#ref16)</sup>. If it feeds a filesystem lookup, traverse to a file whose contents you control or can predict, then sign HS256 with that file's bytes as the secret.

```json
{ "alg":"HS256", "kid":"../../../../dev/null" }
```

`/dev/null` reads as empty, so signing HS256 with an empty-string secret yields a valid signature the server reproduces. If `kid` feeds a SQL query, it is a SQL injection sink: `kid` values like `nonexistent' UNION SELECT 'attacker-known-key'-- ` can make the query return an attacker-known key. Why it works: `kid` is untrusted input used to select trusted key material.

### 8. Other header abuse

`cty` (content type) set to `text/xml` or `application/x-java-serialized-object` can open XXE or deserialization if signature verification is already bypassed. `x5c` (embedded cert chain) is a `jwk`-style self-signed injection plus X.509 parser attack surface; PortSwigger cites CVE-2017-2800 and CVE-2018-2633 for X.509 parsing bugs<sup>[[6]](#ref6)</sup>.

### 9. Claim-validation gaps and cross-service confusion

Even with a perfect signature, failing to validate claims is exploitable:

- No `exp` check: stolen or old tokens live forever.
- No `aud` check: a token minted for service A is replayed against service B that shares the key or issuer (RFC 8725 calls this cross-JWT confusion and substitution<sup>[[16]](#ref16)</sup>). An access token accepted where an ID token was expected is the same class.
- No `iss` check: tokens from an unexpected issuer are trusted.
- `alg`/`typ` not pinned: opens confusion and the `none` family.

### 10. ECDSA "Psychic Signatures" (CVE-2022-21449)

Java 15 to 18 (Neil Madden, ForgeRock, 2022) accepted an ECDSA signature with `r = s = 0` as valid for ES256/ES384/ES512<sup>[[13]](#ref13)</sup>. A JWT with a two-zero signature verified against any P-256 public key, forging ES-signed tokens with no key knowledge. It is the modern analogue of `alg: none` for asymmetric tokens and a favourite interview curveball.

### 11. ID-token-as-access-token substitution (OIDC to OAuth crossover)

OpenID Connect ID tokens and OAuth 2.0 access tokens are both JWTs signed by the same issuer, often with the same key, and they differ only in claims. An ID token's `aud` is the OIDC client ID and its purpose is to authenticate the end user to that client; an access token's `aud` is the resource API and its purpose is to authorize API calls. If a resource server verifies signature, `iss`, and `exp` but skips `aud` and `typ`, an attacker who obtains an ID token for user X (routine in an OIDC login flow) can present it as `Authorization: Bearer <id_token>` and authenticate as X against the API.

The mechanism is claim-shape confusion: the ID token has `sub` and no `scope`, so a resource server that trusts `sub` as the caller identity and treats missing `scope` as "no restrictions" grants full user access. The same trick works between microservices that share an issuer whenever `aud` is unchecked, and between a legacy `typ: JWT` deployment and a newer `typ: at+jwt` deployment when the newer service accepts either type.

RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens) fixes this by requiring access tokens carry `typ: at+jwt` in the JOSE header, so an ID token (which is `typ: JWT`) cannot be presented at an access-token endpoint by a strict verifier<sup>[[14]](#ref14)</sup>. RFC 8725 section 3.11 generalizes this as "Use Explicit Typing": pin `typ` per endpoint class and refuse anything else<sup>[[16]](#ref16)</sup>. In practice, resource servers that only check signature and `iss` are the majority of real-world OAuth breaches in this class. See [14-oauth-oidc.md](14-oauth-oidc.md) for where the ID token sits in the full Authorization Code flow and the client-side defenses around it.

### 12. JWE-specific attacks (invalid curve, PBES2 iteration DoS, compression oracle)

JWE (RFC 7516) encrypts the payload rather than just signing it, and its algorithm surface introduces failure modes JWS does not have<sup>[[5]](#ref5)</sup>.

Invalid curve attack (Antonio Sanso, 2017, affecting `node-jose`, `jose4j`, and multiple JOSE libraries)<sup>[[15]](#ref15)</sup>: the ECDH-ES key agreement lets the sender supply an ephemeral public key. Libraries that failed to check the point lies on the correct curve (P-256, P-384, P-521) accepted attacker-crafted points on a related low-order curve. A small-subgroup attack then leaks bits of the recipient's static ECDH private key per crafted JWE, and a few dozen probes recover the full key. Defense: validate that received points are on-curve before scalar multiplication, and prefer X25519 (Curve25519) whose Montgomery-ladder implementation is naturally resistant.

PBES2 iteration-count DoS: JWE's password-based algorithms (`PBES2-HS256+A128KW` family) carry the PBKDF2 iteration count `p2c` in the JOSE header. A malicious sender sets `p2c: 100000000` and forces the recipient into multi-second key derivation before any authentication check, converting one unauthenticated HTTP request into significant CPU. Defense: cap `p2c` at a small ceiling (RFC 8725 section 3.8-adjacent guidance recommends limits proportional to expected sender capability<sup>[[16]](#ref16)</sup>) or disallow PBES2 entirely for machine-to-machine paths where passwords are not the input.

Compression oracle via `zip: DEF`: JWE permits DEFLATE compression of the plaintext before encryption. When attacker-controlled data and secret data are compressed together, ciphertext length leaks whether they share substrings, the same primitive that powers CRIME and BREACH against TLS. An attacker probing a header they partially control (a cookie, a claim) can extract the secret one byte at a time from length side channels. RFC 8725 section 3.6 explicitly warns against JWE compression<sup>[[16]](#ref16)</sup>; the safe answer is to disable `zip` on the recipient.

## Defense

Ordered by how much attack surface each removes within its group.

### Real fix

1. Pin the algorithm; never trust `alg` from the token (RFC 8725 section 3.1, "Perform Algorithm Verification"<sup>[[16]](#ref16)</sup>). The verifier must be told which algorithm(s) are acceptable and reject everything else, rather than reading `alg` and dispatching on it. In Node `jsonwebtoken`: `jwt.verify(token, key, { algorithms: ['RS256'] })`. In Java `auth0/java-jwt`: build the verifier with a fixed algorithm, `JWT.require(Algorithm.HMAC256(key)).build()`, so a `none` or swapped `alg` throws. This single control kills `alg: none`, unexpected-algorithm acceptance, and RS256-to-HS256 confusion.

2. Separate keys by purpose and never let one key material be usable under two algorithm families (RFC 8725 section 2.4 rationale<sup>[[16]](#ref16)</sup>). Asymmetric verification keys must not also be accepted as HMAC secrets. A hard allowlist of one algorithm per key eliminates confusion even if `alg` pinning is somehow bypassed.

3. Verify, do not decode. Use the library's verifying entry point on every inbound token, and treat verification failure as a hard 401. Never branch on `decode()` output for authz.

4. Strong, unique HMAC secrets. Per OWASP<sup>[[17]](#ref17)</sup>, an HS256 secret should be machine-generated from a CSPRNG and at least 64 characters (256 bits of entropy or more), never a default or human-typed string (RFC 8725 section 3.5, "Ensure Cryptographic Keys Have Sufficient Entropy"<sup>[[16]](#ref16)</sup>). Prefer asymmetric (RS/ES/EdDSA) so verifiers hold only public keys and a compromised verifier cannot mint tokens.

5. Lock down header parameters. Do not honour `jwk` for trust. Maintain a static allowlist of `kid` values, and treat `kid` as untrusted input: parameterize any DB lookup and reject path-traversal characters to stop SQLi and file traversal. For `jku`/`x5u`, enforce a strict allowlist of exact trusted hosts (not substring matches) and disable the feature if unused (RFC 8725 section 3.10, "Do Not Trust Received Claims", and section 2.9 on indirect/SSRF attacks<sup>[[16]](#ref16)</sup>).

6. Validate every claim, not just the signature. Enforce `exp` (with small clock skew), `nbf`, `iss` against an expected issuer, and `aud` against this service's identifier (RFC 8725 sections 3.8 and 3.9<sup>[[16]](#ref16)</sup>). Use `typ`/explicit typing (RFC 8725 section 3.11<sup>[[16]](#ref16)</sup>) and mutually exclusive validation rules per token kind (section 3.12) to stop cross-JWT and ID-token/access-token substitution. For OAuth access tokens, require `typ: at+jwt` per RFC 9068<sup>[[14]](#ref14)</sup> and refuse tokens with `typ: JWT` at API endpoints; that one check blocks the ID-token-as-access-token class outright.

7. Do not compress-then-encrypt (JWE), do not put secrets in the payload (it is only encoded, not confidential), and avoid tokens in URLs (they leak via logs and Referer).

### Defense in depth

1. Storage and transport. A JWT in `localStorage` is readable by any XSS and is exfiltrated instantly; a token in an `HttpOnly; Secure; SameSite` cookie is not script-readable but then needs CSRF defenses (CSRF token or SameSite). OWASP's token-sidejacking mitigation<sup>[[17]](#ref17)</sup> binds the token to a browser context: issue a high-entropy random value as a `__Secure-Fgp` hardened cookie (`HttpOnly; Secure; SameSite=Strict`) and store only its SHA-256 in the JWT (`userFingerprint` claim); at verification, hash the cookie and require it to equal the claim. A stolen token alone is then useless without the paired cookie, and storing the hash (not the raw value) means XSS reading the token cannot reconstruct the cookie. Keep token lifetimes short (OWASP suggests 15 to 30 minute idle, an absolute cap such as 8 hours) and add a strict Content-Security-Policy.

2. Revocation and refresh-token rotation. Access tokens should be short-lived; a long-lived refresh token (opaque, server-stored) mints new access tokens. Rotate the refresh token on every use and keep a per-family lineage: if a previously-used (rotated-out) refresh token is presented again, that signals theft, so revoke the entire family (reuse detection). For access-token revocation before expiry, keep a server-side denylist keyed on a SHA-256 digest of the token (or its `jti`) with a TTL equal to the token's remaining life; check it on each request. This reintroduces state and is the explicit tradeoff of stateless JWTs.

3. Sender-constrained tokens (proof-of-possession) to narrow blast radius after theft. Fingerprint cookies raise the bar for pure XSS exfiltration but do nothing against a compromised TLS-terminating proxy or a leaked log line. The invariant is that the token alone must not authenticate a request: the caller must also prove possession of a key bound to the token.

   RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens) is the mTLS variant<sup>[[18]](#ref18)</sup>. The client presents a TLS client certificate on every API call, and the access token carries a `cnf.x5t#S256` claim containing the SHA-256 thumbprint of that certificate. The resource server confirms the presenting cert's thumbprint matches the claim, so a stolen bearer token replayed from a different TLS session fails. Strong in server-to-server and mobile flows; weaker where a fronting proxy terminates TLS and forwards without the client cert, which quietly re-introduces bearer semantics.

   RFC 9449 (DPoP, "Demonstrating Proof of Possession") is the browser-friendly variant<sup>[[19]](#ref19)</sup>. The client generates an ephemeral keypair (WebCrypto, non-extractable) and, on every API request, sends a `DPoP` header carrying a proof JWT signed with the private key. The proof includes `htu` (HTTP URI), `htm` (method), `iat`, `jti`, and `ath` (SHA-256 of the access token), and the access token carries `cnf.jkt` = SHA-256 of the client's public JWK. The resource server verifies the proof signature, checks `htu`/`htm` match the actual request, replay-caches `jti`, and confirms `jkt` matches the presenting key. A leaked access token cannot be replayed without the private key, and each proof is tied to one request. Common wrong implementation: storing the DPoP private key in an extractable CryptoKey or in JavaScript memory reachable from XSS, which defeats the whole scheme because the same script that steals the token also steals the key. Store the key as `extractable: false` in WebCrypto or in a hardware-backed keystore.

4. JWKS key rotation without breaking the world, to bound the window a compromised or stale key stays trusted. Publish the JWKS with multiple active keys, each with a distinct `kid`, during rotation. The issuer starts signing new tokens with the new `kid` immediately; verifiers continue to accept tokens signed under the old `kid` until the longest outstanding token's `exp` has passed, so the rotation window must be at least the maximum access-token lifetime. Verifiers cache the JWKS with a bounded TTL and refresh on `kid` miss, but must rate-limit that refresh, because an unauthenticated `kid` in an inbound token is attacker-controlled cache-buster input and a trivial DoS or SSRF amplifier against the JWKS URL. Libraries such as `jwks-rsa` expose `jwksRequestsPerMinute` for exactly this reason<sup>[[20]](#ref20)</sup>.

   The common wrong implementations: removing the old key too early invalidates in-flight tokens and users get logged out mid-request; refreshing on every miss lets an attacker force outbound requests to the JWKS URL with arbitrary `kid` values; caching indefinitely means a compromised signing key stays trusted long after rotation; and if the JWKS URL is HTTPS but the CA validation is loose or the URL is HTTP behind a "trusted" proxy, an on-path attacker serves a fake JWKS and forges tokens accepted by every verifier that pulled the poisoned cache. Emergency revocation of a compromised signing key requires pushing an updated JWKS, invalidating verifier caches (out-of-band signal or short cache TTL), and relying on short access-token TTLs so the window of forged-token acceptance is bounded.

## Interviewer probes

**How do you stop a stolen access token from being replayed by an attacker who has captured it?**

Mid: Keep access-token lifetimes short and always use HTTPS, so a captured token has a narrow window before it expires and is harder to intercept in transit in the first place.

Principal: The layered answer starts with short TTLs (minutes, not days) plus refresh-token rotation with reuse detection so the theft window is bounded and detectable. Fingerprint cookies (OWASP token-sidejacking mitigation) block naive XSS exfiltration by requiring the paired `HttpOnly` cookie whose SHA-256 is claimed in the JWT. The structural fix is sender-constrained tokens: RFC 8705 mTLS binds the token to the client's TLS certificate via `cnf.x5t#S256`, and RFC 9449 DPoP binds it to an ephemeral client keypair via `cnf.jkt`, with a per-request signed proof JWT carrying `htu`, `htm`, `jti`, and `ath`. Pick mTLS for server-to-server and mobile where cert distribution and pinning are tractable; pick DPoP for browsers and SPAs, but only if the private key lives in non-extractable WebCrypto storage (`extractable: false`) or a hardware keystore, because the XSS that steals the token also steals an exfiltratable key. The wrong answer is IP or user-agent binding: both are trivially spoofed and break real users behind CGNAT or browser updates.

**How do you rotate JWKS signing keys safely?**

Mid: Add the new key to the JWKS under a new `kid` and start signing new tokens with it, then leave the old key published until every token signed with it has expired before removing it.

Principal: Publish both old and new keys in JWKS with distinct `kid`s. Sign new tokens with the new `kid` immediately, keep the old key in JWKS for at least the maximum outstanding access-token lifetime so in-flight tokens still verify, then remove it. Verifiers cache JWKS with a bounded TTL and refresh on `kid` miss, but rate-limit the refresh, otherwise an attacker sending random `kid` values weaponizes verifiers into a DoS or SSRF amplifier against the JWKS URL. The subtle failures are indefinite caching (a compromised key stays trusted after rotation), loose TLS validation on the JWKS fetch (an on-path fake JWKS forges every token), and removing the old key too early (mass logout mid-session). Emergency compromise response is push a new JWKS, force cache invalidation via a short TTL or an out-of-band signal, and rely on short access-token lifetimes so the window of accepted forgeries is bounded rather than open-ended.

**What is the difference between an OIDC ID token and an OAuth access token, and why does it matter for a resource server?**

Mid: An ID token tells the client app who the user is, while an access token is what the client presents to call an API on the user's behalf, so a resource server should only accept access tokens, not ID tokens.

Principal: An ID token authenticates the end user to the OIDC client; its `aud` is the client ID, it carries identity claims like `sub` and `email`, and it is not meant to authorize API calls. An access token authorizes API calls; its `aud` is the resource server, it carries `scope`, and per RFC 9068 it should carry `typ: at+jwt` in the JOSE header. Both are typically signed by the same issuer with the same key, so signature verification alone does not distinguish them. A resource server that checks signature, `iss`, and `exp` but skips `aud` and `typ` accepts an ID token as an access token, and an attacker who logs in via OIDC as user X can hit the API as X. The two-line fix is pin `aud` to this API's identifier and pin `typ` to `at+jwt`; RFC 8725 section 3.11 generalizes this as explicit typing.

**JWTs are supposed to be stateless. Why do most production systems end up building a way to revoke them anyway?**

Mid: Because sometimes you need to kill a token before it naturally expires, like on logout or a suspected compromise, so teams add a denylist or short-lived tokens with refresh rotation to handle that case.

Principal: Statelessness means any backend can verify a token locally without a session-store lookup, but that is exactly what makes revocation hard: there is no server-side record to delete. Real revocation always means giving something back: a denylist keyed on a SHA-256 digest or `jti` with a TTL, short access-token lifetimes paired with refresh-token rotation and reuse detection, or opaque reference tokens that require a lookup. Every one of those reintroduces the state lookup you adopted JWTs to avoid. The senior answer names this trade explicitly and knows when to skip JWTs altogether: a single-datacenter app with an existing session store often gains nothing from JWTs and just inherits the revocation problem for free.

**RS256-to-HS256 confusion mixes a symmetric and an asymmetric algorithm under one key. Isn't that a fundamental cryptographic flaw?**

Mid: No, it's an implementation bug rather than a crypto flaw: some verification code trusts the `alg` header from the token itself instead of pinning the expected algorithm, so an RSA public key can end up being misused as an HMAC secret.

Principal: No, HMAC and RSA are each correctly implemented; the bug lives at the API layer, not the primitive. A generic `verify(token, key)` call dispatches on the attacker-controlled `alg` header instead of the caller pinning which algorithm is acceptable, so the same key material gets reinterpreted under an incompatible algorithm family. That is also why "the RSA key is public anyway" does not save you: JWKS endpoints, TLS certificates, and Git-committed keys routinely leak it, and even when it is not published, tools like `rsa_sign2n`/`sig2n` recover the modulus from two captured tokens. The fix is API design, pin one algorithm per key and reject anything else, which is why RFC 8725 leads with algorithm verification rather than a crypto-level patch.

**How does the 2022 Java ECDSA 'Psychic Signatures' bug (CVE-2022-21449) relate to `alg: none`, which is a much older attack?**

Mid: Both let a token pass verification without a real signature behind it: `alg: none` does it by telling the verifier there's no signature to check, while CVE-2022-21449 was a buggy ECDSA implementation that wrongly accepted a bogus signature as valid.

Principal: They are the same failure wearing different costumes: a token accepted with no real proof of possession. `alg: none` is the explicit version, an attacker sets the header to an unsecured JWS and an unpatched library treats the empty signature as valid. CVE-2022-21449 is the implicit version: affected Java versions accepted an ECDSA signature with `r = s = 0` as valid against any P-256 public key, so a forged signature with no key knowledge at all passed verification. Recognizing that both are instances of "the verifier never confirmed a real signature was produced," rather than treating them as unrelated bugs from different eras, is the signal of someone who understands JWT verification structurally.

**A developer wants to put a customer's SSN in a JWT claim because 'it's signed, so it's secure.' What's wrong with that reasoning?**

Mid: Signing only protects against tampering, not readability, the payload is just base64-encoded, so anyone with the token can decode it and read the SSN in plain text.

Principal: Signing proves integrity, not confidentiality. The header and payload are base64url-encoded, not encrypted, so anyone holding the token, in browser storage, a proxy log, or a leaked request, can decode and read every claim without touching the signature. Only a JWS's signature is cryptographic; if the claims themselves need to be hidden you need a JWE, which actually encrypts the payload, and even then the signature or AEAD tag is what stops tampering, not the encoding. Conflating "signed" with "confidential" is a common interview tell, and the practical fix is simple: never put sensitive data in a JWS payload.

## Sources

<a id="ref1"></a>[1] RFC 7519, "JSON Web Token (JWT)". IETF. May 2015. https://datatracker.ietf.org/doc/html/rfc7519

<a id="ref2"></a>[2] RFC 7515, "JSON Web Signature (JWS)". IETF. May 2015. https://datatracker.ietf.org/doc/html/rfc7515

<a id="ref3"></a>[3] RFC 7517, "JSON Web Key (JWK)". IETF. May 2015. https://datatracker.ietf.org/doc/html/rfc7517

<a id="ref4"></a>[4] RFC 7518, "JSON Web Algorithms (JWA)". IETF. May 2015. https://datatracker.ietf.org/doc/html/rfc7518

<a id="ref5"></a>[5] RFC 7516, "JSON Web Encryption (JWE)". IETF. May 2015. https://datatracker.ietf.org/doc/html/rfc7516

<a id="ref6"></a>[6] PortSwigger Web Security Academy, "JWT attacks". Retrieved 2026. https://portswigger.net/web-security/jwt

<a id="ref7"></a>[7] Tim McLean, "Critical vulnerabilities in JSON Web Token libraries". auth0 blog. 2015. https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

<a id="ref8"></a>[8] ticarpi, `jwt_tool`. GitHub. Retrieved 2026. https://github.com/ticarpi/jwt_tool

<a id="ref9"></a>[9] hashcat, mode 16500 (JWT). Retrieved 2026. https://hashcat.net/hashcat/

<a id="ref10"></a>[10] PortSwigger Web Security Academy, "Algorithm confusion attacks". Retrieved 2026. https://portswigger.net/web-security/jwt/algorithm-confusion

<a id="ref11"></a>[11] silentsignal/rsa_sign2n and portswigger/sig2n, public-key recovery for algorithm confusion. GitHub. Retrieved 2026. https://github.com/silentsignal/rsa_sign2n

<a id="ref12"></a>[12] PortSwigger, "Working with JWTs in Burp Suite". Retrieved 2026. https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management/jwts

<a id="ref13"></a>[13] Neil Madden, "Psychic Signatures in Java" (CVE-2022-21449). 2022-04-19. https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/

<a id="ref14"></a>[14] RFC 9068, "JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens". IETF. October 2021. https://datatracker.ietf.org/doc/html/rfc9068

<a id="ref15"></a>[15] Antonio Sanso, "Critical vulnerability in JSON Web Encryption (JWE) - RFC 7516" (invalid curve attack). 2017-03. https://blog.intothesymmetry.com/2017/03/critical-vulnerability-in-json-web.html

<a id="ref16"></a>[16] RFC 8725 (BCP 225), "JSON Web Token Best Current Practices". IETF. February 2020. https://datatracker.ietf.org/doc/html/rfc8725

<a id="ref17"></a>[17] OWASP, "JSON Web Token for Java Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

<a id="ref18"></a>[18] RFC 8705, "OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens". IETF. February 2020. https://datatracker.ietf.org/doc/html/rfc8705

<a id="ref19"></a>[19] RFC 9449, "OAuth 2.0 Demonstrating Proof of Possession (DPoP)". IETF. September 2023. https://datatracker.ietf.org/doc/html/rfc9449

<a id="ref20"></a>[20] auth0, `node-jwks-rsa` (JWKS caching and rate limiting). GitHub. Retrieved 2026. https://github.com/auth0/node-jwks-rsa
