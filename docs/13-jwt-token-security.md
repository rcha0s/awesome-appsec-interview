# JWT and Token Security

> A JWT (almost always a JWS, a signed token) is a self-contained, stateless credential: the server keeps no record of what it issued, so trust rests entirely on the recipient re-deriving and verifying the signature over the exact bytes it received. Every high-impact JWT bug is a failure of that verification step: the server either does not check the signature, checks it with an attacker-influenced algorithm or key, or checks the signature correctly but never validates the claims (exp, aud, iss). Because the token is the identity, forging one is instant privilege escalation or account takeover, and because it is stateless, revoking a leaked one is the hard problem.

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

Payload: the claims. Registered claims are defined by RFC 7519: `iss` (issuer), `sub` (subject), `aud` (audience), `exp` (expiry, NumericDate), `nbf` (not before), `iat` (issued at), `jti` (unique token id).

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

The distinction that drives most attacks: with HMAC the verification key is a secret; with RSA/ECDSA the verification key is public. Terminology per RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT). A JWT can also be a JWE (RFC 7516), where the payload is encrypted; "JWT" in interviews almost always means JWS.

Wire delivery is usually an `Authorization: Bearer <jwt>` header or a cookie. A JWK Set (public keys for RS/ES verification) is commonly published at `/.well-known/jwks.json`:

```json
{ "keys": [ { "kty": "RSA", "kid": "9136ddb3", "e": "AQAB", "n": "o-yy1wpYmffgXBxhAUJz..." } ] }
```

## Attack techniques

1. Unverified signature (decode instead of verify).

Libraries expose both a verifying call and a non-verifying decode. In Node `jsonwebtoken`, `jwt.verify(token, key)` checks the signature and `jwt.decode(token)` does not. Developers who route inbound tokens through `decode()` accept any signature. Confirmation: take a valid token, flip a claim (`"role":"admin"`), leave the signature untouched or garbage, and see if access is granted. Why it works: the server never re-derives the MAC/signature, so the payload is fully attacker-controlled.

2. `alg: none` (unsecured JWS).

RFC 7519 defines an "unsecured" JWT where `alg` is `none` and the signature segment is empty. Set the header to `{"alg":"none"}`, tamper the payload, and send `header.payload.` (trailing dot required, signature empty).

```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.
```

Servers commonly reject the literal string `none`, so bypass the string filter with case and encoding tricks: `None`, `NONE`, `nOnE`. Tim McLean's 2015 disclosure (auth0 blog, "Critical vulnerabilities in JSON Web Token libraries") documented libraries that treated `none` as a verified signature; CVE-2015-9235 covers this in Node `jsonwebtoken` before 4.2.2. Why it works: the `alg` value is attacker-controlled input read before any trust is established.

3. Weak HMAC secret (offline brute force).

If HS256 is used with a guessable or default secret (a copy-pasted `secret`, `changeme`, a framework placeholder), capture one valid token and crack it offline. No requests hit the server, so it is fast and silent.

```
hashcat -a 0 -m 16500 <jwt> jwt.secrets.list
# 16500 = JWT (JWS HMAC). Output: <jwt>:<recovered-secret>
```

`jwt_tool` (ticarpi) and John the Ripper do the same. Wallarm publishes a well-known-secrets wordlist. Once the secret is known, forge any header/payload and re-sign with valid HS256. Why it works: HMAC security collapses to the entropy of the secret, and cracking is entirely local.

4. RS256 to HS256 algorithm confusion (key confusion).

The server intends RS256 and calls an algorithm-agnostic verify with its RSA public key. If the attacker submits a token whose header says `alg: HS256`, the library treats the RSA public key bytes as an HMAC secret. Since the public key is public, the attacker signs the forged token with `HMAC-SHA256(data, publicKeyPEM)` and verification passes.

Steps:

- Obtain the public key: fetch `/.well-known/jwks.json` or `/jwks.json`, or derive it from two captured tokens with `silentsignal/rsa_sign2n` (`docker run --rm -it portswigger/sig2n <token1> <token2>`), which computes candidate `n` values and emits a forged token per candidate; only the server-accepted one is correct.
- Convert JWK to the exact PEM the server holds (X.509 SubjectPublicKeyInfo PEM is typical). Byte-for-byte identity matters: same PEM format, same trailing newline. In Burp JWT Editor, import the JWK as an RSA key, export PEM, base64-encode it, then paste that as the `k` value of a new symmetric (HMAC) key.
- Set `alg` to `HS256`, tamper the payload, sign with the symmetric key whose `k` is the base64 of the PEM.

```json
Header: {"alg":"HS256"}
Payload: {"sub":"admin","role":"admin","exp":9999999999}
Signature: HMACSHA256(b64url(header)+"."+b64url(payload), <server RSA public key PEM bytes>)
```

Why it works: one generic `verify(token, key)` dispatches on the untrusted `alg` header, so the same key material is interpreted under two incompatible algorithms.

5. Header-parameter injection: embedded `jwk`.

JWS allows an inline public key in the `jwk` header. A misconfigured server verifies using whatever key is embedded rather than a pinned allowlist. Generate your own RSA keypair, embed the public key in `jwk`, sign with your private key.

```json
{
  "alg": "RS256",
  "kid": "attacker-key",
  "jwk": { "kty":"RSA", "e":"AQAB", "kid":"attacker-key", "n":"<attacker-modulus>" }
}
```

Burp JWT Editor "Embedded JWK" attack automates this and syncs `kid`. Real case: CVE-2018-0114 in Cisco's `node-jose` accepted an embedded JWK and verified against it. Why it works: the token carries its own trust anchor.

6. Header-parameter injection: `jku` / `x5u` (attacker JWK Set / cert URL).

`jku` points the server at a JWK Set URL; `x5u` at an X.509 cert URL. If the host allowlist is missing or bypassable, point it at attacker-controlled infrastructure hosting your public key.

```json
{ "alg":"RS256", "kid":"attacker-key", "jku":"https://trusted.example.com.attacker.net/jwks.json" }
```

Bypass weak host filtering with the same URL-parsing and SSRF tricks used elsewhere (`@`, embedded credentials, open redirect on the trusted host, DNS games). Why it works: the server fetches key material from an untrusted, attacker-influenced location.

7. Header-parameter injection: `kid` path traversal, SQLi, and static-file signing.

`kid` selects a key by an arbitrary developer-defined string (file path, DB row). If it feeds a filesystem lookup, traverse to a file whose contents you control or can predict, then sign HS256 with that file's bytes as the secret.

```json
{ "alg":"HS256", "kid":"../../../../dev/null" }
```

`/dev/null` reads as empty, so signing HS256 with an empty-string secret yields a valid signature the server reproduces. If `kid` feeds a SQL query, it is a SQL injection sink: `kid` values like `nonexistent' UNION SELECT 'attacker-known-key'-- ` can make the query return an attacker-known key. Why it works: `kid` is untrusted input used to select trusted key material.

8. Other header abuse.

`cty` (content type) set to `text/xml` or `application/x-java-serialized-object` can open XXE or deserialization if signature verification is already bypassed. `x5c` (embedded cert chain) is a `jwk`-style self-signed injection plus X.509 parser attack surface (PortSwigger cites CVE-2017-2800 and CVE-2018-2633 for X.509 parsing bugs).

9. Claim-validation gaps and cross-service confusion.

Even with a perfect signature, failing to validate claims is exploitable:

- No `exp` check: stolen or old tokens live forever.
- No `aud` check: a token minted for service A is replayed against service B that shares the key or issuer (RFC 8725 calls this cross-JWT confusion and substitution). An access token accepted where an ID token was expected is the same class.
- No `iss` check: tokens from an unexpected issuer are trusted.
- `alg`/`typ` not pinned: opens confusion and the `none` family.

10. ECDSA "Psychic Signatures" (CVE-2022-21449).

Java 15 to 18 (Neil Madden, ForgeRock, 2022) accepted an ECDSA signature with `r = s = 0` as valid for ES256/ES384/ES512. A JWT with a two-zero signature verified against any P-256 public key, forging ES-signed tokens with no key knowledge. It is the modern analogue of `alg: none` for asymmetric tokens and a favourite interview curveball.

## Defense

Ordered by how much attack surface each removes. This maps to RFC 8725 (BCP 225, "JSON Web Token Best Current Practices", Feb 2020) and the OWASP JWT cheat sheets.

1. Pin the algorithm; never trust `alg` from the token (RFC 8725 section 3.1, "Perform Algorithm Verification"). The verifier must be told which algorithm(s) are acceptable and reject everything else, rather than reading `alg` and dispatching on it. In Node `jsonwebtoken`: `jwt.verify(token, key, { algorithms: ['RS256'] })`. In Java `auth0/java-jwt`: build the verifier with a fixed algorithm, `JWT.require(Algorithm.HMAC256(key)).build()`, so a `none` or swapped `alg` throws. This single control kills `alg: none`, unexpected-algorithm acceptance, and RS256-to-HS256 confusion.

2. Separate keys by purpose and never let one key material be usable under two algorithm families (RFC 8725 section 2.4 rationale). Asymmetric verification keys must not also be accepted as HMAC secrets. A hard allowlist of one algorithm per key eliminates confusion even if `alg` pinning is somehow bypassed.

3. Verify, do not decode. Use the library's verifying entry point on every inbound token, and treat verification failure as a hard 401. Never branch on `decode()` output for authz.

4. Strong, unique HMAC secrets. Per OWASP, an HS256 secret should be machine-generated from a CSPRNG and at least 64 characters (256 bits of entropy or more), never a default or human-typed string (RFC 8725 section 3.5, "Ensure Cryptographic Keys Have Sufficient Entropy"). Prefer asymmetric (RS/ES/EdDSA) so verifiers hold only public keys and a compromised verifier cannot mint tokens.

5. Lock down header parameters. Do not honour `jwk` for trust. Maintain a static allowlist of `kid` values, and treat `kid` as untrusted input: parameterize any DB lookup and reject path-traversal characters to stop SQLi and file traversal. For `jku`/`x5u`, enforce a strict allowlist of exact trusted hosts (not substring matches) and disable the feature if unused (RFC 8725 section 3.10, "Do Not Trust Received Claims", and section 2.9 on indirect/SSRF attacks).

6. Validate every claim, not just the signature. Enforce `exp` (with small clock skew), `nbf`, `iss` against an expected issuer, and `aud` against this service's identifier (RFC 8725 sections 3.8 and 3.9). Use `typ`/explicit typing (RFC 8725 section 3.11) and mutually exclusive validation rules per token kind (section 3.12) to stop cross-JWT and ID-token/access-token substitution.

7. Storage and transport. A JWT in `localStorage` is readable by any XSS and is exfiltrated instantly; a token in an `HttpOnly; Secure; SameSite` cookie is not script-readable but then needs CSRF defenses (CSRF token or SameSite). OWASP's token-sidejacking mitigation binds the token to a browser context: issue a high-entropy random value as a `__Secure-Fgp` hardened cookie (`HttpOnly; Secure; SameSite=Strict`) and store only its SHA-256 in the JWT (`userFingerprint` claim); at verification, hash the cookie and require it to equal the claim. A stolen token alone is then useless without the paired cookie, and storing the hash (not the raw value) means XSS reading the token cannot reconstruct the cookie. Keep token lifetimes short (OWASP suggests 15 to 30 minute idle, an absolute cap such as 8 hours) and add a strict Content-Security-Policy.

8. Revocation and refresh-token rotation. Access tokens should be short-lived; a long-lived refresh token (opaque, server-stored) mints new access tokens. Rotate the refresh token on every use and keep a per-family lineage: if a previously-used (rotated-out) refresh token is presented again, that signals theft, so revoke the entire family (reuse detection). For access-token revocation before expiry, keep a server-side denylist keyed on a SHA-256 digest of the token (or its `jti`) with a TTL equal to the token's remaining life; check it on each request. This reintroduces state and is the explicit tradeoff of stateless JWTs.

9. Do not compress-then-encrypt (JWE), do not put secrets in the payload (it is only encoded), and avoid tokens in URLs (they leak via logs and Referer).

## Interview-grade nuances

- The core tension: JWTs are prized for statelessness (any of N backends verifies locally, no session store lookup), but statelessness is exactly what makes revocation, logout, and "kick this session now" hard. Any real revocation (denylist, short TTL plus refresh rotation, or reference tokens) trades away the statelessness you adopted JWTs for. Be able to argue when opaque/reference tokens beat JWTs: single-datacenter apps with an existing session store often gain nothing from JWTs and inherit the revocation problem.

- Why RS256-to-HS256 confusion exists at the API level, not the crypto level: HMAC and RSA are both "correct", the bug is a generic `verify(token, key)` that dispatches on attacker-controlled `alg`. The fix is API design (pin the algorithm), which is why RFC 8725 leads with algorithm verification.

- The public key for confusion is rarely secret: JWKS endpoints, TLS certs, and Git-committed keys all leak it, and `sig2n`/`rsa_sign2n` recover it from two tokens when it is not published. "The secret is public" is the whole point of the attack.

- `alg: none` and CVE-2022-21449 are the same failure in two costumes: accepting a token that carries no real proof of possession. One is a string, one is a degenerate ECDSA `(0,0)` signature.

- Base64url is not encryption. Interviewers probe whether candidates conflate "signed" with "confidential". Anything sensitive in a claim is world-readable unless you use JWE; even then, the signature, not the encoding, is what stops tampering.

- Clock skew and `exp`: reject expired tokens but allow a small leeway (30 to 60 seconds) for skew; huge leeway reintroduces replay windows.

- `kid` is a general injection sink, not just traversal: whatever backend it feeds (filesystem, DB, LDAP, cache key) inherits an injection point because it is untrusted input used to pick trusted keys.

- Cross-JWT confusion is an authorization boundary, not a signature bug: shared signing keys or shared issuers across microservices mean a valid token for one audience is a valid forgery for another unless `aud` is checked. This is why RFC 8725 section 3.12 wants mutually exclusive validation rules per token type.

## Sources

- PortSwigger Web Security Academy, "JWT attacks": https://portswigger.net/web-security/jwt
- PortSwigger Web Security Academy, "Algorithm confusion attacks": https://portswigger.net/web-security/jwt/algorithm-confusion
- PortSwigger, "Working with JWTs in Burp Suite": https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management/jwts
- RFC 8725 (BCP 225), "JSON Web Token Best Current Practices": https://datatracker.ietf.org/doc/html/rfc8725
- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT).
- OWASP, "JSON Web Token for Java Cheat Sheet": https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- Tim McLean, "Critical vulnerabilities in JSON Web Token libraries" (auth0, 2015): https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- Neil Madden, CVE-2022-21449 "Psychic Signatures in Java": https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
- silentsignal/rsa_sign2n and portswigger/sig2n (public-key recovery for algorithm confusion): https://github.com/silentsignal/rsa_sign2n
- ticarpi/jwt_tool: https://github.com/ticarpi/jwt_tool
- hashcat (mode 16500, JWT): https://hashcat.net/hashcat/
