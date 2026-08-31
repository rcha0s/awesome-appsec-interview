# Cryptographic Failures

> Real-world crypto almost never breaks because someone factored an RSA modulus. It breaks because of misuse: the wrong primitive (a fast hash where a KDF belongs, plain encryption where you needed authentication), a reused or predictable value (nonce, IV, salt, RNG seed), a missing integrity check, or a side channel that leaks one bit or one byte at a time (a padding error, a timing difference, a compression ratio). The mental model for A02:2021 is that confidentiality, integrity, and authenticity are separate properties that you must each provision deliberately, and that the safe move is to reach for a vetted high-level construction (AEAD, HMAC, a CSPRNG, a password KDF) instead of composing block-cipher primitives yourself. OWASP renamed this category from "Sensitive Data Exposure" precisely to shift attention from the symptom (leaked data) to the root cause (the crypto decision that leaked it).

**Interview frequency:** Common

## How it works

Cryptography in an application decomposes into a handful of jobs, and most failures are a mismatch between the job and the tool.

- Password verification: a one-way, deliberately slow, salted transform. This is NOT encryption (reversible) and NOT a general hash (fast). The correct tool is a memory-hard password KDF (Argon2id, scrypt, bcrypt) or PBKDF2 for FIPS.
- Bulk data confidentiality + integrity: authenticated encryption with associated data (AEAD), meaning AES-GCM, AES-CCM, or ChaCha20-Poly1305. One primitive gives you both secrecy and tamper detection.
- Message/token authentication: a keyed MAC, meaning HMAC (or a keyed hash like BLAKE2/KMAC), verified in constant time.
- Unpredictable values: keys, IVs, nonces, session IDs, CSRF tokens, and password-reset tokens all come from a cryptographically secure PRNG (CSPRNG), never a statistical PRNG.
- Transport: TLS 1.3 (or 1.2 with AEAD suites and forward secrecy), with certificate validation actually enabled and HSTS enforcing it.
- Key custody: keys live in a KMS/HSM or secrets manager, are scoped per purpose, and rotate on a schedule.

A few primitives whose internals you should be able to sketch, because interviewers probe them:

- Block cipher modes. A block cipher (AES) only maps one 16-byte block. Modes extend it. ECB encrypts each block independently (deterministic, leaks structure). CBC chains blocks with XOR and needs a random IV. CTR turns the cipher into a keystream generator: `ciphertext = plaintext XOR E(key, nonce||counter)`. CTR and CBC provide confidentiality only, with zero integrity.
- AEAD. GCM is CTR mode for encryption plus a GHASH-based authentication tag over ciphertext and associated data. The tag binds integrity to the same key, so tampering is detected on decrypt.
- Merkle-Damgard hashes. MD5, SHA-1, and SHA-256 process a message in blocks, carrying an internal chaining state that IS the output. That structural fact is what enables length-extension attacks.

```
ECB:  C_i = E(K, P_i)                      # identical P_i -> identical C_i (bad)
CBC:  C_i = E(K, P_i XOR C_{i-1}), C_0=IV  # malleable, needs random IV + a MAC
CTR:  C_i = P_i XOR E(K, nonce || i)       # nonce reuse = catastrophe, needs a MAC
GCM:  CTR for secrecy + GHASH tag          # AEAD: secrecy AND integrity in one key
```

## Quick reference

```
# CBC padding-oracle byte recovery (Vaudenay): no key required, ~128 requests per byte
# Target block C2, preceding block C1. Attacker submits C1' || C2.
# Vary the last byte of C1' from 0x00..0xff until the server reports "valid padding" (0x01).
# intermediate = C1'_last XOR 0x01    plaintext_last = intermediate XOR C1_last
# Repeat for 0x02 0x02, etc., walking right-to-left through the block.
# Any distinguishable padding-valid/invalid signal (error text, status code, or timing)
# is enough to decrypt the whole block with zero key knowledge.
```

| Invariant | Where enforced | How violated | Source |
|---|---|---|---|
| Ciphertext is authenticated before it is decrypted (encrypt-then-MAC ordering) | Protocol/composition design, AEAD library | MAC-then-encrypt or unauthenticated CBC/CTR forces decryption before verification, opening the Vaudenay/Lucky-Thirteen padding-oracle family | <sup>[[6]](#ref6)</sup> |
| A (key, nonce) pair encrypts at most one message | AEAD encryption call site / nonce management | GCM nonce reuse enables the "forbidden attack," recovering the GHASH authentication key and letting an attacker forge arbitrary valid tags | <sup>[[5]](#ref5)</sup> |
| Password verification cost is deliberately asymmetric (slow for attacker and defender alike) | Password KDF (Argon2id/scrypt/bcrypt/PBKDF2) | Fast, unsalted hashing (SHA-256/MD5) lets a commodity GPU rig crack billions of guesses per second | <sup>[[3]](#ref3)</sup> |
| Keys derived via HKDF are domain-separated per purpose, and HKDF never substitutes for a password KDF | HKDF-Expand call site (distinct `info` strings) | Running HKDF on a human password, or a password KDF on already-random master-key material, discards the intended cost profile | <sup>[[4]](#ref4)</sup> |
| Deprecated TLS versions and cipher suites are disabled | TLS server/client configuration | Legacy suites and downgrade paths (Sweet32, FREAK/Logjam, DROWN, ROBOT) remain reachable when TLS 1.0/1.1 and weak ciphers stay enabled | <sup>[[10]](#ref10)</sup> |
| Signing/verification keys never double as symmetric secrets and rotate on schedule from a KMS/HSM | Key management / secrets vault | Hardcoded or environment-variable keys leak (`phpinfo()`, `/proc/self/environ`), or a database-only breach yields crackable hashes with no separate pepper | <sup>[[8]](#ref8)</sup> |
| RSA operations use OAEP (encryption) or PSS (signatures), never raw PKCS#1 v1.5 | RSA library padding-scheme selection | Bleichenbacher's padding oracle recovers plaintext via the PKCS#1 v1.5 `0x00 0x02` prefix leak; PKCS#1 v1.5 signature verifiers that parse forward through padding accept forged signatures | <sup>[[7]](#ref7)</sup> |

## Attack techniques

### 1. Fast-hash password cracking

If a dump contains `sha256(password)` or `md5(password)`, a commodity GPU rig computes billions to hundreds of billions of candidate hashes per second (fast hashes are designed for throughput). With a wordlist plus rules (hashcat), most human-chosen passwords fall in minutes. Unsalted hashes are worse: a rainbow table (precomputed hash-to-plaintext chains) cracks them with a lookup, and identical hashes reveal users who share a password. Confirmation: the stored value is a bare hex digest with no cost parameter and no per-row salt. Why it works: the defender's per-guess cost equals the attacker's, and for a fast hash that cost is nearly zero.

### 2. ECB structure leakage and block cut-and-paste

Because ECB is deterministic and stateless per block, an encrypted bitmap still shows the image outline (the "ECB penguin"), and an attacker who controls block-aligned plaintext can shuffle or splice ciphertext blocks to forge structured messages (for example moving an `admin=` block into a token). Confirmation: encrypt two identical 16-byte plaintext blocks and observe identical ciphertext blocks. Why it works: no diffusion across blocks and no integrity.

### 3. Bit-flipping on unauthenticated CBC/CTR

Without a MAC, ciphertext is malleable. In CTR, flipping a ciphertext bit flips the exact same plaintext bit after decryption, because decryption is just XOR against the keystream. In CBC, flipping a byte in block `C_{i-1}` flips the corresponding byte in decrypted block `P_i` (while garbling `P_{i-1}`), so an attacker who knows the plaintext layout can turn `role=user` into `role=root`. Why it works: integrity was never provided, so any modification decrypts to attacker-chosen changes.

### 4. Padding oracle (Vaudenay) and POODLE

Serge Vaudenay's 2002 result showed that a CBC decryptor which reveals whether PKCS#7 padding is valid (via distinct error, status code, or response timing) is an oracle that recovers plaintext one byte at a time, roughly 128 queries per byte, with no key knowledge, and can also forge ciphertexts. POODLE (CVE-2014-3566, disclosed 2014 by Bodo Moller, Thai Duong, and Krzysztof Kotowicz at Google) is a padding oracle specific to SSL 3.0, whose CBC padding bytes are not checked, combined with a downgrade dance that forces browsers to fall back to SSL 3.0. Lucky Thirteen (CVE-2013-0169, AlFardan and Paterson, 2013) is the same idea via a TLS MAC-then-encrypt timing side channel. Confirmation: send ciphertexts with mangled last blocks and diff the responses (error text, HTTP status, or timing). Why it works: the padding check leaks a validity bit that is dependent on the secret plaintext.

```
# Padding oracle, last-byte recovery sketch (CBC)
# Target block C2, preceding block C1. Attacker submits C1' || C2.
# Vary the last byte of C1' from 0x00..0xff until the server reports
# "valid padding" (0x01). Then: intermediate = C1'_last XOR 0x01
#                                plaintext_last = intermediate XOR C1_last
# Repeat for 0x02 0x02, etc., walking right-to-left through the block.
```

### 5. IV/nonce reuse

In CTR and GCM, encrypting two messages under the same key and nonce produces two ciphertexts sharing a keystream: `C1 XOR C2 = P1 XOR P2`, which leaks plaintext relationships and, with any known plaintext, recovers the other. For GCM specifically nonce reuse is worse than a leak: it enables the "forbidden attack" (Antoine Joux) that recovers the GHASH authentication key `H`, letting the attacker forge arbitrary valid tags. This was found in the wild across public HTTPS servers by the "Nonce-Disrespecting Adversaries" study (Bock, Zauner, et al., 2016). BEAST (CVE-2011-3389, Duong and Rizzo) exploited TLS 1.0's use of the previous ciphertext block as the next IV (a predictable, chained IV). Confirmation: same 12-byte nonce appearing twice under one key. Why it works: stream-cipher security collapses entirely when the keystream repeats.

### 6. Hash length-extension

Given `MAC = H(secret || message)` where `H` is Merkle-Damgard (MD5, SHA-1, SHA-256) and given the MAC plus the length of `secret`, an attacker sets the hash function's internal state to the known digest and continues hashing to compute `H(secret || message || padding || attacker_data)`, a valid MAC for an extended message, without ever knowing `secret`. Tools: `hash_extender`, HashPump. This broke the Flickr API signing scheme (2009). Confirmation: the signature construction is literally hash-of-secret-prepended-to-data. Why it works: the digest fully exposes the chaining state, and the mode lets you resume from it.

### 7. Non-constant-time comparison (timing side channel)

Comparing a submitted MAC, token, HMAC, or password hash with `==` or `memcmp` short-circuits at the first mismatching byte. Over many requests the response-time distribution reveals how many leading bytes matched, so an attacker recovers a valid MAC byte by byte. The Google Keyczar timing flaw (Nate Lawson, 2009) is the canonical example. Why it works: the comparison's running time depends on the secret.

### 8. Weak randomness and predictable tokens

A statistical PRNG (`Math.random`, `java.util.Random` which is a 48-bit LCG, C `rand()`, the Mersenne Twister) is fully reconstructable from a few observed outputs, so any token minted from it (session ID, reset token, OTP, IV) is predictable and account takeover follows. The Debian OpenSSL disaster (CVE-2008-0166) crippled the seed entropy so that all generated keys came from a space of ~32,768 possibilities. Version 1 UUIDs are timestamp plus MAC address, not random. Confirmation: trace the token back to its RNG source, or collect outputs and predict the next. Why it works: statistical generators optimize for distribution, not unpredictability, and low entropy makes brute force trivial.

### 9. Transport downgrade, interception, and library bugs

Weak or legacy configuration invites Sweet32 (CVE-2016-2183, birthday attack on 64-bit-block 3DES/Blowfish in long-lived CBC connections), FREAK/Logjam (forced downgrade to export-grade RSA or 512-bit DH), DROWN (CVE-2016-0800, cross-protocol attack that abuses an SSLv2 endpoint sharing a key), and ROBOT (a revival of Bleichenbacher's 1998 RSA PKCS#1 v1.5 padding oracle)<sup>[[1]](#ref1)</sup>. Separately, disabling certificate validation ("just make the TLS error go away") converts any on-path box into a silent MITM. Heartbleed (CVE-2014-0160) is a reminder that even correct protocol design fails on an implementation bug: a missing bounds check in OpenSSL's TLS heartbeat leaked up to 64 KB of process memory per request, including private keys. Confirmation: `testssl.sh` or SSL Labs enumerates protocols, suites, and known-CVE exposure.

### 10. BREACH and HTTP-layer compression side channels

BREACH (2013, disclosed by Prado, Harris, and Gluck at Black Hat)<sup>[[2]](#ref2)</sup> is a compression oracle at the HTTP layer rather than the TLS layer, so disabling TLS compression (which closed CRIME) does not touch it, and TLS 1.3 does not close it either because TLS 1.3 only forbids TLS-level compression. The precondition is a response body that is gzip- or deflate-compressed and that reflects an attacker-controlled input (a query parameter, form field, or header) somewhere alongside a secret the attacker wants (a CSRF token, session id, OAuth authorization code, or JSON containing an email or credit-card fragment). The attacker scripts a victim browser (via a malicious ad or a lure page) to issue requests with guesses of the secret placed in the reflected input; a guess that matches a longer prefix of the real secret compresses better and produces a shorter TLS-encrypted response. Length observation from a passive on-path position yields byte-by-byte recovery in a few thousand requests.

TIME (2013, Be'ery and Shulman) is the same primitive read through response timing rather than length, and applies when a WAF or CDN masks the length side channel. Mitigations layered from most to least effective: disable HTTP response compression on any endpoint that echoes user input near a secret, keep secrets off pages that reflect input at all, add random-length padding to compressed responses, rotate CSRF tokens per request so the byte-recovery loop resets before it converges, and enforce a strong same-origin gate (Sec-Fetch-Site, Origin, Referer) so the browser cannot be scripted into the guessing loop from a foreign origin. CRIME (2012, Duong and Rizzo) is the TLS-compression sibling and is closed by disabling TLS-level compression outright.

### 11. Bleichenbacher RSA PKCS#1 v1.5 padding oracle

RSA encryption padding under PKCS#1 v1.5 begins with a fixed prefix of `0x00 0x02`. A server that RSA-decrypts a ciphertext and reveals through an error message, HTTP status, or response timing whether the resulting plaintext begins with that prefix is a padding oracle. Bleichenbacher (1998)<sup>[[1]](#ref1)</sup> turned this bit into full plaintext recovery by exploiting RSA's multiplicative homomorphism: for any attacker-chosen `s`, `Dec(c * s^e mod N) = m * s mod N`, so submitting the mangled ciphertext `c * s^e mod N` and receiving the padding-valid signal narrows the interval of possible plaintexts. Each oracle hit roughly halves the interval, and after a few hundred thousand to a million queries against 1024-bit RSA the message is fully recovered without any key knowledge. Modern variants converge in far fewer queries.

ROBOT (2017, Bock, Somorovsky, and Young)<sup>[[1]](#ref1)</sup> rediscovered this exact class across F5 BIG-IP, Citrix NetScaler, Cisco ACE, Erlang/OTP, WolfSSL, and other TLS stacks that still supported RSA key transport with a padding check that leaked one bit through a distinguishable error or timing difference. On the signature side the same PKCS#1 v1.5 family has its own history of parsing bugs, most famously Bleichenbacher's 2006 `e=3` signature forgery where verifiers walked forward through the padding rather than reconstructing the expected structure and comparing byte-for-byte. Confirmation: send a ciphertext with a deliberately mangled `0x00 0x02` prefix and diff the server's response (error string, status code, or timing) against a well-formed one. Why it works: the decryption pipeline has one branch that depends on the plaintext, and one branch is all the oracle needs.

## Defense

Ordered by how much risk each removes within its group.

### Real fix

1. Do not roll your own crypto and do not compose primitives. Use a vetted high-level library (libsodium, Google Tink, the platform `crypto` module) that exposes misuse-resistant APIs. This single choice preempts most of the attack techniques above, because the library picks AEAD, manages nonces, and compares in constant time for you.

2. Passwords: use a memory-hard KDF with a per-user random salt (built into the format), tuned so one verification takes on the order of hundreds of milliseconds<sup>[[3]](#ref3)</sup>.

   - Argon2id: `m=19456` (19 MiB), `t=2`, `p=1` as a floor, or `m=47104` (46 MiB), `t=1`, `p=1`. Preferred for new systems (side-channel and GPU resistant).
   - scrypt: `N=2^17`, `r=8`, `p=1` when Argon2id is unavailable.
   - bcrypt: work factor >= 10, and enforce a 72-byte input cap (bcrypt silently truncates at 72 bytes). Only for legacy stacks.
   - PBKDF2-HMAC-SHA256 at 600,000 iterations when FIPS-140 validation is mandatory.
   - Add a server-side pepper as defense in depth: HMAC the password (or the resulting hash) with a secret key held in a KMS/HSM, separate from the database, so a database-only breach (SQLi, stolen backup) yields uncrackable hashes. A pepper alone provides nothing; it supplements salt + KDF. Beware naive pre-hashing before bcrypt (`bcrypt(sha512($pw))`) because of null-byte truncation and "password shucking"; if you must pre-hash, do `bcrypt(base64(hmac-sha384(pw, pepper)))`.
   - Store algorithm and parameters with the hash (PHC string format) so you can raise the work factor and re-hash on next login.

   Distinguish a password KDF from HKDF. HKDF (RFC 5869)<sup>[[4]](#ref4)</sup> is the correct tool for deriving multiple purpose-scoped keys from a single high-entropy secret: a master key, a Diffie-Hellman shared secret, a DEK returned by a KMS. It is fast on purpose because the input already has cryptographic entropy, so the goal is domain separation and expansion, not slowing an attacker down. HKDF has an extract step (HMAC over a salt to concentrate entropy into a pseudo-random key) and an expand step (produce N bytes with a per-use `info` string, for example `"encryption-key-v1"` versus `"mac-key-v1"`, so different consumers of the same master cannot collide). Never run HKDF on a human password (no work factor, brute-force is trivial) and never run Argon2/bcrypt/scrypt/PBKDF2 to expand a random master key into subkeys (wrong tool, wrong cost profile, and PBKDF2's iteration cost is pure waste on already-random input). The envelope pattern is: KMS returns a DEK, HKDF-Expand it into an AEAD key and (if you need one) a MAC key with distinct info strings, or use the DEK directly as the AEAD key when only one key is needed.

3. Encryption: use AEAD, always<sup>[[5]](#ref5)</sup>. AES-256-GCM or ChaCha20-Poly1305, with a unique nonce per message under a given key (a 96-bit random nonce is safe up to ~2^32 messages per key; use a counter or XChaCha20's 192-bit nonce when you need more headroom). Never ECB. Never encrypt without authenticating. If you are forced into CBC/CTR, apply encrypt-then-MAC with an independent HMAC key and verify the MAC in constant time before decrypting (which also closes padding oracles, since you never decrypt unauthenticated data). For RSA encryption use OAEP padding, not PKCS#1 v1.5.

   Composition order matters and is a classic interview probe. Three ways to combine a cipher and a MAC: Encrypt-and-MAC (SSH: MAC the plaintext, send both), MAC-then-Encrypt (old TLS: MAC the plaintext, then encrypt plaintext plus MAC), and Encrypt-then-MAC (IPsec, modern designs: encrypt the plaintext, MAC the ciphertext, send both). Only Encrypt-then-MAC is generically secure (Krawczyk, 2001)<sup>[[6]](#ref6)</sup>; the other two are secure only for specific ciphers and were the entry point for Lucky Thirteen, because MAC-then-Encrypt forces the receiver to decrypt before it can verify, which puts a padding-oracle attacker exactly where they need to be. Encrypt-then-MAC lets the receiver reject a forged ciphertext before touching the cipher, and that structural property is what closes padding oracles rather than any patch to the padding check itself.

   For RSA signatures, prefer RSA-PSS over PKCS#1 v1.5 signatures. PSS is randomized and has a formal security reduction, while PKCS#1 v1.5 signature verifiers have repeatedly shipped bugs that accept malformed signatures because they parse forward through the padding rather than reconstructing the expected padded structure and comparing byte-for-byte in constant time. If PSS is not available for legacy compatibility, verify PKCS#1 v1.5 by rebuilding the full expected structure and doing a single constant-time comparison against the raw RSA output, never by walking the padding fields. For new code prefer Ed25519 for signatures (deterministic, no RNG required at signing time, no padding to get wrong) and X25519 for key agreement, both of which sidestep the PKCS#1 family entirely.

4. Randomness: CSPRNG for everything security-sensitive. `secrets` (Python), `crypto.randomBytes`/`crypto.randomUUID` (Node), `java.security.SecureRandom` (Java), `crypto/rand` (Go), `RandomNumberGenerator` (.NET), `getrandom(2)`/`/dev/urandom` (C). Use >= 128 bits of entropy for security tokens. Do not manually seed a modern CSPRNG.

5. Integrity and comparisons: build MACs with real HMAC (or KMAC/keyed BLAKE2), never `H(secret || message)`. Compare all secrets (MACs, tokens, hashes) with a constant-time function: `hmac.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual` (modern JDK), `subtle.ConstantTimeCompare`.

6. Key management: generate keys from a CSPRNG, store them in a KMS/HSM or secrets vault, keep keys per purpose and fully independent, and use envelope encryption (a KEK wrapping per-data DEKs) so rotation re-wraps DEKs instead of re-encrypting data<sup>[[8]](#ref8)</sup>. Rotate on schedule, on suspected compromise, or after a key has protected a defined data volume. Never hard-code keys, never commit them to VCS, avoid environment variables (leak via `phpinfo()` or `/proc/self/environ`). Keep the rotation runbook tested before you need it.

7. Transport and storage: default to TLS 1.3, allow TLS 1.2 with AEAD/forward-secret suites, and disable TLS 1.0/1.1 (formally deprecated by RFC 8996<sup>[[10]](#ref10)</sup>) plus SSLv2/SSLv3<sup>[[9]](#ref9)</sup>. Prefer server-side cipher ordering, disable TLS compression (CRIME), enable `TLS_FALLBACK_SCSV` against downgrade, keep the crypto library patched (Heartbleed), and validate the certificate chain and hostname on every client call. Enforce HTTPS with HSTS (`max-age` >= 6 months, `includeSubDomains`, `preload`). Encrypt sensitive data at rest, and minimize/tokenize regulated data (PCI, PII) so what you never store cannot be stolen. Never leak decrypt or verify error detail to callers.

### Defense in depth

1. Deprecate legacy algorithms on a schedule (MD5, SHA-1, DES/3DES, RC4, RSA-1024, PKCS#1 v1.5) and add SAST/CI rules that fail the build on weak-crypto APIs so regressions cannot merge.

2. Certificate and public-key pinning (for thick clients). Invariant enforced: only a pre-authorized keypair can terminate TLS for this client-server pair, so a rogue CA (or a locally trusted root injected by a corporate proxy, EDR agent, or malware) cannot silently MITM. The client hashes the SPKI (SubjectPublicKeyInfo) of a certificate in the chain and compares it against a compiled-in list; a mismatch aborts the connection. Why it works: pinning removes the "any CA trusted by the OS can vouch for any hostname" trust assumption, which is the assumption an attacker with a stolen or misissued cert relies on. On the web the current answer is Certificate Transparency monitoring and CAA DNS records rather than pins, because HPKP was deprecated after bad pins bricked sites for the pin lifetime. On mobile apps and thick clients pinning is still standard: pin the SPKI hash of the leaf or an intermediate, ship at least one backup pin, embed pins in the binary rather than fetching them at runtime (fetching them defeats the point), pair with an emergency remote kill-switch, and ship the new pin in a client release before rotating the server certificate. Common wrong implementation: pinning the entire leaf certificate (breaks on every renewal), pinning with no backup pin (one lost key bricks the app), or downloading pins over the same channel you are trying to protect.

3. Post-quantum posture and crypto agility. Invariant enforced: no cryptographic identifier is baked into a format that cannot be rotated, and long-lived confidential data is protected against "harvest now, decrypt later." Shor's algorithm on a large fault-tolerant quantum computer breaks RSA and ECC for both key exchange and signatures, while Grover's only halves symmetric strength, so AES-256 and SHA-384/SHA-512 remain safe and AES-128/SHA-256 slip to a weaker margin. Anything with a multi-year confidentiality horizon (medical records, financial transactions, government data, source code, long-lived signing keys) is at risk today, because an adversary who records the ciphertext now can decrypt when PQ hardware arrives. Why it works: pre-adopting hybrid key exchange means today's session keys are not recoverable even against a future quantum adversary; per-record algorithm identifiers mean rotation is a re-encrypt-on-touch rather than a stop-the-world migration. Practical steps: adopt hybrid TLS key exchange (X25519 combined with ML-KEM/Kyber, already shipping in Chrome and Cloudflare), inventory long-lived RSA/ECDSA certificates and signing keys with a migration path to ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) once ecosystem support stabilizes, keep symmetric strength at the 256-bit tier for anything that must outlast the transition (NIST FIPS 203/204/205 were finalized in 2024<sup>[[11]](#ref11)</sup>), and stamp algorithm identifiers into every stored ciphertext, session cookie, and signed token. Common wrong implementation: hard-coding an algorithm name into a stored format ("this column is AES-GCM, period") so rotation requires a full data rewrite, or treating PQ as a "when it becomes a problem" issue when the recording is happening now.

## Interviewer probes

Mid: "Someone tells you 'we encrypt sensitive fields with AES.' Is that enough to sign off?"

Principal: No, that sentence has left out the two things that actually matter: which mode, and where is the integrity check. Unauthenticated CBC or CTR is malleable, an attacker who knows the plaintext layout can flip bits or splice blocks and get attacker-chosen changes on decrypt, and CBC without a MAC opens a padding oracle that recovers plaintext byte by byte with no key knowledge. "Encrypted" only claims confidentiality; it says nothing about integrity or authenticity. The answer you want to hear is AEAD, AES-GCM or ChaCha20-Poly1305, which gives you both in one primitive, or encrypt-then-MAC if you're stuck with a legacy mode.

Mid: "Why do we hash passwords instead of encrypting them, if encryption is the 'stronger' primitive?"

Principal: Because the goal is different. You never need to recover a password's plaintext, only verify that a submitted guess matches, so a one-way, deliberately slow, salted transform is the correct tool, not a reversible one. Encryption implies you can decrypt, which means there's a key that, if compromised, hands over every password in the database in plaintext at once. Seeing passwords encrypted rather than hashed is a red flag unless there's a hard requirement to replay them to a legacy system, and even then the encryption key becomes the single point of failure the hash was designed to avoid.

Mid: "What's the difference between a salt and a pepper, and do you need both?"

Principal: They defeat different attacks. Salt is per-user, public, and stored right alongside the hash; its job is to defeat precomputed rainbow tables and stop two users with the same password from producing the same hash. Pepper is a single secret kept outside the database entirely, typically HMACed in via a KMS or HSM, and its job is to defeat a database-only breach, SQL injection or a stolen backup, because the attacker gets the hashes but not the pepper needed to crack them. A pepper alone provides nothing; it only supplements a proper salted KDF, it doesn't replace one.

Mid: "You're moving from CBC to GCM. Can you keep generating a random IV the same way?"

Principal: Not quite, and conflating "random" with "unique" is exactly where GCM nonce-reuse disasters come from. CBC needs an unpredictable, random IV. CTR and GCM need a nonce that is merely unique, it never has to be random, it just must never repeat under the same key, so a counter is perfectly valid and often safer than relying on randomness at scale. The stakes are also different: reusing a nonce in CTR leaks a keystream and the XOR of two plaintexts, but reusing a nonce in GCM is worse, it recovers the GHASH authentication key itself via the "forbidden attack," letting the attacker forge arbitrary valid tags on top of the confidentiality break. Losing integrity is qualitatively worse than losing confidentiality alone.

Mid: "SHA-256 is collision resistant, so is `H(secret || message)` a safe way to build a MAC?"

Principal: No, and this is where people conflate two different properties. Length extension is a property of the Merkle-Damgard construction, not a break of collision resistance; SHA-256 can be perfectly collision resistant and still let an attacker take the digest of `H(secret||message)` plus the length of `secret`, and compute a valid MAC for `H(secret||message||padding||attacker_data)` without ever learning the secret. That's exactly why HMAC exists, its nested keying construction is specifically designed to prevent this, and it's why SHA-3 and BLAKE2 (not classic Merkle-Damgard, or keyed) don't have the same problem. A candidate who says "SHA-256 is secure so this is fine" has missed that security property and vulnerability class are not the same axis.

Mid: "Is `Math.random()` really a security problem, or is it just 'lower quality' randomness?"

Principal: It's a real, practical exploitation path, not a quality nitpick. `Math.random()` is a statistical PRNG, and in V8 specifically, its algorithm state can be recovered from a handful of observed outputs, which makes predicting every future value deterministic rather than probabilistic. Anything minted from it, a session ID, a password-reset token, an OTP, is only as unpredictable as the attacker's ability to reconstruct the generator state, and that's a solved problem for the common runtimes. The fix isn't "use a better statistical generator," it's use a CSPRNG, `crypto.randomBytes`/`crypto.randomUUID` in Node, for anything security-sensitive.

Mid: "Heartbleed and POODLE both hit TLS around the same era. Are they the same kind of bug?"

Principal: No, and naming which class each belongs to is the signal of depth here. Heartbleed is an implementation memory-safety bug, a missing bounds check in OpenSSL's heartbeat handling that over-read up to 64 KB of process memory, including private keys, on a protocol that was otherwise fine. POODLE is a protocol and mode design flaw, SSL 3.0's CBC padding bytes were never checked at all, and an attacker forces a downgrade to that broken protocol to exploit it. One is "the code has a bug," the other is "the design itself is unsound," and the fixes differ accordingly: Heartbleed needed a patched library, POODLE needed SSLv3 disabled outright.

Mid: "The database uses transparent data encryption. Does that protect us against a SQL injection that dumps the customers table?"

Principal: No, and that's a common false sense of security. TDE protects data at rest, against a stolen disk, an unencrypted backup, or physical access to storage, because it decrypts transparently for any authenticated connection to the database. A SQL injection query runs through the same authenticated application connection the database always decrypts for, so the injected query gets plaintext back exactly like a legitimate one would. This is OWASP's Scenario #1 for cryptographic failures: matching the encryption layer to the actual threat model matters more than which encryption you picked, TDE answers "what if someone steals the disk," not "what if the application's own trusted path is abused."

## Sources

<a id="ref1"></a>[1] Daniel Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1" (CRYPTO 1998); Bock, Somorovsky, and Young, ROBOT ("Return Of Bleichenbacher's Oracle Threat"). 2017. https://robotattack.org/

<a id="ref2"></a>[2] Prado, Harris, and Gluck, "BREACH" attack. Black Hat. 2013. http://breachattack.com/

<a id="ref3"></a>[3] OWASP, "Password Storage Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

<a id="ref4"></a>[4] RFC 5869, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)". IETF. May 2010. https://www.rfc-editor.org/rfc/rfc5869

<a id="ref5"></a>[5] OWASP, "Cryptographic Storage Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

<a id="ref6"></a>[6] Hugo Krawczyk, "The Order of Encryption and Authentication for Protecting Communications". CRYPTO 2001. https://www.iacr.org/archive/crypto2001/21390309.pdf

<a id="ref7"></a>[7] RFC 8017, "PKCS #1: RSA Cryptography Specifications Version 2.2" (RSA-OAEP, RSA-PSS). IETF. November 2016. https://www.rfc-editor.org/rfc/rfc8017

<a id="ref8"></a>[8] OWASP, "Key Management Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

<a id="ref9"></a>[9] OWASP, "Transport Layer Security Cheat Sheet". Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html

<a id="ref10"></a>[10] RFC 8996, "Deprecating TLS 1.0 and TLS 1.1". IETF. March 2021. https://datatracker.ietf.org/doc/html/rfc8996

<a id="ref11"></a>[11] NIST, Post-Quantum Cryptography: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). August 2024. https://csrc.nist.gov/projects/post-quantum-cryptography
