# Cryptographic Failures

> Real-world crypto almost never breaks because someone factored an RSA modulus. It breaks because of misuse: the wrong primitive (a fast hash where a KDF belongs, plain encryption where you needed authentication), a reused or predictable value (nonce, IV, salt, RNG seed), a missing integrity check, or a side channel that leaks one bit or one byte at a time (a padding error, a timing difference, a compression ratio). The mental model for A02:2021 is that confidentiality, integrity, and authenticity are separate properties that you must each provision deliberately, and that the safe move is to reach for a vetted high-level construction (AEAD, HMAC, a CSPRNG, a password KDF) instead of composing block-cipher primitives yourself. OWASP renamed this category from "Sensitive Data Exposure" precisely to shift attention from the symptom (leaked data) to the root cause (the crypto decision that leaked it).

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

## Attack techniques

1. Fast-hash password cracking. If a dump contains `sha256(password)` or `md5(password)`, a commodity GPU rig computes billions to hundreds of billions of candidate hashes per second (fast hashes are designed for throughput). With a wordlist plus rules (hashcat), most human-chosen passwords fall in minutes. Unsalted hashes are worse: a rainbow table (precomputed hash-to-plaintext chains) cracks them with a lookup, and identical hashes reveal users who share a password. Confirmation: the stored value is a bare hex digest with no cost parameter and no per-row salt. Why it works: the defender's per-guess cost equals the attacker's, and for a fast hash that cost is nearly zero.

2. ECB structure leakage and block cut-and-paste. Because ECB is deterministic and stateless per block, an encrypted bitmap still shows the image outline (the "ECB penguin"), and an attacker who controls block-aligned plaintext can shuffle or splice ciphertext blocks to forge structured messages (for example moving an `admin=` block into a token). Confirmation: encrypt two identical 16-byte plaintext blocks and observe identical ciphertext blocks. Why it works: no diffusion across blocks and no integrity.

3. Bit-flipping on unauthenticated CBC/CTR. Without a MAC, ciphertext is malleable. In CTR, flipping a ciphertext bit flips the exact same plaintext bit after decryption, because decryption is just XOR against the keystream. In CBC, flipping a byte in block `C_{i-1}` flips the corresponding byte in decrypted block `P_i` (while garbling `P_{i-1}`), so an attacker who knows the plaintext layout can turn `role=user` into `role=root`. Why it works: integrity was never provided, so any modification decrypts to attacker-chosen changes.

4. Padding oracle (Vaudenay) and POODLE. Serge Vaudenay's 2002 result showed that a CBC decryptor which reveals whether PKCS#7 padding is valid (via distinct error, status code, or response timing) is an oracle that recovers plaintext one byte at a time, roughly 128 queries per byte, with no key knowledge, and can also forge ciphertexts. POODLE (CVE-2014-3566, disclosed 2014 by Bodo Moller, Thai Duong, and Krzysztof Kotowicz at Google) is a padding oracle specific to SSL 3.0, whose CBC padding bytes are not checked, combined with a downgrade dance that forces browsers to fall back to SSL 3.0. Lucky Thirteen (CVE-2013-0169, AlFardan and Paterson, 2013) is the same idea via a TLS MAC-then-encrypt timing side channel. Confirmation: send ciphertexts with mangled last blocks and diff the responses (error text, HTTP status, or timing). Why it works: the padding check leaks a validity bit that is dependent on the secret plaintext.

```
# Padding oracle, last-byte recovery sketch (CBC)
# Target block C2, preceding block C1. Attacker submits C1' || C2.
# Vary the last byte of C1' from 0x00..0xff until the server reports
# "valid padding" (0x01). Then: intermediate = C1'_last XOR 0x01
#                                plaintext_last = intermediate XOR C1_last
# Repeat for 0x02 0x02, etc., walking right-to-left through the block.
```

5. IV/nonce reuse. In CTR and GCM, encrypting two messages under the same key and nonce produces two ciphertexts sharing a keystream: `C1 XOR C2 = P1 XOR P2`, which leaks plaintext relationships and, with any known plaintext, recovers the other. For GCM specifically nonce reuse is worse than a leak: it enables the "forbidden attack" (Antoine Joux) that recovers the GHASH authentication key `H`, letting the attacker forge arbitrary valid tags. This was found in the wild across public HTTPS servers by the "Nonce-Disrespecting Adversaries" study (Bock, Zauner, et al., 2016). BEAST (CVE-2011-3389, Duong and Rizzo) exploited TLS 1.0's use of the previous ciphertext block as the next IV (a predictable, chained IV). Confirmation: same 12-byte nonce appearing twice under one key. Why it works: stream-cipher security collapses entirely when the keystream repeats.

6. Hash length-extension. Given `MAC = H(secret || message)` where `H` is Merkle-Damgard (MD5, SHA-1, SHA-256) and given the MAC plus the length of `secret`, an attacker sets the hash function's internal state to the known digest and continues hashing to compute `H(secret || message || padding || attacker_data)`, a valid MAC for an extended message, without ever knowing `secret`. Tools: `hash_extender`, HashPump. This broke the Flickr API signing scheme (2009). Confirmation: the signature construction is literally hash-of-secret-prepended-to-data. Why it works: the digest fully exposes the chaining state, and the mode lets you resume from it.

7. Non-constant-time comparison (timing side channel). Comparing a submitted MAC, token, HMAC, or password hash with `==` or `memcmp` short-circuits at the first mismatching byte. Over many requests the response-time distribution reveals how many leading bytes matched, so an attacker recovers a valid MAC byte by byte. The Google Keyczar timing flaw (Nate Lawson, 2009) is the canonical example. Why it works: the comparison's running time depends on the secret.

8. Weak randomness and predictable tokens. A statistical PRNG (`Math.random`, `java.util.Random` which is a 48-bit LCG, C `rand()`, the Mersenne Twister) is fully reconstructable from a few observed outputs, so any token minted from it (session ID, reset token, OTP, IV) is predictable and account takeover follows. The Debian OpenSSL disaster (CVE-2008-0166) crippled the seed entropy so that all generated keys came from a space of ~32,768 possibilities. Version 1 UUIDs are timestamp plus MAC address, not random. Confirmation: trace the token back to its RNG source, or collect outputs and predict the next. Why it works: statistical generators optimize for distribution, not unpredictability, and low entropy makes brute force trivial.

9. Transport downgrade, interception, and library bugs. Weak or legacy configuration invites Sweet32 (CVE-2016-2183, birthday attack on 64-bit-block 3DES/Blowfish in long-lived CBC connections), FREAK/Logjam (forced downgrade to export-grade RSA or 512-bit DH), DROWN (CVE-2016-0800, cross-protocol attack that abuses an SSLv2 endpoint sharing a key), and ROBOT (a revival of Bleichenbacher's 1998 RSA PKCS#1 v1.5 padding oracle). Separately, disabling certificate validation ("just make the TLS error go away") converts any on-path box into a silent MITM. Heartbleed (CVE-2014-0160) is a reminder that even correct protocol design fails on an implementation bug: a missing bounds check in OpenSSL's TLS heartbeat leaked up to 64 KB of process memory per request, including private keys. Confirmation: `testssl.sh` or SSL Labs enumerates protocols, suites, and known-CVE exposure.

## Defense

Ordered by how much risk each removes.

1. Do not roll your own crypto and do not compose primitives. Use a vetted high-level library (libsodium, Google Tink, the platform `crypto` module) that exposes misuse-resistant APIs. This single choice preempts most of the attack techniques above, because the library picks AEAD, manages nonces, and compares in constant time for you.

2. Passwords: use a memory-hard KDF with a per-user random salt (built into the format), tuned so one verification takes on the order of hundreds of milliseconds.

   - Argon2id: `m=19456` (19 MiB), `t=2`, `p=1` as a floor, or `m=47104` (46 MiB), `t=1`, `p=1`. Preferred for new systems (side-channel and GPU resistant).
   - scrypt: `N=2^17`, `r=8`, `p=1` when Argon2id is unavailable.
   - bcrypt: work factor >= 10, and enforce a 72-byte input cap (bcrypt silently truncates at 72 bytes). Only for legacy stacks.
   - PBKDF2-HMAC-SHA256 at 600,000 iterations when FIPS-140 validation is mandatory.
   - Add a server-side pepper as defense in depth: HMAC the password (or the resulting hash) with a secret key held in a KMS/HSM, separate from the database, so a database-only breach (SQLi, stolen backup) yields uncrackable hashes. A pepper alone provides nothing; it supplements salt + KDF. Beware naive pre-hashing before bcrypt (`bcrypt(sha512($pw))`) because of null-byte truncation and "password shucking"; if you must pre-hash, do `bcrypt(base64(hmac-sha384(pw, pepper)))`.
   - Store algorithm and parameters with the hash (PHC string format) so you can raise the work factor and re-hash on next login.

3. Encryption: use AEAD, always. AES-256-GCM or ChaCha20-Poly1305, with a unique nonce per message under a given key (a 96-bit random nonce is safe up to ~2^32 messages per key; use a counter or XChaCha20's 192-bit nonce when you need more headroom). Never ECB. Never encrypt without authenticating. If you are forced into CBC/CTR, apply encrypt-then-MAC with an independent HMAC key and verify the MAC in constant time before decrypting (which also closes padding oracles, since you never decrypt unauthenticated data). For RSA encryption use OAEP padding, not PKCS#1 v1.5.

4. Randomness: CSPRNG for everything security-sensitive. `secrets` (Python), `crypto.randomBytes`/`crypto.randomUUID` (Node), `java.security.SecureRandom` (Java), `crypto/rand` (Go), `RandomNumberGenerator` (.NET), `getrandom(2)`/`/dev/urandom` (C). Use >= 128 bits of entropy for security tokens. Do not manually seed a modern CSPRNG.

5. Integrity and comparisons: build MACs with real HMAC (or KMAC/keyed BLAKE2), never `H(secret || message)`. Compare all secrets (MACs, tokens, hashes) with a constant-time function: `hmac.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual` (modern JDK), `subtle.ConstantTimeCompare`.

6. Key management: generate keys from a CSPRNG, store them in a KMS/HSM or secrets vault, keep keys per purpose and fully independent, and use envelope encryption (a KEK wrapping per-data DEKs) so rotation re-wraps DEKs instead of re-encrypting data. Rotate on schedule, on suspected compromise, or after a key has protected a defined data volume. Never hard-code keys, never commit them to VCS, avoid environment variables (leak via `phpinfo()` or `/proc/self/environ`). Keep the rotation runbook tested before you need it.

7. Transport and storage: default to TLS 1.3, allow TLS 1.2 with AEAD/forward-secret suites, and disable TLS 1.0/1.1 (formally deprecated by RFC 8996) plus SSLv2/SSLv3. Prefer server-side cipher ordering, disable TLS compression (CRIME), enable `TLS_FALLBACK_SCSV` against downgrade, keep the crypto library patched (Heartbleed), and validate the certificate chain and hostname on every client call. Enforce HTTPS with HSTS (`max-age` >= 6 months, `includeSubDomains`, `preload`). Encrypt sensitive data at rest, and minimize/tokenize regulated data (PCI, PII) so what you never store cannot be stolen. Never leak decrypt or verify error detail to callers.

8. Deprecate legacy algorithms on a schedule (MD5, SHA-1, DES/3DES, RC4, RSA-1024, PKCS#1 v1.5) and add SAST/CI rules that fail the build on weak-crypto APIs so regressions cannot merge.

## Interview-grade nuances

- "Encrypted" is not "authenticated." Unauthenticated CBC or CTR is malleable and padding-oracle-prone; AEAD is the answer, and if someone says "we encrypt with AES" the immediate follow-up is "which mode, and where is the integrity check."
- Hashing versus encryption for passwords: passwords are hashed (one-way, slow, salted), not encrypted, because you never need to recover the plaintext, only to verify it. Encryption for passwords is a red flag unless there is a hard requirement to replay them to a legacy system.
- Salt versus pepper: salt is per-user, public, stored with the hash, and defeats precomputation and cross-user comparison; pepper is a single secret, kept outside the database (KMS/HSM), and defeats a database-only breach. They solve different problems.
- IV requirements differ by mode: CBC needs an unpredictable (random) IV; CTR/GCM need a unique (never-repeated) nonce, which does not have to be random but must never repeat under one key. Conflating "random" with "unique" causes GCM nonce-reuse disasters.
- GCM nonce reuse is not just a confidentiality leak; it leaks the authentication key `H` and destroys integrity (forgery), which is qualitatively worse than CTR nonce reuse.
- Length extension is a property of the construction, not the hash's collision resistance: SHA-256 is collision resistant yet still extendable, which is exactly why HMAC (nested keying) exists and why SHA-3/BLAKE2 (not classic Merkle-Damgard, or keyed) are not affected the same way.
- Constant-time comparison matters over the network. Jitter does not save you; averaging over enough requests recovers the signal. Treat any secret comparison as needing a constant-time primitive.
- `Math.random()` is not merely low quality, it is reconstructable: V8's algorithm state can be recovered from observed outputs, so predicting future values is deterministic, not probabilistic.
- Downgrade is a first-class attack. POODLE, FREAK, Logjam, and DROWN all hinge on convincing a peer to negotiate something weak, which is why you disable weak protocols/suites outright rather than merely "preferring" strong ones, and why `TLS_FALLBACK_SCSV` exists.
- Heartbleed versus POODLE distinction: Heartbleed is an implementation memory-safety bug (over-read), POODLE is a protocol/mode design flaw (unchecked SSLv3 CBC padding). Naming which class a CVE belongs to signals depth.
- Database transparent encryption (TDE) protects against stolen disks, not against SQL injection, because the app decrypts on read; OWASP Scenario #1 is exactly this. Match the encryption layer to the threat model.

## Sources

- OWASP Top 10 A02:2021 Cryptographic Failures: https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Transport Layer Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- OWASP Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- Serge Vaudenay, "Security Flaws Induced by CBC Padding" (2002); POODLE CVE-2014-3566; Lucky Thirteen CVE-2013-0169; BEAST CVE-2011-3389; Sweet32 CVE-2016-2183; DROWN CVE-2016-0800; Heartbleed CVE-2014-0160
- Cryptopals crypto challenges (hands-on misuse): https://cryptopals.com/
