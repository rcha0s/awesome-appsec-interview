# File Upload and Storage Security

> File storage security is the CIA triad applied to bytes at rest instead of credentials in flight: confidentiality is who can retrieve a stored object, integrity is whether what comes back is the same thing that was written, and availability is whether the object survives the storage layer's own durability, backup, and restore guarantees, tested, not just assumed to hold. Upload-time validation decides whether a file's bytes get trusted at all; this doc governs everything after that decision, where the object lives, who can ask for it back, how that request gets authorized, and how long the answer stays yes. That question forks hard by file sensitivity and serving context, because a marketing image served from a public CDN and a KYC document served to one authenticated user have almost nothing in common architecturally even though both started as an HTTP upload. The single biggest thing a Principal reviewer checks is whether retrieval happens through a signed or authenticated reference that expires and re-checks authorization, or through a path that, once known, works forever.

**Interview frequency:** Common

## Where this decision forks

The decomposition axis is file sensitivity and serving context, because the realistic storage and delivery architecture, and the operational cost of getting it wrong, differ sharply depending on who a file is for and how public it's allowed to be.

- **Public, low-sensitivity content** (avatars, marketing assets, product images) wants cheap, high-throughput serving through a CDN and tolerates a leaked URL doing no real damage.
- **Private user documents** (financial statements, identity documents, contracts) need retrieval gated by authorization on every request, not just at upload time, because the cost of one leaked object is a security incident.
- **System-generated files** (exports, backups, invoices, partner-delivered artifacts) sit in the same storage layer but were never uploaded by an end user at all, and it's the context teams most often forget to apply access-control discipline to at all.

### Public and low-sensitivity content

Traffic and cost dominate the design here more than access control does, because the content is meant to be reachable by anyone. The surviving risk is what a public, high-reputation-domain upload endpoint can be abused for, and what the file quietly carries that the uploader never meant to publish.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Object storage (S3/GCS/Azure Blob) fronted by a CDN, public-read on the bucket | High-traffic public assets, avatars, product images, marketing media, the default at any real scale | One bucket also holds private objects, mixing sensitivity tiers under the same public policy | Preferred | [10-file-upload.md](10-file-upload.md) |
| App-server-proxied delivery from local disk or a private bucket | Small deployments with low traffic and no CDN budget | Traffic or file count outgrows a single server's bandwidth and disk | Legacy | [10-file-upload.md](10-file-upload.md) |
| Signed URL for content that's technically public but not meant to be indexed or bulk-scraped | Public-ish content with a soft privacy expectation, an unlisted photo album | The content is genuinely public and a signature adds latency without real access control | Niche-but-required | [15-access-control-idor.md](15-access-control-idor.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Predictable or sequential object keys | A sequential or ID-derived key turns "public but not linked" into "public and crawlable" the instant one URL leaks<sup>[[1]](#ref1)</sup> | Generate high-entropy, non-sequential keys, never derive them from a user ID or row number | [21-information-disclosure.md](21-information-disclosure.md) |
| EXIF/metadata not stripped before public serving | Uploaded photos routinely carry GPS coordinates, device IDs, and internal filesystem paths the uploader never saw<sup>[[2]](#ref2)</sup> | Strip EXIF/metadata server-side at ingest, before the object is written to the public bucket | [21-information-disclosure.md](21-information-disclosure.md) |
| Content-Type/nosniff enforcement on served objects | A browser that content-sniffs a served file into an unexpected type can turn a hosted asset into stored XSS on the serving origin<sup>[[3]](#ref3)</sup><sup>[[4]](#ref4)</sup> | Force `nosniff` and a locked-down `Content-Type` at serve time, never trust the uploader's declared type | [19-security-misconfiguration-headers.md](19-security-misconfiguration-headers.md) |
| Origin isolation for renderable content (HTML/SVG) | Nosniff doesn't help when the file genuinely is HTML or SVG with an honest Content-Type; the browser renders it on whatever origin served it, cookies and same-origin reach included | Serve user content from a separate, cookie-less domain, force `Content-Disposition: attachment` on anything renderable | [19-security-misconfiguration-headers.md](19-security-misconfiguration-headers.md) |
| CDN cache staleness after a moderation takedown | An edge cache can keep serving a removed file for its full TTL after the origin object is deleted<sup>[[5]](#ref5)</sup> | Pair takedown with an explicit cache purge, don't rely on TTL expiry alone | [19-security-misconfiguration-headers.md](19-security-misconfiguration-headers.md) |
| Malware distributed through a public-upload feature | Attackers abuse public, reputable-domain upload endpoints as free hosting for malware or phishing payloads; the victim is whoever downloads the file, not the bucket owner | Scan public uploads too, matched to distribution risk, not content sensitivity | [10-file-upload.md](10-file-upload.md) |
| Storage that cannot execute what it holds | Object storage with no execution path removes served-file RCE outright; a webroot-adjacent disk directory is one server config change away from being interpreted as code | Use object storage, or a disk directory outside every document root with no interpreter mapped to it, verified not assumed | [10-file-upload.md](10-file-upload.md) |

Also worth a mention: hotlinking and bandwidth theft via unauthenticated CDN URLs, directory listing left enabled on the bucket itself, orphaned public objects from deleted accounts never cleaned up, see [10-file-upload.md](10-file-upload.md) and [21-information-disclosure.md](21-information-disclosure.md).

### Private and sensitive documents

The two realistic serving mechanisms trade audit strength against operational simplicity: a presigned URL hands the client a time-limited bearer token good for direct object-store access, while an authenticated proxy keeps every byte flowing through the app server where access control and logging already live. A healthcare records platform and a B2B SaaS storing signed contracts both serve private documents, but the healthcare platform is far more likely to need the proxy's per-request audit trail, because a regulator will eventually ask who accessed which record and when, not just whether the bucket was private.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Presigned/time-limited object-store URLs | High-volume private downloads that need to scale past app-server bandwidth | A regulatory requirement demands every access recorded server-side, or the URL is likely to be forwarded outside its intended recipient | Preferred | [15-access-control-idor.md](15-access-control-idor.md) |
| Authenticated proxy/streaming through the app server | Highest-sensitivity documents needing per-request authorization, a durable audit trail, and instant revocation | File volume or size makes app-server bandwidth and CPU the bottleneck | Preferred | [15-access-control-idor.md](15-access-control-idor.md) |
| Unlisted or guessable direct object-store URL, no signature | Rarely the right call, still shipped as a shortcut | Any document with real sensitivity, an unguessable key is not an authorization control | Legacy | [21-information-disclosure.md](21-information-disclosure.md) |
| Permanent client-embedded download token | Legacy architectures predating object-store signing | New builds, a token that never expires leaks through browser history, referrer headers, and shared logs | Legacy | [15-access-control-idor.md](15-access-control-idor.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| Presigned URL expiry, scope, and revocation lag | A URL good for a week, or scoped to a whole prefix, is a bearer credential wearing a signature<sup>[[6]](#ref6)</sup><sup>[[7]](#ref7)</sup>; once issued, the object store honors it without consulting the app, so deleting the share record doesn't revoke a URL already in flight | Shortest TTL the workflow tolerates, scoped to the single object; for tiers needing instant revocation, proxy instead or issue against destroyable per-share keys | [15-access-control-idor.md](15-access-control-idor.md) |
| CDN/edge caching of private objects | A presigned URL is a signed but otherwise ordinary GET; an edge or shared cache that caches on URL alone replays the object to any requester for the rest of the cache TTL, independent of the signature's own expiry<sup>[[5]](#ref5)</sup> | Mark every private download response `no-store`/`private`, keep private objects off cacheable CDN paths entirely | [19-security-misconfiguration-headers.md](19-security-misconfiguration-headers.md) |
| Envelope encryption and per-tenant key scoping at rest | One shared data-at-rest key means one key-management failure exposes every document, not just the one an attacker was after | Envelope-encrypt with a KMS-backed data key scoped per tenant or sensitivity tier, not one key for the whole bucket | [98-secrets-keys-data-protection.md](98-secrets-keys-data-protection.md) |
| Untrusted parsers in preview/OCR/conversion pipelines | A preview or OCR pipeline parses the uploaded file with a separate parser upload validation never reviewed, inheriting both XXE from Office/XML/SVG documents and RCE from image/document converters with a long exploited-parser history (ImageTragick is the canonical case)<sup>[[8]](#ref8)</sup> | Disable external entity resolution in every such parser, and run conversion/thumbnailing in an isolated, credential-free, resource-capped worker, never in-process on the app server | [06-xxe.md](06-xxe.md) |
| Cross-tenant storage isolation for shared buckets | A shared bucket with tenant-prefixed keys and no server-enforced boundary depends entirely on application code getting every prefix check right, forever<sup>[[9]](#ref9)</sup> | Enforce tenant scope with bucket policy or object-store-native isolation, not application logic alone | [102-multi-tenancy-isolation.md](102-multi-tenancy-isolation.md) |
| Retention windows, deletion SLAs, and PII minimization | A document collected for one purpose and kept indefinitely becomes liability with no offsetting business value<sup>[[10]](#ref10)</sup> | Define a retention window and deletion SLA per document class before onboarding it, not after a regulator asks | [99-privacy-engineering.md](99-privacy-engineering.md) |
| AV/malware scan bypass via encrypted or archived payloads | A password-protected zip or encrypted attachment sails past content-based scanning because the scanner can't see inside it<sup>[[11]](#ref11)</sup> | Reject or quarantine encrypted/archived uploads the scanner can't inspect | [10-file-upload.md](10-file-upload.md) |

Also worth a mention: weak or missing encryption algorithm choice at the storage layer ([17-cryptographic-failures.md](17-cryptographic-failures.md)), decompression bombs inside preview/OCR pipelines ([43-unbounded-consumption.md](43-unbounded-consumption.md)), pre-signed PUT URLs handed out for direct-to-bucket writes with no server-side content-type or size check on completion, bypassing the upload validation this doc otherwise assumes already happened ([10-file-upload.md](10-file-upload.md)).

### System-generated and internal files

The generation and delivery pipeline itself becomes the attack surface here: a URL-based export or a webhook-delivered file introduces server-side-request risk that a purely user-uploaded document never had to deal with, and it rarely gets reviewed that way because it's framed as an export or import feature rather than a network request. A B2B platform generating monthly usage reports and a payments product ingesting partner-delivered PDF invoices both sit in this context, but the payments product's ingestion path is the one that needs to treat every partner callback as untrusted input, not an internal-looking source.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
| --- | --- | --- | --- | --- |
| Synchronous generation streamed directly in the response, no persistent copy | Small, fast exports, a CSV under a few MB generated in-request | Generation time or size makes blocking the request impractical | Preferred | [43-unbounded-consumption.md](43-unbounded-consumption.md) |
| Async job writes to storage, delivered via signed URL or notification | Large or slow-to-generate artifacts: bulk exports, reports, ML training artifacts | The artifact is a bulk sensitive extract whose persisted copy's retention, key-scope, and access surface cost more than the generation time it saves | Preferred | [15-access-control-idor.md](15-access-control-idor.md) |
| Direct bucket write from a partner or webhook callback | Integrations where a third party pushes the file, billing-provider invoices, partner document delivery | The callback's origin isn't strongly authenticated and gets treated as internally-sourced by default | Still common | [04-ssrf.md](04-ssrf.md) |
| Lifecycle-tiered cold storage for long-retention backups | Audit archives and backups rarely read back, where retrieval latency is acceptable | Frequent read access is needed and retrieval latency or cost becomes the actual blocker | Preferred | [98-secrets-keys-data-protection.md](98-secrets-keys-data-protection.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
| --- | --- | --- | --- |
| SSRF via URL-fetch import/export or webhook-delivered files | "Fetch this file from a URL and process it" is a server-side request whose destination the caller fully controls, the same defect class behind the 2019 Capital One breach, where SSRF against a cloud metadata endpoint led to mass S3 exfiltration<sup>[[12]](#ref12)</sup> | Treat every fetch-by-URL or webhook feature as an SSRF sink with destination allowlisting | [04-ssrf.md](04-ssrf.md) |
| Decompression/zip bombs during export bundling or backup restore | A small compressed input expanding to gigabytes exhausts disk or memory on whichever process unpacks it<sup>[[13]](#ref13)</sup> | Enforce per-entry and total decompressed-size limits before extraction, not after | [43-unbounded-consumption.md](43-unbounded-consumption.md) |
| Orphaned files from failed or abandoned jobs | A job that fails after partial output, or a report nobody downloaded, accumulates as storage with no owner and no deletion trigger | Tie every generated file to a job record with an expiry, sweep unreferenced objects on a schedule | [99-privacy-engineering.md](99-privacy-engineering.md) |
| Predictable or enumerable generated-file paths | Export paths built from sequential job IDs or predictable timestamps let one authenticated user guess another's export URL | Generate high-entropy object keys for every generated artifact, same as any other private object | [21-information-disclosure.md](21-information-disclosure.md) |
| Backup/export encryption drifting from the primary store's standard | Backups are routinely the least-reviewed copy of the data, encrypted with an older key or sometimes not at all | Backups and exports inherit the same encryption and key-rotation policy as the primary store, verified, not assumed | [98-secrets-keys-data-protection.md](98-secrets-keys-data-protection.md) |
| Storage/processing quota exhaustion from repeated report generation | An unthrottled "generate my report" button is a denial-of-wallet primitive against both compute and storage cost | Rate-limit and quota generation requests per tenant, same discipline as any other expensive endpoint | [43-unbounded-consumption.md](43-unbounded-consumption.md) |

Also worth a mention: partner-callback authentication treated as trusted-by-network-position instead of verified ([04-ssrf.md](04-ssrf.md)), backup restore paths tested as rarely as they're exercised, log files accumulating PII with no retention policy separate from application data, see [99-privacy-engineering.md](99-privacy-engineering.md).

## Recommended defaults by context

| Context | Recommended default | Why |
| --- | --- | --- |
| Public/low-sensitivity content | Object storage plus CDN, public-read on the bucket, high-entropy non-sequential keys, EXIF stripped, and origin isolation plus nosniff/Content-Disposition enforced at serve time | Cheapest at scale while closing the enumeration, metadata-leak, and same-origin-rendering gaps "it's just an avatar" thinking skips |
| Private/sensitive documents | Short-TTL presigned URLs scoped to the single object for high-volume paths, authenticated proxy for the tier needing a durable audit trail | A leaked presigned URL is a bearer credential bounded only by its TTL and any cache sitting in front of it; a proxy is bounded by continuous per-request authorization instead |
| System-generated/internal files | Async generation to storage with server-issued signed delivery, every fetch-by-URL and webhook-delivered path treated as an SSRF sink, high-entropy paths, scheduled deletion sweep | The generation pipeline is server-side request-making code that rarely gets reviewed as such, the exact gap the Capital One breach exploited<sup>[[12]](#ref12)</sup> |

## Migration path

Most systems start by serving everything, avatars and KYC documents alike, from the same bucket or local disk path with no distinction in access control, because that's the fastest thing to ship and the gap doesn't show up until a scanner or a pen test finds an unauthenticated document URL. The first migration step for private content is splitting storage by sensitivity tier before changing anything about how retrieval works, because a mixed bucket makes every later access-control fix apply unevenly across content that should never have shared a boundary in the first place.

Moving from an unsigned or long-lived-token retrieval path to short-TTL presigned URLs breaks any client that cached the old URL and expects it to keep working, so the safe sequence issues both URL shapes in parallel for a deprecation window before cutting the old one off, and instruments which clients are still hitting the legacy path before removing it. Teams push back on the TTL length specifically: product wants a URL that survives an email forward or a slow mobile connection, security wants minutes, and the resolution is usually a longer TTL for asynchronous delivery paths (email, exports) than for interactive in-app downloads.

For the tier that needs an authenticated proxy instead of a presigned URL, the migration is rarely a clean cutover, because routing file bytes through the app server changes a bandwidth and infrastructure cost line item platform teams notice immediately. Staging it behind a flag scoped to the highest-sensitivity document types first, rather than every document at once, lets the team validate the app server can actually absorb the bandwidth before committing the rest of the fleet to it.

None of the above touches objects already sitting in storage under the old scheme, and that backfill decision is where these migrations get genuinely expensive. Re-keying millions of existing sequential-keyed objects to high-entropy keys breaks every cached, emailed, or third-party-embedded URL pointing at the old key unless a mapping layer is kept indefinitely; stripping EXIF from years of accumulated public photos means reprocessing the whole bucket, not just new writes. Most teams end up choosing to apply the new scheme going forward only and accept a permanently mixed legacy tier, rather than backfill, and that choice deserves to be made explicitly rather than by default.

System-generated files are usually the last context a team hardens, because a scheduled export job or a partner webhook doesn't look like user input the way an upload form does. The first real step is auditing every fetch-by-URL and webhook-delivered code path for SSRF exposure and allowlisting destinations, because that's additive and low-risk compared to redesigning the generation pipeline itself. Encryption and key-rotation parity between backups and the primary store is usually the slower-moving piece, because it means re-encrypting an existing backup archive rather than just changing config for new writes going forward.

Across every context, the rollback shape stays the same: keep the legacy retrieval path live and monitored until the new one has run a full production cycle with no access-control regression, and gate the cutover behind a flag scoped per content type rather than one global switch.

## Interviewer probes

**When would you choose a presigned URL over an authenticated proxy for private document delivery?**

Mid: When you need to scale download bandwidth past what the app server can absorb and don't need a hard per-request audit trail.

Principal: A presigned URL hands the object store's own infrastructure the job of serving bytes, the right call for high-volume delivery where the app server would just become a bottleneck. It's the wrong call for the highest-sensitivity tier because the token, once issued, is a bearer credential nobody re-checks until it expires; an authenticated proxy re-authorizes and logs every request, at the cost of routing every byte through infrastructure you have to scale yourself. The real question is whether the workflow needs per-request revocation and audit strength, or whether TTL-bounded exposure is an acceptable tradeoff for the volume involved.

**A team says their public avatar bucket "doesn't need" AV scanning because it's not processing sensitive data. What's wrong with that reasoning?**

Mid: Sensitivity of the content and risk of the distribution channel are different things; a public upload endpoint is still a free, reputable-domain file host.

Principal: Attackers routinely abuse exactly this kind of feature, a public, unauthenticated, high-reputation-domain upload endpoint, to host malware or phishing payloads rather than to attack the app itself. Whoever downloads the hosted file bears the harm, and the app's domain reputation absorbs the blast radius when the file gets flagged. Scanning scope should be driven by the distribution risk of the serving surface, not the sensitivity classification of the content it happens to hold.

**What's the most commonly missed gap when a team migrates from local-disk file storage to S3?**

Mid: They carry over the access-control assumptions of "it's not in the webroot" without replicating them as an actual bucket policy.

Principal: Local disk storage often has an implicit boundary, the directory just isn't in the webroot, that nobody wrote down as an explicit rule. Moving to S3 without an explicit bucket policy and object-level access control frequently defaults to a broader-than-intended posture, especially when a "quick fix" makes a bucket public-read to unblock testing and the change never gets reverted. The migration should replace an implicit boundary with an explicit, reviewable policy, not just relocate the bytes.

**How does a preview or OCR pipeline reintroduce vulnerability classes upload validation already closed?**

Mid: XXE and RCE, if the pipeline parses an uploaded Office document or SVG, or shells out to an image/document converter, server-side.

Principal: Upload-time validation typically checks the file's type and whether it's dangerous to execute, but a preview or OCR pipeline runs a second, separate parsing step later, often on a different service, that the original validation review never covered. If that step resolves external entities or invokes a converter like ImageMagick or Ghostscript on untrusted input, the same file that passed upload validation cleanly becomes an XXE or RCE vector at preview-generation time, exactly what CVE-2016-3714 (ImageTragick) demonstrated at scale.<sup>[[8]](#ref8)</sup> Every downstream consumer of an uploaded file, not just the upload endpoint itself, needs the same threat-modeling pass and ideally runs in an isolated, credential-free worker.

**When is storage isolation stronger than prefix-based scoping (a dedicated bucket per tenant) actually worth it for file storage?**

Mid: Regulated or contractually-isolated tenants demanding physical separation they can independently verify.

Principal: A shared bucket with tenant-prefixed keys depends entirely on every code path enforcing the prefix boundary correctly, forever, the same fragility as an application-only tenant check on a database. A dedicated bucket or a bucket policy enforcing the prefix boundary at the storage layer turns a missed application check into a denied request instead of a leaked object. The cost scales with tenant count, so it's reserved for the tier whose contract or regulatory posture specifically requires it, the same logic that justifies database-per-tenant.

**What's commonly missed when a team adds a "process this file from a URL" feature, an avatar-from-URL import, say?**

Mid: SSRF, because the server is making a request to a URL the caller controls.

Principal: The feature is functionally identical to any other SSRF sink, a server-side fetch to an attacker-influenced destination, but it rarely gets reviewed as one because it's framed as a file-import feature rather than a network request. The fetch can reach internal metadata endpoints or internal services with no auth of their own, the exact mechanism that turned an SSRF finding into full S3 credential theft in the 2019 Capital One breach.<sup>[[12]](#ref12)</sup> Every URL-based import needs the same destination allowlisting and internal-range blocking as any other outbound-fetch feature, reviewed as an SSRF sink, not a file-upload feature.

**A retention policy says user documents get deleted after 90 days. Six months later, a document from month 2 is still recoverable. Where did the policy actually break?**

Mid: Probably backups, the primary object got deleted but a backup snapshot or a CDN cache still has a copy.

Principal: Deletion from primary storage is often the only thing the retention policy actually implements, and every derived or replicated copy, backups, CDN edge caches, search indexes, a preview thumbnail generated at upload time, needs its own deletion trigger tied to the same clock, a minimization obligation GDPR Article 5 makes explicit rather than optional.<sup>[[10]](#ref10)</sup> Verifiable deletion has to cover every location the data was copied to, not just the record marked deleted in the primary table. The fix is enumerating every derived copy a document creates at the point the retention policy is designed, not discovering them one at a time during an audit.

## Sources

<a id="ref1"></a>[1] MITRE. CWE-330: Use of Insufficiently Random Values. https://cwe.mitre.org/data/definitions/330.html

<a id="ref2"></a>[2] MITRE. CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer. https://cwe.mitre.org/data/definitions/212.html

<a id="ref3"></a>[3] MDN Web Docs. X-Content-Type-Options header. Retrieved 2026-08. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options

<a id="ref4"></a>[4] OWASP. Secure Headers Project. Retrieved 2026. https://owasp.org/www-project-secure-headers/

<a id="ref5"></a>[5] Cloudflare. How to purge cache. Cloudflare Developer Docs. Retrieved 2026-08. https://developers.cloudflare.com/cache/how-to/purge-cache/

<a id="ref6"></a>[6] Amazon Web Services. Using presigned URLs. Amazon S3 User Guide. Retrieved 2026-08. https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html

<a id="ref7"></a>[7] Google Cloud. Signed URLs. Cloud Storage Documentation. Retrieved 2026-08. https://cloud.google.com/storage/docs/access-control/signed-urls

<a id="ref8"></a>[8] NIST NVD. CVE-2016-3714 (ImageTragick). May 2016. https://nvd.nist.gov/vuln/detail/CVE-2016-3714

<a id="ref9"></a>[9] Amazon Web Services. SaaS Tenant Isolation Strategies. AWS Whitepaper. Retrieved 2026-08. https://docs.aws.amazon.com/whitepapers/latest/saas-tenant-isolation-strategies/welcome.html

<a id="ref10"></a>[10] European Parliament and Council. General Data Protection Regulation (GDPR), Article 5. 2016. https://gdpr-info.eu/art-5-gdpr/

<a id="ref11"></a>[11] OWASP. File Upload Cheat Sheet. Retrieved 2026. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

<a id="ref12"></a>[12] Krebs, B. What We Can Learn from the Capital One Hack. Krebs on Security. August 2019. https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/

<a id="ref13"></a>[13] MITRE. CWE-409: Improper Handling of Highly Compressed Data. https://cwe.mitre.org/data/definitions/409.html
