# Privacy Engineering and Data Protection

> Security asks whether data stays confidential, intact, and available. Privacy asks a further set of questions that can stay open even when all three of those hold. LINDDUN names seven threat categories, linkability, identifiability, non-repudiation, detectability, disclosure of information, unawareness, non-compliance<sup>[[2]](#ref2)</sup>, and three of them drive most day-to-day architecture decisions: can two data points be tied to the same individual without either one alone being identifying (linkability), can a specific individual be singled out from a group (identifiability), and can a sensitive fact about someone be derived without ever directly observing it (inference, the practical face of non-compliance and disclosure risk together). This doc covers how an organization decides what personal data to collect, how to process and de-identify it, and when to delete it, and each decision forks hard depending on where in the data's lifecycle you're standing. A Staff reviewer checks first whether data minimization is enforced by the schema and the collection code path, or whether it exists only as a paragraph in a privacy policy nobody wired into the system.

**Interview frequency:** Common

*See also: [File Upload and Storage Security](103-file-upload-storage-security.md) for retention windows, deletion SLAs, and PII minimization applied to stored files and their derived copies (backups, caches, previews).*

## Where this decision forks

Privacy risk splits into three separate decisions with distinct failure modes depending on which point in the data lifecycle you're looking at. At collection, the mistake is capturing more than the feature needs because it's technically free to grab. At processing, the mistake is treating de-identification as a permanent, one-time transformation instead of a re-identification risk that shifts as auxiliary datasets grow. At retention, the mistake is architecting deletion as a database delete statement without accounting for the backups, replicas, and legal holds that keep the data alive anyway. This doc forks into three contexts along that axis: collection and minimization, processing and de-identification, and retention and deletion.

LINDDUN itself is a method, not just a vocabulary: it runs as a structured pass over a data-flow diagram, the same artifact a STRIDE threat model already needs, walking each data flow against the seven threat categories rather than reasoning about privacy in the abstract. Teams that already run STRIDE on a DFD can add a LINDDUN pass over the same diagram at a fraction of the setup cost, and the data-flow inventory that produces that DFD is also the first concrete step toward every control in this doc, referenced again in the migration path below.

### Collection and minimization

Every field a signup form or API accepts becomes a liability the moment it's stored, whether or not the product ever reads it back. The realistic failure here is an architecture that made minimization somebody's job to remember rather than something the schema enforces. Purpose-scoped collection ties every stored field to a declared purpose at write time, so a reviewer can ask what a field is for and get an answer from the schema rather than from institutional memory.

Consider a signup flow that needs an email for account recovery and a phone number only if the user opts into SMS alerts. A purpose-scoped schema stores each field with a `purpose` tag (`account_recovery`, `sms_alerts`) and a `consent_ref` pointing at the specific consent grant that authorized collecting it. A read path that wants to email a marketing campaign queries against the `marketing` purpose tag, finds nothing for a user who only granted `account_recovery`, and fails closed instead of silently reusing the recovery email. That failure-closed behavior is the actual architectural control; a privacy policy stating the same intent does nothing at query time.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
|---|---|---|---|---|
| Collect-everything-just-in-case | Nothing defensible in a regulated product | Any system touching PII, any GDPR/CCPA scope | Legacy | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |
| Purpose-scoped collection with explicit schema | Production systems handling PII, regulated data | Prototype stage where the purpose genuinely isn't known yet | Preferred | GDPR Art. 5(1)(c)<sup>[[8]](#ref8)</sup> |
| Progressive / just-in-time collection | Conversion-sensitive onboarding, mobile signup flows | Data is needed immediately for the core function (KYC, fraud checks) | Emerging | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |

| Consideration | Why it matters | Design guidance | Deep dive |
|---|---|---|---|
| Consent scope for a minor's own data | A minor's consent chain differs from an adult data subject's, and the age threshold varies by regulation | Store consent as a scoped grant keyed to the data subject, with a separate `authorized_by` field for a parent or guardian | GDPR Art. 8<sup>[[8]](#ref8)</sup>, COPPA<sup>[[14]](#ref14)</sup> |
| Delegated access beyond minors (guardianship, power of attorney) | An adult under guardianship or a deceased user's estate needs access without the underlying account credentials ever changing hands | Model delegation as its own grant type (grantor, delegate, scope, expiry) distinct from account ownership, and expire it explicitly rather than relying on someone to revoke it | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |
| Purpose limitation drift | Data collected for fraud checks quietly becomes a marketing segment feature, with nobody re-verifying consent | Reject a read outside its tagged purpose at the data-access layer instead of trusting the caller's stated intent | GDPR Art. 5(1)(b)<sup>[[8]](#ref8)</sup> |
| Analytics/ML training data provenance and consent scope | A model trained on data collected for one purpose can leak that scope into an unrelated product | Carry a consent-scope tag alongside every record that reaches a training pipeline, and check it at training time, not just at collection | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |
| Third-party data-sharing agreements and sub-processor visibility | A vendor's sub-processor nobody vetted can hold a copy of data the org promised to protect | Maintain a live sub-processor registry tied to each sharing agreement, not a one-time due-diligence PDF | GDPR Art. 28<sup>[[8]](#ref8)</sup> |
| Schema-enforced purpose tagging vs. free-text consent notices | A consent banner isn't an architectural control if the backend never checks it | Encode purpose and consent scope as first-class schema fields the write path validates, not prose in a policy | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |
| Consent re-verification cadence | A grant given years ago under one product surface may not cover a feature built later | Re-check consent scope against current purpose at the point of reuse, not only at original collection | GDPR Art. 5(1)(b)<sup>[[8]](#ref8)</sup> |

Other collection-time gaps worth a mention: cookie and pixel consent enforcement, marketing tags bypass consent; data-broker resale disclosure, do-not-sell attaches at collection; age-gating for children's data, COPPA turns on actual knowledge.

### Processing and de-identification

De-identification looks like a one-time transformation, but it functions as a risk assessment with a shelf life. The auxiliary data an attacker can join against grows every year, so a dataset safe to release in 2020 isn't automatically safe in 2026. A dataset headed to a researcher under a data-use agreement tolerates a different risk profile than one pushed to a public dashboard, and the technique should follow that distinction rather than a default. Tokenization solves an adjacent, narrower problem, replacing one value with a surrogate rather than de-identifying a dataset as a whole (see [Payment and PII Tokenization](87-tokenization.md)). Where de-identification fails, the result is the security-side failure mode of [information disclosure](21-information-disclosure.md), driven by a privacy decision instead of a broken access control.

Safe Harbor is a fixed 18-identifier removal list, but it's a two-prong test, not one. The second prong requires the covered entity to have no actual knowledge that the remaining information could identify an individual, even after every enumerated identifier is stripped<sup>[[4]](#ref4)</sup>. That second prong is where combinatorial risk still bites: a record recoded to "age 90 or older" per the rule, carrying a rare diagnosis code and a three-digit ZIP covering a sparse rural population, can still single out one person even though nothing on the enumerated list survives. The ZIP rule itself is narrower than it looks: the first three digits may be retained only where the corresponding geographic unit contains more than 20,000 people, and must be zeroed out otherwise<sup>[[4]](#ref4)</sup>.

Attribute inference is the threat category that k-anonymity alone doesn't touch. A k-anonymous equivalence class hides which specific person a record belongs to, but if every record in that class shares the same sensitive attribute, an attacker who narrows a target to the class still learns the attribute with certainty. l-diversity exists specifically to close that gap, requiring diversity in the sensitive attribute within each equivalence class rather than just group size<sup>[[7]](#ref7)</sup>. The same threat resurfaces against deployed models as membership inference (can an attacker tell whether a specific record was in the training set) and attribute inference against model outputs, which is a privacy harm with confidentiality fully intact, no breach, no unauthorized access, just a model that answers a question nobody meant to expose.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
|---|---|---|---|---|
| Safe Harbor enumerated-identifier removal | Fast disclosure of HIPAA-covered data under a known checklist | Dataset has rich free text, genomic data, or fine-grained geography and dates | Still common | 45 CFR § 164.514(b)(2)<sup>[[4]](#ref4)</sup> |
| Expert Determination | High-value or high-risk datasets where Safe Harbor's fixed list over- or under-redacts | No qualified statistician is available, or the process needs to repeat cheaply at scale | Niche-but-required | HHS de-identification guidance<sup>[[3]](#ref3)</sup> |
| k-anonymity / l-diversity (syntactic models) | Analytics datasets released to a bounded audience under a data-use agreement | Many quasi-identifiers push group sizes toward uniqueness (high-dimensional data) | Still common | k-anonymity<sup>[[5]](#ref5)</sup>, l-diversity<sup>[[7]](#ref7)</sup> |
| Differential privacy | Aggregate queries, ML training pipelines, repeated-query analytics systems | The privacy budget is exhausted, or small counts need to stay precise | Emerging | Differential privacy<sup>[[6]](#ref6)</sup> |
| Full anonymization | A public open-data release meant to exit regulatory scope entirely | Almost any other case: genuinely irreversible anonymization is rare and destroys most analytical utility | Niche-but-required | NIST SP 800-188<sup>[[10]](#ref10)</sup> |

| Consideration | Why it matters | Design guidance | Deep dive |
|---|---|---|---|
| Re-identification risk from linkage | De-identified data joined against a public or breached auxiliary dataset frequently re-identifies individuals | Treat de-identification as risk reduction, not elimination, and run a linkage-attack simulation before release | Linkage re-identification research<sup>[[11]](#ref11)</sup><sup>[[12]](#ref12)</sup> |
| Attribute and membership inference against models | A model's outputs or confidence scores can leak a training record's membership or a sensitive attribute with confidentiality fully intact | Test deployed models for membership-inference susceptibility before shipping, especially on small or unbalanced training sets | l-diversity<sup>[[7]](#ref7)</sup> |
| Differential-privacy budget exhaustion | Each query against a DP-protected dataset spends epsilon, and a spent budget cannot be reclaimed | Track cumulative epsilon spend per dataset and cut off queries once the budget is exhausted | Differential privacy<sup>[[6]](#ref6)</sup> |
| Data residency and cross-border transfer constraints | Processing a record outside its committed region can violate the transfer basis the consent was given under | Pin processing region at the pipeline level, not only at storage, and fail closed on cross-region calls | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |
| Logging and telemetry as an under-recognized egress path | Structured logs, APM traces, and third-party error trackers ship personal data off-platform without anyone deciding that on purpose | Scrub or tokenize PII fields before they reach the logging pipeline, not after | [Information Disclosure](21-information-disclosure.md) |
| De-identification technique revalidation as auxiliary data grows | A dataset safe under k-anonymity in 2022 can become linkable once new public datasets appear | Re-run the risk assessment on a fixed cadence, not only at initial release | NIST SP 800-188<sup>[[10]](#ref10)</sup> |
| Synthetic data as an alternative to de-identified real data | Synthetic records trained on real data can still memorize and leak outliers | Treat synthetic-data generators as a processing step needing their own re-identification review, not a free pass | [LLM Sensitive Information Disclosure](35-sensitive-info-disclosure.md) |

Other processing-time gaps worth a mention: quasi-identifier drift, new fields reopen a closed analysis; vendor analytics SDKs, third-party code sees raw PII first; small-cell suppression, aggregate reports can still leak outliers.

### Retention and deletion

Retention is the context where privacy engineering runs into a genuinely unresolved tension. A regulation can require keeping a financial record for seven years while a privacy deletion request demands removing it now, and the two obligations don't rank against each other cleanly. Backups compound this: a hard-deletion architecture built around one authoritative datastore breaks the moment nightly backups, read replicas, and a data warehouse each hold their own copy.

Crypto-shredding sidesteps the data-hunting problem by encrypting each erasure-eligible record or cohort under its own key and destroying that key on deletion, rather than locating and overwriting every copy of the ciphertext. A workable design gives each user (or each retention cohort, if per-user keys are too fine-grained) a distinct data-encryption key wrapped by a shared key-encryption key in a key management service. Deleting the user means deleting their wrapped DEK from the KMS; every backup, replica, and warehouse extract still holds the ciphertext, but none of them can decrypt it. This collapses if the backup system snapshots the KMS itself as part of its immutability policy, because restoring that snapshot restores the destroyed key alongside the ciphertext it was meant to orphan. There's no fully clean fix, only a design choice to exclude key material from the same immutability policy the ciphertext gets, and to version key destruction separately from data backup generations.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
|---|---|---|---|---|
| Time-based retention with hard deletion | Data with a clear, short-lived purpose and no long-tail legal hold | Backups or immutable storage make a true hard delete unverifiable | Still common | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |
| Crypto-shredding (destroy the key, not the data) | Encrypted-at-rest data spread across backups, replicas, and archives that are impractical to purge individually | Data was ever written unencrypted, or the same key protects records that must survive the shred | Preferred | NIST SP 800-88 Rev. 1<sup>[[13]](#ref13)</sup> |
| Anonymize-in-place | Records with lasting statistical or audit value but no ongoing need for individual identification | The anonymization step is itself reversible via linkage, which defeats the point | Still common | NIST SP 800-188<sup>[[10]](#ref10)</sup> |

| Consideration | Why it matters | Design guidance | Deep dive |
|---|---|---|---|
| Retention-vs-deletion legal tension | A regulator can compel retention at the same time a privacy law compels deletion | Document the conflict explicitly per data category instead of a default that silently favors one law | GDPR Art. 17(3)<sup>[[8]](#ref8)</sup> |
| Crypto-shredding key granularity | A shared tenant-wide key means shredding one user's key breaks every other record it protects | Issue erasure-eligible records or cohorts their own key from the start, never a shared key | NIST SP 800-88 Rev. 1<sup>[[13]](#ref13)</sup> |
| Immutable and write-once backups defeating crypto-shredding | A WORM backup or immutable snapshot can retain the encrypted blob and the key together, or the key in an unreachable backup generation | Exclude key material from ciphertext immutability policies, and track key-backup generations separately | NIST SP 800-88 Rev. 1<sup>[[13]](#ref13)</sup> |
| Right-to-erasure against derived and cached copies | Search indexes, CDN caches, and warehouse extracts routinely outlive the source record's deletion | Treat every downstream copy as its own deletion target with an SLA, tracked from the original erasure request | GDPR Art. 17<sup>[[8]](#ref8)</sup> |
| Data residency's interaction with disaster-recovery replication | A DR strategy replicating to a second region can violate a residency commitment the moment replication starts, not only on failover | Scope DR replication to residency-compatible regions before enabling it | NIST Privacy Framework<sup>[[1]](#ref1)</sup> |
| Consent withdrawal versus already-processed data | A withdrawal stops future processing, but doesn't retroactively invalidate processing that was lawful at the time | Record the withdrawal timestamp and gate only processing that happens after it | GDPR Art. 7(3)<sup>[[8]](#ref8)</sup> |

Other retention-time gaps worth a mention: litigation holds, they override deletion SLAs; data-warehouse snapshot sprawl, analytics teams keep untracked exports; backup restore testing, a restore can resurrect deleted keys.

## Recommended defaults by context

| Context | Recommended default | Why |
|---|---|---|
| Collection and minimization | Purpose-scoped collection with an explicit schema; progressive collection for non-essential fields | Enforces minimization architecturally and asks for optional data only when it's about to be used |
| Processing and de-identification | Expert Determination for regulated external releases; k-anonymity/l-diversity or differential privacy for internal analytics and ML pipelines | Safe Harbor's fixed list under-protects rich datasets, and syntactic models or DP degrade more gracefully as auxiliary data grows |
| Retention and deletion | Crypto-shredding as the default hard-delete mechanism, paired with per-cohort key issuance and key-backup exclusion; anonymize-in-place for records with lasting statistical value | Scales to backups and replicas without a per-request data-hunting project, though immutable backup policies still need explicit key exclusion to hold |

## Migration path

**Collection.** Start with a data-flow inventory across every datastore, log sink, and third-party integration, the same DFD a LINDDUN pass runs against, since nobody can minimize what they can't find. Retrofit purpose tags onto collection one form at a time after that. Engineering tends to push back here because it looks like busywork with no feature attached; framing it as unblocking future deletion requests, which product and legal both want, usually gets it prioritized.

**Processing.** Move de-identification from a one-time export script into a pipeline with a revalidation cadence. Data science pushes back here, because a tighter k-anonymity threshold or a smaller differential-privacy budget measurably reduces dataset utility, and that tradeoff needs a business owner rather than an engineering call made in isolation. Bring logging and telemetry into scope after the primary pipeline, and expect surprises: APM traces and third-party error trackers are often where a privacy review first finds raw PII leaving the platform, because nobody treated the logging pipeline as a data-processing system when it was set up.

**Retention.** Stand up crypto-shredding, with per-user or per-cohort keys, before the first deletion-at-scale request arrives. Retrofitting per-record keys onto an existing encrypted-at-rest system is a real migration, not a config change, and it's far cheaper before a regulator or a large customer demands proof of deletion. Legal is the stakeholder to bring in early here, not late, because the retention-vs-deletion conflict this doc calls unresolved needs someone with authority to pick a default per data category before the first live conflict forces an ad hoc call.

What breaks along the way: dashboards built directly against raw PII tables lose fields when minimization lands, ML pipelines trained on unscoped exports need retraining once provenance tagging arrives, and customer-support tooling that relies on full-record lookups needs a delegated-access path instead of a raw query.

## Interviewer probes

**When is purpose-scoped collection overkill, and when is collect-everything actually a defensible short-term choice?**

Mid: At the earliest prototype stage, before any real user's PII lands, collecting broadly on non-sensitive fields is fine if there's a concrete plan to formalize before production traffic arrives.

Principal: Every field added without a purpose tag becomes schema debt: something a later minimization pass has to reverse-engineer the reason for, and by the time real PII shows up nobody remembers why half the fields exist. Draw the line before the first real user's data lands, not before the first paying customer, because a design partner's data during a pilot is real PII under GDPR or CCPA the moment it's collected<sup>[[8]](#ref8)</sup><sup>[[9]](#ref9)</sup>.

**Safe Harbor de-identification versus Expert Determination, when do you actually need the more expensive option?**

Mid: Safe Harbor when the dataset matches the 18-identifier list closely, direct identifiers stripped, dates generalized, ages over 89 collapsed to a single category. Expert Determination when the dataset has dimensions the fixed list doesn't anticipate, free text, imaging, genomic data, or a small population where the remaining quasi-identifiers narrow to a handful of people.

Principal: Safe Harbor is mechanical by design, which makes it cheap and fast, but it also has a second prong that's easy to skip: the covered entity must have no actual knowledge that the remaining information could still identify someone<sup>[[4]](#ref4)</sup>. A record recoded to "90 or older" with a rare diagnosis code and a sparse-population ZIP satisfies every enumerated rule and can still be unique in practice, which is exactly the combinatorial risk Expert Determination is built to catch by modeling what a realistic adversary could link.

**How do you reconcile a data-retention regulation with an incoming right-to-erasure request for the same record?**

Mid: Neither obligation is satisfiable by deleting the row, so restrict rather than delete: mark the record erasure-requested and suppress it from every purpose except the one the retention law protects.

Principal: This needs a legal-hold flag plus purpose-based access restriction rather than actual deletion, and the harder part is deciding which regulation wins for which data category before the first request arrives. Deciding it live under legal pressure produces inconsistent answers across similar requests, and that inconsistency is itself a compliance finding waiting to happen.

**What's commonly missed when a team implements crypto-shredding as their deletion strategy?**

Mid: Backups. If the ciphertext and the key ride in the same backup generation, restoring the backup restores the ability to decrypt the record that was supposedly deleted.

Principal: The deeper miss is key granularity. Shared tenant-wide or table-wide keys make shredding one user's key impossible without also breaking every other record that key protects, so crypto-shredding only works if key issuance was designed per record or per cohort from the start. Immutable or WORM backup policies make this worse, retaining key material under the same immutability rule as the ciphertext and defeating the shred even when key granularity was done right. There's no fully clean answer, only tradeoffs between operational complexity and how completely a "deleted" record actually is.

**Why is de-identified data still a privacy risk after Safe Harbor or k-anonymity has been applied?**

Mid: Linkage against an auxiliary dataset. A landmark study re-identified a large share of a supposedly anonymous movie-ratings dataset by joining it against public reviews on another site<sup>[[11]](#ref11)</sup>, and an earlier study re-identified a state governor's medical records by joining anonymized hospital discharge data against public voter rolls<sup>[[12]](#ref12)</sup>.

Principal: De-identification is a point-in-time risk assessment against a specific threat model of available auxiliary data, and both the target dataset's context and the auxiliary-data landscape keep changing. A technique adequate at release time can become inadequate purely because a new public dataset appeared, with zero change to the original release, which is why re-identification risk needs a revalidation cadence rather than a one-time sign-off.

**What does k-anonymity alone fail to protect against, and how does l-diversity address it?**

Mid: k-anonymity guarantees a record can't be distinguished from at least k-1 others in the same equivalence class, but it says nothing about the sensitive attribute inside that class.

Principal: If every record in a k-anonymous class shares the same sensitive value, an attacker who narrows a target down to the class learns the attribute with certainty even without identifying which row is theirs. That's a homogeneity attack, and it's a pure inference failure with linkability and identifiability both nominally protected. l-diversity closes it by requiring the sensitive attribute to take at least l well-represented values within each class<sup>[[7]](#ref7)</sup>, which is why the two are usually deployed together rather than k-anonymity alone.

**How does logging and telemetry undermine an otherwise solid privacy architecture?**

Mid: APM traces and structured logs often capture full request and response bodies including PII fields, and third-party error trackers ship stack traces containing user objects straight to a vendor nobody ever scoped into the data-processing inventory.

Principal: Logging pipelines usually get built by platform or SRE teams who don't think of themselves as building a data-processing system, so PII scrubbing never enters the design conversation the way it does for the primary datastore. The fix is treating log ingestion as a boundary needing the same field-level scrubbing and tokenization discipline as production data, not an exemption granted because it's "just for debugging," and it's the same disclosure surface [Information Disclosure](21-information-disclosure.md) covers on the security side.

**A data-residency commitment says EU data stays in the EU, then someone turns on cross-region disaster recovery. What breaks?**

Mid: The DR replica now holds a copy of the data outside the committed region the moment replication starts, regardless of whether failover is ever actually triggered.

Principal: Replication is the transfer, not the failover event, so the compliance question isn't about the org's intent to fail over, it's about whether data crossed the boundary the moment cross-region replication turned on. The fix is scoping DR to residency-compatible regions, EU-to-EU multi-region rather than EU-to-US, or building region-pinned DR that costs more to operate but keeps the residency commitment intact.

## Sources

<a id="ref1"></a>[1] NIST Privacy Framework: A Tool for Improving Privacy through Enterprise Risk Management, Version 1.0. National Institute of Standards and Technology. January 2020. https://www.nist.gov/privacy-framework

<a id="ref2"></a>[2] A Privacy Threat Analysis Framework: Supporting the Elicitation and Fulfillment of Privacy Requirements (LINDDUN taxonomy). Requirements Engineering, vol. 16, 2011. https://www.linddun.org

<a id="ref3"></a>[3] U.S. Department of Health and Human Services. Guidance Regarding Methods for De-identification of Protected Health Information in Accordance with the HIPAA Privacy Rule. November 2012. https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html

<a id="ref4"></a>[4] 45 CFR § 164.514(b)(2), HIPAA Privacy Rule, Safe Harbor de-identification method. https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514

<a id="ref5"></a>[5] k-Anonymity: A Model for Protecting Privacy. International Journal of Uncertainty, Fuzziness and Knowledge-Based Systems, 10(5), 2002. https://doi.org/10.1142/S0218488502001648

<a id="ref6"></a>[6] Differential Privacy. Proceedings of ICALP 2006, Springer LNCS 4052. https://doi.org/10.1007/11787006_1

<a id="ref7"></a>[7] l-Diversity: Privacy Beyond k-Anonymity. ACM Transactions on Knowledge Discovery from Data, 1(1), 2007. https://doi.org/10.1145/1217299.1217302

<a id="ref8"></a>[8] Regulation (EU) 2016/679, General Data Protection Regulation. Official Journal of the European Union, 2016. https://eur-lex.europa.eu/eli/reg/2016/679/oj

<a id="ref9"></a>[9] California Consumer Privacy Act, as amended by the California Privacy Rights Act. California Civil Code § 1798.100 et seq. https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=3.&part=4.&lawCode=CIV&title=1.81.5

<a id="ref10"></a>[10] NIST Special Publication 800-188, De-Identifying Government Datasets. National Institute of Standards and Technology, 2023. https://csrc.nist.gov/pubs/sp/800/188/final

<a id="ref11"></a>[11] Robust De-anonymization of Large Sparse Datasets. IEEE Symposium on Security and Privacy, 2008. https://doi.org/10.1109/SP.2008.33

<a id="ref12"></a>[12] Simple Demographics Often Identify People Uniquely. Carnegie Mellon University, Data Privacy Working Paper 3, 2000. https://dataprivacylab.org/projects/identifiability/paper1.pdf

<a id="ref13"></a>[13] NIST Special Publication 800-88 Revision 1, Guidelines for Media Sanitization. National Institute of Standards and Technology, December 2014. https://csrc.nist.gov/pubs/sp/800/88/r1/final

<a id="ref14"></a>[14] Children's Online Privacy Protection Act (COPPA), 15 U.S.C. §§ 6501–6506; implementing rule at 16 CFR Part 312 (Federal Trade Commission). https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa
