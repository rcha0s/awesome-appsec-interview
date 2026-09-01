# Architectural Controls

Every other section in this site is a deep dive into one system or one vulnerability class. This section is different: each doc here is a design checklist over one security-architecture decision (Authentication, Authorization, Secrets Management, ...), the kind of decision a Staff or Senior security engineer actually walks through in an architecture review.

Each doc breaks its decision down by whichever context the security profile genuinely diverges across (deployment surface, environment/lifecycle stage, actor type, or another axis, stated explicitly per topic), enumerates the realistic options per context, names the modern default and why it's preferred now, and calls out the secondary features an option drags along that carry their own security considerations (password auth is never just "hash the password"; the reset flow, the forgot-password flow, and remember-me are separate design decisions with their own failure modes). These docs deliberately stay shallow on mechanism and attack detail. That depth already lives in the deep-dive docs elsewhere in this site, linked from every table here.

See [what "invariant" means in these docs](../index.md#what-invariant-means-in-these-docs) for the vocabulary the deep-dive docs use; the "Design guidance" column in these docs points at the same underlying invariants, one line at a time.

## Topics in this section

| Doc | Forks by | Focus |
|---|---|---|
| [Authentication](../96-authentication.md) | Deployment surface: web, mobile, desktop/native, service-to-service | Realistic options and modern defaults per surface, plus the sub-feature gaps each drags along (password reset, remember-me, MFA recovery, deep-link interception, credential rotation at scale) |
| [Authorization](../97-authorization.md) | Actor type: human-facing vs service-to-service | RBAC vs ABAC vs ReBAC, Zanzibar, policy engines, PDP/PEP placement, break-glass and policy drift |
| [Secrets, Keys, and Data Protection](../98-secrets-keys-data-protection.md) | Custody boundary: server/cloud, CI/CD, mobile, data at rest | The credential escalation ladder, HSM/TPM/TEE, envelope encryption, crypto-shredding, and the protocol axes (bearer vs proof-of-possession) that decide when storing a secret better beats eliminating it |
| [Privacy Engineering and Data Protection](../99-privacy-engineering.md) | Data lifecycle stage: collection, processing, retention | Data minimization, de-identification, LINDDUN's linkability/identifiability/inference, consent, and the retention-vs-deletion tension |
| [Audit Logging and Non-repudiation](../100-audit-logging.md) | Who or what is audited: human, privileged, automated | What must be logged, tamper-evidence, keeping sensitive data out of the log while auditing access to it, break-glass review |
| [Session Management](../101-session-management.md) | Deployment surface: web, mobile/desktop, service-to-service | Where the continuity proof lives and how it's revoked, deeper than Authentication's brief treatment |
| [Multi-Tenancy and Isolation](../102-multi-tenancy-isolation.md) | Isolation layer: data, compute, application | Why application-layer checks fail silently and data-layer isolation (RLS, per-tenant schemas, vector-store scoping) fails loudly instead |

More architectural control docs are planned; see the repo's `CONTEXT.md` and `docs/adr/0003-architectural-control-doc-shape.md` for the doc shape and the current backlog.
