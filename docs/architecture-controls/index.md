# Architectural Controls

Every other section in this site is a deep dive into one system or one vulnerability class. This section is different: each doc here is a design checklist over one security-architecture decision (Authentication, Authorization, Secrets Management, ...), the kind of decision a Staff or Senior security engineer actually walks through in an architecture review.

Each doc breaks its decision down by whichever context the security profile genuinely diverges across (deployment surface, environment/lifecycle stage, actor type, or another axis, stated explicitly per topic), enumerates the realistic options per context, names the modern default and why it's preferred now, and calls out the secondary features an option drags along that carry their own security considerations (password auth is never just "hash the password"; the reset flow, the forgot-password flow, and remember-me are separate design decisions with their own failure modes). These docs deliberately stay shallow on mechanism and attack detail. That depth already lives in the deep-dive docs elsewhere in this site, linked from every table here.

See [what "invariant" means in these docs](../index.md#what-invariant-means-in-these-docs) for the vocabulary the deep-dive docs use; the "Design guidance" column in these docs points at the same underlying invariants, one line at a time.

## Topics in this section

| Doc | Forks by | Focus |
|---|---|---|
| [Authentication](../96-authentication.md) | Deployment surface: web, mobile, desktop/native, service-to-service | Realistic options and modern defaults per surface, plus the sub-feature gaps each drags along (password reset, remember-me, MFA recovery, deep-link interception, credential rotation at scale) |

More architectural control docs are planned; see the repo's `CONTEXT.md` and `docs/adr/0003-architectural-control-doc-shape.md` for the doc shape and the current backlog.
