# Awesome AppSec Interview

A revision aid, not a tutorial. Each file under `docs/` is one topic aimed at a principal-security-engineer level interview reload. Content assumes deep prior knowledge and prioritises fast re-loading of technique-level detail over teaching from scratch.

## Language

**Doc**:
A single markdown file under `docs/NN-<slug>.md`. One topic per file. Not a tutorial and not a spec.
_Avoid_: Article, page, guide.

**Hub doc**:
A short overview doc that indexes deep dives on related topics (docs 30, 31, 32 are hubs). Still attack-shaped: it follows the same locked doc section order as every other doc.
_Avoid_: Umbrella, index.

**Architectural control doc**:
A design-checklist doc over one security-architecture decision (Authentication, Authorization, Secrets Management, ...), not one system. Breaks the decision down by whichever deployment context its risk profile actually diverges across (web / mobile / desktop-native / service-to-service, or another axis when that's the real one for the topic), enumerates the realistic options per context, and for each option surfaces both its top-level tradeoffs and the security-relevant sub-features it drags along (e.g. password auth's reset/remember-me/recovery flows) as concrete, high-level design guidance, not a full defense treatment. Links out to the existing deep-dive docs for attack mechanics and defense-in-depth instead of repeating them. Follows the shape locked in [docs/adr/0003-architectural-control-doc-shape.md](adr/0003-architectural-control-doc-shape.md), not the section order below, which applies to every other doc type. Never attack-shaped; never carries its own Attack techniques or Defense sections.
_Avoid_: Comparison doc, overview doc.

**Interview frequency**:
A tag every doc carries: Core (near-certain in any senior/staff appsec interview), Common (comes up often, not universal), Situational (depends on the role/domain matching), or Niche (real depth, rarely the actual focus). Defined here and mirrored in `README.md`'s Freq column and `docs/index.md`.

**Opener contract**:
The set of properties every doc's opening block must satisfy. Currently: title on line 1, blockquote mental-model paragraph immediately after, then `## Quick reference` with wire example and invariants table. Reviewer agents check this contract on every draft.
_Avoid_: Depth-bar, header spec.

**Mental model**:
A single paragraph of prose stating the root cause of the topic so an interviewer can quote it back. Rendered as a top-level Markdown blockquote (`>`) directly under the title, no sub-heading. 4-7 sentences.
_Avoid_: TL;DR, summary, executive summary.

**Quick reference**:
A `## Quick reference` section that follows the mental model. Contains exactly two elements: a wire-level example (code block) and an invariants table. Nothing else lives here.
_Avoid_: Overview, at-a-glance.

**Wire-level example**:
A code block showing real bytes / JSON / HTTP / protocol frames at issue. For attack docs a payload plus expected observation. For protocol docs the spec-defined message shape. For defense docs a before/after transformation.
_Avoid_: Snippet, sample.

**Invariants table**:
A 3-8 row markdown table with columns Invariant | Where enforced | How violated | Source. The Source column names the governing spec / RFC / OWASP artifact by name (URL lives in Sources via numbered ref). Highest-density surface in the doc.
_Avoid_: Rules table, requirements table.

**Attack technique**:
One enumerated attack under `## Attack techniques`, rendered as `### N. <name>`. The body is prose (2-4 short paragraphs) covering four elements woven in: mechanism, payload/example, black-box + blind/OOB confirmation, and escalation. No bolded sub-heads inside a technique.

**Mechanism**:
The exact state change or wire moment that makes an attack work. Not the attack's name or category.

**Escalation**:
What an attack reaches. RCE, ATO, cross-tenant access, data exfil, wallet drain. Every attack technique names one.

**Real fix**:
A defense that changes what the attacker can reach (invariant enforced). Every doc splits the Defense section into "Real fix" items and "Defense in depth" items, ordered by effectiveness within each group.
_Avoid_: Mitigation, control.

**Defense in depth**:
A defense that raises attacker cost or narrows blast radius without removing the reachability. Sits below "Real fix" in every doc.
_Avoid_: Compensating control, secondary.

**Interviewer probe**:
A Q&A pair under `## Interviewer probes`. Each Q is a rabbit-hole follow-up an interviewer might ask. Each A carries both a "Mid:" one-liner and a "Principal:" answer that names mechanism, invariant, failure mode, defense trade-off, and a real incident. Docs contain 5-8 probes. This replaces the earlier "Interview-grade nuances" section, which no longer exists.

**Sources reference**:
An inline numbered citation of the form `<sup>[[N]](#refN)</sup>` appearing only inside the Attack techniques and Defense sections. Every `[N]` resolves to a `## Sources` entry at the doc bottom with an HTML anchor (`<a id="refN"></a>`). Same source cited twice reuses the same number. Sources list is dense (no gaps) and entries follow `Title. Venue. Date. URL.` No inline author names in prose.

**War story**:
A single real, sourced incident with attacker steps and defender takeaway. Optional. Included only when a real incident fits the topic; omitted otherwise.

## Doc section order (locked)

Every doc follows this order:

1. `#` Title.
2. Blockquote mental-model paragraph.
3. `## How it works` (mechanism / architecture / protocol; uses `###` sub-headings where natural; diagrams live here). Runs before Quick reference because the invariants table is easier to load after the reader has the architecture.
4. `## Quick reference` (wire example, invariants table).
5. `## Attack techniques` (numbered `### N. <name>` sub-headings, prose bodies with woven rubric).
6. `## Defense` ("Real fix" cluster then "Defense in depth" cluster; numbered items with clickable `[N]` refs).
7. `## Detection and telemetry` (log fields, alerts, canary shapes; no `[N]` required).
8. `## Interviewer probes` (5-8 Q&A pairs).
9. `## War story` (optional).
10. `## Sources` (global numbered list with HTML anchors).

## Style rules

- No em-dashes anywhere in body prose.
- No warm-up generalities. Start on the specific claim.
- No purpose-clause endings ("... to help teams stay agile").
- Prose over stacked bullets. Bullets earn their place only for enumerable lists.
- No inline author names in prose. Sources entries name the venue / URL, not authors.
- Never invent a paper, CVE, or advisory. If uncertain, drop the claim.

## Repo rules

- Every commit that adds, removes, or renames a doc under `docs/` also updates `README.md` in the same commit. A doc that exists on disk but not in the index is invisible to the reader. This is not optional and does not get deferred to a follow-up.
- Before drafting a new doc, check whether the topic substantially overlaps an existing one (search the README Index and grep `docs/`). If it does, extend the existing doc instead of forking a near-duplicate. Two docs covering the same ground splits reader attention and the copies drift out of sync; one doc that covers it fully is the correct outcome.
- A new doc that relates to an existing one (shared mechanism, prerequisite, or attack that chains into another) gets cross-linked from both sides in the same commit: the new doc references the existing one, and the existing one is edited to reference the new doc back. A one-way link is a dead end for a reader who lands on the older doc first.
- A new doc also gets added to `mkdocs.yml`'s `nav:` tree in the same commit, not just `README.md`. The README is the GitHub entry point; the nav is the live-site entry point. Both need the doc or half the audience can't find it.

## Backlog (not yet scheduled)

- Real-fix Defense items often resolve to "use a library or a config flag" in practice. Consider a closing line per Defense section naming the concrete way to get there in one representative ecosystem (Python, matching the primary stack), not an exhaustive per-language survey, e.g. "pin `algorithms=` in `PyJWT`/`python-jose`, don't read `alg` from the token." Keep it to the single ecosystem so the docs don't rot as library versions and language choices shift.
