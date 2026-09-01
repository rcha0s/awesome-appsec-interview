---
name: add-architectural-control
description: Create ONE new architectural-control doc for this repo (a design-checklist doc over one security-architecture decision, e.g. Authentication, Authorization, Secrets Management). Invoke when the user says "/add-architectural-control <topic>", "add an architecture control doc on X", or otherwise asks to add a new architecture-review-level comparison/design-checklist doc under docs/. Sibling to add-appsec-topic, not a replacement: that skill still owns every per-vulnerability and per-protocol deep dive. Runs a 4-agent pipeline (draft → parallel[correctness, interviewer, sources] → merge), writes ONE doc in the ADR-0003 shape, and updates README.md, mkdocs.yml nav, docs/index.md, the architecture-controls index, and bidirectional cross-links in the existing docs it cites.
---

# add-architectural-control

Adds ONE new architectural-control doc to the awesome-appsec-interview repo, matching the shape locked in [../../../docs/adr/0003-architectural-control-doc-shape.md](../../../docs/adr/0003-architectural-control-doc-shape.md) and the glossary entry in [../../../CONTEXT.md](../../../CONTEXT.md). Sibling to [../add-appsec-topic/SKILL.md](../add-appsec-topic/SKILL.md): that skill produces per-vulnerability/per-protocol deep dives in the ADR-0001/0002 shape; this one produces the design-checklist layer above them. Reserve this skill for single-doc adds. For multi-doc runs, author a Workflow script directly.

## What this skill produces

- One markdown file at `docs/NN-<slug>.md` where `NN` is the next available two-digit number in the docs directory (same flat numbering as `add-appsec-topic`, no new subdirectory).
- Opener: `#` title on line 1, blockquote mental-model paragraph on line 3 grounding the topic in its established first-principles framework by name (not paraphrased: authentication's three factors per NIST SP 800-63B, authorization's RBAC/ABAC/ReBAC access-control models, encryption's CIA triad and Kerckhoffs's principle, etc.), stating what decision this control governs, why it forks by context, and the single biggest thing a Principal reviewer checks for, then `**Interview frequency:** Core | Common | Situational | Niche`.
- `## Where this decision forks`: states the decomposition axis this topic actually forks on (deployment surface, environment/lifecycle stage, actor type, or another axis — topic-dependent, never assumed).
- One `### <context>` subsection per fork, each with an options table (`Option | Best for | Avoid when | Status (2026) | Deep dive`) and a design-considerations table for that context's sub-feature gaps (`Consideration | Why it matters | Design guidance | Deep dive`), **capped at 5-8 rows**: the highest-signal gaps only. Everything else worth a mention gets one compact closing line under the table instead of its own row (comma-separated, gap name plus a three-to-six word reason, linking to the deep-dive doc(s) that cover the rest).
- `## Recommended defaults by context` (compact table), `## Migration path`, `## Interviewer probes` (5-8 Q&A pairs, tradeoff- and gap-framed, Mid vs Principal answers), `## Sources` (HTML-anchored numbered entries).
- No `## How it works`, no `## Attack techniques`, no `## Defense`. Mechanism depth and defense-in-depth stay in the linked deep-dive docs; this doc never re-explains them.
- Design-guidance cells in the considerations tables are one line each: name the gap, why it matters, the shape of the right choice. Never a defense-in-depth paragraph, never an attack walkthrough.
- Every internal doc-link resolves to a real file. Bidirectional cross-links: each existing doc this doc cites gets a "See also" pointer back.

## Inputs

- **topic**: the architecture decision, e.g. "Authentication", "Secrets Management", "Session Management". Required. Name the decision, not one mechanism ("Authentication," not "Passwords vs Passkeys").
- **scope brief**: 3-8 sentences on what to cover: the realistic options worth comparing, the sub-feature gaps known to matter (e.g. for Authentication: password reset, forgot-password, remember-me, MFA recovery), and any existing docs known to be relevant. If the user did not provide one, offer to draft one from the topic name and pause for approval. Highest-leverage input, same as `add-appsec-topic`.
- **decomposition axis** (optional): the fork this topic's security profile actually diverges across, e.g. `deployment-surface` (web/mobile/desktop-native/service-to-service), `environment-lifecycle` (dev/CI-CD/production), `actor-type` (human-facing/service-to-service), `deployment-target` (application config/infrastructure). If omitted, the draft agent infers it and states it explicitly in the doc's "Where this decision forks" section. Do not force every topic through the same four buckets.

## Preconditions

- Working directory is or is inside the repo. Confirm with `git rev-parse --show-toplevel` and check the remote is `rcha0s/awesome-appsec-interview`. Bail if not.
- `docs/` exists.

## Steps

### 1. Pick the doc number

```bash
next=$(ls docs/ | grep -E '^[0-9]{2}-' | awk -F- '{print $1}' | sort -n | tail -1)
echo $((next + 1))
```

Pad to two digits. If it would exceed 99, ask the user how to renumber; do not overwrite.

### 2. Generate the slug

Lowercase kebab-case of the topic. Ask the user if the slug is odd; otherwise proceed.

### 3. Confirm the scope brief and decomposition axis with the user

If they gave a full brief, echo it back for confirmation. If they gave a topic name only, propose a scope brief (3-8 sentences: realistic options, known sub-feature gaps, likely decomposition axis) and pause for approval.

### 4. Gather the existing docs this topic should link to

Grep `docs/` and the README Index for the topic and its known sub-mechanisms (e.g. for Authentication: search for "password", "MFA", "WebAuthn", "SSO", "SAML", "OAuth", "JWT", "session", "mTLS", "token exchange", "SPIFFE"). Build an explicit list of `docs/NN-slug.md` filenames and titles. Pass this list into the workflow so the draft agent links to real files instead of inventing plausible-sounding ones — this is the one failure mode unique to a link-out-heavy doc type, and the sources verifier checks every link against this same list.

### 5. Run the Workflow

Call `Workflow`. Script template below. Same 4-agent pipeline as `add-appsec-topic`: draft (high, default model) → parallel [correctness (high), interviewer (high, opus), sources (high)] → merge (medium). Merge is the only agent that writes to disk.

### 6. Post-run checks

After the workflow returns, verify:

- File exists at `docs/NN-<slug>.md`.
- Line 1 is `# <title>` and line 3 starts with `> ` (blockquote mental model), and that blockquote names the topic's real first-principles framework (not a paraphrase or an invented one) before anything else. `**Interview frequency:**` line follows.
- No sentence anywhere in the doc states a diagram was considered, included, or omitted. That call belongs only in the merge agent's own response to you, never in the shipped file.
- `## Where this decision forks` states an explicit axis in its opening sentence.
- Prose paragraphs stay short (2-4 sentences) and don't restate the mental-model blockquote in different words. If a paragraph in "Where this decision forks" or a context's opening reads like the blockquote said again more slowly, push back and ask for a tighter pass.
- Any run of 3+ parallel, independent short paragraphs (not a worked example) got converted to a bulleted list with bold lead-ins. No section opens with a sentence describing its own format instead of its first real point.
- No prose paragraph runs past 5-6 sentences. Table cells are exempt (they're already dense by design); this check is for the blockquote and the prose in "Where this decision forks" and each context's opening only.
- At least two `### <context>` subsections exist (a doc that doesn't fork at all is not this doc type; push back and ask whether it should be a regular `add-appsec-topic` doc instead).
- Every `### <context>` subsection has both an options table and a design-considerations table with the exact headers specified in the shape spec.
- Every design-considerations table has 5-8 rows, not more. If a context genuinely needs more coverage, the excess belongs in the compact closing line under the table, not additional rows. A table over 8 rows is the specific failure mode that prompted this cap; push back and re-run merge with an explicit row-count directive if any table exceeds it.
- Each `### <context>` subsection has a compact closing line after its design-considerations table naming any other sub-feature gaps worth a mention that didn't make the table, each in a few words with a link, not a full sentence per gap.
- No `## How it works`, `## Attack techniques`, or `## Defense` sections exist. If any do, the draft regressed toward the other doc shape; re-run merge with an explicit fix directive.
- Every design-guidance table cell is one line. Flag and re-run merge if any cell has expanded into multi-sentence defense-in-depth prose or an attack explanation, the discipline this whole shape depends on.
- `## Recommended defaults by context`, `## Migration path`, and `## Interviewer probes` (5-8 Q&A, each with Mid and Principal) all exist.
- `## Sources` exists with numbered `<a id="refN"></a>[N] ...` entries; inline refs are all `<sup>[[N]](#refN)</sup>`.
- Every internal `docs/NN-slug.md` link in every table resolves to a real file (cross-check against the list from step 4 and `ls docs/`).
- No em-dashes in body prose. No inline author-name attributions.
- Line count is roughly 160 to 260, scaling with context count. Check content coverage directly rather than treating length alone as a quality signal.

If any check fails, surface it to the user with the exact line ranges and offer to re-run merge with a specific fix directive.

### 7. Update indexes and cross-links (mandatory, same commit)

Unlike `add-appsec-topic` (which only updates README.md), this skill updates all of the following in the same commit, per the `CONTEXT.md` Repo rules:

- **README.md**: add a row to the section table that best fits, or a new "Architectural controls" section if this is the first entry.
- **mkdocs.yml**: add the doc to the `Architectural Controls` nav section (create the section, placed right after `Home` and before `Injection`, if this is the first architectural-control doc).
- **docs/architecture-controls/index.md**: add the doc to the landing page's list (create the landing page, following the pattern of `docs/ai/index.md` etc., if this is the first one).
- **docs/index.md**: add or update the "Topics" table row for Architectural Controls.
- **Bidirectional cross-links**: for each existing doc the new doc links to (per step 4's list), add a short "See also" pointer back to the new doc, near that doc's mental model or in its Sources context, whichever reads naturally. A one-way link is a dead end for a reader who lands on the older doc first.

Do not skip this step and do not defer any part of it to a follow-up commit.

## Workflow script template

Substitute `<NN>`, `<slug>`, `<title>`, `<axis>`, `<scope>`, `<repo>`, and `<existing-docs>` before invoking. `<repo>` is the absolute path from `git rev-parse --show-toplevel` in Preconditions; do not hardcode a path from a prior invocation or a different machine. `<existing-docs>` is the list gathered in step 4, formatted as `NN-slug.md: Title` lines.

```javascript
export const meta = {
  name: 'add-architectural-control-<NN>-<slug>',
  description: 'Add one new architectural control doc: <title>',
  phases: [
    { title: 'Draft' },
    { title: 'Verify' },
    { title: 'Merge' },
  ],
}

const REPO = '<repo>'
const OUTFILE = `${REPO}/docs/<NN>-<slug>.md`

const SHAPE_SPEC = `
DOC SHAPE (per docs/adr/0003-architectural-control-doc-shape.md and CONTEXT.md's "Architectural control doc" glossary entry). This is a design-checklist doc over ONE security-architecture decision spanning several options and contexts, NOT a single-system deep dive. Every doc follows this shape EXACTLY.

Section order:
  1. \`#\` Title on line 1 (the decision, e.g. "Authentication," not one mechanism).
  2. Blockquote mental-model paragraph on line 3 (starts with '> ', 4-7 sentences): OPENS by naming the topic's established first-principles framework (authentication: something you know / have / are, per NIST SP 800-63B; authorization: RBAC/ABAC/ReBAC; encryption: the CIA triad and Kerckhoffs's principle; use the real framework for whatever the topic is, never invent one), then what decision this control governs, why it forks by context, and the single biggest thing a Principal reviewer checks for. A reader without the framework already in mind has nothing to hang the rest of the doc on; this is not optional.
  3. \`**Interview frequency:** Core | Common | Situational | Niche\` on its own line.
  4. \`## Where this decision forks\`: 3-5 sentences naming the decomposition axis this topic's security profile actually diverges across. Suggested axis: <axis>. Use it if it fits; if a different axis is truer to this specific topic, use that one instead and say so explicitly. Do not force every topic through deployment-surface (web/mobile/desktop/service-to-service) if that is not the axis that matters here.
  5. One \`### <context>\` subsection per fork named in step 4. Each contains, in order:
     a. A short paragraph: what's different about this decision in this context.
     b. An options table: \`| Option | Best for | Avoid when | Status (2026) | Deep dive |\`. Status is one of Preferred / Still common / Legacy / Emerging / Niche-but-required. Deep dive links to an existing repo doc from the EXISTING DOCS list below (never invent a filename).
     c. A design-considerations table for the security-relevant sub-features this context's option(s) drag along: \`| Consideration | Why it matters | Design guidance | Deep dive |\`. This is where gaps like password-reset, forgot-password, remember-me, MFA-recovery, credential-rotation-at-scale belong. "Design guidance" is ONE LINE: name the shape of the right choice (e.g. "single-use, ~15min TTL, invalidated on use"). It is NEVER a defense-in-depth paragraph and NEVER an attack explanation; both of those live in the Deep dive link.
        CAP THIS TABLE AT 5-8 ROWS. Pick the gaps a Principal-level interviewer would actually probe on or that materially change the design, not every conceivable sub-feature. A table beyond 8 rows becomes an unreadable wall, exactly the failure this shape exists to avoid.
     d. Immediately under the design-considerations table, one compact closing line naming any other sub-feature gaps still worth a mention that didn't make the table: comma-separated, each gap name plus a three-to-six-word reason, linking to whichever deep-dive doc(s) cover the rest. Not a sentence per gap, not a bullet list, one line. Example shape: "Also worth checking: cookie domain scope (avoid over-broad \`Domain=\`), idle vs. absolute session timeout, delegated admin access without credential sharing, see [Authentication and Session Management](12-authentication-session.md)."
  6. \`## Recommended defaults by context\`: a compact table \`| Context | Recommended default | Why |\`, the fast-skim answer.
  7. \`## Migration path\`: practical staged guidance for moving from a legacy default to the recommended one, per context where it differs meaningfully. What a rollout looks like, what breaks, what stakeholders push back on.
  8. \`## Interviewer probes\`: 5-8 Q&A pairs, mixing tradeoff framing ("when would you choose X over Y") and gap-probing framing ("what's commonly missed when..."). Each Q on its own bold or heading line. Each A has "Mid:" one-liner AND "Principal:" answer (2-4 sentences) naming the concrete reason or a real incident, not an assertion.
  9. \`## Sources\` (global numbered list, dense).

DOES NOT APPEAR IN THIS SHAPE:
  - No \`## How it works\`. Mechanism lives in the linked deep-dive docs.
  - No \`## Attack techniques\`. This doc compares options across contexts; it does not enumerate exploits.
  - No \`## Defense\` / Real fix / Defense in depth split. The design-considerations tables replace this at the right altitude.
  - No \`## Detection and telemetry\`. Per-mechanism, belongs in the linked docs.
  - No \`## Spec / RFC anchors\` standalone block, no \`## Interview-grade nuances\` bullet list (same removals as every other doc in this repo).

CLICKABLE REFERENCES:
  - Inline: \`<sup>[[N]](#refN)</sup>\` (superscript). Not bare \`[N]\`.
  - Sources entry: \`<a id="refN"></a>[N] Title. Venue. Date. URL.\`
  - Internal doc links in tables: plain markdown \`[NN-slug.md](NN-slug.md)\` or \`[Title](NN-slug.md)\`, must be one of the EXISTING DOCS listed below. Never invent a filename.

STYLE (writing-style skill rules, applied verbatim):

Sentence-level:
  1. No "Whether X or Y, ..." openers.
  2. No "The X? The Y." or "The X: The Y." Say "The X is Y" or cut the setup.
  3. No "It's more than X. It's Y." and no "Not X, Y." constructions. Just say Y.
  4. Three-item lists: ask if two items covers it. Vary structure across the doc.
  5. No general-then-colon-specifics. "Delivers where it counts: X and Y" becomes "Delivers X and Y."
  6. No purpose-clause endings ("... to help teams stay agile"). Cut them.
  7. Word swaps: "but" over "yet"; "because" or "so" over "since" unless temporal; cut "as a result", "this means", "consequently", "therefore".
  8. No em-dashes anywhere. Commas, periods, colons, or parens.
  9. No signposting labels: "Concretely,", "Bottom line:", "Net:", "Verdict:", "To be clear,", "In short,". Deliver the claim.
  10. No staccato-fragment emphasis ("Real. Not hypothetical."). Plain sentence.

Structural:
  11. AI-shaped paragraph (general opener + specific application + three-item list + em-dash summary): rewrite.
  12. Do not open a section with a warm-up generality. Start on the specific claim.
  13. Say the point, do not circle it. Do not talk about the point; be the point.
  14. Bulleted lists: if every bullet uses the same syntactic template (bold noun, colon, description), vary or convert to prose, or use a table instead (tables are the primary structure in this doc shape).
  15. Bold sparingly outside table cells.

Doc-specific:
  - No inline author names in prose. Sources entries name venue + URL.
  - Length: roughly 160 to 260 lines, scaling with context count (2 contexts lands nearer the bottom, 4 nearer the top). Revised down from an original 350-600 target set before the 5-8 row cap existed; once every table is properly capped and paragraphs stay short, a well-built doc naturally lands in this range. Do not pad to hit a higher number, and do not read a doc in this range as thin by default, check its actual content coverage instead.
  - Prose paragraphs in "Where this decision forks" and each context's opening (before its tables) stay short, 2-4 sentences, one idea each. This doc type is tables-first; long paragraphs here are exactly the kind of dense wall the tables exist to replace. Do not restate a claim the mental-model blockquote already made; each paragraph should add something the blockquote didn't cover, not re-explain it in different words.
  - Within "Where this decision forks" and each context's opening, when a section accumulates 3+ paragraphs that are each making one PARALLEL, independent point (not building on each other sequentially), convert those into a short bulleted list with a 3-6 word bold lead-in per bullet instead of leaving them as back-to-back paragraphs. A reader skimming several short paragraphs in a row loses the parallel structure between them; a bulleted list keeps it visible. The one exception: a worked example that contrasts two concrete scenarios (e.g. "a fintech signup flow vs. an internal admin console both land on different defaults") reads better as flowing prose and should stay a paragraph, not get bulleted into fragments.
  - No sentence anywhere describes what a section's format is or does ("The questions below mix X framing with Y framing because...", "This table compares..."). That is meta-commentary about the document, not content for the reader. Open directly on the first real point, table, or question.

CONCISENESS (applies to prose only, never to table cells, which are already dense by design):
  - Long, dense paragraphs get skimmed past by engineers, not read. This doc type is especially exposed to it: the topic is deliberately high-level, which tempts narrating every nuance in prose instead of trusting the tables to carry the comparison. If a paragraph exceeds roughly 5-6 sentences, split it or convert it to the structure that says the same thing faster (a bullet list, a table row, a shorter sentence). This does not relax citation-honesty, framework-grounding, or the row caps above; say the same substance in less space, do not cut substance to hit a length target.
  - The doc-specific rules above (short paragraphs, converting parallel-point paragraph runs to bulleted lists, cutting meta-commentary and blockquote restatement) are how this principle plays out concretely in this doc type's opener and context sections. Apply them together, not as a checklist to satisfy in isolation.

DIAGRAMS:
  - Optional, topic-dependent, same selectivity rule as add-appsec-topic. Include at most one \`\`\`mermaid diagram, in "Where this decision forks" or the first context subsection, ONLY if a single request-flow diagram annotated with where each option inserts would genuinely clarify faster than the tables alone. Most architectural-control docs skip the diagram; the tables ARE the primary visual structure of this doc type. Report the diagram call ("diagram: included/omitted, <reason>") as your OWN RESPONSE TEXT to the orchestrating task, never as a literal sentence inside the shipped document body. The reader of the published doc does not need to be told a diagram was considered and skipped; that line is process metadata, not content, and it must not appear in the doc itself, in any section, under any heading.
  - MERMAID GOTCHA: never put a semicolon (;) inside a node label, edge label, or Note text. Use a comma.
  - LAYOUT GOTCHA: 3+ unconnected sibling \`subgraph\` blocks lay out in one illegible row. Split into separate diagrams or force a grid with \`~~~\` rank-only links.
  - Do not set explicit background/text/theme colors in diagram source. The site's theming applies automatically.

CITATION HONESTY:
  - Never invent papers, CVEs, advisories, RFC clauses, arXiv IDs, CVE numbers. Must be accurate.
  - Never invent an internal doc filename. Every Deep dive link must be one of the EXISTING DOCS listed below.

EXISTING DOCS (link only to these for Deep dive columns; do not invent others):
<existing-docs>
`

const CORRECTNESS_CHARTER = `
ROLE: Correctness verifier.
Flag:
  - Unsourced technical claims in options/considerations tables lacking [N] ref where a specific fact needs one
  - Bare [N] not wrapped in <sup>[[N]](#refN)</sup>
  - Sources entries missing <a id="refN"></a> anchor
  - Wrong CVE, wrong OWASP mapping, wrong spec revision, wrong RFC clause
  - Author names in inline prose (style rule violation)
  - Any internal doc link (Deep dive column) that is not in the EXISTING DOCS list, or that points to a filename that does not plausibly exist
  - Diagrams that contradict text
  - Presence of removed sections: ## How it works, ## Attack techniques, ## Defense, ## Detection and telemetry, ## Interview-grade nuances, standalone ## Spec / RFC anchors
  - Design-guidance table cells that have expanded past one line into defense-in-depth prose or an attack explanation (the core discipline of this shape)
  - Fewer than two ### <context> subsections (this doc does not actually fork; flag as critical, it may not be the right doc type for this topic)
  - Missing options table or missing design-considerations table in any ### <context> subsection
  - Any design-considerations table with more than 8 rows (flag as high severity: excess rows belong in the compact closing line, not the table)
  - Missing compact closing line under any design-considerations table, OR a closing line that has expanded into multiple sentences/a bullet list instead of one line
Writing-style violations (writing-style skill rules 1-15, same list as add-appsec-topic):
  - Em-dashes anywhere in prose (rule 8; strongest AI tell)
  - "Whether X or Y," openers (rule 1)
  - "The X? The Y." or "The X: The Y." constructions (rule 2)
  - "Not X, Y." or "Not X. Y." constructions (rule 3)
  - Purpose-clause endings like "... to help teams stay agile" (rule 6)
  - "yet"/"as a result"/"this means"/"consequently"/"therefore"/"since" (temporal only) (rule 7)
  - Signposting labels: "Concretely,", "Bottom line:", "Net:", "Verdict:", "To be clear,", "In short," (rule 9)
  - Staccato-fragment emphasis ("Real. Not hypothetical.") (rule 10)
  - AI-shaped paragraphs (rule 11)
  - Section openings with warm-up generalities (rule 12)
  - Sentences that talk about the point rather than being the point (rule 13)
  - Bolding every 2-3 lines outside tables (rule 15)
Output STRICT JSON array. Each finding: {"line_or_section": <string>, "issue": <one sentence>, "severity": "critical"|"high"|"medium"|"low", "fix": <one sentence>}. Empty [] if none.
`

const INTERVIEWER_CHARTER = `
ROLE: Principal-appsec-interviewer verifier, for a design-checklist doc (not a per-vulnerability doc).
Every ### <context> subsection must give a Principal-level reader enough to answer "which option would you pick here, and what have you not thought about yet."
Every design consideration must be something a candidate could plausibly be probed on missing.

Opener check:
  - Blockquote mental model on line 3 names the topic's real first-principles framework by name before anything else (flag as critical if missing or invented), and states the fork and the core tension
  - Interview frequency tag present
  - ## Where this decision forks names an explicit, topic-appropriate axis (not a generic default applied without justification)
  - No sentence anywhere in the doc describes a diagram decision (included/omitted/considered); that is process metadata and must not appear in the shipped file
  - No prose paragraph merely restates the mental-model blockquote in different words

Shape check:
  - At least two ### <context> subsections, each with both required tables
  - No mechanism-explainer content: options tables state tradeoffs, not how each option works internally
  - Design-guidance cells stay one line; if a cell reads like a defense writeup, flag it

Recommended-defaults check:
  - ## Recommended defaults by context names concrete reasons or incidents, not just an assertion ("prefer X" with no "because")

Probe check:
  - Each Q&A pair has Mid AND Principal answer
  - At least some probes are gap-probing ("what's commonly missed when...") not just tradeoff-framed, since the sub-feature-gap coverage is the differentiator of this doc type
  - Principal answers name the concrete tradeoff, the gap, or the incident, not a generic restatement of the option's marketing pitch

Output STRICT JSON array. Each finding: {"section": <string>, "gap": <one paragraph>, "severity": "critical"|"high"|"medium"|"low", "suggested_addition": <one sentence>}. Empty [] if none.
`

const SOURCES_CHARTER = `
ROLE: Sources verifier, with an added internal-link-honesty duty unique to this doc type.
Flag:
  - Fabricated papers / advisories (invented arXiv, wrong CVE, invented titles)
  - Wrong dates on real works
  - Wrong RFC clause / RFC-to-topic mapping
  - Wrong OWASP mapping
  - URLs likely to 404
  - Missing Sources entry for a cited [N]
  - Missing <a id="refN"></a> anchor
  - Inline author names in prose
  - CRITICAL, checked against the EXISTING DOCS list passed in context: every internal Deep dive link in every table must be one of the listed files. Any link to a filename not on that list is a fabricated cross-reference and must be flagged as critical severity regardless of how plausible the filename looks.

Output STRICT JSON array. Each finding: {"citation": <exact text>, "issue": <one sentence>, "severity": "critical"|"high"|"medium"|"low", "fix": <one sentence>}. Empty [] if none.
`

const TOPIC = '<title>'
const AXIS = '<axis>'
const SCOPE = `<scope>`
const EXISTING_DOCS = `<existing-docs>`

const context = `${SHAPE_SPEC}\n\nTOPIC: ${TOPIC}\nDOC PATH: ${OUTFILE}\nSUGGESTED AXIS: ${AXIS}\nSCOPE:\n${SCOPE}\n\nEXISTING DOCS (link only to these):\n${EXISTING_DOCS}`

phase('Draft')
const draft = await agent(
  `${context}\n\nTASK: Produce the full markdown for ${OUTFILE}. Follow every rule above. Your response IS the file contents. Do NOT write to disk (merge is the only writer).`,
  { label: 'draft', phase: 'Draft', effort: 'high' }
)

phase('Verify')
const [correctness, interviewer, sources] = await parallel([
  () => agent(`${context}\n\n${CORRECTNESS_CHARTER}\n\nDRAFT:\n---\n${draft}\n---`,
    { label: 'verify:correctness', phase: 'Verify', effort: 'high' }),
  () => agent(`${context}\n\n${INTERVIEWER_CHARTER}\n\nDRAFT:\n---\n${draft}\n---`,
    { label: 'verify:interviewer', phase: 'Verify', effort: 'high', model: 'opus' }),
  () => agent(`${context}\n\n${SOURCES_CHARTER}\n\nDRAFT:\n---\n${draft}\n---`,
    { label: 'verify:sources', phase: 'Verify', effort: 'high' }),
])

phase('Merge')
const final = await agent(
  `${context}

TASK: Produce the FINAL markdown for ${OUTFILE}. Apply every valid finding. Re-verify the opener (title, blockquote mental model, Interview frequency tag, then ## Where this decision forks). Re-verify no ## How it works / ## Attack techniques / ## Defense / ## Detection and telemetry sections crept in. Re-verify every internal Deep dive link is in the EXISTING DOCS list. Re-verify inline refs are all <sup>[[N]](#refN)</sup>. Re-verify every design-guidance table cell is one line, not a paragraph.

Call the Write tool to write the final markdown to ${OUTFILE}. Return the full markdown as your response text as well, and state the decomposition axis used and why.

DRAFT:
---
${draft}
---

CORRECTNESS FINDINGS:
---
${correctness}
---

INTERVIEWER FINDINGS:
---
${interviewer}
---

SOURCES FINDINGS:
---
${sources}
---`,
  { label: 'merge', phase: 'Merge', effort: 'medium' }
)

return { final }
```

## Post-workflow: verify and offer next steps

Run the checks in step 6, then update indexes and cross-links (step 7, mandatory). Once both are done, ask:

- Commit the new doc AND all index/cross-link updates in one commit? (if yes, conventional-commit format: `feat(docs): add architectural control doc on <title>`; user is author of record; no co-author line; commit body lists which existing docs got a back-link)
- Add another architectural-control topic?

## Anti-patterns

- Never draft the doc directly in the main context. Every new doc goes through the 4-agent pipeline.
- Never let the doc regress toward the `add-appsec-topic` shape. No `## How it works`, `## Attack techniques`, or `## Defense` sections; those belong to the sibling skill.
- Never let a design-guidance cell expand into a defense-in-depth paragraph or attack explanation. One line, then link out.
- Never let a design-considerations table grow past 8 rows. Curate to the highest-signal gaps and push the rest into the compact closing line; exhaustive enumeration is what made the pilot doc unreadable and prompted this cap.
- Never invent an internal doc filename for a Deep dive link. If no existing doc covers something worth linking, say so in the design-guidance cell instead of fabricating a link.
- Never ship a new doc without updating README.md, mkdocs.yml nav, the architecture-controls index, docs/index.md, and bidirectional cross-links in the same commit.
- Do not commit without explicit user approval.
- Do not force every topic through a web/mobile/desktop/service-to-service fork; use the axis that's actually real for the topic.

## Failure modes

- **Workflow fails or a draft agent times out**: the run returns a partial result. Read the workflow's journal.jsonl before re-running; often the draft cached and only a verifier needs to retry.
- **Merge agent didn't write the file**: the notification will show a Write tool call missing. Manually write the returned `final` string to disk.
- **Fabricated internal doc link slipped through**: show the offending line to the user, offer to re-run merge with the correct EXISTING DOCS list re-emphasized or the claim dropped.
- **Doc doesn't actually fork (only one context makes sense)**: this topic may not need the architectural-control treatment; consider whether it should be a regular `add-appsec-topic` doc or a simpler single-context checklist instead of forcing an artificial second context.
- **Shape check fails (How it works / Attack techniques crept back in)**: the draft agent defaulted to the more familiar shape. Re-run draft with the SHAPE_SPEC's "DOES NOT APPEAR IN THIS SHAPE" block re-emphasized.
