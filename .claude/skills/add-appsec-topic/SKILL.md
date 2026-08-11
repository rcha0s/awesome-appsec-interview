---
name: add-appsec-topic
description: Create ONE new principal-level appsec revision doc for this repo. Invoke when the user says "/add-appsec-topic <topic>", "add a topic on X", "write a doc for Y", or otherwise asks to add a single new file under docs/ to the awesome-appsec-interview repo. Runs the same 4-agent pipeline (draft → parallel[correctness, interviewer, sources] → merge) that batch 1a/1b used, writes ONE doc to disk emitting the ADR-0001 prose-first shape, and updates the README index if requested.
---

# add-appsec-topic

Adds ONE new topic doc to the awesome-appsec-interview repo, matching the locked format in [../../../CONTEXT.md](../../../CONTEXT.md) and [../../../docs/adr/0001-doc-format-prose-first.md](../../../docs/adr/0001-doc-format-prose-first.md). Reserve this skill for single-doc adds. For multi-doc runs, author a Workflow script directly.

## What this skill produces

- One markdown file at `docs/NN-<slug>.md` where `NN` is the next available two-digit number in the docs directory.
- The doc's opener is prose-first: `#` title on line 1, a blockquote mental-model paragraph on line 3, then `## Quick reference` (wire-level example + invariants table only).
- Full body: `## How it works` with `###` sub-headings and mermaid diagrams, `## Attack techniques` with `### N. <name>` per technique and prose-woven rubric (mechanism, payload, black-box + blind/OOB confirmation, escalation) with NO bolded sub-heads inside, `## Defense` split into `### Real fix` and `### Defense in depth`, `## Detection and telemetry`, `## Interviewer probes` (5-8 Q&A pairs with Mid vs Principal answers), optional `## War story`, and `## Sources` with HTML-anchored numbered entries.
- Attack and Defense sections carry clickable inline references as `<sup>[[N]](#refN)</sup>` resolving to Sources entries that open with `<a id="refN"></a>`.
- No inline author names in prose. No `## Interview-grade nuances` section. No standalone `## Spec / RFC anchors` block.

## Inputs

- **topic**: short human title, e.g., "SAML XSW", "WebAuthn passkeys", "GraphQL batching abuse". Required.
- **scope brief**: 3-8 sentences on what to cover, including named research, RFCs, OWASP mapping, CVEs, cross-links to existing docs. If the user did not provide one, offer to draft one from the topic name and pause for their approval before proceeding. This is the highest-leverage input.
- **shape** (optional): one of `attack-class | protocol | defense-standalone | defense-reference | infrastructure`. If omitted, infer from the topic. This shapes the emphasis (protocol docs need a handshake diagram; attack docs need an attack-chain flowchart; defense docs need before/after transformations).

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

### 3. Confirm the scope brief with the user

If they gave a full brief, echo it back for confirmation. If they gave a topic name only, propose a scope brief (3-8 sentences) naming OWASP/NIST/MITRE mapping, named research or RFCs to cover, cross-links to existing docs, and shape emphasis. Pause for approval.

### 4. Run the Workflow

Call `Workflow`. Script template below. The pipeline is 4 agents: draft (high, default model) → parallel [correctness (high), interviewer (high, opus), sources (high)] → merge (medium). Merge is the only agent that writes to disk.

### 5. Post-run checks

After the workflow returns, verify:

- File exists at `docs/NN-<slug>.md`.
- Line 1 is `# <title>` and line 3 starts with `> ` (blockquote mental model).
- `## Quick reference` section exists and contains a code block plus a markdown table with headers `Invariant | Where enforced | How violated | Source`.
- `## How it works` section exists with at least one mermaid block.
- `## Attack techniques` section exists with `### N. <name>` sub-headings and no `**Mechanism.**` / `**Payload.**` / `**Black-box confirmation.**` / `**Escalation.**` bolded sub-heads inside.
- `## Defense` section has both `### Real fix` and `### Defense in depth` sub-headings.
- `## Interviewer probes` exists with 5-8 Q&A pairs; each answer has a "Mid:" and "Principal:" component.
- `## Sources` exists with numbered `<a id="refN"></a>[N] ...` entries.
- No `## Interview-grade nuances` and no `## Spec / RFC anchors` sections.
- Inline refs in Attack and Defense are all `<sup>[[N]](#refN)</sup>` (no bare `[N]`).
- No em-dashes in body prose. No inline author-name attributions in Attack/Defense (surname mentions in the Sources section itself are allowed only when a domain is the identifier, e.g., simonwillison.net).
- Line count is roughly 250 to 700.

If any check fails, surface it to the user with the exact line ranges and offer to re-run merge with a specific fix directive.

### 6. Update README (mandatory)

Every new doc gets an entry in `README.md` in the same commit as the new file. The README is the reader's entry point; a doc that exists on disk but not in the index is invisible. Add a row to the section table that best fits the new doc, with a one-line Focus description. If no existing section fits, add a new section under an appropriate header and place the row inside it. Do not skip this step and do not defer it to a follow-up commit.

## Workflow script template

Substitute `<NN>`, `<slug>`, `<title>`, `<shape>`, and `<scope>` before invoking.

```javascript
export const meta = {
  name: 'add-appsec-topic-<NN>-<slug>',
  description: 'Add one new appsec topic doc: <title>',
  phases: [
    { title: 'Draft' },
    { title: 'Verify' },
    { title: 'Merge' },
  ],
}

const REPO = '/Users/risawe/Desktop/security/awesome-appsec-interview'
const OUTFILE = `${REPO}/docs/<NN>-<slug>.md`

const SHAPE_SPEC = `
DOC SHAPE (per ADR-0001 as amended by ADR-0002, see docs/adr/ and CONTEXT.md). Every doc follows this shape EXACTLY.

Section order:
  1. \`#\` Title on line 1.
  2. Blockquote mental-model paragraph on line 3 (starts with '> ', 4-7 sentences, states the root cause so an interviewer can quote it back). ONLY title and this blockquote appear before ## How it works.
  3. \`## How it works\` (mechanism / architecture / protocol). Uses \`###\` sub-headings where natural. Diagrams (mermaid) live here. Runs BEFORE Quick reference because the invariants table is easier to load after the reader has the architecture context.
  4. \`## Quick reference\` containing exactly (a) a wire-level example code block (real bytes / JSON / HTTP / protocol frame), then (b) the invariants table (columns Invariant | Where enforced | How violated | Source; 3-8 rows). Source column names the spec in plain text (URL lives in numbered Sources). Nothing else in Quick reference.
  5. \`## Attack techniques\`: enumerated with \`### N. <name>\` sub-headings. Each technique body is prose (2-4 short paragraphs) that WEAVES all four rubric elements without bolded sub-heads: mechanism, payload/example, black-box + blind/OOB confirmation, escalation. Do NOT use \`**Mechanism.**\`, \`**Payload.**\`, \`**Black-box confirmation.**\`, \`**Escalation.**\` bolded sub-heads.
  6. \`## Defense\`: split into \`### Real fix\` and \`### Defense in depth\` sub-headings. Numbered items within each cluster, ordered by effectiveness. Each states invariant enforced, why it works, common wrong implementation, source. Clickable [N] refs.
  7. \`## Detection and telemetry\` (log fields, alerts, canary shapes; prose; no [N] required).
  8. \`## Interviewer probes\`: 5-8 Q&A pairs. Each Q on its own bold or heading line. Each A has "Mid:" one-liner AND "Principal:" answer (2-4 sentences).
  9. \`## War story\` (optional).
  10. \`## Sources\` (global numbered list, dense).

REMOVED:
  - No \`## Spec / RFC anchors\` standalone block. Every spec citation lives inside numbered Sources.
  - No \`## Interview-grade nuances\` bullet list. Mid-vs-principal signal lives inside probes.

CLICKABLE REFERENCES:
  - Inline: \`<sup>[[N]](#refN)</sup>\` (superscript). Not bare \`[N]\`.
  - Sources entry: \`<a id="refN"></a>[N] Title. Venue. Date. URL.\`

STYLE:
  - No em-dashes. No inline author names in prose. No warm-up generalities. Prose over stacked bullets. Bold sparingly.
  - Length: 300 to 700 lines. No filler.

DIAGRAMS:
  - Mermaid only. Protocol docs: full-handshake sequence diagram with attack surface annotated. Attack docs: attack-chain flowchart end-to-end.

CITATION HONESTY:
  - Never invent papers, CVEs, advisories. RFC clauses, arXiv IDs, CVE numbers, MITRE ATLAS technique IDs (must use AML.T#### prefix) must be accurate.
`

const CORRECTNESS_CHARTER = `
ROLE: Correctness verifier.
Flag:
  - Unsourced technical claims in Attack/Defense lacking [N] ref (bare or clickable)
  - Bare [N] not wrapped in <sup>[[N]](#refN)</sup> inside Attack or Defense
  - Sources entries missing <a id="refN"></a> anchor
  - Wrong CVE, wrong OWASP mapping, wrong spec revision, wrong RFC clause, wrong MITRE ATLAS ID, wrong arXiv ID
  - Author names in inline prose (style rule violation)
  - Defense claims that do not enforce the invariant they claim
  - Missing failure modes on defenses
  - Diagrams that contradict text
  - Broken cross-references
  - Presence of removed sections (Interview-grade nuances, Spec / RFC anchors standalone)
  - Bolded rubric sub-heads inside Attack techniques
  - Missing Defense split into Real fix + Defense in depth
Output STRICT JSON array. Each finding: {"line_or_section": <string>, "issue": <one sentence>, "severity": "critical"|"high"|"medium"|"low", "fix": <one sentence>}. Empty [] if none.
`

const INTERVIEWER_CHARTER = `
ROLE: Principal-appsec-interviewer verifier.
Every attack technique must cover: mechanism, black-box confirmation, blind/OOB variant, escalation.
Every defense: invariant enforced, common wrong implementation, source.
Every protocol element framed by security reason it exists.

Opener check:
  - Blockquote mental model on line 3
  - ## Quick reference with wire example + invariants table (nothing else)
  - No standalone Spec / RFC anchors block

Reference-numbering check:
  - Attack and Defense sections use <sup>[[N]](#refN)</sup>
  - Sources has anchored numbered list

Probe check:
  - Each Q&A pair has Mid AND Principal answer
  - Principal answers name mechanism, invariant, failure mode, defense trade-off, incident

Output STRICT JSON array. Each finding: {"section": <string>, "gap": <one paragraph>, "severity": "critical"|"high"|"medium"|"low", "suggested_addition": <one sentence>}. Empty [] if none.
`

const SOURCES_CHARTER = `
ROLE: Sources verifier.
Flag:
  - Fabricated papers / advisories (invented arXiv, wrong CVE, invented titles)
  - Wrong dates on real works
  - Wrong RFC clause / RFC-to-topic mapping
  - Wrong OWASP mapping (LLM01 vs LLM06 etc.)
  - Wrong MITRE ATLAS IDs (must use AML.T#### prefix)
  - Wrong spec revision
  - URLs likely to 404
  - Missing Sources entry for a cited [N]
  - Missing <a id="refN"></a> anchor
  - Inline author names in prose

Output STRICT JSON array. Each finding: {"citation": <exact text>, "issue": <one sentence>, "severity": "critical"|"high"|"medium"|"low", "fix": <one sentence>}. Empty [] if none.
`

const TOPIC = '<title>'
const SHAPE = '<shape>'
const SCOPE = `<scope>`

const context = `${SHAPE_SPEC}\n\nTOPIC: ${TOPIC}\nDOC PATH: ${OUTFILE}\nSHAPE: ${SHAPE}\nSCOPE:\n${SCOPE}`

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

TASK: Produce the FINAL markdown for ${OUTFILE}. Apply every valid finding. Re-verify opener contract (title, blockquote mental model, ## Quick reference with wire + invariants only, then ## How it works). Re-verify Defense split into Real fix + Defense in depth. Re-verify inline refs are all <sup>[[N]](#refN)</sup>.

Call the Write tool to write the final markdown to ${OUTFILE}. Return the full markdown as your response text as well.

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

Run the checks in step 5, then update the README (step 6, mandatory). Once both are done, ask:

- Commit the new doc AND the README update in one commit? (if yes, conventional-commit format: `feat(docs): add doc NN on <title>`; user is author of record; no co-author line; commit body notes the README section that was updated)
- Add another topic?

## Anti-patterns

- Never draft the doc directly in the main context. Every new doc goes through the 4-agent pipeline so correctness, interviewer, and sources verifiers get a shot.
- Never skip the opener contract. Line 1 is title, line 3 is blockquote mental model, then Quick reference. Depth-bar regressions silently accumulate if the skill emits a different order.
- Do not write outside `docs/` and `README.md`. This skill produces one new doc plus one README entry.
- Never ship a new doc without updating README.md in the same commit. A doc that exists on disk but not in the index is invisible.
- Do not commit without explicit user approval.
- Do not reintroduce the removed sections (`## Interview-grade nuances`, standalone `## Spec / RFC anchors`).

## Failure modes

- **Workflow fails or a draft agent times out**: the run returns a partial result. Read the workflow's journal.jsonl before re-running; often the draft cached and only a verifier needs to retry.
- **Merge agent didn't write the file**: the notification will show a Write tool call missing. Manually write the returned `final` string to disk.
- **Fabricated citation slipped through**: show the offending line to the user, offer to re-run merge with a corrected sources list.
- **Depth-bar check fails**: line count under 250 usually means the topic scope was too thin; propose expanding the scope brief and re-running.
