---
name: add-appsec-topic
description: Create ONE new principal-level appsec revision doc for this repo. Invoke when the user says "/add-appsec-topic <topic>", "add a topic on X", "write a doc for Y", or otherwise asks to add a single new file under docs/ to the awesome-appsec-interview repo. Runs the same 4-agent pipeline (draft → parallel[correctness, interviewer, sources] → merge) that batch 1a/1b used, writes ONE doc to disk, and updates the README index if requested.
---

# add-appsec-topic

Adds ONE new topic doc to the awesome-appsec-interview repo, matching the current style bar exactly. Reserve this skill for single-doc adds. For multi-doc runs, author a Workflow script directly.

## What this skill produces

- One markdown file at `docs/NN-<slug>.md` where `NN` is the next available two-digit number in the docs directory.
- Depth-bar-compliant opener: wire-level example, invariants table (Invariant | Where enforced | How violated | Spec clause / source), spec / RFC anchors, mental model.
- Full body: how it works with mermaid diagrams, attack techniques (each with mechanism / payload / OOB confirmation / escalation), defense (real fix vs defense-in-depth split), detection and telemetry, interview-grade nuances, 5-8 interviewer probes (mid vs principal answers), optional war story, numbered `[N]` references in the Attack and Defense sections resolving to a global Sources list.
- No inline author names in prose. Sources entries are `Title. Venue. Date. URL.`

## Inputs

- **topic**: short human title, e.g., "SAML XSW", "WebAuthn passkeys", "GraphQL batching abuse". Required.
- **scope brief**: 3-8 sentences on what to cover, including named research, RFCs, OWASP mapping, CVEs, cross-links to existing docs. If the user did not provide one, offer to draft one from the topic name and pause for their approval before proceeding. This is the highest-leverage input; do not skimp on it.
- **shape** (optional): one of `attack-class | protocol | defense-standalone | defense-reference | infrastructure`. If omitted, infer from the topic. This shapes the emphasis (protocol docs need a handshake diagram; attack docs need an attack-chain flowchart; defense docs need before/after transformations).

## Preconditions

- Working directory is or is inside `/Users/risawe/Desktop/security/awesome-appsec-interview` (or wherever the repo lives). Confirm with `git rev-parse --show-toplevel` and check the remote is `rcha0s/awesome-appsec-interview`. Bail if not.
- `docs/` exists. If it does not, the target is wrong; bail.

## Steps

### 1. Pick the doc number

```bash
next=$(ls docs/ | grep -E '^[0-9]{2}-' | awk -F- '{print $1}' | sort -n | tail -1)
echo $((next + 1))
```

Pad to two digits. If the next number would exceed 99, ask the user how they want to renumber; do not overwrite.

### 2. Generate the slug

Lowercase kebab-case of the topic, stripped of stopwords and punctuation. Examples:

- "SAML XSW" → `saml-xsw`
- "WebAuthn passkeys" → `webauthn-passkeys`
- "GraphQL batching abuse" → `graphql-batching-abuse`

Ask the user if the slug is odd (e.g., includes a proper noun that could be shortened). Otherwise proceed.

### 3. Confirm the scope brief with the user

If the user gave a full brief, echo it back for confirmation and proceed. If they gave a topic name only, propose a scope brief (3-8 sentences) that names:

- OWASP / NIST / MITRE mapping (Web Top 10, API Top 10, LLM Top 10, Mobile Top 10, ASVS, ATLAS technique IDs)
- Named research or RFCs to cover (PortSwigger Research post, arXiv paper, spec revision)
- Cross-links to existing docs in this repo (list docs 01 through highest current, minus reserved numbers)
- What the shape emphasis should be (protocol wire-level, attack chain, defense trade-off)

Pause for their approval. Once approved, save it for the Workflow call.

### 4. Run the Workflow

Call the `Workflow` tool. Script template below. The pipeline is 4 agents: draft (high, default model) → parallel [correctness (high, default), interviewer (high, opus), sources (high, default)] → merge (medium, default). Merge is the ONLY agent that writes to disk.

### 5. Post-run checks

After the workflow returns, verify:

- File exists at `docs/NN-<slug>.md`
- Line count is 210 to 900
- Contains one `## Invariants` (or `## Invariant table`) section
- Contains at least one `mermaid` block
- Contains at least 8 numbered references in the Attack or Defense sections (`grep -c "^\[[0-9]" docs/NN-<slug>.md`)
- Contains no inline author-name attributions in Attack/Defense (grep for common surnames: Rehberger, Willison, Greshake, Goodside, Debenedetti, Carlini, Hines, Kettle, Heyes; author names in the Sources section itself are fine when they are the author's own domain like simonwillison.net)

If any check fails, surface it to the user with the exact line ranges and offer to re-run merge with a specific fix directive.

### 6. Update README (optional)

Ask the user if they want the README index updated. If yes, add the new doc under the appropriate section table with a one-line "Focus" description; if no obvious section fits, ask which section header to place it under.

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

const SHARED_HEADER = `
You are writing (or reviewing) ONE topic doc for a Principal-Security-Engineer-level appsec interview revision repo:
  https://github.com/rcha0s/awesome-appsec-interview
The doc will be committed to git alongside existing docs in ${REPO}/docs. Numbering continues from the existing set (01 through the current maximum in the docs directory).

REPO STYLE / TEMPLATE (order matters - technical density FIRST, prose commentary AFTER):

  1. Title (one line, no colon).
  2. Wire-level example: a code block or ASCII wire dump. For attack docs a real payload plus expected observation. For protocol docs the spec-defined message shape. For defense docs a before/after transformation.
  3. Invariants table with columns Invariant | Where enforced | How violated | Spec clause / source. 3-8 rows.
  4. Spec / RFC anchors: exact spec revision and clause / section number.
  5. Mental model: one paragraph, 4-7 sentences.
  6. How it works: mechanism at wire level. Every design element framed by the SECURITY REASON it exists. Mermaid diagrams here.
  7. Attack techniques enumerated. Each covers all four rubric elements: mechanism, payload/example, black-box + blind/OOB confirmation, escalation. Every citable claim gets a numbered inline reference [N] pointing to the Sources section.
  8. Defense ordered by effectiveness. Real fix vs defense-in-depth explicitly separated. Each defense states invariant, why it works, common wrong implementation, source. Numbered inline [N] refs.
  9. Detection and telemetry: log fields, alert shapes, canary shapes. Prose with URLs is fine here; no [N] required.
  10. Interview-grade nuances: 3-6 bullets on mid vs principal.
  11. Interviewer probes: 5-8 Q&A pairs, each with a mid-level answer and a principal answer that names mechanism, invariant, failure mode, defense trade-off, incident.
  12. War story: ONE real sourced incident with attacker steps + defender takeaway, only if a real one fits. Otherwise omit.
  13. Sources: global numbered list at bottom. Format: [N] Title. Venue. Date. URL. Author names OPTIONAL and only when the author IS the identifier (PortSwigger Research, OWASP Foundation etc.).

REFERENCE NUMBERING RULES (STRICT):
  - Inline [N] refs appear ONLY inside Attack techniques and Defense.
  - One global numbered list per doc. Same source cited N times reuses the same number.
  - Renumber dense (no gaps).
  - Every Sources entry has a resolvable URL. Prefer primary sources.
  - Avoid inline author-name attribution in prose. Say "the Spotlighting paper [3] reports" not "Hines et al. [3] report".

CITATION HONESTY:
  - Never invent a paper, CVE, or advisory. If uncertain, drop the claim.
  - RFC clauses, arXiv IDs, CVE numbers, MITRE ATLAS technique IDs (must use AML.T####), and OWASP mappings must be accurate.

WRITING RULES:
  - No em-dashes anywhere.
  - No "Not X, Y." or "The X? The Y." constructions.
  - No purpose-clause endings.
  - No warm-up generalities. Start on the specific claim.
  - "but" over "yet". Cut "as a result", "this means", "therefore".
  - Prose paragraphs of 2-4 sentences over stacked bullets. Bold sparingly.
  - Length: 300 to 900 lines. No filler.

DIAGRAM RULES:
  - Mermaid for sequence diagrams and flowcharts. No external images.
  - Protocol docs: at least one full-handshake sequence diagram with attack surface annotated.
  - Attack docs: one attack-chain flowchart end-to-end.
`

const CORRECTNESS_CHARTER = `
ROLE: Correctness verifier.
Find:
  - Unsourced technical claims in Attack/Defense lacking [N] ref
  - Wrong or outdated technical claims (misremembered CVE, wrong OWASP mapping, deprecated API, wrong spec revision, wrong RFC clause, wrong MITRE ATLAS ID, wrong arXiv ID)
  - Author names in inline prose (style rule violation)
  - Defense claims that do not enforce the invariant they say they enforce
  - Missing failure modes on defenses
  - Diagrams that contradict the accompanying text
  - Broken cross-references
Output STRICT JSON array. Each finding: {"line_or_section": <string>, "issue": <one sentence>, "severity": "critical"|"high"|"medium"|"low", "fix": <one sentence>}. Empty [] if none.
`

const INTERVIEWER_CHARTER = `
ROLE: Principal-appsec-interviewer verifier. Grill against this rubric:

For every attack technique all four required: mechanism, black-box confirmation, blind/OOB variant, escalation.
For every defense: invariant enforced, common wrong implementation, OWASP/NIST/MITRE source.
Every protocol element framed by the SECURITY REASON it exists.

Opener depth-bar check:
  - Wire-level detail first
  - Invariant table with 4 columns, 3-8 rows
  - Spec revision and clause anchored

Reference numbering check:
  - Attack and Defense sections have inline [N]
  - Sources has global numbered list
  - No inline author names in prose

Probe distinguishing signal:
  - Each Q&A pair has mid-level AND principal answer
  - Principal answer names mechanism, invariant, failure mode, defense trade-off, incident

Output STRICT JSON array. Each finding: {"section": <string>, "gap": <one paragraph>, "severity": "critical"|"high"|"medium"|"low", "suggested_addition": <one sentence>}. Empty [] if none.
`

const SOURCES_CHARTER = `
ROLE: Sources verifier. Fact-check every citation.
Flag:
  - Fabricated papers or advisories (invented arXiv IDs, wrong CVE numbers, invented titles)
  - Wrong dates on real works
  - Wrong RFC clause numbers or RFC-to-topic mappings
  - Wrong OWASP mapping (LLM01 vs LLM06 etc.)
  - Wrong MITRE ATLAS technique IDs (must use AML.T#### prefix)
  - Wrong spec revision
  - URLs likely to 404 based on domain or path shape
  - Missing sources on Attack/Defense claims (must have [N])
  - Inline author names in prose

Output STRICT JSON array. Each finding: {"citation": <exact text>, "issue": <one sentence>, "severity": "critical"|"high"|"medium"|"low", "fix": <one sentence>}. Empty [] if none.
`

const TOPIC = '<title>'
const SHAPE = '<shape>'
const SCOPE = `<scope>`

const context = `${SHARED_HEADER}\n\nTOPIC: ${TOPIC}\nDOC PATH: ${OUTFILE}\nSHAPE: ${SHAPE}\nSCOPE:\n${SCOPE}`

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

TASK: Produce the FINAL markdown for ${OUTFILE}. Apply every valid finding. Re-read for depth-bar compliance (wire-level opener, invariant table, spec anchor before prose, [N] refs in Attack/Defense, global numbered Sources list, no inline author names) and style compliance.

Call the Write tool to write the final markdown to ${OUTFILE}. Return the full markdown as your response as well.

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

Run the six checks in step 5. Report each result to the user. If everything passes, ask:

- Update the README index? (offer to add under the section that best fits)
- Commit the new doc? (if yes, use conventional-commit format: `feat: add doc NN on <title>`; user is author of record; no co-author line)
- Add another topic?

## Anti-patterns

- Never draft the doc directly in the main context. Every new doc goes through the 4-agent pipeline so the correctness / interviewer / sources verifiers get a shot.
- Never skip the invariant table or the wire-level opener. Those are the depth-bar signals; skipping them silently regresses the repo's quality.
- Do not write outside `docs/`. This skill produces one file only.
- Do not update the README without explicit user approval; the README is the reader's entry point and edits should be deliberate.
- Do not commit without explicit user approval, per this repo's git-workflow doctrine.

## Failure modes

- **Workflow fails or a draft agent times out**: the run returns a partial result. Read the workflow's journal.jsonl before re-running; often the draft cached and only a verifier needs to retry.
- **Merge agent didn't write the file**: the notification will show a Write tool call missing. Manually write the returned `final` string to disk.
- **Fabricated citation slipped through**: happens rarely. Show the offending line to the user, offer to re-run merge with a corrected sources list.
- **Depth-bar check fails**: line count under 210 usually means the topic scope was too thin; propose expanding the scope brief and re-running.
