# Audit Logging and Non-repudiation

> Audit logging exists to answer who did what, when, and whether they can deny it afterward, the non-repudiation property. Operational telemetry answers a different question, whether the system is healthy right now, and the two get conflated constantly because they both start life as a log statement. An audit record has to be attributable to a specific, individually identifiable actor, tamper-evident against after-the-fact edits<sup>[[15]](#ref15)</sup>, and retained for a defined period<sup>[[1]](#ref1)</sup>; operational logs, request traces, error dumps, performance counters, need none of that and get rotated out in days by default. This doc covers what counts as an audit trail, who write-protects it, and how long it survives, and that decision forks hard depending on who or what generated the action being logged. A Principal reviewer's first question is almost always the same: is this log a compliance artifact with retention and integrity guarantees behind it, or is it application debug output pressed into service as an audit trail because nobody built the real thing.

**Interview frequency:** Core

## Where this decision forks

The realistic controls, the review process, and the failure mode all differ by who or what is being audited, so that's the axis this doc uses rather than industry or data type. Routine human access to a resource needs consistent who/what/when/where coverage and a retention window long enough to matter. Privileged or break-glass access is usually legitimate and time-boxed, but nobody follows up on whether it was misused while it was active, which is a review problem more than a coverage problem. Automated or agent-driven actions run under a service account or an LLM-driven agent, and a standard web-request log throws away the argument detail needed to reconstruct what actually happened. Each fork gets its own options table and design-considerations table below.

### Human user access

Human access logging is the case most teams already do something for, but that something is often a web server or application log never designed to survive an audit request. Every access to a regulated or sensitive resource needs a consistent record, and the retention window comes from whatever regulation or contract governs the data, not from the team's log-rotation defaults. A healthcare portal and an internal admin panel both log user access, but HIPAA<sup>[[3]](#ref3)</sup> sets the portal's retention and turns its access-log review into a compliance obligation, while the admin panel's retention is a business call with a much shorter realistic shelf life. The reviewer question is whether the record was designed as evidence or exists only because a log statement happened to sit near the code path.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
|---|---|---|---|---|
| Append-only application logs | Early-stage products with low regulatory burden and no dedicated logging budget yet | The log is also writable by the same admins being audited, defeating the point | Still common | |
| Dedicated tamper-evident audit log (signed or hash-chained entries, separate write path) | Regulated data, internal admin tooling, payment or PII vaults where an audit request is a real possibility | The team has no capacity to run and monitor a second write path | Preferred | [87-tokenization.md](./87-tokenization.md) |
| Managed audit service (cloud-native, CloudTrail-shaped) | Cloud-native stacks already committed to one provider's control plane<sup>[[6]](#ref6)</sup> | Multi-cloud or on-prem estates the service doesn't reach uniformly | Preferred | |

A quick way to see the gap: an application log line reading `2026-02-14 09:12:03 GET /api/records/8842 200` tells a reviewer that a request happened and succeeded, nothing about who made it or what they saw. A well-formed audit record for the same event carries the actor's individual identity and authentication method, the resource ID, the action taken, a write-path timestamp, and a request ID for correlation<sup>[[5]](#ref5)</sup>, something closer to `actor=jdoe auth=sso+webauthn session=9f21 resource=record:8842 action=view ts=2026-02-14T09:12:03Z(audit-write) req=a7f3`. The second version can answer a repudiation claim; the first can't.

| Consideration | Why it matters | Design guidance | Deep dive |
|---|---|---|---|
| Attribution strength | A shared or generic login lets any user of that credential claim "that wasn't me," which defeats non-repudiation before the log format even matters<sup>[[10]](#ref10)</sup> | Require individual accounts for audited actions and log the authentication method and session ID alongside the actor | |
| Log integrity and tamper-evidence | A compromised admin account can edit its own trail if the log lives in the same writable store it audits<sup>[[11]](#ref11)</sup> | Append-only storage, hash-chain or sign entries, keep the write path separate from the audited system | [87-tokenization.md](./87-tokenization.md) |
| Verification and completeness | An unverified hash chain and a log source that quietly stops emitting events both look healthy from the outside | Run chain or signature verification on a schedule, alert on log-source absence rather than only on log content | |
| Time authority | A hash chain proves ordering relative to itself, not wall-clock accuracy, if the emitting client supplies the timestamp | Timestamp on the audit-store write path from a synchronized source, don't trust the emitting system's clock | |
| Keep sensitive data out of the log | Logging the record contents duplicates the exposure the audit exists to detect<sup>[[4]](#ref4)</sup> | Log the record ID and the action taken instead of the field values | |
| Retention tied to the actual requirement | Default log-rotation policies rarely match what a regulation<sup>[[7]](#ref7)</sup> or a contract<sup>[[2]](#ref2)</sup> demands | Set retention per data class from the applicable regulation or contract, not a platform default | |
| Log shipping to an independent destination | A log kept only on the system it audits can disappear in the same compromise it should have caught<sup>[[14]](#ref14)</sup> | Ship to a destination the primary system's compromise can't also reach | |
| Access-log review as a scheduled detective control | Logs nobody reads function as paperwork, not as a control<sup>[[9]](#ref9)</sup> | Put periodic review on a calendar, separate from real-time alerting | |

Other gaps worth a mention: log format drift across services (breaks correlation queries), missing correlation IDs (blocks tracing downstream effects), inconsistent actor-ID formats between systems (fails cross-system joins).

### Privileged and break-glass access

Break-glass access has to exist for real incidents, and that part is legitimate. The finding in most audits isn't that emergency access exists, it's that it's standing, broad, and nobody checks what was done with it afterward. Automatic expiry proves the access ended, not that anyone looked at what happened while it was active, and both questions need answering separately. Break-glass isn't limited to data access either, since an emergency KMS decrypt bypasses the same field-level controls a normal read would go through and needs the identical review discipline as a break-glass data grant.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
|---|---|---|---|---|
| No dedicated control (standing broad access, ad hoc grants) | Nothing; this is the finding a review is meant to surface | Never; flag it whenever it turns up in an access review | Legacy | |
| Just-in-time elevation with automatic expiry | Small teams starting to formalize break-glass with limited on-call reviewer capacity | Access is used to touch data no one ever later reviews | Still common | |
| Just-in-time elevation with automatic expiry plus mandatory post-hoc review | Regulated environments, incident-response tooling, any system with a named security owner | The team has no on-call reviewer capacity to close the loop within the review SLA | Preferred | [47-hitl-bypass.md](./47-hitl-bypass.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
|---|---|---|---|
| Justification required at request time | A grant with no stated reason can't be evaluated later, only guessed at from the surrounding incident | Require a free-text or ticket-linked reason before elevation is granted | |
| Automatic expiry | Standing elevated access is the most common break-glass finding in a security review | Time-box every grant, default measured in hours, not days | |
| Mandatory post-hoc review | Expiry proves the access ended, not that anyone checked what happened during it | Route every elevation to a reviewer queue with an SLA, not just a dashboard | [47-hitl-bypass.md](./47-hitl-bypass.md) |
| Key and decrypt access gets the same discipline as data access | Emergency decrypt of a KMS-protected field bypasses field-level controls entirely | Treat every emergency decrypt as its own break-glass event with its own review | [87-tokenization.md](./87-tokenization.md) |
| Append-only, signed grant and action logs | A privileged actor with standing access can otherwise edit their own trail<sup>[[8]](#ref8)</sup> | Signed or hash-chained entries, on a write path the elevated role can't modify | [47-hitl-bypass.md](./47-hitl-bypass.md) |
| Alerting on elevation, review on a cadence | Real-time alerts get ignored at volume; scheduled review is what closes the loop<sup>[[12]](#ref12)</sup> | Alert on grant, review on a weekly or monthly cadence regardless of alert volume | |
| Scope limited to the declared purpose | A grant issued for one query that carries full admin scope defeats the point of justification | Scope the elevation to the resource or action named in the request, not a blanket role | |
| Break-glass usage volume as its own metric | Frequent emergencies against the same resource usually mean the standing-access model is wrong | Track grant frequency per team and treat a rising trend as a design signal | |

Other gaps worth a mention: shared break-glass credentials (destroys individual attribution), out-of-band approval skipping justification (defeats the request-time control), review-queue backlog (defeats review in practice).

### Automated and agent-driven actions

Automated systems and agents act through service accounts or API keys, and generic application logging captures the endpoint hit and a status code, not the arguments that determined what actually happened. The log itself has to preserve enough fidelity to reconstruct a decision after the fact, not just confirm that an action occurred. High-volume automated traffic also rules out full manual review, so the realistic fallback is risk-weighted sampling rather than reviewing everything. An agent that can invoke arbitrary tools compounds the problem, since the identity that actually executed a call can drift from the identity the model believed it was calling.

| Option | Best for | Avoid when | Status (2026) | Deep dive |
|---|---|---|---|---|
| Generic application logging of tool calls | Low-risk, high-volume internal automation with no real-world side effects | Any action with real-world side effects, payments or data deletion | Legacy | |
| Structured per-tool-call trace logging with full argument capture | Agent and automation platforms handling sensitive actions at meaningful scale | Argument payloads carry secrets that can't be logged verbatim without redaction | Preferred | [32-agentic-ai-threats.md](./32-agentic-ai-threats.md) |
| Per-tool-call trace logging plus human-review sampling | High-risk agent actions: financial, destructive, or external-facing | The team has no reviewer bandwidth to act on sampled findings | Emerging | [32-agentic-ai-threats.md](./32-agentic-ai-threats.md) |

| Consideration | Why it matters | Design guidance | Deep dive |
|---|---|---|---|
| Full argument capture, not a summary | A summarized description can't be replayed or verified against what the tool actually received | Log the exact argument bytes passed to the tool call | [47-hitl-bypass.md](./47-hitl-bypass.md) |
| Attribution to the triggering identity | An agent acting on a user's behalf still needs a traceable actor, not just "system" | Carry the originating user or workflow ID through every downstream tool call | |
| Resolved tool and server identity, not the requested name | A drifted or shadowing tool can execute under a different identity than the one the model asked for | Log the resolved tool and server identity actually invoked | [52-mcp-cross-server-shadowing.md](./52-mcp-cross-server-shadowing.md) |
| Tool-definition version at call time | A tool that changed behavior after logging began makes past logs misleading | Log the tool definition hash or version alongside each call | [53-rug-pull-tool-drift.md](./53-rug-pull-tool-drift.md) |
| Human-review sampling on high-risk actions | Full manual review doesn't scale with agent call volume | Sample and review disproportionately by action risk, not uniformly | [32-agentic-ai-threats.md](./32-agentic-ai-threats.md) |
| Redaction discipline within full-fidelity traces | Full argument capture and never logging secrets pull in opposite directions<sup>[[13]](#ref13)</sup> | Log record IDs and argument structure, redact secret values within the trace | |
| Replay and retry markers on trace entries | A retried call logged as a fresh action inflates the record and hides the actual event sequence | Tag retries with the originating request ID so a reviewer can collapse them back to one action | |
| Trace retention aligned to the data it touches | An agent trace reaching regulated data inherits that data's retention obligation, not a shorter default | Set trace retention by the sensitivity of what the tool call touched | |

Other gaps worth a mention: uncaptured tool output (loses the outcome, not just the call), multi-agent handoffs dropping the original requester (breaks attribution at the boundary), high-volume trace storage cost (pushes premature sampling).

## Recommended defaults by context

| Context | Recommended default | Why |
|---|---|---|
| Human user access to regulated or sensitive data | Dedicated tamper-evident audit log, individual-account attribution, retention set by the governing regulation | Application logs alone rarely survive an audit request or a compromised admin account |
| Privileged and break-glass access | Just-in-time elevation, automatic expiry, mandatory post-hoc review on every grant | Expiry alone doesn't prove anyone checked what the access was used for |
| Automated and agent-driven actions | Structured per-tool-call trace logging with full arguments, risk-weighted human sampling | Generic logs lose the fidelity needed to reconstruct what an agent actually did |

## Migration path

Most teams start from the same place, application logs that were never designed as an audit trail doing the job anyway because nothing else existed. The first stage is an honest inventory, because "we already log every request" usually turns out to mean actor identity is inconsistent, resource IDs are missing on a third of events, and rotation runs at 30 days regardless of what the data actually requires.

For human access, the next stage separates the write path, standing up an append-only or signed store for anything touching regulated data and retiring the primary application log as the source of audit evidence. Engineering pushback lands here first, since it's a second system to run, and building it usually surfaces gaps: actions with no attributable actor, service accounts shared across features, that need code changes rather than log-config changes. Retention comes after, and it has to be a number compliance or legal states from the actual regulation or contract rather than an engineering estimate. Dashboards built against the old, shorter-lived format need rebuilding against the new store, and any process that quietly relied on rotation to control storage cost now needs an explicit policy instead. The safer rollback, if the new path leaves coverage gaps, is running both stores in parallel until the new one has a full retention cycle of verified coverage rather than cutting the old log off in one step.

For privileged and break-glass access, automatic expiry is nearly always the first control teams add, cheap to implement against an existing IAM system and uncontroversial to justify. Mandatory post-hoc review is the harder stage and the one most orgs stall on, since it needs a named reviewer with an SLA, and nobody wants to own a queue that grows every time someone else has an incident. On-call rotations built around grabbing standing access and going now have an extra step, and teams that measure incident response purely by time-to-mitigate push back because JIT elevation adds friction to that number even though it closes a real gap. This is also the step where a review most often finds the daylight between policy and practice, expiry in place, review never actually staffed, worth checking directly rather than assuming a JIT rollout is complete once expiry alone ships.

For automated and agent-driven actions, the migration runs in the opposite risk direction from the other two, needing to happen before agent scope expands past read-only actions rather than after. Retrofitting argument-level fidelity once an agent already has write access to production data is the expensive path, and stakeholders push back on the up-front cost because it looks like latency overhead with no visible payoff until the first incident that needs the trace to reconstruct what happened. Generic logging pipelines built for request/response pairs have no slot for structured tool-call arguments, so the trace format ends up as a new pipeline rather than an extension of the old one, and teams that already shipped agents on generic logging face a stretch where earlier actions simply aren't reconstructable.

Tooling matters as much as sequencing across all three contexts. Every migration above goes smoother when the new and old logging paths run behind a feature flag rather than cut over in one step, since a flag lets a team roll back one affected segment without an emergency deploy. Ownership matters just as much: the migrations that stall are the ones with no team accountable for finishing them, because audit logging touches every product team's data access but belongs fully to none of them without an explicit platform-security owner driving the cutover.

The signal that a migration stage is actually done is rarely a calendar date. For human access and break-glass, it's whether a real audit request or a real post-hoc review can be answered from the log without an engineer manually reconstructing events from application code. For agent actions, it's whether a sampled high-risk call can be replayed from its logged arguments alone. A stage that can't clear that bar isn't finished even if the dashboard says logging is on.

## Interviewer probes

**What's the actual difference between an audit log and an application log? Isn't it all just logging?**

Mid: An application log exists to help debug or monitor system health, while an audit log exists to prove who did something and when, so it needs guarantees the app log was never built for. The two often start from the same log statement, which is exactly how teams end up treating one as the other.

Principal: The gap shows up the first time a real audit request lands. Retention was set for storage cost rather than the applicable regulation, and there's no signature or hash chain proving nobody edited an entry after a suspicious event, so the trail fails both the retention test and the tamper-evidence test at the exact moment it's needed as evidence.

**You've got a tamper-evident audit log with signed entries. What's still missing?**

Mid: Whether the log itself contains sensitive data that shouldn't be there in the first place. Signing proves entries weren't edited after the fact; it says nothing about what was written into them.

Principal: The failure that shows up in reviews is logging the full record, a customer's SSN, a payment card number, instead of the record ID and the action taken, which turns the audit log into a second copy of the data it's supposed to be protecting. A signed copy of a data breach is still a data breach, just a well-attested one.

**Your audit pipeline stops receiving events from one of forty services. How long until anyone notices, and what would make that automatic?**

Mid: Realistically nobody notices until someone goes looking for a specific event and it isn't there, unless there's active monitoring on the pipeline itself. A log that contains records looks healthy even when it's missing an entire source.

Principal: Audit failure is silent by construction, nothing breaks for users when logging stops, so detection has to be built deliberately: per-source heartbeat or canary events with alerting on absence rather than only on volume, scheduled hash-chain or signature verification instead of trusting the chain was never checked, and periodic reconciliation of logged sources against the current service inventory so a service that shipped six weeks ago and was never wired into the pipeline gets caught before an incident needs its trail.

**Break-glass access expires automatically after four hours. Is that sufficient?**

Mid: No, expiry only proves the access ended, not that anyone reviewed what happened during it. A grant can be used for exactly what it was justified for or for something else entirely, and expiry alone can't tell the difference.

Principal: The actual finding in most break-glass reviews is that grants expire cleanly but nobody's assigned to look at the access log afterward, so misuse during a valid window goes unnoticed until it surfaces somewhere else, usually a downstream incident that traces back to a break-glass session nobody ever checked.

**Full argument capture on every agent tool call roughly triples your log storage bill. What do you cut, and what do you refuse to cut?**

Mid: I'd cut full-fidelity logging on low-risk, read-only actions first and keep it on anything with a real-world side effect, since that's where the trace actually needs to survive a replay.

Principal: The cut has to be risk-weighted rather than uniform. Read-only lookups can drop to sampled full-fidelity logging with a summarized fallback for the rest, but anything financial, destructive, or externally visible keeps full argument capture and full retention regardless of cost, because that's precisely the action an incident review will need to replay byte-for-byte, and a summarized log at that tier is the gap that makes the whole trail worthless in the one case it exists for.

**Why would key or decrypt access need its own audit trail separate from data access logs?**

Mid: Because field-level encryption is often the last control standing between an attacker with data-layer access and the plaintext. If decrypt events aren't logged and reviewed, that last control has no detective backstop.

Principal: Anomalous decrypt volume from a service account, a spike outside its normal pattern, is one of the few detective controls that catches exfiltration through an otherwise-authorized path. That only works if every KMS decrypt is logged and reviewed, not just gated, since gating alone confirms the request was allowed, not that the allowed volume is normal.

**What's a realistic incident where good audit logging catches something a real-time alert misses?**

Mid: A privileged user pulling data gradually over weeks, staying under any single alert threshold each time. Real-time alerting tuned for spikes has no reason to fire on a pattern like that.

Principal: A scheduled access-log review comparing volume against a user's normal baseline is what actually catches slow exfiltration, because alerting answers whether something unusual just happened while review answers whether a pattern, taken as a whole, looks wrong over time. Teams that only wire up real-time alerting and treat review as optional consistently miss this class of incident until it surfaces downstream.

**Two teams both log "tool_call: get_customer_data" for an agent action. One team's logging is fine, the other has a real gap. What's the difference?**

Mid: Whether the logged tool name matches the tool that actually executed the call. If the log just echoes what the agent requested, it can be wrong.

Principal: The gap shows up when cross-server shadowing or a naming collision routes the call to a different implementation than the one requested, and the audit trail only records the name the agent asked for. The log looks complete, but it attributes the action to the wrong tool entirely, which is exactly the blind spot a malicious or drifted tool depends on to stay invisible in review.

## Sources

<a id="ref1"></a>[1] NIST SP 800-92. Guide to Computer Security Log Management. NIST. 2006. https://csrc.nist.gov/pubs/sp/800/92/final

<a id="ref2"></a>[2] PCI Security Standards Council. Payment Card Industry Data Security Standard (PCI DSS) v4.0, Requirement 10: Log and Monitor All Access to System Components and Cardholder Data. PCI SSC. 2022. https://www.pcisecuritystandards.org/document_library/

<a id="ref3"></a>[3] U.S. Department of Health and Human Services. HIPAA Security Rule, Audit Controls, 45 CFR § 164.312(b). HHS. https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html

<a id="ref4"></a>[4] OWASP Foundation. Logging Cheat Sheet. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

<a id="ref5"></a>[5] OWASP Foundation. Logging Vocabulary Cheat Sheet. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html

<a id="ref6"></a>[6] Amazon Web Services. AWS CloudTrail User Guide, Logging IAM and AWS STS API Calls. AWS. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/

<a id="ref7"></a>[7] European Union. General Data Protection Regulation (GDPR), Article 5(1)(e), Storage Limitation. 2016. https://gdpr-info.eu/art-5-gdpr/

<a id="ref8"></a>[8] NIST SP 800-53 Rev. 5. Security and Privacy Controls for Information Systems and Organizations, AU (Audit and Accountability) control family. NIST. 2020. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

<a id="ref9"></a>[9] Cloud Security Alliance. Cloud Controls Matrix, Logging and Monitoring (LOG) domain. CSA. https://cloudsecurityalliance.org/research/cloud-controls-matrix

<a id="ref10"></a>[10] NIST SP 800-63-4. Digital Identity Guidelines. NIST. 2025 (final publication date subject to verification against the current NIST catalog). https://pages.nist.gov/800-63-4/

<a id="ref11"></a>[11] International Organization for Standardization. ISO/IEC 27001:2022, Annex A.8.15, Logging. ISO. 2022. https://www.iso.org/standard/82875.html

<a id="ref12"></a>[12] AICPA. SOC 2 Trust Services Criteria, CC7.2 (System Operations, Monitoring). AICPA. https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services

<a id="ref13"></a>[13] OWASP Foundation. Application Security Verification Standard (ASVS) 4.0.3, V7 Error Handling and Logging. OWASP. https://owasp.org/www-project-application-security-verification-standard/

<a id="ref14"></a>[14] CISA, NSA, FBI, and international partners. Best Practices for Event Logging and Threat Detection. Joint cybersecurity guidance. 2024. https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection

<a id="ref15"></a>[15] MITRE ATT&CK. Technique T1070, Indicator Removal (including log tampering and clearing). MITRE. https://attack.mitre.org/techniques/T1070/
