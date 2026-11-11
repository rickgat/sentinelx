# Breach Notification Runbook

> **Last reviewed:** 2026-06-13
> **Maintainer:** Chief Compliance Officer (`cco@sentinelx.example`) / Backup: General Counsel
> **Next review:** 2026-08-13 (bimonthly cadence due to regulatory drift)
> **Document owner:** Compliance + Legal + Security (tri-owned)
> **Classification:** Internal — Restricted (distribute only to named on-call rotations)

---

## 1. Purpose

This runbook governs SentinelX's response to a confirmed or suspected
**personal data breach** or **material security incident**, including how we
classify severity, who we notify internally on what clock, what we owe
regulators, what we owe customers, and how we communicate with media.

It is paired with:

- [Incident Response Runbook](./incident-response.md) for the technical
  response and the four canonical IR playbooks (P3-004: ransomware,
  data-exfil, credential-compromise, insider) that operationalise the
  NIST 800-61 lifecycle on the platform.
- [Disaster Recovery Runbook](./disaster-recovery.md) for events that
  are also DR scenarios (notably Scenario C — audit-chain tamper).
- [Compliance evidence runbook](../operations/compliance-evidence.md)
  for the **P1-004 evidence collector** that is the canonical source of
  audit-grade evidence preserved under WORM (S3 Object Lock COMPLIANCE
  mode, 7-year retention) and pushed to GRC via P2-009. Every breach
  triggers a forced evidence-collection run for the affected tenant —
  see §8.1 below.

If technical containment is the body, this runbook is the **clock**.

---

## 2. Definitions

| Term | Definition |
| --- | --- |
| **Personal data** | Any data that identifies or can identify a natural person, per GDPR Art. 4(1) and UU PDP (Indonesia) Art. 1(1). |
| **Sensitive data** | A subclass of personal data: health, financial, biometric, government ID, children's data, location. |
| **Security incident** | Any event compromising confidentiality, integrity, or availability of SentinelX systems. |
| **Breach** | A confirmed security incident involving unauthorized access, disclosure, alteration, or destruction of personal data. |
| **Suspected breach** | An incident where breach status is unconfirmed but plausible. **Treat as a breach until proven otherwise** for clock purposes. |
| **Affected data subject** | A natural person whose personal data is involved. |
| **Customer-affecting** | An incident that materially impacts customer data, regardless of personal-data status. |

---

## 3. Severity Classification

Severity is the join of **data class** and **scale**. The IC assigns severity
within 30 minutes of incident declaration. Severity can only be **upgraded**
from working-level — downgrade requires CCO + Security Director sign-off.

### 3.1 Data class

| Class | Examples |
| --- | --- |
| **D-Crit** | Authentication credentials, audit chain, encryption keys, customer regulated data (health, financial), children's data |
| **D-High** | PII linked to identity (name + email + address), behavioral profiles, internal security telemetry |
| **D-Med** | Pseudonymized PII, internal non-customer ops data |
| **D-Low** | Public marketing data, anonymized aggregates |

### 3.2 Scale

| Scale | Definition |
| --- | --- |
| **S-Mass** | ≥ 10,000 data subjects affected, or ≥ 1 enterprise customer's full tenant |
| **S-Mid** | 100–9,999 data subjects, or single high-value enterprise account |
| **S-Small** | < 100 data subjects |

### 3.3 Severity matrix

| | D-Crit | D-High | D-Med | D-Low |
| --- | --- | --- | --- | --- |
| **S-Mass** | **P0** | **P0** | **P1** | **P2** |
| **S-Mid** | **P0** | **P1** | **P1** | **P2** |
| **S-Small** | **P1** | **P1** | **P2** | **P2** |

### 3.4 Severity implications

| Severity | Internal notify clock | External notify clock | Status page | Media response |
| --- | --- | --- | --- | --- |
| **P0** | 1h (full exec) | Regulatory min (see §5) | Major Outage / Security | Active PR posture |
| **P1** | 4h (extended leadership) | Regulatory min, generally same as P0 | Degraded | Reactive PR |
| **P2** | 24h (security + compliance) | Only if regulator requires | Notice (optional) | None unless asked |

---

## 4. Internal Notification Matrix

The clock starts at **T0 = time of confirmed incident** (not detection — the
moment the IC says "this is real"). Suspected breaches still trigger
the clock at the same T0.

### 4.1 Within 1 hour (T+1h)

For **P0** and **P1**:

| Who | Channel | Owner of notification |
| --- | --- | --- |
| CEO | Page + Signal | CCO or CSO |
| CTO | Page + Signal | IC |
| CCO | Page + Signal | IC (or self) |
| General Counsel | Page + Signal | IC |
| CSO / Head of Security | Page + Signal | IC |
| VP Eng | Slack `#exec-sev` + page | IC |
| On-call SRE Lead | Page | IC |
| Customer Success Director | Slack + page | IC |
| Compliance officer (regional, if relevant) | Page | CCO |

For **P2**: Skip the 1h ring — go directly to 24h notification.

### 4.2 Within 4 hours (T+4h)

For **P0** and **P1**:

| Who | Channel | Owner |
| --- | --- | --- |
| Full extended leadership (VPs + Directors) | Slack `#leadership-sev` | CCO |
| Board chair (P0 only) | Email + call | CEO |
| Outside counsel (DLA Piper APAC) | Email + call | General Counsel |
| Cyber insurance broker | Email | CFO delegate |
| External IR retainer (CrowdStrike Services) | Email + call | CSO |
| PR firm of record | Email | Comms Lead |
| Customer Success leads for top-50 accounts | Slack `#cs-leads-sev` | CS Director |

### 4.3 Within 24 hours (T+24h)

For **P0**, **P1**, and **P2**:

| Who | Channel | Owner |
| --- | --- | --- |
| All-hands engineering | Email + town hall (if working hours) | CTO |
| Full board | Written brief | CEO |
| Major customers (top-50, NDA contacts) | CSM direct outreach | CS Director |
| Affected customers (all tiers) | Email per §9 templates | Comms Lead |
| All employees | Internal email (need-to-know basis preserved) | Chief of Staff |
| Auditors (SOC2 / ISO) | Email | CCO |

### 4.4 Notification template (internal)

```
SUBJECT: [{SEV}] Breach notification — {short description} — T+{Xh}

Severity:   P0 | P1 | P2
Data class: D-Crit | D-High | D-Med | D-Low
Scale:      S-Mass | S-Mid | S-Small
Status:     CONFIRMED | SUSPECTED

T0:         YYYY-MM-DDTHH:MM:SSZ
Now:        YYYY-MM-DDTHH:MM:SSZ
IC:         {name}
Scribe:     {name}

What we know:
- ...

What we're doing now:
- ...

What we don't know yet:
- ...

Next update by: HH:MM TZ
War room: {Zoom link}
Slack: #sev-{ID}

Do not forward without IC + CCO approval.
```

---

## 5. Legal & Regulatory Clocks

The regulatory clock starts at **awareness** of the breach (which varies by
jurisdiction — many start at "becoming aware," not at confirmation). When in
doubt, start the clock at T0.

### 5.1 Regulator clock table

| Regulator | Jurisdiction | Clock | Trigger | Channel | Owner |
| --- | --- | --- | --- | --- | --- |
| **GDPR** (Art. 33) | EU / EEA / UK GDPR | **72 hours** | Personal data breach likely to result in risk to rights and freedoms | Lead supervisory authority via Art. 56 OSS | DPO |
| **UU PDP** (Indonesia, Law 27/2022) | Indonesia | **3 × 24 hours (72h)** | Failure to protect personal data of Indonesian subjects | Kominfo + affected data subjects | DPO ID |
| **Singapore PDPA** | Singapore | **72 hours** to PDPC; **as soon as practicable** to individuals if significant harm | Notifiable breach (≥ 500 individuals OR significant harm) | PDPC online portal | DPO |
| **Australia Privacy Act / NDB** | Australia | **As soon as practicable** (no explicit hours; expected within 30 days) | Eligible data breach with likely serious harm | OAIC online form | DPO AU |
| **California CCPA / CPRA** | California, US | **Without unreasonable delay** (no explicit hours; expected ≤ 60 days) | Unauthorized access + exfiltration of personal information | Email to affected residents; AG if > 500 CA residents | US Privacy Counsel |
| **NY SHIELD Act** | New York, US | **Most expedient time possible** | Breach of private information | Affected residents; NY AG / Dept of State / Consumer Protection | US Privacy Counsel |
| **Texas (BC&C 521.053)** | Texas, US | **No later than 60 days** | Breach of system security | Affected residents; AG if > 250 TX residents | US Privacy Counsel |
| **Other US states (varies)** | All 50 states | **30–90 days, varies** | State-specific definitions | Varies (AG, individuals) | US Privacy Counsel |
| **HIPAA** (if applicable) | US healthcare data | **60 days** to individuals; **60 days post-EOY** to HHS for < 500; **60 days** to HHS + media for ≥ 500 | PHI breach | HHS portal; affected individuals | CCO + Healthcare Counsel |
| **PCI DSS** | Payment card data | **Immediately** to acquiring bank + card brands | CHD compromise | Acquirer comms channel | CCO + Finance |
| **SOC 2** | Customers (contract) | **Per contract**, typically 24–72h | Customer-data incident | CSAT portal + email | CCO |
| **NIS2** (if EU presence) | EU critical infra | **24h early warning**, **72h notification**, **1mo final report** | Significant incident | National CSIRT | CSO |
| **SEC (if public)** | Public US companies | **4 business days** (Form 8-K Item 1.05) | Material cybersecurity incident | EDGAR | CFO + General Counsel |

### 5.2 Clock-management rules

1. **Start all clocks at T0.** Do not wait for confirmation in ambiguous
   cases; you can always close a clock by filing "no breach occurred."
2. **The shortest applicable clock wins.** If a single dataset triggers
   both GDPR (72h) and a US state law (60 days), prepare for the 72h clock
   first.
3. **Clock pauses are rare.** Only law-enforcement requests to delay
   notification can pause a regulator clock; document any pause in
   writing with the requesting agency.
4. **Each regulator clock has a named owner (§5.1).** Owner files the
   notice; CCO signs off; General Counsel reviews language.
5. **Multi-jurisdiction file-and-forget is forbidden.** Each filing must be
   tailored — copy-paste filings have been cited as aggravating factors in
   enforcement actions.

### 5.3 Clock workflow

```
T0  ──► Severity assigned (§3) within 30 min
        └─► DPO drafts jurisdictional impact list within 2h
            └─► For each jurisdiction:
                ├─► Clock owner identified
                ├─► Filing draft started by T+8h
                ├─► Legal review by T+24h
                └─► File before clock expiry
```

---

## 6. Communication Channels

| Channel | When | Owner | Notes |
| --- | --- | --- | --- |
| Status page (status.sentinelx.io) | Any customer-visible impact, or P0 even if invisible | Comms Lead | Coordinate with CCO before security wording |
| Email — affected customers | All P0/P1; P2 if customer-affecting | Comms Lead + CS | Per templates §9 |
| In-app banner | All P0; P1 if active risk | Comms Lead | Avoid causing panic; coordinate with Product |
| Regulator portals | Per §5 | Clock owner | Use legal-vetted language only |
| Press release | P0 with broad public interest; or when leak is imminent | PR Firm + CEO | Per §10 |
| Social media (status only) | When external chatter starts | Comms Lead | Route to status page |
| Direct customer call (top-50) | All P0 | CSM | Personal; CSM owns relationship |
| Partner / integration notice | When breach affects shared data flows | BD Lead | Pre-agreed in MSAs |

### 6.1 Status page state machine

```
Operational ─► Notice ─► Identified ─► Investigating ─► Identified
                                            │
                                            ├─► Monitoring ─► Operational
                                            │
                                            └─► Major Outage (if cust-impacting)
```

For security incidents, the IC may keep status as `Operational` and post
to a **Security Notices** sub-page, separate from the uptime status. Use
this when an incident is not customer-degrading but is notifiable.

### 6.2 Cadence rules

- **Updates every 30 minutes** on the status page during active P0.
- **Updates every 60 minutes** during active P1.
- **At least once per day** during active P2 until resolved.
- **"No new information" is a valid update.** Silence is not.

---

## 7. Roles & Responsibilities

| Role | Responsibility |
| --- | --- |
| Incident Commander (IC) | Owns the technical incident; declares severity in consultation with CCO |
| Chief Compliance Officer (CCO) | Owns this runbook; final call on regulator filings |
| General Counsel | Reviews all external comms; coordinates outside counsel |
| Data Protection Officer (DPO) | Files regulator notices in EU/SG/ID; maintains jurisdictional impact list |
| Chief Security Officer (CSO) | Forensics, evidence preservation, IR retainer engagement |
| Comms Lead | Customer comms, status page, social, PR coordination |
| Customer Success Director | Top-50 customer outreach; CSM coordination |
| PR Firm of Record | Media handling per §10 |
| CEO | Owns board comms; final approval on press release |
| CFO | Insurance broker engagement; financial-impact briefings |
| Scribe | Maintains a tamper-evident decision log throughout |

---

## 8. Detection → Containment → Eradication → Recovery → Lessons

Every breach response follows the same five-phase template. Times are
**budgets** for a P0; P1 doubles them, P2 quadruples.

### 8.1 Detection (T0 → T+30m)

- Confirm the event is a security incident (not a bug).
- IC assigns severity per §3, applying the IR-grading mapping in
  [`incident-response.md`](./incident-response.md#1-severity-classification)
  — D-Crit + S-Mass and D-Crit + S-Mid both auto-promote to P0 here as
  well.
- Initial regulator-jurisdiction list drafted by DPO.
- Scribe opens decision log.
- **Evidence preservation** — within 30 min of declaration:
  - Force a P1-004 evidence collection for the affected tenant
    covering every shipped control:
    ```bash
    sx-cli compliance collect \
      --tenant <tenant-id> \
      --all-controls \
      --force \
      --reason "incident #inc-<id> — pre-remediation snapshot"
    ```
  - The resulting bundle is sealed under WORM (S3 Object Lock
    COMPLIANCE mode) and cannot be altered by any party for 7 years.
  - Snapshot affected systems via the standard `sx-cli forensics
    snapshot --tenant <tid>` (preserves Postgres + Redis state at the
    incident moment).
  - Trigger the appropriate **P3-004 IR playbook** for the incident
    class — `ransomware`, `data-exfil`, `credential-compromise`, or
    `insider`. The playbook runs the standard NIST 800-61 step machine
    (Prepare / Detect / Contain / Eradicate / Recover / Post-Incident)
    against the affected scope; each step emits a signed audit row
    (`action = ir.playbook_step_*`).

### 8.2 Containment (T+30m → T+4h)

- Stop the bleeding: kill compromised tokens, isolate affected nodes,
  block egress.
- Tri-owners (CCO, GC, CSO) convene; severity confirmed or upgraded.
- T+1h notifications fired (§4.1).
- Outside counsel engaged.
- IR retainer engaged for forensics.

### 8.3 Eradication (T+4h → T+24h)

- Remove root cause: patch, rotate keys, kill malicious accounts.
- Build affected-subject list (this is the "biting" task — usually the
  long pole).
- Confirm scope is no longer expanding.
- T+4h notifications fired.
- Holding statement published per §9.1.

### 8.4 Recovery (T+24h → T+72h)

- Restore systems to full operation.
- File regulator notices on their respective clocks.
- Customer notification per §9.2 if affected-subject list is finalized;
  otherwise per-jurisdiction interim filings.
- Status page returns to Operational.

### 8.5 Lessons (T+72h → T+30d)

- Post-incident review (blameless) within 7 days.
- Action items tracked to closure.
- Public technical writeup, if material, within 30 days.
- Final regulator filings closed out.
- Runbook updated.

---

## 9. Customer Communication Templates

All templates are stored in source and versioned. Use the IDs in [§6 of
incident-response.md](./incident-response.md#6-comms) when referencing
them in the IC dashboard.

### 9.1 Initial holding statement (within 4 hours)

**Template ID:** `BREACH-HOLD-01`

> **Subject:** Important notice from SentinelX
>
> Dear {customer name},
>
> On {date, in UTC} at {time}, we identified a security incident affecting
> {brief scope — service / region / dataset}. We are actively investigating
> and have engaged our security team and external experts to determine the
> nature and extent of the issue.
>
> Based on what we know so far:
>
> - **What we have confirmed:** {1–2 bullet points, factual only}.
> - **What we are still investigating:** {1–2 bullet points}.
> - **What you should do now:** {one clear action OR "no action required
>   at this time"}.
>
> We are treating this with the highest urgency. Our next update will be
> by {time + 24h}, or sooner if material new information becomes
> available.
>
> If you have urgent questions, please reach your account contact or
> reply to this email.
>
> We are sorry for any concern this causes you.
>
> {signer — CSO or CCO}
> {name, title}
> SentinelX

**Rules:**
- No speculation. No legal hedging that obscures meaning.
- No "we take security seriously" boilerplate.
- Time-bound the next update.

### 9.2 Technical follow-up (within 72 hours)

**Template ID:** `BREACH-TECH-02`

> **Subject:** Follow-up: {incident reference}
>
> Dear {customer name},
>
> Following our notice on {date}, here is what we now know.
>
> ### What happened
> Between {window start} and {window end}, {factual description of
> root cause}. {Cause was a combination of {N} factors / a single
> failure of {control}}.
>
> ### Whose data was affected
> {Specific dataset scope. If your tenant was affected, the next
> section explains what was accessible.}
>
> ### What was accessible
> - {dataset 1}: {accessible | not accessible | unknown}
> - {dataset 2}: ...
>
> ### What was not affected
> - {dataset N+1}: {evidence basis}
>
> ### What we have done
> - {action 1}
> - {action 2}
>
> ### What we are doing next
> - {action 1, with date}
> - {action 2}
>
> ### What you should do
> - {clear, actionable}
>
> ### Regulator notifications
> We have notified {list of regulators where you are subject}. You may
> separately have your own obligations as a controller; we will provide
> whatever evidence you need to discharge those.
>
> ### Direct contacts
> - Security: security@sentinelx.io
> - Your CSM: {name, email}
> - Compliance: compliance@sentinelx.io
>
> Your final report will follow within {N} business days.
>
> {signer — CCO}

### 9.3 Final resolution (within 30 days of containment)

**Template ID:** `BREACH-FINAL-03`

> **Subject:** Final report: {incident reference}
>
> Dear {customer name},
>
> This is our final report on the incident first communicated on {T0
> date}.
>
> ### Summary
> {2-3 sentences plain-English summary.}
>
> ### Root cause
> {Single root cause, no hand-waving. Reference the contributing factors.}
>
> ### Timeline
> | Time (UTC) | Event |
> | --- | --- |
> | T0 | Incident detected |
> | T+30m | Severity assigned ({SEV}) |
> | ... | ... |
> | T+{N}h | Containment confirmed |
> | T+{N}d | Eradication complete |
> | T+{N}d | This report |
>
> ### Impact
> - Customers affected: {N}
> - Data subjects affected: {N}
> - Records affected: {N}
> - Service disruption: {none | partial | full} for {duration}
>
> ### Permanent corrective actions
> 1. {control + date deployed}
> 2. {control + date deployed}
> 3. ...
>
> ### Independent validation
> {Third-party attestation reference, if applicable.}
>
> ### What we owe you
> - Audit-evidence package: available via {channel}.
> - SLA credits (if any): {applied | will be applied on {date}}.
>
> Thank you for your patience. We have published a technical write-up at
> {URL} for the broader community.
>
> {signer — CCO + CEO}

---

## 10. PR & Media Handling

### 10.1 Posture by severity

| Severity | Posture | Spokesperson | Speed of public statement |
| --- | --- | --- | --- |
| P0 (mass + critical) | **Active** — own the story | CEO + CSO | Within 24h |
| P0 (mass + high) | **Active** | CSO + CCO | Within 48h |
| P1 | **Reactive** — respond if asked | CCO | Only on inquiry |
| P2 | **Silent** | – | Only if leaked |

### 10.2 No-fly list

The following are forbidden in any public statement:

- "Sophisticated attack" — usually inaccurate, infuriates security
  community.
- "We take security seriously" — boilerplate, distrusted.
- "No evidence of misuse" — only say if you have positive evidence,
  not as substitute for negative evidence.
- "Password hashes were salted and unreadable" — describe algorithm
  honestly; many "hashed" passwords are recoverable.
- Speculation about attacker identity unless attributed by law enforcement.

### 10.3 Pre-approved holding line for any inbound media query

> "We identified a security incident on {date} and are actively
> investigating with the assistance of external experts. We have notified
> affected customers and the relevant regulators. We will share further
> details as our investigation progresses. Customer trust is the
> foundation of our business and we will be fully transparent about what
> happened and what we are doing to prevent recurrence."

Use only if no specific facts can yet be shared. Replace with substance
as soon as available.

### 10.4 Media-handling flow

1. All inbound media goes to `press@sentinelx.io`.
2. PR firm acknowledges within 2 business hours.
3. Comms Lead drafts response in 4 business hours.
4. CCO + General Counsel review.
5. CEO signs off.
6. Response sent; logged.

### 10.5 Coordinated disclosure

If a researcher reports the issue (vs. internal detection):

- Engage them via `security@sentinelx.io` within 24 hours.
- Negotiate a disclosure date that respects regulator clocks.
- Credit them in the final writeup unless they decline.
- Do not threaten — even when the disclosure was rough. Public legal
  threats against researchers reliably destroy security reputations.

---

## 11. Tabletop Exercise Template

Tabletops run **twice per year** (one P0 scenario, one P1 scenario).
Tabletops are mandatory for: CEO, CTO, CCO, GC, CSO, Comms Lead, CS
Director, on-call SRE Lead, DPO.

### 11.1 Pre-exercise checklist

- [ ] Scenario selected and reviewed by CCO + CSO.
- [ ] Facilitator assigned (rotation; never the IC).
- [ ] Observer from outside counsel invited.
- [ ] Observer from cyber insurer invited.
- [ ] Date confirmed; 3-hour block on calendars.
- [ ] No live system access — tabletop only.

### 11.2 Tabletop scenario template

```markdown
# Tabletop Exercise — {scenario name}

- **Date:** YYYY-MM-DD
- **Facilitator:** {name}
- **Observers:** {names}
- **Participants:** [list per §11]

## Scenario brief
{2–3 paragraphs. Include time of day, what is "known," what is "unknown."}

## Injects
[Pre-planned events the facilitator drops at specific times.]

| T+ | Inject | Source | What it tests |
| --- | --- | --- | --- |
| 0:00 | Initial detection | Synth | Detection + severity |
| 0:15 | Press inquiry | "Reuters reporter" | Media handling |
| 0:45 | Second affected dataset surfaces | Forensics | Scope expansion |
| 1:30 | Regulator email from DPC | EU DPC | Clock management |
| 2:15 | Customer requests immediate call | Top-10 acct | CS coordination |

## Decision points the team must surface
- Severity assignment
- Containment vs. preservation tradeoff
- Customer notification timing
- Media holding statement
- Regulator filing order

## Score sheet
| Item | Met? | Notes |
| --- | --- | --- |
| Severity assigned within 30 min | Y/N | |
| T+1h notifications fired | Y/N | |
| Status page updated within 30 min | Y/N | |
| Regulator clocks correctly identified | Y/N | |
| Holding statement drafted within 4h | Y/N | |
| No "no-fly list" language used | Y/N | |
| Decision log maintained | Y/N | |

## Hotwash (immediately after)
- What worked?
- What did not?
- What surprised us?
- What process changes will we make?

## Action items
| # | Owner | Due | Description | Tracking |
| --- | --- | --- | --- | --- |

## Sign-off
- Facilitator: __________
- CCO: __________
```

### 11.3 Scenario library

| ID | Title | Severity tested | Last run |
| --- | --- | --- | --- |
| TT-01 | Audit-chain tamper (DR Scenario C twin) | P0 | 2026-02-18 |
| TT-02 | Customer-tenant lateral access via shared token | P0 | 2025-11-04 |
| TT-03 | Stolen laptop with engineer KMS-wrapped key cache | P1 | 2026-04-22 |
| TT-04 | Vendor breach upstream (supply-chain) | P1 | — |
| TT-05 | Insider threat — exfil to personal cloud | P0 | — |
| TT-06 | Children's-data inadvertent exposure (D-Crit + S-Mid) | P0 | — |

---

## 12. Cross-References

- [Incident Response Runbook](./incident-response.md) — the technical
  twin of this document.
- [Disaster Recovery Runbook](./disaster-recovery.md) — Scenario C
  (audit-chain tamper) is the joint exercise.
- [FinOps Runbook](./finops.md) — breach response will have a cost tail;
  log into monthly review.
- [Operations: regulator filing register](../operations/regulator-filings.md).
- [Operations: decision logs](../operations/incident-decisions.md).
- [Security: audit chain design](../security/audit-chain.md).

---

## 13. Change History

| Date | Author | Change |
| --- | --- | --- |
| 2026-05-30 | CCO | Initial publication. Aligned with GDPR + UU PDP + US state laws. |
| 2026-04-22 | DPO | Pre-publication draft incorporating TT-03 hotwash. |
| 2026-06-13 | CCO | Reaffirmed regulator clocks (GDPR 72 h, UU PDP 3×24 h ≡ 72 h, PDPA SG 72 h). Added §8.1 forced P1-004 evidence collection at T+30 min; added P3-004 IR playbook trigger; clarified incident grading mapping to incident-response.md. |
