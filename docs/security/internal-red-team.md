# SentinelX Internal Red Team Rotation

> Last reviewed: 2026-06-13
> Maintainer: Security Engineering Lead (`security@sentinelx.example`)
> Audience: Engineering, Security, and Leadership
> Cadence: Quarterly rotation; annual external engagement

---

## Table of contents

1. [Mission](#1-mission)
2. [Scope and relationship to other security programs](#2-scope-and-relationship-to-other-security-programs)
3. [Quarterly rotation schedule](#3-quarterly-rotation-schedule)
4. [Onboarding checklist for incoming red teamers](#4-onboarding-checklist-for-incoming-red-teamers)
5. [Standard two-week engagement format](#5-standard-two-week-engagement-format)
6. [Rules of engagement](#6-rules-of-engagement)
7. [Reporting template](#7-reporting-template)
8. [Post-engagement transfer brief](#8-post-engagement-transfer-brief)
9. [Annual external red team engagement](#9-annual-external-red-team-engagement)
10. [Governance and metrics](#10-governance-and-metrics)

---

## 1. Mission

The Internal Red Team exists to **continuously challenge SentinelX's own
detective and preventive controls** from an adversary perspective, using
realistic, in-house, ethical operators.

We do this because:

- The defensive team (blue) cannot grade its own homework.
- External bug bounty (see `bug-bounty.md`) gives us coverage on the *attack
  surface* exposed to the internet but rarely tests internal lateral
  movement, IAM blast radius, or insider scenarios.
- Annual external red-team engagements (see §9) are deep but infrequent.

A rotating internal red team gives us **continuous, low-cost, high-context**
adversarial pressure between external engagements.

---

## 2. Scope and relationship to other security programs

### 2.1 In scope for internal red team

- Production AWS / GCP control plane (read-only by default; write only via
  pre-authorized, time-boxed change tickets).
- Staging and pre-production environments (`*.dev.sentinelx.io`,
  `*.stg.sentinelx.io`). Full write access permitted.
- Corporate identity providers (Okta, GitHub SSO, Google Workspace).
- Build pipelines (GitHub Actions, Buildkite, internal SLSA attestor).
- Engineer endpoints (with prior consent of the individual).
- The SentinelX product itself, including customer-facing API and dashboard,
  via a dedicated red-team tenant.

### 2.2 Out of scope for internal red team

- Real customer tenants and real customer data.
- Personally Identifiable Information (PII) of employees beyond directory
  metadata.
- Health, financial, or legal records of any individual.
- Vendor systems (Zendesk, Stripe, Datadog) beyond their public sign-in.
- Physical intrusion into offices or data centres.
- Phishing campaigns against named individuals without HR pre-approval and
  written consent at hire (see §6).

### 2.3 Distinction from other programs

| Program                    | Scope                                  | Operator                  | Cadence    |
|----------------------------|----------------------------------------|---------------------------|------------|
| Bug bounty                 | Public-internet attack surface         | External researchers      | Continuous |
| Internal red team          | Full production + corp, ethical scope  | Rotating SentinelX engs   | Quarterly  |
| External red team          | Full-scope, OPSEC-tight                | Contracted boutique firm  | Annual     |
| Threat modelling           | Design-time analysis                   | Feature team + security   | Per-feature|
| Pen-test (compliance)      | Defined surface (SOC 2, ISO 27001)     | Approved auditor          | Annual     |

The four operational programs feed one shared backlog: `JIRA SEC` board.

---

## 3. Quarterly rotation schedule

### 3.1 Structure

- **Four engineers per quarter**, two from product engineering and two from
  platform / infrastructure engineering.
- Each engineer commits **two weeks of full-time** participation during the
  quarter; the remaining time stays on their regular team.
- **No repeat within 12 months.** An engineer who served in Q1 cannot serve
  again until at least Q1 of the following year.
- The Security Engineering Lead is a permanent member and acts as engagement
  coordinator, but does not count toward the four.

### 3.2 Selection criteria

Candidates must:

1. Have at least 12 months tenure at SentinelX.
2. Hold an in-good-standing security awareness certification (annual).
3. Be cleared by their direct manager for two weeks of context-switching.
4. Have signed the Rules of Engagement acknowledgment (§6) within the past
   12 months.

Candidates may **self-nominate** at any time; the Security Lead and engineering
directors finalize the slate one quarter in advance.

### 3.3 Calendar template

| Quarter | Engagement 1 (weeks 2–3) | Engagement 2 (weeks 7–8) | Engagement 3 (weeks 11–12) |
|---------|---------------------------|---------------------------|-----------------------------|
| Q1      | Identity & IAM            | Build-pipeline             | Tenant isolation             |
| Q2      | Data exfil paths          | Detection coverage gaps    | Insider-misuse simulation    |
| Q3      | Cloud control plane       | Container escape           | OPSEC of SecOps tooling      |
| Q4      | Year-in-review chained op | (External engagement)      | (External engagement)        |

Engagement themes are revisable each quarter based on outstanding risks from
the previous cycle. Q4 deliberately leaves space for the annual external team
(see §9).

### 3.4 No-repeat enforcement

The roster is tracked in `docs/security/roster-history.yaml` (private). The
Security Lead audits the roster before each quarter and blocks any name whose
last engagement closed less than 12 months prior.

---

## 4. Onboarding checklist for incoming red teamers

Each incoming red teamer completes the following before day 1 of the
engagement. The checklist is tracked as a Jira sub-task on the engagement
ticket.

### 4.1 Paperwork

- [ ] Signed **Rules of Engagement** acknowledgment (current version).
- [ ] Signed **Confidentiality addendum** specific to red-team material.
- [ ] HR confirmation that the engineer is in good standing.
- [ ] Manager sign-off on calendar reservation.

### 4.2 Access provisioning

- [ ] `redteam-Qx-YYYY` IAM role provisioned, expiring at engagement end.
- [ ] Dedicated red-team tenant credentials (separate from personal
      dashboard account).
- [ ] Time-boxed VPN profile for lab subnet (`10.250.0.0/16`).
- [ ] Loaner laptop or hardened VM image with the BAS framework pre-installed.
- [ ] Slack channel access: `#sec-redteam-private`.

### 4.3 Tooling and training

- [ ] One-hour walk-through of the chosen Breach and Attack Simulation
      (BAS) framework (currently Atomic Red Team + an internal harness).
- [ ] Review of the latest external red-team report (read-only on the
      Security Lead's laptop, not exported).
- [ ] Review of last two quarterly internal reports.
- [ ] Familiarization with the current detection coverage matrix
      (MITRE ATT&CK mapping).
- [ ] Reading list:
  - SentinelX architecture (`docs/architecture.md`).
  - STRIDE threat model (`docs/security/threat-model-stride.md`).
  - Supply-chain controls (`docs/security/supply-chain.md`).
  - Operational SLOs (`docs/slos.md`).

### 4.4 Personal preparation

- [ ] Out-of-office set on personal Jira queue.
- [ ] Pager rotation handed off.
- [ ] Customer escalations re-routed.
- [ ] Personal calendar updated with engagement block.

### 4.5 Pre-engagement security briefing

- [ ] 30-minute briefing with Security Lead covering:
  - Current SOC posture and on-call rotation.
  - Known false-positive sources (so we don't burn analyst time).
  - "Red lines" specific to this quarter (e.g. customer migration in
    progress, active incident, regulator review).
- [ ] Verbal confirmation of understanding (logged in engagement ticket).

---

## 5. Standard two-week engagement format

Each engagement follows a four-phase structure. Phase boundaries are days
(business days, UTC); operators may finish a phase early but cannot extend
without Security Lead approval.

### 5.1 Day 1–3: Recon

- Passive enumeration of in-scope assets.
- Review of recent deploys, feature flags, and config changes.
- Identification of one to three **objectives** (e.g. "prove that a
  compromised CI runner can push a signed image"), signed off by the
  Security Lead.
- Output: written recon brief, stored in the engagement ticket.

### 5.2 Day 4–7: Attack

- Execute attack chain(s) using only the agreed BAS framework or
  hand-written, reviewed tooling.
- All actions logged with UTC timestamps in the engagement journal.
- Daily 15-minute sync with Security Lead at 16:00 UTC.
- Stop conditions:
  - Real customer data appears in a payload → halt, page Security Lead.
  - Production availability impacted → halt, page on-call.
  - An unscoped third party is touched → halt, document, report.

### 5.3 Day 8–9: Exfil (simulated)

- Demonstrate egress paths for proven attack chains.
- Exfil only **canary data** placed by the red team itself; never real data.
- Verify whether the blue team's egress detection fired and how long it
  took to alert (mean-time-to-detect, MTTD).

### 5.4 Day 10: Report

- Draft the engagement report (template in §7).
- Walk-through with Security Lead and one independent reviewer.
- Schedule the post-engagement debrief with the blue team (next business week).
- Hand back all access tokens; verify in IAM that the `redteam-Qx-YYYY` role
  is destroyed, not just disabled.

### 5.5 Buffer day (day 11)

Each engagement reserves the eleventh business day as a buffer for:

- Rewriting the report after blue-team feedback.
- Re-testing one detection that was added mid-engagement.
- Administrative wrap-up (timesheets, expense claims, retro).

---

## 5A. BAS technique library (P1-008) and chain replay (P2-015)

Internal red-team engagements rely on two SentinelX-native primitives.
Operators run them through `sx-cli bas` (operator-side) or directly
against the API (`POST /v1/bas/run`).

### 5A.1 BAS technique library (P1-008)

The library ships 50+ techniques pre-mapped to MITRE ATT&CK and
categorised by the **minimum engagement mode** required to dispatch
them. The full catalogue lives in
`crates/sx-bas/src/catalog/{credential_access,defense_evasion,discovery,execution,exfiltration,lateral_movement,persistence,privilege_escalation,reconnaissance}/`.

Selected coverage (the catalogue refresh log lives in
`crates/sx-bas/CATALOG_CHANGELOG.md`):

| ATT&CK tactic            | Example techniques                                                            | Required mode  |
|--------------------------|-------------------------------------------------------------------------------|----------------|
| Reconnaissance (TA0043)  | T1595.001 active scanning, T1592.002 host info gathering                       | Passive        |
| Initial Access (TA0001)  | T1078.004 valid cloud accounts                                                 | Active         |
| Execution (TA0002)       | T1059.004 unix shell, T1059.006 python                                         | Active         |
| Persistence (TA0003)     | T1098.001 additional cloud credentials                                         | Disruptive     |
| Privilege Escalation (TA0004) | T1548.003 sudo + sudo caching                                             | Disruptive     |
| Defense Evasion (TA0005) | T1070.004 file deletion, T1562.001 disable security tools                      | Disruptive     |
| Credential Access (TA0006)| T1003.008 /etc/passwd-shadow, T1552.001 cred in files                         | Active         |
| Discovery (TA0007)       | T1083 file/dir discovery, T1018 remote system discovery                        | Passive        |
| Lateral Movement (TA0008)| T1021.004 SSH, T1021.001 RDP, T1550.001 use-alternate-auth                     | Disruptive     |
| Exfiltration (TA0010)    | T1567.002 exfil to cloud storage (controlled canary bucket)                    | Disruptive     |

Run a single technique:

```bash
sx-cli bas run \
  --engagement-id eng_01J... \
  --technique T1083 \
  --target asset_01J... \
  --reason "internal Q3 W2 day-2 discovery"
```

The orchestrator refuses to dispatch if any of the gates listed in
[`../compliance/engagement-roe-template.md`](../compliance/engagement-roe-template.md#64-platform-safety-pipeline-defence-in-depth)
rejects (mode, window, active-exploit, two-person, kill switch).

### 5A.2 Lateral movement chain replay (P2-015)

A *chain* is a directed graph of techniques where each node carries a
"success criterion" predicate read from the artefacts of prior nodes.
The platform ships **three canonical chains** that map to the standing
quarterly themes:

| Chain ID                  | MITRE chain              | Purpose                                                             |
|---------------------------|--------------------------|---------------------------------------------------------------------|
| `chain.cloud-takeover`    | T1595 → T1078.004 → T1098.001 → T1567.002 | External recon → valid cloud cred → additional cred → exfil to canary bucket. Tests cloud blast-radius (P1-010). |
| `chain.k8s-lateral`       | T1595 → T1059.004 → T1552.001 → T1021.004 | Recon → in-pod shell → cred-in-file → SSH to neighbouring pod. Tests Falco (P2-016) + admission analyzer (P2-014). |
| `chain.insider-exfil`     | T1078.001 → T1083 → T1003.008 → T1567.002 | Valid local cred → file discovery → shadow extraction → cloud exfil. Tests UEBA (P2-005) + DLP (P2-006). |

Replay a chain:

```bash
# 1. Stage the chain (validates every gate without dispatching).
sx-cli bas chain stage \
  --engagement-id eng_01J... \
  --chain chain.k8s-lateral \
  --targets asset_01J...,asset_01J...

# 2. Request two-person approval.
sx-cli bas chain request-approval --chain-run-id cr_01J...

# 3. Second operator approves.
sx-cli bas chain approve --chain-run-id cr_01J...

# 4. Dispatch.
sx-cli bas chain run --chain-run-id cr_01J...
```

The orchestrator persists every dispatched step into `bas_chain_steps`
with the predicate evaluation result and the artefact references; the
chain summary serialises into the engagement report (§7) under
`Attack narrative`.

### 5A.3 Approval gates per mode

The mode → approval matrix is enforced at the **platform** layer; this
table is the operator-facing summary.

| Engagement mode | Permitted technique modes | Per-technique approval | Per-chain approval         | Active-exploit gating |
|-----------------|---------------------------|------------------------|-----------------------------|------------------------|
| Passive         | Passive                   | None                   | None                        | Inert (no payload)      |
| Active          | Passive, Active           | Engagement lead        | Engagement lead             | Single-step only        |
| Disruptive      | Passive, Active, Disruptive| CISO or delegate      | Two-person rule (§6.2)      | Required + safety officer |

Mode promotion mid-engagement is a written change request signed by the
customer CISO and recorded as `audit.engagement_mode_changed`.

### 5A.4 Evidence retention and chain-of-custody

All BAS artefacts (request/response captures, dropped canary tokens,
screenshots) are persisted into the per-tenant `bas_artefacts` S3
bucket, encrypted with the tenant KEK, and **referenced from the audit
chain by SHA-256**. The chain row contains the digest, not the bytes,
so chain verification confirms artefact integrity without ever reading
the underlying object.

Retention contract:

| Artefact class       | Retention                                                            |
|----------------------|----------------------------------------------------------------------|
| Engagement report    | Indefinite — required for customer trust portal and SOC 2 evidence   |
| Raw BAS artefacts    | 90 days after engagement close (then crypto-shredded; chain digest retained) |
| Chain digest of above| Indefinite (hash-chained + TSA-anchored, P1-015)                      |
| Operator journal     | 7 years (mirrors RPA-009 in DPIA)                                    |
| Engagement bridge transcript | 7 years                                                       |

Chain-of-custody handoff to compliance evidence (P1-004):

1. Engagement closure command (`sx-cli engagement close`) emits an
   audit row `action = engagement.closed` carrying the digest of every
   artefact still under retention.
2. The next P1-004 evidence collection includes that audit row in the
   bundle manifest, so the SOC 2 / ISO 27001 auditor has the artefact
   list as a sealed item under WORM.
3. The 90-day shredder, when it runs, emits
   `action = bas.artefacts_shredded` referencing the same digests. The
   chain shows the lifecycle from creation to shredding without ever
   exposing the payload.

---

## 6. Rules of engagement

The Rules of Engagement (RoE) are binding. Violation is treated as a serious
HR matter and may end employment.

### 6.1 Hard prohibitions

1. **No production credentials of real users.** Operators must use the
   dedicated `redteam-Qx-YYYY` IAM role; no harvesting of live employee or
   customer credentials, even for proof.
2. **No PII access without legal review.** Any path that would touch
   customer or employee PII must be paused, documented, and submitted to
   Legal + Security Lead for written approval before continuing.
3. **BAS framework only.** Attack tooling is restricted to:
   - The current internal BAS harness — `sx-bas` catalogue (P1-008,
     50+ MITRE-mapped techniques) and chain replay (P2-015).
   - Atomic Red Team techniques tagged "safe-for-prod" (via the
     `sx-bas` Atomic Red Team adapter).
   - Custom scripts that have been code-reviewed by a non-engagement
     security engineer.
   No off-the-shelf C2 frameworks (Cobalt Strike, Sliver, Mythic) in
   production, regardless of licensing.
4. **No service disruption.** Any technique whose worst-case is a tenant
   outage (broad fork-bomb, queue flooding) is forbidden; simulate at < 1 %
   of production load and confirm circuit breakers fire.
5. **No persistence beyond engagement.** Remove all artefacts on day 10;
   the Security Lead audits on day 11.
6. **No social engineering of named individuals without consent.** Phishing
   simulations against the broader workforce are run by HR + Security,
   separately from this program.
7. **No collateral damage to vendors.** If an attack chain pivots to a
   vendor (Stripe, AWS Support), stop and document.
8. **No publication.** Engagement artefacts are confidential indefinitely;
   non-sensitive lessons learned may be shared internally only.

### 6.2 Soft conventions

- "Loudness budget": each engagement may file up to **two false-positive
  detections** with the SOC before pausing for tuning.
- Operators identify themselves to the SOC within 30 minutes of any direct
  human escalation triggered by their activity.
- The 2-week clock is hard. If you didn't prove the objective, that itself
  is a finding ("hardening sufficient to resist a 2-week attempt by an
  insider with read access").

### 6.3 Escalation paths

- Operator → Security Engineering Lead (immediate).
- Security Lead → CTO + Head of Legal (severity ≥ High, or any PII concern).
- CTO → CEO + Board (only if customer-facing impact occurred).

---

## 7. Reporting template

Every engagement closes with a written report in the following structure.
Filename: `docs/security/redteam/YYYY-Qx-engagement-N.md` (internal repo,
private).

```
# Internal Red Team Report — YYYY Qx — Engagement N

## Executive summary
- Theme:
- Operators (4):
- Objectives stated on day 1:
- Objectives achieved (Y/N each):
- Highest-severity finding:
- Top recommended action:

## Engagement metadata
- Start date / end date:
- Engagement coordinator:
- Blue-team observers:
- BAS framework version:
- Total operator-days:

## Recon summary
- Assets enumerated:
- Anomalies noted:
- Pre-existing risks confirmed:

## Attack narrative
- Day-by-day timeline with UTC timestamps.
- Tools and techniques (mapped to MITRE ATT&CK).
- Detections that fired (true positive vs missed).

## Findings
For each finding:
- ID (RT-YYYY-Qx-N-NN)
- Title
- Severity (Critical / High / Medium / Low)
- Description
- Reproduction steps (reference engagement journal section)
- Impact
- Recommended remediation
- Owning team
- Target resolution date

## Detection gap analysis
- Detections expected but absent:
- Detections present but slow (MTTD > target):
- Detections noisy (false positive rate too high):

## Recommendations
Prioritized list, each tied to a Jira ticket on board `SEC`.

## Lessons learned for next rotation
- Process improvements:
- Tooling improvements:
- Scope adjustments to suggest:

## Appendices
- A. Raw engagement journal
- B. BAS harness output
- C. IAM role lifecycle proof
```

Reports are reviewed by the Security Lead and one independent reviewer
(typically the previous quarter's lead operator) before being finalized.

---

## 8. Post-engagement transfer brief

Within five business days of the engagement closing, the outgoing team
delivers a **transfer brief** to:

- The incoming quarter's roster (if known).
- The blue team's detection engineering lead.
- The Security Engineering Lead.

### 8.1 Contents

1. **One-page summary** of objectives, outcomes, and the top three
   recommended follow-ups.
2. **Open findings table** — what was found but not yet remediated, owner,
   ETA.
3. **Tooling delta** — any scripts or BAS modules created, with code review
   status.
4. **Coverage delta** — MITRE ATT&CK techniques newly proven detectable or
   newly proven undetectable, in a single table.
5. **Suggested theme for next quarter** — based on what we *didn't* get to.
6. **Live "do not retest" list** — areas with in-flight migration or
   customer-sensitive change that should be skipped next quarter.

### 8.2 Delivery format

- Read-out: 45-minute meeting, recorded and stored in the engagement folder.
- Written: appended to the engagement report, section "Transfer Brief".
- Signature: incoming team lead acknowledges receipt in writing.

### 8.3 Knowledge retention

The Security Engineering Lead maintains a rolling **Red Team Playbook**
incorporating reusable lessons. Each transfer brief contributes one to
three entries.

---

## 9. Annual external red team engagement

### 9.1 Why external

Internal rotations are continuous and high-context, but suffer from
familiarity bias: operators know our defences. Once per year, we hire an
external boutique to perform a full-scope, OPSEC-tight engagement against
our production environment.

### 9.2 Budget

- Allocation: **USD 250,000** per fiscal year, included in the security
  cost centre.
- Of which: up to USD 200,000 for the engagement itself; USD 30,000
  reserved for follow-up remediation engineering; USD 20,000 for the joint
  read-out workshop and post-engagement retro.
- Budget owner: CTO; co-signed annually by CFO.
- Carry-over: unspent budget rolls into the next fiscal year up to 50 %.

### 9.3 Selection process

1. **Long-list (Q3)** — Security Lead drafts a long-list of 6–8 firms with
   demonstrated experience against cloud-native security products. Sources:
   peer recommendations, public reports, OWASP listings.
2. **RFI (early Q4)** — issue a Request for Information covering:
   - Team CVs and certifications (OSCP, OSEP, CRTO, CRTL).
   - Past engagements against similar B2B SaaS.
   - Proposed methodology and ATT&CK coverage.
   - Insurance and indemnification.
   - References (at least two we can contact).
3. **Short-list (Q4 week 4)** — narrow to 3 firms.
4. **Technical interview (Q4 week 6)** — each firm walks through a
   sanitized past report and answers scenario questions.
5. **Reference checks (Q4 week 8)** — direct conversation with two
   customers; specific questions about scope discipline, communication,
   and follow-up.
6. **Final selection (Q4 week 10)** — CTO + Security Lead + Head of Legal
   sign off. Procurement issues a Statement of Work.
7. **Engagement (Q1 of following fiscal year)** — typically 4–6 weeks.

### 9.4 Scope agreement

The Statement of Work codifies:

- Assets in scope (explicit allow-list).
- "Out-of-scope-or-stop" list — PII, customer-side actions, certain
  vendor systems.
- Crown-jewel objectives.
- Approved tooling (and what is not approved).
- Reporting cadence and final deliverable format.
- Disclosure and confidentiality terms.

The internal team supports but does not direct day-to-day operations.

### 9.5 After-action

- 90-minute joint read-out with Engineering leadership.
- Remediation tickets created within 5 business days, with owners and SLAs
  matching the bug-bounty severity SLA (`bug-bounty.md` §5.1).
- Re-test budget allocated by default; the same firm conducts the re-test
  within 90 days of remediation.
- Lessons learned feed into the next year's internal rotation themes
  (see §3.3) and into the threat model (`threat-model-stride.md`).

### 9.6 Reconciling internal and external findings

Where an internal rotation and the external engagement raise overlapping
findings, the **external write-up is authoritative for the public-facing
artefact** (SOC 2, customer trust portal) and the internal write-up retains
its operational context. Both reports remain on file.

---

## 10. Governance and metrics

### 10.1 Steering

- Quarterly governance review: Security Lead + Engineering Directors.
- Annual review with CTO + CEO covering:
  - Roster diversity and engineer development outcomes.
  - Findings closure rate vs SLA.
  - MTTD / MTTR trends derived from engagements.
  - Budget vs spend on internal + external programs.

### 10.2 Tracked metrics

| Metric                                            | Target           |
|---------------------------------------------------|------------------|
| Engagements completed per year                    | 12 (4 × 3)       |
| Mean time to detect (red team simulated breach)   | < 30 minutes     |
| Mean time to respond (analyst engagement)         | < 60 minutes     |
| Findings open > SLA                               | 0                |
| Repeat findings across quarters                   | < 10 %           |
| Engineer satisfaction (post-rotation survey)      | ≥ 4 / 5          |
| Roster no-repeat rule violations                  | 0                |

### 10.3 Continuous improvement

The Red Team Playbook (see §8.3) is revised at the end of every quarter,
with the changes summarized in a one-paragraph diff appended to the
engagement report. Major changes (scope, RoE, BAS tooling) require
re-signature of the RoE by all active operators within 30 days.

---

## 11. Contact

- Program owner: Security Engineering Lead — `security@sentinelx.io`
- Operator escalation: `#sec-redteam-private` (Slack, urgent)
- Legal review: `legal-security@sentinelx.io`
- Roster history (private): `docs/security/roster-history.yaml`
