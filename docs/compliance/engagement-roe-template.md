# Rules of Engagement (RoE) — SentinelX Security Testing

**Last reviewed:** 2026-06-13
**Maintainer:** Engagement Governance Office
**Document owner:** Director of Offensive Security
**Template version:** 3.2 (2026-Q2)
**Cross references:**
- [PCI DSS v4.0 mapping](./pci-dss-v4-mapping.md)
- [GDPR/PDP DPIA](./gdpr-pdp-dpia.md)
- [Operations runbooks](../runbooks/)
- [Architecture](../architecture.md)

> Use this template to draft a Rules of Engagement (RoE) agreement before any SentinelX testing activity begins. All `<<placeholders>>` must be completed and reviewed by legal counsel for both parties. Once signed, this document is legally binding for the engagement window. Any change requires a written amendment signed by both parties.

---

## 1. Parties

| Field | Customer | SentinelX |
|-------|----------|-----------|
| Legal name | <<Customer Legal Name>> | <<SentinelX entity (e.g., SentinelX Pte. Ltd. / PT SentinelX Indonesia)>> |
| Registered address | <<Address>> | <<Address>> |
| Authorised signatory | <<Name, Title>> | <<Name, Title>> |
| Engagement sponsor (business) | <<Name, Title, Email>> | <<Name, Title, Email>> |
| Engagement technical owner | <<Name, Title, Email, Phone>> | <<Name, Title, Email, Phone>> |
| Billing contact | <<Name, Email>> | <<Name, Email>> |

This RoE supplements the Master Services Agreement (MSA) signed on <<MSA Date>> and the Data Processing Addendum (DPA) signed on <<DPA Date>>. In the event of conflict, the order of precedence is: (1) signed amendment, (2) this RoE, (3) DPA, (4) MSA.

---

## 2. Engagement summary

| Field | Value |
|-------|-------|
| Engagement ID | `ENG-<<YYYYMMDD>>-<<SLUG>>` |
| Engagement type | <<External pentest / Internal pentest / Red team / Purple team / BAS / Continuous attack surface mgmt / Cloud config review / Source code review / Other>> |
| Objective | <<2-3 sentences describing the desired business outcome>> |
| Threat model assumed | <<External opportunistic / External targeted / Insider / Supply chain / Mixed>> |
| Methodology | <<PTES / OSSTMM / NIST SP 800-115 / OWASP WSTG / MITRE ATT&CK-aligned / Hybrid>> |
| Reporting standard | <<CVSS v4.0 / DREAD / Internal SentinelX severity matrix>> |
| Estimated effort | <<N person-days>> |
| Engagement value | <<Currency + Amount>> |

---

## 3. Scope

### 3.1 In-scope assets

Provide all that apply. At least one row must be populated.

| Type | Identifier | Owner | Environment | Notes |
|------|-----------|-------|------------|-------|
| CIDR | <<e.g. 203.0.113.0/24>> | <<Customer>> | <<prod/staging>> | <<notes>> |
| FQDN | <<e.g. api.example.com>> | <<Customer>> | <<prod>> | <<notes>> |
| URL | <<e.g. https://app.example.com/v2/*>> | <<Customer>> | <<prod>> | <<notes>> |
| Mobile app | <<package name + store URL>> | <<Customer>> | <<prod>> | <<iOS/Android>> |
| API endpoint | <<spec URL or Postman collection ID>> | <<Customer>> | <<prod>> | <<auth model>> |
| Source repo | <<git URL>> | <<Customer>> | <<branch ref>> | <<read-only token>> |
| Cloud account | <<AWS account id / GCP project / Azure subscription>> | <<Customer>> | <<prod>> | <<role assumed>> |
| SaaS tenant | <<tenant id, e.g. Okta org>> | <<Customer>> | <<prod>> | <<read-only OAuth>> |
| Physical | <<address>> | <<Customer>> | <<prod>> | <<for social/physical>> |

### 3.2 Out-of-scope (denylist)

The following are expressly excluded; any interaction is prohibited and constitutes a deliverable violation:

| Type | Identifier | Reason |
|------|-----------|--------|
| CIDR | <<e.g. 10.0.0.0/8>> | <<internal corporate net>> |
| FQDN | <<vendor.example.com>> | <<third party>> |
| URL | <<https://billing.example.com/*>> | <<separate scope>> |
| Service | <<production payment gateway>> | <<PCI carve-out>> |
| User | <<CEO mailbox>> | <<no social on executives>> |
| Data | <<live customer PII>> | <<use synthetic>> |
| Region | <<Indonesia region except gov scope>> | <<jurisdictional>> |

### 3.3 Dependencies and shared infrastructure

| Dependency | Customer-owned? | Authorisation provided | Notes |
|-----------|-----------------|------------------------|-------|
| AWS shared account | No (managed by parent) | <<Yes/No + ref>> | <<scope-limited role>> |
| CDN (Cloudflare) | No | <<Yes/No>> | bypass via origin-only IP allowlist |
| Identity provider (Okta) | Yes | Yes | dedicated test users |
| Email provider | No (Microsoft 365) | <<Yes/No>> | phishing-tag header `X-Test-SX: <<id>>` |

Where a target is hosted on third-party infrastructure (AWS, GCP, Azure, Cloudflare, etc.) the customer warrants that they have obtained any required separate authorisation (e.g., AWS pentest acknowledgement is automatic since 2019 for standard services; out-of-band notice for non-standard).

---

## 4. Time window

| Field | Value |
|-------|-------|
| Start date and time | <<YYYY-MM-DD HH:MM UTC>> |
| End date and time | <<YYYY-MM-DD HH:MM UTC>> |
| Permitted hours of high-impact testing | <<e.g. weekdays 09:00-17:00 customer local time>> |
| Forbidden windows (blackout) | <<e.g. close-of-month 28-31, holidays>> |
| Continuous monitoring window (low-impact) | <<24/7 if applicable>> |
| Time zone of reference | <<e.g. Asia/Jakarta>> |

### 4.1 Pre-engagement checklist (T-7 to T-0)

| T- | Action | Owner |
|----|--------|-------|
| T-7 | Kick-off call; review RoE; identify approvers | Both |
| T-5 | Customer freezes scope; provides credentials and test accounts | Customer |
| T-3 | SentinelX provisions launch infra; shares source IPs | SentinelX |
| T-2 | Test connectivity (low-noise nmap to one host); confirm allowlist | Both |
| T-1 | Final go/no-go call; sign-off captured in Slack thread | Both |
| T-0 | Engagement starts | SentinelX |

---

## 5. Permitted and prohibited techniques

Mapped to severity classes. Severity refers to the potential blast radius of the technique itself, not the finding.

### 5.1 Severity classes

| Class | Description | Approval | Notification | Two-person rule |
|-------|-------------|----------|-------------|-----------------|
| S0 — Passive | OSINT, certificate transparency, public DNS, public scans (Shodan/Censys), spectrum analysis from public spectrum | Standard RoE | None | No |
| S1 — Low impact | Banner grab, version probe, unauth API enumeration, read-only endpoints, content discovery (low QPS) | Standard RoE | None | No |
| S2 — Active enumeration | Authenticated enumeration, fuzzing under approved QPS, parameter tampering, brute-force on disposable accounts | Standard RoE | Daily summary | No |
| S3 — Exploit (proof) | Single-step exploit of identified vulnerability to confirm presence; no persistence | Tech owner email | Same-day notice | Recommended |
| S4 — Exploit (chained) | Multi-step chain, privilege escalation, lateral movement | Written approval per scope cluster | Pre-action notice | Required |
| S5 — Destructive or high blast radius | DoS test, ransomware simulation, data exfil to controlled bucket, hardware reset, OT/ICS interaction | Executive sign-off (customer CISO or delegate) + legal review | 2h pre-action notice, real-time channel watch | Required + safety officer |

### 5.2 Permitted technique catalogue

| Technique | Class | Default |
|-----------|-------|---------|
| Port scan (TCP SYN, UDP top 200) | S1 | Permitted |
| Vulnerability scanner (Nessus/Qualys/Nuclei) | S1 | Permitted with rate limit 50 rps/host |
| Web application crawl (depth 5) | S1 | Permitted |
| Web application active scan (SQLi/XSS/SSRF probes) | S2 | Permitted |
| Authenticated API fuzz | S2 | Permitted; QPS <= 30 |
| Password spray (3 attempts/account/hour) | S2 | Permitted on test accounts only |
| Phishing simulation (controlled list) | S2-S3 | Permitted with separate consent register |
| Vishing / smishing | S3 | Requires written approval per attempt |
| Vulnerability exploitation (single PoC) | S3 | Permitted with same-day notice |
| Privilege escalation chain | S4 | Requires written approval |
| Lateral movement to in-scope CIDR | S4 | Requires written approval |
| Data exfil (synthetic payload to controlled S3) | S4 | Requires written approval |
| Persistence implants | S4 | Requires written approval; auto-uninstall TTL <= 7 days |
| Physical entry test | S3-S4 | Separate physical RoE addendum |
| Social engineering of named executives | S3-S4 | Requires C-level approval |
| Denial of Service / Stress test | S5 | Off by default; requires S5 process |
| OT/ICS exploitation | S5 | Off by default |
| Ransomware simulation | S5 | Off by default; requires recovery rehearsal |

### 5.3 Prohibited at all times

The following are prohibited absent a separately signed addendum:

- Modifying or destroying production data of real users.
- Deploying real malware or live ransomware (simulation-only with safety tags is permitted under S5).
- Exfiltration of actual customer PII or cardholder data. Use synthetic markers (e.g., `SX-CANARY-<id>`) instead. If real PII is observed mid-exploit, halt and notify within 1 hour.
- Exploitation of third-party systems that are not in scope, even if encountered transitively.
- Any technique on a target in the denylist.
- Any access from a jurisdiction not in the SentinelX operating list without prior approval.
- Public disclosure of findings to non-parties.
- Pivoting beyond the agreed network boundary.

---

## 6. Approval and two-person rule

### 6.1 Approval matrix

| Action | Approver (Customer) | Approver (SentinelX) | Evidence stored |
|--------|--------------------|--------------------|-----------------|
| Engagement start | Tech owner | Engagement lead | Signed kick-off note |
| S3 action | Tech owner (email) | Engagement lead | Email + audit log entry |
| S4 action | CISO or delegate | Engagement lead + Director of Offensive Security | Signed CR ticket |
| S5 action | CISO + CIO + Legal | Director of Offensive Security + Safety Officer | Signed CR + safety brief |
| Scope expansion | CISO | Engagement lead | Amendment |
| Window extension | Tech owner | Engagement lead | Slack-confirmed |
| Out-of-hours work | Tech owner | Engagement lead | Slack-confirmed |
| Emergency stop | Anyone with safe word | Anyone with safe word | Auto-logged |

### 6.2 Two-person rule for active exploitation

Any S4 or S5 action requires two SentinelX operators present in the engagement bridge and acknowledging the action in the audit log. The platform enforces this through:

- `engagement.action_initiate` requires `approver_id != actor_id` and both are members of the engagement role group.
- A 5-second confirm window during which either party can abort.
- An automatic recording of the action including command, target, timestamp and SHA-256 of any payload (hash-chained, TSA-anchored under P1-015).
- The `sx-bas` orchestrator (P1-008 catalogue, P2-015 chain replay) refuses to dispatch a chain step whose mode exceeds the engagement's authorised mode and refuses to dispatch an S5 step without the approval token.

If only one operator is available, the action is queued until a second operator joins; no implicit override.

### 6.4 Platform safety pipeline (defence-in-depth)

Operator discipline is the first line. The platform enforces four additional gates in series, each independently capable of blocking an out-of-bounds action:

1. **Kill switch** (Redis-pubsub broadcast on `sentinelx.killswitch`). Any named contact on either side may trip it from the dashboard, the API (`POST /v1/safety/kill-switch`) or `sx-cli`. Scopes: `global | tenant | engagement | family`. Trip propagation is ≤ 1 s and verified by `sx_killswitch_triggered_total`. Reset requires the two-person rule. See [`../operations/runbook.md`](../operations/runbook.md#4-trip-the-kill-switch-from-cli).
2. **Mode-gate**. The engagement carries an `EngagementMode` (`Passive`, `Active`, `Disruptive`). Every BAS technique declares its minimum mode; dispatch is refused if `technique.required_mode > engagement.mode`. Mode promotion requires a signed change-request in the engagement bridge.
3. **Window gate**. The engagement carries a `time_window` (`start_at`, `end_at`, `permitted_hours`, `forbidden_windows`). The orchestrator wall-clocks every dispatch and refuses outside the window. Out-of-window override requires the customer tech-owner's approval recorded in §6.1.
4. **Active-exploit gating**. Any S3/S4 technique that lands a payload on a target is gated on (a) the engagement having S3/S4 approval recorded, (b) the technique being on the customer's `permitted_techniques` allowlist, and (c) the **mode-gate** above. A BAS chain (P2-015) is rejected as a unit if **any** step fails any gate — partial-chain runs are forbidden.
5. **Two-person approval** for chain runs (see §6.2): the chain is enqueued in a `pending_approval` state and remains there until a second operator approves via `sx-cli bas chain approve <chain-id>`. Approver and actor must differ; both identities are captured in the audit row.

Audit-row contract for every gate hit:

| Gate              | `action`                                        | Severity  |
|-------------------|-------------------------------------------------|-----------|
| Kill switch trip  | `safety.kill_switch_tripped`                    | high      |
| Mode-gate reject  | `bas.dispatch_rejected_mode_gate`               | medium    |
| Window-gate reject| `bas.dispatch_rejected_window_gate`             | medium    |
| Active-exploit reject | `bas.dispatch_rejected_active_exploit_gate` | high      |
| Two-person pending| `bas.chain_pending_approval`                    | low       |
| Two-person reject | `bas.chain_rejected_approver_eq_actor`          | high      |

### 6.3 Safe words

| Word | Meaning | Action |
|------|---------|--------|
| `PAUSE` | Temporary stop; investigate suspected impact | All active probes halt within 60s; standing connections maintained |
| `HALT` | Immediate stop of all active testing | All probes halt; nothing new started; existing implants remain in observe-only |
| `RESET` | Engagement ended early | HALT + begin cleanup (revoke creds, remove implants, restore configs) |
| `WHITE-CARD <id>` | Skip a step (simulate success) | Operator records the white card; no further action on that step |

Safe words may be invoked by any named contact from either party via the engagement bridge (Slack channel, dedicated phone, or in-app safe-word button).

---

## 7. Communication channels and escalation

### 7.1 Channels

| Channel | Purpose | Members |
|---------|---------|---------|
| `#eng-<<id>>` Slack | Day-to-day | Both parties named contacts |
| Daily stand-up call | 15-min status | Tech owner + engagement lead |
| Email distribution | Formal notifications | Both legal + signatories |
| 24/7 incident phone | Emergency | Two numbers per party |
| Engagement dashboard | Live actions and findings | SSO-protected, both parties |
| Status page | High-level health | All stakeholders |

### 7.2 Escalation tree

```
Day-to-day issue
  -> Engagement lead (SX) <-> Tech owner (Cust)        [within 1h]
Material risk to production
  -> + Director Offensive Security (SX) <-> CISO (Cust)  [within 30m]
Suspected real-world breach
  -> + DPO (SX) <-> DPO (Cust) <-> Legal (both)        [within 15m]
  -> Trigger incident response per [PCI DSS section 12](./pci-dss-v4-mapping.md#12-information-security-policy)
Engagement compromise (creds leaked, infra compromised)
  -> Immediate HALT + executive bridge                  [immediate]
```

### 7.3 Status cadence

- **Daily** (during active testing): SentinelX provides written end-of-day note (techniques, findings count by severity, planned next-day).
- **Weekly** (engagements > 1 week): 30-minute review call.
- **Material finding (critical/high)**: Notification within 4h of confirmation.
- **End of engagement**: Wrap-up call within 2 business days.

---

## 8. Reporting cadence and deliverables

### 8.1 Cadence

| Deliverable | Trigger | Format | SLA |
|------------|---------|--------|-----|
| Daily status note | EOD during testing | Markdown in Slack | Same day |
| Critical/High finding flash | Confirmation of severity Critical or High | Email + Slack + portal entry | 4h |
| Mid-engagement readout | T+50% of window if window > 5d | Slides + portal | 1 business day after midpoint |
| Draft report | T+5 business days after engagement end | PDF + portal | T+5 |
| Final report | After customer review (max 10 business days) | PDF + portal | T+15 |
| Executive summary | With final report | 2-page PDF | T+15 |
| Re-test report | Within 30 days of remediation request | PDF | 5 business days from request |

### 8.2 Final report structure

1. Executive summary (one page).
2. Engagement scope and methodology.
3. Risk overview with severity heat map.
4. Findings (per finding, see template below).
5. Strategic recommendations.
6. Re-test plan.
7. Appendices: tools used, IPs/UAs, evidence index, hash list of artefacts.

### 8.3 Finding template

| Field | Value |
|-------|-------|
| ID | `FND-<<engagement>>-<<seq>>` |
| Title | <<short>> |
| Severity | <<Critical/High/Med/Low/Info>> |
| CVSS v4.0 vector | <<vector>> |
| Affected assets | <<list>> |
| Description | <<plain language>> |
| Reproduction | <<numbered steps>> |
| Evidence | <<screenshots, request/response, hash>> |
| Impact | <<technical + business>> |
| Likelihood | <<reasoning>> |
| Recommendation | <<prioritised>> |
| References | <<CWE, OWASP, vendor docs>> |
| Status | <<Open/Fixed/Risk-Accepted>> |

### 8.4 Evidence retention

Evidence is retained in encrypted form by SentinelX for **90 days** after delivery of the final report unless the customer requests earlier destruction. Hash list of all artefacts is delivered with the final report so the customer can verify integrity for the duration of their retention obligations.

---

## 9. Data handling

### 9.1 Classification

| Class | Definition | Handling |
|-------|------------|----------|
| RoE-Public | Information about the engagement that may be shared publicly | Not used in this template; nothing is public by default |
| RoE-Internal | Engagement metadata, methodology | TLS-only, accessible to named contacts |
| RoE-Confidential | Findings, configurations, credentials | TLS + encryption at rest, named contacts only, no third-party share |
| RoE-Restricted | Active exploit chains, real-data observations | Restricted to engagement operators; access logged; auto-purge at T+90d |

### 9.2 Storage and transport

- All engagement artefacts stored in customer-segregated tenant.
- Communications carry the classification label in subject/title.
- File transfer via the engagement portal only; no email attachments above `RoE-Internal`.
- Credentials provided by the customer use one-time secret links or HSM-backed sharing; never plain text in chat or email.

### 9.3 Personal data observed during testing

If personal data (per GDPR or UU PDP) is observed during testing, the operator follows the personal data handling procedure in [docs/runbooks/personal-data-handling.md](../runbooks/) and the DPIA at [GDPR/PDP DPIA section 18](./gdpr-pdp-dpia.md#18-childrens-data-and-vulnerable-subjects). Real personal data is not stored as evidence; observation is recorded as a counted summary instead.

### 9.4 Return and destruction

Within 30 days after final report acceptance:

- Customer artefacts are securely deleted from active systems.
- Encrypted backups follow the standard 90-day rotation and are then crypto-shredded.
- A signed Certificate of Destruction is provided on request.

---

## 10. Legal terms

### 10.1 Authorisation and safe harbour

The Customer hereby authorises SentinelX, its named operators and approved sub-contractors to perform the activities listed in section 5 against the assets listed in section 3, between the dates listed in section 4, in accordance with the techniques permitted by the severity matrix.

Subject to good-faith compliance with this RoE, the Customer agrees not to bring or threaten any civil, criminal, regulatory or administrative action against SentinelX, its operators, sub-contractors or representatives for actions undertaken in scope, in window and in accordance with the agreed severity matrix. This safe harbour extends to claims under computer misuse, data protection (within the parameters of the DPA), and trespass laws of the jurisdictions named in section 10.7.

The safe harbour does not extend to:

- Actions performed outside the scope, time window, or severity matrix.
- Wilful misconduct or gross negligence.
- Public disclosure of findings.
- Activities by individuals not on the operator roster.

### 10.2 Indemnity

SentinelX shall indemnify the Customer for direct damages arising from gross negligence or wilful misconduct of SentinelX operators, up to the aggregate liability cap defined in the MSA. The Customer shall indemnify SentinelX for damages arising from the Customer's incorrect representation of scope ownership or for third-party claims caused by the Customer's failure to obtain required authorisations.

Neither party shall be liable for indirect, incidental, consequential, special or punitive damages, including loss of profit, revenue, anticipated savings, business interruption, or data loss beyond what is recoverable from documented backups.

### 10.3 Insurance

SentinelX maintains cyber liability insurance with a per-claim limit of at least USD <<5,000,000>> and an aggregate of at least USD <<10,000,000>>. Proof of insurance is available on request.

### 10.4 Breach notification

In the event of a confirmed or suspected unauthorised disclosure of Customer data while in SentinelX custody, SentinelX shall notify the Customer's tech owner and DPO within **24 hours** of awareness and provide a written assessment within 72 hours. This is in addition to any regulatory notification obligations under GDPR Art. 33/34 or UU PDP Pasal 46.

### 10.5 Confidentiality

All information disclosed in the course of the engagement is Confidential Information per the MSA. Confidentiality survives termination by 5 years (perpetual for trade secrets). Neither party may name the other in marketing or public statements without prior written consent.

### 10.6 Intellectual property

- Pre-existing IP remains with its owner.
- The final report and findings are licensed to the Customer for internal use, including remediation, audit and re-test purposes.
- Generic tools, frameworks and methodologies developed by SentinelX remain SentinelX IP.
- Customer-specific configurations developed during the engagement (e.g., custom Nuclei templates, fix patches) are jointly owned with reciprocal licence.

### 10.7 Governing law and dispute resolution

| Field | Value |
|-------|-------|
| Governing law | <<e.g. laws of Singapore>> |
| Dispute resolution | <<Singapore International Arbitration Centre (SIAC), one arbitrator, English language>> |
| Seat of arbitration | <<Singapore>> |
| Service of process | At addresses in section 1; email is acceptable secondary |
| Indonesia carve-out (if applicable) | Engagements affecting Indonesian data subjects are also subject to Pengadilan Negeri Jakarta Pusat for matters under UU PDP that cannot be arbitrated. |

### 10.8 Termination

Either party may terminate the engagement on **24 hours notice** for convenience; immediately for material breach. On termination, the cleanup procedures in section 11 apply.

### 10.9 Force majeure

Neither party is in breach for delay caused by events outside its reasonable control, including natural disaster, war, sabotage, government action, or major Internet outage. Notification within 24 hours of occurrence.

### 10.10 Severability and entire agreement

If any provision is held unenforceable, the remainder remains in effect. This RoE, together with MSA and DPA, constitutes the entire agreement for the engagement and supersedes prior discussions.

---

## 11. Cleanup and de-confliction

At engagement end (planned or early termination), SentinelX performs:

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Revoke all SentinelX-issued credentials | Customer disables accounts |
| 2 | Remove all SentinelX-deployed implants, scripts, tooling | Operator checklist + customer scan |
| 3 | Restore any modified config to recorded baseline | Diff log |
| 4 | Disable any test phishing sites and redirect to neutral page | DNS owner confirms |
| 5 | Deliver hash list of all artefacts retained | Email + portal |
| 6 | Mark engagement closed in dashboard | Auto-trigger evidence retention timer |

A Certificate of Engagement Completion is issued within 5 business days listing the above. The customer signs to acknowledge cleanup.

De-confliction with concurrent activities (other vendors, internal red team, SOC drills) is the joint responsibility of both engagement leads; a shared calendar entry in the engagement portal is mandatory.

---

## 12. Acceptance and sign-off

By signing below, both parties confirm:

- They have authority to authorise the activities described.
- They warrant the accuracy of the scope and denylist.
- They have read and accept the severity matrix and approval rules.
- They have reviewed the DPA and incident notification process.
- They acknowledge that the safe harbour applies only to good-faith, in-scope, in-window activity.

### Sign-off table

| Role | Name | Title | Signature | Date |
|------|------|-------|-----------|------|
| Customer authorised signatory | <<Name>> | <<Title>> | _____________________ | <<YYYY-MM-DD>> |
| Customer tech owner | <<Name>> | <<Title>> | _____________________ | <<YYYY-MM-DD>> |
| Customer CISO (S4/S5 actions) | <<Name>> | <<Title>> | _____________________ | <<YYYY-MM-DD>> |
| Customer DPO (if PII in scope) | <<Name>> | <<Title>> | _____________________ | <<YYYY-MM-DD>> |
| SentinelX authorised signatory | <<Name>> | <<Title>> | _____________________ | <<YYYY-MM-DD>> |
| SentinelX engagement lead | <<Name>> | <<Title>> | _____________________ | <<YYYY-MM-DD>> |
| SentinelX Director of Offensive Security | <<Name>> | <<Title>> | _____________________ | <<YYYY-MM-DD>> |

---

## Appendix A. Operator roster

To be filled at T-7. Operators must be SentinelX employees or approved sub-contractors who have signed a personal NDA and completed background checks per the MSA.

| Name | Role | Email | Phone | Background-check date | Source country |
|------|------|-------|-------|----------------------|----------------|
| <<Name>> | Lead | <<email>> | <<phone>> | <<YYYY-MM-DD>> | <<country>> |
| <<Name>> | Operator | <<email>> | <<phone>> | <<YYYY-MM-DD>> | <<country>> |
| <<Name>> | Operator | <<email>> | <<phone>> | <<YYYY-MM-DD>> | <<country>> |
| <<Name>> | Safety Officer | <<email>> | <<phone>> | <<YYYY-MM-DD>> | <<country>> |

---

## Appendix B. Source IPs and identifiers

SentinelX activity may originate from the following identifiers, which the customer may add to allowlists or use for forensic correlation.

| Field | Value |
|-------|-------|
| Source IPv4 ranges | <<list>> |
| Source IPv6 ranges | <<list>> |
| User agents (web) | `SentinelX/<<eng-id>> (operator=<<op-id>>)` |
| Custom headers | `X-SentinelX-Engagement: <<eng-id>>`, `X-SentinelX-Operator: <<op-id>>` |
| Test phishing domains | <<list>> |
| Test malware tag | `SX-SAFE-<<eng-id>>` (no payload effect; signals defenders this is a simulation) |

The customer agrees not to share these identifiers outside the engagement bridge until 30 days after engagement close, to avoid premature disclosure.

---

## Appendix C. Change request template

| Field | Value |
|-------|-------|
| CR ID | `CR-<<engagement>>-<<seq>>` |
| Requested by | <<Name + Party>> |
| Date/time | <<UTC>> |
| Change type | <<Scope / Window / Technique / Approval / Operator roster / Other>> |
| Description | <<plain language>> |
| Risk impact | <<assessment>> |
| Approvers | <<list>> |
| Decision | <<Approved/Denied/Conditional>> |
| Effective from | <<UTC>> |

---

## Appendix D. Glossary

- **RoE** — Rules of Engagement.
- **MSA** — Master Services Agreement.
- **DPA** — Data Processing Addendum.
- **CR** — Change Request.
- **Safe harbour** — agreed protection from legal claims for good-faith in-scope testing.
- **Two-person rule** — high-impact actions require both a primary operator and an independent approver.
- **White card** — agreed simulation of success without performing the action.
- **De-confliction** — coordination among concurrent security activities to avoid false positives or interference.

---

## Appendix E. Document control

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| 1.0 | 2024-08-22 | Engagement Governance | First public template. |
| 2.0 | 2025-04-10 | Engagement Governance | Added S5 class and two-person rule. |
| 3.0 | 2026-01-18 | Engagement Governance | Aligned with new MSA; added UU PDP carve-out. |
| 3.1 | 2026-05-31 | Engagement Governance | Refresh; expanded severity matrix; clarified cleanup. |
| 3.2 | 2026-06-13 | Engagement Governance | Added §6.4 platform safety pipeline (kill-switch + mode-gate + window + active-exploit + two-person); referenced BAS catalogue (P1-008), chain replay (P2-015) and TSA anchoring (P1-015) explicitly. |
