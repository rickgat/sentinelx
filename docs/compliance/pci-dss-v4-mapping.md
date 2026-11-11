# PCI DSS v4.0 Compliance Mapping — SentinelX

**Last reviewed:** 2026-06-13
**Maintainer:** Compliance Office
**Document owner:** Chief Information Security Officer (CISO)
**Applies to:** SentinelX platform, supporting infrastructure, and managed service operators
**Standard version:** PCI DSS v4.0.1 (effective 2025-03-31)
**Review cadence:** Annual ROC, quarterly attestation, on material change
**Cross references:**
- [Security architecture](../architecture.md)
- [GDPR/PDP DPIA](./gdpr-pdp-dpia.md)
- [Engagement RoE template](./engagement-roe-template.md)
- [Operations runbooks](../runbooks/)
- [SLOs](../slos.md)

---

## 1. Purpose and scope

SentinelX processes telemetry from scanners, BAS engines, and customer SIEM bridges. When a customer in scope of PCI DSS routes Cardholder Data Environment (CDE) telemetry through SentinelX (alert metadata, vulnerability records, asset inventories that reference CDE systems), SentinelX falls under PCI DSS as a **third-party service provider (TPSP)**. This document maps each of the twelve PCI DSS v4.0 requirement areas to concrete SentinelX controls, evidence sources, and audit log queries.

In-scope assets:

| Asset class | Examples | CDE adjacency |
|---|---|---|
| Ingestion services | `ingest-api`, `ingest-worker` | Adjacent (may receive CDE asset IDs) |
| Storage backends | `pg-primary`, `clickhouse-events`, `s3-evidence` | Adjacent (stores CDE references) |
| Identity & access | `auth-service`, `rbac-service` | In-scope (controls CDE-adjacent access) |
| Observability | `otel-collector`, `loki`, `prom` | Connected (must not log CHD) |
| Customer integrations | `siem-bridge`, `webhook-fanout` | Connected (egress to customer CDE) |

Out of scope: SentinelX does **not** store Primary Account Numbers (PAN), Sensitive Authentication Data (SAD), or Cardholder Data (CHD). Detection rules and logging policies enforce truncation, masking, and rejection of any payload matching PAN regex (`^(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})$`).

---

## 2. PCI DSS v4.0 — Requirement-by-requirement mapping

### Requirement 1 — Install and maintain network security controls

**Objective:** Restrict inbound and outbound traffic to/from the CDE.

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 1.2.1 | Network segmentation enforced via Cilium NetworkPolicy + AWS Security Groups | `infra/k8s/policies/netpol-default-deny.yaml`, `infra/terraform/sg/*.tf` |
| 1.2.5 | Allowed ports/services documented in `network-baseline.md`; deviations require CR approval | `docs/security/network-baseline.md` |
| 1.2.6 | Insecure protocols (telnet, FTP, SMBv1) blocked at egress firewall | `infra/firewall/egress-deny.json` |
| 1.3.1 | Inbound traffic to CDE limited to documented services; default-deny posture | NetworkPolicy + WAF rules |
| 1.3.2 | Outbound traffic from CDE explicitly authorized | Egress policy `egress-cde-allowlist.yaml` |
| 1.4.2 | Anti-spoofing measures: RPF, BGP route validation | Edge router config |
| 1.4.5 | NAT and other obfuscation between trusted and untrusted | Terraform NAT gateway config |

**Audit log queries:**
```promql
# Denied egress to non-allowlisted destinations
sum by (destination_ip) (rate(cilium_drop_count_total{reason="policy-deny"}[24h]))
```
```sql
-- Firewall changes in last 90 days
SELECT actor, change_summary, change_ts
FROM audit_log
WHERE component IN ('netpol','sg','waf')
  AND change_ts > now() - INTERVAL '90 days'
ORDER BY change_ts DESC;
```

---

### Requirement 2 — Apply secure configurations to all system components

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 2.2.1 | Hardened baseline images via Packer + CIS benchmark profile | `infra/packer/ubuntu-22-cis.json` |
| 2.2.2 | Vendor defaults removed/changed before deployment; tracked in CMDB | `cmdb.assets` table, field `vendor_default_removed_at` |
| 2.2.4 | Only necessary services enabled; verified by daily Lynis scan | `evidence/lynis/<host>/<date>.json` |
| 2.2.5 | Insecure services (rsh, tftpd) explicitly disallowed by Ansible role | `ansible/roles/hardening/tasks/disable-insecure.yml` |
| 2.2.6 | System security parameters (sysctl, auditd) baseline enforced | `ansible/roles/hardening/files/sysctl-cis.conf` |
| 2.3.1 | Console & remote admin access via SSH with key auth only; password auth disabled | `/etc/ssh/sshd_config` baseline |
| 2.3.2 | Wireless admin disabled | Hardware procurement spec, no Wi-Fi NICs |

**Evidence query:**
```sql
SELECT host, baseline_version, lynis_score, last_scan_at
FROM cmdb.host_compliance
WHERE in_scope_pci = true AND lynis_score < 85;
-- Expect: 0 rows
```

---

### Requirement 3 — Protect stored account data

SentinelX **does not store CHD**. This requirement is satisfied through prevention controls.

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 3.2.1 | Data retention policy explicitly forbids PAN/SAD; ingestion-level reject | `policies/data-classification.md` |
| 3.3.1 | PAN never displayed; truncation at ingress via `ingest-api` middleware | `services/ingest-api/src/middleware/pan_scrub.rs` |
| 3.4.1 | If a PAN slips through, it is hashed (HMAC-SHA-256) and original record quarantined | `services/quarantine/src/handlers/pan_detected.rs` |
| 3.5.1 | Multi-cloud KEK providers: AWS KMS (P1-005), GCP Cloud KMS (P1-006), Azure Key Vault (P1-007). DEK envelope per tenant. All three share `sx-secrets::kek::KekProvider` trait. | `crates/sx-secrets/src/kek/{aws,gcp,azure}.rs`; KEK ARNs in `terraform/kms/*.tf` |
| 3.6.1 | Key generation, distribution, storage, rotation procedures documented | `docs/operations/runbook.md#8-rotate-the-kek-per-provider` |
| 3.7.x | Annual DEK rotation, 3-year KEK rotation; each rotation emits `secrets.kek_rotated` audit row carrying old + new version IDs and operator | `evidence/kms/rotation-<year>.pdf`; chain-anchored, TSA-signed (P1-015) |

**Audit query — PAN detection events:**
```sql
SELECT count(*) AS detections, date_trunc('day', detected_at) AS day
FROM quarantine.pan_events
WHERE detected_at > now() - INTERVAL '90 days'
GROUP BY day ORDER BY day;
-- Expect: low single digits, all reviewed.
```

---

### Requirement 4 — Protect cardholder data with strong cryptography during transmission

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 4.2.1 | TLS 1.3 enforced on all public endpoints; TLS 1.2 minimum for legacy; SSL/early-TLS denied | `infra/ingress/tls-policy.yaml`, NGINX `ssl_protocols` directive |
| 4.2.1.1 | Inventory of certificates with expiry tracking | `cmdb.certificates`, alert on <30 days |
| 4.2.2 | PAN never sent via email/SMS/IM — enforced inline by **`sx-dlp` content inspection (P2-006)**. 12+ detectors include PAN (Luhn-validated), IBAN, US SSN, ID-NIK, JWT, AWS access keys, OAuth secrets and named-entities. Match emits hash-of-span + class only; plaintext never persisted. | `crates/sx-dlp/src/detectors/*.rs`; snapshot tests in `crates/sx-dlp/tests/fixtures/` |

**Evidence:**
- Quarterly Qualys SSL Labs scan against external endpoints → must score A or better.
- mTLS between internal services validated via Istio policy `peer-authentication-strict.yaml`.

```bash
# Validation command
sslyze --regular ingest.sentinelx.io,api.sentinelx.io,console.sentinelx.io > evidence/sslyze/$(date +%F).txt
```

---

### Requirement 5 — Protect all systems and networks from malicious software

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 5.2.1 | Anti-malware deployed on all in-scope hosts (CrowdStrike Falcon) | `cmdb.endpoint_protection` view |
| 5.2.2 | Real-time scanning + weekly full scan | Falcon policy ID `pci-fullscan-weekly` |
| 5.3.1 | Anti-malware engine + sigs auto-updated daily | Falcon update telemetry → Loki |
| 5.3.4 | Anti-malware logs forwarded to SentinelX SIEM ingestion | `falcon-streaming-api` source |
| 5.4.1 | Anti-phishing controls: DMARC `p=reject`, SPF strict, MTA-STS | DNS records exported in `evidence/dns/<date>.zone` |

**Audit query:**
```sql
SELECT host, days_since_last_scan
FROM cmdb.endpoint_protection
WHERE in_scope_pci = true AND days_since_last_scan > 7;
-- Expect: 0 rows
```

---

### Requirement 6 — Develop and maintain secure systems and software

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 6.2.1 | Bespoke and custom software developed per SecSDLC | `docs/security/sdlc.md` |
| 6.2.2 | Developers complete annual secure-coding training (OWASP Top 10 + ASVS) | `training/records/<year>.csv` |
| 6.2.3 | All code reviewed pre-merge by ≥1 peer + 1 security-bot approval | GitHub branch protection on `main` |
| 6.2.4 | Coding standards address: injection, broken auth, XSS, deserialization, SSRF | `.clippy.toml`, `eslint.security.json`, `bandit.yaml` |
| 6.3.1 | Vulnerabilities identified via **`sx-vuln-ingest` (P0-002)** — pulls from internal scanners, customer-supplied feeds, and SBOMs — joined with **NVD + CISA KEV (P0-006)** for exploit-in-the-wild signal. Severity tier mapped to CVSS v3.1; KEV-listed vulns auto-promoted to CRITICAL. | `crates/sx-vuln-ingest/src/*.rs`; CI artifacts in `evidence/ci/<run-id>/` |
| 6.3.2 | Inventory of bespoke software components | SBOM `sbom/spdx-<release>.json` produced + cosign-attested per release |
| 6.3.3 | Patch critical CVEs within 30 days; KEV-listed within 7 days | Tracked in `vuln_management.findings`; SLA enforced by remediation outcomes (P1-011) |
| 6.4.1 | Public-facing apps protected by WAF (AWS WAF + custom rules) | `terraform/waf/*.tf` |
| 6.4.2 | Annual + post-change pentests of public apps | See Requirement 11; ref `engagement-roe-template.md` |
| 6.5.1 | Change control: PR + approval + change ticket + post-deploy verification | Linear/Jira workflow `CHG-` |

---

### Requirement 7 — Restrict access by business need to know

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 7.2.1 | Access control model: RBAC + ABAC; documented per service | `docs/security/rbac.md` |
| 7.2.2 | Least privilege enforced; quarterly access reviews | `evidence/access-review/q<n>-<year>.xlsx` |
| 7.2.3 | Default-deny for all roles; explicit grants only | `auth-service/policies/*.cedar` |
| 7.2.4 | User access reviewed at least every six months | Cadence: quarterly (exceeds minimum) |
| 7.2.5 | Application/system accounts least privilege | `service-accounts.yaml` inventory |
| 7.2.6 | Direct DB access by users limited to break-glass; logged + alerted | `pg_audit` rules + Slack #sec-alerts |

**Audit query:**
```sql
SELECT user_id, role, granted_at, last_used_at
FROM rbac.assignments
WHERE last_used_at < now() - INTERVAL '90 days'
  AND role NOT IN ('break-glass');
-- Candidates for revocation; reviewed quarterly.
```

---

### Requirement 8 — Identify users and authenticate access to system components

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 8.2.1 | All users assigned unique IDs; shared accounts prohibited | `auth-service` user table |
| 8.2.2 | Group/shared/generic accounts only with documented exception | None exist currently |
| 8.2.4 | Lifecycle managed via SCIM from Okta (joiner/mover/leaver) | SCIM logs in `loki` |
| 8.3.1 | Strong authentication: **passwordless WebAuthn (P1-002)** as primary, plus risk-based authentication **(P1-003)** for step-up. PIV for admins. | `crates/sx-iam/src/webauthn/*.rs`, `crates/sx-rba/src/*.rs` |
| 8.3.6 | Passwords (where used): ≥12 chars, complexity, history 4 | Okta password policy `pci-admins`; verified weekly by P1-004 collector `SX-AWS-IAM-PASSWORD-POLICY` |
| 8.3.9 | If password is the only factor — rotated every 90 days **or** continuous risk-based auth | WebAuthn + RBA — rotation N/A per CC-001 |
| 8.4.1 | MFA required for all access to CDE | WebAuthn-mandatory tenant policy; verified weekly by P1-004 collector `SX-MFA-ENROLLMENT-RATE` |
| 8.4.2 | MFA required for all administrative access | Same; RBA threshold lowered for admin scopes via `risk_policies` |
| 8.4.3 | MFA required for all remote access from outside corp network | Device-trust posture middleware **(P2-008)** rejects requests from un-attested endpoints regardless of MFA status |
| 8.5.1 | MFA implementation resistant to replay (FIDO2 / WebAuthn) | WebAuthn `authenticatorData` includes signature counter; replay detected by `sx-iam` increments check |
| 8.6.x | Application/system account authentication via short-lived tokens (OIDC + SPIFFE/SPIRE) | `spire-server` deployment |

---

### Requirement 9 — Restrict physical access to cardholder data

SentinelX runs on AWS (us-east-1, ap-southeast-3) and a co-located DC in Jakarta (IDC). PCI DSS physical controls are inherited.

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 9.1.x | AWS / IDC physical controls inherited | AWS PCI AoC, IDC PCI AoC in `evidence/aoc/` |
| 9.2.x | Visitor access to IDC racks logged + escorted | IDC visitor log monthly export |
| 9.3.x | Personnel access to IDC requires biometric + badge | IDC access reports |
| 9.4.x | Media (backup tapes) — N/A, all backups in S3 with KMS | Backup policy `backups.md` |
| 9.5.x | POI devices — N/A (SentinelX does not handle payment devices) | Statement of non-applicability |

---

### Requirement 10 — Log and monitor all access to system components and cardholder data

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 10.2.1 | Audit logs enabled for all in-scope components; events emitted into the **OCSF 1.1 pipeline (P0-003)** by every `sx-*` crate via `sx-audit::RecordAuditEventUseCase` | `crates/sx-audit/src/*.rs`; ClickHouse `events_ocsf` |
| 10.2.1.1 | All individual user access to CHD — N/A (no CHD) | DLP **(P2-006)** enforces; PAN-matching payloads rejected at ingress |
| 10.2.1.2 | All admin actions logged | `sx-iam` emits `admin.*` to OCSF; hash-chained in `sx-audit` |
| 10.2.1.3 | All access to audit logs logged | `audit-reader` role; reads recorded as `audit.read` chain entries |
| 10.2.1.4 | All invalid login attempts | `iam.login.fail` audit row + RBA event row (P1-003) |
| 10.2.1.5 | All changes to identification/authentication mechanisms | RBAC changes emit `iam.permission_changed`; WebAuthn cred lifecycle emits `iam.webauthn_*` |
| 10.2.1.7 | Creation/deletion of system-level objects | Terraform Cloud audit; K8s admission analyzer (P2-014) admits/denies recorded |
| 10.2.2 | Each log entry captures: user, event type, date/time, success/fail, origin, affected resource | Schema enforced (OCSF 1.1 `events_ocsf`); `sx-audit::AuditAction` is `#[non_exhaustive]` |
| 10.3.x | Log access restricted (read = `security-analyst`, modify = nobody) | RBAC role definitions; Postgres FORCE-RLS prevents direct table access |
| 10.4.1 | Log review (automated) for in-scope systems daily | KQL/SPL hunts (P3-006) over `events_ocsf`; alert → PagerDuty |
| 10.5.1 | Logs retained ≥12 months; 3 months immediately accessible | Audit chain rows kept 7 years in Postgres; WORM evidence bundles (P1-004) under S3 Object Lock COMPLIANCE mode, 7-year retention |
| 10.5.x | Tamper-evident logging | **Hash-chained audit log (`sx-audit::chain`) anchored to RFC 3161 TSA every N entries (P1-015)**; `category=BROKEN_CHAIN` CRITICAL fires within 5 min of any verification failure | `crates/sx-audit/src/chain.rs`, `crates/sx-audit/src/tsa.rs` |
| 10.6.1 | Time synchronization via chrony to redundant NTP | `chrony.conf` baseline |
| 10.7.x | Failures of critical security control systems alert within 24h | Prom alert `SecurityControlFailure`; P1-004 evidence collector `SX-AUDIT-CHAIN-INTEGRITY-VERIFY` runs daily |

**Audit log queries:**
```sql
-- 10.2.1.4 invalid login attempts last 24h
SELECT user_id, count(*) AS attempts
FROM audit_log
WHERE event_type = 'auth.login.fail'
  AND occurred_at > now() - INTERVAL '24 hours'
GROUP BY user_id
HAVING count(*) > 5;
```
```sql
-- 10.7 detection of log forwarding failure
SELECT host, last_heartbeat_at
FROM logging.forwarder_health
WHERE last_heartbeat_at < now() - INTERVAL '5 minutes';
```

---

### Requirement 11 — Test security of systems and networks regularly

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 11.2.1 | Wireless — N/A (no wireless in CDE); quarterly scan attests | `evidence/wireless-scan/q<n>.pdf` |
| 11.3.1 | Internal vulnerability scans quarterly + after significant change | `evidence/vulnscan/internal/q<n>.csv` |
| 11.3.2 | External vulnerability scans by ASV quarterly | `evidence/vulnscan/asv/q<n>.pdf` |
| 11.4.1 | External penetration test annually + after significant change | `evidence/pentest/<year>-external.pdf`; RoE in `engagement-roe-template.md` |
| 11.4.2 | Internal penetration test annually | `evidence/pentest/<year>-internal.pdf` |
| 11.4.3 | Test segmentation controls annually | `evidence/segmentation-test/<year>.pdf` |
| 11.5.1 | IDS/IPS deployed at perimeter and CDE boundary; runtime detection in-pod via **Falco (P2-016)** with OCSF normalisation and HMAC-authenticated webhook ingestion | Suricata cluster + `crates/sx-runtime` |
| 11.5.2 | Change-detection on critical files. For the SentinelX platform itself, **the audit chain + RFC 3161 TSA anchoring (P1-015)** is the file-integrity-monitoring equivalent: every config and policy mutation is hash-chained and externally anchored, so any tamper is detected by chain verification rather than by file hashes. Legacy host paths still monitored via osquery FIM. | `crates/sx-audit/src/chain.rs`, `crates/sx-audit/src/tsa.rs`; `osquery/queries/fim.sql` |
| 11.6.1 | Detect and respond to unauthorized changes on payment pages — N/A | Statement of non-applicability |

---

### Requirement 12 — Support information security with organizational policies and programs

| Sub-req | SentinelX control | Evidence pointer |
|---|---|---|
| 12.1.1 | Comprehensive infosec policy reviewed annually | `policies/infosec-policy.md` |
| 12.2.1 | Risk assessment annual + on material change | `evidence/risk-assessment/<year>.xlsx` |
| 12.3.1 | Targeted risk analyses for controls allowing flexibility (e.g., custom approach) | `evidence/tra/<control-id>.md` |
| 12.3.3 | Cryptographic cipher inventory + monitoring | `crypto-inventory.yaml` |
| 12.4.1 | Executive accountability for PCI compliance | CISO charter signed by CEO |
| 12.5.1 | Inventory of in-scope system components | `cmdb.assets WHERE in_scope_pci = true` |
| 12.5.2 | PCI scope confirmed annually | Scoping doc `evidence/scoping/<year>.md` |
| 12.6.1 | Security awareness training on hire + annually | `training/records/<year>.csv` |
| 12.7.1 | Personnel screening prior to hire (background check) | HR records |
| 12.8.1 | List of TPSPs with which CHD is shared | `tpsp-register.md` |
| 12.8.2 | Written agreement with each TPSP acknowledging PCI responsibilities | DocuSign vault folder `PCI-TPSP` |
| 12.8.3 | Process to engage TPSPs incl. due diligence | `procurement/security-questionnaire.md` |
| 12.8.4 | Monitor TPSPs' PCI compliance status annually | `tpsp-register.md` columns `aoc_received`, `aoc_expires_at` |
| 12.10.1 | Incident response plan reviewed annually + tested. Four canonical **IR playbooks (P3-004)** baked into the platform: ransomware, data-exfiltration, credential-compromise, insider — each implementing NIST 800-61 lifecycle (Prepare / Detect / Contain / Eradicate / Recover / Post-Incident). | `crates/sx-ir-playbooks/src/playbooks/*.rs`; `runbooks/incident-response.md` |
| 12.10.2 | IR plan covers: roles, contacts, escalation, legal, communications | Yes — see plan and `runbooks/breach-notification.md` |
| 12.10.5 | Detection alerts trigger IR | PagerDuty integration; auto-promotion rules in `runbooks/incident-response.md` |

---

## 3. Annual Report on Compliance (ROC) — structure & evidence index

The ROC follows the official PCI SSC template. For each section we identify a primary owner, expected evidence artefact, and the location.

| ROC section | Owner | Evidence artefact | Location |
|---|---|---|---|
| 1. Executive Summary | CISO | Narrative + scope diagram | `evidence/roc/<year>/01-exec-summary.docx` |
| 2. Description of Scope | Compliance Lead | Asset inventory export | `evidence/roc/<year>/02-scope-inventory.csv` |
| 2.1 Network diagrams | Network Eng | Updated diagrams | `evidence/roc/<year>/02.1-network.pdf` |
| 2.2 Dataflow diagrams | Architecture | DFDs marking CHD-adjacency | `evidence/roc/<year>/02.2-dfd.pdf` |
| 3. Sampling | QSA | Sampling methodology | QSA artefact |
| 4. Findings & observations per requirement 1–12 | Compliance | This document + per-control evidence | `evidence/roc/<year>/04-findings/r<1..12>.md` |
| 5. Compensating controls worksheets | CISO | See §5 below | `evidence/roc/<year>/05-comp-controls.xlsx` |
| 6. Attestation of Compliance (AoC) | CEO + CISO | Signed AoC | `evidence/aoc/sentinelx-<year>.pdf` |

### Section-by-section evidence harvest queries

Run these queries 30 days before QSA on-site to assemble the evidence pack.

```sql
-- Requirement 7/8: privileged accounts last review
SELECT role, max(reviewed_at) AS last_review
FROM rbac.access_reviews
GROUP BY role
HAVING max(reviewed_at) < now() - INTERVAL '180 days';
-- Expect: empty.
```

```sql
-- Requirement 10: log retention sufficiency
SELECT min(occurred_at) AS oldest_log_in_hot_tier
FROM audit_log;
-- Expect: oldest <= now() - INTERVAL '12 months'.
```

```bash
# Requirement 11.3.2 ASV scan freshness
ls -la evidence/vulnscan/asv/ | awk '{print $9}' | tail -5
# Expect: 4 PDFs within last 365 days, latest within 90 days.
```

---

## 4. Quarterly Attestation Template

Used internally each quarter (and externally when contractually required). Filed in `evidence/quarterly-attestation/q<n>-<year>.md`.

```
# SentinelX Quarterly PCI DSS Attestation — Q<n> <year>

Reporting period: <YYYY-MM-DD> to <YYYY-MM-DD>
Prepared by: <Compliance Lead>
Reviewed by: <CISO>
Date submitted: <YYYY-MM-DD>

## 1. Scope confirmation
- In-scope assets count: <n>
- Change since last quarter: <+a / -b>
- Material scope change (Y/N): <>
- If Y, describe: <>

## 2. Control health summary
| Requirement | Status | Open findings | Comments |
|-------------|--------|---------------|----------|
| 1. NSC      | Green  | 0             |          |
| 2. Secure config | Green | 1 (low) | <ID, ETA> |
| 3. Stored data | N/A | — | No CHD stored |
| 4. Transmit | Green  | 0             |          |
| 5. Malware  | Green  | 0             |          |
| 6. Secure SDLC | Amber | 2 (mid)   | <IDs>    |
| 7. Access   | Green  | 0             |          |
| 8. Identity | Green  | 0             |          |
| 9. Physical | Inherited | — | AWS / IDC AoCs current |
| 10. Logging | Green  | 0             |          |
| 11. Testing | Green  | 0             |          |
| 12. Policy  | Green  | 0             |          |

## 3. Scans & tests completed this quarter
- Internal vuln scan: <date>, <findings_count>
- External ASV scan: <date>, <pass/fail>
- Penetration test (if scheduled): <date>, <ref>
- Segmentation test (if scheduled): <date>, <ref>
- IR tabletop (if scheduled): <date>

## 4. Incidents and breaches
- Incidents triggering PCI obligations: <n>
- Card-brand notifications sent: <n>
- See: runbooks/incident-response.md

## 5. Personnel & training
- New hires in scope: <n>; onboarding security training complete: <n/n>
- Annual refresher completion rate: <%>

## 6. Open compensating controls
| Comp control ID | Original req | Status | Next review |
|-----------------|--------------|--------|-------------|

## 7. Sign-off
- Compliance Lead: __________________ Date: __________
- CISO: ____________________________ Date: __________
```

---

## 5. Compensating controls register

A compensating control is permitted only when a stated requirement is impractical due to documented business or technical constraint, and an equal-or-greater control achieves the same intent.

### Register

| ID | Original req | Constraint | Compensating control | Equivalence rationale | Status | Owner | Next review |
|----|--------------|------------|----------------------|-----------------------|--------|-------|-------------|
| CC-001 | 8.3.9 (90-day password rotation for non-MFA) | All admin auth uses WebAuthn — passwords not the only factor | Continuous risk-based auth via Okta ThreatInsight + hardware FIDO2 keys | Replay-resistant, phishing-resistant; exceeds rotation goal | Active | CISO | 2026-12-01 |
| CC-002 | 3.5.1 (key on HSM) for legacy ingestion key (`legacy-ingest-2021`) | Key embedded in deprecated agent v0.9; migration ETA 2026-Q4 | Key wrapped under KMS CMK, decrypted in-memory only, rotated every 30 days, agent path EOL'd | Reduces exposure window; usage monitored | Active until 2026-Q4 | Platform Lead | 2026-09-01 |
| CC-003 | 11.5.2 (FIM on all critical files) on serverless functions | Lambda runtime is ephemeral; FIM not applicable | Code provenance via Sigstore + SBOM diff per deploy + runtime read-only FS | Equal change-detection assurance | Active | DevSecOps | 2027-01-15 |

### Compensating Control Worksheet template

```
Compensating Control Worksheet — CC-<NNN>

1. Constraint
   Describe the legitimate technical or documented business constraint preventing the
   stated requirement from being met as written.

2. Objective of original requirement
   State the security intent (not just the literal text).

3. Identified risk
   What risk arises from not meeting the requirement as written.

4. Definition of compensating control(s)
   Describe controls in place, with diagrams/configs.

5. Validation of compensating controls
   Describe how the controls were tested. Provide test results & dates.

6. Maintenance
   Describe how the controls are monitored and reviewed.
```

---

## 6. Self-assessment checklist

Use before any external audit. Mark each item Pass / Fail / N/A and attach evidence link.

- [ ] Scope diagram refreshed (≤ 90 days)
- [ ] Asset inventory `in_scope_pci=true` reconciled with CMDB and Terraform state
- [ ] Network and dataflow diagrams updated
- [ ] All in-scope hosts show Lynis score ≥ 85
- [ ] All in-scope hosts show Falcon last-scan ≤ 7 days
- [ ] All in-scope hosts show OS patch level within 30 days of vendor release for critical CVEs
- [ ] SSL Labs grade A or better on every public endpoint
- [ ] No `tls1.0` or `tls1.1` ciphers offered anywhere
- [ ] Quarterly internal vuln scan completed and findings triaged
- [ ] Quarterly ASV scan completed and passed
- [ ] Annual external pentest completed; criticals remediated within 30 days
- [ ] Annual internal pentest completed
- [ ] Annual segmentation test completed
- [ ] All admin access requires phishing-resistant MFA (FIDO2)
- [ ] Quarterly access review signed off
- [ ] Audit logs ingested from every in-scope service in last 24h
- [ ] Audit log retention ≥ 12 months verified by query
- [ ] Time sync (chrony) healthy on all in-scope hosts
- [ ] IDS/IPS rules updated within last 30 days
- [ ] Security awareness training completion ≥ 95% in last 12 months
- [ ] Incident response tabletop exercise completed in last 12 months
- [ ] TPSP register reviewed; all AoCs unexpired
- [ ] No open critical findings older than 30 days
- [ ] No open high findings older than 90 days
- [ ] Compensating controls register reviewed
- [ ] All policies reviewed in last 12 months

---

## 7. Sample SAQ-D (Service Provider) — illustrative answers

> SAQ-D is the full self-assessment used by service providers. The answers below are **template responses** for common questions — they must be re-verified each cycle and tailored to current state.

### Section A — Information about the assessment

| Field | Answer |
|---|---|
| Company name | SentinelX, PT (Indonesia) + SentinelX, Inc. (Delaware) |
| URL | https://sentinelx.io |
| Contact | compliance@sentinelx.io |
| QSA company (if applicable) | <QSA name> |
| Type of service | Managed detection, BAS, vulnerability orchestration |
| Number of in-scope locations | 3 (AWS us-east-1, AWS ap-southeast-3, IDC Jakarta) |
| Number of in-scope payment channels | 0 — SentinelX does not process, store, or transmit CHD |
| If TPSP, services provided to clients | Security telemetry processing; CHD-adjacent metadata only |

### Section B — Self-Assessment (selected requirements)

**Req 1.2.1 — Are there configuration standards for network security controls?**
- Answer: **Yes**.
- Evidence: `docs/security/network-baseline.md`, `infra/k8s/policies/`, `infra/terraform/sg/`.

**Req 2.2.1 — Are configuration standards developed, implemented, and maintained for all system component types?**
- Answer: **Yes**.
- Evidence: Packer + Ansible hardening roles; Lynis evidence in `evidence/lynis/`.

**Req 3.2.1 — Account data storage is kept to a minimum?**
- Answer: **Yes — no PAN or SAD stored.** Ingress middleware rejects PAN-matching payloads; quarantine pipeline + automated review.
- Evidence: `services/ingest-api/src/middleware/pan_scrub.rs`; quarantine logs.

**Req 4.2.1 — Strong cryptography and security protocols implemented?**
- Answer: **Yes**. TLS 1.3 default, TLS 1.2 minimum; SSL/early-TLS forbidden.
- Evidence: NGINX/Envoy configs; quarterly SSL Labs reports.

**Req 6.3.1 — Vulnerabilities identified and managed?**
- Answer: **Yes**. SCA (Trivy, OSV), SAST (Semgrep), DAST (ZAP) in CI; findings tracked in Jira project `VULN`.
- Evidence: CI artefacts; Jira export.

**Req 8.4.1 — MFA implemented for all access into the CDE?**
- Answer: **Yes — FIDO2/WebAuthn**.
- Evidence: Okta MFA group `cde-access` membership export; auth-service audit log.

**Req 10.5.1 — Audit log history retained for at least 12 months?**
- Answer: **Yes**. 12 months online + 36 months archive.
- Evidence: S3 lifecycle policy; sample query above.

**Req 11.4.1 — External penetration testing performed at least annually?**
- Answer: **Yes**. Annual + post material change.
- Evidence: `evidence/pentest/<year>-external.pdf`; engagement governed by `engagement-roe-template.md`.

**Req 12.10.1 — Incident response plan in place and ready to be activated?**
- Answer: **Yes**.
- Evidence: `runbooks/incident-response.md`; tabletop minutes.

### Section C — Compensating controls

See §5 above.

### Section D — Explanation of non-applicability

| Req | Reason for N/A |
|---|---|
| 3.x (storage of CHD) | SentinelX does not store CHD; ingress prevents. |
| 9.5.x (POI devices) | SentinelX does not handle payment devices. |
| 11.6.1 (payment page change detection) | SentinelX does not host payment pages. |

---

## 8. Change history

| Date | Author | Change |
|---|---|---|
| 2026-05-30 | Compliance Office | Initial issue mapped to PCI DSS v4.0.1 |
| 2026-06-13 | Compliance Office | Updated mappings to reference SentinelX-delivered capabilities: multi-cloud KMS KEK providers (P1-005 AWS / P1-006 GCP / P1-007 Azure) at Req 3.5.1; DLP content inspection (P2-006) at Req 4.2.2; vuln-ingest (P0-002) + NVD/KEV (P0-006) at Req 6.3.1/6.3.3; WebAuthn (P1-002) + RBA (P1-003) + device-trust (P2-008) across Req 8.x; OCSF 1.1 pipeline (P0-003), hash-chained audit + RFC 3161 TSA anchoring (P1-015), WORM evidence retention (P1-004) across Req 10.x; Falco runtime (P2-016) + audit-chain-as-FIM at Req 11.5.x; IR playbooks (P3-004) at Req 12.10.x. |

---

## 9. Related references

- PCI DSS v4.0.1 (PCI SSC, 2024-06)
- PCI DSS v4.0 Customised Approach Sample Templates (PCI SSC, 2024)
- AWS PCI DSS Responsibility Summary
- ISO/IEC 27001:2022 — control overlap map (internal, `evidence/iso/27001-overlap.xlsx`)
- [SentinelX GDPR & Indonesia PDP DPIA](./gdpr-pdp-dpia.md)
- [SentinelX Engagement RoE Template](./engagement-roe-template.md)
