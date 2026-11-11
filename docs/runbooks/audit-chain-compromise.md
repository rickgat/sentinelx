# Audit Hash-Chain Compromise — Operational Runbook (CRIT-002)

**Severity:** CRITICAL — invalidates SOC 2 Type II audit trail trust
boundary. Triggers GDPR Art. 33 (72h) and Indonesia PDP UU 27/2022 §46
(24h) regulator notification clocks.

**Scope:** This runbook governs the first 15 minutes of response when the
`sx-audit` background chain verifier emits an `audit.chain.broken`
event and the auto-fire pipeline opens the `audit_chain_compromise` IR
playbook.

**Owner:** Incident Commander on-call. Co-owners: Forensics Lead, Data
Protection Officer (DPO), Infrastructure Lead.

---

## 0. Pre-conditions (Preparation)

Before any incident fires, the following MUST be true. The
`prep-tsa-cert-validity`, `prep-last-good-baseline`, and
`prep-oncall-rotation` steps of the playbook re-verify them at fire
time.

| Item                                  | Where to check                                                                  |
|---------------------------------------|---------------------------------------------------------------------------------|
| TSA cert validity                     | `GET /v1/audit/anchors?limit=1` → `tsa_cert_serial`, then OCSP                  |
| Pinned CA cert reachable              | `audit.chain.pinned_ca_pem` in config; checksum vs. `audit_anchor_runs.expected_ca_fp` |
| On-call rotation                      | PagerDuty schedule "sentinelx-ir-primary"                                       |
| Outside legal counsel reachable       | `comms_tree.legal_counsel.phone` (encrypted vault)                              |
| Forensics S3 bucket Object-Lock = ON  | `aws s3api get-object-lock-configuration --bucket sentinelx-forensics`         |

---

## 1. T+0 — Detection confirmed (Detection & Analysis)

The verifier already re-verified the chain when it emitted
`audit.chain.broken`. Confirm independently:

```bash
# Re-export the hot tail (last 24h) and re-verify off-box.
sx-cli audit dump --tenant <TENANT_ID> --to /tmp/break.ndjson
sx-cli audit verify \
    --signing-key-env SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER \
    --source /tmp/break.ndjson \
    --json | tee /tmp/break.report.json

# Confirm via the last TSA anchor too. If this verify ALSO fails the
# tamper extends beyond the hot tail.
LAST_RUN=$(curl -s "$API/v1/audit/anchors?limit=1" | jq -r '.items[0].run_id')
curl -X POST "$API/v1/audit/anchors/verify/$LAST_RUN"
```

Capture the failing `(seq, expected_hash, actual_hash)` triple from the
JSON output. This is the structured payload that already populated the
auto-fired incident's `prep-tsa-cert-validity` evidence list.

**Decision tree:**

| Re-verify result          | Anchor verify result   | Action                                              |
|---------------------------|------------------------|-----------------------------------------------------|
| Fails at same seq          | Fails                  | Escalate to **EXEC** + outside counsel immediately. Chain compromise extends past last anchor. |
| Fails at same seq          | Succeeds               | Tamper is within the hot tail only. Continue runbook normally. |
| Succeeds (false positive)  | n/a                    | Mark incident `Skipped` with reason; file a verifier bug; do NOT close the incident until RCA confirms. |

**Start the regulator clock (`detect-start-regulator-timer`).** The DPO
records `t0` in the incident — this is the moment `chain_verified=false`
was *confirmed by an operator*, not the moment the verifier first emitted
the event. GDPR 72h and PDP 24h windows both start at `t0`.

---

## 2. T+5 — Containment

### 2.1 Trip the kill switch

```bash
curl -X POST "$API/v1/safety/kill-switch" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"reason": "audit_chain_compromise", "incident_id": "<INCIDENT_ID>"}'
```

The kill switch halts every active engagement, BAS run, and autonomous
remediation across the tenant. Confirm with `GET /v1/safety/kill-switch`
(should report `tripped=true`).

### 2.2 Freeze audit writes

```bash
# Use the admin API (preferred); falls back to direct env override on
# the monolith deployment if the API is also affected.
curl -X POST "$API/v1/admin/feature-flags/audit_writes_frozen" \
     -d '{"enabled": true, "reason": "<INCIDENT_ID>"}'
```

Once frozen, the audit recorder returns `503 ServiceUnavailable` for
every append. This **must** happen before `pg_basebackup` so the backup
captures a stable trailing offset.

### 2.3 Snapshot Postgres via pg_basebackup

```bash
SNAPSHOT_DIR="/var/forensics/audit-$(date +%Y%m%dT%H%M%SZ)"
mkdir -p "$SNAPSHOT_DIR"

# -X stream: ship WAL alongside the base. -P: progress. -v: verbose.
PGPASSWORD="$(vault read -field=password secret/forensics/pg)" \
    pg_basebackup \
      -D "$SNAPSHOT_DIR" \
      -h "$PG_PRIMARY" \
      -U sx_forensics_ro \
      -X stream -P -v

# Tar + checksum + ship to immutable bucket.
tar -czf "$SNAPSHOT_DIR.tgz" -C "$(dirname "$SNAPSHOT_DIR")" "$(basename "$SNAPSHOT_DIR")"
sha256sum "$SNAPSHOT_DIR.tgz" > "$SNAPSHOT_DIR.tgz.sha256"

aws s3 cp "$SNAPSHOT_DIR.tgz"        "s3://sentinelx-forensics/$(basename $SNAPSHOT_DIR).tgz" \
    --object-lock-mode=COMPLIANCE --object-lock-retain-until-date "$(date -u -d "+7 years" +%Y-%m-%dT%H:%M:%SZ)"
aws s3 cp "$SNAPSHOT_DIR.tgz.sha256" "s3://sentinelx-forensics/$(basename $SNAPSHOT_DIR).tgz.sha256"
```

Attach the S3 URI + sha256 to the incident via `PATCH
/v1/ir/incidents/{id}/steps/contain-pg-basebackup` with
`evidence=<s3-uri>` and `evidence=<sha256>`.

---

## 3. T+10 — Eradication / RCA seed

### 3.1 Chain-of-custody record

Open one custody record per artifact (incident kit ships a Markdown
template; copy it into each evidence line). Each entry must include:

- Collector name + employee id
- Collection timestamp (UTC, RFC 3339, second precision)
- SHA-256 of the artifact
- Storage URI
- Witness signature (PGP, key ID in custody record header)

### 3.2 Root-cause hypotheses (top four)

| Hypothesis                                    | Kill-or-confirm signal                                                                           |
|-----------------------------------------------|--------------------------------------------------------------------------------------------------|
| Compromised DB superuser credential           | `pg_stat_activity` snapshot from the snapshot bucket — UNKNOWN client_addr/application_name      |
| Signing key leak from KMS                     | KMS access log for the audit signing-key resource (`audit.chain.signing_key`) since last anchor  |
| Bug in recorder seq monotonicity guard        | Reproduce break in a staging tenant via `sx-cli audit simulate-break`; check `RecordAuditEventUseCase` lock | 
| Disk-level torn writes                        | `dmesg`, EBS volume health, scrubber report                                                      |

Each hypothesis must have an assigned investigator + a 4h kill-or-confirm
deadline.

---

## 4. T+15+ — Recovery

### 4.1 Restore from last TSA-verified period

1. Fetch the baseline `(last_good_run_id, last_good_seq)` captured in
   `prep-last-good-baseline`.
2. Restore audit rows up to and including `last_good_seq` from the
   forensics snapshot into the live store via:

   ```bash
   sx-cli audit replay --tenant <TID> --from /var/forensics/audit-<ts>/base \
                       --through-seq <last_good_seq>
   ```
3. Replay every event recorded after `last_good_seq` from the WORM
   object-storage mirror (configured via `audit.object_store_mirror`).
4. Confirm the restored chain verifies clean via the same
   `sx-cli audit verify` flow as §1.

### 4.2 Re-anchor

```bash
curl -X POST "$API/v1/audit/anchors/run?tenant=<TID>" -H "Authorization: Bearer $TOKEN"
```

The response carries the new `anchor_run_id`. Verify with
`POST /v1/audit/anchors/verify/{anchor_run_id}` before lifting the
write-freeze. **Do not lift the freeze until the new anchor verifies.**

```bash
# Lift the write-freeze.
curl -X POST "$API/v1/admin/feature-flags/audit_writes_frozen" \
     -d '{"enabled": false, "reason": "<INCIDENT_ID> anchor verified"}'
```

---

## 5. Communication Templates

### Template A — Customer notification email (initial, T+24h)

```
Subject: [SentinelX Security Notice] Audit log integrity incident — {{tenant_name}}

Dear {{customer_contact}},

At {{t0_utc}} UTC the SentinelX background audit-chain verifier detected
an integrity violation on the tamper-evident audit log for your tenant
({{tenant_id}}). We immediately:

  1. Tripped the engagement kill switch — every active scan and
     remediation was halted.
  2. Froze new audit log writes pending forensic snapshot.
  3. Opened internal incident {{incident_id}} per the audit-chain
     compromise playbook (NIST SP 800-61 Rev 2).
  4. Notified our outside legal counsel and the on-call DPO.

Affected window: audit events with seq >= {{break_seq}} (recorded
between {{break_start_utc}} and {{break_end_utc}}). This is
{{event_count}} events out of the {{total_events}} in your tenant log.

Other SentinelX subsystems (engagement results, finding data, customer
PII, billing data) are NOT affected. No customer data is known to have
been exfiltrated as a result of this event.

We will issue a follow-up communication within the next 24 hours with
the post-restoration root-cause status. Per our MSA §11 we are also
notifying the supervisory authority where required.

A live office-hour slot for tier-1 customers will be available at
{{office_hour_link}}. For urgent questions please reply to this email or
call +{{ir_hotline}}.

— SentinelX Incident Response
```

### Template B — Regulator letter outline (GDPR Art. 33 / PDP §46)

```
1. Notifying entity:    SentinelX <legal-name>
2. Contact:             {{dpo_name}}, {{dpo_email}}, +{{dpo_phone}}
3. Type of incident:    Integrity violation of tamper-evident audit log
                        (no confidentiality breach known).
4. Categories impacted: Tenant audit events (security-event metadata
                        only — no personal data outside actor identifiers
                        already disclosed per the privacy policy).
5. Data subjects:       Operator + end-user actors recorded in the
                        impacted seq window ({{break_seq}}+).
                        Estimated count: {{actor_count}}.
6. Consequences:        Audit log entries in {{break_start_utc}}–
                        {{break_end_utc}} cannot be relied on for
                        evidentiary purposes until restoration.
7. Measures taken:      (i) Kill switch tripped, (ii) write-freeze,
                        (iii) immutable forensic snapshot,
                        (iv) restoration from last TSA-anchored baseline,
                        (v) re-anchoring.
8. Lessons-learned ETA: {{post_mortem_due_date}}.
```

### Template C — Internal pager dispatch (T+0)

```
PAGE: audit_chain_compromise tenant={{tenant_id}}
  break_seq={{break_seq}}  last_good_seq={{last_good_seq}}
  incident={{incident_id}}  playbook=audit_chain_compromise
  runbook=docs/runbooks/audit-chain-compromise.md
```

---

## 6. Decision Tree — When to escalate / notify regulator

```
            +---------------------------------+
            | Verifier emitted chain.broken   |
            +----------------+----------------+
                             |
              Re-verify confirms break? -- NO --> File verifier bug;
                             |                    open low-sev incident;
                             | YES                continue monitoring.
                             v
        Was the last TSA anchor also broken? -- NO --> Tamper is hot-tail
                             |                          only. Notify
                             | YES                      customer (24h).
                             v
        Cross-tenant impact (sx-cli audit verify on
        every other tenant exits 1)? -- YES --> ESCALATE TO EXEC + 
                             |                  OUTSIDE COUNSEL.
                             | NO               Notify *all* regulators
                             v                  within 24h (Indonesia PDP).
        Notify regulator(s):
          • GDPR: Art. 33, 72h, supervisory authority of customer's MS.
          • PDP-RI: UU 27/2022 §46, 24h, PDP Authority.
          • SOC 2: report to auditor at next QBR + interim memo.
```

---

## 7. Post-Incident Report Template

```markdown
# Audit Chain Compromise — Incident Report

**Incident id:** ............................
**Tenant:** ..................................
**Severity:** CRITICAL
**Opened (t0):** ............................. UTC
**Contained:** ............................... UTC
**Recovered:** ............................... UTC
**Closed:** .................................. UTC

## Detection
- Verifier tick timestamp:
- Break seq:
- Last good seq:
- Re-verify confirmation timestamp:

## Impact
- Audit events impacted:
- Customers notified (count, contacts):
- Regulators notified (entity, case id, ts):
- Data-subject categories:

## Timeline (UTC)
| ts | event | actor |
|----|-------|-------|
|    |       |       |

## Root cause
[2-3 paragraphs]

## What went well
1. ...

## What didn't
1. ...

## Action items
| # | Owner | Due | Description |
|---|-------|-----|-------------|
| 1 |       |     |             |

## Lessons learned
[2-3 paragraphs]

## Sign-off
- IR Commander:
- Forensics Lead:
- DPO:
- Outside Counsel:
- Engineering VP:
```

---

## 8. Drill exercise (sx-cli simulator)

Every quarter the IR team runs the drill against a **test tenant** only.
The CLI refuses to inject a tampered row in any tenant whose id is not
in the `audit.chain_verifier.allowed_drill_tenants` allow-list.

```bash
sx-cli audit simulate-break \
    --tenant 00000000-0000-7000-8000-0000000000ff \
    --seq 42 \
    --report-out /tmp/drill-report.json
```

The drill drives the playbook end-to-end and asserts:

1. The verifier emits `audit.chain.broken` within one tick.
2. The IR auto-fire opens an `audit_chain_compromise` incident.
3. Walking the incident through the runbook reaches the `recovery`
   phase (state `contained`).
4. A post-incident report is generated.

The drill report is committed to the compliance evidence store via
`sx-cli evidence` so SOC 2 / ISO 27001 auditors can see proof of
exercise.
