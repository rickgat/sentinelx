# Incident Response Playbook

Maintainer: Security Operations (`#sentinelx-secops`)
Last reviewed: 2026-06-13

This is the on-call playbook for SentinelX security and reliability
incidents. Read it cold; do not look up sections under pressure.

If you are reading this because something is on fire **right now**,
jump to [Triage checklist](#3-triage-checklist).

This runbook operationalises the **P3-004 IR playbook engine**
(`crates/sx-ir-playbooks/`). The engine ships four canonical playbooks
— `ransomware`, `data-exfil`, `credential-compromise`, `insider` —
each modelled as a state machine over the NIST 800-61 lifecycle
(Prepare / Detect / Contain / Eradicate / Recover / Post-Incident).
Every state transition emits a signed audit row, so the post-mortem
timeline is reconstructible from the chain alone. See §11 for the
playbook lookup and dispatch.

---

## 1. Severity classification

Every incident is assigned a severity at declaration time. The
incident commander (IC) re-evaluates severity at least every 30
minutes during the active phase.

| Severity | Definition                                                                                                              | Examples                                                                                              | Time to acknowledge | Time to resolve target |
| -------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------- | ---------------------- |
| **P0**   | Active customer data exposure, active wide-scope breach, full platform outage, or any BAS-caused customer harm.         | Cross-tenant data leak; audit chain tampering detected; kill switch fails to trip; full Postgres down. | < 5 minutes         | Mitigated < 1 hour     |
| **P1**   | Severe degradation of a core flow; suspected breach pending confirmation; security control failure with limited impact. | Auth service down for one tenant; OIDC outage; SLO budget burns 4x; suspected credential leak.        | < 15 minutes        | Mitigated < 4 hours    |
| **P2**   | Degradation of a non-critical flow; latency outside SLO; non-urgent security finding requiring attention.               | Reporting slow; one optional integration broken; CVE in a dependency without exploitability.          | < 1 hour            | Resolved < 2 business days |

**Default to higher severity if uncertain.** Downgrading is cheap;
upgrading late is expensive.

### Auto-promotion triggers

Some signals automatically promote an incident:

- Audit chain verification failure on any tenant -> P0.
- Kill switch fails to trip within 5 seconds of API call -> P0.
- More than one tenant reports the same authentication failure -> P1.
- SLO error budget burn rate > 14.4x for > 5 min -> P1.
- Any unauthorized write to `iam.user` or `iam.role` -> P1.

---

## 2. Detection paths

We rely on three independent detection paths so a failure in any one
of them does not blind us.

### 2.1 Falco

Falco runs as a DaemonSet on every Kubernetes node. Custom rules in
`deploy/falco/rules-sentinelx.yaml` watch for:

- Spawn of an unexpected process inside the `sentinelx` namespace
  (anything other than `sx-monolith`, `sx-cli`, `sx-agent`).
- Outbound TCP to non-allowlisted destinations from the BAS pod
  (the orchestrator is the only thing allowed to reach the public
  internet, and only to the destinations in its target list).
- `exec` or `attach` into a running pod (auditable but always
  alerts).
- Reads of `/etc/secrets/*` from any process not named in the
  allowlist.

Falco events go to the `#sentinelx-alerts-falco` Slack channel and
to PagerDuty if the rule is tagged `severity=critical`.

### 2.2 The SentinelX audit log

Every mutating action is logged to the audit chain (ADR 0005). A
periodic verifier runs:

- **Continuous**: every 5 minutes the chain rotator anchors to S3 and
  cross-checks. A mismatch is a P0.
- **Hourly**: a full chain walk per tenant. Mismatches paged.
- **Daily**: a deep verification including a re-fetch of S3 anchor
  manifests and re-validation of their signatures.

The audit log also feeds the **anomaly detector** in
`sx-ml/anomaly_detector` which flags:

- Auth failures spiking above baseline for a tenant.
- Unusual actor/action pairs (e.g. a viewer attempting to write).
- BAS techniques attempted with mode > current engagement mode.

### 2.3 Grafana alerts

Metrics from the OTel collector land in Prometheus and are evaluated
by Grafana Alerting. Alerts of interest to IR:

- `sx_safety_kill_switch_evaluations_total{result="error"} > 0` over
  any 1-minute window -> P0.
- `sx_audit_chain_verify_failures_total > 0` -> P0.
- `sx_auth_login_failures_total / sx_auth_login_attempts_total > 0.5`
  for any tenant over 5 minutes -> P1.
- `histogram_quantile(0.99, sum by (le, route)(rate(http_request_duration_seconds_bucket[5m])))`
  exceeding the per-route SLO -> P1 if sustained 10 minutes.

All P0 alerts page the primary on-call via PagerDuty. P1 alerts
page during business hours, escalate to PagerDuty after 30 minutes
unacknowledged.

### 2.4 Other detection paths

- **Customer report** via support email or in-product report button.
  Treat every customer report as at least P2 until triaged.
- **Falco upstream rules**, default set, paging on container
  capability changes.
- **Cloud-provider alerts**: AWS GuardDuty, Azure Defender, GCP SCC.
  Mirrored to `#sentinelx-alerts-cloud`.

---

## 3. Triage checklist

The first responder works through this list, in order, without
skipping. The list takes about 5 minutes when nothing is on fire and
about 12 minutes when everything is.

1. **Acknowledge the page.** PagerDuty -> Acknowledge. Sets the SLA
   clock.
2. **Open the incident channel.** `#inc-<short-name>` in Slack.
   Bot will pin the incident template.
3. **Declare yourself IC.** "I am IC. Working in `#inc-<short-name>`."
4. **Capture the alert payload.** Copy the page contents into the
   channel. Future you will thank present you.
5. **Read the runbook section** matching the alert. Skim, do not yet
   act.
6. **Confirm the symptom yourself.** Hit the API, view the dashboard,
   read the metric. Do not trust an alert until you have seen it.
7. **Decide severity.** Reread [Section 1](#1-severity-classification).
   Announce in the channel.
8. **Page the relevant subject matter expert(s)** if severity is P0
   or P1.
9. **Start the timeline.** First entry: alert time. Second: ack time.
   Every action goes in the timeline.
10. **Decide between containment and observation.** For P0 lean
    containment. For P1/P2 prefer observation if blast radius is
    bounded.
11. **Communicate.** First customer-facing update goes out within 30
    minutes for P0/P1 (see [Section 6](#6-communication-template)).

---

## 4. Containment

Containment is the act of stopping the bad thing from getting worse
while we figure out what is happening. It is **not** root cause
analysis.

### 4.1 BAS containment — trip the kill switch

The fastest containment for anything BAS-related:

```sh
ACCESS=$(./scripts/login.sh operator@sentinelx.io)
curl -sS -X POST https://api.sentinelx.io/v1/safety/kill-switch \
  -H "authorization: Bearer ${ACCESS}" \
  -H 'content-type: application/json' \
  -d '{
    "scope": "global",
    "reason": "incident #inc-... — IC alice — triaging",
    "tripped_by": "alice@sentinelx.io"
  }'
```

A `global` scope kill switch stops every technique in every tenant
in every engagement within one second (see ADR 0004). Less invasive
options:

```sh
# Stop one tenant
-d '{"scope":"tenant","tenant":"acme","reason":"..."}'

# Stop one engagement
-d '{"scope":"engagement","engagement_id":"eng_01J...","reason":"..."}'

# Stop a technique family across all tenants
-d '{"scope":"family","family":"exfiltration","reason":"..."}'
```

Verify the trip took effect:

```sh
curl -sS https://api.sentinelx.io/v1/safety/kill-switch?scope=global \
  -H "authorization: Bearer ${ACCESS}" | jq '.data'
# expect: { "tripped": true, "tripped_at": "...", "reason": "...", ... }
```

The reset path requires the two-person rule and goes in
[Section 5](#5-eradication--recovery).

### 4.2 Auth containment — revoke tokens

To kill a user's session right now:

```sh
curl -sS -X POST https://api.sentinelx.io/v1/iam/users/{user_id}/sessions/revoke-all \
  -H "authorization: Bearer ${ACCESS}"
```

To rotate the platform HS256 secret (worst-case auth incident — see
[Credential leak runbook](#71-credential-leak)):

```sh
# Operator action; logs you out of the rotation tool too.
./scripts/identity/rotate-hs256.sh --immediate
```

This invalidates every access token issued before the rotation and
forces every user to log in again. Refresh tokens remain valid (they
are stored, not signed) so users who had a refresh token simply mint
a new access token transparently. Refresh tokens may be revoked en
masse separately.

### 4.3 Data path containment — block egress

If the suspicion is data exfiltration:

```sh
# Apply the deny-egress NetworkPolicy
kubectl apply -f deploy/k8s/incident/deny-egress.yaml -n sentinelx
```

This NetworkPolicy denies all egress from the `sentinelx` namespace
except to in-cluster Postgres and Redis. Confirms the platform
cannot reach the public internet. The agent stops working under this
policy; that is intentional and acceptable for an incident.

### 4.4 Database containment — drop write access

If a database-level compromise is suspected:

```sh
# Promotes the read-replica to primary, demotes the previous primary,
# and forces application reconnection to the new primary in read-only
# mode pending IR sign-off.
./scripts/db/incident-readonly.sh
```

After this, no writes succeed. Production is degraded but not
exfiltrating new state. Reads continue.

---

## 5. Eradication and recovery

Eradication: remove the root cause. Recovery: restore service.

### 5.1 Eradication checklist

- [ ] Root cause hypothesis is confirmed by at least two pieces of
      evidence (logs + metric, or audit log + reproducer).
- [ ] All known compromised credentials are rotated.
- [ ] All known compromised infrastructure (pods, hosts, agents) is
      destroyed and rebuilt from known-good images.
- [ ] All known affected data is identified, scope-bounded, and either
      restored or quarantined.
- [ ] All known affected customers are listed in the incident channel
      with their tenant_id.
- [ ] Persistence vectors (cron jobs, scheduled tasks, new IAM
      principals) are listed and removed.

### 5.2 Recovery checklist

- [ ] Containment actions are reversed one at a time, with metric
      observation between each.
- [ ] Kill switch resets follow the two-person rule:
      ```sh
      # Operator A requests reset:
      sx-cli safety reset --scope global --reason "post-IR — root cause is X"

      # Operator B (not A) approves:
      sx-cli safety reset --approve <request_id>
      ```
- [ ] NetworkPolicy is reverted (`kubectl delete -f deploy/k8s/incident/deny-egress.yaml`).
- [ ] Database is returned to read-write after a clean checkpoint.
- [ ] All on-call alerts are re-enabled.
- [ ] A "service restored" message goes to the customer channel and
      status page within 15 minutes of full recovery.

### 5.3 Recovery gate

Recovery is only declared **complete** when:

1. The IC confirms the symptom is gone for at least 30 minutes.
2. The error budget burn has returned to baseline.
3. The audit log has been verified end-to-end for the affected
   tenants since the start of the incident.
4. A "post-incident" item is on the calendar with a draft owner.

---

## 6. Communication template

### 6.1 Internal Slack channel template

Bot-pinned at incident open. Replace the placeholders. Update fields
in place — do not post follow-up messages for status; use the pinned
message for situational awareness.

```text
:rotating_light: INCIDENT — <severity> — <short title>

IC: @alice
Comms: @bob
Tech lead: @carol
Customer-impacting: yes/no/unknown

Start: 2026-MM-DD HH:MM UTC
Status: triage | containing | eradicating | recovering | monitoring | resolved

Summary:
- One sentence describing the symptom.
- One sentence describing the hypothesis.
- One sentence describing the next action.

Timeline (UTC):
- HH:MM — page received
- HH:MM — IC declared
- HH:MM — symptom confirmed
- HH:MM — containment action <X>
- HH:MM — ...

Affected tenants: <list or "none confirmed">
Affected services: <list>
Customer comms: <link to status page update, last sent timestamp>
Doc: <link to live incident doc>
```

### 6.2 Customer notification — SLA

| Severity | First customer-facing notice | Cadence during incident | Final notice              |
| -------- | ---------------------------- | ----------------------- | ------------------------- |
| P0       | Within 30 minutes of declare | Every 30 minutes        | Within 1 hour of resolve  |
| P1       | Within 1 hour of declare     | Every 1 hour            | Within 2 hours of resolve |
| P2       | Within 4 hours if customer-facing | Daily              | At resolve                |

Channels:

- **Status page** (https://status.sentinelx.io) — every notice.
- **Email** to tenant admins — P0/P1 only.
- **Direct customer support** for named accounts — P0 only.

### 6.3 Customer notice template

```text
Subject: SentinelX Incident <inc-id> — <severity> — <short title>

Hello,

We are writing to inform you of an ongoing incident affecting SentinelX.

Severity: <P0 / P1>
Started: <UTC time>
Status: <triage / containing / recovering / resolved>

What is happening:
<one paragraph in plain language>

What we are doing:
<one paragraph>

What you should do:
<one paragraph, or "no action required from your side at this time">

We will send the next update by <UTC time>.

— The SentinelX team
```

---

## 7. Specific runbooks

### 7.1 Credential leak

**Trigger**: an HS256 secret, OIDC client secret, agent token, or
operator credential has been observed outside of where it should be
(GitHub commit, customer ticket, public paste site, repo scan).

**Severity**: P0 if the leaked credential is the HS256 secret, an
operator credential, or an agent token reaching a production tenant.
P1 otherwise.

**Containment**:

1. Rotate the credential immediately:
   - HS256: `./scripts/identity/rotate-hs256.sh --immediate`
   - OIDC client secret: rotate in the IdP console, update tenant
     config via `POST /v1/iam/tenants/{id}/oidc/rotate-secret`.
   - Agent token: revoke via `POST /v1/agents/{agent_id}/revoke`.
   - Operator password: forced reset + revoke all sessions.
2. Revoke all sessions for the relevant identity scope.
3. If any session may have used the leaked credential, treat any
   action attributed to it during the leak window as suspect.

**Eradication**:

- Audit log scan: `sx-cli audit query --actor <leaked_identity> --since <leak_time>`.
  Confirm or refute usage.
- If usage is confirmed, treat as a P0 breach and pivot to the
  "Suspected breach" path.

**Recovery**:

- Re-issue clean credentials to the rightful owner.
- Update the incident doc with the leak source so we can address the
  process gap.

**Post-mortem must answer**:

- Where did the credential live before the leak?
- Why was it where it was found?
- What detective control should have caught this earlier?

### 7.2 Public-bucket exposure

**Trigger**: an S3, GCS, or Azure blob container we own is detected
public-readable when it should not be. Likely sources:
`scripts/scan-buckets.sh` (runs hourly), customer report, or
GuardDuty.

**Severity**: P0 if the bucket contains audit log anchors, customer
data, or reports. P1 otherwise.

**Containment**:

1. Apply the closing policy:
   ```sh
   aws s3api put-bucket-policy \
     --bucket <bucket> \
     --policy file://deploy/aws/policies/bucket-deny-public.json
   ```
2. For S3, also re-enable Block Public Access at the bucket level:
   ```sh
   aws s3api put-public-access-block --bucket <bucket> \
     --public-access-block-configuration \
     'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
   ```

**Eradication**:

- Pull the CloudTrail (or equivalent) audit for who-changed-what on
  the bucket policy during the exposure window.
- Identify the IAM principal; rotate or revoke as appropriate.
- Pull the bucket access log; estimate the exposure (objects read,
  by whom, when).

**Recovery**:

- Re-enable downstream consumers that depend on the bucket.
- Confirm Object Lock and Versioning are intact for any audit-related
  bucket. If versions were deleted, see [Audit chain tampering
  hypothesis](#audit-chain-tampering-hypothesis).

**Post-mortem must answer**:

- How was the public ACL applied?
- Why did `scripts/scan-buckets.sh` not catch it earlier?
- Should this bucket exist at all?

### 7.3 Malicious dependency CVE

**Trigger**: a CVE is published, OR a customer reports, OR
`cargo deny` / `pnpm audit` flags a critical advisory in a dependency
we ship.

**Severity**: P1 by default. P0 if exploitable in our deployment and
under active exploitation.

**Containment**:

1. Identify the affected services from `cargo deny check advisories`
   or `pnpm audit`.
2. Determine reachability. The advisory is only exploitable if our
   code reaches the vulnerable path. Search the codebase; consult the
   advisory text.
3. If exploitable and trivially mitigatable (config flag, feature
   disable), apply the mitigation and re-deploy.
4. If exploitable and not trivially mitigatable, consider taking the
   affected route or feature offline via the platform's feature
   flags.

**Eradication**:

- Bump the dependency to the fixed version. Open a PR with the
  advisory link in the description.
- Run the full test suite. Pay particular attention to the area the
  CVE touches.

**Recovery**:

- Deploy the patched build through the standard canary path.
- Watch the burn rate for the affected route's SLO for 1 hour.
- Update the dependency registry tracker.

**Post-mortem must answer**:

- How did we not catch this earlier? (Was the advisory published
  before our last `cargo deny` run?)
- Should we have a faster channel for this class of advisory?
- Is there a structural change that reduces our exposure (sandbox,
  fewer deps, in-house alternative)?

### 7.4 Kill-switch trip (planned or unplanned)

**Trigger**: any `POST /v1/safety/kill-switch` with `tripped=true`.

**Severity**:
- P0 if global and unplanned, or if it failed to take effect within
  5 seconds.
- P1 if scoped (tenant / engagement / family) and unplanned.
- P2 if planned (drill or maintenance).

**Triage**:

1. Identify who tripped it and why from the audit log:
   ```sh
   sx-cli audit query --action safety.kill_switch.trip --since 1h
   ```
2. Confirm in-flight techniques have stopped:
   ```sh
   sx-cli bas runs list --status executing
   # expect: empty within 1 second of trip
   ```
3. If not empty after 5 seconds: page the BAS owner and escalate to
   P0. The pipeline is not behaving.

**Containment**: the kill switch is the containment; nothing more is
needed unless it fails to take effect.

**Recovery**:

1. Confirm the cause that triggered the trip is resolved.
2. Reset requires the two-person rule:
   ```sh
   sx-cli safety reset --scope <scope> --reason "post-IR — root cause is X"
   sx-cli safety reset --approve <request_id>     # different operator
   ```
3. Watch the BAS metrics for 30 minutes after reset:
   - `sx_bas_techniques_scheduled_total` returns to baseline.
   - `sx_bas_safety_blocks_total` does not spike.

**Post-mortem must answer (if unplanned)**:

- What technique or condition triggered the trip?
- Was the trip the right scope (could it have been narrower)?
- Did the reset go smoothly? Were both approvers available?

### 7.5 OIDC provider outage

**Trigger**: customer reports inability to log in via SSO, or our
synthetic monitor for the IdP returns errors for > 5 minutes, or our
OIDC adapter logs `IdpUnreachable` for > 50% of attempts on one
tenant.

**Severity**: P1 (single tenant SSO outage) up to P0 (multiple
tenants on the same IdP).

**Triage**:

1. Confirm with the IdP's status page (Okta, Azure AD, Google).
2. Confirm with our synthetic check:
   `curl -sS https://internal-mon.sentinelx.io/oidc/<tenant>`
3. Confirm whether password fallback is enabled for the tenant:
   `sx-cli iam tenants get <slug> | jq .oidc.enforced`

**Containment**:

- If password fallback is enabled, no action required — affected
  users may fall back.
- If password fallback is disabled and the IdP outage is sustained,
  consider a **temporary tenant-policy override**:
  ```sh
  sx-cli iam tenants oidc-enforce <slug> --disable \
      --duration 1h --reason "Okta global outage — see status.okta.com"
  ```
  This requires the two-person rule and is audit-logged. The override
  auto-expires after the duration.

**Recovery**:

- When the IdP recovers, the override expires on its own.
- Re-enable `oidc.enforced` if it was manually disabled.

**Post-mortem must answer**:

- Did we communicate to affected tenants?
- Was our synthetic monitor noisy or quiet enough?
- For tenants who insist on `oidc.enforced=true`, do they have a
  documented break-glass path?

### Audit chain tampering hypothesis

If at any point you suspect the audit chain has been tampered with:

1. **Stop**. Do not act on the audit log content until verified.
2. **Page the CISO.** This is a P0.
3. Run the offline verifier against a fresh PG dump plus the latest
   S3 anchor manifest:
   ```sh
   ./scripts/audit/verify-offline.sh --tenant <id> --since <date>
   ```
4. If the verifier reports a mismatch, isolate the affected
   `(tenant, epoch)`, freeze writes for that scope, and run a full
   forensic walk of the chain. Preserve the dump.

---

## 8. Post-mortem template

A post-mortem is required for every P0 and P1 and recommended for
notable P2s. The blame-free format:

```text
# Post-mortem: <inc-id> — <title>

Status: draft | review | final
Author: <name>
Reviewers: <list>
Date of incident: <UTC>
Date of post-mortem: <UTC>
Severity: <P0 / P1 / P2>

## TL;DR
<3-5 sentences. The reader who never opens the rest of the doc
should still understand the impact.>

## Impact

- Duration of customer-visible impact: <minutes>
- Customers affected: <count or list>
- Data exposed: <count, type, scope>
- Money affected: <if applicable, e.g. credits>

## Timeline (UTC)

| Time  | Event                                                                  |
| ----- | ---------------------------------------------------------------------- |
| HH:MM | (Source event — bug introduced, config change, etc.)                  |
| HH:MM | First detection signal.                                                |
| HH:MM | Page sent / IC declared.                                               |
| HH:MM | Containment action (with link to script or PR).                        |
| HH:MM | Root cause identified.                                                 |
| HH:MM | Recovery action.                                                       |
| HH:MM | Symptoms resolved.                                                     |
| HH:MM | IC declared incident resolved.                                         |

## Root cause

<Plain language. One or two paragraphs.>

## Contributing factors

- Factor A: <e.g. monitoring did not page until 10 minutes after the
  symptom started because the rule window was 5 min and the rule was
  evaluated every 5 min>.
- Factor B: <...>.
- Factor C: <...>.

(There are always at least two factors. If you can only name one,
look harder.)

## What went well

- <e.g. the kill switch tripped in under 1 second>.
- <e.g. the customer comms went out in 24 minutes>.

## What went poorly

- <without naming individuals; processes and systems only>.

## Action items

| ID    | Action                                                  | Owner    | Due     | Status |
| ----- | ------------------------------------------------------- | -------- | ------- | ------ |
| AI-1  | Add alert for X                                         | @alice   | 1 week  | open   |
| AI-2  | Refactor Y to remove the unsafe path                    | @bob     | 1 month | open   |
| AI-3  | Document the operator override for Z in the runbook     | @carol   | 2 weeks | open   |

## Lessons learned

<One section per "we now know" item.>

## Appendix

- Links to dashboards (with snapshots, since metrics expire).
- Links to PRs.
- Customer communication that went out.
```

A post-mortem is **public to the company**. Anyone may read.
Customer-facing summaries are derived from the post-mortem and are
written by the IC plus the comms lead.

---

## 9. After the incident

- IC closes the incident in PagerDuty.
- IC files the post-mortem within 5 business days for P0/P1.
- IC schedules the post-mortem review meeting within 7 business days
  for P0/P1, optional for P2.
- The action items are tracked in the platform issue tracker with the
  `incident-action-item` label.
- Action items are reviewed monthly until closed.

---

## 10. Drills

We run a tabletop incident drill **monthly** and a live drill
**quarterly**. The drills rotate scenarios from
[Section 7](#7-specific-runbooks). The on-call rotation is the primary
participant. The drill output updates this runbook.

---

## 11. P3-004 IR playbooks — NIST 800-61 state machine

### 11.1 Playbook catalogue

| Playbook ID           | Trigger conditions                                                                                            | Auto-promote to severity |
|-----------------------|---------------------------------------------------------------------------------------------------------------|---------------------------|
| `ir.ransomware`       | Falco rule "SentinelX Sensitive Path Write Outside Monolith" + `entropy(file)` > threshold + extension change | P0                        |
| `ir.data-exfil`       | Egress to non-allowlisted destination AND bytes > 100 MB in 1 h AND originating pod has `tenant_id` claim     | P0                        |
| `ir.credential-compromise` | RBA `replay` detector fires + auth from new ASN AND `jti` reuse within 5 min                            | P0 if HS256/operator; P1 otherwise |
| `ir.insider`          | UEBA (P2-005) anomaly: an actor's action distribution drifts > 4σ from baseline AND involves access to RPA-009/010 data | P1                |

### 11.2 NIST 800-61 lifecycle (every playbook)

```
+------+    +--------+    +----------+    +-----------+    +---------+    +---------------+
| Prep |--> | Detect |--> | Contain  |--> | Eradicate |--> | Recover |--> | Post-Incident |
+------+    +--------+    +----------+    +-----------+    +---------+    +---------------+
                |              |               |               |               |
              chain         chain            chain          chain           chain
              audit         audit            audit          audit           audit
```

Each phase is a state in the playbook FSM. Transitions are gated on
explicit operator approval (two-person for P0). The chain row for each
transition carries `(playbook_id, phase_from, phase_to, evidence_ref)`.

### 11.3 Per-step audit contract

| Step                            | `action`                              | Severity  |
|---------------------------------|---------------------------------------|-----------|
| Playbook instantiated           | `ir.playbook_started`                 | medium    |
| Phase entered                   | `ir.playbook_phase_entered`           | low       |
| Operator action recorded        | `ir.playbook_step_executed`           | medium    |
| Two-person approval received    | `ir.playbook_step_approved`           | medium    |
| Phase exited                    | `ir.playbook_phase_exited`            | low       |
| Playbook closed                 | `ir.playbook_closed`                  | medium    |

### 11.4 Dispatching a playbook

```bash
# 1. Dispatch a playbook for an open incident.
sx-cli ir playbook start \
  --incident-id inc_01J... \
  --playbook ir.data-exfil \
  --tenant 11111111-1111-1111-1111-111111111111

# 2. Mark the current phase as entered (after the IC confirms).
sx-cli ir playbook phase-enter \
  --run-id pb_01J... \
  --phase contain

# 3. Execute a containment step (e.g. kill-switch trip).
sx-cli ir playbook step-execute \
  --run-id pb_01J... \
  --step "trip kill-switch (scope=tenant)" \
  --command "POST /v1/safety/kill-switch"

# 4. Request two-person approval for a destructive step.
sx-cli ir playbook step-request-approval \
  --run-id pb_01J... \
  --step "force-revoke-all-sessions"

# 5. Second operator approves.
sx-cli ir playbook step-approve \
  --run-id pb_01J... \
  --step-id stp_01J...

# 6. Transition to next phase.
sx-cli ir playbook phase-exit --run-id pb_01J... --phase contain
sx-cli ir playbook phase-enter --run-id pb_01J... --phase eradicate

# 7. Close the playbook.
sx-cli ir playbook close --run-id pb_01J... --root-cause "<text>"
```

### 11.5 Cross-references

- Post-mortem template (§8) — populated automatically from the chain
  rows above by `sx-cli ir playbook post-mortem-skeleton`.
- Breach-notification clock — playbook close emits the
  `ir.playbook_closed` row, which the breach runbook
  (`breach-notification.md` §8) uses as the
  T+72h "final report" anchor for regulator-clock workflow.
