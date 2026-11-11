# Failover Drill — Live Checklist Template

> **Purpose:** Quarterly cross-region failover drill template.
> Different scope from the full DR drill: this exercises the
> planned-promotion path (region A is healthy, but we proactively
> swing primary to region B), not the unplanned region loss.
> Use this template for:
>
> - Quarterly steady-state failover validation.
> - Pre-deployment failover dry-run (gate for the TOP5-#4 production
>   deployment validation per `./multi-region-deployment.md` §11.3).
> - Post-incident drill replays.
>
> The shape mirrors `./disaster-recovery-drill-template.md` (the DR
> template). Where the DR template handles unplanned loss, this
> template handles planned promotion — same artefacts, different
> trigger.
>
> **At drill start:** copy this file to
> `docs/operations/failover-drill-register/{YYYY}-{Qn}/drill-checklist.md`,
> fill in inline, commit at the end. Pair with
> `./multi-region-deployment.md` and `./disaster-recovery.md`.

---

## 0. Header

| Field | Value |
| --- | --- |
| Sentinel ID | FO-DRILL-{YYYY}-{Q#}-{seq} |
| Scenario | [ ] A: PG primary swing  [ ] B: full region swing  [ ] C: blue/green region cutover  [ ] D: pre-deploy dry-run |
| Mode | [ ] Live in production  [ ] DR sandbox  [ ] Staging only |
| Drill date | YYYY-MM-DD |
| Window (planned) | HH:MM – HH:MM SGT (= HH:MM – HH:MM UTC) |
| Window (actual) | HH:MM – HH:MM UTC |
| Status page link | https://status.sentinelx.io/incidents/______ |
| War-room Slack | #war-room-fo-______ |
| Source region | [ ] us-east-1  [ ] eu-west-1  [ ] ap-southeast-1  [ ] other: ______ |
| Target region | [ ] us-east-1  [ ] eu-west-1  [ ] ap-southeast-1  [ ] other: ______ |

### Roles (all four required to start)

| Role | Name | Pager | Joined at (UTC) |
| --- | --- | --- | --- |
| Drill Commander | ______ | ______ | __:__ |
| DBRE Lead | ______ | ______ | __:__ |
| Comms Lead | ______ | ______ | __:__ |
| Auditor | ______ | ______ | __:__ |

### Drill clock

| Marker | Planned | Actual |
| --- | --- | --- |
| T+0   Promotion announced | __:__ | __:__ |
| T+5   DNS drained from source region | __:__ | __:__ |
| T+10  Postgres promoted in target | __:__ | __:__ |
| T+15  Smoke tests complete | __:__ | __:__ |
| T+30  Failover declared complete | __:__ | __:__ |
| T+60  Drill closeout window ends | __:__ | __:__ |

**Target total RTO: ≤ 30 min** (per `./multi-region-deployment.md` §11.4).

---

## 1. Pre-drill gate (DBRE Lead signs off — must all be GREEN)

- [ ] Pre-drill announcement sent **≥ 5 calendar days** prior to
      `customers@sentinelx.io` and `dr-steerco@sentinelx.io`
      (Comms Lead). Date sent: ______

- [ ] No active P0/P1 incident in the last 24 h.

  ```bash
  sentinelx-cli incidents list --severity P0,P1 --since 24h
  # expect: empty
  ```

- [ ] Pre-flight checklist from `./multi-region-deployment.md` §11.3
      all green (replication lag, backup recency, schema parity,
      seed parity, load-test, telemetry, kill-switch).

- [ ] Patroni cluster state clean on both regions.

  ```bash
  patronictl -c /etc/patroni/source.yml list
  patronictl -c /etc/patroni/target.yml list
  # expect: exactly one Leader per cluster, all Followers streaming
  ```

- [ ] Replication lag < 5 s on the target region.

  ```sql
  SELECT slot_name, confirmed_flush_lsn,
         pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn) AS lag_bytes,
         EXTRACT(EPOCH FROM (now() - reply_time)) AS lag_seconds
    FROM pg_replication_slots
    JOIN pg_stat_replication USING (application_name)
   WHERE slot_type = 'physical';
  ```

- [ ] Last quarterly DR drill ≤ 90 days ago (cross-check
      `docs/operations/dr-drill-register/`).

- [ ] Backup recency (per `./disaster-recovery-drill-template.md` §1).

  ```bash
  WALG_S3_PREFIX=s3://sentinelx-basebackup/pg-primary \
    wal-g backup-list --pretty | head -2
  # expect: most recent backup ≤ 24h
  ```

- [ ] Kill-switch reachable from both regions.

  ```bash
  for region in source target; do
    curl -fsS "https://api-${region}.sentinelx.io/v1/safety/kill-switch" \
      -H "Authorization: Bearer $SX_OPS_TOKEN"
  done
  # expect: HTTP 200 from each
  ```

- [ ] Capacity headroom: target region has ≥ 100% of source region
      sustained RPS available.

  ```bash
  sentinelx-cli capacity headroom --region target
  # expect: rps_available >= rps_observed_p95
  ```

**DBRE Lead sign-off:** ______ at __:__ UTC

> **DO NOT START THE DRILL** if any pre-drill gate is RED. Reschedule.

---

## 2. Phase: ANNOUNCE & FREEZE

Target: **≤ 5 min**.

- [ ] Drill Commander opens incident:

      ```bash
      sentinelx-cli incident open --sev=P2 \
        --topology-action=failover --drill={sentinel_id}
      ```

      Incident ID: ______

- [ ] Status page set to "Maintenance — planned region failover"
      (Comms Lead).
- [ ] Deploy freeze engaged for both regions:

      ```bash
      sentinelx-cli flag set --flag deploy.frozen --value true \
        --reason "FO drill {sentinel_id}"
      ```

- [ ] War-room Slack created (`#war-room-fo-______`).
- [ ] Forensic snapshot of source region taken (Auditor confirms):

      ```bash
      sentinelx-cli forensic snapshot \
        --label "fo-drill-{sentinel_id}-pre-promote"
      ```

      Snapshot ID: ______ SHA-256: ______

**T+5 actual:** __:__

---

## 3. Phase: DNS DRAIN

Target: **≤ 5 min** (T+5 → T+10).

| Step | Owner | Command / expected | Done at (UTC) |
| --- | --- | --- | --- |
| 3.1 Set source region health check to forced-FAIL | Platform | AWS Route 53 console / `aws route53 update-health-check --inverted` | __:__ |
| 3.2 Observe Route 53 propagation | Platform | `for i in 1.1.1.1 8.8.8.8 9.9.9.9; do dig +short @$i api.sentinelx.io; done` returns target NLB IPs | __:__ |
| 3.3 Source-region monolith RPS drops to < 1% of baseline | SRE on-call | Grafana panel `sx_http_requests_total{region="source"}` | __:__ |
| 3.4 In-flight requests drained (5-min wait) | SRE on-call | Active connections on source NLB → 0 | __:__ |

---

## 4. Phase: POSTGRES PROMOTION

Target: **≤ 5 min** (T+10 → T+15). Reference:
`./multi-region-deployment.md` §5.1 and §11.2 step P4.

| Step | Owner | Command | Done at (UTC) | Notes |
| --- | --- | --- | --- | --- |
| 4.1 Verify standby ready | DBRE | `psql -h pg-target -tAc "SELECT pg_is_in_recovery(), pg_last_wal_replay_lsn();"` | __:__ | lag_lsn=____ |
| 4.2 Pause writes globally | Platform | `sentinelx-cli flag set --flag global.writes_enabled --value false --reason "FO drill {sentinel_id}"` | __:__ | |
| 4.3 Final WAL flush check | DBRE | source `SELECT pg_switch_wal();` then target `SELECT pg_wal_replay_pause(); SELECT pg_wal_replay_resume();` to confirm caught up | __:__ | |
| 4.4 Promote standby | DBRE | `patronictl failover --candidate pg-target-leader --cluster pg-primary` | __:__ | new timeline=____ |
| 4.5 Verify single leader | DBRE | `patronictl list` reports exactly one Leader; old leader Demoted | __:__ | |
| 4.6 Re-enable writes | Platform | `sentinelx-cli flag set --flag global.writes_enabled --value true` | __:__ | |

**Promotion-phase RTO actual:** ______ min from T+10 (target ≤ 5)
**Promotion RPO measured (data loss):** ______ s (target ≤ 30s for findings)

---

## 5. Phase: SMOKE TESTS

Target: **≤ 15 min** (T+15 → T+30). Reference:
`./multi-region-deployment.md` §7 — all 15 tests must pass.

| # | Test | Pass criterion | Result | Notes |
| --- | --- | --- | --- | --- |
| 1 | DNS resolution | new primary NLB IP < 90 s of promote | [ ] | |
| 2 | Edge health | `/-/healthz` 200, all deps green | [ ] | |
| 3 | PG write | insert < 200 ms, replica visible < 1 s | [ ] | |
| 4 | PG cross-region read | < 5 s | [ ] | |
| 5 | ClickHouse insert | local shard visible < 2 s | [ ] | |
| 6 | Redis cache round-trip | < 5 ms p99 | [ ] | |
| 7 | Redis queue round-trip | < 2 s | [ ] | |
| 8 | Vault secret read | canary value returned | [ ] | |
| 9 | KMS envelope encrypt/decrypt | < 100 ms | [ ] | |
| 10 | Kafka MM2 lag | < 30 s | [ ] | |
| 11 | Auth token mint | `home_region` claim matches target | [ ] | |
| 12 | E2E synthetic (login + list) | < 3 s | [ ] | |
| 13 | Audit anchor write (dry-run) | retain-until = today + 7y | [ ] | |
| 14 | Cross-region BAS dispatch | other-region worker picks up < 30 s | [ ] | |
| 15 | Backup readiness (WAL-G) | most recent WAL ≤ 5 min | [ ] | |

**All 15 must pass within 15 minutes.** Any fail = HOLD ramp.

---

## 6. Phase: TRAFFIC RAMP

Target: **≤ 15 min** (post-smoke). Watch the error budget burn.

| Step | RPS share | Hold (min) | SLO check at end | Done at (UTC) |
| --- | --- | --- | --- | --- |
| 6.1 | 10% | 5 | `sx_http_request_duration_seconds_bucket` p95 within budget per route | __:__ |
| 6.2 | 50% | 5 | same + `sx_http_requests_total{status=~"5.."}` rate < 0.5% | __:__ |
| 6.3 | 100% | 5 | full SLO suite per `docs/slos.md` §2 | __:__ |

**Error budget burn during drill:** ______% / 30-day window
(target: < 5% — the drill itself must not eat the SLA budget).

---

## 7. Phase: VALIDATION

- [ ] L7 application logs in target region show same per-endpoint
      mix as source region pre-drill (no missing route family).
- [ ] Audit chain unbroken across the promotion:

      ```bash
      sentinelx-cli audit verify --from $(date -u -d '-1d' +%F) --to today
      # expect: chain_intact=true, no break_detected
      ```

- [ ] No `xmldsig_shadow_mismatch_total` metric increase outside
      pre-drill baseline (SAML verifier regression check —
      ADR-0022).

      ```bash
      curl -s http://target-prom:9090/api/v1/query \
        --data-urlencode 'query=increase(xmldsig_shadow_mismatch_total[1h])'
      # expect: 0
      ```

- [ ] FOUND-001 insert path observed (post-drill finding count
      delta within expected band, no `findings.insert_failed` spike).

      ```bash
      curl -s http://target-prom:9090/api/v1/query \
        --data-urlencode 'query=rate(sx_findings_ingested_total[5m])'
      ```

- [ ] No replication slot stuck in `inactive` state.

      ```sql
      SELECT slot_name, active, restart_lsn FROM pg_replication_slots;
      ```

---

## 8. Post-drill

- [ ] Status page resolved (Comms Lead).
- [ ] Deploy freeze lifted:

      ```bash
      sentinelx-cli flag set --flag deploy.frozen --value false
      ```

- [ ] Pre-promote forensic snapshot retained 30 days.
- [ ] Drill checklist committed to
      `docs/operations/failover-drill-register/{YYYY}-{Qn}/`.

### 8.1 Timeline replay (Auditor)

Fill the actuals into the §0 drill clock. Anything > planned by
> 2 min must have a one-line cause in §8.2.

### 8.2 Deviations from plan

| # | Step | Planned | Actual | Cause | Follow-up issue |
| --- | --- | --- | --- | --- | --- |
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

### 8.3 Follow-ups filed

| Issue | Title | Owner | Due |
| --- | --- | --- | --- |
| | | | |

### 8.4 RTO/RPO summary

| Metric | Target | Actual | Pass? |
| --- | --- | --- | --- |
| Overall RTO (T+0 → ramp 100%) | ≤ 30 min | ____ min | [ ] |
| Auth-path RPO | 0 | ____ s | [ ] |
| Finding-write RPO | ≤ 30 s | ____ s | [ ] |
| Audit chain RPO | 0 | ____ s | [ ] |

### 8.5 Sign-offs

| Role | Name | Sign-off (UTC) |
| --- | --- | --- |
| Drill Commander | ______ | __:__ |
| DBRE Lead | ______ | __:__ |
| Auditor | ______ | __:__ |

---

## 9. Cancellation criteria

Abort the drill (return to pre-drill state) if:

- An unrelated P0/P1 incident opens during the drill.
- A pre-drill gate retroactively fails (e.g. replication lag
  spikes during phase 2).
- The smoke matrix produces any fail with no rapid root cause.
- Customer-visible error rate exceeds the 30-day SLA budget burn at
  any traffic-ramp step.

Aborting is **not failure**. Document the abort cause and reschedule.

---

## 10. Change Log

| Date | Change | Author |
| --- | --- | --- |
| 2026-06-25 | Initial failover-drill template (TOP5-#4) | Platform Engineering |
