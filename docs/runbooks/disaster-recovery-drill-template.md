# DR Drill — Live Checklist Template

> **Purpose:** This is the **fill-in-the-blanks** checklist the on-call SRE
> uses *live, in the war room*, during a quarterly DR drill or a real DR
> event. Copy this file to
> `docs/operations/dr-drill-register/{YYYY}-{Qn}/drill-checklist.md`
> at the start of the drill, fill it in inline, and commit at the end.
>
> Pair this file with [`./disaster-recovery.md`](./disaster-recovery.md).
> Section references below (e.g. §5.2) point into that runbook.

---

## 0. Header

| Field | Value |
| --- | --- |
| Sentinel ID | DR-DRILL-{YYYY}-{Q#}-{seq} |
| Scenario | [ ] A region outage  [ ] B PG corruption  [ ] C audit tamper  [ ] D cert compromise |
| Mode | [ ] Live in production  [ ] DR sandbox |
| Drill date | YYYY-MM-DD |
| Window (planned) | HH:MM – HH:MM SGT (= HH:MM – HH:MM UTC) |
| Window (actual) | HH:MM – HH:MM UTC |
| Status page link | https://status.sentinelx.io/incidents/______ |
| War-room Slack | #war-room-dr-______ |
| Zoom bridge | https://sentinelx.zoom.us/j/______ |

### Roles (all four required to start)

| Role | Name | Pager | Joined at (UTC) |
| --- | --- | --- | --- |
| Drill Commander | ______ | ______ | __:__ |
| Backup Reviewer | ______ | ______ | __:__ |
| Comms Lead | ______ | ______ | __:__ |
| Auditor | ______ | ______ | __:__ |

### Drill clock

| Marker | Planned | Actual |
| --- | --- | --- |
| T+0  Disaster declared | __:__ | __:__ |
| T+30 min  Tier-0 RTO budget end | __:__ | __:__ |
| T+2 h  Tier-1 RTO budget end | __:__ | __:__ |
| T+4 h  Tier-2 RTO budget end | __:__ | __:__ |

---

## 1. Pre-drill gate (Backup Reviewer signs off — must all be GREEN)

- [ ] Pre-drill announcement sent **≥ 7 calendar days** prior to `customers@sentinelx.io` and `dr-steerco@sentinelx.io` (Comms Lead). Date sent: ______
- [ ] No active P0/P1 incident in the last 24 h.

  ```bash
  sentinelx-cli incidents list --severity P0,P1 --since 24h
  # expect: empty
  ```

- [ ] WAL-G integrity verification clean for pg-t0 / pg-t1 / pg-t2.

  ```bash
  for c in pg-t0 pg-t1 pg-t2; do
    WALG_S3_PREFIX=s3://sentinelx-basebackup/$c wal-g wal-verify integrity
  done
  # expect: OK for each
  ```

- [ ] Latest base backup age within tier policy.

  ```bash
  for c in pg-t0 pg-t1 pg-t2; do
    WALG_S3_PREFIX=s3://sentinelx-basebackup/$c wal-g backup-list --pretty | head -2
  done
  # T0 ≤ 12h, T1 ≤ 24h, T2 ≤ 7d
  ```

- [ ] ClickHouse last full backup ≤ 24h, last hourly ≤ 1h.

  ```bash
  aws s3 ls s3://sentinelx-clickhouse-backup-dr/logs/full/ | tail -2
  aws s3 ls s3://sentinelx-clickhouse-backup-dr/logs/hourly/ | tail -2
  ```

- [ ] Redis RDB freshness per cluster.

  ```bash
  for c in cache queue ratelimit session; do
    aws s3 ls s3://sentinelx-redis-rdb-dr/$c/ --recursive | sort | tail -1
  done
  # expect: timestamp within tier policy (queue ≤ 15m, session ≤ 5m, cache ≤ 1h)
  ```

- [ ] Vault snapshot age ≤ 6 h.

  ```bash
  vault operator raft snapshot save /tmp/precheck.snap
  ls -lh /tmp/precheck.snap
  ```

- [ ] HSM client cert in DR region valid ≥ 30 days.

  ```bash
  vault kv get -field=cert secret/sentinelx/hsm/client/ap-southeast-3 \
    | openssl x509 -noout -enddate
  ```

- [ ] CRR replication lag < 60 s for all backup buckets.

  ```bash
  for b in sentinelx-wal sentinelx-basebackup sentinelx-clickhouse-backup \
           sentinelx-redis-rdb sentinelx-audit-anchors; do
    aws s3api get-bucket-replication --bucket "$b" >/dev/null && echo "$b OK"
  done
  ```

- [ ] Drill-sandbox infrastructure provisioned (for B/C) — `terraform plan` is empty.

**Backup Reviewer sign-off:** ______ at __:__ UTC

> **DO NOT START THE DRILL** if any pre-drill gate is RED. Reschedule per §8 cancellation criteria.

---

## 2. Phase: DETECTION

Target: **≤ 5 min** from injected fault to first page acknowledged.

| Step | Owner | Command / expected | Done at (UTC) |
| --- | --- | --- | --- |
| 2.1 Inject fault (per scenario, see §7.{1\|2\|3\|4}) | Drill Commander | … | __:__ |
| 2.2 Synthetic probe failed | — | `sentinelx-cli synthetics status --probe api-health` | __:__ |
| 2.3 Page received | SRE on-call | PagerDuty incident ID: ______ | __:__ |
| 2.4 Page acknowledged (MTTA ≤ 10 min) | SRE on-call | — | __:__ |
| 2.5 War-room Slack created | Comms Lead | `#war-room-dr-______` | __:__ |
| 2.6 Zoom bridge live | Comms Lead | — | __:__ |

**MTTD actual:** ______ min (target ≤ 5)
**MTTA actual:** ______ min (target ≤ 10)

---

## 3. Phase: CONTAINMENT

Target: **≤ 10 min** from page ack.

- [ ] Drill Commander declares disaster, starts RTO timer at T+0 = __:__
- [ ] Status page moved to `Major Outage` with `STATUS-HOLD-DR-01` (Comms Lead)
- [ ] Writes disabled globally:

      ```bash
      sentinelx-cli flag set --flag global.writes_enabled --value false \
        --reason "DR drill {sentinel_id}"
      ```

- [ ] `dr-steerco@sentinelx.io` notified
- [ ] (Scenario A only) Primary VPC ingress blocked to prevent split-brain
- [ ] (Scenario B only) Replication paused on `pg-t0-standby`:

      ```bash
      psql -h pg-t0-standby -c "SELECT pg_wal_replay_pause();"
      ```

- [ ] (Scenario C only) Audit sidecar flag enabled:

      ```bash
      sentinelx-cli flag set --flag audit.sidecar_only --value true
      ```

- [ ] Forensic snapshot captured (Auditor confirms hash):

      ```bash
      sentinelx-cli forensic snapshot --label "drill-{sentinel_id}-pre-recovery"
      ```

      Snapshot ID: ______
      SHA-256:    ______

---

## 4. Phase: ERADICATION

Choose the recovery vector and document the target.

| Decision | Value |
| --- | --- |
| Vector | [ ] Standby promote (§5.3)  [ ] PITR (§5.2)  [ ] Full restore (§5.1)  [ ] Other: ______ |
| Justification (one line) | ______ |
| PITR target time (if PITR) | ______ UTC |
| Base backup chosen | s3://sentinelx-basebackup-dr/___/{label} |
| WAL gap check passed? | [ ] yes  [ ] no (HALT and page DBRE lead) |

**Drill Commander go/no-go for Recovery:** ______ at __:__ UTC

---

## 5. Phase: RECOVERY — Tier 0 (budget: 30 min from T+0)

| Step | Owner | Command | Done at (UTC) | Notes |
| --- | --- | --- | --- | --- |
| 5.1 pg-t0 promoted OR restored | DBRE | per §5.3 / §5.2 | __:__ | timeline_id=____ |
| 5.2 `pg_is_in_recovery() = f` | DBRE | `psql -h pg-t0-new -tAc "SELECT pg_is_in_recovery();"` | __:__ | |
| 5.3 HSM unwrap probe OK in DR region | SecEng | `sx-secrets-cli kek probe --region ap-southeast-3` | __:__ | latency_ms=____ |
| 5.4 Vault performance replica promoted | SecEng | `vault write -f sys/replication/performance/secondary/promote` | __:__ | |
| 5.5 §5.7 Tier-0 known-good queries pass (T0.1–T0.5) | Backup Reviewer | `psql -f /opt/sentinelx/dr/known-good-tier0.sql` | __:__ | All 5 PASS? [ ] yes [ ] no |
| 5.6 Audit reconciliation (§7.5) | Auditor | `sentinelx-cli audit verify --from $(date -u -d '-7d' +%F) --to today` | __:__ | result: ______ |

**Tier-0 RTO actual:** ______ min from T+0 (target ≤ 30)
**Tier-0 RPO actual (data loss measured):** ______ min (target ≤ 1)

> If Tier-0 budget exceeded, Drill Commander MUST reassess: continue, abort, or roll back. Document the call here: ______

---

## 6. Phase: RECOVERY — Tier 1 (budget: 2 h from T+0)

| Step | Owner | Command | Done at (UTC) | Notes |
| --- | --- | --- | --- | --- |
| 6.1 pg-t1 promoted / restored | DBRE | §5.3 or §5.2 | __:__ | |
| 6.2 Redis failover all clusters | Platform | `for c in queue cache ratelimit session; do sentinelx-cli redis failover --cluster "$c" --target dr-region --confirm; done` | __:__ | |
| 6.3 Kafka MM2 consumer offsets reset | Data Eng | per §6.4 | __:__ | |
| 6.4 BAS workers redeployed | Detection Eng | `terraform apply -target=module.bas_workers` | __:__ | replicas=____ |
| 6.5 §5.7 Tier-1 known-good queries pass (T1.1–T1.7) | Backup Reviewer | `psql -f /opt/sentinelx/dr/known-good-tier1.sql` | __:__ | All 7 PASS? [ ] yes [ ] no |
| 6.6 Edge / API failover (Route53) | Platform | per §6.5 | __:__ | DNS TTL=____ |
| 6.7 Re-enable writes | Drill Commander | `sentinelx-cli flag set --flag global.writes_enabled --value true` | __:__ | |
| 6.8 Smoke tests | SRE | `sentinelx-cli dr smoke --suite full` | __:__ | pass/fail: ____ |

**Tier-1 RTO actual:** ______ min from T+0 (target ≤ 120)
**Tier-1 RPO actual:** ______ min (target ≤ 15)

---

## 7. Phase: RECOVERY — Tier 2 (budget: 4 h from T+0)

| Step | Owner | Command | Done at (UTC) | Notes |
| --- | --- | --- | --- | --- |
| 7.1 pg-t2 promoted / restored | DBRE | §5.3 or §5.1 | __:__ | |
| 7.2 ClickHouse full RESTORE | Data Eng | per §5.4 | __:__ | |
| 7.3 ClickHouse incremental chain re-applied | Data Eng | per §5.4 | __:__ | last hourly: ____ |
| 7.4 §5.7 Tier-2 known-good queries pass (T2.1–T2.3) | Backup Reviewer | `clickhouse-client < /opt/sentinelx/dr/known-good-tier2.sql` | __:__ | All 3 PASS? [ ] yes [ ] no |
| 7.5 Status page → `Operational — Degraded` | Comms Lead | — | __:__ | |
| 7.6 Status page → `Operational` | Comms Lead | — | __:__ | |

**Tier-2 RTO actual:** ______ min from T+0 (target ≤ 240)
**Tier-2 RPO actual:** ______ min (target ≤ 60)

---

## 8. Phase: LESSONS

- [ ] Drill marker signed into audit chain:

      ```bash
      sentinelx-cli audit marker --label "drill-${sentinel_id}-$(date +%F)"
      ```

      Marker seq: ______

- [ ] All in-drill workarounds captured below
- [ ] Gap list drafted in post-drill report (§10 of runbook)
- [ ] Forensic snapshot retained per Auditor instructions
- [ ] Status page incident closed

### In-drill workarounds & gaps (raw notes for the post-drill report)

| Time (UTC) | Note | Owner |
| --- | --- | --- |
| __:__ | … | … |
| __:__ | … | … |

---

## 9. Final scoreboard

| Tier | RPO target | RPO actual | RTO target | RTO actual | Pass/Fail |
| --- | --- | --- | --- | --- | --- |
| 0 | 1 min  | ____ | 30 min | ____ | ____ |
| 1 | 15 min | ____ | 2 h    | ____ | ____ |
| 2 | 1 h    | ____ | 4 h    | ____ | ____ |

| Other gate | Target | Actual | Pass/Fail |
| --- | --- | --- | --- |
| MTTD | 5 min | ____ | ____ |
| MTTA | 10 min | ____ | ____ |
| All §5.7 known-good queries | all green | ____ | ____ |
| Audit chain reconciliation | clean | ____ | ____ |
| Customer comms ≥ 7d prior | yes | ____ | ____ |
| Pre-drill gate (§1) all green at start | yes | ____ | ____ |

---

## 10. Sign-off (live, end of drill)

- Drill Commander: ______________  at __:__ UTC
- Backup Reviewer: ______________  at __:__ UTC
- Comms Lead:     ______________  at __:__ UTC
- Auditor:        ______________  at __:__ UTC

---

## 11. Post-drill (within 5 business days)

- [ ] Full post-drill report drafted from §10 of `disaster-recovery.md`
- [ ] Gap list + action items filed in JIRA (Auditor cross-checks JIRA IDs)
- [ ] Report published to `docs/operations/dr-drill-register/{YYYY}-{Qn}/`
- [ ] Report mirrored to S3 Object-Lock bucket
      `s3://sentinelx-dr-reports/{YYYY}/{QN}/` with 7-year retain-until
- [ ] Compliance liaison signs the 7-year retention record

> **Retention:** this checklist and the post-drill report are both retained
> for **7 years** from the drill date. Deletion before that date requires
> written approval from the General Counsel.
