# Disaster Recovery Runbook

> **Last reviewed:** 2026-06-14 (P2-011 tiered targets + drill template)
> **Maintainer:** SRE Lead (sre-lead@sentinelx.io) / On-call rotation: `pagerduty://sentinelx-sre`
> **Next review:** 2026-09-14 (quarterly cadence)
> **Document owner:** Platform Engineering
> **Classification:** Internal — Restricted
> **Retention:** 7 years for this document and every post-drill report (compliance: ISO 27001 A.5.30, SOC 2 CC7.5, PDPA §11(2), HIPAA §164.308(a)(7)(ii)(D)).

---

## 1. Purpose & Scope

This runbook governs SentinelX's **disaster recovery (DR)** posture. It defines
what constitutes a disaster, the **per-data-class** RTO/RPO targets the
business has committed to, the mechanics of every backup pipeline, the
restore + failover playbooks, and the quarterly drill cadence that keeps the
procedures honest.

A "disaster" is any event that causes the loss of an entire AZ, region, data
tier, or trust boundary — or one with a credible threat of doing so within the
RTO. It is **not** the same as a routine incident (see
[`./incident-response.md`](./incident-response.md)).

Out of scope: routine deploy rollbacks, partial cell drains, single-node
failures handled by the orchestrator. See the
[operations playbooks](../operations/) for those.

---

## 2. Recovery Objectives — by Data Tier

SentinelX classifies persistent state into three tiers. Each tier has its own
RPO and RTO; the platform-wide RTO of a region-loss event is the **max** of
the per-tier RTOs of the tiers required for customer read/write.

### 2.1 Tier matrix

| Tier | Data class | Primary store(s) | RPO | RTO | Rationale |
| --- | --- | --- | --- | --- | --- |
| **Tier 0** | Audit hash chain (`audit_log`, `audit_anchor_external`), tenant config (`tenants`, `tenant_risk_weights`, `rba_config`, `saml_idp_config`), secrets KEK references (`tenant_deks` wrapped material) | Postgres (replicated) + HSM (KEK only) | **≤ 1 min** | **≤ 30 min** | Loss breaks compliance / breaks every downstream tenant. Hash chain must reconcile. KEK loss = tenant data unrecoverable. |
| **Tier 1** | Findings (`findings`), assets (`assets`), intel indicators (`tenant_iocs`, `intel_feed_status`), engagements (`engagements`), CVE master (`cve_master`, `cves`), RBA state (`rba_decisions`), remediation outcomes (`remediation_outcomes`, `regression_events`), blast-radius cache (`blast_radius_cache`), UEBA state (`ueba_state`), device posture (`device_posture_policy`, `device_posture_snapshots`) | Postgres (replicated) + Redis (queues) | **≤ 15 min** | **≤ 2 h** | Operational data that drives the live product. Synchronous replication + 5-min WAL upload cycle delivers ~5 min RPO in practice. |
| **Tier 2** | Reports (`report_snapshots`, `report_schedules`), structured logs (ClickHouse `logs.*`), BAS history (`bas_approvals`, ClickHouse `bas.runs`), vulnerability imports (`vuln_imports`), SCIM audit (`scim_audit`), Copilot approvals (`copilot_approvals`) | Postgres (slower replication tier) + ClickHouse + S3 | **≤ 1 h** | **≤ 4 h** | Historical / analytical. Customers can re-run reports; logs flushed from edge buffers cover the gap. |

> **KEK material itself is NOT backed up.** The KEK lives only in the HSM
> (AWS CloudHSM cluster `kek-prod` and the GCP Cloud KMS HSM-protected key
> `projects/sentinelx-prod/locations/asia-southeast1/keyRings/sx-kek/cryptoKeys/kek-v1`).
> What Postgres stores (`tenant_deks.wrapped`, `tenant_deks.key_id`) is the
> wrapped DEK and the KEK key-ID reference — the unwrap operation requires
> the HSM to be online. See §4.5.

### 2.2 RTO budget — region-loss event (worst case)

Region-loss must rebuild Tier 0 and Tier 1; Tier 2 may lag.

| Phase | Tier 0 budget | Tier 1 budget | Notes |
| --- | --- | --- | --- |
| Declaration + comms | 5 min | 5 min | IC + comms-lead spin up |
| Infra spin-up (warm standby) | 10 min | 25 min | Terraform `dr-region` plan; Tier-1 spins up after Tier-0 holds |
| Postgres promote (Tier 0 cluster) | 10 min | — | Synchronous standby in DR region; promote in ≤10 min |
| Postgres restore / promote (Tier 1) | — | 60 min | WAL replay caps at ~45 min |
| Redis warm-up | — | 10 min | RDB load + replication catch-up |
| HSM access verify | 5 min | 5 min | Confirm DR-region HSM client can unwrap a sample DEK |
| App cutover + DNS | — | 15 min | Health gates + traffic shift |
| Validation + audit reconciliation | — | _included in T0_ | Audit anchor verify, smoke tests |
| **Total budget** | **30 min** | **120 min** | Matches §2.1 |
| Buffer in §2.1 SLA | — | — | None — tier targets are commitments, not budgets-with-buffer |

Tier 2 budget (4h) absorbs the entire above flow plus ClickHouse `BACKUP`
restore (§5.4) and S3 cross-region read latency.

### 2.3 Per-tenant SLA overlay

Enterprise-tier tenants whose contract overrides §2.1 inherit the **stricter**
of (contract, platform default). Starter-tier tenants get §2.1 verbatim.
Contract overrides live in `tenants.tier`-keyed Vault entries at
`secret/sentinelx/sla/{tenant_slug}` and MUST be reviewed quarterly by the
Compliance liaison.

---

## 3. Architecture Overview (DR-relevant)

SentinelX runs **active/warm-standby** across two regions:

- **Primary:** `ap-southeast-1` (Singapore) — production traffic
- **Standby:** `ap-southeast-3` (Jakarta) — warm replicas, scaled to 25% capacity

Key components and their DR posture:

| Component | DR Strategy | Failover Time | Tier | Owner |
| --- | --- | --- | --- | --- |
| Postgres **Tier-0** cluster (`pg-t0`) | Synchronous streaming + WAL-G PITR | 10 min | T0 | DBRE |
| Postgres **Tier-1** cluster (`pg-t1`) | Async streaming + WAL-G PITR | 30–60 min | T1 | DBRE |
| Postgres **Tier-2** cluster (`pg-t2`) | Async streaming + nightly base backup | 1–2 h | T2 | DBRE |
| ClickHouse (logs, BAS history) | `BACKUP TABLE … TO S3` hourly + CRR | 30–60 min | T2 | Data Eng |
| Redis (cache, queues, ratelimit) | Cross-region read-replica + RDB snapshot | 5–15 min | T1 | Platform |
| Object storage (S3) | Cross-region replication (CRR) + Object Lock | Continuous | T0/T2 | Platform |
| Kafka (event spine) | MirrorMaker 2 to standby | 15 min | T1 | Data Eng |
| Audit log chain | Hash-chained in `pg-t0`, anchored daily to S3 Object Lock + RFC 3161 TSA | 1 min RPO | T0 | Compliance |
| **HSM / KEK** | CloudHSM cluster + GCP KMS HSM (multi-region replicated, **no software backup**) | 5 min | T0 | SecEng |
| Vault | Performance replica in standby + integrated-storage snapshot 6h | 5 min | T0 | SecEng |
| Edge / API gateway | Anycast + Route53 health checks | < 2 min | All | Platform |
| BAS workers (spot) | Stateless, rebuilt from container registry | 10 min | T1 | Detection Eng |

---

## 4. Backup Strategy

### 4.1 Postgres — `pg_basebackup` + WAL streaming

Each Postgres cluster (`pg-t0`, `pg-t1`, `pg-t2`) runs the same pattern;
parameters differ per tier.

```
postgres ──► WAL segment closed (archive_timeout=60s)
         └─► WAL-G compresses + encrypts (AES-256, KMS-wrapped)
             └─► uploaded to s3://sentinelx-wal/{cluster}/
                 └─► CRR ──► s3://sentinelx-wal-dr/{cluster}/

postgres ──► daily 03:15 SGT: pg_basebackup (parallel jobs, streamed via WAL-G)
         └─► s3://sentinelx-basebackup/{cluster}/{yyyymmddTHHMMZ}/
             └─► CRR ──► s3://sentinelx-basebackup-dr/{cluster}/
```

**Per-tier cluster settings**

| Setting | `pg-t0` (Tier 0) | `pg-t1` (Tier 1) | `pg-t2` (Tier 2) |
| --- | --- | --- | --- |
| `synchronous_commit` | `remote_apply` | `on` | `off` |
| `synchronous_standby_names` | `'ANY 1 (pg-t0-standby-1, pg-t0-standby-dr)'` | `'pg-t1-standby-1'` (async OK) | unset |
| `archive_mode` | `on` | `on` | `on` |
| `archive_timeout` | `30s` (RPO ≤ 1 min) | `60s` (RPO ≤ 15 min) | `300s` (RPO ≤ 1 h) |
| `wal_level` | `replica` | `replica` | `replica` |
| `max_wal_senders` | `10` | `10` | `6` |
| `wal_keep_size` | `8GB` | `8GB` | `2GB` |
| WAL-G upload cycle | continuous (push-mode) | continuous | 5 min |
| Base backup cadence | every 12 h | daily 03:15 SGT | weekly Sunday 03:15 SGT |
| Retention | 35 d (point), 12 mo (weekly) | 35 d (daily), 12 mo (weekly) | 90 d (weekly), 12 mo (monthly) |
| Encryption | KMS CMK `arn:aws:kms:.../sentinelx-wal-t0` | `…/sentinelx-wal-t1` | `…/sentinelx-wal-t2` |
| Integrity verification | `wal-g wal-verify integrity` nightly + hourly LSN gap probe | nightly | nightly |

**Base backup command (canonical, runs from the backup host)**

```bash
# Tier 0 example. Replace cluster name + S3 prefix for t1/t2.
WALG_S3_PREFIX="s3://sentinelx-basebackup/pg-t0" \
WALG_COMPRESSION_METHOD=zstd \
WALG_LIBSODIUM_KEY_PATH=/etc/walg/t0.key \
wal-g backup-push /var/lib/pgsql/16/data \
  --pgdata /var/lib/pgsql/16/data \
  --full
```

Under the hood wal-g shells `pg_basebackup --pgdata=- --format=tar --wal-method=fetch --checkpoint=fast`
and streams the tar to S3.

**WAL push (configured via `archive_command` in `postgresql.conf`)**

```ini
archive_command = '/usr/local/bin/wal-g wal-push %p'
restore_command = '/usr/local/bin/wal-g wal-fetch %f %p'
```

**RPO checks (run hourly)**

```bash
# Latest base backup not older than: 12h (T0) / 24h (T1) / 7d (T2)
wal-g backup-list --pretty | head

# Latest WAL on S3 lag vs primary
LATEST_S3=$(wal-g wal-show --json | jq -r '.[-1].name')
PG_LATEST=$(psql -h pg-t0 -tAc "SELECT pg_walfile_name(pg_current_wal_lsn());")
echo "S3=$LATEST_S3 PG=$PG_LATEST"
# Alert if more than 1 segment behind (T0) / 4 segments (T1)
```

### 4.2 ClickHouse — `BACKUP` to S3 hourly

Tier-2 analytical store. Both `logs.*` and `bas.runs` are backed up via the
native `BACKUP` statement to S3 with KMS encryption, plus full nightly.

```sql
-- Hourly incremental (runs via clickhouse-keeper-scheduled task)
BACKUP DATABASE logs
TO S3('https://sentinelx-clickhouse-backup.s3.ap-southeast-1.amazonaws.com/logs/hourly/{_partition_id}', '{AWS_ACCESS_KEY}', '{AWS_SECRET}')
SETTINGS
    base_backup = S3('https://sentinelx-clickhouse-backup.s3.ap-southeast-1.amazonaws.com/logs/full/latest', '{AWS_ACCESS_KEY}', '{AWS_SECRET}'),
    compression_method = 'zstd',
    compression_level = 3;

-- Full nightly at 02:00 SGT
BACKUP DATABASE logs
TO S3('https://sentinelx-clickhouse-backup.s3.ap-southeast-1.amazonaws.com/logs/full/2026-06-14', '{AWS_ACCESS_KEY}', '{AWS_SECRET}')
SETTINGS compression_method = 'zstd';

BACKUP DATABASE bas
TO S3('https://sentinelx-clickhouse-backup.s3.ap-southeast-1.amazonaws.com/bas/full/2026-06-14', '{AWS_ACCESS_KEY}', '{AWS_SECRET}')
SETTINGS compression_method = 'zstd';
```

| Setting | Value | Why |
| --- | --- | --- |
| Hourly incremental | every 60 min, top of hour | RPO ≤ 1 h |
| Full backup cadence | nightly 02:00 SGT | Rebase incremental chain |
| Retention | 14 days (hourly), 90 days (full), 12 months (first-of-month full) | Compliance lookback |
| Encryption | SSE-KMS with `…/sentinelx-clickhouse-backup` | Per data-class policy |
| Bucket | `sentinelx-clickhouse-backup` + CRR to `sentinelx-clickhouse-backup-dr` | Region failure tolerance |
| Integrity verification | nightly `SYSTEM SYNC FILE CACHE` + restore-into-shadow-cluster smoke test on first-of-month | Detects bitrot / catalog drift |

### 4.3 Redis — RDB snapshot cadence + AOF on queues

| Cluster | Persistence | Cadence | Why |
| --- | --- | --- | --- |
| `redis-cache` | RDB only | `save 300 100` and `save 60 10000` + cron hourly RDB upload | Cache loss only affects latency |
| `redis-queue` | RDB + AOF (`appendfsync everysec`) | RDB every 15 min, AOF continuous | In-flight job durability (sub-second) |
| `redis-ratelimit` | RDB only | `save 900 1` | Brief loss is acceptable |
| `redis-session` | RDB | every 5 min | Forces re-auth on full loss; acceptable |

RDB upload (driven by `redis-rdb-uploader` sidecar):

```bash
# Triggered by BGSAVE callback or by cron 5 min after last save
aws s3 cp /var/lib/redis/dump.rdb \
  s3://sentinelx-redis-rdb/${CLUSTER}/${HOSTNAME}/$(date -u +%Y%m%dT%H%MZ).rdb \
  --sse aws:kms --sse-kms-key-id alias/sentinelx-redis-rdb
```

| Setting | Value |
| --- | --- |
| Retention | 7 days (each upload), 30 days (one per day) |
| Encryption | SSE-KMS |
| CRR | enabled to `sentinelx-redis-rdb-dr` |

### 4.4 Audit anchors — daily Merkle root to S3 Object Lock + RFC 3161 TSA

The audit hash chain in `audit_log(tenant_id, seq, prev_hash, hash)` is
anchored once per day to S3 (Object Lock, Compliance mode, 7-year retention)
and to an external RFC 3161 timestamping authority. The record of every
anchor is stored back in Postgres in `audit_anchor_external`.

```
audit_log (Postgres pg-t0, hash-chained per tenant)
   └─► daily 00:05 UTC: compute Merkle root over (tenant_id, audit_seq_from..audit_seq_to)
       └─► sign payload with HSM key `audit-anchor-2026`
           └─► submit to RFC 3161 TSA (DigiCert + GlobalSign, dual-anchor)
               └─► INSERT INTO audit_anchor_external
                    (tenant_id, window_start, window_end,
                     audit_seq_from, audit_seq_to,
                     merkle_root, tsa_provider, tsa_timestamp, tsa_token)
                  PUT s3://sentinelx-audit-anchors/{tenant_id}/{yyyy}/{mm}/{dd}.json
                       with Object Lock retain-until = +7y
```

Anchor JSON schema (must match `audit_anchor_external` exactly):

```json
{
  "tenant_id":      "1f2c91…",
  "window_start":   "2026-06-13T00:00:00Z",
  "window_end":     "2026-06-13T23:59:59Z",
  "audit_seq_from": 8421300912,
  "audit_seq_to":   8429145007,
  "merkle_root":    "0x9c3a…e1",
  "tsa_provider":   "digicert",
  "tsa_timestamp":  "2026-06-14T00:05:14Z",
  "tsa_token":      "MIIK…",
  "signing_key_id": "audit-anchor-2026"
}
```

Every DR exercise **must** include an audit chain reconciliation step (§7.5).

### 4.5 KEK / DEK — HSM-only, no software backup

> **Hard rule:** the KEK never lands on disk or in any backup pipeline. Loss
> of *all* HSM replicas is the cryptographic equivalent of a region+region+
> off-site loss and is treated as a customer-impacting event under SLA.

| Asset | Storage | Backup | Recovery |
| --- | --- | --- | --- |
| KEK (primary) | AWS CloudHSM cluster `kek-prod` (3 HSMs, ap-southeast-1) | **None** | HSM cluster auto-heals across the 3 HSMs; loss requires HSM-cluster-restore from off-region replica |
| KEK (DR replica) | GCP Cloud KMS HSM-protected `kek-v1` (multi-region, ap-southeast2 + asia-southeast1) | **None** | Multi-region by construction |
| Wrapped DEK | `tenant_deks.wrapped` in `pg-t0` | Included in pg-t0 WAL/base backups | Restored with Postgres |
| KEK key-ID reference | `tenant_deks.key_id` | Postgres backups | Restored with Postgres |
| HSM client cert | Vault `secret/sentinelx/hsm/client/{region}` | Vault snapshot (§4.6) | Issued from Vault PKI |

In a DR scenario, restoring Postgres alone does not unlock tenant data: the
**HSM in the target region** must be reachable, and the running pod must hold
a valid HSM client cert. See §5.6 for the HSM verification step.

### 4.6 Configuration & secrets

| Asset | Backup | Recovery |
| --- | --- | --- |
| Terraform state | S3 + DynamoDB lock, versioned, CRR | Re-init in DR region |
| Vault | Performance replica + integrated storage snapshot every 6h | Promote replica |
| Kubernetes manifests | GitOps (Argo) — source of truth is Git | `argocd app sync` |
| KMS keys (data) | Multi-region CMKs | No action needed |
| Container images | ECR with CRR | Pull from DR registry |

---

## 5. Restore Procedures (step-by-step)

> **Order matters.** Restore Tier 0 (audit + tenant config + HSM access)
> before Tier 1 (operational data). Tier 1 before Tier 2. Tier 1 reads from
> Tier 0 (`audit_log` FK, `tenants` FK) and will fail RLS bootstrap otherwise.

### 5.1 Postgres restore — full (no PITR target)

Pulls the latest base backup + replays all archived WAL, ending at the last
durable LSN.

```bash
# 1. Stop application writes to this cluster
sentinelx-cli flag set --flag global.writes_enabled --value false \
  --reason "DR restore pg-t0"

# 2. Provision an empty target host (same major version: Postgres 16)
sentinelx-cli pg provision --cluster pg-t0-restore --version 16 \
  --instance-type db.r6i.4xlarge --region ap-southeast-3

# 3. Pull the latest base backup
export WALG_S3_PREFIX=s3://sentinelx-basebackup-dr/pg-t0
export PGDATA=/var/lib/pgsql/16/data
sudo -u postgres wal-g backup-fetch "$PGDATA" LATEST

# 4. Drop in recovery configuration
sudo -u postgres tee "$PGDATA/postgresql.auto.conf" <<'EOF'
restore_command = '/usr/local/bin/wal-g wal-fetch %f %p'
EOF
sudo -u postgres touch "$PGDATA/recovery.signal"

# 5. Start Postgres; it replays all archived WAL
sudo systemctl start postgresql@16-main

# 6. Wait for recovery to complete
psql -h pg-t0-restore -tAc "SELECT pg_is_in_recovery();"
# loop until false

# 7. Sanity (see §5.7 known-good queries)
psql -h pg-t0-restore -f /opt/sentinelx/dr/known-good-tier0.sql
```

### 5.2 Postgres restore — Point-In-Time Recovery (PITR)

Use when corruption has been committed and we want to land **before** a known
LSN or timestamp. The most common eradication path for Drill B.

```bash
# 1. Choose the target. One of:
#    - TIMESTAMP: '2026-06-13 11:41:00 UTC' (one minute before corruption)
#    - LSN:        '0/3A1E8C40'
#    - XID:        '47892311'

TARGET_TIME='2026-06-13 11:41:00 UTC'

# 2. Provision the restore cluster (separate host; do not overwrite primary)
sentinelx-cli pg provision --cluster pg-t1-pitr-$(date +%s) --version 16

# 3. Pull base backup taken BEFORE the target time
export WALG_S3_PREFIX=s3://sentinelx-basebackup-dr/pg-t1
export PGDATA=/var/lib/pgsql/16/data

# wal-g picks the latest base backup whose stop-time <= TARGET_TIME
sudo -u postgres wal-g backup-fetch "$PGDATA" --target-time "$TARGET_TIME"

# 4. Configure PITR recovery
sudo -u postgres tee "$PGDATA/postgresql.auto.conf" <<EOF
restore_command       = '/usr/local/bin/wal-g wal-fetch %f %p'
recovery_target_time  = '$TARGET_TIME'
recovery_target_action = 'pause'
EOF
sudo -u postgres touch "$PGDATA/recovery.signal"

# 5. Start Postgres
sudo systemctl start postgresql@16-main

# 6. Confirm recovery paused AT the target
psql -h pg-t1-pitr-... -tAc "SELECT pg_is_wal_replay_paused();"
# expect: t
psql -h pg-t1-pitr-... -tAc "SELECT pg_last_wal_replay_lsn(), now();"

# 7. Verify the data is what you expect (see §5.7)
psql -h pg-t1-pitr-... -f /opt/sentinelx/dr/known-good-tier1.sql

# 8. If OK, promote the recovery
psql -h pg-t1-pitr-... -tAc "SELECT pg_wal_replay_resume();"
# After replay reaches recovery_target_time, server promotes automatically.

# 9. Verify timeline switch
psql -h pg-t1-pitr-... -tAc "SELECT timeline_id FROM pg_control_checkpoint();"
psql -h pg-t1-pitr-... -tAc "SELECT pg_is_in_recovery();"  # expect: f
```

**PITR gotchas the on-call MUST know**

- WAL between the chosen base backup and `recovery_target_time` must be
  *complete*. If `wal-g wal-verify integrity` shows a gap, **stop and page
  the DBRE lead**. Do not promote.
- `recovery_target_inclusive` defaults to `true`: the named time is **included**.
- Recovery into a cluster with `synchronous_commit=remote_apply` and no live
  standby will hang on first write. Drop sync to `on` for the recovery window.
- The reconciliation step (§5.7) MUST run before any traffic is allowed.

### 5.3 Postgres failover — promote a live standby

Faster than restore. Use when the standby is healthy and within RPO.

**Pre-flight (run in parallel)**

```bash
# 1. Confirm primary is unreachable (3 independent probes)
sentinelx-cli dr probe --target pg-t0-primary --from {dr-region,oob,laptop}

# 2. Check standby lag
psql -h pg-t0-standby-dr -c "
SELECT pg_last_wal_replay_lsn(),
       now() - pg_last_xact_replay_timestamp() AS replay_lag;
"
# T0 lag MUST be < 1 min; T1 < 15 min; otherwise restore (§5.1/§5.2)

# 3. Capture pre-failover state
sentinelx-cli dr snapshot --component postgres --label "pre-failover-$(date +%s)"
```

**Promotion**

```bash
# Stop application writes via feature flag
sentinelx-cli flag set --flag global.writes_enabled --value false --reason "DR failover"

# Drain in-flight transactions (max 60s)
sentinelx-cli pg drain --timeout 60s

# Promote standby
ssh pg-t0-standby-dr "sudo -u postgres pg_ctl promote -D /var/lib/pgsql/16/data"

# Verify timeline switch
psql -h pg-t0-standby-dr -tAc "SELECT pg_is_in_recovery();"   # expect: f
psql -h pg-t0-standby-dr -tAc "SELECT timeline_id FROM pg_control_checkpoint();"

# Rewire app config (Vault entry flips)
vault kv put secret/sentinelx/pg/t0/primary host=pg-t0-standby-dr port=5432
sentinelx-cli config refresh --service all

# Re-enable writes ONLY after §5.7 known-good queries pass
```

### 5.4 ClickHouse restore — `RESTORE` from S3

```bash
# 1. Identify the latest full + the incremental chain
aws s3 ls s3://sentinelx-clickhouse-backup-dr/logs/full/ | tail -3
# choose: full/2026-06-13/  hourly/2026-06-13T19:00/  hourly/2026-06-13T20:00/ …
```

```sql
-- 2. Restore the full backup
RESTORE DATABASE logs
FROM S3('https://sentinelx-clickhouse-backup-dr.s3.ap-southeast-3.amazonaws.com/logs/full/2026-06-13', '{AWS_ACCESS_KEY}', '{AWS_SECRET}')
SETTINGS allow_non_empty_tables = 0;

-- 3. Re-apply the incremental chain in chronological order
RESTORE DATABASE logs
FROM S3('https://sentinelx-clickhouse-backup-dr.s3.ap-southeast-3.amazonaws.com/logs/hourly/2026-06-13T19:00', '{AWS_ACCESS_KEY}', '{AWS_SECRET}')
SETTINGS base_backup = S3('…/full/2026-06-13', '…', '…');

-- repeat for each hourly until current
```

```sql
-- 4. Verify with known-good Tier-2 queries (§5.7)
SELECT count() FROM logs.events WHERE event_time >= now() - INTERVAL 1 HOUR;
SELECT count(), max(event_time) FROM bas.runs WHERE started_at >= now() - INTERVAL 24 HOUR;
```

### 5.5 Redis restore — RDB load

```bash
# Latest RDB from CRR bucket
LATEST=$(aws s3 ls s3://sentinelx-redis-rdb-dr/${CLUSTER}/${HOSTNAME}/ \
  | sort | tail -1 | awk '{print $4}')
aws s3 cp s3://sentinelx-redis-rdb-dr/${CLUSTER}/${HOSTNAME}/${LATEST} \
  /var/lib/redis/dump.rdb

# Ensure ownership before starting
chown redis:redis /var/lib/redis/dump.rdb

# Start; Redis loads the RDB at boot
systemctl start redis-${CLUSTER}

# Confirm
redis-cli -h redis-${CLUSTER}.dr INFO persistence | grep loading
# loading:0 means load complete
redis-cli -h redis-${CLUSTER}.dr DBSIZE
```

For `redis-queue`, also replay AOF if present:

```bash
aws s3 cp s3://sentinelx-redis-aof-dr/redis-queue/${HOSTNAME}/appendonly.aof.latest \
  /var/lib/redis/appendonly.aof
chown redis:redis /var/lib/redis/appendonly.aof
# Redis will load AOF after RDB if appendonly=yes
```

### 5.6 HSM access verification (Tier 0)

The crypto layer cannot decrypt any tenant column until the HSM is reachable
from the DR-region pods. Verify before declaring restore complete.

```bash
# 1. Confirm HSM client cert is present and unexpired
vault kv get -field=cert secret/sentinelx/hsm/client/ap-southeast-3 \
  | openssl x509 -noout -enddate

# 2. Sanity-unwrap a known sample DEK (test tenant only)
sx-secrets-cli kek probe \
  --tenant 00000000-0000-0000-0000-000000000001 \
  --region ap-southeast-3
# expects: status=ok, latency_ms<200

# 3. Confirm wrap/unwrap round-trip
sx-secrets-cli kek roundtrip --region ap-southeast-3
# expects: status=ok
```

If any of these fail, **DO NOT** flip traffic — the platform will return
500s on every encrypted read. Page SecEng on-call and follow
[HSM recovery](../security/hsm-recovery.md).

### 5.7 Known-good queries — restoration verification

These queries MUST succeed (return data within expected ranges) before
declaring restore complete. Stored at
`/opt/sentinelx/dr/known-good-tier{0,1,2}.sql`.

**Tier 0 — must succeed before any Tier 1 work**

```sql
-- T0.1: Tenants table populated (at least the platform tenant)
SELECT count(*) AS tenant_count FROM tenants WHERE deleted_at IS NULL;
-- expect: >= 1

-- T0.2: Audit chain integrity (no gaps in seq per tenant)
SELECT tenant_id, count(*) AS rows,
       max(seq) - min(seq) + 1 AS expected,
       (max(seq) - min(seq) + 1) = count(*) AS dense
FROM audit_log
GROUP BY tenant_id
HAVING NOT ((max(seq) - min(seq) + 1) = count(*));
-- expect: 0 rows

-- T0.3: Audit chain hash linkage (each row's prev_hash matches predecessor)
WITH chain AS (
    SELECT tenant_id, seq, hash,
           LAG(hash) OVER (PARTITION BY tenant_id ORDER BY seq) AS expected_prev,
           prev_hash
    FROM audit_log
)
SELECT count(*) AS broken_links
FROM chain
WHERE seq > (SELECT min(seq) FROM audit_log a WHERE a.tenant_id = chain.tenant_id)
  AND prev_hash IS DISTINCT FROM expected_prev;
-- expect: 0

-- T0.4: Most-recent external anchor is within 24h
SELECT max(tsa_timestamp) AS last_anchor,
       now() - max(tsa_timestamp) AS lag
FROM audit_anchor_external;
-- expect: lag < interval '36 hours' (daily cadence + grace)

-- T0.5: Wrapped DEKs cover every active tenant
SELECT count(*) FROM tenants t
LEFT JOIN tenant_deks d USING (tenant_id)
WHERE t.deleted_at IS NULL AND d.tenant_id IS NULL;
-- expect: 0
```

Note: queries T0.2–T0.5 reference `tenant_deks` and `audit_log` which have RLS
forced. Run them as the platform-admin role
(`SET ROLE sentinelx_dr_verifier;`) which is exempt via `BYPASSRLS`.

**Tier 1 — must succeed before customer traffic restore**

```sql
-- T1.1: Finding count and most-recent timestamp per tenant
SELECT tenant_id, count(*) AS findings_n, max(detected_at) AS newest
FROM findings
GROUP BY tenant_id
ORDER BY findings_n DESC
LIMIT 10;
-- expect: counts within ±5% of pre-event baseline (compare to `/var/sentinelx/dr/baseline-tier1.json`)

-- T1.2: Asset fingerprints are unique per tenant (deduplication intact)
SELECT tenant_id, fingerprint, count(*)
FROM assets
GROUP BY tenant_id, fingerprint
HAVING count(*) > 1;
-- expect: 0 rows

-- T1.3: IOC store within capacity (1M cap per tenant)
SELECT tenant_id, count(*) AS iocs_n
FROM tenant_iocs
GROUP BY tenant_id
HAVING count(*) > 1000000;
-- expect: 0 rows

-- T1.4: Intel feeds polling — no feed silent > 24h
SELECT tenant_id, feed_id, last_success_at,
       now() - last_success_at AS silence
FROM intel_feed_status
WHERE last_success_at IS NULL OR (now() - last_success_at) > interval '24 hours';
-- expect: 0 rows (or known-out feeds documented in baseline)

-- T1.5: Findings FK closure (every finding's asset and engagement exists)
SELECT count(*) AS orphan_findings
FROM findings f
LEFT JOIN assets a      ON a.id = f.asset_id     AND a.tenant_id = f.tenant_id
LEFT JOIN engagements e ON e.id = f.engagement_id AND e.tenant_id = f.tenant_id
WHERE a.id IS NULL OR e.id IS NULL;
-- expect: 0 (FKs are CASCADE, so any orphan indicates restore inconsistency)

-- T1.6: Remediation outcomes ledger continuity (P1-011)
-- ttr_seconds must be non-negative (CHECK constraint) and closed_at must
-- be ≥ opened_at. A restore-time violation indicates row corruption.
SELECT count(*) AS bad_outcomes
FROM remediation_outcomes
WHERE closed_at < opened_at OR ttr_seconds < 0;
-- expect: 0
-- (Note: finding_id is intentionally NOT FK-constrained — historical
-- outcomes outlive the source finding row by design. Do not orphan-check.)

-- T1.7: Device-trust posture freshness (P2-008) — note the table is
-- `device_posture_snapshots` and the timestamp column is `observed_at`.
SELECT count(DISTINCT session_id) AS sessions_with_stale_posture
FROM device_posture_snapshots
WHERE observed_at < now() - interval '24 hours'
  AND status IN ('trusted', 'untrusted');
-- expect: within baseline tolerance (compare to baseline-tier1.json)
```

**Tier 2 — must succeed before declaring full restore complete**

```sql
-- T2.1 (ClickHouse): logs ingestion live in DR region
SELECT count() AS recent_logs,
       max(event_time) AS newest_log
FROM logs.events
WHERE event_time >= now() - INTERVAL 15 MINUTE;
-- expect: recent_logs > 0 after edge cutover; newest_log within 5 min of now()

-- T2.2 (ClickHouse): BAS run history continuous
SELECT toStartOfDay(started_at) AS day, count() AS runs
FROM bas.runs
WHERE started_at >= now() - INTERVAL 7 DAY
GROUP BY day ORDER BY day;
-- expect: monotonic, no day with 0 runs unless documented downtime

-- T2.3 (Postgres): report snapshots recoverable
SELECT count(*) FROM report_snapshots
WHERE created_at >= now() - interval '7 days';
-- expect: matches baseline ± report-schedule cancellations
```

**Acceptance:** every block in §5.7 must return `expect: …` per its comment.
Any failure pauses the restore. Document the failure in the drill timeline
even if it is later cleared.

---

## 6. Failover Procedures (region loss)

### 6.1 Declaration

Disaster is declared by the **Incident Commander (IC)** after consulting with
the SRE on-call and the on-call engineering manager. Declaration triggers:

1. PagerDuty escalation policy `dr-declared` (pages all DR leads).
2. `#war-room-dr` Slack channel auto-created.
3. Zoom bridge auto-started (link in pager note).
4. Status page moved to `Major Outage` with holding statement.
5. RTO timer started in the IC dashboard.

### 6.2 Postgres failover

See **§5.3** (live-standby promote) or **§5.1 / §5.2** (restore).

### 6.3 Redis failover

```bash
# For each cluster: queue, cache, ratelimit, session
for c in queue cache ratelimit session; do
  sentinelx-cli redis failover --cluster "$c" --target dr-region --confirm
done

# Verify
redis-cli -h redis-${c}.dr CLUSTER NODES | grep master
```

If the standby replica is too far behind (`master_repl_offset` lag > 5MB),
fall back to **RDB-only restore** (§5.5).

### 6.4 Kafka failover

MirrorMaker 2 keeps standby topics within ~5s of primary.

```bash
# 1. Stop primary producers (already off if app is down)
# 2. Reset consumer group offsets to mirrored topics
kafka-consumer-groups --bootstrap-server kafka-dr:9092 \
  --reset-offsets --to-datetime "$(date -u -d '-15 min' +%FT%TZ)" \
  --group bas-processor --all-topics --execute

# 3. Flip producer config
sentinelx-cli config set kafka.brokers kafka-dr-0:9092,kafka-dr-1:9092,kafka-dr-2:9092
sentinelx-cli config refresh --service api,bas-worker
```

### 6.5 Edge / API failover

Route53 health checks should auto-fail over within 60–120 seconds. To force:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123 \
  --change-batch file://dr-failover-cname.json
```

### 6.6 Vault failover

```bash
vault operator raft list-peers
vault write -f sys/replication/performance/secondary/promote
```

Re-key any session tokens issued by the old primary if `vault read sys/health`
reports `replication_dr_mode=primary` mismatch.

### 6.7 BAS workers

Stateless. Spin up via Terraform:

```bash
cd terraform/dr-region
terraform apply -target=module.bas_workers -var "desired_count=200"
```

---

## 7. Drill Scenarios

Each scenario follows the same five-phase template:
**Detection → Containment → Eradication → Recovery → Lessons.**

> Every drill must be tracked in the [DR drill register](../operations/dr-drill-register.md)
> with start, end, RTO actual (per tier), RPO actual (per tier), and a
> post-drill report. **Reports are retained for 7 years.**

### 7.1 Drill A — Primary region outage

**Scenario:** `ap-southeast-1` is fully unreachable (simulated by hard
network-policy block on all egress from the primary VPC). All customer
traffic must shift to `ap-southeast-3`.

**Detection** — within 5 minutes (matches Tier 0 detection):

```bash
sentinelx-cli synthetics status --probe api-health
sentinelx-cli logs query --service edge --window 5m --filter 'status>=500'
```

**Containment** — within 10 minutes:

1. IC declares disaster (§6.1).
2. Move status page to `Major Outage`. Use `STATUS-HOLD-DR-01`.
3. Disable writes globally.
4. Notify `dr-steerco@sentinelx.io`.

**Eradication** — within 30 minutes:

1. Confirm primary region is unrecoverable in the drill window.
2. Snapshot primary state for forensic review when it returns.
3. Block primary VPC ingress to prevent split-brain.

**Recovery** — within tier RTO budgets (§2.2):

1. Postgres `pg-t0` promote (§5.3) — target 10 min (Tier 0 RTO).
2. HSM access verify (§5.6) — target 5 min.
3. Audit reconciliation (§5.7 T0.* + §7.5).
4. Postgres `pg-t1` promote (§5.3) — target 60 min.
5. Redis failover (§6.3) — target 10 min.
6. Kafka failover (§6.4) — target 15 min.
7. Vault failover (§6.6) — target 5 min.
8. Tier-1 known-good queries (§5.7) — target 10 min.
9. Edge / API failover (§6.5) — target 5 min after gates pass.
10. BAS workers redeploy (§6.7) — target 10 min, parallel.
11. ClickHouse `RESTORE` (§5.4) — target 90 min, parallel.
12. Smoke tests:

    ```bash
    sentinelx-cli dr smoke --suite full
    ```

13. IC moves status page to `Operational — Degraded` then `Operational`.

**Lessons:**

- Tier-0 RTO ≤ 30 min? Tier-1 ≤ 2h? Tier-2 ≤ 4h?
- Synchronous standby lag ≤ 1 min at promotion?
- All §5.7 queries passed first attempt?

### 7.2 Drill B — Postgres data corruption

**Scenario:** A bad migration corrupts `audit_log` page 0xC4A2 in `pg-t0`.
The corruption committed and replicated to standby 12 minutes ago. On-call
detected via a CHECKSUM error during routine VACUUM.

**Detection** — within 15 minutes:

```bash
journalctl -u postgresql --since "30 min ago" | grep -i "invalid page"
sentinelx-cli alerts list --service data-quality --severity high
```

**Containment** — within 30 minutes:

1. Freeze writes to the affected table.

    ```bash
    sentinelx-cli flag set --flag table.audit_log.writes_enabled --value false
    ```

2. Pause replication on the standby:

    ```bash
    psql -h pg-t0-standby -c "SELECT pg_wal_replay_pause();"
    ```

3. Take a logical dump of unaffected rows:

    ```bash
    pg_dump -h pg-t0-primary -t audit_log \
      --where "seq < 8429000000" > /backups/audit_pre_corruption.sql
    ```

**Eradication** — within 60 minutes (Tier 0 RTO):

1. Identify the offending transaction:

    ```sql
    SELECT xmin, * FROM audit_log WHERE ctid = '(50338,0)';
    ```

2. Identify the LSN before corruption:

    ```bash
    wal-g wal-show | grep -B1 "2026-06-13 11:42"
    ```

3. PITR to corruption-minus-one-minute per §5.2.

**Recovery** — within RTO:

1. Provision fresh restore cluster via §5.2.
2. Verify integrity:

    ```bash
    psql -h pg-t0-pitr-... -c "REINDEX TABLE CONCURRENTLY audit_log;"
    psql -h pg-t0-pitr-... -c "VACUUM (VERBOSE, ANALYZE) audit_log;"
    ```

3. Run §5.7 Tier-0 queries. T0.2/T0.3 must pass.
4. Diff-merge writes that occurred AFTER corruption from non-corrupted
   tables:

    ```bash
    sentinelx-cli pg diff-merge \
      --source pg-t0-primary \
      --target pg-t0-pitr-... \
      --since '2026-06-13 11:41:00 UTC' \
      --exclude-table audit_log
    ```

5. Cutover (§5.3).
6. Re-anchor the audit chain with a `corruption-recovery` marker (§7.5).

**Lessons:**

- Corruption detected before customer impact?
- Avoided promoting poisoned standby?
- Data loss ≤ Tier-0 RPO (1 min)?

### 7.3 Drill C — Audit-chain tamper detected

**Scenario:** The nightly verifier reports Merkle-root mismatch between
`audit_log` and the latest `audit_anchor_external` row / S3 anchor object.

**Detection** — within 5 minutes of nightly verifier:

```bash
sentinelx-cli audit verify --segment 2026-06-13
# STATUS: MISMATCH
```

Page **P0**. Treat as a potential **security breach** in parallel.

**Containment** — within 30 minutes:

1. Flip writes to the audit sidecar (Kafka topic `audit-cold`).
2. Snapshot suspect Postgres cluster and the suspect anchor object version.
3. Rotate Vault tokens for `pg-audit-writer` role.

**Eradication** — within 90 minutes:

1. Recompute the chain from raw WAL using a clean PITR restore (§5.2).
2. Compare against:
   - Current Postgres `audit_log` chain.
   - `audit_anchor_external.merkle_root`.
   - S3 anchor object (`s3://sentinelx-audit-anchors/{tenant_id}/…`).
   - RFC 3161 TSA token verification.
3. Diagnose the divergence point.

**Recovery** — within RTO:

- If software bug: patch verifier, re-anchor, document.
- If operator tamper: restore audit table via PITR, replay sidecar writes,
  re-anchor with `tamper-recovery` marker, proceed to
  [breach notification](./breach-notification.md).
- If storage tamper: cross-check against off-platform mirror
  `glacier-deep://sentinelx-anchors-mirror/`.

### 7.4 Drill D — Certificate compromise

**Scenario:** Leaked private key for `*.sentinelx.io` discovered in a public
gist. Rotate cert, invalidate old sessions, notify pinned clients.

(Full sub-steps unchanged from prior version — see §7.4 detection /
containment / eradication / recovery / lessons in the change-log entry for
2026-05-30 if needed for compliance audit reference. The rotation deadline
is **60 minutes** from confirmed compromise.)

### 7.5 Audit reconciliation checklist (every drill)

```bash
# 1. Verify the chain from the last known-good anchor to now
sentinelx-cli audit verify --from $(date -u -d '-7 days' +%F) --to today

# 2. Confirm no anchor was missed during the drill window
sentinelx-cli audit anchors list --since 7d

# 3. Compare DB anchor row vs S3 anchor object byte-for-byte
sentinelx-cli audit anchor-diff --tenant <id> --date 2026-06-13

# 4. Sign a drill marker into the chain
sentinelx-cli audit marker --label "drill-${scenario}-$(date +%F)"
```

---

## 8. Quarterly Drill Schedule

The DR program runs **one full drill per quarter**, rotating through the four
scenarios so each is exercised at least annually. Off-quarter, we run
**tabletop** exercises against the next scenario.

| Quarter | Live drill | Tabletop | Dry-run target | Notes |
| --- | --- | --- | --- | --- |
| Q1 (Mar) | Scenario A — region outage | Scenario B | All three tiers within budget | Annual peak season prep |
| Q2 (Jun) | Scenario B — PG corruption | Scenario C | Tier-0 RPO ≤ 1 min, RTO ≤ 30 min | Pre-audit window |
| Q3 (Sep) | Scenario C — audit tamper | Scenario D | Audit chain reconciles, anchor round-trip OK | Compliance week |
| Q4 (Dec) | Scenario D — cert compromise | Scenario A | Cert rotation < 60 min | Year-end freeze |

**Drill windows:** Tuesdays, 02:00–08:00 SGT, with customer notice ≥ 7 days
in advance. Scenarios A and D may run in production with explicit
blast-radius controls. Scenarios B and C run in an isolated DR sandbox with
synthetic data only.

**Cancellation criteria:** Any P0/P1 active incident in the 24h preceding
the drill cancels it; reschedule within 30 days.

### 8.1 Pre-drill announcement template

Send the announcement to **both** `customers@sentinelx.io` (top-tier
distribution) and `dr-steerco@sentinelx.io` **at least 7 calendar days**
ahead. Template:

```
Subject: [PLANNED] SentinelX DR drill — Scenario {A|B|C|D} — {YYYY-MM-DD}

Hello,

SentinelX SRE will execute its quarterly disaster-recovery drill on
{YYYY-MM-DD} from {02:00–08:00 SGT}. This drill exercises the
{region-outage | PG-corruption | audit-tamper | cert-compromise}
scenario per the runbook at docs/runbooks/disaster-recovery.md §7.{1|2|3|4}.

Customer-visible impact (expected):
  - {scenario A: brief failover blip <2 min; otherwise: NONE}

Customer-visible impact (worst case if drill fails):
  - Up to {Tier-1 RTO = 2 hours} of degraded reads in {ap-southeast-1}.

Mitigations:
  - Synchronous standby in ap-southeast-3 remains hot.
  - Rollback decision point at T+45 min.

Drill Commander: {name}, {pager}
Comms Lead:      {name}, {email}
Status page:     https://status.sentinelx.io
Sentinel ID:     DR-DRILL-{YYYY}-{Q#}-{seq}

You may opt your account out of any in-production drill steps by replying
to this email at least 72 hours in advance.

— SentinelX Platform Engineering
```

---

## 9. Roles & Responsibilities

The four named drill roles below are the **minimum** quorum required to
start any live drill. Region-outage drills (Scenario A) additionally require
the operational on-calls (DBRE, Platform, SecEng).

| Role | Responsibility | Backup |
| --- | --- | --- |
| **Drill Commander** | Owns the drill clock. Calls go/no-go at each phase. Owns RTO timer. Authority to abort. Reports outcome to Compliance. | SRE Lead |
| **Backup Reviewer** | Pre-drill: signs off that all backup health checks (WAL-G integrity, ClickHouse BACKUP catalog, Redis RDB freshness, Vault snapshot age) are green. Post-drill: verifies §5.7 known-good queries returned the expected ranges. | DBRE on-call |
| **Comms Lead** | Drives status page + customer comms + internal `#war-room-dr` updates. Owns the pre-drill announcement (§8.1) and the customer-facing portion of the post-drill report. | PR Lead |
| **Auditor** | Independent observer. Captures timeline events with timestamps. Verifies audit-chain reconciliation (§7.5) and post-drill report accuracy. Cannot also be Drill Commander or Backup Reviewer. Signs the 7-year retention record. | Compliance liaison |

| Supporting role | Responsibility | Backup |
| --- | --- | --- |
| Incident Commander | Declares real disasters (non-drill); during drills, acts as Drill Commander | SRE Lead |
| Scribe | Maintains live timeline in war room | On-call AM |
| DBRE on-call | Postgres + WAL-G + PITR operations | Platform on-call |
| Platform on-call | Redis, Kafka, edge | DBRE on-call |
| SecEng on-call | Vault, KMS, HSM, secrets | SRE on-call |
| Compliance liaison | Audit chain reconciliation, regulator clock | Legal |
| Customer Success | Direct customer outreach for top accounts | AM rotation |

**Conflict-of-interest rule:** The Auditor role for any given drill must be
staffed by someone who did not author the runbook change being exercised
and is not on the on-call rotation for the impacted component during the
drill window.

---

## 10. Post-Drill Report Template

Copy this template into the [drill register](../operations/dr-drill-register.md)
under `YYYY-Qn/`. **Retention: 7 years** from the drill date (compliance).

```markdown
# DR Drill Report — Scenario {A|B|C|D} — {YYYY-MM-DD}

- **Sentinel ID:** DR-DRILL-{YYYY}-{Q#}-{seq}
- **Drill date:** YYYY-MM-DD
- **Drill window:** HH:MM – HH:MM TZ
- **Scenario:** A — Region outage | B — PG corruption | C — Audit tamper | D — Cert compromise
- **Drill Commander:** {name}
- **Backup Reviewer:** {name}
- **Comms Lead:** {name}
- **Auditor:** {name}
- **Scribe:** {name}
- **Participants:** {names}

## Objectives

- [ ] Tier 0 — RPO ≤ 1 min, RTO ≤ 30 min
- [ ] Tier 1 — RPO ≤ 15 min, RTO ≤ 2 h
- [ ] Tier 2 — RPO ≤ 1 h, RTO ≤ 4 h
- [ ] All five phases executed (Detection → Containment → Eradication → Recovery → Lessons)
- [ ] Customer comms validated (§8.1 announcement sent ≥7d prior, status page updated)
- [ ] Audit reconciliation passed (§7.5)
- [ ] All §5.7 known-good queries passed

## Timeline

| Time (UTC) | Phase | Action | Owner | Notes |
| --- | --- | --- | --- | --- |
| HH:MM | Detection | Synthetic probe failed | … | … |
| HH:MM | Detection | Page acknowledged | … | … |
| HH:MM | Containment | Status page → Major Outage | Comms | … |
| HH:MM | Eradication | PITR target chosen: {LSN/time} | Backup Reviewer | … |
| HH:MM | Recovery  | pg-t0 promoted | DBRE | timeline_id={N} |
| HH:MM | Recovery  | HSM unwrap probe OK | SecEng | latency_ms={N} |
| HH:MM | Recovery  | §5.7 T0 queries passed | Backup Reviewer | … |
| HH:MM | Lessons   | Marker signed into audit chain | Auditor | label=drill-{X}-{date} |

## Metrics — actual vs target

| Tier | Metric | Target | Actual | Pass/Fail |
| --- | --- | --- | --- | --- |
| 0 | RPO | ≤ 1 min | … | … |
| 0 | RTO | ≤ 30 min | … | … |
| 1 | RPO | ≤ 15 min | … | … |
| 1 | RTO | ≤ 2 h | … | … |
| 2 | RPO | ≤ 1 h | … | … |
| 2 | RTO | ≤ 4 h | … | … |
| — | MTTD | 5 min | … | … |
| — | MTTA | 10 min | … | … |
| — | Audit-chain reconciliation | clean | … | … |
| — | Customer comms ≥ 7d prior | yes | … | … |

## Gap list

Each gap that was uncovered, even if mitigated in-drill, MUST be listed.
A clean drill with zero gaps is suspicious and triggers a peer review.

| # | Gap (one sentence) | Severity (P0/P1/P2) | Root cause | Mitigation in drill | Permanent fix owner |
| --- | --- | --- | --- | --- | --- |
| 1 | … | … | … | … | … |

## Action items

| # | Owner | Due | Description | Tracking |
| --- | --- | --- | --- | --- |
| 1 | DBRE | YYYY-MM-DD | … | JIRA-… |

## What went well

- …

## What went poorly

- …

## Sign-off

- Drill Commander: __________  Date: __________
- Backup Reviewer: __________  Date: __________
- Auditor:         __________  Date: __________
- SRE Lead:        __________  Date: __________
- Compliance:      __________  Date: __________

## Retention

This report is retained for **7 years** from {YYYY-MM-DD} in the drill
register and the S3 Object-Lock bucket
`s3://sentinelx-dr-reports/{YYYY}/{QN}/`. Deletion before
{YYYY+7-MM-DD} requires written approval from the General Counsel.
```

---

## 11. Cross-References

- [DR drill template](./disaster-recovery-drill-template.md) — fill-in-the-blanks live checklist.
- [Incident Response Runbook](./incident-response.md) — for non-DR incidents.
- [Breach Notification Runbook](./breach-notification.md) — when DR is also a breach (e.g., Scenario C).
- [FinOps Runbook](./finops.md) — for cost impact of DR events.
- [Architecture overview](../architecture.md) — component map.
- [SLOs](../slos.md) — what we owe customers in steady state.
- [Audit chain design](../security/audit-chain.md) — internals of the hash chain.
- [sx-storage migrations](../../crates/sx-storage/migrations/) — authoritative table definitions referenced by §5.7.
- [DR drill register](../operations/dr-drill-register.md) — historical drill reports.

---

## 12. Change History

| Date | Author | Change |
| --- | --- | --- |
| 2026-06-14 | SRE Lead | **P2-011**: tiered RTO/RPO (T0/T1/T2), pg_basebackup + WAL streaming commands, ClickHouse `BACKUP`/`RESTORE`, Redis RDB cadence table, HSM-only KEK section, step-by-step PITR keyed to sx-storage tables, drill roles (Drill Commander / Backup Reviewer / Comms Lead / Auditor), pre-drill announcement template, post-drill report template with RPO/RTO actual-vs-target + gap list, 7-year retention. |
| 2026-05-30 | SRE Lead | Initial publication. RPO 15 min, RTO 4 h. |
| 2026-03-12 | SRE Lead | Drafted from Q1 drill retro. |
