# Multi-Region Deployment Runbook

> **Last reviewed:** 2026-06-14
> **Maintainer:** SRE Lead (sre-lead@sentinelx.io) / On-call rotation: `pagerduty://sentinelx-sre`
> **Next review:** 2026-09-14 (quarterly cadence)
> **Document owner:** Platform Engineering
> **Classification:** Internal — Restricted
> **Related:** [`./disaster-recovery.md`](./disaster-recovery.md), [`./incident-response.md`](./incident-response.md), [`./finops.md`](./finops.md)

---

## 1. Purpose & Scope

This runbook governs **steady-state multi-region operation** of SentinelX — the
day-2 reality of running active-active or active-warm-standby across two or more
regions. It complements the disaster-recovery runbook: DR covers the unplanned
loss of a region; this document covers everything that has to be *true every
day* for that DR plan to actually work, plus the planned-promotion procedures
used during scheduled regional drains, blue/green region cutovers, and tenant
geo-pinning changes.

**In scope:**

- Topology choices (active-active vs. active-passive) and the tenant-size class
  decision matrix.
- Traffic routing (GeoDNS, anycast, health-check failover, session pinning).
- Data-plane replication for every stateful component (Postgres, ClickHouse,
  Redis, S3, Vault/KMS, Kafka).
- Terraform module layout for per-region IaC.
- Smoke tests run after region promotion.
- Rough cost model (percentage uplift vs. single-region baseline).
- Risk register for cross-region operation.

**Out of scope:**

- Unplanned region loss → see [`./disaster-recovery.md`](./disaster-recovery.md).
- Per-incident comms / status page → see [`./incident-response.md`](./incident-response.md).
- Per-AZ failure inside a single region — handled by the orchestrator and not
  surfaced to operators.

---

## 2. Tenant Size Classes

Topology recommendations below are keyed off a tenant size class. The classifier
lives in `sx-billing::tenant_class`; the boundaries are intentionally loud so
the field stays a discrete enum (no "between L and XL"):

| Class | Active orgs | Indicators (any one trips the class) | Default topology |
| --- | --- | --- | --- |
| **S** (small) | 1–25 | < 50 RPS sustained, < 50 GB warm data, < 5 ingestion sources | Single-region, multi-AZ |
| **M** (mid) | 26–250 | 50–500 RPS, 50 GB–2 TB warm, BAS opt-in | Single-region + warm DR (active/warm-standby) |
| **L** (large) | 251–2 500 | 500–5 000 RPS, 2–25 TB warm, regulated industry, MSSP reseller | **Active-active 2 regions** (read-anywhere, tenant-pinned writes) |
| **XL** (enterprise) | 2 500+ or sovereign | Custom SLA, data-residency clause in MSA, dedicated cell | **Active-active 3+ regions**, dedicated cell per region, no shared tenancy with other XL |

`tenant_class` is recomputed nightly. A class promotion triggers a JIRA ticket
to the customer-success rep so we can plan the topology change with the
customer — never a silent migration.

---

## 3. Topology Choices

### 3.1 Active-active vs. active-passive

| Dimension | Active-active | Active-warm-standby (active-passive) |
| --- | --- | --- |
| RTO | < 60 s (DNS TTL + health check) | 5 min–4 h (region warm-up, Postgres promote) |
| RPO | 0 for cross-replicated tables, 1–5 s for async | 15 min (matches DR runbook) |
| Steady-state cost vs. single-region | +85 %–110 % | +35 %–50 % |
| Operational complexity | High — split-brain risk, conflict resolution, dual-write debugging | Medium — promote-and-pray on the bad day |
| Required eng maturity | Senior DBRE on staff, chaos drills run | SRE on-call + quarterly DR drill |
| Best for | L, XL, regulated, MSSP | S, M, single-tenant-region deployments |
| Worst for | Write-heavy bursty workloads with strong ordering needs | Customers paying for sub-minute RTO |

**Recommendation per class:**

| Class | Recommended | Acceptable fallback | Hard no |
| --- | --- | --- | --- |
| S | Single-region multi-AZ | — | Active-active (wasteful) |
| M | Active-warm-standby | Single-region multi-AZ if customer signs RTO=4h waiver | Active-active (wasteful) |
| L | **Active-active 2 region, tenant-pinned writes** | Active-warm-standby if eng team < 4 SREs | Single-region |
| XL | **Active-active 3 region cell per tenant** | Active-active 2 region with dedicated cell | Shared cell with other XL |

The "tenant-pinned writes" pattern (a.k.a. **home region**) is the central
trick: every tenant has exactly one *write* region. Reads can be served from
any region. This gives us active-active read availability without paying the
multi-master write-conflict tax. We do **not** run multi-master Postgres in
production for the OLTP path. (We do run multi-master for the audit ledger;
that table is append-only and conflict-free by construction.)

### 3.2 Active-active sub-modes

1. **Symmetric** — every region runs every service, every tenant routes by
   geo-proximity to its home region. Default for L.
2. **Cellular** — each tenant lives in a *cell*; cells are placed in regions,
   never split. XL only. A cell is a Terraform workspace; see §6.
3. **Read-replica fan-out** — writes go to one region, reads anywhere. We use
   this for the data-residency case where a customer demands writes stay in
   `eu-central-1` but is okay with cached reads served from `us-east-1`.

---

## 4. Traffic Routing

### 4.1 GeoDNS as the first hop

We use Route 53 **geolocation** routing for the customer-facing apex
(`api.sentinelx.io`, `app.sentinelx.io`) with a *latency* fallback. Each region
publishes a regional CNAME (`api.use1.sentinelx.io`, `api.apse1.sentinelx.io`,
etc.) protected by a Route 53 health check.

> **RFC 9460 note (SVCB/HTTPS records):** for the public API endpoint we also
> publish `HTTPS` resource records (RFC 9460 §7) with `alpn=h2,h3` and
> `ipv4hint`/`ipv6hint` parameters. This lets clients on RFC 9460-aware
> resolvers (Chrome 117+, Firefox 119+, BIND 9.18+) skip the A/AAAA round trip
> and start TLS to the geo-closest endpoint in one RTT. The SVCB *target* is
> the regional CNAME, so geolocation routing still drives the choice — we are
> not bypassing the policy, just shaving a round trip when clients support it.

| Record | Type | Routing policy | TTL |
| --- | --- | --- | --- |
| `api.sentinelx.io` | A / AAAA | Geolocation (continent → region) | 60 s |
| `api.sentinelx.io` | HTTPS (SVCB) | Same target, advertises h2 + h3 | 300 s |
| `api.{region}.sentinelx.io` | A / AAAA | Failover (primary = regional NLB, secondary = next-nearest region NLB) | 30 s |
| `*.tenant.sentinelx.io` | CNAME | Weighted (controlled per tenant home-region) | 60 s |

**60-second apex TTL** is deliberate. Going lower (Route 53 minimum is 1 s)
trades resolver cost for failover speed we cannot actually use, because
Postgres promote dominates the timeline. Going higher punishes us during
deliberate region drains.

### 4.2 Health checks and failover

- Route 53 health checks hit `/-/healthz` on the regional NLB every 10 s from
  3 checker locations. Threshold: 3 consecutive failures → unhealthy (30 s to
  fail).
- The health endpoint is *deep* — it touches Postgres (read), Redis (PING),
  ClickHouse (`SELECT 1`), and the region's Vault unseal status. A region that
  cannot serve real requests must not pass `/-/healthz`.
- We also wire a CloudWatch alarm on `5xx_rate_5m > 2 %` as a *secondary*
  failover trigger via Lambda → Route 53 record-set update, because DNS
  health checks alone miss application-layer brownouts.
- DNS failover is **advisory, not authoritative**. The operator-facing decision
  to declare a region down still goes through the IC (see DR runbook §5.1) for
  any failover that involves Postgres promotion.

### 4.3 Session pinning: cookie-based vs. token-only

We are token-only. We do **not** use sticky session cookies for region pinning,
for three reasons:

1. **Multi-device users.** A cookie scoped to `api.sentinelx.io` does not
   travel cleanly across the dashboard SPA, the CLI, and the BAS agent on the
   same account.
2. **JWT carries the region claim already.** Every access token issued by
   `sx-auth` contains a `home_region` claim. The edge proxy reads it and
   routes write requests to that region's NLB. Reads stay local. This is the
   only place tenant-pin enforcement happens, and there is exactly one of it.
3. **Sticky cookies + GeoDNS = footgun.** When DNS fails over but the cookie
   still pins to the dead region, the client black-holes silently. The
   token-only path means a region failure invalidates *nothing* — the token's
   `home_region` claim just resolves to the failover region after Route 53
   updates.

For the unauthenticated marketing site we use cookie-based pinning (`SX-Edge`
cookie, `SameSite=Lax`, 30 min) purely for cache affinity. It is never trusted
for security decisions.

### 4.4 Anycast for the ingest plane

Customer ingest (`ingest.sentinelx.io` — agents, SIEM forwarders, webhook
sources) terminates on AWS Global Accelerator anycast IPs, not GeoDNS. Reasons:

- Agents resolve DNS once at process start and cache for hours; GeoDNS would
  pin them to one region for too long.
- Global Accelerator gives us **sub-30-second** withdrawal of a region from
  BGP advertisement, faster than DNS TTL.
- Ingest is write-asymmetric and tenant-pinned at the application layer
  anyway; the anycast hop just lands traffic at the nearest healthy region's
  ingest gateway, which then forwards (or queues) to the tenant's home region.

---

## 5. Data Plane

### 5.1 Postgres

**We run Patroni 3.3.x on PostgreSQL 16.x.** Streaming physical replication
for the OLTP tier; logical replication for cross-region "global tables"
(tenant directory, feature flags). We evaluated and rejected Citus (see below).

| Component | Choice | Why |
| --- | --- | --- |
| Cluster manager | **Patroni 3.3** with `etcd` v3 DCS | Patroni's `synchronous_node_count` is per-cluster, well-understood, and the leader-election semantics are documented in the Patroni 3.x reference |
| Replication mode (intra-region) | Synchronous (`ANY 1 (replica_a, replica_b)`) | 1 sync replica protects the RPO without doubling write latency |
| Replication mode (cross-region) | Asynchronous streaming + WAL-G shipping | Cross-region sync would push p99 writes past 80 ms — not acceptable for L tenants |
| PITR | WAL-G to S3, `archive_timeout=60s`, 5-minute upload cycle | Matches DR runbook §4.1 |
| Connection pooling | PgBouncer per region, `transaction` mode | Required for tenant-pin enforcement at the proxy layer |
| Read replicas | 2 per region (1 sync, 1 async + reporting role) | Reporting role serves the BAS and finops dashboards |

**Why not Citus?** Citus 12.x (now bundled into Postgres 17 as a community
extension) is excellent for *horizontal sharding within a single region* but
adds little for our cross-region story. Our hot tables are already
tenant-keyed; we shard them by `tenant_id` at the application layer via
PgBouncer pool selection. Adding Citus would force every join through the
coordinator and reintroduce a single point of failure we have spent two years
removing. Reconsider if a single tenant ever exceeds 5 TB of warm OLTP data.

**Failover lag — the 5-minute reality.** Patroni's *automatic* failover within
a region is sub-30-second. **Cross-region promotion is a 5-minute floor**,
and operators should plan for that. The number comes from:

| Step | Time | Notes |
| --- | --- | --- |
| Detect primary region down | 30–60 s | Route 53 + Patroni `loop_wait` |
| Drain in-flight cross-region writes | 30 s | Hard stop after timeout |
| Wait for WAL replay catch-up on standby | 60–180 s | Depends on lag at moment of failure; nightly we check this stays < 60 s |
| Promote standby leader (`patronictl failover`) | 30 s | New leader elected |
| Repoint PgBouncer in DR region | 15 s | Config reload, no restart |
| Application warm-up + cache rebuild | 30–60 s | First queries warm Linux page cache |
| **Total floor** | **~5 min** | Matches the DR runbook RTO bucket |

Do not promise customers anything tighter than 5 minutes for cross-region
Postgres failover. The DR runbook's overall 4-hour RTO bakes this in.

**Multi-region keyspaces.** Three table classes:

1. **Tenant-local** (default): single home region, async replica elsewhere
   for DR only. Reads against the replica are explicitly opt-in per query.
2. **Global directory** (small, slow-changing — tenants, users, feature flags):
   one writer region, logical replication to all others via
   `pglogical` 2.4 subscriptions. Conflict policy: writer-wins, with a daily
   reconciliation job.
3. **Append-only audit ledger**: see §5.7 below.

### 5.2 ClickHouse

ClickHouse holds detection telemetry, posture history, and the UEBA baseline
event store. The multi-region topology:

| Layer | Topology |
| --- | --- |
| Cluster | `sx_cluster_{region}`, 3 shards × 2 replicas (6 nodes) per region |
| Replication within region | `ReplicatedMergeTree` with ZooKeeper (or ClickHouse Keeper from 24.8 onwards) |
| Replication across regions | Distributed table over a **federated** view, plus async S3-backed `system.parts` shipping for cold tiers |
| Storage | Tiered: hot on local NVMe, warm on EBS `gp3`, cold on S3 with `storage_policy = 'hot_warm_cold'` |
| Cross-region query | `clusterAllReplicas('sx_global', system, parts)` — fan-out reads only for compliance dashboards |

We do **not** synchronously replicate ClickHouse across regions. We replicate
*S3 parts* asynchronously and let each region serve queries from its local
shards. Cross-region fan-out is gated behind an `X-Sx-Allow-Cross-Region`
header that the dashboard sets only for the compliance officer role.

**Why ClickHouse Keeper.** ZooKeeper is operationally heavy for what is
essentially a Raft log. From ClickHouse 24.8 LTS we run Keeper standalone
(3-node) per region. Cross-region Keeper is **not** supported and we do not
run it; each region's Keeper is independent. Failover semantics: a region
loss is a data loss for the **last 60–300 s** of telemetry not yet shipped to
S3, which is acceptable per the UEBA RPO of 15 minutes.

### 5.3 Redis

| Use case | Topology | Failover |
| --- | --- | --- |
| Cache (sessions, hot lookups) | **Redis Cluster 7.4** intra-region (3 masters + 3 replicas), no cross-region replication | Treat cross-region as cold — rebuild on failover |
| Queues (BullMQ, job state) | **Redis Sentinel** intra-region (1 master + 2 replicas + 3 sentinels), async cross-region replica via `replicaof` | Sentinel auto-promotes within region; cross-region is manual |
| Rate-limit counters | Redis Cluster, no cross-region | Acceptable to lose 1 minute of counters |

**Why Cluster for cache, Sentinel for queues.** Redis Cluster gives us
horizontal sharding and sub-second intra-region failover, but its
cross-region story is poor (no cross-cluster replication primitive that we
trust in production as of Redis 7.4). Sentinel is single-shard but supports
plain `replicaof` to a cross-region replica, which is what we need for the
queue tier where we cannot afford to drop in-flight jobs.

**Do not** put queue Redis on Redis Cluster and hope for the best. The
`MOVED`/`ASK` redirection semantics interact poorly with BullMQ's transaction
scripts and we have a postmortem on file from 2024 to prove it.

### 5.4 S3 / Object storage

| Bucket class | Replication | Lock |
| --- | --- | --- |
| Telemetry archives | S3 CRR, `STANDARD_IA` → `GLACIER_IR` after 30 d | None |
| Audit anchors | S3 CRR + **Object Lock Compliance mode**, 7-year retention | Compliance |
| WAL-G | S3 CRR | None |
| Customer evidence (DAST, BAS reports) | S3 CRR + Object Lock Governance, 1-year | Governance |
| Terraform state | S3 versioning + CRR + DynamoDB lock per region | Versioning |

CRR is configured with **Replication Time Control (RTC) 15-minute SLA** on
audit-anchor and WAL-G buckets — both pay the RTC surcharge in exchange for
the AWS-backed 99.99 % / 15-min replication SLA. Other buckets use vanilla
CRR (best-effort, typically < 15 min, no SLA).

Replication is one-way per bucket pair. Bidirectional replication is
deliberately avoided for compliance reasons (a corrupted object in the DR
region must not propagate back to the primary).

### 5.5 Secrets, KMS, multi-region keyrings

| System | Multi-region strategy |
| --- | --- |
| Vault (HashiCorp 1.16+) | Performance replica in each non-primary region; one primary cluster (Raft, 5 nodes) globally; performance secondaries forward writes to primary |
| AWS KMS | **Multi-Region Keys** for envelope encryption (`MRK-` prefix). One primary, replicas in every active region |
| GCP Cloud KMS | Multi-region keyrings (`global`, `nam4`, `eur4`) per data-class — see [`sx-secrets` P1-006/P1-007 KEK provider](../../crates/sx-secrets/README.md) |
| Application secrets | Vault KV-v2 + Transit per region; cached via agent sidecar with 5-min TTL |

**Key-rotation coordination is the single most-stepped-on rake in multi-region
operation.** The rules:

1. **One rotation window per quarter, globally.** Never overlap regions.
2. **Old key version stays decrypt-capable for ≥ 30 days** after rotation
   (Vault Transit `min_decryption_version` rule). This covers the worst-case
   cross-region replication lag plus a 7-day buffer.
3. **KMS MRK rotation is region-pinned** (AWS rotates the primary; replicas
   pick up the new key material lazily). Audit anchors signed before the
   rotation must still verify after — the anchor record carries the key
   version explicitly.
4. **The rotation is a chaos drill in disguise.** If a rotation breaks
   anything, we caught a multi-region replication bug before a real outage.

### 5.6 Kafka / event spine

| Component | Topology |
| --- | --- |
| Brokers | 3-broker cluster per region (Strimzi on K8s) |
| Cross-region | MirrorMaker 2.0 (Kafka 3.7+), one-way `primary → dr`, plus a *separate* MirrorMaker pair for `dr → primary` audit events only |
| Consumer offset replication | `enabled: true` (MM2 offset sync); consumers in DR region resume within ~1 minute of failover |
| Topic naming | Region-prefixed (`use1.posture.events`) to avoid bidirectional loops |

### 5.7 Audit ledger (append-only, multi-master)

The audit ledger is the *one* place we run effectively-multi-master writes.
Mechanism:

- Each region appends to its own partition (`audit_{region}`).
- Partitions are merged in a daily Merkle root, anchored to S3 Object Lock
  (see DR runbook §4.3).
- No cross-region row conflicts are possible because no row is ever updated.
- A reader querying "show me everything" walks all region partitions and
  merges by `(region, seq, ts)`.

This pattern is intentionally narrow. Do not generalize it without writing a
new RFC.

---

## 6. Per-Region IaC Layout (Terraform)

Module layout under `infra/terraform/`:

```
infra/terraform/
├── modules/
│   ├── region-foundation/      # VPC, subnets, NACLs, IAM baseline
│   ├── data-postgres/          # Patroni + WAL-G + PgBouncer
│   ├── data-clickhouse/        # CH cluster + Keeper + S3 disk
│   ├── data-redis-cluster/     # cache tier
│   ├── data-redis-sentinel/    # queue tier
│   ├── data-kafka/             # Strimzi + MM2 hooks
│   ├── edge-route53/           # geo + failover records (global, not per-region)
│   ├── edge-globalaccelerator/ # anycast for ingest
│   ├── secrets-vault/          # Vault primary/secondary toggle
│   └── observability/          # Prom, Loki, Tempo per region
├── envs/
│   ├── prod-use1/              # us-east-1 — region root
│   │   ├── main.tf             # composes modules; flips region_role = "primary" | "secondary"
│   │   ├── backend.tf          # S3 bucket sentinelx-tfstate-use1
│   │   └── terraform.tfvars
│   ├── prod-euc1/              # eu-central-1
│   ├── prod-apse1/             # ap-southeast-1
│   └── prod-global/            # global resources: Route 53 zones, KMS MRKs, IAM roles
└── policies/                   # Sentinel / OPA policy bundles
```

Rules:

1. **Each region has its own state file and its own DynamoDB lock table.** A
   Terraform apply that touches two regions at once is forbidden — it goes
   through `prod-global` (which orchestrates) or two sequential applies.
2. **`prod-global` is the only workspace allowed to create cross-region
   resources** (KMS MRKs, Route 53 zones, IAM org-level roles, S3 CRR rules).
3. **`region_role` is a variable, not a module.** Flipping a region from
   secondary to primary is a `tfvars` change + a controlled apply, not a
   different code path. This makes blue/green region cutovers a code review
   instead of a migration.
4. **No `count` / `for_each` across regions.** Each region is a separate
   workspace; we never want a single plan to be able to destroy two regions.
5. **Module versioning is pinned in `envs/*/main.tf`** via `?ref=v1.4.0`. We
   roll out a module version to one region at a time.

Promotion of a region from secondary to primary (planned cutover):

```bash
cd infra/terraform/envs/prod-apse1
# Flip the role
sed -i '' 's/region_role = "secondary"/region_role = "primary"/' terraform.tfvars
terraform plan -out promotion.plan
# Plan must show: NLB weight update, Route 53 health-check primary swap,
# Patroni leader hint update. Nothing else.
terraform apply promotion.plan
```

This must show fewer than 25 resource changes. More than that means something
upstream drifted; halt and reconcile.

---

## 7. Smoke Tests After Region Promotion

Run **immediately** after the promotion apply completes. Each test maps to a
`sentinelx-cli smoke` subcommand and has a hard pass/fail.

| # | Test | Command | Pass criterion | If fail |
| --- | --- | --- | --- | --- |
| 1 | DNS resolution | `dig +short api.{region}.sentinelx.io` | Returns the new primary NLB IP within 90 s of apply | DNS cache; recheck from a fresh resolver |
| 2 | Edge health | `curl -fsS https://api.sentinelx.io/-/healthz` | HTTP 200, JSON `status=ok`, all deps green | Roll back region role; page IC |
| 3 | Postgres write | `sentinelx-cli smoke pg-write --tenant smoke-tenant` | Insert returns < 200 ms, row visible on local replica < 1 s | Inspect Patroni leader, PgBouncer pool |
| 4 | Postgres cross-region read | `sentinelx-cli smoke pg-read --from-region {other}` | Row from test #3 visible within 5 s | Likely WAL ship lag; check `pg_replication_slots` |
| 5 | ClickHouse insert | `sentinelx-cli smoke ch-write --table events.smoke` | Row visible on local shard < 2 s | Check Keeper quorum |
| 6 | Redis cache | `sentinelx-cli smoke redis-cache` | SET/GET round-trip < 5 ms p99 | Check cluster slot map |
| 7 | Redis queue (BullMQ) | `sentinelx-cli smoke queue-roundtrip` | Job enqueued and processed < 2 s | Check Sentinel failover state |
| 8 | Vault secret read | `sentinelx-cli smoke vault-read --path kv/smoke/canary` | Returns expected canary value | Vault unseal / replica lag |
| 9 | KMS envelope encrypt | `sentinelx-cli smoke kms-encrypt` | Encrypt + decrypt round-trip < 100 ms | MRK propagation; wait 60 s, retry |
| 10 | Kafka MM2 lag | `sentinelx-cli smoke kafka-lag` | MM2 lag for `*.audit.events` < 30 s | Check MM2 connector status |
| 11 | Auth token mint | `sentinelx-cli smoke auth-mint --tenant smoke-tenant` | Token issued, `home_region` claim matches new primary | sx-auth config drift |
| 12 | End-to-end synthetic | `sentinelx-cli smoke e2e --scenario login-and-list` | Walks login → API → render in < 3 s | Look at trace in Tempo |
| 13 | Audit anchor write | `sentinelx-cli smoke audit-anchor --dry-run` | Anchor would write to S3 Object Lock with retain-until = today + 7y | Object Lock policy drift |
| 14 | Cross-region BAS dispatch | `sentinelx-cli smoke bas-dispatch` | Worker in other region picks up job < 30 s | MM2 lag, worker pool size |
| 15 | Backup readiness | `sentinelx-cli smoke wal-g-status` | Most recent WAL ≤ 5 min old in this region | WAL-G cron stuck |

**All 15 must pass within 15 minutes of promotion.** Any fail is a hold on
ramping traffic past 10 %.

---

## 8. Cost Model

Percent uplift vs. a single-region baseline (S-class single region = 100 %).
Numbers are rough — within ±10 %, suitable for sizing conversations, not for
contract negotiations.

| Topology | Compute | Storage | Network egress | Total uplift |
| --- | --- | --- | --- | --- |
| Single region, multi-AZ (baseline) | 100 % | 100 % | 100 % | **100 %** |
| Active-warm-standby (DR-only second region at 25 % capacity) | +28 % | +45 % | +12 % | **+35 %–50 %** |
| Active-active 2 region, tenant-pinned writes | +85 % | +95 % | +60 % | **+85 %–110 %** |
| Active-active 3 region cellular (XL) | +175 % | +180 % | +120 % | **+170 %–200 %** |

Drivers worth knowing:

- **Cross-region data transfer** is the line item that surprises people. For
  active-active, ~60 % uplift on egress is mostly Postgres WAL shipping +
  Kafka MM2 + S3 CRR.
- **CRR with RTC** doubles per-GB replication cost vs. vanilla CRR. We pay it
  only on audit-anchor and WAL-G buckets.
- **ClickHouse storage** in active-active is +95 % not +100 % because the
  cold tier on S3 is single-copy (with CRR), not duplicated per region.
- **Compute uplift is sub-linear** in active-active because the secondary
  serves reads, not idle.

Always reconcile with the [`finops.md`](./finops.md) runbook before quoting
these to a customer.

---

## 9. Risk Register

| # | Risk | Likelihood | Impact | Mitigation | Owner |
| --- | --- | --- | --- | --- | --- |
| R1 | Cross-region replication lag exceeds RPO window during regional saturation | M | H | Alarm on `pg_replication_slots.confirmed_flush_lsn` lag > 30 s; auto-throttle non-essential writes; quarterly lag drill | DBRE |
| R2 | Split-brain on Patroni cross-region promotion (old primary returns) | L | **Critical** | `pg_rewind` only with operator approval; STONITH via security group revoke before promote; DNS cutover gated on `patronictl list` showing exactly one leader | DBRE |
| R3 | KMS MRK rotation desync — encrypt-region pre-rotation, decrypt-region post-rotation | M | H | `min_decryption_version` ≥ N-1 for 30 days; rotation is a single-region apply followed by 24h soak | SecEng |
| R4 | Route 53 health-check flap during brownout — flips traffic faster than Postgres can promote | M | H | 30-second failure threshold (3 × 10 s); secondary CloudWatch trigger has 5-minute cooldown | Platform |
| R5 | GeoDNS misroutes EU traffic to US region post-failover (residency violation) | L | **Critical** (regulatory) | EU-resident tenants tagged `data_residency=eu`; sx-auth refuses to mint tokens with `home_region != eu` for those tenants; smoke test #11 verifies | SecEng + Legal |
| R6 | S3 CRR queue backs up during region pressure; audit anchor RPO breached | L | H | CloudWatch alarm on `ReplicationLatency > 900s`; manual `aws s3api put-bucket-replication` reprioritization | Platform |
| R7 | Kafka MM2 offset drift — DR consumers replay or skip on failover | M | M | MM2 offset-sync enabled; idempotent consumers required; consumer-group naming convention enforces region prefix | Data Eng |
| R8 | Terraform `prod-global` apply during region outage — cannot reach affected region | M | M | `prod-global` plans must succeed in *isolation* mode (`-target` excludes the down region); documented break-glass | SRE |
| R9 | Redis Sentinel cross-region replica diverges silently | L | M | Daily `INFO replication` lag alert; weekly checksum on a canary key | Platform |
| R10 | ClickHouse Keeper quorum lost mid-promotion | L | M | 3-node Keeper minimum; per-region Keeper independent so a region loss never breaks another region's Keeper | Data Eng |
| R11 | Vault performance replica falls > 60 s behind primary | L | H | `vault read sys/replication/performance/status` exported to Prom; alert on `last_remote_wal` lag | SecEng |
| R12 | Cost overrun from accidental bidirectional CRR | L | M | Terraform OPA policy forbids `replication_configuration` blocks on more than one bucket-pair direction | FinOps |
| R13 | Sticky-session middleware accidentally enabled in front of token auth | L | H | Integration test `tests/edge/no_sticky_session.rs` runs in CI; alerts on `Set-Cookie: SX-Pin=` header in prod traffic sample | Platform |
| R14 | Patroni `etcd` DCS partition between region pair | L | H | `etcd` is per-region only (cross-region etcd is not supported); each Patroni cluster is single-region | DBRE |
| R15 | DNS TTL too low burns through Route 53 query budget at scale | L | L | 60 s apex TTL is the floor; budget reviewed monthly in finops | FinOps |

**Critical-impact risks (R2, R5)** must be exercised in the quarterly DR drill,
not just documented.

---

## 10. Operational Cadences

| Cadence | Activity | Owner |
| --- | --- | --- |
| Continuous | Replication-lag monitoring (PG, CH, Kafka, Vault) | SRE on-call |
| Daily | Cross-region pg_replication_slots health check | DBRE |
| Daily | S3 CRR backlog check on audit/WAL buckets | Platform |
| Weekly | Redis Sentinel cross-region canary key checksum | Platform |
| Monthly | Route 53 health-check synthetic failover (non-prod region) | SRE |
| Monthly | Terraform module drift detection (`terraform plan` in CI on every env) | SRE |
| Quarterly | Region drain drill — drain one region, smoke-test, undrain | IC + SRE |
| Quarterly | KMS / Vault Transit rotation (single region per quarter) | SecEng |
| Quarterly | Cost reconciliation against §8 model | FinOps |
| Annually | Re-evaluate Citus / multi-master Postgres against §5.1 rationale | DBRE |

---

## 11. Production Deployment Validation Gate (TOP5-#4)

This section is the **production-deployment readiness contract** added
in TOP5-#4. The PO walks the checklists here before allowing the
deployment to leave its window. It does NOT supersede §§1–10 — those
remain the steady-state operating contract — but it adds explicit
pass/fail gates a release manager can sign on.

### 11.1 Topology — the deployed picture

```
                    GeoDNS (Route 53, 60s TTL)
                            │
                  ┌─────────┴─────────┐
                  │                   │
              region-A             region-B
              (PRIMARY)            (STANDBY)
              ├ Patroni PG       ├ Patroni PG (sync replica via §5.1)
              │  leader          │  follower
              ├ ClickHouse        ├ ClickHouse
              │  shard 1         │  shard 2 (CRR via §5.2)
              ├ sx-monolith      ├ sx-monolith
              │  pods × N        │  pods × N (warm pool, ≥ 25% capacity)
              ├ Redis cluster    ├ Redis cluster
              │  (intra-region)  │  (intra-region; cold rebuild on FO)
              └ Vault perf       └ Vault perf
                 primary            secondary

       Cross-region: S3 CRR + MM2 Kafka mirror + audit anchor S3 Object Lock
```

The deployed topology MUST match this shape for the validation gate to
sign off. Any deviation (e.g. cross-region etcd, see §9 R14) is a
**hold** until exempted in writing by the DBRE lead.

### 11.2 Promotion playbook — when primary fails

Use this when the primary region is unreachable or degraded and the
on-call SRE elects to fail over (criteria: §4.2 + §10 risk register).
Reference for the underlying procedures: §5.1 (Postgres), §4.2
(routing), §7 (smoke tests).

| Step | Action | Owner | Pass criterion | Reference |
| --- | --- | --- | --- | --- |
| P0 | Declare incident; freeze deploys via `sentinelx-cli incident open --sev=P1 --topology-action=failover` | IC | Incident posted to status page within 5 min | `docs/runbooks/incident-response.md` §3 |
| P1 | Confirm primary actually down (not flap): three consecutive `/healthz` 5xx + Route 53 health check FAILED for ≥ 90 s | SRE on-call | All three signals red, not yellow | §4.2 |
| P2 | Engage DBRE: walk `patronictl list --cluster pg-primary` from a region-B operator host | DBRE | Reports `Leader: None` or unreachable, no split-brain candidate | §5.1 |
| P3 | Take old primary out of DNS *before* promoting standby (STONITH-by-DNS): `aws route53 change-resource-record-sets --hosted-zone-id ... --change-batch file://primary-out.json` | Platform | NXDOMAIN from a fresh resolver within TTL (60 s) | §4.1 R2 mitigation |
| P4 | Promote standby Postgres: `patronictl failover --candidate pg-standby-b-leader --cluster pg-primary` | DBRE | `patronictl list` reports exactly ONE leader | §5.1 Failover lag |
| P5 | Update DNS to point apex `api.sentinelx.io` to region-B NLB | Platform | DNS resolves to new IPs within 90 s of apply | §4.1 |
| P6 | Run the §7 smoke matrix (15 tests) | SRE on-call | All 15 pass within 15 min | §7 |
| P7 | Ramp traffic 10% → 50% → 100% with 10-min holds, watching `sx_http_requests_total{status=~"5.."}` and the SLO error budget burn | SRE on-call | No SLO threshold breach at each step | §11.3 (this section) |
| P8 | Declare promotion complete; reopen change window | IC | Status page updated; rollback playbook archived | `incident-response.md` §6 |

**Total floor: ~10 minutes** if every step is green. Real-world target
per the validation gate: **RTO ≤ 30 minutes**. Anything > 30 minutes
indicates the runbook needs amendment, not just the incident reviewed.

### 11.3 Pre-flight checklist (re-run before every prod cutover)

Sign with operator initials and timestamp. All MUST be green to ramp.

- [ ] **Replication lag SLO** — `pg_replication_slots.confirmed_flush_lsn`
      lag < 5 s on the standby region for the last hour.
      Query: `SELECT * FROM pg_replication_slots WHERE slot_type='physical';`
      (§5.1 / §9 R1)
- [ ] **Backup recency** — Most recent base backup < 24h old per
      `tier`; `wal-g backup-list` head shows a backup with `time` within
      window. (§9 R6 / `docs/runbooks/disaster-recovery.md`)
- [ ] **Failover dry-run** — Last quarterly failover drill ≤ 90 days
      ago, no skipped steps. See `docs/runbooks/failover-drill-template.md`.
- [ ] **Schema parity verified** — `tests/migration/parity_check.sh`
      exit 0 against the staging Postgres in the last 24h.
- [ ] **Seed parity verified** — `tests/migration/seed_parity.sh`
      exit 0 in the last 24h.
- [ ] **Load-test green** — `tests/load/k6/auth_flow.js` against the
      staging deployment passes all thresholds in the last 24h.
- [ ] **Telemetry readiness** — every box in
      `docs/runbooks/telemetry-readiness.md` ticked.
- [ ] **Kill-switch reachable** — `curl -fsS https://api.sentinelx.io/v1/safety/kill-switch`
      returns 200 from both regions. (Per §2.1 of `docs/slos.md`, kill
      switch is the load-bearing safety contract.)

### 11.4 RTO / RPO targets — production deployment gate

The gate enforces these targets, which are **tighter than** the
contractual SLAs in `docs/slos.md` so that an SLA breach is the
*second* signal an operator sees, not the first.

| Path | SLI | Target | Why this value |
| --- | --- | --- | --- |
| Auth (`POST /v1/auth/login`, `POST /v1/auth/refresh`) | RTO | < 5 min | Authentication is the entry point — locked-out customers cannot reach the kill switch or any other critical surface. The 5-min target absorbs DNS TTL (60 s) + health-check delay (90 s) + monolith warm-pool ramp (≤ 60 s). |
| Auth | RPO | 0 | Auth state (sessions, refresh tokens) is recreated on next login; no data loss possible by design. |
| Finding writes (`FOUND-001` insert path) | RTO | < 5 min | Same critical path: a finding insert that fails is a missed detection. Standby pods are warm and pre-authenticated to PG. |
| Finding writes | RPO | < 30 s | Findings carry CWE / CVSS / evidence — losing 30 s of inserts is acceptable; losing 5 min is a customer-visible coverage gap. Matches PG sync-replica commit lag floor. |
| Scan submission (`POST /v1/scans/http-headers`) | RTO | < 10 min | Async path; users can re-submit. |
| Scan submission | RPO | < 5 min | A lost in-flight scan re-runs from the SARIF cache (TOP5-#3-P2-SARIF-API). |
| SARIF read (`GET /v1/scans/:id.sarif`) | RTO | < 5 min | Read path; goes against the local replica post-promotion. |
| SARIF read | RPO | 0 | SARIF is rendered from stored `ScanRecord`; the underlying row is covered by the finding-write RPO. |
| Audit chain integrity (`/v1/audit/anchors`) | RTO | < 5 min | The anchor publisher is region-paired; standby publisher takes over via TSA fallback (`crates/sx-audit::tsa_fallback`). |
| Audit chain integrity | RPO | 0 | Anchor S3 bucket has Object Lock + CRR (§5.7); zero anchor loss tolerated. |

### 11.5 Telemetry — alerts that MUST be live before sign-off

Cross-link to `docs/runbooks/telemetry-readiness.md` for the full
checklist. The minimum set for the failover-needed signal:

| Alert | Metric | Threshold | Why it fires before a customer notices |
| --- | --- | --- | --- |
| Primary region down | `up{job="sx-monolith",region="primary"}` | == 0 for 90 s | Catches network partition before DNS health check |
| PG replication lag | `pg_replication_slots_confirmed_flush_lag_seconds` | > 30 s for 5 min | RPO budget burn for finding writes |
| Audit anchor stale | `sx_anchor_last_success_age_seconds` | > 86400 (24h) | Anchor RPO; cited in `docs/slos.md:46` |
| XMLDSig shadow mismatch spike | `xmldsig_shadow_mismatch_total` rate | > 0.01 / min | SAML verifier regression detector — ADR-0022 contract |
| Findings insert failed | `sx_findings_ingested_total{status="failed"}` rate | > 0.01 / min | FOUND-001 insert path health |
| Rate-limit reject burst | `log_ingest.rate_limited_total` rate | > 100 / 5 min | Indicator that the rate-limit emission path is firing (P2-008); itself not a fail, but feeds the SOC |
| RBA block burst | `rba_decision_total{action="block"}` rate | > 50 / 5 min per tenant | Abnormal block volume → IdP or attacker scan |

All metric names are the canonical strings from
`crates/sx-telemetry/`, `crates/sx-xmlsec/src/dual.rs:70`,
`crates/sx-rba/src/metrics.rs:74`, and `crates/sx-log-ingest/src/rate_limit.rs:47`.
Grep before editing.

---

## 12. Local Validation Harness

> **Added 2026-06-25 (TOP5-#4 LOCAL-VALIDATED).** A laptop-scale
> docker-compose harness that lets the PO drive the §11 validation
> artifacts before paying for a cloud staging cluster.

### 12.1 Where it lives

`deploy/local-multiregion/` — a self-contained docker-compose stack:

```
deploy/local-multiregion/
├── docker-compose.yml          7 services, 1 bridge network
├── README.md                   bring-up / smoke / parity / failover dry-run
├── .env.example                dev creds (well-known constants)
├── monolith.dockerfile         multi-stage rust:bookworm → debian-slim
├── monolith_config/            container-friendly sentinelx.local.yaml
├── nginx_lb/nginx.conf         round-robin upstream + /lb-health
├── pg_primary/                 init.sql (repl role + slot) + hba shim
├── pg_standby/                 standby-entrypoint.sh (pg_basebackup → standby.signal)
└── scripts/parity_local.sh     wrapper around tests/migration/parity_check.sh
```

### 12.2 What it validates

The harness exercises the same wire / topology surface the §11.3
pre-flight checklist gates on, at laptop scale:

| Validation slot | What the harness gives you |
| --- | --- |
| §11.2 promotion playbook step 2 (DNS / LB switch) | nginx round-robin between `monolith_primary` and `monolith_standby` — pull one out with `docker compose stop monolith_primary`, watch traffic shift |
| §11.2 step 4 (DB role swap: `pg_promote()`) | Real streaming-replication pair: `docker compose exec pg_standby psql -c "SELECT pg_promote(true, 60);"` — covered in README §8 |
| §11.3 pre-flight item 5 (k6 smoke against the auth flow) | `docker compose exec smoke_runner k6 run /tests/load/k6/auth_flow.js` |
| §11.4 RTO contract dry-run (auth / finding-write RTO) | Stop a monolith, time how long nginx + k6 take to settle (sub-second locally, NOT a cloud-scale measurement) |
| Migration parity gate (separate from the runbook itself) | `./deploy/local-multiregion/scripts/parity_local.sh` — wraps `tests/migration/parity_check.sh` |
| `failover-drill-template.md` step "promote standby" | Same `pg_promote()` step above — real Postgres 16 streaming replication, not a mock |

### 12.3 What it does NOT validate

The harness deliberately scopes down to "topology + wire path on one
host". The following gaps remain externally blocked on a real cloud
staging cluster:

- **Real cross-region latency.** Single Docker engine — `monolith_primary`
  and `monolith_standby` share a kernel scheduler. No RTT signal.
- **Real cloud-LB failover.** nginx OSS round-robin only; no active
  health probing, no anycast / GeoDNS, no session pinning.
- **ClickHouse multi-shard.** Single CH node — enough to validate the
  analytics adapter handshake, NOT to validate sharding or Keeper
  failover.
- **Network-partition behaviour.** Docker bridge doesn't model
  partitions; the in-tree `pg_basebackup` slot is conservative but
  won't surface split-brain. Use `pumba` or `tc netem` separately.
- **Cloud KMS / IAM rotation.** Vault / KMS adapters stay disabled.
- **Real workload mix.** Smoke is k6 at `K6_VUS=1 K6_DURATION=10s` by
  default; the §11.4 RTO/RPO numbers are still cloud-scale claims.
- **Per-AZ failure modes** — same as before, the orchestrator absorbs
  these and the local harness doesn't even have AZs.

### 12.4 PO workflow

1. `cp deploy/local-multiregion/.env.example deploy/local-multiregion/.env`
2. `cd deploy/local-multiregion && docker compose up -d --build`
   (first build is 10–25 min; subsequent <1 min)
3. `docker compose exec smoke_runner k6 run /tests/load/k6/auth_flow.js`
4. `./deploy/local-multiregion/scripts/parity_local.sh`
5. Failover dry-run per README §8.
6. Tick the relevant §11.3 pre-flight rows for "validated locally".
7. **Then** provision cloud staging and re-tick for "validated at scale".

### 12.5 Cross-references

- `deploy/local-multiregion/README.md` — bring-up + smoke + parity + failover dry-run
- `tests/load/README.md` §"Local smoke" — k6 entry point
- `docs/runbooks/failover-drill-template.md` — runbook the dry-run mirrors
- `docs/SPRINT_HARDENING_HANDOFF.md` — TOP5-#4 status row

---

## 13. Change Log

| Date | Change | Author |
| --- | --- | --- |
| 2026-06-14 | Initial multi-region runbook (P2-010) | Platform Engineering |
| 2026-06-25 | §11 production deployment validation gate (TOP5-#4): topology diagram, promotion playbook, pre-flight checklist, RTO/RPO contract, alert minimum set | Platform Engineering |
| 2026-06-25 | §12 local validation harness (TOP5-#4 LOCAL-VALIDATED): docker-compose smoke stack lets PO run §11 artifacts before cloud staging; renumbered Change Log to §13 | Platform Engineering |

