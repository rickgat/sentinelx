# ADR 0014 — ClickHouse for log events; projection strategy + retention TTLs (over Postgres TimescaleDB)

Status: Accepted
Date: 2026-06-12
Deciders: Principal Data Engineer, Principal Platform Engineer, SRE Lead
Supersedes: None
Superseded by: None

## Context

P0-003 ingests log events at high volume. The 12-month projection
for a 10 k-tenant deployment is:

- ~5 k events/s steady-state (peak 25 k events/s during a customer
  incident).
- ~430 M events/day at steady-state.
- ~12-month retention for `events_normalized`.

The hot read patterns are:

- "show me all auth events for user X in the last 24 h" (UI search);
- "give me the per-hour count of severity ≥ HIGH events for tenant
  T" (dashboard widget);
- "match this OCSF event against the SOC correlator's rule set"
  (correlator hot path);
- "give me every event matching this MITRE technique" (threat-hunt
  query).

We evaluated three OLAP candidates plus the in-Postgres extension:

1. **Postgres + TimescaleDB.** Compresses well, hypertables make
   partitioning trivial, the team already operates Postgres.
   Falls down at 5 k events/s sustained write (we'd need 4-shard
   Postgres + dedicated Timescale clusters per tenant cohort).
2. **ClickHouse.** Purpose-built for OLAP at this scale, columnar
   storage, projection support for hot read paths, well-understood
   operational profile (the SRE team has run ClickHouse on a prior
   product).
3. **Apache Druid.** Strong for time-series OLAP but operationally
   heavier (Zookeeper, multiple process types) and weaker
   write-path ergonomics from Rust.
4. **VictoriaLogs / Loki.** Strong for log search but weak for
   OCSF-shape relational queries (categorical filters across
   millions of rows).

## Decision

### Engine: ClickHouse 24.x

- Columnar `MergeTree` engine with native ZSTD compression.
- `LowCardinality(String)` for the source / severity / cloud_*
  columns gives 10–20× compression on those.
- Native `IPv6` type (with IPv4 mapping) for `src_ip` / `dst_ip`.
- Projections for the two hot read patterns the dashboard hits
  (by user, by severity).

### Tables

See [RDBMS.md §16](../RDBMS.md#16-clickhouse--ocsf-log-event-lake-p0-003)
for full DDL. Summary:

- `events_raw` — line-level capture, 7-day TTL.
- `events_normalized` — OCSF 1.x canonical shape, 13-month TTL.
- `soc_event_archive` — legacy `soc_event` cold partitions, 12-month TTL.

### Partition + ordering keys

- `events_normalized` partitions by `toYYYYMM(time)` (one part per
  month per tenant); ordered by `(tenant_id, time, class_uid,
  event_id)`. The leading `tenant_id` ensures per-tenant scans are
  contiguous on disk.
- `events_raw` partitions by `toYYYYMMDD(received_at)` (one part
  per day per tenant). The shorter partition is because raw rows
  age out aggressively (7 days) and per-day parts make the TTL
  drop cheap.

### Projection strategy

Two projections on `events_normalized`:

| Projection | Read pattern | Order |
|---|---|---|
| `events_normalized_by_user` | "all events for user X in the last N hours" | `(tenant_id, actor_user_name, time)` |
| `events_normalized_by_severity` | "severity ≥ HIGH in the last N hours" | `(tenant_id, severity_id, time)` |

Both projections materialise the same columns as the base table.
Disk overhead is ~2× the base table; the query latency on the
indexed columns drops from ~800 ms to ~30 ms at the 12-month scale.

Adding a third projection requires data-engineer sign-off because
each one approximately doubles the disk footprint of the
underlying part.

### Retention TTLs

| Table | TTL | Action |
|---|---|---|
| `events_raw` | `received_at + INTERVAL 7 DAY` | DELETE |
| `events_normalized` | `time + INTERVAL 13 MONTH` | DELETE (no cold archive — cost-prohibitive at scale) |
| `soc_event_archive` | `received_at + INTERVAL 1 YEAR` | DELETE |

A tenant on the `enterprise` / `sovereign` edition can extend the
`events_normalized` retention to 24 months by paying the storage
overage. The override lands on `tenant.events_retention_months`
(default 13) and is applied at part-merge time via a TTL recompute.

### Tenant isolation

ClickHouse does not have a Postgres-RLS equivalent that respects
the SET-GUC pattern. We enforce isolation in two layers:

1. **Driver-layer template enforcement** — every Cypher-shaped
   template in `crates/sx-log-ingest/src/ch.rs` prepends
   `tenant_id = {tid:UUID}` and refuses templates that already
   contain a `tenant_id` literal.
2. **`ROW POLICY` on the read-only user** — the `sx_app_ro`
   ClickHouse user holds only SELECT, and only through a row
   policy that filters on the `SX_TENANT_ID` session setting.

Both layers must pass for a read to land; either alone is
considered insufficient (defence in depth).

### Operational profile

- 3-node ClickHouse cluster with ReplicatedMergeTree for HA.
- ZooKeeper / ClickHouse Keeper for replication coordination
  (Keeper preferred, ZooKeeper kept as a fallback).
- Disk: NVMe with separate SSD for the WAL.
- Backups: daily `clickhouse-backup` to S3 (separate bucket from
  Postgres backups, separate KMS key).
- Sizing at 10 k tenants: ~24 TB hot tier, ~70 TB after 13 months
  with replication factor 2.

## Consequences

- **Sub-second dashboard queries at scale.** The projections turn
  the user-search and severity-filter widgets into ~30 ms
  responses.
- **Two new operational dependencies** (ClickHouse + Keeper)
  beyond the Postgres-only deployment.
- **Tenant isolation is enforced in two places.** Both layers
  required; either alone is a defence-in-depth gap.
- **Replay path is straightforward.** Normaliser bugfix? Re-read
  `events_raw` for the affected source + window, re-emit through
  the normaliser, INSERT to `events_normalized` with
  `ON CONFLICT DO NOTHING` semantics (via the per-row `event_id`).
- **Cost-vs-retention trade-off is explicit.** 13 months default;
  extension is a paid option on the higher editions.
- **No cold archive past 13 months in the default tier.** Tenants
  that need 7-year retention buy the enterprise tier or hand over
  to a customer-side SIEM for long-term storage.

## Alternatives Considered

- **Postgres + TimescaleDB.** Rejected — would not survive the
  5 k events/s sustained write at 10 k-tenant scale without
  sharded Postgres, which adds operational complexity larger than
  running ClickHouse.
- **Apache Druid.** Rejected — operationally heavier (multiple
  process types) and the Rust write-path tooling is thinner than
  for ClickHouse.
- **Elasticsearch / OpenSearch.** Rejected — strong for free-text
  search but weak for categorical filters across hundreds of
  millions of rows; also licensing churn is a long-term tail risk.
- **Loki + VictoriaLogs.** Rejected — strong for log search,
  weak for the OCSF-shape relational queries the SOC correlator
  needs.
- **Materialised views instead of projections.** Considered;
  rejected because ClickHouse projections give us the same
  read-path acceleration without forcing the writer to maintain
  the MV on every INSERT.
