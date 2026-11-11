# ADR 0002: PostgreSQL as the primary transactional store

Maintainer: Platform Engineering (`#sentinelx-platform`)
Last reviewed: 2026-05-30

- Status: Accepted
- Date: 2026-05-30
- Deciders: Platform engineering, Data engineering
- Supersedes: None
- Superseded by: None

## Context

SentinelX persists at least seven distinct kinds of state, each with
different access patterns and durability needs:

1. **Transactional domain state** — tenants, users, engagements,
   findings, assets, audit log rows. Strong consistency required.
   Multi-row transactional writes. ACID is non-negotiable.
2. **Hot read-side cache** — JWT-blacklisted refresh-token IDs, rate
   limit counters, idempotency keys, short-lived session blobs. Sub-ms
   reads, may be lossy on restart.
3. **Attack graph** — assets connected by exposure edges, identity
   relationships, network paths. Query pattern is multi-hop traversal
   ("which assets are reachable from this leaked credential within
   four hops?"). Relational joins do not fit; recursive CTEs are too
   slow at our target scale (10M nodes).
4. **Cold analytics projections** — historical findings, trend
   analysis, executive reporting. Write-once, read-many, columnar
   aggregations dominate. Online OLTP would suffer if we joined
   against these.
5. **Object storage** — generated PDFs, SARIF bundles, raw scanner
   output, evidence ZIPs for auditors. Large blobs, content-addressed,
   write-rarely, read-rarely-but-strictly-when-asked.
6. **Time-series telemetry** — Prometheus metrics, OTel traces. Handled
   by the observability stack, out of scope for the application
   database choices but mentioned for completeness.
7. **Search index** — full-text on findings, comments, asset metadata.
   Currently small enough to live inside Postgres `tsvector`; may need
   to graduate.

We need to pick the primary store for (1) and decide where each of the
other workloads lives. The choice should minimize operational surface
area now while leaving room to graduate workloads as they outgrow the
primary.

Operational constraints:

- We run on Kubernetes in customer-owned clouds (BYOC) and in our
  managed offering. The store must work in both.
- We have one platform engineer per region; we cannot operate a
  bespoke distributed database.
- Recovery point objective (RPO) for transactional state: 5 minutes.
- Recovery time objective (RTO) for transactional state: 30 minutes.
- Audit log durability requirement (see ADR 0005): effectively zero
  loss; 99.999% durability target.

## Decision

PostgreSQL 16+ is the **primary transactional store**. Every workload
in category (1) lives in Postgres. We graduate workloads to specialized
stores only when measured demand makes the cost justified.

Specifically:

| Workload                        | Primary store         | When it graduates                                      |
| ------------------------------- | --------------------- | ------------------------------------------------------ |
| Tenants, users, JWT refresh     | Postgres              | Never. This is canonical state.                        |
| Engagements, assets, findings   | Postgres              | Never. Joined with everything else.                    |
| Audit log (append-only)         | Postgres + S3 anchors | See ADR 0005.                                          |
| Refresh-token denylist          | **Redis**             | Day-one. Postgres is fine but Redis TTL is simpler.    |
| Rate limit counters             | **Redis**             | Day-one. Postgres at 1 KHz writes is overkill.         |
| Idempotency keys                | Redis (24h TTL)       | Day-one.                                               |
| Short-lived BAS run state       | Redis (Streams)       | Day-one for live runs; archive lands in Postgres.      |
| Attack graph                    | Postgres -> **Neo4j** | When p99 of a 4-hop traversal exceeds 250 ms.          |
| Cold analytics                  | Postgres -> **ClickHouse** | When the warehouse table exceeds 500 GB.          |
| Object storage                  | **S3-compatible**     | Day-one. Bucket per tenant, lifecycle policy on each.  |
| Search                          | Postgres `tsvector`   | When index size exceeds 50 GB or recall drops below 95%. |

We deliberately accept Postgres "is enough" for now even where a
specialist DB would be faster, because operational simplicity beats
peak throughput at our scale.

### Postgres specifics

- **Version**: 16+ (we depend on `pg_stat_io`, generated columns, and
  the parallel COPY improvements).
- **Extensions**: `pgcrypto`, `uuid-ossp`, `pg_stat_statements`,
  `pg_trgm` for fuzzy search, `pgaudit` for system-level audit.
- **Schema-per-tenant** for tenant data. Shared `iam` and `audit`
  schemas. Row-level security policies on every tenant table; tests
  fail if RLS is disabled.
- **Connections** via SQLx pool, max 50 per pod, with a hard timeout of
  10s for any single query. Long-running scans go to a separate
  read-only pool with `statement_timeout=5min`.
- **Migrations** via SQLx migrations, checked into
  `crates/sx-storage/migrations`. Forward-only. Down migrations are a
  trap and we do not write them.
- **Backups**: continuous WAL archiving to S3, full base backup
  nightly, PITR retention 30 days. RPO 5 min validated quarterly.

### When Redis kicks in

Redis 7+ is the **non-durable** working set. Anything we put in Redis
must be reconstructable from Postgres or recomputable from inputs. We
use:

- **Strings + TTL** for idempotency keys, refresh-token denylist
  entries, login throttle counters.
- **Sorted sets** for rate limits (sliding window).
- **Streams** for live BAS run telemetry between the orchestrator and
  the dashboard websocket layer.
- **Pub/sub** for cluster-wide kill-switch propagation (see ADR 0004).

We do not use Redis as a primary store. If a Redis instance is lost we
should be able to bring up a fresh one and the platform self-heals
within a request cycle.

### When Neo4j enters

Neo4j is the attack-graph store. It enters the architecture only when
the Postgres-backed graph implementation cannot meet the latency
target (p99 < 250 ms for 4-hop traversal). The seam is the `GraphRepo`
trait in `sx-graph`; we have a Postgres adapter today (recursive CTE)
and a Neo4j adapter scaffolded behind a feature flag.

The trigger for switching the production binding is operational: when
the recursive CTE plan exceeds 250 ms on a representative tenant for
three days running, we flip the binding to Neo4j and reset the alert.

### When ClickHouse handles cold projections

ClickHouse is the analytics store. It enters when:

- A Postgres reporting query exceeds 30s p95, or
- The reporting tables exceed 500 GB and replication starts to lag.

Pattern is CDC (logical replication) from Postgres to ClickHouse via
Debezium or a Kafka Connect pipeline. Reports against the warehouse
flow through a separate `sx-report` adapter; the API surface does not
change.

## Consequences

### Positive

- **One backup procedure**, one PITR story, one set of operator
  muscle memory. The on-call doc for "the database is sad" is short
  because there is only one production-critical database.
- **Joins across bounded contexts** are normal Postgres joins, not
  cross-service queries. The engagement view that needs counts of
  findings by severity per asset is one SQL statement.
- **Migrations are linear and testable.** We run the same migration
  set in CI on a real Postgres container; no chance of dialect drift.
- **Row-level security gives us tenancy at the database** in addition
  to at the application. A bug in the application that forgets to
  filter by `tenant_id` is still caught by RLS.

### Negative

- **Graph traversal in SQL is unpleasant.** Recursive CTEs are
  legible but slow; we have written and rewritten the 4-hop query
  three times.
- **Reporting workloads steal IOPS from OLTP.** We mitigate with a
  separate read replica for reporting, but the temptation to "just run
  this big query on the primary" never goes away. We monitor and
  page on it.
- **Lock contention on the audit log** is real. The chain head
  serializes writes by design (see ADR 0005); throughput is capped
  around 2,000 entries/sec per chain. We shard chains per tenant to
  avoid global contention.
- **Connection pool sizing is a discipline.** Postgres connections are
  expensive; we cap at 50/pod, use `pgbouncer` in transaction-pool
  mode for the API tier, and tune pool sizes per workload class.

### Risk register

| Risk                                                       | Mitigation                                                          |
| ---------------------------------------------------------- | ------------------------------------------------------------------- |
| Postgres becomes a single point of failure.                | Streaming replication with async standby; failover via Patroni.     |
| WAL volume fills the disk.                                 | Hard alert at 70%; auto-archive to S3 with 1h retention floor.      |
| RLS bug exposes cross-tenant data.                         | RLS-enforced in CI; explicit `set_config('app.tenant_id', ...)`.    |
| Reporting query takes down OLTP.                           | Replica with `statement_timeout=5min`; analyst pool is replica-only. |
| Audit chain head contention caps throughput.               | Per-tenant chain sharding; chain rotator off the hot path.          |

## Alternatives considered

### Alternative 1: CockroachDB or YugabyteDB from day one

Postgres-compatible distributed SQL databases. Would give us
horizontal scaling and multi-region writes out of the box.

**Why we did not choose it:**

- Operating distributed SQL in customer-owned clouds is genuinely
  hard. The customer's infra team will not be excited to host
  CockroachDB.
- We do not need multi-region writes yet, and probably will not for
  18-24 months.
- The price of distributed transactions is real (latency floor of
  about 2x single-region Postgres).
- Migration story to and from these databases is good but not as
  battle-tested as Postgres.

We can migrate later if scale demands. The application uses SQLx with
a Postgres dialect, and CockroachDB advertises compatibility.

### Alternative 2: DynamoDB or another NoSQL for primary state

Considered briefly for the managed-offering deployment. Schemaless,
serverless, no operator burden.

**Why we did not choose it:**

- We need cross-entity transactions (engagement -> findings ->
  assets). DynamoDB transactions are limited (25 items, single
  region, single table or known-set-of-tables).
- BYOC deployments cannot assume DynamoDB. We would need two storage
  layers.
- Cross-tenant analytics with joins is not what DynamoDB is for.

### Alternative 3: Aurora Serverless

Aurora Postgres-compatible with auto-scaling. AWS-managed.

**Why we did not choose it:**

- BYOC customers may be in Azure or GCP. We do not want an
  AWS-specific dependency.
- The pricing model (ACU-hours) is hard to predict for a workload
  with bursty BAS traffic.
- The flavor differences from upstream Postgres (`pg_stat_statements`
  not always available, some extensions blocked) bit us in a previous
  project.

We may still recommend Aurora for the AWS-managed offering; the
compatibility surface is well-known. We will not depend on Aurora-only
features.

### Alternative 4: Multi-master Postgres (BDR, PgEdge)

Symmetric writes from multiple Postgres nodes.

**Why we did not choose it:**

- Conflict resolution semantics on the audit chain would be
  catastrophic to debug.
- Operationally it is harder than streaming replication, with limited
  vendor support across clouds.

If we ever need multi-region writes, the path is more likely to be
"shard by tenant region" than "multi-master".

## References

- [PostgreSQL: Concurrency Control](https://www.postgresql.org/docs/16/mvcc.html)
- [Aurora vs. RDS Postgres pricing analysis](https://aws.amazon.com/rds/postgresql/) (internal data not linked)
- [Patroni: HA for Postgres](https://patroni.readthedocs.io/)
- [ADR 0001: Modular monolith](./0001-rust-modular-monolith.md)
- [ADR 0005: Audit log HMAC chain](./0005-audit-log-hmac-chain-anchoring.md)
- The existing project ADR [`0003-knowledge-graph-neo4j.md`](./0003-knowledge-graph-neo4j.md) is the authoritative record on the Neo4j seam.
