# ADR 0006 — Neo4j attack-graph adapter: `neo4rs` Bolt, per-tenant property scoping, boot-time migrations

Status: Accepted
Date: 2026-06-12
Deciders: Principal Platform Engineer, Principal Data Engineer, Security Engineering
Supersedes: None (refines ADR 0003)
Superseded by: None

## Context

ADR 0003 picked Neo4j over Postgres CTEs and Apache AGE for the
`sx-graph` attack-graph store. It left three downstream decisions
unanswered:

1. **Driver choice.** The Rust ecosystem ships two production
   candidates — `neo4rs` (Bolt v4.4 + v5.x, async/Tokio, actively
   maintained) and `cypher-rs` (HTTP-only, lower-level, last
   release 2024). Both compile, both have non-trivial integration
   work.
2. **Multi-tenancy strategy.** Neo4j 5.x offers three options:
   per-tenant database (Enterprise multi-DB), label-prefix scoping
   (`Asset_TenantA`), or **per-tenant property scoping**
   (`Asset { tenant_id }` + indexed predicate on every query).
3. **Schema migration approach.** Cypher has no DDL the way SQL
   does — constraints + indexes are best-effort declarative and
   silently no-op when already present. We need a story that
   matches the discipline of our `sqlx-cli` Postgres migrations.

We also need this adapter to coexist with `InMemoryGraphRepository`
(petgraph) which `sx-monolith` selects in dev / test.

## Decision

### Driver: `neo4rs` Bolt v5

- Async-native (matches our Tokio runtime), maintained on a steady
  release cadence (5–8 releases per year through 2025–2026), and
  has first-class connection-pool semantics that align with our
  Postgres pool model.
- HTTP-only drivers (`cypher-rs`) leak request-per-query overhead
  we cannot afford on the blast-radius BFS read path.
- The crate ships a Bolt v5 implementation with TLS pinning support
  via `rustls-tls`, which matches our `rustls`-only TLS policy.

We pin `neo4rs = { version = "0.7", default-features = false, features = ["rustls"] }`
in `crates/sx-graph/Cargo.toml`.

### Multi-tenancy: per-tenant property scoping (NOT Enterprise multi-DB)

The single Neo4j database holds every tenant's graph. Every node
and every edge carries a `tenant_id` property; every Cypher template
prepends `WHERE n.tenant_id = $tenant_id` before hitting the driver.

Rationale:

- **Community-edition compatibility.** Multi-DB is Enterprise-only.
  Pinning the adapter to per-tenant DBs would force operators onto
  the Enterprise license tier; we don't want that coupling.
- **Cross-tenant ATT&CK reference data.** `Technique` and `Actor`
  nodes come from the MITRE ATT&CK STIX bundle and are shared
  across every tenant. Multi-DB would force a copy per tenant
  database, which then drifts when MITRE publishes an update.
- **Adapter symmetry with Postgres.** The Postgres adapter enforces
  `tenant_id = app_current_tenant()` via FORCED RLS. The Neo4j
  adapter enforces `tenant_id = $tenant_id` via Cypher predicate.
  Both stories audit the same way ("show me every query template;
  prove every one carries the predicate").

Label-prefix scoping (`Asset_TenantA`) was rejected: it makes
operator queries unreadable and prevents indexing the prefix-less
label.

### Schema migration approach: idempotent boot-time replay

Constraints + indexes are declared in
`crates/sx-graph/migrations/neo4j/<YYYYMMDDHHMMSS>__<descr>.cypher`
and applied in lexical order by `Neo4jMigrationRunner::run` at
boot. The runner:

- Records every applied file in a `:_SxMigration { name, applied_at }`
  node — duplicate runs are no-ops.
- Refuses to start the binary if any constraint / index the adapter
  expects is missing (`assert_schema()` runs after the replay).
- Uses `CREATE CONSTRAINT … IF NOT EXISTS` / `CREATE INDEX … IF
  NOT EXISTS` so a partial replay on a pre-existing database
  converges to the desired state.

The full constraint + index list lives in [`RDBMS.md`](../RDBMS.md#154-constraints--indexes).

CI runs a `cypher-lint` pre-commit hook that:

- parses every committed Cypher template;
- asserts the `tenant_id = $tenant_id` predicate is present on
  every label-rooted MATCH;
- asserts every `CREATE` mutates only nodes / edges that carry a
  `tenant_id` property.

## Consequences

- **Single database backup.** A `neo4j-admin database dump` of the
  one database backs up every tenant; we don't need an N-tenant
  fanout. We document the dump cadence in
  `docs/runbooks/db-restore.md`.
- **Per-tenant delete is a Cypher script, not a DROP DATABASE.**
  `crypto_erase_tenant` runs a `MATCH (n) WHERE n.tenant_id = $tid
  DETACH DELETE n` in a transaction. Slower than dropping a
  database, but acceptable at our scale (largest tenants in 2026
  hold ~2 M nodes; the delete completes in ~20 s under load).
- **Predicate discipline is load-bearing.** A missing
  `tenant_id = …` predicate in one Cypher template would silently
  expose every tenant's graph to the calling tenant. The `cypher-
  lint` CI step and the `cypher_templates_carry_tenant_filter` unit
  test are the only guards; both are required to merge.
- **In-memory adapter stays.** `InMemoryGraphRepository` (petgraph)
  remains the default for tests + dev. A shared port-level
  conformance test exercises both adapters against the same
  fixtures.
- **Future migration path.** If Enterprise multi-DB becomes
  attractive later (e.g. for a sovereign-tenant deployment), the
  port abstraction lets us swap the Neo4j adapter for a multi-DB
  variant without touching call sites. Tenant data already carries
  `tenant_id` everywhere, so a per-DB migration is a one-time
  Cypher fan-out.

## Alternatives Considered

- **`cypher-rs` over HTTP.** Rejected — HTTP overhead per query,
  no Bolt streaming, smaller maintainer footprint.
- **Enterprise multi-DB.** Rejected — licensing coupling and the
  ATT&CK reference-data duplication problem.
- **Per-tenant Cypher fragment compiler that auto-injects the
  WHERE clause.** Rejected — the `cypher-lint` check is simpler,
  more auditable, and catches the same class of bug at compile
  time instead of runtime.
- **Apache AGE over Postgres.** Rejected in ADR 0003 (managed-
  Postgres availability); no new reason to revisit.
