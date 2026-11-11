# ADR 0003 — Knowledge graph backed by Neo4j with in-memory fallback for dev

Status: Accepted
Date: 2026-05-30

## Context

The `sx-graph` crate computes attack paths across heterogeneous assets,
identities, credentials, and known vulnerabilities. The core query shape
is "shortest weighted path from an exposed asset to a crown-jewel asset
via privilege-escalation, credential-reuse, and exploitable-CVE edges,
filtered by tenant".

We evaluated three storage strategies:

1. **Pure PostgreSQL with recursive CTEs.** Wins on operational simplicity
   (we already run Postgres in `sx-storage`) but breaks down past a few
   hops: recursive CTEs over a multi-million-edge graph either fan out
   into pathological work or require hand-rolled Bloom-filter pruning we
   would have to maintain ourselves.
2. **Apache AGE (Postgres extension).** Gives us Cypher-like queries on
   top of Postgres, but the extension is not available on the managed
   Postgres targets our customers prefer (RDS, Cloud SQL, Azure), so we
   would have to ship a custom Postgres image just to support graph
   queries.
3. **Neo4j.** Purpose-built for traversal workloads, first-class Cypher,
   well-understood operational profile (we already need a JVM in our
   stack for the OTel collector add-ons), production-grade clustering
   in the community edition is good enough for our scale targets, and
   the official Rust driver `neo4rs` is actively maintained.

Local development is a separate concern: requiring contributors to run
Neo4j alongside Postgres + Redis + Jaeger + the monolith just to compile
the crate would meaningfully raise the bar to entry.

## Decision

- The production adapter for `sx-graph`'s `GraphRepositoryPort` writes
  and queries Neo4j via `neo4rs` (Cypher). Schema migrations live in
  `sx-graph/migrations/neo4j/` and run idempotently at boot.
- A second adapter, `InMemoryGraphRepository`, implements the same port
  using `petgraph` for traversal and serde-snapshot-on-shutdown so dev
  state survives restarts. This is the default when
  `SENTINELX__GRAPH__BACKEND` is unset or equals `memory`.
- The composition root (`services/sx-monolith`) selects between the two
  at boot based on config; no caller code knows which adapter is wired.
- Tests use the in-memory adapter exclusively to keep the suite hermetic.
- Production deployments default to `SENTINELX__GRAPH__BACKEND=neo4j`
  and fail closed if the Neo4j URL is unreachable for more than
  `graph.startup_timeout` (default 30s).

## Consequences

- **Operational cost rises.** Operators must provision a Neo4j cluster
  alongside Postgres and Redis. We document the minimum sizing (1 core,
  4 GiB, SSD) and link an official Helm chart from `deploy/helm/`.
- **Schema discipline.** Cypher does not enforce schema, so we add
  pre-commit Cypher linting (`cypher-lint`) and an integration test that
  diff-compares the production migrations against a known-good snapshot.
- **Backup and restore.** Neo4j's dump format is incompatible with
  Postgres', so DR procedures must back up both. Documented in
  `docs/operations/runbook.md`.
- **In-memory drift risk.** The two adapters can drift in subtle ways
  (e.g. equality of edge weights, secondary-index ordering). We mitigate
  this with a shared trait-level conformance test exercised against both
  implementations.
- **Future evolution.** If Neo4j becomes a licensing problem (community
  edition has clustering limits), the same port lets us swap in an
  alternative graph engine (TigerGraph, Memgraph, JanusGraph) without
  touching any caller code.
