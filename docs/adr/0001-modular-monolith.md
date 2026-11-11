# ADR 0001 — Modular monolith in Rust, ports & adapters

Status: Accepted
Date: 2026-05-29

## Context
SentinelX integrates many domains (asset discovery, scanning, threat intel,
risk, identity, engagement safety) into one product. The PRD lists Go + Rust +
Python; the TRD recommends Rust as primary language for memory safety and
single-binary deployment. The team is small for Phase 1.

## Decision
- **One language for the core**: Rust (edition 2021, MSRV 1.88).
- **One monorepo Cargo workspace** with one crate per bounded context
  (`sx-config`, `sx-core`, `sx-telemetry`, `sx-iam`, `sx-audit`, `sx-storage`,
  `sx-engagement`, `sx-risk`, `sx-discovery`, `sx-api`).
- **MVC inside each crate**: explicit `model/`, `view/`, `controller/`,
  `service/` folders so the layering is visible to every reader.
- **Hexagonal at the seams**: every cross-crate dependency goes through a
  trait declared by the consumer (port) and implemented by the provider.
- **Single composition root**: `services/sx-monolith` wires adapters into
  trait objects.

## Consequences
- Refactors across crates are compile-time checked.
- Services can be extracted from the monolith later by re-using the same
  trait boundary that already exists.
- Polyglot work (ML, exploit DSL) stays out-of-tree and connects through
  HTTP/gRPC sidecars when needed.
