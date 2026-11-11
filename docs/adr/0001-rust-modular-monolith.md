# ADR 0001: Rust modular monolith with hexagonal seams

Maintainer: Platform Engineering (`#sentinelx-platform`)
Last reviewed: 2026-05-30

- Status: Accepted
- Date: 2026-05-30
- Deciders: Founding engineering team, CTO
- Supersedes: None (greenfield decision)
- Superseded by: None

## Context

SentinelX is a security validation platform built by a small team
(initially three engineers, growing to ten in year one). The product
spans six recognizable bounded contexts — identity, engagement,
discovery, risk, attack-graph, breach-and-attack simulation — plus
support contexts (audit, reporting, compliance, telemetry, storage,
config). Every one of those bounded contexts looks plausibly like its
own service if you squint, but we are pre-revenue and cannot afford to
operate ten Kubernetes deployments, ten databases, and the cross-cutting
glue (auth, tracing, deploy, observability) for each.

We also have hard constraints from the product:

- The audit log must be tamper-evident and cryptographically chained.
  A network hop between the writer and the chain head invites a class
  of race conditions we do not want to debug under incident pressure.
- The BAS safety pipeline must be able to globally trip a kill switch
  in under one second, with strong consistency. Distributed coordination
  for "stop everything right now" is solvable but expensive in person-hours.
- Several flows touch four or five bounded contexts in a single
  transaction (engagement -> discovery -> risk -> graph -> report).
  Cross-service transactions are notoriously hard; cross-module
  transactions in a single binary are trivial.

At the same time, we want optionality. If two years from now we need to
extract `sx-bas` behind a network boundary so it can scale separately,
we want that to be a refactor, not a rewrite.

The constraint that drove the language choice:

- The platform's hot paths (audit chain hashing, graph traversal, BAS
  technique evaluation, JWT validation) need predictable low latency at
  p99 < 100 ms. GC pauses are a known foot-gun for the audit chain and
  for the kill-switch path.
- Multi-tenancy means we run untrusted attacker simulation logic in
  process with high-trust IAM logic. Memory safety is a hard requirement.
- We need first-class async I/O, mature crypto libraries, and a single
  static binary for the agent process that runs in customer networks.

## Decision

We will build SentinelX as a **single Rust workspace** containing many
crates, deployed as a single binary, with **hexagonal seams** between
bounded contexts.

Concretely:

1. **Every bounded context is its own crate.** `crates/sx-iam`,
   `crates/sx-engagement`, `crates/sx-bas`, etc. Each crate owns its
   models, services, error types, and persistence adapters.
2. **Crates never depend on each other directly.** A crate that needs
   data from a sibling defines a port — a Rust trait, e.g.
   `pub trait FindingsRepo` — and asks the composition root to inject
   an implementation. `cargo-deny` config enforces this at CI time by
   banning forbidden dependency edges.
3. **The composition root is a single binary** (`services/sx-monolith`).
   It builds connection pools, constructs concrete adapters, wraps them
   in `Arc<dyn Trait>`, and hands them to the API layer. Routes are
   mounted from `sx-api` which is itself just another crate behind the
   `axum::Router` trait.
4. **The same code can ship as microservices later.** Because the
   transport boundary is a Rust trait, not in-process calls, we can
   write a second adapter that proxies the trait over gRPC and split
   any crate into its own binary without touching the consumer.
5. **The on-disk service catalogue is one item today, three later.**
   `services/sx-monolith` is the platform. `services/sx-cli` is the
   operator CLI. `services/sx-agent` is the remote probe that customers
   install in their network. These are three binaries, all built from
   the same workspace, all sharing the kernel crates.

## Consequences

### Positive

- **One deploy, one log stream, one trace context.** New engineers
  trace a request from HTTP ingress to database query inside a single
  RustRover window. The cognitive load is one binary.
- **In-process transactions across modules.** The engagement create
  flow writes to four crates' tables in a single PG transaction. No
  sagas, no two-phase commit, no compensating actions.
- **Strict compile-time refactoring.** Renaming `EngagementId` requires
  the compiler to validate eleven crates. The compiler tells us when
  the abstraction leaks.
- **Predictable performance.** Rust's lack of a GC means the audit
  chain's hash-and-write loop has stable p99 latency.
- **Future microservice extraction is mechanical.** Because we already
  pay the abstraction cost (ports, adapters, dependency injection at
  composition), splitting a crate behind a network boundary is a two-PR
  refactor: write the gRPC adapter, swap the binding.

### Negative

- **The binary is large.** Release build is approximately 180 MB; cold
  start is roughly 600 ms. Acceptable for our deploy cadence; would be
  unacceptable for a serverless model.
- **Hexagonal seams are a tax.** Defining a port and an adapter for
  every cross-crate need adds boilerplate. We have written
  `sx-core::ports!` macros to ease the boilerplate, but it is not free.
- **Workspace compile time is long.** A full `cargo build --release`
  is currently around 12 minutes on a 16-core M3 Pro. We mitigate with
  `sccache`, `mold` linker, and `cargo nextest` for tests.
- **Module ownership requires discipline.** Without strict review, the
  modular boundaries decay into a ball of mud. We enforce with
  `cargo-deny` rules and a regular architecture review.

### Risk register

| Risk                                                    | Mitigation                                                                |
| ------------------------------------------------------- | ------------------------------------------------------------------------- |
| Compile time grows beyond engineer tolerance.           | `cargo-chef` for layered Docker, `sccache`, parallel CI shards.           |
| A team merges a direct crate dependency, eroding seams. | `cargo-deny` `[bans]` config + CI lint + ADR-required exception process.  |
| The single binary becomes a single point of failure.    | Two Pods minimum, HPA on CPU and request rate, ADR 0005 audit durability. |
| Extracting a crate to a service is harder than claimed. | Quarterly drill: extract one crate end-to-end in a throwaway branch.      |

## Alternatives considered

### Alternative 1: Go microservices

We considered a Go service-per-bounded-context layout from day one,
modeled on the patterns common in adjacent infosec startups.

**Why we did not choose it:**

- We need very strict memory safety because the BAS module runs
  effectively-adversarial code in-process with IAM. Go's race-y
  channel patterns and lack of `Send`/`Sync` enforcement in the type
  system worried us for code on hot paths.
- The operational overhead of ten services for a three-person team is
  prohibitive. We would spend more time on Helm charts than on the
  product.
- Cross-service transactions for the engagement create flow are
  genuinely hard. Sagas with compensating writes are a known
  reliability pothole.
- Go is excellent at this scale; we just believed Rust's compile-time
  guarantees would save more engineer-hours than they cost over the
  first three years.

The pre-decision spike (two weeks, two engineers) confirmed the team
shipped a working `engagement-svc` in Go in three days, but the BAS
safety-pipeline correctness work took twice as long because the type
system did not stop them from forgetting to check the kill switch in
two of four control flow paths. In Rust the compiler refused to compile
without the check because of the `KillSwitch::guard()` return type.

### Alternative 2: Python with FastAPI

We considered FastAPI for the API layer with Celery workers for the
discovery and BAS engines. This was particularly tempting because the
data team's ML triage models are PyTorch.

**Why we did not choose it:**

- GC pauses on the audit chain writer are a hard blocker.
- Python's lack of compile-time type checking would make refactoring
  the modular monolith very painful at scale. `mypy --strict` helps but
  is not the same guarantee.
- Deploying Python services with native dependencies (e.g. `psycopg2`,
  `cryptography`) and matching glibc versions across customer-installed
  agents is a known source of incident pages.
- The ML triage model is offline-batch, not on the request path. We
  can keep Python in `sx-ml/python/` and call it via an in-process
  PyO3 binding or out-of-process via stdio. The hot path stays in Rust.

### Alternative 3: Modular monolith in Java / Kotlin

Strong candidates: Spring Modulith for Java, Ktor for Kotlin. Mature
ecosystem, excellent tooling, predictable performance with the JVM.

**Why we did not choose it:**

- JVM startup time (3-5s warm, 8-10s cold) impacts our 60-second
  rolling deploy SLO.
- JVM heap tuning is its own discipline. The audit chain writer
  workload is hash-dominated; we did not want to also become JVM GC
  experts.
- Distributing the customer-installed agent as a JVM binary is
  workable (jpackage, native-image) but harder than `cargo build
  --release` for the agent.

### Alternative 4: Pure microservices in Rust

Same advantages as Rust, but adopt service-per-context from day one.

**Why we did not choose it:**

- All of the "Go microservices" operational arguments still apply; the
  language does not change the platform cost.
- We forfeit in-process transactions without gaining much. We would
  re-introduce the saga problem just to feel cleaner architecturally.

## References

- [Modular Monolith: A Primer](https://www.kamilgrzybek.com/design/modular-monolith-primer/) — Kamil Grzybek
- [Spring Modulith](https://docs.spring.io/spring-modulith/docs/current/reference/html/) — for the modular boundary patterns we mimic
- [hexagonal architecture (Cockburn 2005)](https://alistair.cockburn.us/hexagonal-architecture/)
- [ADR 0002: PostgreSQL as primary store](./0002-postgres-as-primary-store.md)
- [ADR 0004: BAS safety pipeline](./0004-safety-pipeline-kill-switch-mode-gate-window-approval.md)
- The existing project ADR [`0001-modular-monolith.md`](./0001-modular-monolith.md) — earlier framing of the same decision; this ADR is the canonical version going forward.
