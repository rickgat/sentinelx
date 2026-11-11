# ADR 0023 — `FindingRepositoryPort::insert` as the service-internal write seam (FOUND-001)

Status: Accepted
Date: 2026-06-25
Deciders: Principal Platform Engineer, Principal Security Engineer, PO
Supersedes: None
Superseded by: None

## Context

Before FOUND-001, the only way a `Finding` row reached Postgres was
through the controller layer: a human-issued REST call to a
controller-specific surface (`POST /v1/findings/manual`, vuln-ingest
mappers, the bug-bounty inbound webhook, …). The platform had no
*service-internal* seam for materialising findings; every emitter that
wanted to surface a hardening signal (the audit-chain break detector,
the log-ingest rate-limit observer, the SAML SP attack observer, the
RBA-block translator) had to either:

1. duplicate finding-row construction inside its own crate and reach
   directly into `PgFindingsAdapter`, breaking the hexagonal seam, or
2. fan-out via a controller-shaped HTTP loopback, which would surface
   in audit logs as a self-call and complicate tenant attribution.

Both shapes were rejected in the senior review 2026-Q2 §3
("Internal-write seam"). The review explicitly asked for a port-level
write surface so emitters could push synthetic findings without
becoming HTTP clients of their own service.

At the same time, several emitters re-fire on the same logical event:

- The chain-verifier re-emits on every poll where the chain remains
  broken.
- The log-ingest rate limiter re-fires within its dedup window.
- The SAML attack observer collapses bursts of XSW attempts into a
  single finding per day.

Without idempotency at the persistence layer, every re-fire would
either duplicate rows or push the de-dup burden up into each emitter.

## Decision

Add a single new method to the existing `FindingRepositoryPort`:

```rust
async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError>;
```

with the following contract:

1. **Service-internal only.** No public REST route is wired to this
   method. External callers continue to use the dedicated controllers
   (`/v1/findings/manual`, the vuln-ingest pipeline, the bug-bounty
   webhook, …) which still go through the same adapter underneath.
2. **Idempotent on `(tenant_id, view.id)`.** The Postgres adapter
   implements this as `INSERT … ON CONFLICT (id) DO NOTHING` and
   returns the already-persisted view rather than
   `EngagementPortError::Conflict`. This lets emitters call `insert`
   without first probing `get`.
3. **Tenant stamping is the caller's responsibility.** `FindingView`
   already carries `tenant_id`; the adapter does not re-derive it from
   any ambient request scope (there is none — emitters run from
   background jobs and observers, not request handlers).
4. **No follow-on audit row from the port itself.** Emitters that
   want an audit row emit one themselves (the chain-break detector
   does; the rate-limit observer does not — the OCSF event already
   carries the rate-limit decision). Keeping audit emission out of
   the port lets each emitter pick its own audit semantics.

The trait surface stays small: `list`, `get`, `update_status` (all
read/transition shapes that back the existing REST controllers) plus
the new `insert`. No new types — `FindingView` is already the
canonical wire shape.

## Consequences

### Operational

- Emitters wire through `Arc<dyn FindingRepositoryPort>` from the
  composition root; no additional config knob, no per-emitter
  feature flag.
- The Postgres adapter (`PgFindingsAdapter::insert`) became the
  single uniqueness-key enforcement point. Test coverage for the
  `ON CONFLICT (id) DO NOTHING` branch lives in
  `services/sx-monolith/tests/findings_idempotent_insert.rs`.
- The in-memory adapter (`InMemoryFindingsAdapter`) mirrors the same
  contract — duplicate-id insert is a no-op returning the existing
  row — so the seam is exerciseable in unit tests without a database.

### Security

- The internal-write seam is *not* exposed as an HTTP route. The
  surface-area review concluded that letting external callers write
  arbitrary `FindingView`s would (a) bypass the controller-layer
  validation each public route currently enforces and (b) widen the
  blast radius of a stolen service-account credential. Keeping the
  seam in-process is the explicit security posture.
- Tenant scoping is enforced by the adapter SQL (`tenant_id` is in
  the row payload and in the row-level-security policy). Even though
  the port does not re-derive `tenant_id`, an emitter passing a
  malformed `view.tenant_id` would fail the RLS check rather than
  poison another tenant.

### Maintenance

- The contract opens a small forward-compatibility door: the
  idempotency wording is `MAY treat (tenant_id, view.id) as
  uniqueness key` rather than `MUST`. An adapter that wants
  stricter conflict semantics (returning `Conflict` to surface
  emitter bugs in CI) can do so; the production adapter has chosen
  `DO NOTHING`. This is documented inline on the trait, not
  re-litigated per call site.
- Future cleanup path: once we have a documented set of "first-class
  emitters" (≥ 5 of them by end of Sprint 6), we may revisit
  promoting the seam to its own port (`FindingEmitterPort`) so the
  read-shape methods stay on `FindingRepositoryPort` and the
  write-shape lives alone. Not done now because there is no caller
  pressure for the split and it would churn every observer.

## Alternatives Considered

- **HTTP self-loopback** — emitters POST to their own service's
  controller-layer routes over `localhost`. Rejected: audit-log
  pollution, tenant attribution complexity, and an extra HTTP-stack
  round-trip on the hot SAML/audit/log-ingest paths.
- **Direct adapter access from emitters** — `Arc<PgFindingsAdapter>`
  threaded into every observer. Rejected: breaks the hexagonal
  seam, makes in-memory testing impossible, and couples observers
  to the storage layer.
- **Separate `FindingEmitterPort`** — new trait, single `insert`
  method. Rejected for now (see the maintenance note above) — would
  duplicate the read shape on the storage adapter without buying
  anything until we have more emitters.

## References

- `crates/sx-api/src/port.rs` — `FindingRepositoryPort::insert`
  trait method + idempotency-contract docstring.
- `services/sx-monolith/src/adapters/incident_sinks.rs` — the
  composition-root wiring that fans `insert` to optional
  `IncidentSinkPort` emission (per [ADR-0024](0024-ssrf-guard.md)
  is unrelated; the sink fan-out is its own surface).
- `services/sx-monolith/src/adapters/audit_break_observer.rs`,
  `saml_attack_observer.rs`, `rba.rs` — emitters that drive the
  `insert` path.
- Senior review 2026-Q2 §3 — the policy escalation that authorised
  the seam.
