# ADR 0018 — Chaos engineering: refused in `APP_ENV=production`

Status: Accepted
Date: 2026-06-12
Deciders: SRE Lead, CISO, CTO
Supersedes: None
Superseded by: None

## Context

SentinelX ships a chaos-engineering crate (`sx-chaos`) that
deliberately injects failures into the platform: kill a connection
mid-flight, slow a Postgres query, drop a Redis pub/sub message,
return a transient 5xx from the OIDC provider. The crate exists so
SRE can validate that the system's retry / circuit-breaker /
fallback paths actually work — that is, that the platform fails
the way the documentation says it does.

Chaos engineering is the canonical "tool you must never aim at
your customers". A misconfiguration that arms chaos in production
would be a self-inflicted denial of service against every tenant
simultaneously. We need a refusal that is impossible to bypass
through a configuration mistake.

The candidates:

1. **Best-effort config flag.** Set `chaos.enabled = false` by
   default; rely on operators to never flip it in production. The
   industry-default approach; fails on the first operator typo.
2. **Compile-out in production.** Use a Cargo feature to compile
   `sx-chaos` out of the production binary. Strong refusal, but
   the production binary loses a documented surface (chaos rests
   exposed only behind a build flag); operators can't dry-run a
   chaos scenario against a production-image staging deployment.
3. **Runtime refusal keyed on `APP_ENV`.** The crate inspects
   `APP_ENV` and refuses to arm any fault injection when
   `APP_ENV == "production"`. The refusal is in the same binary;
   the production image carries the crate but cannot use it.

## Decision

### Runtime refusal keyed on `APP_ENV`

`sx-chaos` constructs every fault injector through a single entry
point:

```rust
pub fn arm(config: ChaosConfig) -> Result<ChaosHandle, ChaosError> {
    let env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
    if env == "production" {
        return Err(ChaosError::ProductionRefused);
    }
    // ... arm the injector ...
}
```

The refusal is:

- **Mandatory.** No code path in `sx-chaos` skips the check.
- **Unbypassable by config.** There is no
  `chaos.allow_in_production` knob. An operator who wants to test
  in production-shaped infrastructure points at a staging
  deployment with `APP_ENV=staging`.
- **Audited at boot.** The platform writes an audit-event row on
  every startup recording `APP_ENV`, the binary's git SHA, and
  the chaos refusal state. An attacker who flipped `APP_ENV` to
  `staging` to bypass the check leaves a fingerprint.
- **Cross-checked at the orchestration layer.** Helm /
  Kustomize / Terraform templates for production set both
  `APP_ENV=production` and a Kubernetes pod label
  `sentinelx.io/env=production`; an admission controller refuses
  to schedule a pod where the label and the env var disagree.

### Lifecycle

When an SRE wants to run a chaos experiment:

1. They identify the scenario (`pg.slow_query`,
   `redis.drop_message`, `oidc.5xx`).
2. They run the scenario against the **staging** deployment (which
   is sized to ~10 % of production capacity for cost reasons but
   carries the same binary).
3. They observe the platform's response in the chaos dashboard.
4. The chaos run is **automatically un-armed** after the configured
   duration (default 5 min, max 1 h). There is no permanent chaos.
5. The chaos run writes an `audit_event` row to staging's audit
   log; the same row format the production audit log uses.

### Production safety drills

Production safety is exercised via:

- **Game days** against staging with chaos armed. Quarterly.
- **Disaster recovery drills** against a separate DR region.
  Quarterly.
- **Failure-injection unit tests** in the binary that exercise the
  retry / circuit-breaker / fallback paths without `sx-chaos`.
  Continuous, as part of CI.

The combination is the production-readiness argument; chaos
testing in production itself is not.

### What about "we already use Gremlin / Litmus in production"

The industry has examples (Netflix, Stripe) of running chaos
testing in production. Their threat model is different from ours:

- Netflix is a content service; a 1 % regression for a few hours
  is an inconvenience.
- SentinelX is a security platform; a 1 % regression for a few
  hours is a customer-side **detection gap** that maps directly
  to undetected incidents.

We make the explicit policy choice that the cost of an undetected
security incident, even a probabilistic one, is too high for
production chaos. Customers who paid for our SLA expect us not to
be the source of their incident.

## Consequences

- **No risk of chaos-induced production outage.** The platform's
  most catastrophic operator-error class is removed.
- **Staging must be production-shaped.** The drills are only
  useful if staging exercises the same failure surfaces as
  production. We size staging at ~10 % of production capacity but
  ship the same binary, the same Postgres + Redis + ClickHouse
  versions, the same KMS provider profile.
- **No production-only failure validation.** Some failure modes
  may only manifest at production load. The mitigation is the
  combination of (a) load-testing staging to production-equivalent
  RPS and (b) post-incident reviews that drive new chaos
  scenarios into the staging cycle.
- **The refusal is auditable.** SOC 2 CC8.1 (change management)
  and CC7.4 (incident response) both lean on the boot-time audit
  row that records the chaos refusal state.

## Alternatives Considered

- **Compile-out in production.** Rejected — the production
  binary loses a documented surface; debugging an issue that
  "works in staging because chaos is compiled in" gets harder.
- **Best-effort config flag.** Rejected — one operator typo
  destroys every tenant simultaneously.
- **Allow chaos in production behind a "tier-3 break-glass"
  approval.** Rejected — there is no business case for chaos
  testing in production that staging cannot satisfy at lower
  risk.
- **Allow chaos in a single-tenant deployment with the
  customer's consent.** Considered for the enterprise tier;
  rejected for now — operationally hard to gate per-tenant in a
  shared platform, the same staging drill covers the test.
