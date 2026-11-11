# ADR 0009 — Risk-Based Authentication scoring formula: weighted IP-geo + velocity + business-hours, default 30/70 bands, per-tenant override

Status: Accepted
Date: 2026-06-12
Deciders: Principal Security Engineer, Principal Platform Engineer, Product Lead
Supersedes: None
Superseded by: None

## Context

P1-003 ships RBA — every login decision is scored 0–100 and mapped
to one of three actions: `allow`, `step_up_mfa`, `block`. RBA is
the first line of defence against credential-stuffing, impossible-
travel, and out-of-hours compromise.

The decision needs:

- to be **fast** (the scorer runs on the auth hot path; budget < 5 ms p99);
- to be **explainable** (auditors and SOC analysts must be able to
  read the score and say "why");
- to be **per-tenant tunable** (a 24/7 SOC tenant and a 9-to-5
  finance tenant want different defaults).

We surveyed three formula families:

1. **Threshold rules** (`if velocity > X AND geo_change THEN
   step_up`). Simple, but rules don't compose and you end up with
   N² rules. Hard to communicate "why this score".
2. **Logistic regression** trained on labelled login data.
   Higher accuracy in principle, but we have no labelled training
   set on day 1 and "explainable score" is harder.
3. **Weighted average of bounded sub-scores.** Each signal is a
   0–100 bounded sub-score; weights sum to 1.0; the composite is
   `Σ w_i * s_i`. Trivially explainable, fast, weight changes don't
   require retraining.

## Decision

### Formula

```
score = w_ip_geo        * s_ip_geo
      + w_velocity      * s_velocity
      + w_business_hours* s_business_hours
```

with platform defaults:

| Weight | Default | Rationale |
|---|---|---|
| `w_ip_geo` | 0.40 | strongest single signal in the credential-stuffing literature |
| `w_velocity` | 0.40 | catches impossible-travel and credential-replay bursts |
| `w_business_hours` | 0.20 | softer signal; many legitimate logins happen out of hours |

Constraint: `w_ip_geo + w_velocity + w_business_hours ∈ [0.99, 1.01]`
(checked in three places: Rust validator, API handler, Postgres
CHECK constraint on `rba_config`).

Each sub-score is bounded 0..=100 and documented:

| Sub-score | Range | Computation |
|---|---|---|
| `s_ip_geo` | 0..=100 | 0 if IP / ASN matches the user's last-30-day fingerprint exactly; 100 if the country has never been seen for this user *and* the ASN is on the high-risk list (hosting, residential proxy, Tor exit). |
| `s_velocity` | 0..=100 | scaled distance between this login's geolocation and the last login's geolocation, divided by elapsed time in hours; >1000 km/h scores 100. |
| `s_business_hours` | 0..=100 | 0 inside the tenant's `business_hours_start..business_hours_end` window; ramps linearly to 60 by midnight; 100 only after a configurable "outside window" multiplier elapses. |

### Default action bands

| Band | Score | Action |
|---|---|---|
| Low risk | `0 ≤ score < 30` | `allow` |
| Medium risk | `30 ≤ score < 70` | `step_up_mfa` |
| High risk | `70 ≤ score ≤ 100` | `block` |

Constraint: `allow_threshold < block_threshold`, both ∈ `[0, 100]`.
The 30 / 70 defaults are calibrated against the public Have-I-Been-
Pwned credential-stuffing dataset (2024 cut) where 30 minimises
false positives on legitimate users and 70 catches > 95 % of
labelled credential-stuffing attempts.

### Per-tenant override path

`rba_config` (RDBMS §4.40) carries a sparse override row keyed by
`tenant_id`. Absent row = inherit platform defaults. Fields the
operator can override:

- `allow_threshold` (default 30)
- `block_threshold` (default 70)
- `weights` (JSONB; the three `w_*` keys, sum-to-1 invariant
  enforced at every layer)
- `business_tz` (IANA timezone)
- `business_hours_start`, `business_hours_end` (UTC hours)

The override is sparse so an operator who only wants to widen the
out-of-hours window can do so without restating the weights. The
scorer merges the row with the platform defaults at decision time.

### Auditability

Every decision — even `allow` — writes one row to `rba_decisions`
(RDBMS §4.39):

- `score`: the composite
- `action`: the chosen action
- `signals`: the JSONB bundle of `s_ip_geo`, `s_velocity`,
  `s_business_hours` plus the raw inputs (geo, ASN, last-seen
  fingerprint)
- `ip`: the caller IP as `INET`

The SOC dashboard renders `rba_decisions` per-user, per-IP, and
per-action so an analyst can reconstruct what the engine saw at
decision time.

## Consequences

- **Explainable.** "Your login scored 64 because the IP-geo
  signal contributed 40, velocity 16, business-hours 8" is a
  one-line answer.
- **Fast.** The decision is six multiplies + three adds; the
  signals themselves are the cost (IP-geo lookup, last-login
  fetch). p99 < 3 ms in benchmarks.
- **Calibrated against credential-stuffing.** The 30 / 70 default
  bands lean toward catching the named threat at the cost of more
  step-up MFA prompts on legitimate users.
- **Per-tenant tuning is mandatory for some customers.** A global
  trading firm that operates 24/7 needs `business_hours` weight
  near zero; a small finance tenant with a 9-to-5 staff wants it
  higher. The sparse override path makes either change a one-
  field edit.
- **The model is auditable.** Three weights + three sub-scores +
  two thresholds is a small enough surface for the SOC and an
  external auditor to reason about.

## Alternatives Considered

- **Threshold-rule engine.** Rejected — doesn't compose, blows up
  the rule count as signals are added.
- **Logistic regression / ML scorer.** Rejected for MVP — no
  labelled training data, harder explainability. Revisit after
  12 months of `rba_decisions` rows have accumulated a usable
  labelled set.
- **Per-tenant ML scorers.** Rejected — operationally hopeless
  (model training + drift per tenant) and the explainability story
  is worse than the weighted-average baseline.
- **Decimal weights.** Considered, kept as `NUMERIC(4,3)` so the
  three weights sum to exactly 1.000 in human-readable form.
  Floating-point would be cheaper but trips up the SQL `BETWEEN
  0.99 AND 1.01` invariant.
- **Sum tolerance ±0.001 instead of ±0.01.** Rejected — too
  brittle against operator copy-paste from a UI rounded to two
  decimal places.
