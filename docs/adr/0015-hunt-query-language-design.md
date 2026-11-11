# ADR 0015 — Hunt query language: pipe-style KQL/SPL subset, parameterised compilation, auto-tenant predicate

Status: Accepted
Date: 2026-06-12
Deciders: Principal Data Engineer, SOC Lead, Principal Platform Engineer
Supersedes: None
Superseded by: None

## Context

P3-006 ships a threat-hunting query language so analysts can pivot
across `events_normalized` and `audit_event` without writing
SQL / ClickHouse-native syntax. The query language is read by both
the SOC analyst in an ad-hoc context and the saved-hunt scheduler
that runs queries every N minutes.

Requirements:

- **Familiar.** SOC analysts arrive from Splunk (SPL) or Microsoft
  Sentinel (KQL); a wholly novel syntax would be a tax on every
  new hire.
- **Bounded.** The language must compile to a bounded query — no
  unbounded WHILE loops, no recursive joins, no UDFs.
- **Parameterised.** Saved hunts accept parameters
  (`{user_name}`, `{cve}`); the parameters MUST be bound through
  the underlying driver's parameter slot, never interpolated as a
  string.
- **Tenant-safe.** The language compiler MUST inject `tenant_id =
  {current}` on every query. There is no "advanced mode" that
  lets an operator omit the predicate.

We considered three approaches:

1. **Expose ClickHouse SQL directly.** Maximum expressiveness, but
   the surface is vast (recursive CTEs, materialised views,
   user-defined functions) and the auto-tenant predicate would be
   bolted on after the fact.
2. **Pipe-style KQL/SPL subset.** Familiar to the target user,
   small enough surface to write a hand-rolled parser, every
   stage compiles to a single ClickHouse SQL fragment.
3. **Domain-specific GUI (filter cards).** Lower learning curve
   but a glass ceiling once the analyst wants a join or a
   sub-aggregation.

## Decision

### Syntax: pipe-style KQL/SPL subset

```
events
| where time > ago(24h)
| where class_uid == 3002
| where severity_id >= 4
| summarize count() by actor_user_name, bin(time, 1h)
| sort desc count_
| take 100
```

The supported operators (subset of KQL):

| Operator | Purpose |
|---|---|
| `where <predicate>` | filter |
| `extend <col> = <expr>` | computed column |
| `project <cols>` | column selection |
| `summarize <agg> by <group-cols>` | aggregation |
| `sort asc \| desc <col>` | order |
| `take <n>` | limit (capped at 100 000 per query) |
| `join kind=inner (<sub>) on <cols>` | join (limited to a single sub-query) |
| `union (<sub>)` | union (limited to two sub-queries) |
| `mv-expand <col>` | array un-pivot |

Expressions are bounded: arithmetic, string ops (`startswith`,
`contains`, `matches regex`), and the OCSF columns. No
user-defined functions, no recursive CTEs, no window functions
beyond the pre-listed aggregates (`count`, `sum`, `avg`, `min`,
`max`, `dcount`, `percentile`).

### Compilation: parameterised, NEVER interpolated

The compiler parses the source into an AST, type-checks each stage
against the OCSF / audit-event schema, and emits a single
parameterised ClickHouse SQL string:

```rust
struct CompiledHunt {
    sql: String,                // never contains user input as a string literal
    params: BTreeMap<String, Value>,  // bound through the driver
    expected_columns: Vec<(String, OcsfType)>,
}
```

User-supplied values land in `params`; the driver substitutes them
via the ClickHouse `{param:Type}` syntax. There is no path in the
compiler that reads a user value into the `sql` string — a fuzz
test (`hunt_compiler_no_string_interpolation`) confirms this by
running 100 k random inputs through the compiler and asserting the
emitted SQL is byte-identical to the AST-derived shape.

### Tenant-id auto-predicate

After the user's `where` clauses are emitted, the compiler appends
a `WHERE tenant_id = {tenant_id:UUID}` clause to every top-level
SELECT and every sub-query. The injection is **before** the SQL
leaves the compiler; there is no way for a user to omit it.

The tenant id flows in from the JWT-derived
`TenantContext::current()` at compile time. A `compile_for_audit`
helper accepts a `tenant_id` parameter explicitly (used by the
saved-hunt scheduler which doesn't have a request-scoped JWT) and
asserts the same predicate.

### Saved hunts

A saved hunt is the AST + parameter definitions + a schedule
(cron). Saved hunts live in `crates/sx-hunt/migrations/<…>__create_hunt.sql`
(table to be created on the phase-2 cut-over); for the MVP they
live in an in-memory registry.

Each scheduled run:

1. resolves parameters from the saved-hunt definition;
2. compiles the AST against the resolving tenant context;
3. runs the query against ClickHouse with a 30 s timeout;
4. writes the result rows to a hunt-result table;
5. evaluates the result-shaped condition (`result_count > 0` or a
   custom expression); if true, raises an alert into the SOC
   correlator queue.

### Output bound

Every query is hard-bounded by:

- `take 100000` (compiler enforces);
- 30 s ClickHouse `max_execution_time`;
- 256 MB `max_memory_usage` per query.

A query that hits any limit returns an explicit "query exceeded
budget" error rather than a partial result.

## Consequences

- **Familiar to the target user.** Splunk + Sentinel users land on
  this syntax with minimal training.
- **No SQL injection by construction.** The compiler never
  string-interpolates user input.
- **Auto-tenant predicate is load-bearing.** A bug in the
  injection logic would silently expose cross-tenant data. The
  fuzz test + the explicit `compile_for_audit` paths are the
  guards.
- **The supported surface is small enough to write tests for.**
  We can exhaustively cover every operator × every column type.
- **A future extension to support a full KQL feature (`union`
  across telescoping windows, joins on > 2 sources) requires an
  ADR amendment.** The surface is deliberately frozen so we don't
  invite the "could you also add X" treadmill.

## Alternatives Considered

- **Expose ClickHouse SQL directly.** Rejected — auto-tenant
  predicate would be bolted on, surface too vast to fuzz-test for
  injection vectors.
- **Build a GUI-only filter-card UX.** Rejected — glass ceiling
  for advanced analysts.
- **Adopt a third-party hunt language wholesale (e.g. Sigma).**
  Rejected — Sigma is great for rules but the analyst hunt-loop
  needs an interactive pipe-style language. Sigma rules **are**
  supported as an import format and compile down to the same hunt
  AST.
- **Adopt OPA / Rego as the hunt expression language.** Rejected
  — Rego is great for policy decisions but a poor fit for log
  analytics (no native time-series aggregates).
