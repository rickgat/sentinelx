# ADR 0016 — SOAR DAG execution model: topological scheduler, cycle detection, `ActionExecutor` registry

Status: Accepted
Date: 2026-06-12
Deciders: Principal Platform Engineer, SOC Lead, Principal Security Engineer
Supersedes: None
Superseded by: None

## Context

P3-005 ships SOAR — Security Orchestration, Automation, and
Response. A SOAR workflow describes "when X happens, do Y, then Z;
if Z fails, do W". The workflow is a directed graph; each node is
an action (block a user, post to Slack, open a Jira ticket,
restart a process, page a human, …).

We need to decide:

- **Execution model.** Linear pipeline? Reactive event loop?
  Topologically-scheduled DAG?
- **Cycle handling.** Reject cyclic workflows at compile time, at
  runtime, or accept them with bounded loop detection?
- **Action surface.** Hard-coded action set or pluggable?
- **Failure semantics.** Stop-on-first-failure or continue-with-
  best-effort?

The SOC playbooks that motivate SOAR (Okta deactivation, Jira
ticket creation, S3 bucket lockdown, Crowdstrike host containment)
naturally express as small DAGs with one or two branching points
and parallel fan-out / fan-in.

## Decision

### DAG with topological scheduler

A workflow is a directed acyclic graph of nodes:

```rust
struct WorkflowDag {
    nodes: BTreeMap<NodeId, Node>,    // each Node carries an ActionRef + inputs
    edges: Vec<Edge>,                  // directed (from, to, condition)
}
```

Execution:

1. Compute a topological order via Kahn's algorithm.
2. For each level in topological order, dispatch every node whose
   `condition` matches the upstream node's output. Within a
   level, nodes run **in parallel** through a per-tenant Tokio
   `JoinSet` with concurrency cap (16 by default).
3. After every level completes, write the per-step record into
   `soar_runs.step_log` (RDBMS §4.57).
4. On any node failure, evaluate the node's `on_failure` policy:
   `stop`, `continue`, or `branch`. Default is `stop`.

The scheduler is single-process (no distributed coordinator); a
workflow's run is pinned to a single `sx-soar` worker for its
lifetime. Horizontal scale is achieved by running multiple workers
each handling a subset of tenants (chosen by consistent hash on
`tenant_id`).

### Cycle detection at compile time

The DAG is validated when the workflow is *saved*, not when it is
*run*:

```rust
fn validate_dag(dag: &WorkflowDag) -> Result<(), DagError> {
    // 1. every edge references a node that exists
    // 2. no parallel duplicate edges between the same pair
    // 3. Kahn's topological sort succeeds (no cycles)
    // 4. exactly one node has in-degree 0 (the trigger)
    // 5. every leaf has a defined on_complete behaviour
}
```

The cycle check uses Kahn's algorithm: if any node remains after
peeling off zero-in-degree nodes iteratively, the graph has a
cycle and the workflow is rejected with a `DagError::Cyclic` that
names the cycle members.

The `soar_workflows` table CHECK is a DEFERRED-to-application
validator (Postgres can't evaluate graph cycles in a row-level
CHECK; the validator runs before every write and the registry
refuses cyclic DAGs).

### `ActionExecutor` registry

Actions are pluggable through a trait:

```rust
#[async_trait]
pub trait ActionExecutor: Send + Sync {
    fn name(&self) -> &'static str;       // 'okta.deactivate_user', 'jira.create_issue', ...
    fn input_schema(&self) -> &'static JsonSchema;
    fn output_schema(&self) -> &'static JsonSchema;
    async fn execute(
        &self,
        ctx: &ActionContext,           // tenant_id, run_id, step_id, plugin sandbox
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ActionError>;
}
```

Built-in actions:

| Name | Purpose |
|---|---|
| `okta.deactivate_user` | Okta API: deactivate user |
| `jira.create_issue` | Jira API: create issue |
| `slack.post_message` | Slack webhook: post message |
| `pagerduty.trigger` | PagerDuty Events API |
| `crowdstrike.contain_host` | CrowdStrike Falcon: contain host |
| `aws.iam.detach_policy` | AWS IAM: detach managed policy |
| `aws.s3.block_public_access` | AWS S3: enable BPA |
| `internal.audit_event` | SentinelX audit-event emit |
| `internal.kill_switch` | SentinelX kill-switch arm |

The registry is read-only at runtime; an executor is registered at
process start (`SoarRegistry::register(ActionExecutor)`) and never
mutated thereafter. New built-in actions ship via a new release;
customer-specific actions ship via the plugin host (ADR 0017).

### Idempotency

Every action MUST be idempotent — the workflow may be replayed on
failure of a downstream node. Idempotency is achieved via:

- a per-run idempotency key (UUIDv7 derived from `(run_id,
  node_id, attempt)`) passed to the external API where supported
  (Jira, Slack, PagerDuty all accept idempotency keys);
- a "compensation" path documented per action for the non-
  idempotent ones (e.g. `okta.deactivate_user` — replay is safe
  because the second call is a no-op).

### Retries

Each node carries a `retry` policy (`max_attempts`, `backoff`).
Failures retry with jittered exponential backoff up to
`max_attempts` (default 3, max 10). After exhausting retries, the
node's `on_failure` policy kicks in.

### Failure semantics

Default `on_failure = stop` — the run fails, the run row is
written with status `failed`, and the operator is paged. A node can
opt into `continue` (best-effort, e.g. "post to Slack but don't
fail the whole workflow if Slack is down") or `branch` (route to
a defined error-handling sub-DAG).

### Observability

- Every node's input + output (after redaction of credentials)
  lands in `soar_runs.step_log` as a JSONB record.
- A per-step trace span is emitted with the OTel context propagated
  from the trigger event.
- A node that takes longer than its declared p99 (the SOAR UI
  surfaces the historical p99 per action) emits a `warn!` log.

## Consequences

- **Familiar to SOC engineers.** DAG semantics map directly onto
  the "if X then do Y, in parallel Z; if Y fails, do W" playbook
  shape SOC teams already use in Splunk SOAR / Tines / Torq.
- **Cycle bugs caught at save time.** An operator who wires a
  cycle into the UI gets a refusal at save; runtime never sees an
  infinite loop.
- **Pluggable action surface.** The trait makes adding actions a
  contained patch; the plugin host (ADR 0017) lets third-party
  developers ship actions without modifying the platform.
- **Single-process per-run scheduler.** Simpler than a distributed
  coordinator. The trade-off is a worker crash mid-run leaves the
  run in `running` status; a periodic janitor flips workflows
  stale > 1 h to `aborted`.
- **No long-running workflows.** A workflow that exceeds the
  per-run budget (1 h by default, configurable per tenant) is
  aborted. SOAR is for fast incident automation; longer-running
  orchestration is out of scope.

## Alternatives Considered

- **Step-functions / Temporal / Cadence.** Operationally heavier
  for the MVP. Re-evaluate if SOAR usage scales beyond ~1 k
  concurrent runs.
- **Reactive event-loop (BPMN-style).** Rejected — playbook
  authors think in DAG terms, not in event streams.
- **Allow cycles with bounded loop detection.** Rejected —
  authoring story is worse and runtime cycle detection is
  strictly weaker than a save-time refusal.
- **No retry framework — fail fast on first error.** Rejected —
  external SOAR endpoints are notoriously flaky; retry is table
  stakes.
