# ADR 0004: Four-stage BAS safety pipeline with kill switch

Maintainer: Platform Engineering + Security Engineering (`#sentinelx-secops`)
Last reviewed: 2026-05-30

- Status: Accepted
- Date: 2026-05-30
- Deciders: Founding engineering team, CISO
- Supersedes: None
- Superseded by: None

## Context

Breach and attack simulation (BAS) is the most dangerous thing
SentinelX does. We deliberately attempt to exploit customer systems
to validate that real attackers could. A bug, a misconfiguration, or a
malicious actor with sufficient privilege could turn the platform into
an outage generator or, worse, a data-loss event.

The risk surface includes:

- **Out-of-scope blast radius**: a technique reaches an asset that is
  not in the engagement scope.
- **Out-of-window execution**: a destructive technique runs at 02:00
  on Black Friday because someone scheduled the engagement against
  prod.
- **Privilege escalation**: a "validate" technique mutates state.
- **Operator coercion**: a compromised operator account approves a
  high-impact engagement.
- **Runaway**: a bug in the orchestrator submits 10,000 simultaneous
  techniques.
- **Provider-side trip**: AWS or Azure escalates rate-limit responses
  and we trigger an account suspension.

The product requires we **never** harm the customer's environment.
"Never" here is a hard product invariant: a single incident undoes a
year of trust building.

We need a layered defense such that any single failure does not
result in a destructive execution.

## Decision

We will implement a **four-stage safety pipeline**. Every BAS
technique execution passes through all four stages, in order, on every
attempt. Each stage is independently sufficient to block.

```
        +-----------+    +-----------+    +-----------+    +-----------+
attempt | (1) Kill  | -> | (2) Mode  | -> | (3) Window| -> | (4) Two-  | -> execute
   ---> |   switch  |    |   gate    |    |   gate    |    |   person  |
        +-----------+    +-----------+    +-----------+    +-----------+
```

A technique that does not pass all four stages is **blocked, logged,
and reported back to the engagement owner**. There is no override path
that bypasses the pipeline. Operators can change the *inputs* to each
stage (raise the kill switch, change the mode, edit the window, grant
the approval) but they cannot remove a stage.

### Stage 1: Kill switch

A global, per-tenant, per-engagement, and per-technique-family kill
switch. The most granular trip wins. The state is held in two
locations for cross-checking:

- **Postgres** `bas.kill_switch` table — durable source of truth.
- **Redis** `kill_switch:{tenant}:{engagement}:{family}` — hot read
  path; subscribed to via Redis pub/sub for sub-second propagation.

On every technique submission the orchestrator:

1. Reads the relevant kill-switch rows from Redis.
2. If any matching row is `tripped=true`, refuses to schedule, logs a
   `KillSwitchBlocked` event with the reason, and returns 423 Locked
   to the API caller.
3. If Redis is unavailable, falls back to Postgres (slower, ~5 ms
   instead of ~0.1 ms).

The kill switch is **fail-closed**: if neither Redis nor Postgres is
reachable, the orchestrator refuses to schedule.

#### Tripping the kill switch

```
POST /v1/safety/kill-switch
Authorization: Bearer <operator-token>
Content-Type: application/json

{
  "scope": "engagement",
  "tenant": "acme",
  "engagement_id": "eng_01J7...",
  "family": "exfiltration",
  "reason": "manual hold while we investigate finding #1234",
  "tripped_by": "alice@acme.com"
}
```

The endpoint requires the `safety:kill_switch:write` scope. It writes
to Postgres synchronously, then publishes to the Redis channel. The
audit log records the trip with the full request body.

Resetting the kill switch requires the **two-person rule** (see Stage
4): two distinct operator approvals before the reset is applied.

### Stage 2: Mode gate

Each engagement has a **mode ladder** that bounds what techniques can
run:

| Mode        | What it permits                                                              |
| ----------- | ---------------------------------------------------------------------------- |
| `observe`   | Read-only enumeration. No state changes anywhere.                            |
| `simulate`  | In-memory simulation. Real targets are touched only for benign confirmation. |
| `validate`  | Active confirmation. May trigger side effects (e.g. a webhook).              |
| `exploit`   | Full exploitation. Allowed only in pre-prod or with explicit customer sign. |

The mode is set at engagement creation and **can only be raised**
through an approval flow. Lowering is free (always safer).

Every technique declares its required mode in its metadata. The mode
gate rejects any technique whose required mode exceeds the engagement
mode.

The mode ladder is also used to filter the technique catalogue in the
UI so operators do not see options they cannot use, but the
filter is a UX nicety — the enforcement is server-side.

### Stage 3: Window gate

Each engagement has a list of **allowed windows** — time ranges
during which executions may run, expressed in the customer's local
timezone and validated against an explicit calendar (e.g.
"weekdays 02:00-06:00 America/Los_Angeles"). The window list also
includes named exclusions: "not on company-listed holidays", "not
during the freeze window 2025-11-25 .. 2025-12-02".

The gate evaluation:

1. Compute `now` in the engagement timezone.
2. For each allowed window, check overlap with `now + lookahead`
   where `lookahead` is the technique's estimated runtime (default 10
   minutes, plus a 2-minute safety margin).
3. For each exclusion window, check `now + lookahead` is not within.
4. If outside all allowed windows or inside an exclusion, reject with
   `WindowGateBlocked` and reschedule for the next allowed window.

Windows can be edited only by the engagement owner. Edits are
auditable. Edits that would expand the window into the next hour are
flagged for manual approval ("you cannot edit your way out of the
window gate at the last minute").

### Stage 4: Two-person rule (approval)

Any technique whose mode is `validate` or `exploit`, or whose target
asset is tagged `production`, requires an explicit approval from a
second human operator before it can run. The flow:

1. Engagement owner submits the technique for execution.
2. The system pins a `pending_approval` record with the technique
   metadata, target, mode, and expected blast radius.
3. A second operator (not the submitter, must have role `approver` or
   higher) reviews and either approves or rejects via the dashboard
   or `sx-cli safety approve`.
4. Approval is good for **15 minutes** and **one execution**. Approval
   is bound to a specific technique, engagement, target list, and
   mode; any of those changing requires a fresh approval.

Approvals are audit-logged with both the submitter and the approver
identities and the full payload that was approved.

The two-person rule also gates:

- Tripping a kill switch (any operator can trip; resetting takes two).
- Raising the engagement mode.
- Editing a window within 1 hour of the current time.

### Implementation summary

The pipeline lives in `crates/sx-bas/src/service/safety.rs` and is
called by the orchestrator before any technique is dispatched. The
order is enforced by the return type — `SafetyGuard` is a struct that
can only be constructed by the safety service, and only the
orchestrator can consume it. The Rust type system makes it impossible
to call the executor without holding a fresh `SafetyGuard`.

```rust
pub struct SafetyGuard { /* private fields */ }

impl SafetyService {
    pub async fn evaluate(&self, req: SafetyRequest) -> Result<SafetyGuard, SafetyError> {
        self.check_kill_switch(&req).await?;     // (1)
        self.check_mode_gate(&req).await?;       // (2)
        self.check_window_gate(&req).await?;     // (3)
        self.check_two_person_rule(&req).await?; // (4)
        Ok(SafetyGuard::new(req))
    }
}

impl TechniqueExecutor {
    pub async fn execute(&self, guard: SafetyGuard) -> Result<TechniqueOutcome, ExecError> {
        // ... cannot be called without a SafetyGuard
    }
}
```

## Consequences

### Positive

- **Defense in depth**. Four independent stages, each fail-closed.
  Even with a bug in three of them, the fourth blocks.
- **Type-system enforcement**. The executor cannot be called without a
  `SafetyGuard`. The compiler is the final reviewer.
- **Auditability**. Every block, every approval, every kill-switch
  trip lands in the audit log with the full payload.
- **Composability with the kill switch**. Operators can trip the
  kill switch in seconds via API, dashboard, or CLI; the dashboard
  surfaces a big red button.
- **No bypass path**. There is exactly zero code in the orchestrator
  that calls the executor without going through `evaluate`. We have
  a compile-time test that asserts this.

### Negative

- **Latency cost.** Each stage adds 1-3 ms to the technique dispatch
  path; the four-stage pipeline costs about 8 ms typical. Acceptable.
- **Two-person rule fatigue.** Operators report friction. We mitigate
  with a UX that shows the approver exactly what changes, and an
  Approve button right next to the request.
- **Window math is timezone-rich and risky.** We use `chrono-tz` with
  a frozen IANA database and revisit the DB version annually.
- **Pipeline is mandatory for every technique.** Even `observe`-mode
  techniques pay the cost. We do not allow "fast paths".

### Risk register

| Risk                                                | Mitigation                                                       |
| --------------------------------------------------- | ---------------------------------------------------------------- |
| Kill switch state diverges between PG and Redis.    | Quarterly reconciliation job + alert if divergence > 0.          |
| Approver and submitter are the same human (sock).   | Auth event records IP, UA, and login chain; review on weekly basis. |
| Window gate timezone bug fires off-hours.           | Calendar tests in CI with all customer timezones.                |
| `SafetyGuard` is constructed bypassing `evaluate`.  | `SafetyGuard::new` is `pub(crate)`; compile-time test asserts.   |
| Kill switch trip causes legitimate work to stall.   | Granular scoping; operators trip at the smallest scope first.    |

## Kill-switch operational guarantees

- **Time to take effect**: < 1 second p99 across all orchestrator
  workers in the same cluster (Redis pub/sub).
- **Cold-start safety**: a newly-started orchestrator pod reads the
  kill switch state from Postgres before accepting work.
- **Audit guarantee**: every trip and every reset is logged with the
  identities involved and the full request body.

## Alternatives considered

### Alternative 1: Single global allow/deny list

A single in-memory list of "what is allowed right now".

**Why not:**
- One layer, one failure point. Does not give defense in depth.
- Does not separate concerns; the window vs. mode vs. approval logic
  ends up tangled.

### Alternative 2: Manual approval for every execution

Always require a human Approve, regardless of mode.

**Why not:**
- Operationally unworkable. `observe`-mode runs may include thousands
  of techniques.
- The friction would push operators to grant blanket approvals,
  which is worse than the current model.

### Alternative 3: Out-of-band approval (email / chat)

Approvals flow through email or Slack rather than the platform.

**Why not:**
- Worse audit story. The approval is in someone's mailbox.
- Identity binding is weaker.
- The approve-via-Slack button gets phished.
- We do offer a Slack-channel **notification** for pending approvals
  with a deep link back to the platform.

### Alternative 4: External policy engine (OPA)

Open Policy Agent evaluating Rego policies.

**Why not (yet):**
- The four stages are simple enough that policy-as-code adds more
  process than it removes.
- OPA introduces a separate ops surface and a separate language to
  learn for the team most likely to modify policy (security
  engineers).
- We may reconsider for very large customers with bespoke policy
  needs.

## References

- [MITRE ATT&CK BAS guidance](https://attack.mitre.org/)
- NIST SP 800-115 ("Technical Guide to Information Security Testing and Assessment")
- [ADR 0001: Modular monolith](./0001-rust-modular-monolith.md)
- [ADR 0005: Audit log HMAC chain](./0005-audit-log-hmac-chain-anchoring.md)
- The existing project ADR [`0004-ai-remediation-copilot-guardrails.md`](./0004-ai-remediation-copilot-guardrails.md) — parallel guardrail pattern for the remediation copilot.
- The runbook section "Kill-switch trip" in [`../runbooks/incident-response.md`](../runbooks/incident-response.md).
