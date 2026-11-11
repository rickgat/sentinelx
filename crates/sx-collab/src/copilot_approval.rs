//! Copilot human-in-loop approval queue.
//!
//! Implements the P1-012 control gate: every state-changing action the AI
//! Copilot wants to take is first materialised as a [`ProposedAction`],
//! deposited into the queue via [`CopilotApprovalService::propose`], and
//! held in a `Pending` state until a human reviewer explicitly approves or
//! rejects it through [`CopilotApprovalService::decide`].
//!
//! ## State machine
//!
//! ```text
//!   Pending ──approve──▶ Approved (terminal)
//!      │
//!      ├──reject ───▶ Rejected (terminal — reason required)
//!      │
//!      └──TTL elapsed▶ Expired  (terminal — surfaced lazily at read time)
//! ```
//!
//! ## TTL semantics
//!
//! Pending entries auto-expire after a configurable duration (default
//! 1 hour). Expiry is enforced *lazily at read time* —
//! [`CopilotApprovalService::list_pending`] filters expired entries on the
//! fly, and [`CopilotApprovalService::decide`] refuses to decide an entry
//! whose deadline has elapsed (returning
//! [`CopilotApprovalError::Expired`]). This keeps the implementation
//! single-threaded without a background sweeper.
//!
//! ## Audit trail
//!
//! Every state transition (`Pending → Approved | Rejected | Expired`)
//! flows through the *caller* — this crate is intentionally storage- and
//! audit-sink-agnostic. The composition root layer (see
//! `services/sx-monolith/src/adapters/copilot_approval.rs`) appends each
//! transition to the `sx-audit` chain. The service does carry an in-memory
//! per-token history vector ([`ApprovalAuditEntry`]) the adapter can
//! cross-check the audit chain against.
//!
//! ## Security posture
//!
//! - `#![forbid(unsafe_code)]` is inherited from the crate root.
//! - No `unwrap`/`expect`/`panic!` on production paths.
//! - Reason is **required** when status = `Rejected` —
//!   [`CopilotApprovalService::decide`] returns
//!   [`CopilotApprovalError::ReasonRequired`] when the reviewer omits it.
//! - The `change_payload` JSON value is held verbatim; this crate does
//!   not introspect it. Callers are expected to keep secrets out of the
//!   payload.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Default lifetime of a `Pending` approval before it auto-expires.
///
/// One hour matches the P1-012 acceptance criteria. Operators can override
/// the value when constructing an [`InMemoryCopilotApprovalService`].
pub const DEFAULT_TTL_SECS: u64 = 3_600;

/// Opaque token returned by [`CopilotApprovalService::propose`] that
/// reviewers later quote when deciding.
///
/// Wrapping a [`Uuid`] keeps the wire shape stable but prevents accidental
/// confusion with other UUID-shaped identifiers (engagement, finding, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApprovalToken(pub Uuid);

impl ApprovalToken {
    /// Mint a fresh, random token.
    #[must_use]
    pub fn new_random() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wire-form string (canonical hyphenated UUID).
    #[must_use]
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }

    /// Parse from the wire form. Returns [`None`] on a malformed input.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Uuid::parse_str(s).ok().map(Self)
    }
}

impl std::fmt::Display for ApprovalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Who proposed the action.
///
/// Today the only proposer is the LLM-backed Copilot, but we leave the
/// enum open-ended for future AI agents (`Autonomy`, `RemediationAgent`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CopilotProposer {
    /// The AI Copilot single-turn chat surface.
    Copilot {
        /// Model identifier that produced the action.
        model: String,
    },
    /// Reserved for the autonomy continuous-validation pipeline.
    Autonomy,
    /// Escape hatch — stable identifier for an out-of-tree proposer.
    Custom {
        /// Machine-readable proposer code (e.g. `"agent.foo.bar"`).
        code: String,
    },
}

/// The set of state-changing actions the Copilot may propose.
///
/// Every variant deliberately holds primitive / `serde_json::Value` data
/// so this crate stays free of cross-crate dependencies on the
/// orchestrator types in `sx-bas` / `sx-remediation` / `sx-policy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProposedAction {
    /// Run a Breach-and-Attack-Simulation technique.
    RunBasTechnique {
        /// Engagement uuid the run is bound to.
        engagement_id: String,
        /// MITRE ATT&CK technique id, e.g. `T1003`.
        technique_id: String,
        /// Free-form target reference (FQDN, asset uuid, …).
        target: String,
        /// Attack mode — `theoretical` / `safe_interactive` /
        /// `active_exploit`. Held as a string to keep this crate decoupled
        /// from `sx-bas`.
        mode: String,
    },
    /// Apply a remediation against the vendor identified by `vendor`.
    ApplyRemediation {
        /// Finding uuid the remediation closes out.
        finding_id: String,
        /// Vendor code (e.g. `crowdstrike`, `microsoft`, `redhat`).
        vendor: String,
        /// Vendor-specific change payload — opaque to this crate.
        change_payload: serde_json::Value,
    },
    /// Change the safety policy.
    ChangeSafetyPolicy {
        /// Diff payload — opaque to this crate.
        policy_diff: serde_json::Value,
    },
}

impl ProposedAction {
    /// Short machine-readable code for the action variant. Used in the
    /// audit-log `action.code` field.
    #[must_use]
    pub const fn kind_code(&self) -> &'static str {
        match self {
            Self::RunBasTechnique { .. } => "run_bas_technique",
            Self::ApplyRemediation { .. } => "apply_remediation",
            Self::ChangeSafetyPolicy { .. } => "change_safety_policy",
        }
    }
}

/// Reviewer decision quoted to [`CopilotApprovalService::decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Approve the action — the caller is expected to dispatch it next.
    Approve,
    /// Reject the action — `reason` is required.
    Reject,
}

impl Decision {
    /// Stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }
}

/// User identifier (a uuid-shaped string is the canonical wire form).
///
/// Wrapping the string lets the controller layer carry whatever opaque
/// identifier the IAM layer mints without leaking that crate into here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub String);

impl UserId {
    /// Borrowed accessor.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Tenant identifier — same string wrapping as [`UserId`] so this crate
/// keeps zero dependencies on `sx-core`'s richer typed ids.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantScope(pub String);

impl TenantScope {
    /// Borrowed accessor.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lifecycle stage of an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting reviewer decision.
    Pending,
    /// Reviewer approved.
    Approved,
    /// Reviewer rejected.
    Rejected,
    /// TTL elapsed before any reviewer acted.
    Expired,
}

impl ApprovalStatus {
    /// Stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

/// A single state transition kept on the per-token audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalAuditEntry {
    /// Status the token was transitioned **into**.
    pub status: ApprovalStatus,
    /// Reviewer who acted, when present. `None` for the genesis
    /// `Pending` entry and for the lazy `Expired` transition.
    pub actor: Option<UserId>,
    /// Reviewer's free-form rationale, when supplied.
    pub reason: Option<String>,
    /// RFC 3339 timestamp the transition was recorded.
    pub at: String,
}

/// Outcome bundle returned by [`CopilotApprovalService::decide`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOutcome {
    /// Token the reviewer acted on.
    pub token: ApprovalToken,
    /// Resulting status (`Approved` or `Rejected`).
    pub status: ApprovalStatus,
    /// Reviewer.
    pub reviewer: UserId,
    /// Reason, when supplied (required for `Reject`).
    pub reason: Option<String>,
    /// RFC 3339 timestamp the decision was recorded.
    pub decided_at: String,
}

/// One pending approval surfaced by [`CopilotApprovalService::list_pending`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApproval {
    /// Token used in subsequent decide calls.
    pub token: ApprovalToken,
    /// Tenant the approval is scoped to.
    pub tenant_id: TenantScope,
    /// Who proposed the action.
    pub proposer: CopilotProposer,
    /// The proposed action.
    pub action: ProposedAction,
    /// Current status — always `Pending` for entries on this list.
    pub status: ApprovalStatus,
    /// RFC 3339 timestamp the proposal was recorded.
    pub proposed_at: String,
    /// RFC 3339 timestamp the proposal will auto-expire.
    pub expires_at: String,
}

/// Errors returned by the approval service.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum CopilotApprovalError {
    /// Token does not match any known approval.
    #[error("approval not found")]
    NotFound,
    /// Tenant id supplied with the decide call does not match the tenant
    /// the approval was scoped to.
    #[error("tenant mismatch")]
    TenantMismatch,
    /// Approval has already been decided.
    #[error("approval already decided")]
    AlreadyDecided,
    /// Approval has expired before the reviewer acted.
    #[error("approval expired")]
    Expired,
    /// Reviewer issued a `Reject` decision without supplying a reason.
    #[error("reason is required when rejecting")]
    ReasonRequired,
    /// Generic internal failure (lock poisoning, clock skew, etc.).
    #[error("internal: {0}")]
    Internal(String),
}

/// Internal record kept in the in-memory queue.
#[derive(Debug, Clone)]
struct ApprovalRecord {
    token: ApprovalToken,
    tenant_id: TenantScope,
    proposer: CopilotProposer,
    action: ProposedAction,
    status: ApprovalStatus,
    proposed_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    decided_at: Option<OffsetDateTime>,
    decided_by: Option<UserId>,
    reason: Option<String>,
    audit_trail: Vec<ApprovalAuditEntry>,
}

/// Service contract.
///
/// `propose` mints a fresh token and queues the action. `decide` resolves
/// the token to a terminal state. `list_pending` returns every still-live
/// (non-expired, undecided) entry for a tenant.
#[async_trait]
pub trait CopilotApprovalService: Send + Sync + std::fmt::Debug {
    /// Queue a fresh proposal. Returns the freshly-minted token.
    async fn propose(
        &self,
        tenant_id: TenantScope,
        proposer: CopilotProposer,
        action: ProposedAction,
    ) -> Result<ApprovalToken, CopilotApprovalError>;

    /// Resolve `token` to a terminal state.
    async fn decide(
        &self,
        token: ApprovalToken,
        tenant_id: TenantScope,
        decision: Decision,
        reviewer: UserId,
        reason: Option<String>,
    ) -> Result<DecisionOutcome, CopilotApprovalError>;

    /// List pending approvals scoped to `tenant_id`. Expired entries are
    /// filtered out and *transitioned* (their on-record status flipped to
    /// `Expired`) so subsequent decide calls surface
    /// [`CopilotApprovalError::Expired`] instead of `NotFound`.
    async fn list_pending(
        &self,
        tenant_id: TenantScope,
    ) -> Result<Vec<PendingApproval>, CopilotApprovalError>;

    /// Inspect any approval (pending or terminal). Returns the audit
    /// trail alongside the record. Used by audit-chain integration tests
    /// and by the controller's "what happened to my token?" lookup.
    async fn inspect(
        &self,
        token: ApprovalToken,
        tenant_id: TenantScope,
    ) -> Result<ApprovalSnapshot, CopilotApprovalError>;
}

/// Snapshot used by [`CopilotApprovalService::inspect`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSnapshot {
    /// Token.
    pub token: ApprovalToken,
    /// Tenant scope.
    pub tenant_id: TenantScope,
    /// Proposer.
    pub proposer: CopilotProposer,
    /// Proposed action.
    pub action: ProposedAction,
    /// Current status (terminal or pending).
    pub status: ApprovalStatus,
    /// RFC 3339 timestamp of proposal.
    pub proposed_at: String,
    /// RFC 3339 timestamp of expiry deadline.
    pub expires_at: String,
    /// RFC 3339 timestamp the reviewer decided; absent until then.
    pub decided_at: Option<String>,
    /// Reviewer that decided; absent until then.
    pub decided_by: Option<UserId>,
    /// Reviewer rationale; required on `Rejected` and absent on auto-
    /// expiry.
    pub reason: Option<String>,
    /// Per-token audit trail — one entry per state transition.
    pub audit_trail: Vec<ApprovalAuditEntry>,
}

/// In-memory `CopilotApprovalService` implementation.
///
/// All entries (pending + terminal) are kept in a single `Mutex<HashMap>`
/// keyed by the canonical token UUID. The map is bounded only by operator
/// behaviour; for the standalone monolith the working-set is well below
/// any concerning size. A Postgres-backed flavour can land alongside this
/// implementation when the persistence story lands.
pub struct InMemoryCopilotApprovalService {
    inner: Mutex<HashMap<Uuid, ApprovalRecord>>,
    ttl: Duration,
}

impl std::fmt::Debug for InMemoryCopilotApprovalService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryCopilotApprovalService")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl InMemoryCopilotApprovalService {
    /// Construct with the default 1-hour TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(DEFAULT_TTL_SECS))
    }

    /// Construct with an explicit TTL.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn format(ts: OffsetDateTime) -> String {
        ts.format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
    }

    fn lock_records(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<Uuid, ApprovalRecord>>, CopilotApprovalError>
    {
        self.inner
            .lock()
            .map_err(|_| CopilotApprovalError::Internal("approval lock poisoned".to_owned()))
    }

    fn maybe_expire(record: &mut ApprovalRecord, now: OffsetDateTime) {
        if record.status == ApprovalStatus::Pending && now >= record.expires_at {
            record.status = ApprovalStatus::Expired;
            record.decided_at = Some(now);
            record.audit_trail.push(ApprovalAuditEntry {
                status: ApprovalStatus::Expired,
                actor: None,
                reason: None,
                at: Self::format(now),
            });
        }
    }
}

impl Default for InMemoryCopilotApprovalService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CopilotApprovalService for InMemoryCopilotApprovalService {
    async fn propose(
        &self,
        tenant_id: TenantScope,
        proposer: CopilotProposer,
        action: ProposedAction,
    ) -> Result<ApprovalToken, CopilotApprovalError> {
        let now = Self::now();
        // `time::Duration::seconds` is signed; clamp to avoid wrap on
        // pathological TTL values. Operators set the TTL via
        // `Duration::from_secs` so the realistic upper bound is well
        // below `i64::MAX`.
        let ttl_secs = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let expires_at = now
            .checked_add(time::Duration::seconds(ttl_secs))
            .ok_or_else(|| CopilotApprovalError::Internal("ttl overflow".to_owned()))?;
        let token = ApprovalToken::new_random();
        let record = ApprovalRecord {
            token,
            tenant_id,
            proposer,
            action,
            status: ApprovalStatus::Pending,
            proposed_at: now,
            expires_at,
            decided_at: None,
            decided_by: None,
            reason: None,
            audit_trail: vec![ApprovalAuditEntry {
                status: ApprovalStatus::Pending,
                actor: None,
                reason: None,
                at: Self::format(now),
            }],
        };
        let mut guard = self.lock_records()?;
        guard.insert(token.0, record);
        Ok(token)
    }

    async fn decide(
        &self,
        token: ApprovalToken,
        tenant_id: TenantScope,
        decision: Decision,
        reviewer: UserId,
        reason: Option<String>,
    ) -> Result<DecisionOutcome, CopilotApprovalError> {
        // Reason is required before we acquire the lock — fail fast.
        if matches!(decision, Decision::Reject)
            && reason.as_ref().is_none_or(|r| r.trim().is_empty())
        {
            return Err(CopilotApprovalError::ReasonRequired);
        }
        let now = Self::now();

        let mut guard = self.lock_records()?;
        let record = guard
            .get_mut(&token.0)
            .ok_or(CopilotApprovalError::NotFound)?;

        if record.tenant_id != tenant_id {
            return Err(CopilotApprovalError::TenantMismatch);
        }

        Self::maybe_expire(record, now);

        match record.status {
            ApprovalStatus::Pending => {}
            ApprovalStatus::Approved | ApprovalStatus::Rejected => {
                return Err(CopilotApprovalError::AlreadyDecided);
            }
            ApprovalStatus::Expired => return Err(CopilotApprovalError::Expired),
        }

        let new_status = match decision {
            Decision::Approve => ApprovalStatus::Approved,
            Decision::Reject => ApprovalStatus::Rejected,
        };
        record.status = new_status;
        record.decided_at = Some(now);
        record.decided_by = Some(reviewer.clone());
        record.reason.clone_from(&reason);
        record.audit_trail.push(ApprovalAuditEntry {
            status: new_status,
            actor: Some(reviewer.clone()),
            reason: reason.clone(),
            at: Self::format(now),
        });

        Ok(DecisionOutcome {
            token,
            status: new_status,
            reviewer,
            reason,
            decided_at: Self::format(now),
        })
    }

    async fn list_pending(
        &self,
        tenant_id: TenantScope,
    ) -> Result<Vec<PendingApproval>, CopilotApprovalError> {
        let now = Self::now();
        let mut guard = self.lock_records()?;

        // Sweep expiry lazily as we walk the map.
        for record in guard.values_mut() {
            Self::maybe_expire(record, now);
        }

        let mut out: Vec<PendingApproval> = guard
            .values()
            .filter(|r| r.tenant_id == tenant_id && r.status == ApprovalStatus::Pending)
            .map(|r| PendingApproval {
                token: r.token,
                tenant_id: r.tenant_id.clone(),
                proposer: r.proposer.clone(),
                action: r.action.clone(),
                status: r.status,
                proposed_at: Self::format(r.proposed_at),
                expires_at: Self::format(r.expires_at),
            })
            .collect();
        // Deterministic ordering: oldest first.
        out.sort_by(|a, b| a.proposed_at.cmp(&b.proposed_at));
        Ok(out)
    }

    async fn inspect(
        &self,
        token: ApprovalToken,
        tenant_id: TenantScope,
    ) -> Result<ApprovalSnapshot, CopilotApprovalError> {
        let now = Self::now();
        let mut guard = self.lock_records()?;
        let record = guard
            .get_mut(&token.0)
            .ok_or(CopilotApprovalError::NotFound)?;
        if record.tenant_id != tenant_id {
            return Err(CopilotApprovalError::TenantMismatch);
        }
        Self::maybe_expire(record, now);
        Ok(ApprovalSnapshot {
            token: record.token,
            tenant_id: record.tenant_id.clone(),
            proposer: record.proposer.clone(),
            action: record.action.clone(),
            status: record.status,
            proposed_at: Self::format(record.proposed_at),
            expires_at: Self::format(record.expires_at),
            decided_at: record.decided_at.map(Self::format),
            decided_by: record.decided_by.clone(),
            reason: record.reason.clone(),
            audit_trail: record.audit_trail.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantScope {
        TenantScope("00000000-0000-0000-0000-000000000001".to_owned())
    }

    fn other_tenant() -> TenantScope {
        TenantScope("00000000-0000-0000-0000-000000000002".to_owned())
    }

    fn reviewer() -> UserId {
        UserId("user-1".to_owned())
    }

    fn sample_action() -> ProposedAction {
        ProposedAction::ApplyRemediation {
            finding_id: "f-1".to_owned(),
            vendor: "redhat".to_owned(),
            change_payload: serde_json::json!({ "patch": "RHSA-2024-1234" }),
        }
    }

    fn proposer() -> CopilotProposer {
        CopilotProposer::Copilot {
            model: "claude-3-5-sonnet-latest".to_owned(),
        }
    }

    #[tokio::test]
    async fn propose_then_approve_round_trips_audit_chain() {
        let svc = InMemoryCopilotApprovalService::new();
        let token = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();

        let pending = svc.list_pending(tenant()).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].token, token);
        assert_eq!(pending[0].status, ApprovalStatus::Pending);

        let outcome = svc
            .decide(
                token,
                tenant(),
                Decision::Approve,
                reviewer(),
                Some("LGTM".to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, ApprovalStatus::Approved);

        let snap = svc.inspect(token, tenant()).await.unwrap();
        assert_eq!(snap.status, ApprovalStatus::Approved);
        assert_eq!(snap.audit_trail.len(), 2);
        assert_eq!(snap.audit_trail[0].status, ApprovalStatus::Pending);
        assert_eq!(snap.audit_trail[1].status, ApprovalStatus::Approved);
        assert_eq!(snap.audit_trail[1].actor.as_ref().unwrap(), &reviewer());
    }

    #[tokio::test]
    async fn propose_then_reject_records_reason() {
        let svc = InMemoryCopilotApprovalService::new();
        let token = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();

        let outcome = svc
            .decide(
                token,
                tenant(),
                Decision::Reject,
                reviewer(),
                Some("noise".to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.status, ApprovalStatus::Rejected);
        assert_eq!(outcome.reason.as_deref(), Some("noise"));
    }

    #[tokio::test]
    async fn reject_without_reason_is_refused() {
        let svc = InMemoryCopilotApprovalService::new();
        let token = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();
        let err = svc
            .decide(token, tenant(), Decision::Reject, reviewer(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, CopilotApprovalError::ReasonRequired));

        // Empty reason is treated the same as `None`.
        let err = svc
            .decide(
                token,
                tenant(),
                Decision::Reject,
                reviewer(),
                Some("   ".to_owned()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, CopilotApprovalError::ReasonRequired));
    }

    #[tokio::test]
    async fn already_decided_returns_conflict() {
        let svc = InMemoryCopilotApprovalService::new();
        let token = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();
        svc.decide(token, tenant(), Decision::Approve, reviewer(), None)
            .await
            .unwrap();
        let err = svc
            .decide(token, tenant(), Decision::Approve, reviewer(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, CopilotApprovalError::AlreadyDecided));
    }

    #[tokio::test]
    async fn tenant_mismatch_is_refused() {
        let svc = InMemoryCopilotApprovalService::new();
        let token = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();
        let err = svc
            .decide(token, other_tenant(), Decision::Approve, reviewer(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, CopilotApprovalError::TenantMismatch));
    }

    #[tokio::test]
    async fn ttl_expires_pending_at_read_time() {
        // 1 nanosecond TTL forces the next read to mark the entry expired.
        let svc = InMemoryCopilotApprovalService::with_ttl(Duration::from_nanos(1));
        let token = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();
        // Yield once so the clock has a chance to tick past the deadline.
        tokio::time::sleep(Duration::from_millis(5)).await;

        let pending = svc.list_pending(tenant()).await.unwrap();
        assert!(
            pending.is_empty(),
            "expired entries must be filtered from the pending list"
        );

        let err = svc
            .decide(token, tenant(), Decision::Approve, reviewer(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, CopilotApprovalError::Expired));

        // Audit trail records both the Pending genesis and the
        // lazy Expired transition.
        let snap = svc.inspect(token, tenant()).await.unwrap();
        assert_eq!(snap.status, ApprovalStatus::Expired);
        let kinds: Vec<_> = snap.audit_trail.iter().map(|e| e.status).collect();
        assert_eq!(
            kinds,
            vec![ApprovalStatus::Pending, ApprovalStatus::Expired]
        );
    }

    #[tokio::test]
    async fn list_pending_is_tenant_scoped() {
        let svc = InMemoryCopilotApprovalService::new();
        let _ta = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();
        let _tb = svc
            .propose(other_tenant(), proposer(), sample_action())
            .await
            .unwrap();
        let a = svc.list_pending(tenant()).await.unwrap();
        let b = svc.list_pending(other_tenant()).await.unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_ne!(a[0].token, b[0].token);
    }

    #[tokio::test]
    async fn list_pending_excludes_terminal() {
        let svc = InMemoryCopilotApprovalService::new();
        let t1 = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();
        let _t2 = svc
            .propose(tenant(), proposer(), sample_action())
            .await
            .unwrap();
        svc.decide(t1, tenant(), Decision::Approve, reviewer(), None)
            .await
            .unwrap();
        let pending = svc.list_pending(tenant()).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0].token, t1);
    }

    #[test]
    fn token_round_trips_through_string() {
        let token = ApprovalToken::new_random();
        let s = token.as_string();
        let parsed = ApprovalToken::parse(&s).unwrap();
        assert_eq!(parsed, token);
    }

    #[test]
    fn token_parse_rejects_garbage() {
        assert!(ApprovalToken::parse("not-a-uuid").is_none());
    }

    #[test]
    fn proposed_action_kind_codes_are_stable() {
        assert_eq!(
            ProposedAction::RunBasTechnique {
                engagement_id: "e".into(),
                technique_id: "t".into(),
                target: "tgt".into(),
                mode: "theoretical".into()
            }
            .kind_code(),
            "run_bas_technique"
        );
        assert_eq!(
            ProposedAction::ApplyRemediation {
                finding_id: "f".into(),
                vendor: "v".into(),
                change_payload: serde_json::Value::Null
            }
            .kind_code(),
            "apply_remediation"
        );
        assert_eq!(
            ProposedAction::ChangeSafetyPolicy {
                policy_diff: serde_json::Value::Null
            }
            .kind_code(),
            "change_safety_policy"
        );
    }
}
