//! Engagement aggregate root.
//!
//! NOTE: ultimately this will be re-exported from `sx_core::entity::engagement`.
//! While the core crate is still being scaffolded, the canonical types live
//! here so that the safety contracts can be exercised in isolation. The shape
//! mirrors the spec verbatim — `Engagement`, `EngagementStatus`,
//! `EngagementApproval` — so the eventual move is a re-export and not a
//! rewrite.
//!
//! ## Re-export migration status (Phase-3 consolidation)
//!
//! The canonical [`Engagement`] aggregate root and its [`EngagementStatus`]
//! finite-state-machine are *structurally* mirrored in
//! `sx_core::entity::engagement` — see the type-resolution path table in
//! `crates/sx-core/MIGRATION.md`. The literal `pub use sx_core::entity::
//! Engagement` swap is blocked on the cross-crate consolidation of the
//! [`crate::model::scope_target::ScopeTarget`] value object (sx-core's
//! version uses the strongly-typed `Fqdn` enum variant, while the
//! sx-engagement version uses a `String` for compatibility with the
//! existing 200+ test-site call patterns of the form
//! `ScopeTarget::Domain("example.com".into())`). Once `ScopeTarget` is
//! unified the [`Engagement`] type can collapse into a single canonical
//! re-export from sx-core; until then the local definition below remains
//! authoritative for the sx-engagement / discovery / monolith call-chain.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId, UserId};
use time::OffsetDateTime;

use crate::error::EngagementError;
use crate::model::intensity::ScanIntensity;
use crate::model::scope_target::ScopeTarget;
use crate::model::window::TimeWindow;

/// Finite-state-machine state for an engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngagementStatus {
    /// Created but not yet authorized to scan.
    Draft,
    /// Authorized; scope validator may grant scan requests.
    Active,
    /// Temporarily halted; may resume to `Active`.
    Paused,
    /// Finished cleanly.
    Completed,
    /// Aborted (manual or via kill switch).
    Aborted,
}

impl std::fmt::Display for EngagementStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
        };
        f.write_str(s)
    }
}

/// A single human approval entry.
///
/// Approvals are unique per `approver` — duplicates are ignored when counting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EngagementApproval {
    /// Identifier of the human who approved.
    pub approver: UserId,
    /// When the approval was recorded.
    pub approved_at: OffsetDateTime,
}

impl EngagementApproval {
    /// Construct a new approval record.
    #[must_use]
    pub const fn new(approver: UserId, approved_at: OffsetDateTime) -> Self {
        Self {
            approver,
            approved_at,
        }
    }
}

/// The engagement aggregate root.
///
/// All safety-critical state lives here:
/// - `scope`: explicit allow-list of `ScopeTarget`s.
/// - `window`: when scanning is permitted.
/// - `max_intensity`: ceiling above which scans are rejected.
/// - `approvals`: dual-approval ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Engagement {
    /// Aggregate identifier.
    pub id: EngagementId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Human-readable name (for audit trails).
    pub name: String,
    /// Current FSM status.
    pub status: EngagementStatus,
    /// Authorized scope — non-empty for `Active`.
    pub scope: Vec<ScopeTarget>,
    /// When scanning is permitted.
    pub window: TimeWindow,
    /// Highest intensity the engagement may exercise.
    pub max_intensity: ScanIntensity,
    /// Approvals on file.
    pub approvals: Vec<EngagementApproval>,
    /// When the engagement record was created.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

impl Engagement {
    /// Construct a new `Draft` engagement.
    ///
    /// Validates that `scope` is non-empty and that all invariants hold.
    pub fn new_draft(
        id: EngagementId,
        tenant_id: TenantId,
        name: impl Into<String>,
        scope: Vec<ScopeTarget>,
        window: TimeWindow,
        max_intensity: ScanIntensity,
        now: OffsetDateTime,
    ) -> Result<Self, EngagementError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(EngagementError::invalid_input("engagement name is empty"));
        }
        if scope.is_empty() {
            return Err(EngagementError::invalid_input("scope must not be empty"));
        }
        Ok(Self {
            id,
            tenant_id,
            name,
            status: EngagementStatus::Draft,
            scope,
            window,
            max_intensity,
            approvals: Vec::new(),
            created_at: now,
            updated_at: now,
        })
    }

    /// Number of *unique* approvers on file.
    #[must_use]
    pub fn unique_approver_count(&self) -> u32 {
        let mut seen = HashSet::new();
        for a in &self.approvals {
            seen.insert(a.approver);
        }
        u32::try_from(seen.len()).unwrap_or(u32::MAX)
    }

    /// Record an approval, refusing duplicates from the same `approver`.
    pub fn add_approval(&mut self, approval: EngagementApproval) -> Result<(), EngagementError> {
        if self
            .approvals
            .iter()
            .any(|a| a.approver == approval.approver)
        {
            return Err(EngagementError::invalid_input(
                "duplicate approval from approver",
            ));
        }
        self.approvals.push(approval);
        Ok(())
    }

    /// Try to transition into a new status.
    ///
    /// Allowed edges:
    /// `Draft -> Active | Aborted`
    /// `Active -> Paused | Completed | Aborted`
    /// `Paused -> Active | Aborted`
    /// `Completed` and `Aborted` are terminal.
    pub fn transition_to(
        &mut self,
        next: EngagementStatus,
        now: OffsetDateTime,
    ) -> Result<(), EngagementError> {
        let allowed = matches!(
            (self.status, next),
            (
                EngagementStatus::Draft | EngagementStatus::Paused,
                EngagementStatus::Active,
            ) | (
                EngagementStatus::Draft | EngagementStatus::Active | EngagementStatus::Paused,
                EngagementStatus::Aborted,
            ) | (
                EngagementStatus::Active,
                EngagementStatus::Paused | EngagementStatus::Completed,
            )
        );
        if !allowed {
            return Err(EngagementError::InvalidStateTransition {
                from: self.status.to_string(),
                to: next.to_string(),
            });
        }
        self.status = next;
        self.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::Duration;

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn make_engagement() -> Engagement {
        let window = TimeWindow::new(epoch(), epoch() + Duration::hours(2)).unwrap();
        Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "test",
            vec![ScopeTarget::Domain("example.com".into())],
            window,
            ScanIntensity::SafeInteractive,
            epoch(),
        )
        .unwrap()
    }

    #[test]
    fn new_draft_rejects_empty_scope() {
        let window = TimeWindow::new(epoch(), epoch() + Duration::hours(1)).unwrap();
        let r = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "x",
            vec![],
            window,
            ScanIntensity::Theoretical,
            epoch(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn new_draft_rejects_empty_name() {
        let window = TimeWindow::new(epoch(), epoch() + Duration::hours(1)).unwrap();
        let r = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "  ",
            vec![ScopeTarget::Domain("example.com".into())],
            window,
            ScanIntensity::Theoretical,
            epoch(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn transition_draft_to_active_ok() {
        let mut e = make_engagement();
        e.transition_to(EngagementStatus::Active, epoch() + Duration::seconds(1))
            .unwrap();
        assert_eq!(e.status, EngagementStatus::Active);
    }

    #[test]
    fn transition_completed_is_terminal() {
        let mut e = make_engagement();
        e.transition_to(EngagementStatus::Active, epoch()).unwrap();
        e.transition_to(EngagementStatus::Completed, epoch())
            .unwrap();
        let r = e.transition_to(EngagementStatus::Active, epoch());
        assert!(matches!(
            r,
            Err(EngagementError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn duplicate_approvals_rejected() {
        let mut e = make_engagement();
        let u = UserId::new();
        e.add_approval(EngagementApproval::new(u, epoch())).unwrap();
        let r = e.add_approval(EngagementApproval::new(u, epoch()));
        assert!(r.is_err());
    }

    #[test]
    fn unique_approver_count_correct() {
        let mut e = make_engagement();
        let u1 = UserId::new();
        let u2 = UserId::new();
        e.add_approval(EngagementApproval::new(u1, epoch()))
            .unwrap();
        e.add_approval(EngagementApproval::new(u2, epoch()))
            .unwrap();
        assert_eq!(e.unique_approver_count(), 2);
    }
}
