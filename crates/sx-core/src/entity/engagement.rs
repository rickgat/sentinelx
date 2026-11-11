//! Engagement entity — the bounded testing context (scope + window + approvals).
//!
//! This is the **canonical** [`Engagement`] aggregate for the `SentinelX`
//! workspace. The shape mirrors `sx_engagement::model::engagement::
//! Engagement` verbatim — `id`, `tenant_id`, `name`, `status`, `scope`,
//! `window`, `max_intensity`, `approvals`, plus the [`OffsetDateTime`]
//! timestamps every persisted entity carries.
//!
//! ## Source-compat re-export status
//!
//! `sx-engagement` keeps a local definition of [`Engagement`] for now
//! because its local [`crate::value_object::scope::ScopeTarget`] uses
//! `Fqdn` for the `Domain` variant while the sx-engagement copy uses
//! `String`. Once [`crate::value_object::scope::ScopeTarget`] is the
//! single source of truth across the workspace the literal
//! `pub use sx_core::entity::Engagement;` swap inside
//! `sx_engagement::model::engagement` becomes a no-op. The structural
//! mirror is preserved here so that conversions / projections always have
//! a stable target type to land on.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::DomainError;
use crate::value_object::ids::{EngagementId, TenantId, UserId};
use crate::value_object::intensity::ScanIntensity;
use crate::value_object::scope::ScopeTarget;
use crate::value_object::time_window::TimeWindow;

/// Lifecycle status of an [`Engagement`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EngagementStatus {
    /// Being defined, not yet started.
    #[default]
    Draft,
    /// Approvals satisfied; running.
    Active,
    /// Temporarily paused.
    Paused,
    /// Finished normally.
    Completed,
    /// Stopped early — abort or kill-switch.
    Aborted,
}

impl fmt::Display for EngagementStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl EngagementStatus {
    /// Whether `self` is terminal — no further transitions allowed.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }

    /// Attempt to transition to `to`.
    pub fn try_transition(self, to: Self) -> Result<Self, DomainError> {
        if self == to {
            return Ok(self);
        }
        let allowed = matches!(
            (self, to),
            (Self::Draft | Self::Paused, Self::Active)
                | (Self::Draft | Self::Active | Self::Paused, Self::Aborted)
                | (Self::Active, Self::Paused | Self::Completed)
        );
        if allowed {
            Ok(to)
        } else {
            Err(DomainError::InvalidStateTransition {
                from: self.to_string(),
                to: to.to_string(),
            })
        }
    }
}

/// An approval record on an engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngagementApproval {
    /// The user who approved.
    pub approver: UserId,
    /// When the approval was recorded.
    pub approved_at: OffsetDateTime,
    /// Optional free-form note (e.g. ticket reference).
    pub note: Option<String>,
}

impl EngagementApproval {
    /// Build an approval record.
    pub fn new(
        approver: UserId,
        approved_at: OffsetDateTime,
        note: Option<String>,
    ) -> Result<Self, DomainError> {
        if let Some(n) = &note {
            if n.len() > 1024 {
                return Err(DomainError::invalid("approval note exceeds 1024 bytes"));
            }
        }
        Ok(Self {
            approver,
            approved_at,
            note,
        })
    }

    /// Build an approval with only `approver` + `approved_at` (no note).
    ///
    /// This is the canonical sibling-crate signature; it never fails.
    #[must_use]
    pub const fn with_timestamp(approver: UserId, approved_at: OffsetDateTime) -> Self {
        Self {
            approver,
            approved_at,
            note: None,
        }
    }

    /// Accessor for the approval timestamp.
    #[must_use]
    pub const fn approved_at(&self) -> OffsetDateTime {
        self.approved_at
    }
}

/// An engagement — a bounded authorization-to-test for a tenant.
///
/// Field shape mirrors `sx_engagement::model::engagement::Engagement`:
/// [`Self::scope`] is a [`Vec<ScopeTarget>`], [`Self::window`] is a single
/// [`TimeWindow`] value object, [`Self::max_intensity`] is the canonical
/// [`ScanIntensity`] enum, and the entity carries `created_at`/`updated_at`
/// timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Engagement {
    /// Identifier.
    pub id: EngagementId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Human-readable label.
    pub name: String,
    /// Lifecycle status.
    pub status: EngagementStatus,
    /// Allowed targets.
    pub scope: Vec<ScopeTarget>,
    /// When scanning is permitted.
    pub window: TimeWindow,
    /// Maximum probe intensity permitted.
    pub max_intensity: ScanIntensity,
    /// Recorded approvals.
    pub approvals: Vec<EngagementApproval>,
    /// When the engagement record was created.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

impl Engagement {
    /// Construct a new `Draft` engagement.
    ///
    /// Validates that `name` is non-empty, fits within the 200-byte
    /// budget, and that `scope` is non-empty.
    pub fn new_draft(
        id: EngagementId,
        tenant_id: TenantId,
        name: impl Into<String>,
        scope: Vec<ScopeTarget>,
        window: TimeWindow,
        max_intensity: ScanIntensity,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(DomainError::invalid("engagement name cannot be empty"));
        }
        if name.len() > 200 {
            return Err(DomainError::invalid("engagement name exceeds 200 bytes"));
        }
        if scope.is_empty() {
            return Err(DomainError::invariant("engagement scope cannot be empty"));
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

    /// Number of *unique* approvers on file (de-duplicated by `UserId`).
    #[must_use]
    pub fn unique_approver_count(&self) -> u32 {
        let mut seen: HashSet<UserId> = HashSet::new();
        for a in &self.approvals {
            seen.insert(a.approver);
        }
        u32::try_from(seen.len()).unwrap_or(u32::MAX)
    }

    /// Whether the approval requirements for activation are satisfied.
    ///
    /// When `max_intensity` requires dual approval (per
    /// [`ScanIntensity::requires_dual_approval`]) two *distinct* approvers
    /// are required; otherwise a single approval suffices.
    #[must_use]
    pub fn approvals_satisfied(&self) -> bool {
        if self.max_intensity.requires_dual_approval() {
            self.unique_approver_count() >= 2
        } else {
            !self.approvals.is_empty()
        }
    }

    /// Record an approval. Duplicate approvers are rejected.
    pub fn add_approval(&mut self, approval: EngagementApproval) -> Result<(), DomainError> {
        if self
            .approvals
            .iter()
            .any(|a| a.approver == approval.approver)
        {
            return Err(DomainError::conflict(format!(
                "approver {} has already approved",
                approval.approver,
            )));
        }
        self.approvals.push(approval);
        Ok(())
    }

    /// Attempt to transition into `next`, ignoring approval / window guards.
    ///
    /// This is a pure finite-state-machine transition. Approval and
    /// window guards live at the use-case layer.
    pub fn try_transition(
        &mut self,
        next: EngagementStatus,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.status = self.status.try_transition(next)?;
        self.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn start() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn end() -> OffsetDateTime {
        start() + time::Duration::days(1)
    }

    fn window() -> TimeWindow {
        TimeWindow::new(start(), end()).unwrap()
    }

    fn scope() -> Vec<ScopeTarget> {
        vec![ScopeTarget::cidr("10.0.0.0/24").unwrap()]
    }

    #[test]
    fn new_draft_ok() {
        let e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "Q3 PT",
            scope(),
            window(),
            ScanIntensity::SafeInteractive,
            start(),
        )
        .unwrap();
        assert_eq!(e.status, EngagementStatus::Draft);
        assert_eq!(e.created_at, start());
        assert_eq!(e.updated_at, start());
    }

    #[test]
    fn new_draft_rejects_empty_scope() {
        let r = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "x",
            vec![],
            window(),
            ScanIntensity::Theoretical,
            start(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn new_draft_rejects_empty_name() {
        let r = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "  ",
            scope(),
            window(),
            ScanIntensity::Theoretical,
            start(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn dual_approval_requires_two_distinct_users() {
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "x",
            scope(),
            window(),
            ScanIntensity::ActiveExploit,
            start(),
        )
        .unwrap();
        let u1 = UserId::new();
        let u2 = UserId::new();
        e.add_approval(EngagementApproval::new(u1, start(), None).unwrap())
            .unwrap();
        assert!(!e.approvals_satisfied());
        assert!(e
            .add_approval(EngagementApproval::new(u1, start(), None).unwrap())
            .is_err());
        e.add_approval(EngagementApproval::new(u2, start(), None).unwrap())
            .unwrap();
        assert!(e.approvals_satisfied());
    }

    #[test]
    fn try_transition_draft_to_active() {
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            scope(),
            window(),
            ScanIntensity::SafeInteractive,
            start(),
        )
        .unwrap();
        let later = start() + time::Duration::seconds(1);
        e.try_transition(EngagementStatus::Active, later).unwrap();
        assert_eq!(e.status, EngagementStatus::Active);
        assert_eq!(e.updated_at, later);
    }

    #[test]
    fn try_transition_terminal_blocks_further_change() {
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            scope(),
            window(),
            ScanIntensity::SafeInteractive,
            start(),
        )
        .unwrap();
        e.try_transition(EngagementStatus::Active, start()).unwrap();
        e.try_transition(EngagementStatus::Completed, start())
            .unwrap();
        assert!(e.status.is_terminal());
        assert!(e.try_transition(EngagementStatus::Active, start()).is_err());
    }

    #[test]
    fn unique_approver_count_dedupes() {
        let mut e = Engagement::new_draft(
            EngagementId::new(),
            TenantId::new(),
            "t",
            scope(),
            window(),
            ScanIntensity::SafeInteractive,
            start(),
        )
        .unwrap();
        let u1 = UserId::new();
        let u2 = UserId::new();
        e.add_approval(EngagementApproval::with_timestamp(u1, start()))
            .unwrap();
        assert!(e
            .add_approval(EngagementApproval::with_timestamp(u1, start()))
            .is_err());
        e.add_approval(EngagementApproval::with_timestamp(u2, start()))
            .unwrap();
        assert_eq!(e.unique_approver_count(), 2);
    }
}
