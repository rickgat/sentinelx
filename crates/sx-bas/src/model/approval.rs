//! Approval ledger + Rules of Engagement.
//!
//! Approvals are unique per [`Approval::approver`]; duplicate entries are
//! ignored when counting. The [`ApprovalPolicy`] derives the required count
//! from the active [`crate::model::mode::AttackMode`].
//!
//! A [`RulesOfEngagement`] artifact is a struct that carries the signing
//! operator and an expiry. Cryptographic verification of the signature is
//! **out of scope** for this crate — the orchestrator validates the signed
//! envelope before constructing the `RulesOfEngagement` value.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::UserId;
use time::OffsetDateTime;

use crate::error::BasError;
use crate::model::mode::AttackMode;

/// A single human-approval entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Approval {
    /// Identifier of the human who approved.
    pub approver: UserId,
    /// When the approval was recorded.
    pub approved_at: OffsetDateTime,
}

impl Approval {
    /// Construct a new approval record.
    #[must_use]
    pub const fn new(approver: UserId, approved_at: OffsetDateTime) -> Self {
        Self {
            approver,
            approved_at,
        }
    }
}

/// Policy object computed for the active mode.
///
/// `required_count` follows the conservative defaults declared by
/// [`AttackMode::required_approvals`]:
/// - `ActiveExploit` → 2
/// - `RedTeam` → 3
/// - All safer modes → 0
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalPolicy {
    /// Required number of unique approvers.
    pub required_count: u32,
}

impl ApprovalPolicy {
    /// Build the conservative-default policy for `mode`.
    #[must_use]
    pub const fn for_mode(mode: AttackMode) -> Self {
        Self {
            required_count: mode.required_approvals(),
        }
    }

    /// Construct a policy with an explicit threshold.
    #[must_use]
    pub const fn with_required(required_count: u32) -> Self {
        Self { required_count }
    }

    /// Returns `true` iff `approvals` contains at least `required_count`
    /// **distinct** approvers.
    #[must_use]
    pub fn met(self, approvals: &[Approval]) -> bool {
        if self.required_count == 0 {
            return true;
        }
        let mut seen: HashSet<UserId> = HashSet::with_capacity(approvals.len());
        for a in approvals {
            seen.insert(a.approver);
            if u32::try_from(seen.len()).unwrap_or(u32::MAX) >= self.required_count {
                return true;
            }
        }
        false
    }
}

/// Signed Rules of Engagement.
///
/// The struct carries the operator who signed, when, and the expiry. The
/// cryptographic verification of the signature is performed by the
/// orchestrator before this value is handed to the safety pipeline — this
/// crate trusts the value's existence as proof that signature verification
/// succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesOfEngagement {
    /// Operator who signed.
    pub signer: UserId,
    /// When the signature was applied.
    pub signed_at: OffsetDateTime,
    /// When the artifact expires.
    pub expires_at: OffsetDateTime,
}

impl RulesOfEngagement {
    /// Construct a validated RoE artifact.
    pub fn new(
        signer: UserId,
        signed_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, BasError> {
        if expires_at <= signed_at {
            return Err(BasError::roe_invalid(
                "expires_at must be strictly after signed_at",
            ));
        }
        Ok(Self {
            signer,
            signed_at,
            expires_at,
        })
    }

    /// Returns `true` when `now` is before the artifact's expiry.
    #[must_use]
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now >= self.signed_at && now < self.expires_at
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Approval, ApprovalPolicy, RulesOfEngagement};
    use crate::model::mode::AttackMode;
    use sx_core::value_object::ids::UserId;
    use time::{Duration, OffsetDateTime};

    fn at(t: OffsetDateTime) -> Approval {
        Approval::new(UserId::new(), t)
    }

    #[test]
    fn zero_threshold_is_always_met() {
        let p = ApprovalPolicy::with_required(0);
        assert!(p.met(&[]));
    }

    #[test]
    fn counts_distinct_approvers() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let a1 = at(now);
        let a2 = at(now);
        let dup = Approval::new(a1.approver, now);
        let p = ApprovalPolicy::with_required(2);
        assert!(!p.met(&[a1.clone(), dup]));
        assert!(p.met(&[a1, a2]));
    }

    #[test]
    fn policy_for_modes() {
        assert_eq!(
            ApprovalPolicy::for_mode(AttackMode::SafeInteractive).required_count,
            0,
        );
        assert_eq!(
            ApprovalPolicy::for_mode(AttackMode::ActiveExploit).required_count,
            2,
        );
        assert_eq!(
            ApprovalPolicy::for_mode(AttackMode::RedTeam).required_count,
            3,
        );
    }

    #[test]
    fn roe_validity_window() {
        let signed = OffsetDateTime::UNIX_EPOCH;
        let expires = signed + Duration::hours(1);
        let roe = RulesOfEngagement::new(UserId::new(), signed, expires).unwrap();
        assert!(roe.is_valid_at(signed));
        assert!(roe.is_valid_at(signed + Duration::minutes(30)));
        assert!(!roe.is_valid_at(expires));
        assert!(!roe.is_valid_at(expires + Duration::seconds(1)));
    }

    #[test]
    fn roe_rejects_immediate_expiry() {
        let t = OffsetDateTime::UNIX_EPOCH;
        assert!(RulesOfEngagement::new(UserId::new(), t, t).is_err());
    }
}
