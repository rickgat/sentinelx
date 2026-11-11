//! [`AuditAction`] — the discriminator for an audit entry.
//!
//! The variant set is intentionally open-ended and extensible. New action
//! variants may be added in the future; existing chains must continue to
//! verify because each entry stores only its own action, not the variant
//! set of the codebase that produced it.

use serde::{Deserialize, Serialize};

/// Discrete, security-relevant action types recorded in the audit log.
///
/// Variants are serialised as `snake_case` strings so the on-disk format
/// remains stable across Rust enum reorderings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    /// A principal authenticated successfully.
    Login,
    /// A principal terminated their session.
    Logout,
    /// A failed authentication attempt.
    LoginFailed,
    /// A new engagement (scan campaign) was created.
    EngagementCreated,
    /// An engagement was updated.
    EngagementUpdated,
    /// An engagement was deleted.
    EngagementDeleted,
    /// A scan was started against an engagement.
    ScanStarted,
    /// A scan completed (successfully or otherwise).
    ScanCompleted,
    /// A scan was aborted before completion.
    ScanAborted,
    /// A new finding was created.
    FindingCreated,
    /// A finding was confirmed by a human reviewer.
    FindingConfirmed,
    /// A finding was rejected as a false positive.
    FindingRejected,
    /// The kill-switch was triggered, halting all active operations.
    KillSwitchTriggered,
    /// The kill-switch was released.
    KillSwitchReleased,
    /// The engagement scope (in-scope / out-of-scope targets) was changed.
    ScopeMutated,
    /// A secret was accessed (read) — secret value is **not** logged.
    SecretAccessed,
    /// A secret was rotated or replaced.
    SecretRotated,
    /// A role or permission grant was changed for a user.
    PermissionChanged,
    /// A new user was provisioned.
    UserCreated,
    /// A user was disabled or deleted.
    UserDisabled,
    /// Escape hatch for actions not yet modelled — `code` carries a stable
    /// machine-readable tag (e.g. `"plugin.foo.bar"`).
    Custom {
        /// Stable identifier for the custom action.
        code: String,
    },
}

impl AuditAction {
    /// Return a short machine-readable code for the variant, suitable for
    /// inclusion in metrics labels and external dashboards.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn code(&self) -> &str {
        match self {
            Self::Login => "login",
            Self::Logout => "logout",
            Self::LoginFailed => "login_failed",
            Self::EngagementCreated => "engagement_created",
            Self::EngagementUpdated => "engagement_updated",
            Self::EngagementDeleted => "engagement_deleted",
            Self::ScanStarted => "scan_started",
            Self::ScanCompleted => "scan_completed",
            Self::ScanAborted => "scan_aborted",
            Self::FindingCreated => "finding_created",
            Self::FindingConfirmed => "finding_confirmed",
            Self::FindingRejected => "finding_rejected",
            Self::KillSwitchTriggered => "kill_switch_triggered",
            Self::KillSwitchReleased => "kill_switch_released",
            Self::ScopeMutated => "scope_mutated",
            Self::SecretAccessed => "secret_accessed",
            Self::SecretRotated => "secret_rotated",
            Self::PermissionChanged => "permission_changed",
            Self::UserCreated => "user_created",
            Self::UserDisabled => "user_disabled",
            Self::Custom { code } => code.as_str(),
        }
    }
}
