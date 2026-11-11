//! Pure evaluator for the per-tenant AAGUID allow/block decision
//! (HIGH-002).
//!
//! Decision matrix:
//!
//! | Tenant has any `allow` row? | Has `block` row for AAGUID? | Has `allow` row for AAGUID? | Decision         |
//! |-----------------------------|-----------------------------|-----------------------------|------------------|
//! | yes                         | yes                         | (any)                       | `Reject(block)`  |
//! | yes                         | no                          | yes                         | `Accept(allow)`  |
//! | yes                         | no                          | no                          | `Reject(deny)`   |
//! | no                          | yes                         | (any)                       | `Reject(block)`  |
//! | no                          | no                          | (any)                       | `Accept(default)`|
//!
//! The tenant flips into "allowlist-only" mode the moment any
//! [`AaguidAction::Allow`] row exists. Once in that mode, the implicit
//! default for AAGUIDs without rows becomes "deny". This implements
//! the spec's "default policy if no row: `allow` (backward compat with
//! P1-002); if tenant has ANY allow row, default-deny anything not
//! allowed."

use uuid::Uuid;

use crate::model::webauthn::{AaguidAction, AaguidPolicy};

/// Outcome of evaluating the tenant's AAGUID policy against a single
/// authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AaguidDecision {
    /// The authenticator is allowed. Carries the rationale string so
    /// the audit log records *why* (e.g. "implicit default", "explicit
    /// allow: SE5+ approved").
    Accept {
        /// Operator-readable rationale.
        reason: String,
    },
    /// The authenticator is rejected. Carries the rationale string for
    /// the audit log and the [`WebauthnError::AaguidBlocked`] message.
    Reject {
        /// Operator-readable rationale.
        reason: String,
    },
}

impl AaguidDecision {
    /// True iff this decision accepts the authenticator.
    #[must_use]
    pub const fn is_accept(&self) -> bool {
        matches!(self, Self::Accept { .. })
    }

    /// Returns the rationale string regardless of variant.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Accept { reason } | Self::Reject { reason } => reason,
        }
    }
}

/// Evaluate the tenant's per-AAGUID policy against `aaguid`.
///
/// `rows` is every policy row for the tenant (already RLS-scoped by the
/// repository). The evaluator is pure and synchronous — the
/// registration path passes it the already-loaded rows so it can be
/// unit-tested without an async fixture.
///
/// `aaguid` is the authenticator's AAGUID as reported in the attestation
/// (`None` is treated as `Uuid::nil` for matching purposes; some U2F
/// devices report all-zero).
#[must_use]
pub fn evaluate(rows: &[AaguidPolicy], aaguid: Uuid) -> AaguidDecision {
    let mut explicit_block: Option<&AaguidPolicy> = None;
    let mut explicit_allow: Option<&AaguidPolicy> = None;
    let mut has_any_allow = false;

    for row in rows {
        if matches!(row.action, AaguidAction::Allow) {
            has_any_allow = true;
            if row.aaguid == aaguid {
                explicit_allow = Some(row);
            }
        } else if matches!(row.action, AaguidAction::Block) && row.aaguid == aaguid {
            explicit_block = Some(row);
        }
    }

    if let Some(block) = explicit_block {
        return AaguidDecision::Reject {
            reason: format!("explicit block: {}", block.reason),
        };
    }
    if let Some(allow) = explicit_allow {
        return AaguidDecision::Accept {
            reason: format!("explicit allow: {}", allow.reason),
        };
    }
    if has_any_allow {
        AaguidDecision::Reject {
            reason: format!("allowlist-only mode: aaguid {aaguid} not on tenant allowlist"),
        }
    } else {
        AaguidDecision::Accept {
            reason: "default policy: no per-tenant rule, allow".to_owned(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::domain::{TenantId, UserId};
    use time::OffsetDateTime;

    fn aaguid(idx: u128) -> Uuid {
        Uuid::from_u128(idx)
    }

    fn row(action: AaguidAction, a: Uuid, reason: &str) -> AaguidPolicy {
        AaguidPolicy {
            tenant_id: TenantId::new(),
            aaguid: a,
            action,
            reason: reason.to_owned(),
            set_by: UserId::new(),
            set_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn empty_rows_default_allow() {
        let d = evaluate(&[], aaguid(1));
        assert!(d.is_accept());
        assert!(d.reason().contains("default"));
    }

    #[test]
    fn explicit_block_rejects() {
        let rows = vec![row(AaguidAction::Block, aaguid(1), "RP-001")];
        let d = evaluate(&rows, aaguid(1));
        assert!(!d.is_accept());
        assert!(d.reason().contains("RP-001"));
    }

    #[test]
    fn block_does_not_affect_other_aaguids_default_allow() {
        let rows = vec![row(AaguidAction::Block, aaguid(1), "RP-001")];
        let d = evaluate(&rows, aaguid(2));
        assert!(d.is_accept());
    }

    #[test]
    fn allow_row_flips_into_allowlist_mode() {
        let rows = vec![row(AaguidAction::Allow, aaguid(1), "L3 approved")];
        // The matching aaguid is allowed.
        let d = evaluate(&rows, aaguid(1));
        assert!(d.is_accept());
        // Any other aaguid is rejected by the implicit default-deny.
        let d = evaluate(&rows, aaguid(2));
        assert!(!d.is_accept());
        assert!(d.reason().contains("allowlist-only"));
    }

    #[test]
    fn block_wins_over_allow_for_same_aaguid() {
        // Defence-in-depth: a block row for the same AAGUID should
        // always reject, even if a stale allow row also exists.
        let rows = vec![
            row(AaguidAction::Allow, aaguid(1), "approved"),
            row(AaguidAction::Block, aaguid(1), "subsequently revoked"),
        ];
        let d = evaluate(&rows, aaguid(1));
        assert!(!d.is_accept());
        assert!(d.reason().contains("subsequently revoked"));
    }

    #[test]
    fn allowlist_mode_blocks_other_aaguids_even_with_a_block_row_present() {
        // Allowlist mode is triggered by the presence of any allow row.
        // A block row alone doesn't trigger it.
        let rows = vec![
            row(AaguidAction::Allow, aaguid(1), "approved L3 vendor"),
            row(AaguidAction::Block, aaguid(2), "RP-002"),
        ];
        // Allowed aaguid → accept.
        assert!(evaluate(&rows, aaguid(1)).is_accept());
        // Explicitly-blocked aaguid → reject (block reason wins).
        let d = evaluate(&rows, aaguid(2));
        assert!(!d.is_accept());
        assert!(d.reason().contains("RP-002"));
        // Not-on-allowlist aaguid → reject (allowlist default-deny).
        let d = evaluate(&rows, aaguid(3));
        assert!(!d.is_accept());
        assert!(d.reason().contains("allowlist-only"));
    }

    #[test]
    fn block_only_does_not_flip_into_allowlist_mode() {
        // Sanity check on the matrix's third row: a tenant with only
        // block rows still defaults to allow for unmentioned aaguids.
        let rows = vec![row(AaguidAction::Block, aaguid(1), "RP-001")];
        let d = evaluate(&rows, aaguid(99));
        assert!(d.is_accept());
        assert!(d.reason().contains("default"));
    }
}
