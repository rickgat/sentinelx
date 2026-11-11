//! Opt-in consent artifact for the threat-network client.
//!
//! Sharing is **opt-in** at the tenant level and per-scope. The threat-network
//! client refuses to submit until the caller provides a non-zero
//! [`TenantConsent`] whose [`SharingScope`] covers vulnerability-frequency
//! data.

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::TenantId;
use time::OffsetDateTime;

/// What categories of anonymised data a tenant has opted in to share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharingScope {
    /// No data sharing — present only as a default-construction safeguard.
    None,
    /// Vulnerability-frequency counts (CVE id + asset-kind hash + count).
    VulnerabilityFrequency,
    /// Vulnerability frequency PLUS anonymised attack-technique observations.
    VulnerabilityAndTechniqueFrequency,
}

impl SharingScope {
    /// `true` when this scope authorises vulnerability-frequency submissions.
    #[must_use]
    pub const fn includes_vulnerability_frequency(self) -> bool {
        matches!(
            self,
            Self::VulnerabilityFrequency | Self::VulnerabilityAndTechniqueFrequency,
        )
    }
}

/// Recorded tenant consent to share data with the threat network.
///
/// This artifact is created by the platform's consent UI and is replayed
/// into the threat-network client per submission. The client never persists
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConsent {
    /// Tenant that granted the consent.
    pub tenant_id: TenantId,
    /// When the consent was recorded.
    pub consented_at: OffsetDateTime,
    /// What kind of data is in scope.
    pub scope: SharingScope,
}

impl TenantConsent {
    /// Build a new consent artifact.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        consented_at: OffsetDateTime,
        scope: SharingScope,
    ) -> Self {
        Self {
            tenant_id,
            consented_at,
            scope,
        }
    }

    /// `true` when this consent is valid for vulnerability-frequency
    /// submissions: scope must include vuln-frequency and `consented_at`
    /// must be a non-zero (post-Unix-epoch) timestamp.
    #[must_use]
    pub fn authorises_vulnerability_frequency(&self) -> bool {
        self.scope.includes_vulnerability_frequency()
            && self.consented_at != OffsetDateTime::UNIX_EPOCH
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scope_includes_check() {
        assert!(!SharingScope::None.includes_vulnerability_frequency());
        assert!(SharingScope::VulnerabilityFrequency.includes_vulnerability_frequency());
        assert!(SharingScope::VulnerabilityAndTechniqueFrequency.includes_vulnerability_frequency());
    }

    #[test]
    fn consent_rejects_epoch_timestamp() {
        let c = TenantConsent::new(
            TenantId::new(),
            OffsetDateTime::UNIX_EPOCH,
            SharingScope::VulnerabilityFrequency,
        );
        assert!(!c.authorises_vulnerability_frequency());
    }

    #[test]
    fn consent_authorises_when_scope_matches() {
        let c = TenantConsent::new(
            TenantId::new(),
            OffsetDateTime::now_utc(),
            SharingScope::VulnerabilityFrequency,
        );
        assert!(c.authorises_vulnerability_frequency());
    }
}
