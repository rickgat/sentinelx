//! The [`VendorAdvisorySource`] trait — the single polymorphic abstraction
//! every concrete vendor adapter implements.

use async_trait::async_trait;
use sx_core::prelude::CveId;

use crate::error::RemediationError;
use crate::model::advisory::VendorAdvisory;

/// One vendor security feed.
///
/// Concrete implementations:
/// - [`crate::service::msrc::MsrcSource`]
/// - [`crate::service::redhat::RedHatSource`]
/// - [`crate::service::ubuntu::UbuntuSource`]
/// - [`crate::service::cisco::CiscoSource`]
#[async_trait]
pub trait VendorAdvisorySource: Send + Sync + std::fmt::Debug {
    /// Stable, lowercase vendor slug. Used by the registry as a logging
    /// field and by [`VendorAdvisory::vendor`] for downstream filtering.
    fn vendor(&self) -> &'static str;

    /// Fetch every advisory the vendor has published for the given CVE.
    ///
    /// Returns an empty `Vec` when the vendor has no record of the CVE.
    /// Returns [`RemediationError::NotFound`] when the vendor explicitly
    /// reports the CVE as unknown (HTTP 404). The registry treats both
    /// outcomes identically.
    async fn fetch_by_cve(&self, cve: &CveId) -> Result<Vec<VendorAdvisory>, RemediationError>;
}
