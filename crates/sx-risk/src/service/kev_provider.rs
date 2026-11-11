//! [`KevProvider`] port — adapter implementations live in downstream crates.

use async_trait::async_trait;
use sx_core::value_object::ids::CveId;

use crate::error::RiskError;

/// Port for checking whether a CVE is listed on the CISA KEV catalogue.
#[async_trait]
pub trait KevProvider: Send + Sync + std::fmt::Debug {
    /// Returns `true` iff `cve` is present on the KEV catalogue.
    async fn is_known_exploited(&self, cve: &CveId) -> Result<bool, RiskError>;
}
