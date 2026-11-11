//! [`EpssProvider`] port — adapter implementations live in downstream crates.

use async_trait::async_trait;
use sx_core::value_object::{epss::EpssScore, ids::CveId};

use crate::error::RiskError;

/// Port for fetching EPSS scores for a CVE.
#[async_trait]
pub trait EpssProvider: Send + Sync + std::fmt::Debug {
    /// Resolve `cve` to its [`EpssScore`], or `None` if the provider has
    /// no record of it.
    async fn fetch(&self, cve: &CveId) -> Result<Option<EpssScore>, RiskError>;
}
