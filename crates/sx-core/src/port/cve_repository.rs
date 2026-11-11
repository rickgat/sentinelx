//! [`CveRepository`] port — read/write the local CVE cache.
//!
//! CVE data is *not* tenant-scoped (it's public reference data), so these
//! methods omit the tenant argument.

use async_trait::async_trait;

use crate::entity::cve::Cve;
use crate::error::DomainError;
use crate::value_object::ids::CveId;
use crate::value_object::page::{Page, PagedResult};

/// Persistence port for [`Cve`] reference data.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CveRepository: Send + Sync {
    /// Look up a CVE record by id.
    async fn find_by_id(&self, id: &CveId) -> Result<Option<Cve>, DomainError>;

    /// List most-recently published CVEs (paged form).
    async fn list_recent(&self, page: Page) -> Result<PagedResult<Cve>, DomainError>;

    /// List the most-recently-published CVEs up to `limit`.
    ///
    /// Convenience wrapper over [`CveRepository::list_recent`] for callers
    /// that just want the top-N. The default implementation builds a
    /// single-page request with `offset = 0` and unwraps the items; adapters
    /// may override for efficiency.
    ///
    /// # Errors
    /// Forwards adapter errors and [`DomainError::InvalidValue`] when
    /// `limit` is zero or exceeds [`Page::MAX_LIMIT`].
    async fn list_recent_n(&self, limit: u32) -> Result<Vec<Cve>, DomainError> {
        let page = Page::new(0, limit)?;
        let result = self.list_recent(page).await?;
        Ok(result.items)
    }

    /// Insert-or-update a CVE record.
    async fn upsert(&self, cve: &Cve) -> Result<(), DomainError>;
}
