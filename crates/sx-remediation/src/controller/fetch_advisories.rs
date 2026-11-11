//! Use-case: fetch every vendor advisory for a CVE.
//!
//! Thin façade over [`crate::service::registry::MultiSourceAdvisoryRegistry`].
//! Exists so the API crate has a stable controller surface that does not
//! change shape when the registry's internals evolve.

use std::sync::Arc;

use sx_core::prelude::CveId;

use crate::error::RemediationError;
use crate::model::advisory::VendorAdvisory;
use crate::service::source::VendorAdvisorySource;

/// Use-case wrapper.
#[derive(Debug, Clone)]
pub struct FetchAdvisoriesUseCase {
    sources: Arc<dyn VendorAdvisorySource>,
}

impl FetchAdvisoriesUseCase {
    /// Build the use-case around any [`VendorAdvisorySource`] —
    /// typically a [`crate::service::registry::MultiSourceAdvisoryRegistry`].
    #[must_use]
    pub fn new(sources: Arc<dyn VendorAdvisorySource>) -> Self {
        Self { sources }
    }

    /// Fetch every advisory for `cve`. Errors only on internal invariant
    /// failure — vendor errors are swallowed by the registry.
    pub async fn execute(&self, cve: &CveId) -> Result<Vec<VendorAdvisory>, RemediationError> {
        self.sources.fetch_by_cve(cve).await
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::single_char_pattern,
    clippy::single_char_add_str,
    clippy::float_cmp,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::model::advisory::VendorAdvisory;
    use async_trait::async_trait;
    use time::OffsetDateTime;
    use url::Url;

    #[derive(Debug)]
    struct StubSource;

    #[async_trait]
    impl VendorAdvisorySource for StubSource {
        fn vendor(&self) -> &'static str {
            "stub"
        }

        async fn fetch_by_cve(
            &self,
            _cve: &CveId,
        ) -> Result<Vec<VendorAdvisory>, RemediationError> {
            Ok(vec![VendorAdvisory::new(
                "stub",
                "ADV-1",
                vec![],
                vec![],
                vec![Url::parse("https://example.com").unwrap()],
                OffsetDateTime::UNIX_EPOCH,
            )])
        }
    }

    #[tokio::test]
    async fn forwards_to_inner_source() {
        let uc = FetchAdvisoriesUseCase::new(Arc::new(StubSource));
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let out = uc.execute(&cve).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vendor, "stub");
    }
}
