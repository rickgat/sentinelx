//! Multi-source advisory registry.
//!
//! Fans out a single `fetch_by_cve` call across every registered
//! [`VendorAdvisorySource`] in parallel via [`futures::future::join_all`].
//! One failed source must not poison the overall result, so we collect
//! successes and log failures at `warn` level. Implements
//! [`VendorAdvisorySource`] itself so the copilot can hold a single source
//! handle without caring whether it is a single vendor or a fan-out.

use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use sx_core::prelude::CveId;

use crate::error::RemediationError;
use crate::model::advisory::VendorAdvisory;
use crate::service::source::VendorAdvisorySource;

/// Aggregating [`VendorAdvisorySource`].
#[derive(Debug, Clone)]
pub struct MultiSourceAdvisoryRegistry {
    sources: Vec<Arc<dyn VendorAdvisorySource>>,
}

impl MultiSourceAdvisoryRegistry {
    /// Build an empty registry.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Build a registry from a fixed source list.
    #[must_use]
    pub fn new(sources: Vec<Arc<dyn VendorAdvisorySource>>) -> Self {
        Self { sources }
    }

    /// Append a source. Useful in test setup.
    pub fn register(&mut self, source: Arc<dyn VendorAdvisorySource>) {
        self.sources.push(source);
    }

    /// How many sources are currently registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// `true` when no sources are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Fetch advisories from every source in parallel. Failed sources are
    /// logged at `warn` and dropped; `NotFound` responses are silently
    /// skipped (they are not failures).
    pub async fn fetch(&self, cve: &CveId) -> Vec<VendorAdvisory> {
        let mut futs = Vec::with_capacity(self.sources.len());
        for s in &self.sources {
            let s = s.clone();
            let cve = cve.clone();
            futs.push(async move {
                let vendor = s.vendor();
                let res = s.fetch_by_cve(&cve).await;
                (vendor, res)
            });
        }
        let outcomes = join_all(futs).await;
        let mut combined = Vec::new();
        for (vendor, res) in outcomes {
            match res {
                Ok(mut items) => combined.append(&mut items),
                Err(RemediationError::NotFound(_)) => {
                    tracing::debug!(target: "sx_remediation::registry", vendor, "no advisories");
                }
                Err(err) => {
                    tracing::warn!(target: "sx_remediation::registry", vendor, error = %err, "source failed");
                }
            }
        }
        combined
    }
}

#[async_trait]
impl VendorAdvisorySource for MultiSourceAdvisoryRegistry {
    fn vendor(&self) -> &'static str {
        "registry"
    }

    async fn fetch_by_cve(&self, cve: &CveId) -> Result<Vec<VendorAdvisory>, RemediationError> {
        Ok(self.fetch(cve).await)
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
    use time::OffsetDateTime;
    use url::Url;

    #[derive(Debug)]
    struct OkSource {
        vendor: &'static str,
        advisory: VendorAdvisory,
    }

    #[async_trait]
    impl VendorAdvisorySource for OkSource {
        fn vendor(&self) -> &'static str {
            self.vendor
        }

        async fn fetch_by_cve(
            &self,
            _cve: &CveId,
        ) -> Result<Vec<VendorAdvisory>, RemediationError> {
            Ok(vec![self.advisory.clone()])
        }
    }

    #[derive(Debug)]
    struct FailingSource {
        vendor: &'static str,
    }

    #[async_trait]
    impl VendorAdvisorySource for FailingSource {
        fn vendor(&self) -> &'static str {
            self.vendor
        }

        async fn fetch_by_cve(
            &self,
            _cve: &CveId,
        ) -> Result<Vec<VendorAdvisory>, RemediationError> {
            Err(RemediationError::transport(self.vendor, "boom"))
        }
    }

    #[derive(Debug)]
    struct NotFoundSource;

    #[async_trait]
    impl VendorAdvisorySource for NotFoundSource {
        fn vendor(&self) -> &'static str {
            "nf-vendor"
        }

        async fn fetch_by_cve(
            &self,
            _cve: &CveId,
        ) -> Result<Vec<VendorAdvisory>, RemediationError> {
            Err(RemediationError::NotFound("nf-vendor"))
        }
    }

    fn sample_adv(vendor: &str) -> VendorAdvisory {
        VendorAdvisory::new(
            vendor,
            "ADV-1",
            vec![],
            vec![],
            vec![Url::parse("https://example.com/a").unwrap()],
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[tokio::test]
    async fn source_registry_collects_successes_and_logs_failures() {
        let ok = Arc::new(OkSource {
            vendor: "ok-vendor",
            advisory: sample_adv("ok-vendor"),
        });
        let fail = Arc::new(FailingSource {
            vendor: "fail-vendor",
        });
        let nf = Arc::new(NotFoundSource);

        let reg = MultiSourceAdvisoryRegistry::new(vec![ok, fail, nf]);
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let out = reg.fetch(&cve).await;

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vendor, "ok-vendor");
    }

    #[tokio::test]
    async fn registry_implements_source_trait() {
        let ok = Arc::new(OkSource {
            vendor: "ok-vendor",
            advisory: sample_adv("ok-vendor"),
        });
        let reg = MultiSourceAdvisoryRegistry::new(vec![ok]);
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let out = reg.fetch_by_cve(&cve).await.unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn registry_register_grows() {
        let mut reg = MultiSourceAdvisoryRegistry::empty();
        assert!(reg.is_empty());
        reg.register(Arc::new(NotFoundSource));
        assert_eq!(reg.len(), 1);
    }
}
