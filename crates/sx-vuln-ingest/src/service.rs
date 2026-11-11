//! Service / port wrapper around the parser + dedup + registry stack.

use std::sync::Arc;

use async_trait::async_trait;

use crate::dedup::deduplicate;
use crate::model::{ImportReport, SourceFormat, VulnIngestError};
use crate::parser::{nessus, openvas};
use crate::registry::CheckIdRegistry;

/// Hard cap on the payload size accepted by [`VulnIngestService::import`].
/// Mirrors the request-body limit applied at the API edge.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 100 * 1024 * 1024;

/// Service surface the API/adapter layer interacts with.
#[async_trait]
pub trait VulnIngestService: Send + Sync {
    /// Parse `payload`, deduplicate, and return a structured
    /// [`ImportReport`] tagged with `tenant_id`. Side-effects (DB write,
    /// audit log entry) are the adapter's responsibility.
    async fn import(
        &self,
        tenant_id: &str,
        source: SourceFormat,
        payload: &[u8],
    ) -> Result<ImportReport, VulnIngestError>;
}

/// Pure in-memory [`VulnIngestService`] implementation. Stateless; safe
/// to wrap in an `Arc` and share across the runtime.
#[derive(Debug, Clone)]
pub struct InMemoryVulnIngestService {
    registry: Arc<CheckIdRegistry>,
    max_payload_bytes: usize,
}

impl Default for InMemoryVulnIngestService {
    fn default() -> Self {
        Self {
            registry: Arc::new(CheckIdRegistry::new()),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }
}

impl InMemoryVulnIngestService {
    /// Build with an explicit registry handle.
    #[must_use]
    pub fn new(registry: Arc<CheckIdRegistry>) -> Self {
        Self {
            registry,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Override the per-payload size limit. Used by tests.
    #[must_use]
    pub fn with_max_payload_bytes(mut self, max: usize) -> Self {
        self.max_payload_bytes = max;
        self
    }
}

#[async_trait]
impl VulnIngestService for InMemoryVulnIngestService {
    async fn import(
        &self,
        tenant_id: &str,
        source: SourceFormat,
        payload: &[u8],
    ) -> Result<ImportReport, VulnIngestError> {
        if payload.len() > self.max_payload_bytes {
            return Err(VulnIngestError::PayloadTooLarge {
                actual: payload.len(),
                max: self.max_payload_bytes,
            });
        }

        let text = std::str::from_utf8(payload)
            .map_err(|e| VulnIngestError::Xml(format!("payload is not utf-8: {e}")))?;

        let raw = match source {
            SourceFormat::Nessus => nessus::parse(text, &self.registry)?,
            SourceFormat::Openvas => openvas::parse(text, &self.registry)?,
        };

        let raw_len = raw.len();
        let report = deduplicate(raw);
        let asset_count = {
            let mut set = std::collections::HashSet::with_capacity(report.findings.len());
            for f in &report.findings {
                set.insert(f.asset_id.clone());
            }
            set.len()
        };

        let parse_errors = raw_len
            .checked_sub(report.findings.len())
            .and_then(|n| n.checked_sub(report.dropped))
            .unwrap_or(0);

        Ok(ImportReport {
            tenant_id: tenant_id.to_owned(),
            source,
            asset_count,
            finding_count: report.findings.len(),
            duplicates_dropped: report.dropped,
            parse_errors,
            findings: report.findings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NESSUS_FIXTURE: &str = r#"<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="t">
    <ReportHost name="10.0.0.1">
      <ReportItem pluginID="51192" pluginName="SSL Expired" severity="3">
        <description>d</description><solution>s</solution>
        <cve>CVE-2024-1234</cve><cvss3_base_score>7.5</cvss3_base_score>
      </ReportItem>
      <ReportItem pluginID="51192" pluginName="SSL Expired" severity="3">
        <description>d</description><solution>s</solution>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.2">
      <ReportItem pluginID="51192" pluginName="SSL Expired" severity="3">
        <description>d</description><solution>s</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"#;

    const OPENVAS_FIXTURE: &str = r#"<report id="r1">
  <results>
    <result>
      <host>10.0.0.1</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103674"><name>OpenSSL</name><cvss_base>7.5</cvss_base></nvt>
      <threat>High</threat>
    </result>
    <result>
      <host>10.0.0.1</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103674"><name>OpenSSL</name></nvt>
      <threat>High</threat>
    </result>
  </results>
</report>"#;

    #[tokio::test]
    async fn imports_and_deduplicates_nessus() {
        let svc = InMemoryVulnIngestService::default();
        let r = svc
            .import("t1", SourceFormat::Nessus, NESSUS_FIXTURE.as_bytes())
            .await
            .unwrap();
        assert_eq!(r.tenant_id, "t1");
        assert_eq!(r.source, SourceFormat::Nessus);
        // 3 raw rows → 2 unique by (asset, check) keys.
        assert_eq!(r.finding_count, 2);
        assert_eq!(r.duplicates_dropped, 1);
        assert_eq!(r.asset_count, 2);
        assert_eq!(r.parse_errors, 0);
    }

    #[tokio::test]
    async fn imports_and_deduplicates_openvas() {
        let svc = InMemoryVulnIngestService::default();
        let r = svc
            .import("t1", SourceFormat::Openvas, OPENVAS_FIXTURE.as_bytes())
            .await
            .unwrap();
        assert_eq!(r.finding_count, 1);
        assert_eq!(r.duplicates_dropped, 1);
        assert_eq!(r.asset_count, 1);
    }

    #[tokio::test]
    async fn rejects_oversized_payload() {
        let svc = InMemoryVulnIngestService::default().with_max_payload_bytes(10);
        let err = svc
            .import("t1", SourceFormat::Nessus, NESSUS_FIXTURE.as_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, VulnIngestError::PayloadTooLarge { .. }));
    }

    #[tokio::test]
    async fn rejects_non_utf8_payload() {
        let svc = InMemoryVulnIngestService::default();
        let bad = [0xff_u8, 0xfe, 0xfd];
        let err = svc
            .import("t1", SourceFormat::Nessus, &bad)
            .await
            .unwrap_err();
        assert!(matches!(err, VulnIngestError::Xml(_)));
    }

    #[tokio::test]
    async fn rejects_unrecognised_xml() {
        let svc = InMemoryVulnIngestService::default();
        let err = svc
            .import("t1", SourceFormat::Nessus, b"<other/>")
            .await
            .unwrap_err();
        assert!(matches!(err, VulnIngestError::UnrecognisedShape(_)));
    }
}
