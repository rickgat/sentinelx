//! Vulnerability-ingest DTOs — backs `POST /v1/vuln/import` and
//! `GET /v1/vuln/imports`.
//!
//! Wire shapes are deliberately small. The full parsed `NormalizedFinding`
//! list lives in `sx-vuln-ingest`; the API surface only ever exposes the
//! per-import receipt (asset / finding counts, source, status) so the
//! dashboard can render an import history without re-shipping potentially
//! large finding payloads over the wire.

use serde::{Deserialize, Serialize};

/// One row of the import-history list, mirroring the `vuln_imports` SQL
/// table 1:1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulnImportView {
    /// Import receipt uuid.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Originating scanner family — `nessus` or `openvas`.
    pub source: String,
    /// Distinct asset count produced by this import.
    pub asset_count: u32,
    /// Distinct `(asset_id, check_id)` count produced by this import.
    pub finding_count: u32,
    /// RFC 3339 timestamp the import was accepted.
    pub ingested_at: String,
    /// `ok | partial | failed`.
    pub status: String,
}

/// Response body for `POST /v1/vuln/import` — the freshly persisted row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulnImportResponse {
    /// The newly recorded import receipt.
    pub import: VulnImportView,
    /// Number of duplicate findings dropped by the dedup pass.
    pub duplicates_dropped: u32,
    /// Items that failed to parse (when `> 0`, `status = "partial"`).
    pub parse_errors: u32,
}

/// Response body for `GET /v1/vuln/imports`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListVulnImportsResponse {
    /// Import receipts matching the query, newest-first.
    pub items: Vec<VulnImportView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn import_view_serialises_with_snake_case_keys() {
        let v = VulnImportView {
            id: "i".into(),
            tenant_id: "t".into(),
            source: "nessus".into(),
            asset_count: 3,
            finding_count: 7,
            ingested_at: "2027-01-01T00:00:00Z".into(),
            status: "ok".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"asset_count\":3"));
        assert!(json.contains("\"finding_count\":7"));
        assert!(json.contains("\"ingested_at\""));
    }

    #[test]
    fn list_response_round_trips() {
        let resp = ListVulnImportsResponse {
            items: vec![VulnImportView {
                id: "i".into(),
                tenant_id: "t".into(),
                source: "openvas".into(),
                asset_count: 1,
                finding_count: 1,
                ingested_at: "2027-01-01T00:00:00Z".into(),
                status: "ok".into(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let round: ListVulnImportsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(round, resp);
    }

    #[test]
    fn import_response_carries_metrics() {
        let resp = VulnImportResponse {
            import: VulnImportView {
                id: "i".into(),
                tenant_id: "t".into(),
                source: "nessus".into(),
                asset_count: 4,
                finding_count: 9,
                ingested_at: "2027-01-01T00:00:00Z".into(),
                status: "partial".into(),
            },
            duplicates_dropped: 2,
            parse_errors: 1,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"duplicates_dropped\":2"));
        assert!(json.contains("\"parse_errors\":1"));
    }
}
