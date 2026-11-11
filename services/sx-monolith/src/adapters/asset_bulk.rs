//! Concrete adapter behind [`sx_api::port::AssetBulkImportPort`].
//!
//! Wraps any [`sx_api::port::AssetWritePort`] trait object so a single
//! HTTP-facing bulk-import call (`POST /v1/assets/bulk-import`) can be
//! demultiplexed into per-row [`AssetWritePort::create`] dispatches. The
//! adapter:
//!
//! 1. Parses the payload as either a JSON array or a CSV body with the
//!    canonical header `engagement_id,kind,identifier,source`. Any other
//!    shape surfaces as [`Phase3PortError::Invalid`] — the controller
//!    translates that into HTTP `400 Bad Request`.
//! 2. Refuses payloads with more than
//!    [`sx_api::view::asset_view::BULK_IMPORT_MAX_ROWS`] rows.
//! 3. Validates every row with `validator::Validate` before dispatching;
//!    a validation failure is recorded as a per-row error and does not
//!    abort the import.
//! 4. Treats `EngagementPortError::Conflict` (duplicate
//!    `(engagement_id, identifier)` pair) as `skipped`; every other
//!    `EngagementPortError` lands in the per-row error list.
//!
//! ## Why a bundle
//!
//! Mirrors [`crate::adapters::asset_write::AssetWriteBundle`] so the
//! composition root picks each port off a single struct — the wiring
//! stays uniform across adapters.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use sx_api::port::{AssetBulkImportPort, AssetWritePort, EngagementPortError, Phase3PortError};
use sx_api::view::asset_view::{
    BulkImportError, BulkImportRequest, BulkImportResponse, CreateAssetRequest,
    BULK_IMPORT_MAX_ROWS,
};
use validator::Validate;

/// Canonical CSV header expected by the bulk-import adapter. The adapter
/// rejects any other header (case-sensitive, exact order).
const CSV_HEADER: &[&str] = &["engagement_id", "kind", "identifier", "source"];

/// Bundle exposing the single bulk-import trait object.
pub(crate) struct AssetBulkImportBundle {
    /// Trait object plugged into [`sx_api::AppState::asset_bulk`].
    pub bulk: Arc<dyn AssetBulkImportPort>,
}

impl AssetBulkImportBundle {
    /// Build the bundle from any [`AssetWritePort`] implementation. The
    /// composition root passes `Arc::clone(&asset_write_bundle.write)`
    /// so bulk imports flow through the same in-memory store as the
    /// per-row `POST /v1/assets` endpoint.
    pub(crate) fn build(writer: Arc<dyn AssetWritePort>) -> Self {
        let adapter = AssetBulkImportAdapter { writer };
        Self {
            bulk: Arc::new(adapter),
        }
    }
}

/// One row decoded from the JSON payload.
#[derive(Debug, Deserialize)]
struct JsonRow {
    engagement_id: String,
    kind: String,
    identifier: String,
    source: String,
}

impl From<JsonRow> for CreateAssetRequest {
    fn from(row: JsonRow) -> Self {
        Self {
            engagement_id: row.engagement_id,
            kind: row.kind,
            identifier: row.identifier,
            source: row.source,
        }
    }
}

/// Concrete adapter — parses + dispatches each row through the supplied
/// [`AssetWritePort`].
struct AssetBulkImportAdapter {
    writer: Arc<dyn AssetWritePort>,
}

impl AssetBulkImportAdapter {
    /// Parse the request body into per-row [`CreateAssetRequest`]s.
    ///
    /// Returns [`Phase3PortError::Invalid`] for malformed input (bad JSON,
    /// non-array root, malformed CSV header, oversized payload).
    fn parse_rows(req: &BulkImportRequest) -> Result<Vec<CreateAssetRequest>, Phase3PortError> {
        let raw_rows: Vec<CreateAssetRequest> = if req.format.eq_ignore_ascii_case("json") {
            parse_json(&req.body)?
        } else if req.format.eq_ignore_ascii_case("csv") {
            parse_csv(&req.body)?
        } else {
            return Err(Phase3PortError::Invalid(format!(
                "unsupported format: {}",
                req.format
            )));
        };
        if raw_rows.len() > BULK_IMPORT_MAX_ROWS {
            return Err(Phase3PortError::Invalid(format!(
                "row count {} exceeds cap {}",
                raw_rows.len(),
                BULK_IMPORT_MAX_ROWS
            )));
        }
        Ok(raw_rows)
    }
}

#[async_trait]
impl AssetBulkImportPort for AssetBulkImportAdapter {
    async fn import(
        &self,
        tenant_id: &str,
        req: BulkImportRequest,
    ) -> Result<BulkImportResponse, Phase3PortError> {
        let rows = Self::parse_rows(&req)?;
        let mut created: u32 = 0;
        let mut skipped: u32 = 0;
        let mut errors: Vec<BulkImportError> = Vec::new();
        for (idx, row) in rows.into_iter().enumerate() {
            let row_idx = u32::try_from(idx).unwrap_or(u32::MAX);
            if let Err(e) = row.validate() {
                errors.push(BulkImportError {
                    row: row_idx,
                    message: summarise_validation(&e),
                });
                continue;
            }
            match self.writer.create(tenant_id, row).await {
                Ok(_view) => {
                    created = created.saturating_add(1);
                }
                Err(EngagementPortError::Conflict(_)) => {
                    skipped = skipped.saturating_add(1);
                }
                Err(e) => {
                    errors.push(BulkImportError {
                        row: row_idx,
                        message: e.to_string(),
                    });
                }
            }
        }
        Ok(BulkImportResponse {
            created,
            skipped,
            errors,
        })
    }
}

/// Parse a JSON-array body into per-row [`CreateAssetRequest`]s.
///
/// Treats anything other than a JSON array of objects with the expected
/// shape as [`Phase3PortError::Invalid`] (mapped to HTTP `400`).
fn parse_json(body: &str) -> Result<Vec<CreateAssetRequest>, Phase3PortError> {
    let rows: Vec<JsonRow> = serde_json::from_str(body)
        .map_err(|e| Phase3PortError::Invalid(format!("malformed JSON: {e}")))?;
    Ok(rows.into_iter().map(CreateAssetRequest::from).collect())
}

/// Parse a CSV body with the canonical header into per-row
/// [`CreateAssetRequest`]s. The header is checked exactly — anything
/// other than `engagement_id,kind,identifier,source` (in that order)
/// surfaces as [`Phase3PortError::Invalid`].
fn parse_csv(body: &str) -> Result<Vec<CreateAssetRequest>, Phase3PortError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .trim(csv::Trim::All)
        .from_reader(body.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| Phase3PortError::Invalid(format!("malformed CSV header: {e}")))?
        .clone();
    if headers.len() != CSV_HEADER.len()
        || !headers
            .iter()
            .zip(CSV_HEADER.iter())
            .all(|(actual, expected)| actual == *expected)
    {
        return Err(Phase3PortError::Invalid(format!(
            "unexpected CSV header — got {:?}, want {:?}",
            headers.iter().collect::<Vec<_>>(),
            CSV_HEADER,
        )));
    }
    let mut rows = Vec::new();
    for (i, record) in reader.records().enumerate() {
        let record =
            record.map_err(|e| Phase3PortError::Invalid(format!("malformed CSV row {i}: {e}")))?;
        // Header was already validated; positional access is stable.
        let engagement_id = record.get(0).unwrap_or_default().to_owned();
        let kind = record.get(1).unwrap_or_default().to_owned();
        let identifier = record.get(2).unwrap_or_default().to_owned();
        let source = record.get(3).unwrap_or_default().to_owned();
        rows.push(CreateAssetRequest {
            engagement_id,
            kind,
            identifier,
            source,
        });
    }
    Ok(rows)
}

/// Project a `validator::ValidationErrors` value into a compact `field:code`
/// summary that is safe to surface inside the per-row error message.
fn summarise_validation(errors: &validator::ValidationErrors) -> String {
    let mut parts = Vec::new();
    for (field, kind) in errors.field_errors() {
        let codes: Vec<&str> = kind.iter().map(|e| e.code.as_ref()).collect();
        parts.push(format!("{field}: {}", codes.join(", ")));
    }
    if parts.is_empty() {
        "validation failed".to_owned()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use crate::adapters::asset_write::AssetWriteBundle;
    use crate::adapters::repository::InMemoryAssets;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";
    const ENGAGEMENT: &str = "e0000001-0000-0000-0000-000000000000";

    fn bundle() -> AssetBulkImportBundle {
        let store = Arc::new(InMemoryAssets::default());
        let write = AssetWriteBundle::build(Arc::clone(&store));
        AssetBulkImportBundle::build(Arc::clone(&write.write))
    }

    fn good_json() -> String {
        format!(
            r#"[
                {{"engagement_id":"{ENGAGEMENT}","kind":"host","identifier":"a.example","source":"import"}},
                {{"engagement_id":"{ENGAGEMENT}","kind":"host","identifier":"b.example","source":"import"}}
            ]"#
        )
    }

    fn good_csv() -> String {
        format!(
            "engagement_id,kind,identifier,source\n{ENGAGEMENT},host,a.example,import\n{ENGAGEMENT},host,b.example,import\n"
        )
    }

    #[tokio::test]
    async fn json_happy_path_creates_two_assets() {
        let b = bundle();
        let req = BulkImportRequest {
            format: "json".into(),
            body: good_json(),
        };
        let resp = b.bulk.import(TENANT, req).await.expect("import ok");
        assert_eq!(resp.created, 2);
        assert_eq!(resp.skipped, 0);
        assert!(resp.errors.is_empty());
    }

    #[tokio::test]
    async fn csv_happy_path_creates_two_assets() {
        let b = bundle();
        let req = BulkImportRequest {
            format: "csv".into(),
            body: good_csv(),
        };
        let resp = b.bulk.import(TENANT, req).await.expect("import ok");
        assert_eq!(resp.created, 2);
        assert_eq!(resp.skipped, 0);
        assert!(resp.errors.is_empty());
    }

    #[tokio::test]
    async fn csv_quoted_fields_are_honoured() {
        let b = bundle();
        // Quote the identifier so it can carry a comma without
        // confusing the parser.
        let body = format!(
            "engagement_id,kind,identifier,source\n{ENGAGEMENT},host,\"a, quoted.example\",import\n"
        );
        let req = BulkImportRequest {
            format: "csv".into(),
            body,
        };
        let resp = b.bulk.import(TENANT, req).await.expect("import ok");
        assert_eq!(resp.created, 1);
        assert_eq!(resp.skipped, 0);
        assert!(resp.errors.is_empty());
    }

    #[tokio::test]
    async fn row_cap_rejects_over_1000_rows() {
        let b = bundle();
        let mut rows = Vec::with_capacity(BULK_IMPORT_MAX_ROWS + 1);
        for i in 0..=BULK_IMPORT_MAX_ROWS {
            rows.push(format!(
                r#"{{"engagement_id":"{ENGAGEMENT}","kind":"host","identifier":"h-{i}.example","source":"import"}}"#
            ));
        }
        let body = format!("[{}]", rows.join(","));
        let req = BulkImportRequest {
            format: "json".into(),
            body,
        };
        let err = b.bulk.import(TENANT, req).await.expect_err("must reject");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn malformed_json_returns_invalid() {
        let b = bundle();
        let req = BulkImportRequest {
            format: "json".into(),
            body: "{not json".into(),
        };
        let err = b.bulk.import(TENANT, req).await.expect_err("must reject");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn malformed_csv_header_returns_invalid() {
        let b = bundle();
        let req = BulkImportRequest {
            format: "csv".into(),
            body: "wrong,header,here,now\n".into(),
        };
        let err = b.bulk.import(TENANT, req).await.expect_err("must reject");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn duplicate_row_counts_as_skipped() {
        let b = bundle();
        let body = format!(
            r#"[
                {{"engagement_id":"{ENGAGEMENT}","kind":"host","identifier":"dup.example","source":"import"}},
                {{"engagement_id":"{ENGAGEMENT}","kind":"host","identifier":"dup.example","source":"import"}}
            ]"#
        );
        let req = BulkImportRequest {
            format: "json".into(),
            body,
        };
        let resp = b.bulk.import(TENANT, req).await.expect("import ok");
        assert_eq!(resp.created, 1);
        assert_eq!(resp.skipped, 1);
        assert!(resp.errors.is_empty());
    }

    #[tokio::test]
    async fn invalid_row_records_per_row_error() {
        let b = bundle();
        // Second row has an unknown kind — validation rejects it as a
        // per-row error while the first row is still created.
        let body = format!(
            r#"[
                {{"engagement_id":"{ENGAGEMENT}","kind":"host","identifier":"a.example","source":"import"}},
                {{"engagement_id":"{ENGAGEMENT}","kind":"spaceship","identifier":"b.example","source":"import"}}
            ]"#
        );
        let req = BulkImportRequest {
            format: "json".into(),
            body,
        };
        let resp = b.bulk.import(TENANT, req).await.expect("import ok");
        assert_eq!(resp.created, 1);
        assert_eq!(resp.skipped, 0);
        assert_eq!(resp.errors.len(), 1);
        let first = resp.errors.first().expect("one error recorded");
        assert_eq!(first.row, 1);
        assert!(first.message.contains("kind"));
    }

    #[tokio::test]
    async fn unsupported_format_returns_invalid() {
        let b = bundle();
        let req = BulkImportRequest {
            format: "yaml".into(),
            body: "x".into(),
        };
        let err = b.bulk.import(TENANT, req).await.expect_err("must reject");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }
}
