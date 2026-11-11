//! Asset DTOs.

use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

/// Asset projection on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetView {
    /// Asset uuid.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Engagement uuid.
    pub engagement_id: String,
    /// Asset kind (`host`, `domain`, `url`, …).
    pub kind: String,
    /// Canonical identifier (e.g. `example.com`).
    pub identifier: String,
    /// Discovery source (`scan`, `manual`, `import`).
    pub source: String,
    /// First-seen timestamp.
    pub first_seen: String,
    /// Last-seen timestamp.
    pub last_seen: String,
    /// Business criticality classification.
    ///
    /// Values are the snake-case [`Display`] form of
    /// [`sx_core::value_object::criticality::AssetCriticality`]:
    /// `"unknown"`, `"dev"`, `"staging"`, `"production"`, `"crown_jewel"`.
    /// Use
    /// [`sx_core::value_object::criticality::parse_criticality`] for a
    /// tolerant parse (case-insensitive, accepts a few common aliases).
    ///
    /// `None` means the underlying row pre-dates the column or carried a
    /// value the adapter could not recognise; downstream consumers should
    /// treat this as "unknown" and fall back to whatever default their
    /// scoring rules dictate.
    ///
    /// [`Display`]: std::fmt::Display
    pub criticality: Option<String>,
}

/// Canonical set of accepted asset kinds.
///
/// The HTTP surface refuses anything outside this list at the validator
/// boundary so downstream adapters never have to second-guess the input.
pub const ASSET_KINDS: &[&str] = &[
    "host",
    "domain",
    "url",
    "bucket",
    "container",
    "identity",
    "repo",
];

/// Canonical set of accepted discovery sources.
pub const ASSET_SOURCES: &[&str] = &["scan", "manual", "import"];

/// `POST /v1/assets` request body.
///
/// `kind` must be one of [`ASSET_KINDS`]; `source` must be one of
/// [`ASSET_SOURCES`]; `identifier` must be non-empty and bounded by 512
/// bytes. The `engagement_id` is validated for canonical UUID shape so the
/// adapter never has to.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CreateAssetRequest {
    /// Engagement the new asset belongs to.
    #[validate(custom(function = "validate_uuid"))]
    pub engagement_id: String,
    /// Asset kind — one of [`ASSET_KINDS`].
    #[validate(custom(function = "validate_kind"))]
    pub kind: String,
    /// Canonical identifier (e.g. `example.com`).
    #[validate(length(min = 1, max = 512))]
    pub identifier: String,
    /// Discovery source — one of [`ASSET_SOURCES`].
    #[validate(custom(function = "validate_source"))]
    pub source: String,
}

/// `PATCH /v1/assets/{id}` request body.
///
/// Every field is optional; the adapter preserves whatever is not supplied.
#[derive(Debug, Clone, Deserialize, Serialize, Validate, Default)]
pub struct UpdateAssetRequest {
    /// New kind — one of [`ASSET_KINDS`] when present.
    #[validate(custom(function = "validate_kind_opt"))]
    pub kind: Option<String>,
    /// New identifier (non-empty, bounded by 512 bytes) when present.
    #[validate(length(min = 1, max = 512))]
    pub identifier: Option<String>,
    /// New discovery source — one of [`ASSET_SOURCES`] when present.
    #[validate(custom(function = "validate_source_opt"))]
    pub source: Option<String>,
}

/// Custom validator — `kind` must be one of [`ASSET_KINDS`].
fn validate_kind(value: &str) -> Result<(), ValidationError> {
    if ASSET_KINDS.contains(&value) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_kind"))
    }
}

/// Custom validator — same as [`validate_kind`] but for the optional form.
fn validate_kind_opt(value: &str) -> Result<(), ValidationError> {
    validate_kind(value)
}

/// Custom validator — `source` must be one of [`ASSET_SOURCES`].
fn validate_source(value: &str) -> Result<(), ValidationError> {
    if ASSET_SOURCES.contains(&value) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_source"))
    }
}

/// Custom validator — same as [`validate_source`] but for the optional form.
fn validate_source_opt(value: &str) -> Result<(), ValidationError> {
    validate_source(value)
}

/// Validate that `value` is a canonical UUID string.
fn validate_uuid(value: &str) -> Result<(), ValidationError> {
    uuid::Uuid::parse_str(value).map_err(|_| ValidationError::new("invalid_uuid"))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn engagement_uuid() -> String {
        "00000000-0000-0000-0000-000000000001".to_owned()
    }

    #[test]
    fn create_request_accepts_canonical_input() {
        let r = CreateAssetRequest {
            engagement_id: engagement_uuid(),
            kind: "host".into(),
            identifier: "api.example.com".into(),
            source: "scan".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn create_request_rejects_unknown_kind() {
        let r = CreateAssetRequest {
            engagement_id: engagement_uuid(),
            kind: "spaceship".into(),
            identifier: "x".into(),
            source: "scan".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_empty_identifier() {
        let r = CreateAssetRequest {
            engagement_id: engagement_uuid(),
            kind: "host".into(),
            identifier: String::new(),
            source: "scan".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_oversized_identifier() {
        let r = CreateAssetRequest {
            engagement_id: engagement_uuid(),
            kind: "host".into(),
            identifier: "x".repeat(513),
            source: "scan".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_unknown_source() {
        let r = CreateAssetRequest {
            engagement_id: engagement_uuid(),
            kind: "host".into(),
            identifier: "x".into(),
            source: "telepathy".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn create_request_rejects_non_uuid_engagement_id() {
        let r = CreateAssetRequest {
            engagement_id: "not-a-uuid".into(),
            kind: "host".into(),
            identifier: "x".into(),
            source: "scan".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn update_request_all_none_is_valid() {
        let r = UpdateAssetRequest::default();
        assert!(r.validate().is_ok());
    }

    #[test]
    fn update_request_rejects_unknown_kind() {
        let r = UpdateAssetRequest {
            kind: Some("spaceship".into()),
            identifier: None,
            source: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn update_request_rejects_unknown_source() {
        let r = UpdateAssetRequest {
            kind: None,
            identifier: None,
            source: Some("telepathy".into()),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn update_request_rejects_empty_identifier() {
        let r = UpdateAssetRequest {
            kind: None,
            identifier: Some(String::new()),
            source: None,
        };
        assert!(r.validate().is_err());
    }
}

// ---------------------------------------------------------------------------
// Bulk import — `POST /v1/assets/bulk-import`
// ---------------------------------------------------------------------------

/// Hard upper bound on the request body byte length accepted by the bulk
/// import endpoint. Matches the documented 5 MiB cap.
pub const BULK_IMPORT_MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Hard upper bound on the number of rows the bulk-import adapter will
/// iterate before short-circuiting with an error. Matches the documented
/// 1000-row cap.
pub const BULK_IMPORT_MAX_ROWS: usize = 1_000;

/// `POST /v1/assets/bulk-import` request body.
///
/// Carries the asset payload inline rather than as a multipart upload so the
/// regular JSON body limit + tenant rate-limit middleware applies. `format`
/// MUST be one of `"json"` or `"csv"` (case-insensitive at the adapter
/// boundary). `body` MUST be no larger than
/// [`BULK_IMPORT_MAX_BODY_BYTES`].
///
/// ## JSON grammar
///
/// A JSON array of objects, each carrying the same fields as
/// [`CreateAssetRequest`]:
///
/// ```json
/// [
///   {
///     "engagement_id": "00000000-0000-0000-0000-000000000001",
///     "kind": "host",
///     "identifier": "api.example.com",
///     "source": "import"
///   }
/// ]
/// ```
///
/// ## CSV grammar
///
/// RFC 4180-flavoured CSV with a leading header row. The header MUST be
/// exactly `engagement_id,kind,identifier,source` (order matters); the
/// adapter rejects any other header. Quoted fields are honoured (the
/// underlying `csv` crate handles RFC 4180 quoting).
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BulkImportRequest {
    /// Wire format — `"json"` or `"csv"`.
    #[validate(custom(function = "validate_bulk_format"))]
    pub format: String,
    /// Request body, capped at [`BULK_IMPORT_MAX_BODY_BYTES`].
    #[validate(custom(function = "validate_bulk_body"))]
    pub body: String,
}

/// `POST /v1/assets/bulk-import` response body.
///
/// `created` counts assets the adapter persisted successfully; `skipped`
/// counts rows that surfaced as duplicates of an existing
/// `(engagement_id, identifier)` pair; `errors` carries one entry per row
/// that failed validation or any other non-duplicate failure.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BulkImportResponse {
    /// Number of rows that produced a fresh asset row.
    pub created: u32,
    /// Number of rows skipped because the asset already exists.
    pub skipped: u32,
    /// Per-row errors. The `row` index is zero-based and excludes the CSV
    /// header (if any).
    pub errors: Vec<BulkImportError>,
}

/// One per-row error inside a [`BulkImportResponse`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BulkImportError {
    /// Zero-based row index within the input payload.
    pub row: u32,
    /// Human-readable reason. Safe to surface to operators.
    pub message: String,
}

/// Custom validator — `format` must be one of `"json"` / `"csv"`
/// (case-insensitive).
fn validate_bulk_format(value: &str) -> Result<(), ValidationError> {
    if value.eq_ignore_ascii_case("json") || value.eq_ignore_ascii_case("csv") {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_format"))
    }
}

/// Custom validator — body must be non-empty and at most
/// [`BULK_IMPORT_MAX_BODY_BYTES`] bytes.
fn validate_bulk_body(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("empty_body"));
    }
    if value.len() > BULK_IMPORT_MAX_BODY_BYTES {
        return Err(ValidationError::new("body_too_large"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod bulk_tests {
    use super::*;

    #[test]
    fn bulk_request_accepts_json_format() {
        let r = BulkImportRequest {
            format: "json".into(),
            body: "[]".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn bulk_request_accepts_csv_format() {
        let r = BulkImportRequest {
            format: "csv".into(),
            body: "engagement_id,kind,identifier,source\n".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn bulk_request_rejects_unknown_format() {
        let r = BulkImportRequest {
            format: "xml".into(),
            body: "<assets/>".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn bulk_request_rejects_empty_body() {
        let r = BulkImportRequest {
            format: "json".into(),
            body: String::new(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn bulk_request_rejects_oversize_body() {
        let r = BulkImportRequest {
            format: "json".into(),
            body: "a".repeat(BULK_IMPORT_MAX_BODY_BYTES + 1),
        };
        assert!(r.validate().is_err());
    }
}
