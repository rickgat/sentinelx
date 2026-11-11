//! Scan DTOs — backs `POST /v1/scans/http-headers` and `GET /v1/scans`.
//!
//! The HTTP-header scanner produces light-weight, self-contained findings
//! that are NOT persisted into the main finding repository (those rows
//! belong to engagement-bound scanners like grype). Scan-derived findings
//! live inside the scan record itself so the dashboard can render the
//! audit trail without polluting the finding stream.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/scans/http-headers` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct HttpHeaderScanRequest {
    /// FQDN or full URL to probe. The scanner prepends `https://` if the
    /// caller passed a bare host. Strict allow-list: `a-zA-Z0-9.-:/` only.
    #[validate(length(min = 4, max = 512))]
    #[validate(custom(function = "validate_target"))]
    pub target: String,

    /// Optional engagement uuid to bind the scan to. Surfaces in the
    /// `/dashboard/engagements/{id}` detail page once the SSR renders it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_optional_uuid"))]
    pub engagement_id: Option<String>,
}

/// One scan finding embedded in [`ScanRecord::findings`].
///
/// Carries the same enrichment surface as
/// [`sx_core::entity::finding::Finding`] (CVSS v3.1 / CWE / MITRE
/// ATT&CK / compliance / confidence) so the `/v1/scans/http-headers`
/// response is procurement-grade — auditors and SOC pipelines can
/// consume the wire payload directly without re-keying findings into a
/// secondary enrichment store. Empty fields serialise as omitted JSON
/// keys via `skip_serializing_if`, keeping legacy clients compatible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanFinding {
    /// Stable check identifier (e.g. `HDR.STRICT_TRANSPORT_SECURITY.MISSING`).
    pub check_id: String,
    /// `info | low | medium | high | critical`.
    pub severity: String,
    /// Short title shown in tables.
    pub title: String,
    /// Long-form explanation.
    pub description: String,
    /// Optional remediation hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,

    // ----- enrichment payload (SX-REVIEW-002 C1 fix) ---------------------
    /// CVSS v3.1 base metric payload, if the emitter looked one up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<sx_core::value_object::cvss_v31::CvssV31>,
    /// CWE identifiers describing the underlying weakness class(es).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<sx_core::value_object::cwe::CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this finding maps to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_attack: Vec<sx_core::value_object::mitre_attack::MitreAttackTechnique>,
    /// Compliance-framework control mappings (NIST 800-53 / ISO 27001
    /// / PCI DSS / SOC 2 / HIPAA).
    #[serde(
        default,
        skip_serializing_if = "sx_core::value_object::compliance::ComplianceTags::is_empty"
    )]
    pub compliance: sx_core::value_object::compliance::ComplianceTags,
    /// Emitter-provided confidence in `0.0..=1.0` (1.0 = certain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    // ----- source-aware location (TOP5-#3 Phase 3) -----------------------
    /// Optional 1-indexed source line for line-oriented emitters (DLP
    /// scanning a config file, YAML/TOML/JSON audits). Maps onto
    /// SARIF `runs[].results[].locations[].physicalLocation.region.startLine`
    /// via [`crate::controller::scan::scan_finding_to_finding`]. Non-source
    /// scanners leave it `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Optional 1-indexed source column, paired with [`Self::line`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// One scan history entry on the wire.
//
// `Eq` is intentionally NOT derived: the enriched [`ScanFinding`]
// carries a [`sx_core::value_object::cvss_v31::CvssV31`] payload
// containing an `f64` base score that only implements `PartialEq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanRecord {
    /// Scan uuid.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Scan family — currently always `http_headers`. Reserved for future
    /// scan types (`tls`, `dns`, …) without changing the wire shape.
    pub kind: String,
    /// Target probed (normalised to `https://<host>`).
    pub target: String,
    /// Optional engagement context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_id: Option<String>,
    /// RFC 3339 start timestamp.
    pub started_at: String,
    /// RFC 3339 finish timestamp.
    pub finished_at: String,
    /// `ok | error`.
    pub status: String,
    /// Free-form error reason when `status = error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Findings produced by this scan, ordered by severity desc.
    pub findings: Vec<ScanFinding>,
}

/// `GET /v1/scans` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListScansResponse {
    /// Scan records matching the query, newest-first.
    pub items: Vec<ScanRecord>,
}

/// Lightweight character-set gate for scan targets — refuses control
/// characters / whitespace and reserves further validation (SSRF
/// guard, scheme allow-list, DNS-resolved IP policy) to
/// `sx_core::reference::url_guard::validate_scan_target`.
///
/// QC-RERUN-2026-06-25 fix: previously rejected `[`, `]`, `%`, `_`
/// which made the SSRF guard's IPv6 branches (Loopback / LinkLocal /
/// CloudMetadata) unreachable AND blocked legitimate RFC 4193
/// IPv6-ULA internal scanning. Char-set now includes every byte
/// legal in an RFC 3986 URI (unreserved + sub-delims + gen-delims +
/// percent-encoding). Inline so the crate avoids a `regex` dependency.
fn validate_target(value: &str) -> Result<(), validator::ValidationError> {
    let ok = !value.is_empty()
        && value.len() <= 2048
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    // RFC 3986 unreserved
                    '-' | '.' | '_' | '~'
                    // RFC 3986 gen-delims (URL structural)
                    | ':' | '/' | '?' | '#' | '[' | ']' | '@'
                    // RFC 3986 sub-delims (auth + query)
                    | '!' | '$' | '&' | '\'' | '(' | ')'
                    | '*' | '+' | ',' | ';' | '='
                    // RFC 3986 percent-encoding marker
                    | '%'
                )
        });
    if ok {
        Ok(())
    } else {
        Err(validator::ValidationError::new("invalid_target"))
    }
}

fn validate_optional_uuid(value: &str) -> Result<(), validator::ValidationError> {
    if value.is_empty() {
        return Ok(());
    }
    uuid::Uuid::parse_str(value).map_err(|_| validator::ValidationError::new("invalid_uuid"))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn target_validator_accepts_fqdn() {
        let req = HttpHeaderScanRequest {
            target: "example.com".into(),
            engagement_id: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn target_validator_accepts_full_url() {
        let req = HttpHeaderScanRequest {
            target: "https://example.com/path".into(),
            engagement_id: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn target_validator_rejects_dangerous_chars() {
        let req = HttpHeaderScanRequest {
            target: "evil.com<script>".into(),
            engagement_id: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn engagement_id_accepts_uuid() {
        let req = HttpHeaderScanRequest {
            target: "x.test".into(),
            engagement_id: Some("019eba39-ee0b-71f0-9c9b-a21c2527dd30".into()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn engagement_id_rejects_garbage() {
        let req = HttpHeaderScanRequest {
            target: "x.test".into(),
            engagement_id: Some("not-a-uuid".into()),
        };
        assert!(req.validate().is_err());
    }
}
