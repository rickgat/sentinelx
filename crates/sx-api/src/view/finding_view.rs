//! Finding DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Finding projection on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingView {
    /// Finding uuid.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Asset uuid the finding is bound to.
    pub asset_id: String,
    /// Severity (`info`, `low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// Status (`open`, `triaged`, `accepted`, `closed`).
    pub status: String,
    /// Short title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// CVSS base score (0.0–10.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f64>,
    /// Optional CVE identifier linked to the finding (e.g. `CVE-2024-1234`).
    ///
    /// Defaults to `None` for backward compatibility with finding rows
    /// minted before Phase-3.5 (when CVE linkage was added). Consumers that
    /// need the canonical CVSS envelope should resolve the id through the
    /// NVD-backed `CveLookup` port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    /// First-seen timestamp.
    pub first_seen: String,
    /// Last-seen timestamp.
    pub last_seen: String,
    /// Optional structured metadata (JSON object). Carries fields like
    /// `business_impact` and `chain_amplifier` that downstream risk
    /// calculation reads. `None` when no row-level metadata exists.
    ///
    /// Added in Phase-3.5+2 — fully optional and backward-compatible with
    /// rows minted before the field existed (the `#[serde(default)]` keeps
    /// older payloads deserialising cleanly).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Patch-status request body.
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateFindingStatusView {
    /// New status: `open`, `triaged`, `accepted`, or `closed`.
    #[validate(custom(function = "validate_status"))]
    pub status: String,
    /// Optional comment recorded on the audit log.
    #[validate(length(max = 2_000))]
    pub comment: Option<String>,
}

fn validate_status(v: &str) -> Result<(), validator::ValidationError> {
    match v {
        "open" | "triaged" | "accepted" | "closed" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_status")),
    }
}

/// Hard cap on the number of finding ids
/// [`BulkUpdateFindingsRequest::ids`] will accept in a single call.
///
/// Bulk operations are CPU-bound (per-id repository writes plus an
/// audit-trail emit) so the API caps payload size to keep individual
/// requests bounded. Callers needing larger updates must page.
pub const MAX_BULK_IDS: usize = 500;

/// Hard cap on the number of rows
/// [`crate::port::FindingBulkPort::export`] will stream per response.
///
/// Mirrors [`crate::view::audit_view::MAX_EXPORT_ENTRIES`] but sized for
/// the finding read surface — at 100k rows a CSV body is still
/// comfortably under 50 MiB and an NDJSON body fits within tower-http's
/// default response-body limit. Operators needing a full snapshot must
/// page by advancing `since`.
pub const MAX_EXPORT_ROWS: usize = 100_000;

/// `POST /v1/findings/bulk-update` request body.
///
/// All ids are updated to the same `status` under the caller's tenant.
/// A single `comment` is recorded on every affected row's audit trail.
///
/// ## Wire shape
///
/// ```json
/// {
///   "ids": ["f0000001-0000-0000-0000-000000000000", "..."],
///   "status": "triaged",
///   "comment": "batched by SOC playbook A-12"
/// }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BulkUpdateFindingsRequest {
    /// Finding ids to update. Bounded by [`MAX_BULK_IDS`] to keep the
    /// request CPU-bounded.
    #[validate(length(min = 1, max = 500))]
    pub ids: Vec<String>,
    /// New status: `open`, `triaged`, `accepted`, or `closed`.
    #[validate(custom(function = "validate_status"))]
    pub status: String,
    /// Optional audit comment recorded on every affected row.
    #[validate(length(max = 2_000))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// `POST /v1/findings/bulk-update` response body.
///
/// `updated` / `failed` are reported separately so the caller can act on
/// a partially-successful batch. Per-id failures (not-found, conflict,
/// dependency) appear in [`Self::errors`] keyed by the offending id.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BulkUpdateResponse {
    /// Count of rows that landed the new status.
    pub updated: u32,
    /// Count of rows that did NOT land — see [`Self::errors`] for details.
    pub failed: u32,
    /// Per-id failure breakdown. Empty when every row updated cleanly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<BulkUpdateError>,
}

/// One per-id failure recorded inside [`BulkUpdateResponse`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BulkUpdateError {
    /// Finding id that failed.
    pub id: String,
    /// Human-readable reason — operator-only, never sensitive.
    pub message: String,
}

/// `GET /v1/findings/export?format=...&since=...` query string.
///
/// `format` defaults to `ndjson` when absent. The controller validates
/// the value against the accepted set (`ndjson`, `csv`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FindingExportQuery {
    /// Export format. `ndjson` (default) or `csv`.
    #[serde(default)]
    pub format: Option<String>,
    /// Lower-bound RFC 3339 timestamp (inclusive) matched against
    /// [`FindingView::last_seen`]. Optional.
    #[serde(default)]
    pub since: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn status_accepted_values() {
        for s in ["open", "triaged", "accepted", "closed"] {
            let v = UpdateFindingStatusView {
                status: s.into(),
                comment: None,
            };
            assert!(v.validate().is_ok(), "{s}");
        }
    }

    #[test]
    fn status_rejected_values() {
        let v = UpdateFindingStatusView {
            status: "deleted".into(),
            comment: None,
        };
        assert!(v.validate().is_err());
    }

    fn base_finding() -> FindingView {
        FindingView {
            id: "f0000001-0000-0000-0000-000000000000".into(),
            tenant_id: "01010101-0101-0101-0101-010101010101".into(),
            asset_id: "a0000001-0000-0000-0000-000000000000".into(),
            severity: "high".into(),
            status: "open".into(),
            title: "demo".into(),
            description: "demo finding".into(),
            cvss: None,
            cve_id: None,
            first_seen: "2026-05-15T00:00:00Z".into(),
            last_seen: "2026-05-29T00:00:00Z".into(),
            metadata: None,
        }
    }

    #[test]
    fn metadata_round_trips_when_set() {
        let mut view = base_finding();
        view.metadata = Some(serde_json::json!({
            "business_impact": 3.5,
            "chain_amplifier": 1.5,
        }));
        let wire = serde_json::to_string(&view).unwrap();
        let decoded: FindingView = serde_json::from_str(&wire).unwrap();
        let meta = decoded.metadata.expect("metadata round-trips");
        assert_eq!(
            meta.get("business_impact")
                .and_then(serde_json::Value::as_f64),
            Some(3.5)
        );
        assert_eq!(
            meta.get("chain_amplifier")
                .and_then(serde_json::Value::as_f64),
            Some(1.5)
        );
    }

    #[test]
    fn metadata_omitted_when_none() {
        let view = base_finding();
        let wire = serde_json::to_string(&view).unwrap();
        assert!(
            !wire.contains("\"metadata\""),
            "serialized payload must skip the metadata key when None, got: {wire}",
        );
    }

    #[test]
    fn metadata_parses_business_impact_factor_from_json() {
        // Backward-compatibility check: a payload that omits `metadata`
        // entirely (older row shape) still decodes cleanly.
        let payload = r#"{
            "id":"f0000001-0000-0000-0000-000000000000",
            "tenant_id":"01010101-0101-0101-0101-010101010101",
            "asset_id":"a0000001-0000-0000-0000-000000000000",
            "severity":"critical",
            "status":"open",
            "title":"t",
            "description":"d",
            "first_seen":"2026-05-15T00:00:00Z",
            "last_seen":"2026-05-29T00:00:00Z",
            "metadata":{"business_impact":4.2,"chain_amplifier":2.0}
        }"#;
        let decoded: FindingView = serde_json::from_str(payload).unwrap();
        let meta = decoded.metadata.expect("metadata present");
        assert_eq!(
            meta.get("business_impact")
                .and_then(serde_json::Value::as_f64),
            Some(4.2)
        );
        assert_eq!(
            meta.get("chain_amplifier")
                .and_then(serde_json::Value::as_f64),
            Some(2.0)
        );

        // And: the same payload with metadata omitted decodes too.
        let payload_no_meta = r#"{
            "id":"f0000001-0000-0000-0000-000000000000",
            "tenant_id":"01010101-0101-0101-0101-010101010101",
            "asset_id":"a0000001-0000-0000-0000-000000000000",
            "severity":"critical",
            "status":"open",
            "title":"t",
            "description":"d",
            "first_seen":"2026-05-15T00:00:00Z",
            "last_seen":"2026-05-29T00:00:00Z"
        }"#;
        let decoded_no_meta: FindingView = serde_json::from_str(payload_no_meta).unwrap();
        assert!(decoded_no_meta.metadata.is_none());
    }

    fn make_ids(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("f0000000-0000-0000-0000-{i:012}"))
            .collect()
    }

    #[test]
    fn bulk_update_request_rejects_empty_ids() {
        let req = BulkUpdateFindingsRequest {
            ids: vec![],
            status: "open".into(),
            comment: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn bulk_update_request_rejects_too_many_ids() {
        let req = BulkUpdateFindingsRequest {
            ids: make_ids(MAX_BULK_IDS + 1),
            status: "open".into(),
            comment: None,
        };
        assert!(
            req.validate().is_err(),
            "{} ids should exceed cap",
            req.ids.len()
        );
    }

    #[test]
    fn bulk_update_request_accepts_capped_ids() {
        let req = BulkUpdateFindingsRequest {
            ids: make_ids(MAX_BULK_IDS),
            status: "triaged".into(),
            comment: Some("playbook".into()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn bulk_update_request_rejects_invalid_status() {
        let req = BulkUpdateFindingsRequest {
            ids: make_ids(1),
            status: "deleted".into(),
            comment: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn bulk_update_response_omits_empty_errors() {
        let v = BulkUpdateResponse {
            updated: 3,
            failed: 0,
            errors: Vec::new(),
        };
        let wire = serde_json::to_string(&v).unwrap();
        assert!(
            !wire.contains("\"errors\""),
            "empty errors must be skipped: {wire}",
        );
    }

    fn remediation_pr_only() -> RemediationLinkRequest {
        RemediationLinkRequest {
            pr_url: Some("https://github.com/acme/widgets/pull/42".into()),
            ticket_url: None,
            comment: Some("auto-patch".into()),
        }
    }

    fn remediation_ticket_only() -> RemediationLinkRequest {
        RemediationLinkRequest {
            pr_url: None,
            ticket_url: Some("https://acme.atlassian.net/browse/SEC-91".into()),
            comment: None,
        }
    }

    #[test]
    fn remediation_pr_url_only_passes_validation() {
        let req = remediation_pr_only();
        assert!(req.validate().is_ok());
        assert!(req.require_at_least_one_url().is_ok());
    }

    #[test]
    fn remediation_ticket_url_only_passes_validation() {
        let req = remediation_ticket_only();
        assert!(req.validate().is_ok());
        assert!(req.require_at_least_one_url().is_ok());
    }

    #[test]
    fn remediation_comment_only_is_rejected_at_struct_level() {
        let req = RemediationLinkRequest {
            pr_url: None,
            ticket_url: None,
            comment: Some("just a note".into()),
        };
        // Field-level `validate()` is satisfied (no URLs to check) but the
        // cross-field guard refuses the payload.
        assert!(req.validate().is_ok());
        assert!(req.require_at_least_one_url().is_err());
    }

    #[test]
    fn remediation_non_https_pr_url_is_rejected() {
        let req = RemediationLinkRequest {
            pr_url: Some("http://github.com/acme/widgets/pull/1".into()),
            ticket_url: None,
            comment: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn remediation_unknown_pr_host_is_rejected() {
        let req = RemediationLinkRequest {
            pr_url: Some("https://bitbucket.org/acme/widgets/pull-requests/1".into()),
            ticket_url: None,
            comment: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn remediation_ticket_url_without_known_marker_is_rejected() {
        let req = RemediationLinkRequest {
            pr_url: None,
            ticket_url: Some("https://acme.atlassian.net/some/other/path".into()),
            comment: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn remediation_link_view_round_trips() {
        let view = RemediationLinkView {
            pr_url: Some("https://gitlab.com/acme/widgets/-/merge_requests/7".into()),
            ticket_url: None,
            comment: Some("fix landed".into()),
            linked_at: "2026-05-31T00:00:00Z".into(),
            linked_by: "u-1".into(),
        };
        let wire = serde_json::to_string(&view).unwrap();
        let decoded: RemediationLinkView = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded.pr_url.as_deref(), view.pr_url.as_deref());
        assert!(decoded.ticket_url.is_none());
        assert_eq!(decoded.linked_by, "u-1");
    }
}

// ---------------------------------------------------------------------------
// Remediation-link DTOs (PATCH/DELETE /v1/findings/{id}/remediation)
// ---------------------------------------------------------------------------

/// Allow-listed hosts for `pr_url`.
///
/// Only canonical GitHub / GitLab hosted code-review URLs are accepted. The
/// allow-list is intentionally tight so adapters never have to deal with
/// arbitrary upstream hosts — operators can always paste an additional
/// link into the `comment` field if they need to reference something else.
pub const REMEDIATION_PR_HOSTS: &[&str] = &["github.com", "gitlab.com"];

/// Path-substring markers an accepted `ticket_url` must contain.
///
/// - `/browse/` — Atlassian Jira issue links (e.g. `/browse/SEC-12`).
/// - `/issues/` — GitHub-style issue links (e.g. `/acme/widgets/issues/42`).
pub const REMEDIATION_TICKET_MARKERS: &[&str] = &["/browse/", "/issues/"];

/// `PATCH /v1/findings/{id}/remediation` request body.
///
/// At least one of `pr_url` / `ticket_url` MUST be provided — a payload that
/// carries only `comment` is refused at the controller boundary via
/// [`RemediationLinkRequest::require_at_least_one_url`]. URL fields are
/// individually validated to be HTTPS and to point at a known host /
/// marker; see [`REMEDIATION_PR_HOSTS`] and [`REMEDIATION_TICKET_MARKERS`].
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct RemediationLinkRequest {
    /// Pull / merge request URL. Must be HTTPS and host one of
    /// [`REMEDIATION_PR_HOSTS`].
    #[validate(custom(function = "validate_pr_url_opt"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_url: Option<String>,
    /// Issue / ticket URL. Must be HTTPS and contain one of
    /// [`REMEDIATION_TICKET_MARKERS`] in its path.
    #[validate(custom(function = "validate_ticket_url_opt"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_url: Option<String>,
    /// Free-form operator comment recorded alongside the link
    /// (audit-trail input). Capped to keep the audit row small.
    #[validate(length(max = 2_000))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl RemediationLinkRequest {
    /// Refuse a payload that omits both URLs.
    ///
    /// Field-level validation already covers shape; this is the cross-field
    /// guard the controller runs immediately after `ValidatedJson` returns.
    ///
    /// # Errors
    ///
    /// Returns `Err` when `pr_url` and `ticket_url` are both `None` (a
    /// comment-only payload).
    pub fn require_at_least_one_url(&self) -> Result<(), validator::ValidationError> {
        if self.pr_url.is_none() && self.ticket_url.is_none() {
            let mut e = validator::ValidationError::new("missing_url");
            e.message = Some(std::borrow::Cow::Borrowed(
                "at least one of pr_url or ticket_url is required",
            ));
            return Err(e);
        }
        Ok(())
    }
}

/// `RemediationLinkView` — projection returned on PATCH success.
///
/// `linked_at` is an RFC 3339 timestamp; `linked_by` is the caller's user id
/// (`sub` from the access claims). The view shape is intentionally narrow
/// so a future Postgres-backed adapter does not need to grow new columns.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RemediationLinkView {
    /// PR / MR URL persisted with the link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_url: Option<String>,
    /// Ticket URL persisted with the link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_url: Option<String>,
    /// Operator comment persisted with the link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// RFC 3339 timestamp the link was recorded.
    pub linked_at: String,
    /// User id that recorded the link.
    pub linked_by: String,
}

/// Validate `pr_url` when present: scheme=https, host in [`REMEDIATION_PR_HOSTS`].
fn validate_pr_url_opt(value: &str) -> Result<(), validator::ValidationError> {
    validate_https_with_host(value, REMEDIATION_PR_HOSTS).map_err(|code| {
        let mut e = validator::ValidationError::new(code);
        e.message = Some(std::borrow::Cow::Borrowed(
            "pr_url must be https://github.com/... or https://gitlab.com/...",
        ));
        e
    })
}

/// Validate `ticket_url` when present: scheme=https, path contains one of
/// [`REMEDIATION_TICKET_MARKERS`].
fn validate_ticket_url_opt(value: &str) -> Result<(), validator::ValidationError> {
    if let Err(code) = validate_https_scheme(value) {
        let mut e = validator::ValidationError::new(code);
        e.message = Some(std::borrow::Cow::Borrowed("ticket_url must use https://"));
        return Err(e);
    }
    let path = path_after_authority(value);
    if !REMEDIATION_TICKET_MARKERS.iter().any(|m| path.contains(m)) {
        let mut e = validator::ValidationError::new("invalid_ticket_marker");
        e.message = Some(std::borrow::Cow::Borrowed(
            "ticket_url must contain /browse/ (Jira) or /issues/ (GitHub) in its path",
        ));
        return Err(e);
    }
    Ok(())
}

/// Helper: enforce https scheme and an explicit host membership.
fn validate_https_with_host(value: &str, hosts: &[&str]) -> Result<(), &'static str> {
    validate_https_scheme(value)?;
    let host = host_from_url(value).ok_or("invalid_host")?;
    if hosts.iter().any(|h| host.eq_ignore_ascii_case(h)) {
        Ok(())
    } else {
        Err("invalid_host")
    }
}

/// Helper: refuse anything that doesn't start with `https://`.
///
/// The scheme test is ASCII-case-insensitive but the rest of the URL is
/// left verbatim — the host / marker checks downstream are
/// ASCII-case-insensitive too, so input like `HTTPS://github.com/...`
/// passes here and is normalised at comparison time.
fn validate_https_scheme(value: &str) -> Result<(), &'static str> {
    let prefix = "https://";
    if value.len() < prefix.len() {
        return Err("non_https_scheme");
    }
    let head = value.get(..prefix.len()).ok_or("non_https_scheme")?;
    if head.eq_ignore_ascii_case(prefix) {
        Ok(())
    } else {
        Err("non_https_scheme")
    }
}

/// Extract the host portion of an `https://host[:port]/path...` URL.
///
/// Returns `None` when the input has no `://` separator, an empty host, or
/// an unparseable userinfo segment.
fn host_from_url(value: &str) -> Option<&str> {
    let rest = value.split_once("://")?.1;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end)?;
    // Strip optional `userinfo@`.
    let after_userinfo = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // Strip optional `:port`.
    let host = after_userinfo
        .rsplit_once(':')
        .map_or(after_userinfo, |(h, _)| h);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Extract the path portion of an `https://host/path` URL (verbatim, kept
/// only for substring marker checks).
fn path_after_authority(value: &str) -> &str {
    let Some((_, rest)) = value.split_once("://") else {
        return "";
    };
    rest.find('/').and_then(|idx| rest.get(idx..)).unwrap_or("")
}
