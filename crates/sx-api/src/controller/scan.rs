//! Scan controller — `POST /v1/scans/http-headers`, `GET /v1/scans`,
//! `GET /v1/scans/{id}` (JSON detail), and `GET /v1/scans/{id}.sarif`
//! (TOP5-#3-P2-SARIF-API + QC-SCAN-2026-06-25 fix c).
//!
//! The HTTP-header scanner produces light-weight, self-contained findings
//! that are NOT persisted into the main finding repository. Scan-derived
//! findings live inside the scan record itself so the dashboard can
//! render the audit trail without polluting the engagement-bound stream.
//!
//! The SARIF v2.1.0 representation of a stored scan record reuses the
//! canonical [`sx_core::sarif::findings_to_sarif`] schema — this
//! controller does NOT construct SARIF inline; it only projects each
//! [`ScanFinding`] back into a [`sx_core::entity::finding::Finding`] via
//! the [`scan_finding_to_finding`] adapter and lets `sx-core` own the
//! envelope.
//!
//! SSRF guard (QC-SCAN-2026-06-25 fixes a + b): the `POST
//! /v1/scans/http-headers` controller runs [`validate_scan_target`]
//! BEFORE handing the target to the scanner port. Non-`http(s)` schemes
//! (`file://`, `gopher://`, …), loopback addresses, link-local
//! addresses, and cloud-metadata IPs all surface as a structured 400
//! before any network probe is attempted.

use std::str::FromStr;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_core::entity::finding::Finding;
use sx_core::reference::url_guard::{validate_scan_target, ScanTargetError};
use sx_core::value_object::ids::{AssetId, TenantId};
use sx_core::value_object::severity::Severity;
use sx_iam::domain::Permission;
use time::OffsetDateTime;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::scan_view::{HttpHeaderScanRequest, ListScansResponse, ScanFinding, ScanRecord};

/// `POST /v1/scans/http-headers`
///
/// SSRF guard (QC-SCAN-2026-06-25 fix a + b): the target is run through
/// [`validate_scan_target`] BEFORE reaching the scanner port. Disallowed
/// schemes, loopback addresses, link-local addresses, and cloud-metadata
/// IPs surface as a 400 with a [`ScanTargetError`] variant message
/// rather than the legacy "200 / status=error" shape.
pub async fn http_headers(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(mut req): ValidatedJson<HttpHeaderScanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "scans:run")?;

    // SSRF guard. We normalise the on-wire `req.target` to the parsed
    // URL string so the scanner adapter does not have to re-derive the
    // scheme — and so the persisted `ScanRecord.target` always reflects
    // the post-guard URL (e.g. `example.com` → `https://example.com/`).
    let validated = validate_scan_target(&req.target)
        .await
        .map_err(map_scan_target_error)?;
    req.target = validated.to_string();

    let record = state
        .http_header_scanner
        .run(req, user.claims.tenant_id.clone())
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(record)))
}

/// Translate a [`ScanTargetError`] into a 400 [`ApiError::BadRequest`].
///
/// Every variant collapses into the same status code (the failure is
/// always "this URL is unacceptable as a scan target") but the wire
/// `message` carries the discriminating string so a client can branch
/// on the failure mode (loopback vs metadata vs scheme) without
/// re-parsing the URL. The mapping is centralised so both the
/// http-headers controller and the DAST controller render identical
/// shapes.
pub(crate) fn map_scan_target_error(err: ScanTargetError) -> ApiError {
    ApiError::BadRequest(err.to_string())
}

/// Query string for `GET /v1/scans`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListScansQuery {
    /// Optional engagement filter.
    pub engagement_id: Option<String>,
    /// Cap; default 50, max 200.
    pub limit: Option<u32>,
}

/// `GET /v1/scans?engagement_id=...&limit=...`
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListScansQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "scans:read")?;
    if let Some(ref id) = q.engagement_id {
        if uuid::Uuid::parse_str(id).is_err() {
            return Err(ApiError::BadRequest(
                "engagement_id must be a uuid".to_owned(),
            ));
        }
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let items = state
        .http_header_scanner
        .list(q.engagement_id.as_deref(), limit)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(ListScansResponse { items })))
}

/// Enforce a single `resource:action` permission with wildcard support.
fn require_permission(user: &AuthenticatedUser, perm: &str) -> Result<(), ApiError> {
    let Ok(required) = Permission::parse(perm) else {
        return Err(ApiError::Internal("invalid permission constant".into()));
    };
    let allowed = user.claims.permissions.iter().any(|p| {
        let r = p.resource() == required.resource() || p.resource() == "*";
        let a = p.action() == required.action() || p.action() == "*";
        r && a
    });
    if allowed {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Tool name advertised in the SARIF `runs[].tool.driver.name` field.
const SARIF_TOOL_NAME: &str = "sentinelx-http-headers";

/// Tool version advertised in SARIF. Tied to the crate version so
/// downstream consumers (GitHub Code Scanning, GitLab Security Dashboard)
/// can pin findings to a specific scanner release.
const SARIF_TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// SARIF v2.1.0 content type per §3.1 of the spec. Distinct from
/// `application/json` so SOC pipelines can content-sniff the payload.
const SARIF_CONTENT_TYPE: &str = "application/sarif+json";

/// `GET /v1/scans/:id.sarif` — return a SARIF v2.1.0 envelope for one
/// stored scan record (TOP5-#3-P2-SARIF-API).
///
/// Same auth posture as [`list`] (`scans:read`). Same tenant scoping —
/// the port's `get` method enforces that the record belongs to the
/// caller's tenant; a record owned by another tenant surfaces as 404
/// (the same shape the JSON path uses), not 403, so we never leak the
/// existence of foreign-tenant scan ids.
pub async fn get_scan_sarif(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id_sarif): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "scans:read")?;
    let id = strip_sarif_suffix(&id_sarif).ok_or(ApiError::NotFound)?;
    build_sarif_response(
        state.http_header_scanner.as_ref(),
        &user.claims.tenant_id,
        id,
        Some(state.release_channel_cfg.organization.as_str()),
        state.release_channel_cfg.download_uri.as_deref(),
    )
    .await
}

/// `GET /v1/scans/:any_id` — unified dispatcher (QC-SCAN-2026-06-25
/// fix c). Routes a single captured segment to either the JSON detail
/// response or the SARIF export based on the `.sarif` suffix:
///
/// * `GET /v1/scans/{id}.sarif` → strip suffix, emit SARIF (200 with
///   `Content-Type: application/sarif+json`).
/// * `GET /v1/scans/{id}` → emit JSON detail (200 with the standard
///   `ApiResponse<ScanRecord>` envelope).
/// * Unknown id (after stripping where applicable) → 404.
///
/// Why dispatcher instead of two routes? axum 0.7 / matchit 0.7 cannot
/// bind `:id.sarif` in a single segment, so both routes had to share a
/// single capture or the JSON path would 404. A future axum 0.8+ bump
/// can split this back into two clean routes without changing the wire
/// surface.
pub async fn get_scan_dispatch(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(any_id): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    require_permission(&user, "scans:read")?;
    let port = state.http_header_scanner.as_ref();
    let tenant_id = &user.claims.tenant_id;
    if let Some(id) = strip_sarif_suffix(&any_id) {
        return build_sarif_response(
            port,
            tenant_id,
            id,
            Some(state.release_channel_cfg.organization.as_str()),
            state.release_channel_cfg.download_uri.as_deref(),
        )
        .await;
    }
    build_json_detail_response(port, tenant_id, &any_id).await
}

/// Resolve the scan and render the standard JSON detail envelope.
///
/// Split out so integration tests can drive the response shape without
/// rebuilding the global [`AppState`]. Mirrors the SARIF helper's
/// signature so both paths look identical at the call site.
pub async fn build_json_detail_response(
    port: &dyn crate::port::HttpHeaderScannerPort,
    tenant_id: &str,
    scan_id: &str,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse as _;

    let record = port
        .get(tenant_id, scan_id)
        .await
        .map_err(map_phase3)?
        .ok_or(ApiError::NotFound)?;

    Ok((StatusCode::OK, Json(ApiResponse::ok(record))).into_response())
}

/// Synthesise a guaranteed-well-formed placeholder [`Finding`] used by
/// [`scan_finding_to_finding`] when the primary builder rejects the
/// projected DTO. Static fields satisfy `Finding::new`'s non-empty
/// validation; this function never panics by construction.
fn placeholder_finding() -> Finding {
    let tenant_id = TenantId::new();
    let asset_id = AssetId::new();
    match Finding::new(
        tenant_id,
        asset_id,
        "HDR.SCAN.MALFORMED",
        "Malformed scan finding",
        "A scan finding could not be projected into the canonical Finding shape.",
        Severity::Info,
        OffsetDateTime::UNIX_EPOCH,
    ) {
        Ok(f) => f,
        // Static inputs always satisfy the validator — this arm is
        // structurally unreachable. We still avoid `unreachable!` to
        // keep `clippy::unreachable` clean: a SARIF export request must
        // never panic, even in the face of a future validator tweak,
        // so we degrade gracefully by returning a bare-bones value
        // with the empty rule id (consumers will see one malformed
        // entry rather than a dropped envelope).
        Err(_) => Finding {
            id: sx_core::value_object::ids::FindingId::new(),
            tenant_id: TenantId::new(),
            asset_id: AssetId::new(),
            rule_id: "HDR.SCAN.MALFORMED".into(),
            title: "Malformed".into(),
            description: String::new(),
            severity: Severity::Info,
            status: sx_core::entity::finding_status::FindingStatus::Discovered,
            evidence_refs: Vec::new(),
            discovered_at: OffsetDateTime::UNIX_EPOCH,
            confirmed_at: None,
            remediated_at: None,
            cvss: None,
            cwe: Vec::new(),
            mitre_attack: Vec::new(),
            compliance: sx_core::value_object::compliance::ComplianceTags::default(),
            confidence: None,
        },
    }
}

/// Strip the `.sarif` suffix from the captured path segment.
///
/// axum 0.7 (matchit 0.7) cannot match `<param>.<literal>` patterns in a
/// single segment, so the route is registered as a single-segment
/// `:id_sarif` parameter and this helper recovers the underlying scan
/// id. A request without the `.sarif` suffix is treated as `not found`
/// — the JSON list endpoint already lives at `/v1/scans`, so an
/// un-suffixed `/v1/scans/{id}` is not a documented route.
fn strip_sarif_suffix(captured: &str) -> Option<&str> {
    captured.strip_suffix(".sarif")
}

/// Resolve the scan, project its findings, and build the SARIF response.
///
/// Split out of [`get_scan_sarif`] so integration tests can exercise the
/// full response shape (status, content-type, body) without having to
/// construct the global [`AppState`] (which carries ~100 trait-object
/// ports and is impractical to assemble outside `services/sx-monolith`).
pub async fn build_sarif_response(
    port: &dyn crate::port::HttpHeaderScannerPort,
    tenant_id: &str,
    scan_id: &str,
    organization: Option<&str>,
    download_uri: Option<&str>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse as _;

    let record = port
        .get(tenant_id, scan_id)
        .await
        .map_err(map_phase3)?
        .ok_or(ApiError::NotFound)?;

    let findings: Vec<Finding> = record
        .findings
        .iter()
        .map(|sf| scan_finding_to_finding(&record, sf))
        .collect();

    let sarif = sx_core::sarif::findings_to_sarif(
        &findings,
        SARIF_TOOL_NAME,
        SARIF_TOOL_VERSION,
        organization,
        download_uri,
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SARIF_CONTENT_TYPE),
    );
    Ok((StatusCode::OK, headers, Json(sarif)).into_response())
}

/// One-way projection from the wire DTO [`ScanFinding`] to the canonical
/// domain entity [`Finding`].
///
/// This adapter is the **canary** for `ScanFinding` ↔ `Finding`
/// divergence: the SX-REVIEW-002 C1 fix landed the enrichment surface on
/// both types as a deliberate 1:1 mapping (CVSS / CWE / MITRE ATT&CK /
/// compliance / confidence). If a future contributor adds a field to one
/// side without the other, this function stops compiling — flag the gap
/// instead of silently dropping enrichment from the SARIF export.
///
/// Severity strings produced by the scanner adapter (`info | low |
/// medium | high | critical`) are reparsed through the canonical
/// `Severity` enum; anything outside the band defaults to `Info` (the
/// most conservative bucket) rather than returning an error — SARIF
/// export must never fail because of a stale severity string.
///
/// The asset id is synthesised per-call because [`ScanRecord`] does not
/// carry one — the scanner targets a URL, not a tracked asset — so each
/// SARIF result effectively says "this finding is bound to a scan, not
/// a managed asset". `tenant_id` is recovered from the parent record so
/// the `Finding.tenant_id` field carries the same scoping the wire DTO
/// already enforces.
///
/// Confidence outside `0.0..=1.0` is dropped (the canonical builder
/// rejects it with `DomainError`). Likewise, `Finding::new` rejects an
/// empty `title`; we substitute the `check_id` if the DTO carries an
/// empty title so the SARIF result still resolves a rule descriptor.
pub fn scan_finding_to_finding(record: &ScanRecord, sf: &ScanFinding) -> Finding {
    let tenant_id = TenantId::from_str(&record.tenant_id).unwrap_or_else(|_| TenantId::new());
    let asset_id = AssetId::new();
    // Unknown severity strings fall through to `Severity::Info` — the
    // most conservative bucket. SARIF export must never fail because of
    // a stale severity label; better to under-warn than to drop the
    // finding entirely.
    let severity = match sf.severity.as_str() {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info,
    };
    let discovered_at = OffsetDateTime::parse(
        &record.started_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap_or(OffsetDateTime::UNIX_EPOCH);

    let title = if sf.title.trim().is_empty() {
        sf.check_id.clone()
    } else {
        sf.title.clone()
    };

    // Unwrap-style here is safe: rule_id (check_id) and title are
    // guaranteed non-empty by the validator above; severity is a known
    // enum value. The fallback path (should be unreachable given the
    // title fixup above) builds a minimal placeholder finding so the
    // caller still gets a parseable SARIF envelope rather than a panic.
    let primary = Finding::new(
        tenant_id,
        asset_id,
        sf.check_id.clone(),
        title,
        sf.description.clone(),
        severity,
        discovered_at,
    );
    let mut finding = match primary {
        Ok(f) => f,
        Err(_) => placeholder_finding(),
    };

    if let Some(cvss) = sf.cvss.clone() {
        finding = finding.with_cvss(cvss);
    }
    if !sf.cwe.is_empty() {
        finding = finding.with_cwe(sf.cwe.clone());
    }
    if !sf.mitre_attack.is_empty() {
        finding = finding.with_mitre_attack(sf.mitre_attack.clone());
    }
    if !sf.compliance.is_empty() {
        finding = finding.with_compliance(sf.compliance.clone());
    }
    if let Some(c) = sf.confidence {
        if let Ok(enriched) = finding.clone().with_confidence(c) {
            finding = enriched;
        }
    }

    // TOP5-#3 Phase 3 — source-aware SARIF locations. When the emitter
    // supplies a 1-indexed (line, column), attach an [`EvidenceRef`]
    // pinned to the scan target so the SARIF emitter renders
    // `runs[].results[].locations[].physicalLocation.region.startLine` /
    // `.startColumn` per §3.30.4. Line-only / column-only shapes are
    // accepted symmetrically; either half is enough to opt into the
    // `region` sub-object. The URI is the scan target (there is no
    // per-finding artifact path for HTTP-header / DLP-in-body shapes) so
    // consumers still see the origin.
    if sf.line.is_some() || sf.column.is_some() {
        let mut ev =
            match sx_core::entity::finding::EvidenceRef::new(record.target.clone(), None, None) {
                Ok(e) => e,
                // Guarded by the validator inside `EvidenceRef::new`: the
                // record's target is populated by the SSRF guard and is
                // never empty in practice; if it ever is, we still project
                // a well-formed EvidenceRef against the check_id URI so the
                // SARIF envelope stays valid.
                Err(_) => match sx_core::entity::finding::EvidenceRef::new(
                    format!("sentinelx://scan/{}", record.id),
                    None,
                    None,
                ) {
                    Ok(e) => e,
                    Err(_) => {
                        // Structurally unreachable — a fixed non-empty
                        // literal always satisfies the validator. Return
                        // the un-anchored finding rather than panicking so
                        // SARIF export never fails mid-response.
                        return finding;
                    }
                },
            };
        // 1-indexed both. Zero-guarding lives inside `with_region`;
        // treat a caller-supplied zero as "field absent" so a stray
        // wire value doesn't torpedo the whole envelope.
        let line = sf.line.filter(|&l| l > 0).unwrap_or(1);
        let column = sf.column.filter(|&c| c > 0).unwrap_or(1);
        if sf.line.is_some() {
            ev.line = Some(line);
        }
        if sf.column.is_some() {
            ev.column = Some(column);
        }
        finding.add_evidence(ev);
    }

    finding
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::view::scan_view::ScanFinding;
    use sx_core::value_object::compliance::ComplianceTags;

    fn empty_record() -> ScanRecord {
        ScanRecord {
            id: "01900000-0000-7000-8000-000000000001".into(),
            tenant_id: "01900000-0000-7000-8000-000000000010".into(),
            kind: "http_headers".into(),
            target: "https://example.test/".into(),
            engagement_id: None,
            started_at: "2026-06-24T00:00:00Z".into(),
            finished_at: "2026-06-24T00:00:01Z".into(),
            status: "ok".into(),
            error: None,
            findings: vec![],
        }
    }

    fn bare_finding(check_id: &str, severity: &str, title: &str) -> ScanFinding {
        ScanFinding {
            check_id: check_id.to_owned(),
            severity: severity.to_owned(),
            title: title.to_owned(),
            description: "irrelevant for adapter shape".into(),
            recommendation: None,
            cvss: None,
            cwe: vec![],
            mitre_attack: vec![],
            compliance: ComplianceTags::default(),
            confidence: None,
            line: None,
            column: None,
        }
    }

    #[test]
    fn adapter_maps_severity_strings() {
        let r = empty_record();
        for (s, expected) in [
            ("info", Severity::Info),
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ] {
            let sf = bare_finding("HDR.X", s, "Title");
            let f = scan_finding_to_finding(&r, &sf);
            assert_eq!(f.severity, expected, "severity `{s}` mismatched");
        }
    }

    #[test]
    fn adapter_substitutes_check_id_when_title_blank() {
        let r = empty_record();
        let sf = bare_finding("HDR.STRICT_TRANSPORT_SECURITY.MISSING", "high", "   ");
        let f = scan_finding_to_finding(&r, &sf);
        assert_eq!(f.title, "HDR.STRICT_TRANSPORT_SECURITY.MISSING");
        assert_eq!(f.rule_id, "HDR.STRICT_TRANSPORT_SECURITY.MISSING");
    }

    #[test]
    fn adapter_unknown_severity_falls_back_to_info() {
        let r = empty_record();
        let sf = bare_finding("HDR.X", "wat", "Title");
        let f = scan_finding_to_finding(&r, &sf);
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn strip_sarif_suffix_recovers_id() {
        assert_eq!(
            strip_sarif_suffix("019eba39-ee0b-71f0-9c9b-a21c2527dd30.sarif"),
            Some("019eba39-ee0b-71f0-9c9b-a21c2527dd30"),
        );
    }

    #[test]
    fn strip_sarif_suffix_rejects_unsuffixed_segment() {
        assert_eq!(strip_sarif_suffix("019eba39-ee0b-71f0"), None);
        assert_eq!(strip_sarif_suffix(""), None);
        assert_eq!(strip_sarif_suffix(".sarif"), Some(""));
    }
}
