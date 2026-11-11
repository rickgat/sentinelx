//! Findings bulk-update + export controllers.
//!
//! Two routes:
//!
//! - `POST /v1/findings/bulk-update` — update up to
//!   [`crate::view::finding_view::MAX_BULK_IDS`] finding ids in one call,
//!   recording an optional audit comment per row. Returns a
//!   [`BulkUpdateResponse`] with per-id failure breakdown so partial
//!   batches stay informative.  RBAC: `findings:write`.
//! - `GET /v1/findings/export?format=ndjson|csv&since=` — stream a
//!   snapshot of the caller's findings. The body is `application/x-ndjson`
//!   or `text/csv`; both are emitted as raw bytes (no envelope) because
//!   they are line-oriented formats consumed by tooling that does not
//!   speak the standard API envelope.  RBAC: `findings:read`.
//!
//! Both handlers delegate to [`crate::port::FindingBulkPort`]. The concrete
//! adapter is wired by the composition root
//! (`services/sx-monolith/src/adapters/findings_bulk.rs`).
//!
//! ## CSV column order
//!
//! When `format=csv` the body opens with a fixed header row matching the
//! [`FindingView`] field order:
//!
//! ```text
//! id,tenant_id,asset_id,severity,status,title,description,cvss,cve_id,first_seen,last_seen
//! ```
//!
//! `metadata` is intentionally omitted from the CSV — RFC-4180 has no
//! canonical encoding for arbitrary JSON, and consumers that need it
//! should request `format=ndjson`.

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::FindingExportFormat;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::finding_view::{
    BulkUpdateFindingsRequest, BulkUpdateResponse, FindingExportQuery,
};

/// `POST /v1/findings/bulk-update`.
///
/// Validates the request body (id-count in `1..=MAX_BULK_IDS`, status in
/// the accepted set) via the `ValidatedJson` extractor, gates on the
/// `findings:write` permission, and delegates to
/// [`crate::port::FindingBulkPort::bulk_update`].
pub async fn bulk_update(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<BulkUpdateFindingsRequest>,
) -> Result<Json<ApiResponse<BulkUpdateResponse>>, ApiError> {
    require_permission(&user, "findings:write")?;
    let resp = state
        .finding_bulk
        .bulk_update(&scope.tenant_id, req)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `GET /v1/findings/export?format=ndjson|csv&since=`.
///
/// Streams the export body directly (no envelope) with the appropriate
/// `Content-Type`. `format` defaults to `ndjson` when absent; unknown
/// formats surface as `422 Unprocessable`.
///
/// The adapter is responsible for capping output at
/// [`crate::view::finding_view::MAX_EXPORT_ROWS`] rows.
pub async fn export(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Query(q): Query<FindingExportQuery>,
) -> Result<Response, ApiError> {
    require_permission(&user, "findings:read")?;
    let raw_format = q.format.as_deref().unwrap_or("ndjson");
    let Some(format) = FindingExportFormat::parse(raw_format) else {
        return Err(ApiError::Unprocessable(format!(
            "unsupported export format: {raw_format}"
        )));
    };
    let body = state
        .finding_bulk
        .export(&scope.tenant_id, format, q.since)
        .await
        .map_err(map_phase3)?;
    let content_type = match format {
        FindingExportFormat::Ndjson => "application/x-ndjson",
        FindingExportFormat::Csv => "text/csv; charset=utf-8",
    };
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response())
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in [`crate::controller::audit`] — kept private here
/// so the controller stays self-contained and there is no cross-module
/// RBAC coupling.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    fn user(perms: Vec<&str>) -> AuthenticatedUser {
        AuthenticatedUser {
            claims: AccessClaims {
                sub: "u".into(),
                tenant_id: "t".into(),
                iss: "i".into(),
                aud: "a".into(),
                iat: 0,
                nbf: 0,
                exp: 0,
                jti: "j".into(),
                sid: "s".into(),
                token_type: TokenType::Access,
                roles: vec![],
                permissions: perms
                    .into_iter()
                    .map(|p| Permission::parse(p).unwrap())
                    .collect(),

                cred_id: None,
            },
        }
    }

    #[test]
    fn bulk_update_requires_findings_write_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "findings:write"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn bulk_update_exact_findings_write_allowed() {
        let u = user(vec!["findings:write"]);
        assert!(require_permission(&u, "findings:write").is_ok());
    }

    #[test]
    fn export_requires_findings_read_permission() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "findings:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn wildcard_findings_action_allowed_for_write() {
        let u = user(vec!["findings:*"]);
        assert!(require_permission(&u, "findings:write").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed_for_export() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "findings:read").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed_for_read() {
        let u = user(vec!["*:read"]);
        assert!(require_permission(&u, "findings:read").is_ok());
    }

    /// Parsing the export-format query string is what dispatches `Csv` vs
    /// `Ndjson` inside [`export`]. The handler relies on
    /// [`FindingExportFormat::parse`], so we lock the dispatch table here.
    #[test]
    fn format_dispatch_recognises_csv_and_ndjson_case_insensitively() {
        assert_eq!(
            FindingExportFormat::parse("ndjson"),
            Some(FindingExportFormat::Ndjson),
        );
        assert_eq!(
            FindingExportFormat::parse("NDJSON"),
            Some(FindingExportFormat::Ndjson),
        );
        assert_eq!(
            FindingExportFormat::parse("csv"),
            Some(FindingExportFormat::Csv),
        );
        assert_eq!(
            FindingExportFormat::parse("CSV"),
            Some(FindingExportFormat::Csv),
        );
    }

    #[test]
    fn format_dispatch_rejects_unknown_format() {
        assert_eq!(FindingExportFormat::parse("xml"), None);
        assert_eq!(FindingExportFormat::parse(""), None);
        assert_eq!(FindingExportFormat::parse("yaml"), None);
    }
}
