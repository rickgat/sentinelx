//! Findings bulk-update + export adapter.
//!
//! Implements [`sx_api::port::FindingBulkPort`] by wrapping the existing
//! [`sx_api::port::FindingRepositoryPort`] trait object. The adapter
//! intentionally re-uses the per-id `update_status` surface rather than
//! reaching for a bespoke batch primitive — repository writes in the
//! monolith today are O(1) (in-memory) or a single tenant-scoped UPDATE
//! (Postgres), so iterating ids inside the adapter is the simplest way to
//! get partial-failure semantics with the existing surface.
//!
//! ## Bounds
//!
//! - [`FindingBulkAdapter::bulk_update`] caps payload at
//!   [`MAX_BULK_IDS`] (the controller already enforces this with
//!   `validator::Validate`; the adapter re-enforces it as defence in
//!   depth).
//! - [`FindingBulkAdapter::export`] caps output at [`MAX_EXPORT_ROWS`]
//!   rows. Callers needing a full snapshot must page by advancing
//!   `since`.
//!
//! ## Export shape
//!
//! - `Ndjson` — one [`FindingView`] per line, compact JSON, `\n`
//!   terminated.
//! - `Csv`    — RFC-4180 with the leading header row
//!   `id,tenant_id,asset_id,severity,status,title,description,cvss,cve_id,first_seen,last_seen`.
//!   The `metadata` JSON column is intentionally omitted (CSV has no
//!   canonical encoding for arbitrary JSON); consumers needing it must
//!   request `format=ndjson`.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{
    EngagementPortError, FindingBulkPort, FindingExportFormat, FindingRepositoryPort,
    Phase3PortError,
};
use sx_api::view::finding_view::{
    BulkUpdateError, BulkUpdateFindingsRequest, BulkUpdateResponse, FindingView, MAX_BULK_IDS,
    MAX_EXPORT_ROWS,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Page size used by [`FindingBulkAdapter::export`] when iterating the
/// underlying repository. Trades round-trip count for memory: a 500-row
/// page keeps the JSON / CSV buffer growth bounded and is small enough
/// for any in-process or Postgres-backed list call.
const EXPORT_PAGE_SIZE: u32 = 500;

/// Build a fresh [`FindingBulkAdapter`] over the supplied finding-repo
/// trait object. Pure (no I/O) — safe to call from `build_app_state`.
pub(crate) fn build(findings: Arc<dyn FindingRepositoryPort>) -> Arc<dyn FindingBulkPort> {
    Arc::new(FindingBulkAdapter { findings })
}

/// Concrete [`FindingBulkPort`] implementation.
///
/// Holds an `Arc` to the read+write finding repository port and delegates
/// every method to its surface. No additional state is kept.
#[derive(Clone)]
pub(crate) struct FindingBulkAdapter {
    findings: Arc<dyn FindingRepositoryPort>,
}

impl std::fmt::Debug for FindingBulkAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FindingBulkAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl FindingBulkPort for FindingBulkAdapter {
    async fn bulk_update(
        &self,
        tenant_id: &str,
        req: BulkUpdateFindingsRequest,
    ) -> Result<BulkUpdateResponse, Phase3PortError> {
        // Defence-in-depth: the controller validates `1..=MAX_BULK_IDS`
        // via `validator::Validate`, but the adapter also refuses
        // oversized payloads in case a future caller bypasses the HTTP
        // layer (e.g. an integration test).
        if req.ids.is_empty() {
            return Err(Phase3PortError::Invalid("ids must be non-empty".into()));
        }
        if req.ids.len() > MAX_BULK_IDS {
            return Err(Phase3PortError::Invalid(format!(
                "ids exceed cap ({} > {MAX_BULK_IDS})",
                req.ids.len(),
            )));
        }

        let mut updated: u32 = 0;
        let mut failed: u32 = 0;
        let mut errors: Vec<BulkUpdateError> = Vec::new();
        let comment = req.comment.as_deref();

        for id in &req.ids {
            match self
                .findings
                .update_status(tenant_id, id, &req.status, comment)
                .await
            {
                Ok(_) => {
                    updated = updated.saturating_add(1);
                }
                Err(err) => {
                    failed = failed.saturating_add(1);
                    errors.push(BulkUpdateError {
                        id: id.clone(),
                        message: project_engagement_err(&err),
                    });
                }
            }
        }

        Ok(BulkUpdateResponse {
            updated,
            failed,
            errors,
        })
    }

    async fn export(
        &self,
        tenant_id: &str,
        format: FindingExportFormat,
        since: Option<String>,
    ) -> Result<Vec<u8>, Phase3PortError> {
        let since_dt = parse_optional_rfc3339(since.as_deref())?;
        let rows = self.snapshot(tenant_id, since_dt.as_ref()).await?;
        match format {
            FindingExportFormat::Ndjson => encode_ndjson(&rows),
            FindingExportFormat::Csv => Ok(encode_csv(&rows)),
        }
    }
}

impl FindingBulkAdapter {
    /// Page through the finding repository for `tenant_id`, filtering by
    /// `since` (inclusive lower bound on `last_seen`) and truncating at
    /// [`MAX_EXPORT_ROWS`]. Returns the projected snapshot in repository
    /// order — the caller chooses the wire format.
    async fn snapshot(
        &self,
        tenant_id: &str,
        since: Option<&OffsetDateTime>,
    ) -> Result<Vec<FindingView>, Phase3PortError> {
        let mut out: Vec<FindingView> = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let page = self
                .findings
                .list(tenant_id, offset, EXPORT_PAGE_SIZE)
                .await
                .map_err(|e| project_engagement_to_phase3(&e))?;
            if page.is_empty() {
                break;
            }
            let page_len = u64::try_from(page.len()).unwrap_or(u64::MAX);
            for row in page {
                if !filter_since(&row, since)? {
                    continue;
                }
                if out.len() >= MAX_EXPORT_ROWS {
                    return Ok(out);
                }
                out.push(row);
            }
            offset = offset.saturating_add(page_len);
            // Short read => repository exhausted.
            if page_len < u64::from(EXPORT_PAGE_SIZE) {
                break;
            }
        }
        Ok(out)
    }
}

/// Parse an optional RFC 3339 timestamp; emits
/// [`Phase3PortError::Invalid`] when present-but-malformed.
fn parse_optional_rfc3339(s: Option<&str>) -> Result<Option<OffsetDateTime>, Phase3PortError> {
    match s {
        None => Ok(None),
        Some(raw) => OffsetDateTime::parse(raw, &Rfc3339)
            .map(Some)
            .map_err(|e| Phase3PortError::Invalid(format!("malformed since: {e}"))),
    }
}

/// Apply the `since` filter against a finding's `last_seen` timestamp.
///
/// A malformed timestamp on a stored row surfaces as
/// [`Phase3PortError::Internal`] — the row was written by the repository
/// adapter and is supposed to be well-formed.
fn filter_since(
    row: &FindingView,
    since: Option<&OffsetDateTime>,
) -> Result<bool, Phase3PortError> {
    let Some(since) = since else {
        return Ok(true);
    };
    let ts = OffsetDateTime::parse(&row.last_seen, &Rfc3339)
        .map_err(|e| Phase3PortError::Internal(format!("stored last_seen: {e}")))?;
    Ok(ts >= *since)
}

/// Encode a finding snapshot as newline-delimited JSON (`\n` separated,
/// trailing newline included).
fn encode_ndjson(rows: &[FindingView]) -> Result<Vec<u8>, Phase3PortError> {
    let mut out: Vec<u8> = Vec::with_capacity(rows.len().saturating_mul(256));
    for row in rows {
        let line = serde_json::to_string(row)
            .map_err(|e| Phase3PortError::Internal(format!("ndjson encode: {e}")))?;
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

/// CSV header emitted before every export body. Column order matches
/// [`FindingView`] field declaration order for the scalar columns;
/// `metadata` is intentionally omitted.
const CSV_HEADER: &str =
    "id,tenant_id,asset_id,severity,status,title,description,cvss,cve_id,first_seen,last_seen";

/// Encode a finding snapshot as RFC-4180-flavoured CSV. Header row is
/// always present; field separator is `,`; line terminator is `\r\n`;
/// values containing `"`, `,`, `\r`, or `\n` are wrapped in `"…"` with
/// embedded `"` doubled.
fn encode_csv(rows: &[FindingView]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(rows.len().saturating_mul(256));
    out.extend_from_slice(CSV_HEADER.as_bytes());
    out.extend_from_slice(b"\r\n");
    for row in rows {
        let cvss = row.cvss.map(|v| v.to_string()).unwrap_or_default();
        let cve_id = row.cve_id.clone().unwrap_or_default();
        let columns = [
            row.id.as_str(),
            row.tenant_id.as_str(),
            row.asset_id.as_str(),
            row.severity.as_str(),
            row.status.as_str(),
            row.title.as_str(),
            row.description.as_str(),
            cvss.as_str(),
            cve_id.as_str(),
            row.first_seen.as_str(),
            row.last_seen.as_str(),
        ];
        for (i, col) in columns.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            write_csv_field(&mut out, col);
        }
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Write a single CSV column to `out`, quoting + escaping per RFC 4180.
fn write_csv_field(out: &mut Vec<u8>, value: &str) {
    let needs_quote =
        value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');
    if !needs_quote {
        out.extend_from_slice(value.as_bytes());
        return;
    }
    out.push(b'"');
    for ch in value.chars() {
        if ch == '"' {
            out.push(b'"');
            out.push(b'"');
        } else {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            out.extend_from_slice(s.as_bytes());
        }
    }
    out.push(b'"');
}

/// Project an [`EngagementPortError`] into the human-readable message
/// stored on a per-id [`BulkUpdateError`]. Stays purposely terse — the
/// HTTP layer never surfaces these to end users without scrubbing.
fn project_engagement_err(err: &EngagementPortError) -> String {
    match err {
        EngagementPortError::NotFound => "not_found".to_owned(),
        EngagementPortError::Forbidden => "forbidden".to_owned(),
        EngagementPortError::Conflict(m) => format!("conflict: {m}"),
        EngagementPortError::Invalid(m) => format!("invalid: {m}"),
        EngagementPortError::Dependency(m) => format!("dependency: {m}"),
        EngagementPortError::Internal(m) => format!("internal: {m}"),
    }
}

/// Translate a repository-layer error into the port-layer error the
/// export path surfaces. Only used by [`FindingBulkAdapter::snapshot`];
/// `bulk_update` records per-id failures rather than failing the whole
/// batch.
fn project_engagement_to_phase3(err: &EngagementPortError) -> Phase3PortError {
    match err {
        EngagementPortError::NotFound => Phase3PortError::NotFound,
        EngagementPortError::Forbidden => Phase3PortError::Forbidden("tenant".into()),
        EngagementPortError::Conflict(m) | EngagementPortError::Invalid(m) => {
            Phase3PortError::Invalid(m.clone())
        }
        EngagementPortError::Dependency(m) => Phase3PortError::Dependency(m.clone()),
        EngagementPortError::Internal(m) => Phase3PortError::Internal(m.clone()),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Recording fake finding repository for adapter unit tests.
    ///
    /// Honours `update_status` against an internal `(tenant_id, id)` map
    /// and can be configured to reject a specific id with
    /// [`EngagementPortError::NotFound`] so the partial-failure code path
    /// is exercised.
    #[derive(Debug, Default)]
    struct FakeFindings {
        rows: Mutex<HashMap<(String, String), FindingView>>,
        miss: Mutex<Vec<String>>,
    }

    impl FakeFindings {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn seed(&self, view: FindingView) {
            self.rows
                .lock()
                .unwrap()
                .insert((view.tenant_id.clone(), view.id.clone()), view);
        }

        fn refuse(&self, id: &str) {
            self.miss.lock().unwrap().push(id.to_owned());
        }
    }

    #[async_trait]
    impl FindingRepositoryPort for FakeFindings {
        async fn list(
            &self,
            tenant_id: &str,
            offset: u64,
            limit: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            let g = self.rows.lock().unwrap();
            let mut items: Vec<FindingView> = g
                .iter()
                .filter(|((t, _), _)| t == tenant_id)
                .map(|(_, v)| v.clone())
                .collect();
            items.sort_by(|a, b| a.id.cmp(&b.id));
            Ok(items
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect())
        }

        async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
            self.rows
                .lock()
                .unwrap()
                .get(&(tenant_id.to_owned(), id.to_owned()))
                .cloned()
                .ok_or(EngagementPortError::NotFound)
        }

        async fn update_status(
            &self,
            tenant_id: &str,
            id: &str,
            new_status: &str,
            _comment: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            if self.miss.lock().unwrap().iter().any(|m| m == id) {
                return Err(EngagementPortError::NotFound);
            }
            let mut g = self.rows.lock().unwrap();
            match g.get_mut(&(tenant_id.to_owned(), id.to_owned())) {
                Some(view) => {
                    view.status = new_status.to_owned();
                    Ok(view.clone())
                }
                None => Err(EngagementPortError::NotFound),
            }
        }
        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            let key = (view.tenant_id.clone(), view.id.clone());
            self.rows.lock().unwrap().insert(key, view.clone());
            Ok(view)
        }
    }

    fn tenant() -> &'static str {
        "01010101-0101-0101-0101-010101010101"
    }

    fn make_finding(id: &str, last_seen: &str) -> FindingView {
        FindingView {
            id: id.to_owned(),
            tenant_id: tenant().to_owned(),
            asset_id: "a0000001-0000-0000-0000-000000000000".to_owned(),
            severity: "high".to_owned(),
            status: "open".to_owned(),
            title: "demo".to_owned(),
            description: "demo finding".to_owned(),
            cvss: Some(7.5),
            cve_id: Some("CVE-2024-1234".to_owned()),
            first_seen: "2026-05-15T00:00:00Z".to_owned(),
            last_seen: last_seen.to_owned(),
            metadata: None,
        }
    }

    /// Adapter refuses an empty `ids` list with `Phase3PortError::Invalid`.
    #[tokio::test]
    async fn bulk_update_rejects_empty_ids() {
        let repo = FakeFindings::new();
        let port = build(repo);
        let err = port
            .bulk_update(
                tenant(),
                BulkUpdateFindingsRequest {
                    ids: vec![],
                    status: "triaged".into(),
                    comment: None,
                },
            )
            .await
            .expect_err("empty ids must be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    /// Adapter caps at [`MAX_BULK_IDS`] even when the caller bypasses
    /// HTTP-level validation.
    #[tokio::test]
    async fn bulk_update_rejects_too_many_ids() {
        let repo = FakeFindings::new();
        let port = build(repo);
        let ids: Vec<String> = (0..=MAX_BULK_IDS)
            .map(|i| format!("f0000000-0000-0000-0000-{i:012}"))
            .collect();
        let err = port
            .bulk_update(
                tenant(),
                BulkUpdateFindingsRequest {
                    ids,
                    status: "triaged".into(),
                    comment: None,
                },
            )
            .await
            .expect_err("oversized ids must be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    /// Successful and missing ids land in `updated` and `errors`
    /// respectively, with `failed` reflecting the miss count.
    #[tokio::test]
    async fn bulk_update_counts_partial_failures() {
        let repo = FakeFindings::new();
        repo.seed(make_finding(
            "f0000001-0000-0000-0000-000000000001",
            "2026-05-29T00:00:00Z",
        ));
        repo.seed(make_finding(
            "f0000002-0000-0000-0000-000000000002",
            "2026-05-29T00:00:00Z",
        ));
        repo.refuse("f0000003-0000-0000-0000-000000000003");
        let port = build(Arc::clone(&repo) as Arc<dyn FindingRepositoryPort>);
        let resp = port
            .bulk_update(
                tenant(),
                BulkUpdateFindingsRequest {
                    ids: vec![
                        "f0000001-0000-0000-0000-000000000001".into(),
                        "f0000002-0000-0000-0000-000000000002".into(),
                        "f0000003-0000-0000-0000-000000000003".into(),
                    ],
                    status: "triaged".into(),
                    comment: Some("playbook A-12".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.updated, 2);
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].id, "f0000003-0000-0000-0000-000000000003");
        assert!(resp.errors[0].message.contains("not_found"));
    }

    /// NDJSON export emits one line per row, terminated by `\n`, with the
    /// `FindingView` JSON shape on each line.
    #[tokio::test]
    async fn export_ndjson_emits_one_line_per_row() {
        let repo = FakeFindings::new();
        repo.seed(make_finding(
            "f0000001-0000-0000-0000-000000000001",
            "2026-05-29T00:00:00Z",
        ));
        repo.seed(make_finding(
            "f0000002-0000-0000-0000-000000000002",
            "2026-05-29T00:00:00Z",
        ));
        let port = build(repo);
        let body = port
            .export(tenant(), FindingExportFormat::Ndjson, None)
            .await
            .unwrap();
        let text = String::from_utf8(body).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let v: FindingView = serde_json::from_str(line).unwrap();
            assert_eq!(v.tenant_id, tenant());
        }
        assert!(text.ends_with('\n'));
    }

    /// CSV export opens with the canonical header row in the column order
    /// declared by [`CSV_HEADER`].
    #[tokio::test]
    async fn export_csv_header_matches_canonical_order() {
        let repo = FakeFindings::new();
        repo.seed(make_finding(
            "f0000001-0000-0000-0000-000000000001",
            "2026-05-29T00:00:00Z",
        ));
        let port = build(repo);
        let body = port
            .export(tenant(), FindingExportFormat::Csv, None)
            .await
            .unwrap();
        let text = String::from_utf8(body).unwrap();
        let first_line = text.lines().next().expect("header row present");
        assert_eq!(first_line, CSV_HEADER);
        // Body rows must come after the header, separated by CRLF.
        assert!(text.contains("\r\n"));
    }

    /// CSV escaping: a row whose `title` contains a comma must be wrapped
    /// in double quotes, and embedded quotes must be doubled.
    #[tokio::test]
    async fn export_csv_escapes_special_chars() {
        let repo = FakeFindings::new();
        let mut row = make_finding(
            "f0000001-0000-0000-0000-000000000001",
            "2026-05-29T00:00:00Z",
        );
        row.title = "needs, \"quote\"".to_owned();
        repo.seed(row);
        let port = build(repo);
        let body = port
            .export(tenant(), FindingExportFormat::Csv, None)
            .await
            .unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(
            text.contains("\"needs, \"\"quote\"\"\""),
            "csv body must escape commas + quotes, got: {text}",
        );
    }

    /// Adapter `since` filter trims rows whose `last_seen` is before the
    /// supplied lower bound (inclusive).
    #[tokio::test]
    async fn export_filters_by_since() {
        let repo = FakeFindings::new();
        repo.seed(make_finding(
            "f0000001-0000-0000-0000-000000000001",
            "2026-05-15T00:00:00Z",
        ));
        repo.seed(make_finding(
            "f0000002-0000-0000-0000-000000000002",
            "2026-05-29T00:00:00Z",
        ));
        let port = build(repo);
        let body = port
            .export(
                tenant(),
                FindingExportFormat::Ndjson,
                Some("2026-05-20T00:00:00Z".into()),
            )
            .await
            .unwrap();
        let text = String::from_utf8(body).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("f0000002-0000-0000-0000-000000000002"));
    }

    /// Malformed `since` surfaces as [`Phase3PortError::Invalid`].
    #[tokio::test]
    async fn export_rejects_malformed_since() {
        let repo = FakeFindings::new();
        let port = build(repo);
        let err = port
            .export(
                tenant(),
                FindingExportFormat::Ndjson,
                Some("not-a-timestamp".into()),
            )
            .await
            .expect_err("malformed since must be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }
}
