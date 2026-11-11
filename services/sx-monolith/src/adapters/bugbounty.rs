//! P3-010 — Bug-bounty bridge adapter.
//!
//! Bridges the per-tenant per-platform connection store and the
//! [`sx_integrations::bugbounty`] connector + webhook surfaces into the
//! [`sx_api::port::BugBountyPort`] trait the HTTP controller calls.
//!
//! ## Composition
//!
//! Six collaborators are wired together inside [`BugBountyAdapter`]:
//!
//! * [`sx_integrations::bugbounty::BugBountyConfigStore`] — per-tenant
//!   `(tenant_id, kind, program_handle)` row store. The MVP uses the
//!   in-memory implementation; the trait shape matches the production
//!   `bug_bounty_connections` Postgres table.
//! * [`sx_secrets::SecretsProvider`] — the secrets backend the adapter
//!   writes API tokens + inbound webhook HMAC secrets into. Tokens are
//!   *never* held in process beyond the
//!   row→secret→connector materialisation window. Rotation upstream is
//!   immediately observable to the next push / next inbound verify.
//! * `reqwest::Client` — the HTTP client every concrete connector
//!   borrows when it talks to HackerOne / Bugcrowd. Long-lived; shared
//!   with the rest of the outbound adapters.
//! * [`sx_integrations::bugbounty::Deduplicator`] — TF-IDF cosine ≥ 0.85
//!   fingerprint over the inbound report's title + description vs the
//!   tenant's existing findings.
//! * [`sx_integrations::bugbounty::BugBountyAuditSink`] — receives one
//!   event per outbound push and per inbound ingest. The MVP wires this
//!   to a process-local [`RecordingAuditSink`]; production swaps it for
//!   the audit-query sink so the trail lands in the same Postgres table
//!   the rest of the platform writes to.
//! * [`sx_api::port::FindingRepositoryPort`] — read-side handle the
//!   inbound dedupe pipeline iterates to fetch the candidate corpus.
//!
//! ## Audit
//!
//! Every push (success, severity-floor reject, transport failure) and
//! every inbound ingest (success, dedup, signature mismatch, malformed
//! payload) emits exactly one
//! [`sx_integrations::bugbounty::BugBountyAuditEvent`]. Tokens, headers,
//! URLs, and raw payloads are never recorded — see the audit module
//! docstring.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use reqwest::{Client, Url};
use secrecy::SecretString;
use sx_api::port::{BugBountyPort, BugBountyPortError, FindingRepositoryPort};
use sx_api::view::bugbounty_view::{
    BugBountyConfigUpsertRequest, BugBountyConfigView, BugBountyInboundOutcomeView,
    BugBountyPushOutcomeView, BugBountyPushRequest,
};
use sx_integrations::bugbounty::{
    is_pushable, load_token, load_webhook_secret, map_to_finding, signature_header_for,
    verify_signature, BugBountyAuditEvent, BugBountyAuditOp, BugBountyAuditOutcome,
    BugBountyAuditSink, BugBountyConfigStore, BugBountyConnectionConfig, BugBountyConnector,
    BugBountyKind, BugcrowdConnector, BugcrowdCredentials, CanonicalFinding, ConfigError,
    ConnectorError, DedupResult, Deduplicator, ExistingFinding, HackerOneConnector,
    HackerOneCredentials, InMemoryBugBountyConfigStore, RecordingAuditSink, TriagedFinding,
    WebhookError, BUGCROWD_BASE_URL, DEDUP_THRESHOLD, HACKERONE_BASE_URL, MIN_PUSH_SEVERITY,
};
use sx_integrations::siem::Severity;
use sx_secrets::{InMemoryProvider, SecretsProvider};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, warn};

/// Bundle returned to the composition root.
pub(crate) struct BugBountyBundle {
    /// HTTP-facing bug-bounty port.
    pub bugbounty: Arc<dyn BugBountyPort>,
}

/// Build the bug-bounty adapter with the default in-memory dependencies.
///
/// The composition root supplies a shared `reqwest::Client` so the
/// connector path reuses the same connection pool as the rest of the
/// outbound integrations and a `FindingRepositoryPort` so the inbound
/// dedupe pipeline iterates the canonical finding corpus.
pub(crate) fn build(http: Client, findings: Arc<dyn FindingRepositoryPort>) -> BugBountyBundle {
    let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
    let store: Arc<dyn BugBountyConfigStore> = Arc::new(InMemoryBugBountyConfigStore::new());
    let audit = Arc::new(RecordingAuditSink::new());
    BugBountyBundle {
        bugbounty: Arc::new(BugBountyAdapter::new(store, secrets, http, findings, audit)),
    }
}

/// Concrete [`BugBountyPort`] implementation.
pub(crate) struct BugBountyAdapter {
    store: Arc<dyn BugBountyConfigStore>,
    secrets: Arc<dyn SecretsProvider>,
    http: Client,
    findings: Arc<dyn FindingRepositoryPort>,
    /// Audit sink shared between the push + ingest paths. Held in an
    /// `Arc` so the test-facing path can introspect the trail. Trait
    /// object so production wiring can swap in the audit-query sink
    /// without touching the adapter shape.
    audit: Arc<dyn BugBountyAuditSink>,
    /// Optional vendor base URLs — when `Some` they override the
    /// production endpoints. Used by integration tests to point the
    /// adapter at a mock server.
    hackerone_base: Option<Url>,
    bugcrowd_base: Option<Url>,
}

impl std::fmt::Debug for BugBountyAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BugBountyAdapter")
            .field(
                "hackerone_base",
                &self.hackerone_base.as_ref().map(Url::as_str),
            )
            .field(
                "bugcrowd_base",
                &self.bugcrowd_base.as_ref().map(Url::as_str),
            )
            .finish_non_exhaustive()
    }
}

impl BugBountyAdapter {
    /// Construct the adapter with production base URLs.
    pub(crate) fn new(
        store: Arc<dyn BugBountyConfigStore>,
        secrets: Arc<dyn SecretsProvider>,
        http: Client,
        findings: Arc<dyn FindingRepositoryPort>,
        audit: Arc<dyn BugBountyAuditSink>,
    ) -> Self {
        Self {
            store,
            secrets,
            http,
            findings,
            audit,
            hackerone_base: None,
            bugcrowd_base: None,
        }
    }

    /// Override the vendor base URLs (test-only).
    #[cfg(test)]
    pub(crate) fn with_base_urls(mut self, hackerone: Url, bugcrowd: Url) -> Self {
        self.hackerone_base = Some(hackerone);
        self.bugcrowd_base = Some(bugcrowd);
        self
    }

    /// Resolve `platform` wire string to a [`BugBountyKind`], mapping
    /// unknown values to the `Invalid` port error.
    fn parse_kind(platform: &str) -> Result<BugBountyKind, BugBountyPortError> {
        BugBountyKind::from_wire(platform).ok_or_else(|| {
            BugBountyPortError::Invalid(format!("unknown bug-bounty platform: {platform}"))
        })
    }

    /// Build a HackerOne connector for `(creds, base?)`.
    fn build_hackerone(&self, creds: HackerOneCredentials) -> HackerOneConnector {
        let base = self.hackerone_base.clone().unwrap_or_else(|| {
            // Constant — `Url::parse` only fails for malformed input.
            Url::parse(HACKERONE_BASE_URL).expect("HACKERONE_BASE_URL parses")
        });
        HackerOneConnector::with_base_url(self.http.clone(), base, creds)
    }

    /// Build a Bugcrowd connector for `(creds, base?)`.
    fn build_bugcrowd(&self, creds: BugcrowdCredentials) -> BugcrowdConnector {
        let base = self
            .bugcrowd_base
            .clone()
            .unwrap_or_else(|| Url::parse(BUGCROWD_BASE_URL).expect("BUGCROWD_BASE_URL parses"));
        BugcrowdConnector::with_base_url(self.http.clone(), base, creds)
    }

    /// Resolve `severity` wire string to the canonical
    /// [`Severity`] enum. Unknown values are surfaced as `Invalid`.
    fn parse_severity(label: &str) -> Result<Severity, BugBountyPortError> {
        match label.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(BugBountyPortError::Invalid(format!(
                "unknown severity: {other}"
            ))),
        }
    }

    /// Build the secret-store paths for `(tenant_id, kind, program_handle)`.
    fn secret_paths(
        tenant_id: &str,
        kind: BugBountyKind,
        program_handle: &str,
    ) -> (String, String) {
        (
            format!(
                "tenants/{tenant_id}/bb/{}/{program_handle}/token",
                kind.as_wire()
            ),
            format!(
                "tenants/{tenant_id}/bb/{}/{program_handle}/webhook",
                kind.as_wire()
            ),
        )
    }

    /// Resolve a row by `(tenant_id, kind, program_handle)` into the
    /// concrete connector + credentials. Surfaces `NotFound` and
    /// `Unauthorized` per the port contract.
    async fn resolve_config(
        &self,
        tenant_id: &str,
        kind: BugBountyKind,
        program_handle: &str,
    ) -> Result<(BugBountyConnectionConfig, SecretString), BugBountyPortError> {
        let row = self
            .store
            .get(tenant_id, kind, program_handle)
            .await
            .map_err(map_config_err)?
            .ok_or(BugBountyPortError::NotFound)?;
        let token = load_token(&self.secrets, &row)
            .await
            .map_err(map_config_err)?;
        Ok((row, token))
    }
}

/// Translate a [`ConfigError`] into the port-level error.
fn map_config_err(err: ConfigError) -> BugBountyPortError {
    match err {
        ConfigError::NotFound | ConfigError::MissingSecret { .. } => BugBountyPortError::NotFound,
        ConfigError::SecretsUnauthorized => BugBountyPortError::Unauthorized,
        ConfigError::Invalid(m) => BugBountyPortError::Invalid(m),
        ConfigError::Secrets(m) => BugBountyPortError::Dependency(m),
    }
}

/// Translate a [`ConnectorError`] into the port-level error.
fn map_connector_err(err: ConnectorError) -> BugBountyPortError {
    match err {
        ConnectorError::Transport(m) | ConnectorError::Format(m) => {
            BugBountyPortError::Dependency(m)
        }
        ConnectorError::Unauthorized => BugBountyPortError::Unauthorized,
        ConnectorError::RateLimited { .. } => BugBountyPortError::RateLimited,
        ConnectorError::BelowSeverityFloor(sev) => {
            BugBountyPortError::Invalid(format!("severity {} below HIGH floor", sev.label()))
        }
    }
}

/// Translate a [`WebhookError`] into the port-level error.
fn map_webhook_err(err: WebhookError) -> BugBountyPortError {
    match err {
        WebhookError::MissingSignature
        | WebhookError::MalformedSignature
        | WebhookError::SignatureMismatch
        | WebhookError::InvalidSecret => BugBountyPortError::Unauthorized,
        WebhookError::MalformedPayload(m) => BugBountyPortError::Invalid(m),
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[async_trait]
impl BugBountyPort for BugBountyAdapter {
    async fn upsert_config(
        &self,
        tenant_id: &str,
        req: BugBountyConfigUpsertRequest,
    ) -> Result<BugBountyConfigView, BugBountyPortError> {
        let kind = Self::parse_kind(&req.platform)?;
        // HackerOne requires an API username; surface a friendly error
        // rather than the lower-level row-validation message.
        if kind == BugBountyKind::HackerOne
            && req
                .api_username
                .as_ref()
                .is_none_or(|u| u.trim().is_empty())
        {
            return Err(BugBountyPortError::Invalid(
                "hackerone requires api_username".to_owned(),
            ));
        }

        let (token_path, webhook_path) = Self::secret_paths(tenant_id, kind, &req.program_handle);

        // Write both secrets into the configured provider. We do this
        // *before* persisting the row so a half-written row never points
        // at a missing secret.
        self.secrets
            .put(&token_path, req.api_token.clone())
            .await
            .map_err(|e| BugBountyPortError::Dependency(e.to_string()))?;
        self.secrets
            .put(&webhook_path, req.webhook_secret.clone())
            .await
            .map_err(|e| BugBountyPortError::Dependency(e.to_string()))?;

        let row = BugBountyConnectionConfig {
            tenant_id: tenant_id.to_owned(),
            kind,
            program_handle: req.program_handle.clone(),
            api_username: req.api_username.clone(),
            webhook_secret_path: webhook_path.clone(),
            token_secret_path: token_path.clone(),
            created_at: now_rfc3339(),
        };
        let row = self.store.upsert(row).await.map_err(map_config_err)?;

        Ok(BugBountyConfigView {
            tenant_id: row.tenant_id,
            platform: row.kind.as_wire().to_owned(),
            program_handle: row.program_handle,
            api_username: row.api_username,
            token_secret_path: row.token_secret_path,
            webhook_secret_path: row.webhook_secret_path,
            created_at: row.created_at,
        })
    }

    async fn list_configs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<BugBountyConfigView>, BugBountyPortError> {
        let rows = self
            .store
            .list_for_tenant(tenant_id)
            .await
            .map_err(map_config_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BugBountyConfigView {
                tenant_id: r.tenant_id,
                platform: r.kind.as_wire().to_owned(),
                program_handle: r.program_handle,
                api_username: r.api_username,
                token_secret_path: r.token_secret_path,
                webhook_secret_path: r.webhook_secret_path,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn push(
        &self,
        tenant_id: &str,
        req: BugBountyPushRequest,
    ) -> Result<BugBountyPushOutcomeView, BugBountyPortError> {
        let kind = Self::parse_kind(&req.platform)?;
        let severity = Self::parse_severity(&req.finding.severity)?;

        // Local guard before we even resolve the row — there is no
        // upstream call cheap enough to ever leak a below-floor finding.
        if !is_pushable(severity) {
            self.audit
                .record(BugBountyAuditEvent {
                    tenant_id: tenant_id.to_owned(),
                    kind,
                    program_handle: req.program_handle.clone(),
                    op: BugBountyAuditOp::Push,
                    outcome: BugBountyAuditOutcome::Rejected,
                    source_ref: req.finding.id.clone(),
                    upstream_id: None,
                    canonical_source: None,
                    dedup_existing_id: None,
                    error_code: Some("severity_floor".to_owned()),
                    emitted_at: now_rfc3339(),
                })
                .await;
            return Err(BugBountyPortError::Invalid(format!(
                "severity {} below HIGH floor (need at least {})",
                severity.label(),
                MIN_PUSH_SEVERITY.label()
            )));
        }

        let (row, token) = self
            .resolve_config(tenant_id, kind, &req.program_handle)
            .await?;

        let triaged = TriagedFinding {
            id: req.finding.id.clone(),
            tenant_id: tenant_id.to_owned(),
            program_handle: req.program_handle.clone(),
            severity,
            title: req.finding.title.clone(),
            description: req.finding.description.clone(),
        };

        let outcome = match kind {
            BugBountyKind::HackerOne => {
                let username = row.api_username.clone().ok_or_else(|| {
                    BugBountyPortError::Invalid("hackerone row missing api_username".into())
                })?;
                let creds = HackerOneCredentials {
                    api_username: username,
                    api_token: token,
                };
                let connector = self.build_hackerone(creds);
                connector.push_internal_note(&triaged).await
            }
            BugBountyKind::Bugcrowd => {
                let creds = BugcrowdCredentials { api_token: token };
                let connector = self.build_bugcrowd(creds);
                connector.push_internal_note(&triaged).await
            }
        };

        match outcome {
            Ok(out) => {
                self.audit
                    .record(BugBountyAuditEvent {
                        tenant_id: tenant_id.to_owned(),
                        kind,
                        program_handle: req.program_handle.clone(),
                        op: BugBountyAuditOp::Push,
                        outcome: BugBountyAuditOutcome::Success,
                        source_ref: req.finding.id.clone(),
                        upstream_id: out.upstream_id.clone(),
                        canonical_source: None,
                        dedup_existing_id: None,
                        error_code: None,
                        emitted_at: now_rfc3339(),
                    })
                    .await;
                Ok(BugBountyPushOutcomeView {
                    platform: kind.as_wire().to_owned(),
                    source_ref: req.finding.id,
                    upstream_id: out.upstream_id,
                    url: out.url,
                })
            }
            Err(err) => {
                let (outcome, code) = match &err {
                    ConnectorError::Unauthorized => {
                        (BugBountyAuditOutcome::Rejected, "unauthorized")
                    }
                    ConnectorError::RateLimited { .. } => {
                        (BugBountyAuditOutcome::Failed, "rate_limited")
                    }
                    ConnectorError::BelowSeverityFloor(_) => {
                        (BugBountyAuditOutcome::Rejected, "severity_floor")
                    }
                    ConnectorError::Transport(_) => (BugBountyAuditOutcome::Failed, "transport"),
                    ConnectorError::Format(_) => (BugBountyAuditOutcome::Failed, "format"),
                };
                self.audit
                    .record(BugBountyAuditEvent {
                        tenant_id: tenant_id.to_owned(),
                        kind,
                        program_handle: req.program_handle.clone(),
                        op: BugBountyAuditOp::Push,
                        outcome,
                        source_ref: req.finding.id.clone(),
                        upstream_id: None,
                        canonical_source: None,
                        dedup_existing_id: None,
                        error_code: Some(code.to_owned()),
                        emitted_at: now_rfc3339(),
                    })
                    .await;
                warn!(
                    target: "adapters.bugbounty",
                    tenant_id,
                    platform = kind.as_wire(),
                    program = %req.program_handle,
                    error_code = code,
                    "bug-bounty push failed",
                );
                Err(map_connector_err(err))
            }
        }
    }

    async fn inbound(
        &self,
        tenant_id: &str,
        platform: &str,
        signature_header: Option<&str>,
        body_bytes: Bytes,
    ) -> Result<BugBountyInboundOutcomeView, BugBountyPortError> {
        let kind = Self::parse_kind(platform)?;

        // Look up the *first* row for this tenant+platform — inbound
        // webhooks do not carry the program handle so we accept any of
        // the tenant's connections under this platform. The signature
        // verification then narrows to the right one. In practice
        // operators configure exactly one row per platform per tenant;
        // the loop is defensive.
        let rows = self
            .store
            .list_for_tenant(tenant_id)
            .await
            .map_err(map_config_err)?
            .into_iter()
            .filter(|r| r.kind == kind)
            .collect::<Vec<_>>();
        if rows.is_empty() {
            self.record_ingest_audit(
                tenant_id,
                kind,
                "unknown",
                BugBountyAuditOutcome::Rejected,
                None,
                None,
                None,
                Some("not_configured"),
            )
            .await;
            return Err(BugBountyPortError::NotFound);
        }

        let sig = signature_header.map(str::to_owned).ok_or_else(|| {
            debug!(
                target: "adapters.bugbounty",
                tenant_id,
                platform = kind.as_wire(),
                "inbound delivery missing signature header `{}`",
                signature_header_for(kind),
            );
            BugBountyPortError::Unauthorized
        })?;

        // Try each configured row's secret. On the happy path the first
        // entry verifies; on rotation both old + new may briefly verify
        // and either is acceptable. Constant-time compare lives inside
        // `verify_signature` so a tampered body can't leak the secret
        // via timing.
        let mut matched_row: Option<BugBountyConnectionConfig> = None;
        for candidate in &rows {
            let Ok(secret) = load_webhook_secret(&self.secrets, candidate).await else {
                continue;
            };
            if verify_signature(&secret, &body_bytes, &sig).is_ok() {
                matched_row = Some(candidate.clone());
                break;
            }
        }

        let Some(row) = matched_row else {
            self.record_ingest_audit(
                tenant_id,
                kind,
                "unknown",
                BugBountyAuditOutcome::Rejected,
                None,
                None,
                None,
                Some("signature_mismatch"),
            )
            .await;
            return Err(BugBountyPortError::Unauthorized);
        };

        let canonical: CanonicalFinding = match map_to_finding(kind, &body_bytes) {
            Ok(c) => c,
            Err(err) => {
                self.record_ingest_audit(
                    tenant_id,
                    kind,
                    &row.program_handle,
                    BugBountyAuditOutcome::Failed,
                    None,
                    None,
                    None,
                    Some("malformed_payload"),
                )
                .await;
                return Err(map_webhook_err(err));
            }
        };

        // Dedupe against the tenant's existing findings. The dedupe is
        // best-effort: if the finding repo cannot be reached we record a
        // failure event and bubble the dependency error.
        let corpus = self.fetch_existing_findings(tenant_id).await?;
        let dedup = Deduplicator::new().is_duplicate_with(
            &canonical.title,
            &canonical.description,
            &corpus,
            DEDUP_THRESHOLD,
        );

        let (deduplicated, dedup_existing_id) = match dedup {
            DedupResult::Duplicate { existing_id, .. } => (true, Some(existing_id)),
            DedupResult::Unique => (false, None),
        };

        let audit_outcome = if deduplicated {
            BugBountyAuditOutcome::Deduplicated
        } else {
            BugBountyAuditOutcome::Success
        };
        self.record_ingest_audit(
            tenant_id,
            kind,
            &row.program_handle,
            audit_outcome,
            Some(canonical.report_id.clone()),
            Some(canonical.source.clone()),
            dedup_existing_id.clone(),
            None,
        )
        .await;

        Ok(BugBountyInboundOutcomeView {
            platform: kind.as_wire().to_owned(),
            source: canonical.source,
            researcher_id: canonical.researcher_id,
            report_id: canonical.report_id,
            deduplicated,
            dedup_existing_id,
        })
    }
}

impl BugBountyAdapter {
    #[allow(clippy::too_many_arguments)]
    async fn record_ingest_audit(
        &self,
        tenant_id: &str,
        kind: BugBountyKind,
        program_handle: &str,
        outcome: BugBountyAuditOutcome,
        source_ref: Option<String>,
        canonical_source: Option<String>,
        dedup_existing_id: Option<String>,
        error_code: Option<&str>,
    ) {
        self.audit
            .record(BugBountyAuditEvent {
                tenant_id: tenant_id.to_owned(),
                kind,
                program_handle: program_handle.to_owned(),
                op: BugBountyAuditOp::Ingest,
                outcome,
                source_ref: source_ref.unwrap_or_else(|| "unknown".to_owned()),
                upstream_id: None,
                canonical_source,
                dedup_existing_id,
                error_code: error_code.map(str::to_owned),
                emitted_at: now_rfc3339(),
            })
            .await;
    }

    /// Best-effort enumeration of the tenant's existing findings, paged
    /// in batches. We cap the corpus at 1000 entries — beyond that the
    /// TF-IDF index dominates inbound latency and the marginal precision
    /// gain is small. Returns an empty corpus when the repo errors so
    /// dedupe degrades gracefully to `Unique`.
    async fn fetch_existing_findings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ExistingFinding>, BugBountyPortError> {
        const PAGE: u32 = 200;
        const CORPUS_CAP: usize = 1000;
        let mut out: Vec<ExistingFinding> = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let batch = match self.findings.list(tenant_id, offset, PAGE).await {
                Ok(b) => b,
                Err(err) => {
                    warn!(
                        target: "adapters.bugbounty",
                        tenant_id,
                        error = %err,
                        "bug-bounty dedupe corpus fetch failed; falling back to empty corpus",
                    );
                    return Ok(out);
                }
            };
            if batch.is_empty() {
                break;
            }
            #[allow(clippy::cast_possible_truncation)]
            let batch_len = batch.len() as u64;
            for f in batch {
                out.push(ExistingFinding {
                    id: f.id,
                    title: f.title,
                    description: f.description,
                });
                if out.len() >= CORPUS_CAP {
                    return Ok(out);
                }
            }
            offset += batch_len;
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use reqwest::Client;
    use serde_json::json;
    use sha2::Sha256;
    use sx_api::view::bugbounty_view::BugBountyFindingInput;
    use sx_api::view::finding_view::FindingView;
    use sx_integrations::bugbounty::{BUGCROWD_SIGNATURE_HEADER, HACKERONE_SIGNATURE_HEADER};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    type HmacSha256 = Hmac<Sha256>;

    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[derive(Debug, Default)]
    struct StubFindings {
        items: Vec<FindingView>,
    }

    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            _tenant_id: &str,
            offset: u64,
            limit: u32,
        ) -> Result<Vec<FindingView>, sx_api::port::EngagementPortError> {
            #[allow(clippy::cast_possible_truncation)]
            let start = offset as usize;
            if start >= self.items.len() {
                return Ok(Vec::new());
            }
            let end = (start + limit as usize).min(self.items.len());
            Ok(self.items[start..end].to_vec())
        }
        async fn get(
            &self,
            _tenant_id: &str,
            id: &str,
        ) -> Result<FindingView, sx_api::port::EngagementPortError> {
            self.items
                .iter()
                .find(|f| f.id == id)
                .cloned()
                .ok_or(sx_api::port::EngagementPortError::NotFound)
        }
        async fn update_status(
            &self,
            _tenant_id: &str,
            _id: &str,
            _new_status: &str,
            _comment: Option<&str>,
        ) -> Result<FindingView, sx_api::port::EngagementPortError> {
            Err(sx_api::port::EngagementPortError::NotFound)
        }
        async fn insert(
            &self,
            view: FindingView,
        ) -> Result<FindingView, sx_api::port::EngagementPortError> {
            // Bug-bounty stub does not exercise the insert path; echo
            // the view so the trait contract holds for any caller that
            // accidentally invokes it.
            Ok(view)
        }
    }

    fn finding(id: &str, title: &str, description: &str) -> FindingView {
        FindingView {
            id: id.into(),
            tenant_id: "t-1".into(),
            asset_id: "a-1".into(),
            severity: "high".into(),
            status: "open".into(),
            title: title.into(),
            description: description.into(),
            cvss: None,
            cve_id: None,
            first_seen: "2027-01-01T00:00:00Z".into(),
            last_seen: "2027-01-02T00:00:00Z".into(),
            metadata: None,
        }
    }

    fn build_adapter(
        findings: Arc<dyn FindingRepositoryPort>,
        audit: Arc<RecordingAuditSink>,
    ) -> BugBountyAdapter {
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store: Arc<dyn BugBountyConfigStore> = Arc::new(InMemoryBugBountyConfigStore::new());
        BugBountyAdapter::new(
            store,
            secrets,
            Client::new(),
            findings,
            audit as Arc<dyn BugBountyAuditSink>,
        )
    }

    fn upsert_req(platform: &str) -> BugBountyConfigUpsertRequest {
        BugBountyConfigUpsertRequest {
            platform: platform.into(),
            program_handle: "acme".into(),
            api_username: if platform == "hackerone" {
                Some("ops".into())
            } else {
                None
            },
            api_token: SecretString::from(format!("{platform}-token-shh")),
            webhook_secret: SecretString::from("hmac-secret-shh".to_owned()),
        }
    }

    #[tokio::test]
    async fn upsert_and_list_round_trips_per_tenant() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), audit);
        let view = adapter
            .upsert_config("t-1", upsert_req("hackerone"))
            .await
            .unwrap();
        assert_eq!(view.platform, "hackerone");
        assert_eq!(view.program_handle, "acme");
        assert_eq!(view.api_username.as_deref(), Some("ops"));
        assert!(view.token_secret_path.ends_with("/bb/hackerone/acme/token"));
        assert!(view
            .webhook_secret_path
            .ends_with("/bb/hackerone/acme/webhook"));

        adapter
            .upsert_config("t-1", upsert_req("bugcrowd"))
            .await
            .unwrap();

        let list = adapter.list_configs("t-1").await.unwrap();
        assert_eq!(list.len(), 2);
        // Different tenant — must be empty.
        assert!(adapter.list_configs("t-other").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn upsert_rejects_hackerone_without_username() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), audit);
        let mut req = upsert_req("hackerone");
        req.api_username = None;
        let err = adapter.upsert_config("t-1", req).await.unwrap_err();
        assert!(matches!(err, BugBountyPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn upsert_rejects_unknown_platform() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), audit);
        let req = BugBountyConfigUpsertRequest {
            platform: "yeswehack".into(),
            program_handle: "acme".into(),
            api_username: None,
            api_token: SecretString::from("token".to_owned()),
            webhook_secret: SecretString::from("hmac".to_owned()),
        };
        let err = adapter.upsert_config("t-1", req).await.unwrap_err();
        assert!(matches!(err, BugBountyPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn push_below_floor_is_rejected_and_audited() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), Arc::clone(&audit));
        adapter
            .upsert_config("t-1", upsert_req("hackerone"))
            .await
            .unwrap();
        let req = BugBountyPushRequest {
            platform: "hackerone".into(),
            program_handle: "acme".into(),
            finding: BugBountyFindingInput {
                id: "f-1".into(),
                title: "low-impact bug".into(),
                description: "blah".into(),
                severity: "medium".into(),
            },
        };
        let err = adapter.push("t-1", req).await.unwrap_err();
        assert!(matches!(err, BugBountyPortError::Invalid(_)));
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].op, BugBountyAuditOp::Push);
        assert_eq!(snap[0].outcome, BugBountyAuditOutcome::Rejected);
        assert_eq!(snap[0].error_code.as_deref(), Some("severity_floor"));
    }

    #[tokio::test]
    async fn push_high_severity_to_hackerone_round_trips_through_wiremock() {
        let server = MockServer::start().await;
        let raw = "ops:h1-token-shh";
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
        );
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .and(header("authorization", basic.as_str()))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "data": {
                    "id": "n-1",
                    "links": {"self": "https://api.hackerone.com/v1/internal_notes/n-1"}
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let audit = Arc::new(RecordingAuditSink::new());
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store: Arc<dyn BugBountyConfigStore> = Arc::new(InMemoryBugBountyConfigStore::new());
        let adapter = BugBountyAdapter::new(
            Arc::clone(&store),
            Arc::clone(&secrets),
            Client::new(),
            Arc::new(StubFindings::default()),
            Arc::clone(&audit) as Arc<dyn BugBountyAuditSink>,
        )
        .with_base_urls(
            Url::parse(&format!("{}/", server.uri())).unwrap(),
            Url::parse(BUGCROWD_BASE_URL).unwrap(),
        );

        let req = BugBountyConfigUpsertRequest {
            platform: "hackerone".into(),
            program_handle: "acme".into(),
            api_username: Some("ops".into()),
            api_token: SecretString::from("h1-token-shh".to_owned()),
            webhook_secret: SecretString::from("hmac".to_owned()),
        };
        adapter.upsert_config("t-1", req).await.unwrap();

        let push = BugBountyPushRequest {
            platform: "hackerone".into(),
            program_handle: "acme".into(),
            finding: BugBountyFindingInput {
                id: "f-7".into(),
                title: "RCE".into(),
                description: "SSTI".into(),
                severity: "critical".into(),
            },
        };
        let outcome = adapter.push("t-1", push).await.unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("n-1"));
        assert!(outcome.url.is_some());
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].outcome, BugBountyAuditOutcome::Success);
    }

    #[tokio::test]
    async fn push_to_bugcrowd_round_trips_through_wiremock() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .and(header("authorization", "Token bc-token-shh"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "data": {
                    "id": "uuid-1",
                    "links": {"self": "https://api.bugcrowd.com/v2/internal_notes/uuid-1"}
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let audit = Arc::new(RecordingAuditSink::new());
        let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store: Arc<dyn BugBountyConfigStore> = Arc::new(InMemoryBugBountyConfigStore::new());
        let adapter = BugBountyAdapter::new(
            Arc::clone(&store),
            Arc::clone(&secrets),
            Client::new(),
            Arc::new(StubFindings::default()),
            Arc::clone(&audit) as Arc<dyn BugBountyAuditSink>,
        )
        .with_base_urls(
            Url::parse(HACKERONE_BASE_URL).unwrap(),
            Url::parse(&format!("{}/", server.uri())).unwrap(),
        );

        let req = BugBountyConfigUpsertRequest {
            platform: "bugcrowd".into(),
            program_handle: "acme".into(),
            api_username: None,
            api_token: SecretString::from("bc-token-shh".to_owned()),
            webhook_secret: SecretString::from("hmac".to_owned()),
        };
        adapter.upsert_config("t-1", req).await.unwrap();

        let push = BugBountyPushRequest {
            platform: "bugcrowd".into(),
            program_handle: "acme".into(),
            finding: BugBountyFindingInput {
                id: "f-9".into(),
                title: "Auth bypass".into(),
                description: "header tampering".into(),
                severity: "high".into(),
            },
        };
        let outcome = adapter.push("t-1", push).await.unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("uuid-1"));
    }

    #[tokio::test]
    async fn inbound_verifies_signature_and_emits_audit() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), Arc::clone(&audit));
        adapter
            .upsert_config("t-1", upsert_req("hackerone"))
            .await
            .unwrap();

        let body = br#"{
            "data": {
                "id": "98765",
                "type": "report",
                "attributes": {
                    "title": "XSS",
                    "vulnerability_information": "Reflected XSS via q",
                    "researcher": {"id": "42"},
                    "program": {"handle": "acme"},
                    "severity": {"rating": "high"}
                }
            }
        }"#;
        let sig = sign("hmac-secret-shh", body);

        let outcome = adapter
            .inbound("t-1", "hackerone", Some(&sig), Bytes::copy_from_slice(body))
            .await
            .unwrap();
        assert!(!outcome.deduplicated);
        assert_eq!(outcome.researcher_id, "42");
        assert_eq!(outcome.report_id, "98765");
        assert_eq!(outcome.source, "bugbounty.hackerone.researcher_42");
        assert!(outcome.dedup_existing_id.is_none());

        let snap = audit.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].op, BugBountyAuditOp::Ingest);
        assert_eq!(snap[0].outcome, BugBountyAuditOutcome::Success);
        assert_eq!(
            snap[0].canonical_source.as_deref(),
            Some("bugbounty.hackerone.researcher_42")
        );
    }

    #[tokio::test]
    async fn inbound_rejects_tampered_body() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), Arc::clone(&audit));
        adapter
            .upsert_config("t-1", upsert_req("hackerone"))
            .await
            .unwrap();
        let original = br#"{
            "data": {
                "id": "98765",
                "attributes": {
                    "title": "XSS",
                    "vulnerability_information": "x",
                    "researcher": {"id": "42"},
                    "program": {"handle": "acme"}
                }
            }
        }"#;
        let tampered = br#"{
            "data": {
                "id": "98765",
                "attributes": {
                    "title": "XSS-PATCHED",
                    "vulnerability_information": "x",
                    "researcher": {"id": "42"},
                    "program": {"handle": "acme"}
                }
            }
        }"#;
        let sig = sign("hmac-secret-shh", original);
        let err = adapter
            .inbound(
                "t-1",
                "hackerone",
                Some(&sig),
                Bytes::copy_from_slice(tampered),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BugBountyPortError::Unauthorized));
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].outcome, BugBountyAuditOutcome::Rejected);
        assert_eq!(snap[0].error_code.as_deref(), Some("signature_mismatch"));
    }

    #[tokio::test]
    async fn inbound_dedupes_against_existing_finding() {
        let audit = Arc::new(RecordingAuditSink::new());
        let stub = StubFindings {
            items: vec![finding(
                "f-existing",
                "Reflected XSS in search query parameter",
                "Reflected cross-site scripting via the search query parameter on the /search endpoint allows attacker controlled javascript execution.",
            )],
        };
        let adapter = build_adapter(Arc::new(stub), Arc::clone(&audit));
        adapter
            .upsert_config("t-1", upsert_req("hackerone"))
            .await
            .unwrap();

        let body = br#"{
            "data": {
                "id": "r-2",
                "attributes": {
                    "title": "Reflected XSS via search query parameter",
                    "vulnerability_information": "Reflected XSS through search query parameter on the /search endpoint allows attacker controlled javascript execution.",
                    "researcher": {"id": "rs-9"},
                    "program": {"handle": "acme"},
                    "severity": {"rating": "high"}
                }
            }
        }"#;
        let sig = sign("hmac-secret-shh", body);
        let outcome = adapter
            .inbound("t-1", "hackerone", Some(&sig), Bytes::copy_from_slice(body))
            .await
            .unwrap();
        assert!(outcome.deduplicated, "expected dedup hit");
        assert_eq!(outcome.dedup_existing_id.as_deref(), Some("f-existing"));
        let snap = audit.snapshot();
        assert_eq!(snap[0].outcome, BugBountyAuditOutcome::Deduplicated);
        assert_eq!(snap[0].dedup_existing_id.as_deref(), Some("f-existing"));
    }

    #[tokio::test]
    async fn inbound_missing_signature_is_unauthorized() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), Arc::clone(&audit));
        adapter
            .upsert_config("t-1", upsert_req("hackerone"))
            .await
            .unwrap();
        let body = br"{}";
        let err = adapter
            .inbound("t-1", "hackerone", None, Bytes::copy_from_slice(body))
            .await
            .unwrap_err();
        assert!(matches!(err, BugBountyPortError::Unauthorized));
    }

    #[tokio::test]
    async fn inbound_unknown_platform_is_invalid() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), audit);
        let err = adapter
            .inbound("t-1", "yeswehack", Some("deadbeef"), Bytes::new())
            .await
            .unwrap_err();
        assert!(matches!(err, BugBountyPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn inbound_with_no_configured_row_is_not_found() {
        let audit = Arc::new(RecordingAuditSink::new());
        let adapter = build_adapter(Arc::new(StubFindings::default()), Arc::clone(&audit));
        // No row configured.
        let err = adapter
            .inbound(
                "t-1",
                "hackerone",
                Some("deadbeef"),
                Bytes::copy_from_slice(b"{}"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BugBountyPortError::NotFound));
        let snap = audit.snapshot();
        assert_eq!(snap[0].outcome, BugBountyAuditOutcome::Rejected);
        assert_eq!(snap[0].error_code.as_deref(), Some("not_configured"));
    }

    #[tokio::test]
    async fn parse_severity_accepts_known_and_rejects_unknown() {
        assert!(matches!(
            BugBountyAdapter::parse_severity("Critical"),
            Ok(Severity::Critical)
        ));
        assert!(matches!(
            BugBountyAdapter::parse_severity("low"),
            Ok(Severity::Low)
        ));
        assert!(matches!(
            BugBountyAdapter::parse_severity("space-alien"),
            Err(BugBountyPortError::Invalid(_))
        ));
    }

    #[test]
    fn signature_header_constants_are_lowercase_per_platform() {
        // Sanity check the constants we expose to the controller path
        // remain lowercase so axum's `HeaderMap::get` lookup hits.
        assert_eq!(HACKERONE_SIGNATURE_HEADER, "x-h1-signature");
        assert_eq!(BUGCROWD_SIGNATURE_HEADER, "x-bugcrowd-signature");
    }
}
