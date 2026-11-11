//! Local trait abstractions ("ports") the HTTP layer depends on.
//!
//! Each port mirrors a use case or repository from a sibling crate. The API
//! layer never imports the concrete type; it accepts a trait object instead.
//! Concrete implementations are wired up at the composition root
//! (`services/sx-monolith`) and the lifetime of each implementation is
//! managed via `Arc`.
//!
//! ## Why a port layer
//!
//! Sibling crates (`sx-iam`, `sx-engagement`, …) are still being scaffolded
//! by other agents. Some of their concrete use-case types are not yet
//! published. Declaring a thin trait here means the API crate can compile,
//! lint, and unit-test independently — and when the sibling crates land,
//! they only need to provide a single `impl` block.
//!
//! ## Error contract
//!
//! Every port returns its own crate's error type (`IamError`,
//! `EngagementError`, …). Controllers translate those into [`ApiError`]
//! via dedicated `map_*` helpers in [`crate::controller`].

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sx_iam::IamError;

use crate::view::admin_view::{CreateUserRequestView, CreateUserResponseView};
use crate::view::auth_view::TokenView;
use crate::view::bas_view::{
    ApprovalView, BasRunRequestView, BasRunResponseView, RecordApprovalRequest,
};
use crate::view::blast_radius_view::BlastRadiusResponseView;
use crate::view::cloud_view::{CloudInventoryRequestView, CloudInventoryResponseView};
use crate::view::collab_view::{
    CollabAllocateTokenRequestView, CollabAllocateTokenResponseView, CollabCallbacksResponseView,
};
use crate::view::compliance_view::{
    ComplianceFrameworkResponseView, ComplianceMapRequestView, ComplianceMapResponseView,
};
use crate::view::engagement_view::{
    CloneEngagementRequest, CreateEngagementView, EngagementView, UpdateEngagementView,
};
use crate::view::finding_view::FindingView;
use crate::view::graph_view::{GraphAttackPathsRequestView, GraphAttackPathsResponseView};
use crate::view::ml_view::{MlTriagePredictRequestView, MlTriagePredictResponseView};
use crate::view::remediation_view::{
    RemediationAdvisoriesRequestView, RemediationAdvisoriesResponseView,
};
use crate::view::report_view::{
    ReportDiffRequestView, ReportDiffResponseView, ReportRenderRequestView,
    ReportRenderResponseView,
};
use crate::view::risk_view::{
    CalculateEngagementRiskRequest, CalculateRiskRequest, CalculateRiskView,
    EngagementRiskBreakdownView,
};

/// Reasoning for a kill-switch trip — recorded on the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchTrigger {
    /// Operator user id (uuid).
    pub actor: String,
    /// Human-readable reason.
    pub reason: String,
}

/// Generic error returned by the engagement port.
///
/// Sibling crates expose richer errors; we collapse them into this enum so
/// the HTTP mapping stays in one place.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EngagementPortError {
    /// Resource does not exist.
    #[error("not found")]
    NotFound,
    /// Caller is not allowed to perform the action.
    #[error("forbidden")]
    Forbidden,
    /// Request collides with the resource's current state.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Business validation failed.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Dependency (db, etc.) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Generic error returned by the risk port.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RiskPortError {
    /// Engagement not found.
    #[error("not found")]
    NotFound,
    /// Invalid request.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

/// Generic error returned by the discovery port.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DiscoveryPortError {
    /// Engagement does not exist or kill switch is on.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Invalid request.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

/// Authentication input passed to [`AuthenticateUserPort::authenticate`].
#[derive(Debug)]
pub struct AuthenticateUserInput {
    /// Tenant uuid as a string (the IAM layer parses it).
    pub tenant_id: String,
    /// Email.
    pub email: String,
    /// Plaintext password (never logged).
    pub password: SecretString,
    /// Caller IP — populated by the login controller from
    /// `X-Forwarded-For` / `X-Real-IP`. `None` when the platform
    /// cannot read either header; downstream RBA evaluation falls
    /// back to a 0.0.0.0 sentinel in that case.
    pub ip: Option<String>,
    /// Caller `User-Agent` — hashed by the RBA adapter into the
    /// `device_fingerprint` signal. `None` when the header is absent.
    pub user_agent: Option<String>,
}

/// Issues an access/refresh token pair for an authenticated user.
#[async_trait]
pub trait AuthenticateUserPort: Send + Sync {
    /// Authenticate + issue a fresh token pair.
    async fn authenticate(&self, input: AuthenticateUserInput) -> Result<TokenView, IamError>;
}

/// Validates a bearer access token. Returns the decoded claims.
#[async_trait]
pub trait ValidateTokenPort: Send + Sync {
    /// Parse + cryptographically verify `token`. Returns the claims on
    /// success.
    async fn validate(&self, token: &str) -> Result<sx_iam::model::claims::AccessClaims, IamError>;
}

/// Refreshes an access token using a refresh token.
#[async_trait]
pub trait RefreshTokenPort: Send + Sync {
    /// Exchange a refresh token for a new token pair.
    async fn refresh(&self, refresh_token: &str) -> Result<TokenView, IamError>;
}

/// Exchanges an external OIDC `id_token` for an SX-internal token pair.
///
/// Backed by `sx_iam::ExchangeOidcUseCase` in production; a stub in
/// monolith builds where OIDC is disabled (which returns
/// [`Phase3PortError::Invalid("OIDC disabled")`]).
#[async_trait]
pub trait OidcExchangePort: Send + Sync {
    /// Validate `id_token` against the configured IdP and issue an
    /// SX-internal access + refresh token pair.
    async fn exchange(
        &self,
        req: crate::view::auth_view::OidcExchangeRequest,
    ) -> Result<TokenView, Phase3PortError>;
}

/// Revokes a session (logout).
#[async_trait]
pub trait LogoutPort: Send + Sync {
    /// Mark the session identified by `jti` as revoked.
    async fn revoke(&self, jti: &str) -> Result<(), IamError>;
}

/// Engagement-management use cases.
#[async_trait]
pub trait EngagementServicePort: Send + Sync {
    /// Create a new engagement bound to `tenant_id`.
    async fn create(
        &self,
        tenant_id: &str,
        req: CreateEngagementView,
    ) -> Result<EngagementView, EngagementPortError>;

    /// List engagements in `tenant_id`.
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<EngagementView>, EngagementPortError>;

    /// Fetch a single engagement by id.
    async fn get(&self, tenant_id: &str, id: &str) -> Result<EngagementView, EngagementPortError>;

    /// Patch an engagement.
    async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        req: UpdateEngagementView,
    ) -> Result<EngagementView, EngagementPortError>;
}

/// Kill-switch — flips the global "stop all scans" bit.
#[async_trait]
pub trait KillSwitchPort: Send + Sync {
    /// Trip the kill switch. The implementation is responsible for
    /// recording the audit event.
    async fn trip(&self, trigger: KillSwitchTrigger) -> Result<(), EngagementPortError>;

    /// Return whether the kill switch is currently engaged.
    async fn is_tripped(&self) -> Result<bool, EngagementPortError>;
}

/// Risk-calculation use case.
#[async_trait]
pub trait CalculateRiskPort: Send + Sync {
    /// Run the composite risk calculation for the given input.
    async fn calculate(
        &self,
        req: CalculateRiskRequest,
    ) -> Result<CalculateRiskView, RiskPortError>;

    /// Aggregate composite scores across every finding in `tenant_id` that
    /// is linked to a CVE.
    ///
    /// Behaviour is parameterised by `req` (see
    /// [`CalculateEngagementRiskRequest`]):
    /// - `include_unscored = true` counts CVE-less findings against
    ///   `total_findings`,
    /// - `top_n` caps the size of the `top` vector.
    ///
    /// The implementation MUST page through the finding repository to
    /// cover every row in the tenant.
    async fn calculate_engagement(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        req: CalculateEngagementRiskRequest,
    ) -> Result<EngagementRiskBreakdownView, RiskPortError>;
}

/// Discovery-run use case.
#[async_trait]
pub trait RunDiscoveryPort: Send + Sync {
    /// Kick off a discovery run for `engagement_id`. Returns the run id.
    async fn run(&self, tenant_id: &str, engagement_id: &str)
        -> Result<String, DiscoveryPortError>;
}

/// Asset read-side repository (controllers only read).
#[async_trait]
pub trait AssetRepositoryPort: Send + Sync {
    /// List assets in a tenant.
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<crate::view::asset_view::AssetView>, EngagementPortError>;

    /// Fetch a single asset.
    async fn get(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<crate::view::asset_view::AssetView, EngagementPortError>;
}

/// Finding repository (read + status update + service-internal insert).
///
/// The [`Self::insert`] method (FOUND-001) lets system-internal emitters
/// — the canonical webapp DAST scanner, the SAML SP attack observer
/// (TOP5-#3-P2-004), the cloud-drift watcher — push synthetic findings
/// into the same store the human-facing `/v1/findings/*` surface reads.
#[async_trait]
pub trait FindingRepositoryPort: Send + Sync {
    /// List findings in a tenant.
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError>;

    /// Fetch a single finding.
    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError>;

    /// Update finding status.
    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        new_status: &str,
        comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError>;

    /// Persist a new finding. Returns the persisted view (with any
    /// server-assigned fields populated).
    ///
    /// # Surface
    ///
    /// This entry point is **service-internal** — it is consumed by
    /// emitters that materialise synthetic findings inside the platform
    /// (audit-chain break detector via TOP5-#3-P2-007, log-ingest rate
    /// limiter via TOP5-#3-P2-008, the SAML SP attack observer via
    /// TOP5-#3-P2-004, etc.). It is *not* exposed through any public
    /// HTTP route; external callers create findings through dedicated
    /// controllers / ingestion pipelines that funnel through the same
    /// adapter underneath.
    ///
    /// # Idempotency contract
    ///
    /// Implementations MAY treat `(tenant_id, view.id)` as a uniqueness
    /// key and silently no-op on conflict, returning the already-persisted
    /// view rather than an [`EngagementPortError::Conflict`]. This lets
    /// emitters that re-fire — the chain-verifier on a repeated break
    /// detection, the rate-limiter within its dedup window, the SAML
    /// attack observer collapsing a day's worth of XSW attempts — call
    /// `insert` without first probing `get`.
    ///
    /// Implementations MUST document their behaviour:
    /// - The Postgres adapter relies on the `findings.id` PRIMARY KEY and
    ///   uses `ON CONFLICT (id) DO NOTHING RETURNING …`; a re-insert with
    ///   the same `(tenant_id, id)` re-reads the existing row.
    /// - The in-memory adapter overwrites the existing entry on a key
    ///   collision — the last write wins. Emitters that need
    ///   "first-write-wins" semantics MUST probe `get` first.
    ///
    /// # Errors
    ///
    /// - [`EngagementPortError::Invalid`] — `view.id` / `view.tenant_id`
    ///   / `view.asset_id` are not parseable UUIDs (Postgres adapter
    ///   only).
    /// - [`EngagementPortError::Dependency`] — backing store is
    ///   unreachable.
    /// - [`EngagementPortError::Internal`] — programming-time invariant
    ///   violated (lock poisoning in-memory; row-decode failure in
    ///   Postgres).
    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError>;
}

/// Tenant repository — used for `/v1/tenants/me` and `/v1/admin/tenants`.
#[async_trait]
pub trait TenantRepositoryPort: Send + Sync {
    /// Fetch a tenant projection by id.
    async fn get(&self, id: &str) -> Result<TenantSummaryView, EngagementPortError>;

    /// List tenant projections newest-first, paged via `(limit, offset)`.
    ///
    /// Default implementation returns an empty vector so existing adapter
    /// types stay source-compatible. Adapters that have a backing store
    /// should override this with a real `SELECT … LIMIT $1 OFFSET $2`.
    async fn list_tenants(
        &self,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<TenantSummaryView>, EngagementPortError> {
        let _ = (limit, offset);
        Ok(Vec::new())
    }
}

/// Tenant projection on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSummaryView {
    /// Tenant uuid.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Slug used in URLs.
    pub slug: String,
    /// Whether the tenant is active.
    pub is_active: bool,
}

/// Convenience alias used across [`crate::state::AppState`].
pub type Shared<T> = Arc<T>;

// ---------------------------------------------------------------------------
// Phase-3 ports
// ---------------------------------------------------------------------------

/// Shared error type returned by all Phase-3 ports.
///
/// Sibling crates expose richer error types (`BasError`, `GraphError`,
/// `ReportError`, …). We collapse them into a single enum here so the HTTP
/// translation lives in exactly one place (see
/// [`crate::controller::map_phase3`]).
#[derive(Debug, Clone, thiserror::Error)]
pub enum Phase3PortError {
    /// Resource (model, framework, technique, …) does not exist.
    #[error("not found")]
    NotFound,
    /// Caller is not permitted to perform the action.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Business validation failed (bad mode, unparseable category, …).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Dependency (storage, queue, intel feed, …) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Breach-and-Attack-Simulation run-execution port.
///
/// At this layer the orchestrator only ever asks for `Theoretical` runs —
/// higher modes traverse a separate approval pipeline before they reach the
/// HTTP surface.
#[async_trait]
pub trait BasRunPort: Send + Sync {
    /// Execute a BAS run with the requested technique and mode.
    async fn run(&self, req: BasRunRequestView) -> Result<BasRunResponseView, Phase3PortError>;
}

/// HTTP-header scanner port.
///
/// Runs a passive external probe against `target` (security-headers, TLS
/// hint, server fingerprint), records the resulting `ScanRecord`, and
/// returns it. The same record is queryable via [`Self::list`] so the
/// dashboard can render persistent scan history.
#[async_trait]
pub trait HttpHeaderScannerPort: Send + Sync {
    /// Probe `target` and persist the resulting record. Tenant + caller
    /// stamping is the controller's job — the port just receives the
    /// fully-resolved record skeleton from the controller.
    async fn run(
        &self,
        req: crate::view::scan_view::HttpHeaderScanRequest,
        tenant_id: String,
    ) -> Result<crate::view::scan_view::ScanRecord, Phase3PortError>;

    /// List recorded scans newest-first. When `engagement_id` is `Some`,
    /// only entries with a matching engagement context are returned.
    async fn list(
        &self,
        engagement_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::view::scan_view::ScanRecord>, Phase3PortError>;

    /// Fetch a single recorded scan by id, scoped to the caller's tenant.
    ///
    /// Returns `Ok(None)` when the id does not exist (the caller maps that
    /// to HTTP 404) or when the record exists but belongs to a different
    /// tenant — the adapter MUST enforce tenant isolation here so SARIF
    /// export cannot bypass row-level scoping. Backs the
    /// `GET /v1/scans/{id}.sarif` endpoint added in TOP5-#3-P2-SARIF-API.
    async fn get(
        &self,
        tenant_id: &str,
        scan_id: &str,
    ) -> Result<Option<crate::view::scan_view::ScanRecord>, Phase3PortError>;
}

/// Persistent BAS run-history port.
///
/// Backs `GET /v1/bas/runs` so operators can audit what was executed
/// across reloads. The controller calls `record` from inside
/// `POST /v1/bas/run` immediately after the orchestrator returns, so a
/// failure to record is logged but never blocks the run itself.
#[async_trait]
pub trait BasRunHistoryPort: Send + Sync {
    /// Persist a single run entry. Implementations are expected to be
    /// idempotent on `simulation_id` (re-recording the same id is a no-op).
    async fn record(
        &self,
        entry: crate::view::bas_view::BasRunHistoryView,
    ) -> Result<(), Phase3PortError>;

    /// List runs, newest-first. When `engagement_id` is `Some`, only
    /// entries with a matching `engagement_id` are returned. `limit` is
    /// clamped by the controller and the adapter — at minimum the adapter
    /// MUST cap at 1000 entries to avoid unbounded responses.
    async fn list(
        &self,
        engagement_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::view::bas_view::BasRunHistoryView>, Phase3PortError>;
}

/// Lateral-movement chain replay port (P2-015).
///
/// Backs `GET /v1/bas/chains`, `POST /v1/bas/chains/{id}/run`, and
/// `GET /v1/bas/chains/runs/{id}`. The adapter is responsible for:
///
/// - Listing the pre-canned chain catalogue (`list_catalogue`).
/// - Starting a run for a given chain (`start_run`) — this MUST go through
///   the BAS safety pipeline and re-use the existing
///   [`ApprovalPort`] count-distinct-approvers check.
/// - Looking up a recorded run by `run_id` (`get_run`).
///
/// The HTTP layer enforces tenant scoping; the adapter persists each run
/// with its tenant id and audit-stamps every transition.
#[async_trait]
pub trait BasChainPort: Send + Sync {
    /// Return the canonical chain catalogue.
    async fn list_catalogue(
        &self,
    ) -> Result<Vec<crate::view::bas_view::LateralChainView>, Phase3PortError>;

    /// Start a run for `chain_id` under `tenant_id` and persist the result.
    async fn start_run(
        &self,
        tenant_id: String,
        chain_id: String,
        req: crate::view::bas_view::StartChainRunRequest,
    ) -> Result<crate::view::bas_view::ChainRunView, Phase3PortError>;

    /// Look up a recorded run by `run_id` scoped to `tenant_id`. Returns
    /// [`Phase3PortError::NotFound`] when the row is missing or belongs to
    /// a different tenant.
    async fn get_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<crate::view::bas_view::ChainRunView, Phase3PortError>;
}

/// Persistent BAS approval port — backs the two-person rule for any
/// `safe_interactive` (and future `active_exploit`) run.
///
/// Implementations MUST be idempotent on the
/// `(engagement_id, technique_id, approver_email)` tuple: re-recording the
/// same approval surfaces as [`Phase3PortError::Invalid`] with the message
/// `"approver already recorded"`. The controller translates this into the
/// HTTP `409 Conflict` envelope.
#[async_trait]
pub trait ApprovalPort: Send + Sync {
    /// Persist a new approval row.
    async fn record(&self, req: RecordApprovalRequest) -> Result<ApprovalView, Phase3PortError>;

    /// List every approval bound to `engagement_id`, oldest-first.
    async fn list(&self, engagement_id: &str) -> Result<Vec<ApprovalView>, Phase3PortError>;

    /// Count distinct approver emails recorded against
    /// `(engagement_id, technique_id)`. Used by the BAS run handler to
    /// enforce the two-person rule before dispatching `safe_interactive`
    /// (and eventually `active_exploit`) runs.
    async fn count_distinct_approvers(
        &self,
        engagement_id: &str,
        technique_id: &str,
    ) -> Result<u32, Phase3PortError>;
}

/// Attack-path search port.
///
/// Wraps [`sx_graph`]'s attack-path query so the HTTP surface can request
/// up to `max_paths` distinct paths between sources and crown-jewel sinks
/// (bounded by `max_depth`).
#[async_trait]
pub trait GraphAttackPathsPort: Send + Sync {
    /// Search for the top-k attack paths in the tenant's graph.
    async fn search(
        &self,
        req: GraphAttackPathsRequestView,
    ) -> Result<GraphAttackPathsResponseView, Phase3PortError>;
}

/// Cloud blast-radius port (P1-010).
///
/// Wraps [`sx_graph::service::blast_radius::BlastRadiusService`] so the
/// HTTP surface can ask "if asset X is compromised, who is reachable?"
/// The adapter is expected to memoise the answer for at most one hour
/// (TTL); requests older than that re-execute the bi-directional BFS.
#[async_trait]
pub trait BlastRadiusPort: Send + Sync {
    /// Compute (or fetch from the 1-hour cache) the blast-radius report
    /// for `seed_asset_id` bounded at `max_depth`.
    async fn compute(
        &self,
        tenant_id: &str,
        seed_asset_id: &str,
        max_depth: u8,
    ) -> Result<BlastRadiusResponseView, Phase3PortError>;
}

/// Report-rendering port.
///
/// Materialises a report (executive PDF, technical PDF, SARIF, STIX, CSV)
/// from an engagement.
#[async_trait]
pub trait ReportRenderPort: Send + Sync {
    /// Render a report for the given tenant + engagement + format.
    async fn render(
        &self,
        req: ReportRenderRequestView,
    ) -> Result<ReportRenderResponseView, Phase3PortError>;

    /// List previously rendered reports for `tenant_id`, capped at `limit`.
    ///
    /// Returns the narrow [`crate::view::report_view::ReportSummaryView`]
    /// projection (id, kind, generated_at, format, size_bytes). Default
    /// implementation returns an empty vector so existing adapter types
    /// stay source-compatible — the in-monolith adapter overrides this
    /// with the in-memory snapshot kept by the dispatcher.
    async fn list_rendered(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<Vec<crate::view::report_view::ReportSummaryView>, Phase3PortError> {
        let _ = (tenant_id, limit);
        Ok(Vec::new())
    }
}

/// Error surface for [`BrandingPort`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum BrandingPortError {
    /// User-facing validation failure (bad colour, oversized logo, …).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Anything else.
    #[error("internal: {0}")]
    Internal(String),
}

/// Per-tenant report branding port (P2-002 MSSP white-label).
///
/// Backs `GET /v1/reports/branding` and `PUT /v1/reports/branding`. The
/// same branding store the report renderer consults, so a change here is
/// reflected on the next rendered PDF. Tenant scoping is enforced by the
/// HTTP layer; the adapter records an audit entry on every write.
#[async_trait]
pub trait BrandingPort: Send + Sync {
    /// Fetch the current branding for `tenant_id` (defaults when unset).
    async fn get(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::branding_view::BrandingView, BrandingPortError>;

    /// Replace the branding for `tenant_id`. `actor` is the acting user id
    /// (audited).
    async fn set(
        &self,
        tenant_id: &str,
        actor: &str,
        req: crate::view::branding_view::SetBrandingRequest,
    ) -> Result<crate::view::branding_view::BrandingView, BrandingPortError>;
}

/// Error surface for [`ComprehensiveReportPort`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum ComprehensiveReportPortError {
    /// User-facing validation failure.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Anything else.
    #[error("internal: {0}")]
    Internal(String),
}

/// Comprehensive cross-module report port (#3).
///
/// Backs `GET /v1/reports/comprehensive` — aggregates the latest results
/// across modules and renders a single executive report artifact
/// (structured fields + Markdown) server-side.
#[async_trait]
pub trait ComprehensiveReportPort: Send + Sync {
    /// Generate the comprehensive report for `tenant_id`.
    async fn generate(
        &self,
        tenant_id: &str,
    ) -> Result<
        crate::view::comprehensive_report_view::ComprehensiveReportView,
        ComprehensiveReportPortError,
    >;
}

/// Error surface for [`ReportSchedulePort`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReportSchedulePortError {
    /// User-facing validation failure (bad cron, format, uuid, …).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Schedule not found.
    #[error("not found")]
    NotFound,
    /// Anything else.
    #[error("internal: {0}")]
    Internal(String),
}

/// Scheduled-report distribution management port (P2-001).
///
/// Backs `GET`/`POST /v1/reports/schedules` and
/// `DELETE /v1/reports/schedules/{id}`. The background scheduler job reads
/// the same store, so a schedule registered here runs on its next tick.
#[async_trait]
pub trait ReportSchedulePort: Send + Sync {
    /// List schedules for `tenant_id`.
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::view::report_schedule_view::ReportScheduleView>, ReportSchedulePortError>;

    /// Register a new schedule.
    async fn create(
        &self,
        tenant_id: &str,
        req: crate::view::report_schedule_view::CreateReportScheduleRequest,
    ) -> Result<crate::view::report_schedule_view::ReportScheduleView, ReportSchedulePortError>;

    /// Disable (soft-delete) a schedule.
    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), ReportSchedulePortError>;
}

/// Differential-report port (P2-003).
///
/// Computes a `[since, until]` diff of findings (added / resolved /
/// regressed) for a single engagement and — optionally — renders a
/// `diff_pdf` artifact backed by [`ReportRenderPort`]. The HTTP layer
/// is responsible for tenant scoping; the adapter records an audit-log
/// entry on every successful call.
#[async_trait]
pub trait ReportDiffPort: Send + Sync {
    /// Compute the diff for `(tenant_id, engagement_id)` over the window
    /// supplied in `req`.
    async fn compute(
        &self,
        req: ReportDiffRequestView,
    ) -> Result<ReportDiffResponseView, Phase3PortError>;
}

/// Remediation-advisories lookup port.
///
/// Looks up vendor advisories (Microsoft, Red Hat, Canonical, …) for a
/// given CVE.
#[async_trait]
pub trait RemediationAdvisoriesPort: Send + Sync {
    /// Fetch advisories for the given CVE.
    async fn advisories(
        &self,
        req: RemediationAdvisoriesRequestView,
    ) -> Result<RemediationAdvisoriesResponseView, Phase3PortError>;
}

/// Compliance-framework port.
///
/// Exposes two thin reads:
///
/// - [`Self::list_framework`] — list all controls of a framework.
/// - [`Self::map_finding`] — map a finding category onto the controls it
///   implicates (across frameworks).
#[async_trait]
pub trait ComplianceFrameworkPort: Send + Sync {
    /// List every control in a framework (e.g. `nist_800_53`, `iso_27001`).
    async fn list_framework(
        &self,
        framework: &str,
    ) -> Result<ComplianceFrameworkResponseView, Phase3PortError>;

    /// Map a finding (by category) onto the implicated controls.
    async fn map_finding(
        &self,
        req: ComplianceMapRequestView,
    ) -> Result<ComplianceMapResponseView, Phase3PortError>;
}

/// ML triage-prediction port.
///
/// Calls the registered ML model identified by `model_id` on the supplied
/// feature row.
#[async_trait]
pub trait MlTriagePredictPort: Send + Sync {
    /// Run the model and return the label + probability.
    async fn predict(
        &self,
        req: MlTriagePredictRequestView,
    ) -> Result<MlTriagePredictResponseView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Autonomy ports (continuous validation, auto-PR remediation, threat network)
// ---------------------------------------------------------------------------

/// Opaque identifier for a continuous-validation engine handle held by the
/// monolith adapter.
///
/// A bare `String` wrapper rather than a UUID newtype because the adapter
/// is free to use any unique key (the implementation today uses
/// `uuid::Uuid::now_v7().to_string()`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AutonomyEngineId(pub String);

impl std::fmt::Display for AutonomyEngineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for AutonomyEngineId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Request to propose an auto-remediation pull request.
///
/// All identifiers are kept as strings so the API crate never imports
/// `sx-autonomy`. The monolith adapter parses, validates, and forwards them
/// into the `AutoRemediationPrGenerator`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposePrInput {
    /// Tenant uuid the request runs under (echoed into audit logs).
    pub tenant_id: String,
    /// Finding id the remediation addresses; embedded in the PR body.
    pub finding_id: String,
    /// GitHub repository owner (org or user).
    pub repo_owner: String,
    /// GitHub repository name.
    pub repo_name: String,
    /// Target branch the PR will be opened against.
    pub target_branch: String,
    /// PR title.
    pub title: String,
    /// PR body — the generator augments it with finding id + signed-off-by.
    pub description: String,
    /// File changes that make up the diff.
    pub changes: Vec<ProposePrChange>,
}

/// One file change inside a [`ProposePrInput`].
#[derive(Debug, Clone, Deserialize)]
pub struct ProposePrChange {
    /// Repo-relative path (no leading slash).
    pub path: String,
    /// Full new content of the file.
    pub new_content: String,
}

/// Outcome of a successful PR proposal.
#[derive(Debug, Clone, Serialize)]
pub struct ProposePrOutcome {
    /// PR number assigned by GitHub.
    pub pull_request_number: u64,
    /// Canonical URL of the opened PR.
    pub url: String,
}

/// Auto-remediation PR proposal port.
///
/// Backed by `sx_autonomy::AutoRemediationPrGenerator` in production; a
/// recording fake in tests. Implementations MUST enforce the autonomy
/// safety pipeline (protected-branch refusal, diff-size guard,
/// signed-off-by footer).
#[async_trait]
pub trait ProposePrPort: Send + Sync {
    /// Propose a pull request. Returns the PR number and URL on success.
    async fn propose(&self, req: ProposePrInput) -> Result<ProposePrOutcome, Phase3PortError>;
}

/// Request to submit a batch of anonymised threat-network observations.
///
/// `scope` is the wire form of `sx_autonomy::SharingScope`; the adapter
/// parses it before forwarding. The adapter is responsible for refusing
/// submissions when the consent scope does not authorise the operation,
/// when the endpoint is not HTTPS, or when the upstream ledger rejects
/// the batch.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitThreatInput {
    /// Tenant uuid (consent owner).
    pub tenant_id: String,
    /// RFC 3339 timestamp of when the tenant recorded their consent.
    pub consented_at: String,
    /// Sharing scope: `vulnerability_frequency` or `ioc_match`.
    pub scope: String,
    /// Observations to submit. Each carries a CVE id, asset-kind classifier,
    /// and count.
    pub observations: Vec<SubmitThreatObservation>,
}

/// One observation inside a [`SubmitThreatInput`].
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitThreatObservation {
    /// CVE identifier observed.
    pub cve_id: String,
    /// Coarse asset-kind classifier (hashed before transmission).
    pub asset_kind: String,
    /// Count of assets in this category exhibiting the CVE.
    pub count: u32,
}

/// Outcome of a successful threat-network submission.
#[derive(Debug, Clone, Serialize)]
pub struct SubmitThreatOutcome {
    /// Whether the upstream ledger accepted the batch (always `true` here,
    /// failures surface as [`Phase3PortError`]).
    pub accepted: bool,
    /// Number of observations submitted.
    pub submitted_count: u32,
}

/// Threat-network observation-submission port.
#[async_trait]
pub trait SubmitThreatObservationPort: Send + Sync {
    /// Submit a batch of anonymised observations to the configured
    /// threat-network endpoint.
    async fn submit(&self, req: SubmitThreatInput) -> Result<SubmitThreatOutcome, Phase3PortError>;
}

/// Request to schedule a continuous-validation engine run.
///
/// Once scheduled, the engine ticks every `interval_secs` and dispatches
/// the listed techniques through the underlying simulator. The handle is
/// retained by the adapter and cancellable via [`ScheduleValidationPort::cancel`].
#[derive(Debug, Clone, Deserialize)]
pub struct ScheduleValidationInput {
    /// Tenant uuid the engine runs under.
    pub tenant_id: String,
    /// Engagement uuid the engine targets.
    pub engagement_id: String,
    /// Interval between ticks, in seconds. Bounded by the HTTP validator to
    /// `60..=86_400`.
    pub interval_secs: u64,
    /// Technique ids to run on every tick. Must be non-empty.
    pub technique_ids: Vec<String>,
}

/// Continuous-validation scheduling port.
///
/// Owns a map of engine handles keyed by [`AutonomyEngineId`]. The HTTP
/// surface only ever sees opaque strings — the adapter manages the
/// concrete `sx_autonomy::EngineHandle` values.
#[async_trait]
pub trait ScheduleValidationPort: Send + Sync {
    /// Start a fresh engine, retain its handle, and return its id.
    async fn schedule(
        &self,
        req: ScheduleValidationInput,
    ) -> Result<AutonomyEngineId, Phase3PortError>;

    /// Cancel a previously scheduled engine. Returns
    /// [`Phase3PortError::NotFound`] when `id` does not match a live
    /// engine.
    async fn cancel(&self, id: &AutonomyEngineId) -> Result<(), Phase3PortError>;
}

/// Cloud-inventory port.
///
/// Drives the `sx-cloud` fan-out use case across every registered
/// connector (AWS / GCP / Azure). The HTTP surface always validates
/// `req` first so the implementation can rely on `providers` containing
/// only the canonical lowercase identifiers.
///
/// At Phase-3.5 the monolith composes this port with an empty connector
/// list (no live tenant credentials are wired yet); the trait surface is
/// still exercised end-to-end and returns an empty `resources` vec.
#[async_trait]
pub trait CloudInventoryPort: Send + Sync {
    /// Run the fan-out inventory for `req` and return a homogeneous
    /// projection of every discovered cloud resource.
    async fn list(
        &self,
        req: CloudInventoryRequestView,
    ) -> Result<CloudInventoryResponseView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Collaborator ports (OOB tokens + callback lookup)
// ---------------------------------------------------------------------------

/// Out-of-band token allocation port.
///
/// Wraps `sx_collab::service::token_alloc::TokenAllocator` behind a thin
/// HTTP-facing trait. The HTTP surface validates `req` (uuid tenant id +
/// non-empty finding id) before calling [`Self::allocate`]; the adapter is
/// only responsible for minting / returning the existing token.
#[async_trait]
pub trait CollabAllocateTokenPort: Send + Sync {
    /// Mint (or reuse) the OOB token bound to `(tenant_id, finding_id)`.
    async fn allocate(
        &self,
        req: CollabAllocateTokenRequestView,
    ) -> Result<CollabAllocateTokenResponseView, Phase3PortError>;
}

/// Out-of-band callback-lookup port.
///
/// Returns every callback recorded against `token` by the DNS / HTTP /
/// SMTP receivers. The HTTP surface validates that `token` matches the
/// canonical 16-hex-character form before dispatching.
#[async_trait]
pub trait CollabLookupCallbacksPort: Send + Sync {
    /// Return every callback recorded for `token`. An unknown but
    /// syntactically valid token returns an empty `callbacks` vec — it is
    /// not an error.
    async fn lookup(&self, token: &str) -> Result<CollabCallbacksResponseView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Admin ports (operator-only provisioning beyond the bootstrap admin)
// ---------------------------------------------------------------------------

/// Admin user-provisioning port.
///
/// Wraps the IAM crate's `CreateUserUseCase` behind a thin HTTP-facing
/// trait. The controller gates access via the `admin:users` permission;
/// the adapter parses the tenant uuid, maps role names onto concrete
/// permission grants, hashes the supplied password, and persists the new
/// [`sx_iam::domain::User`].
///
/// Errors are collapsed into [`Phase3PortError`] so the HTTP layer can
/// share the existing translation table — see
/// [`crate::controller::map_phase3`].
#[async_trait]
pub trait CreateUserPort: Send + Sync {
    /// Provision a new user under the requested tenant + roles.
    async fn create(
        &self,
        req: CreateUserRequestView,
    ) -> Result<CreateUserResponseView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// SOC port (autonomous alert correlator)
// ---------------------------------------------------------------------------

/// Autonomous-SOC port.
///
/// Wraps the `sx-soc` correlator + buffered alert sink behind a thin
/// HTTP-facing trait. The HTTP surface only ever sees the trait object —
/// the concrete `Correlator` / `BufferAlertSink` are owned by the monolith
/// adapter and reachable exclusively through this port.
///
/// ## Endpoints
///
/// - `GET  /v1/soc/alerts`  — list recent buffered alerts scoped to
///   the caller's tenant (RBAC: `soc:read`).
/// - `POST /v1/soc/events`  — operators push an event into the correlator
///   for rule testing (RBAC: `soc:write`).
///
/// ## Tenant scoping
///
/// [`Self::list_alerts`] projects the buffered alerts into
/// [`crate::view::soc_view::SocAlertView`] and filters by `tenant_id`:
/// `None` matches alerts with no tenant (global), `Some(t)` matches
/// alerts bound to that tenant. The adapter is free to be more permissive
/// (e.g. return all alerts to root operators); the controller passes the
/// caller's tenant verbatim.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait SocPort: Send + Sync {
    /// Snapshot the buffered alerts (oldest-first) for the given tenant.
    async fn list_alerts(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<crate::view::soc_view::SocAlertView>, Phase3PortError>;

    /// Forward a raw event into the correlator's mpsc channel.
    ///
    /// Returns the count of events accepted by the sender (always `1` on
    /// success). The adapter MUST translate a closed/dropped sender into
    /// [`Phase3PortError::Dependency`] so the operator sees a 502.
    async fn submit_event(&self, event: serde_json::Value) -> Result<u32, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Twin port (cyber digital twin)
// ---------------------------------------------------------------------------

/// Cyber-digital-twin read port.
///
/// Wraps the `sx-twin` in-memory simulator behind a thin HTTP-facing
/// trait. The HTTP surface only ever sees the trait object — the concrete
/// `Twin` store is owned by the monolith adapter and is reachable
/// exclusively through this port.
///
/// ## Endpoint
///
/// - `GET /v1/twin/engagement/{engagement_id}` — return the current twin
///   snapshot (assets + edges + compromised set) for the engagement.
///   RBAC: `twin:read`.
///
/// ## Tenant scoping
///
/// The caller's tenant uuid is resolved from the bearer token
/// ([`crate::extractor::tenant::TenantScope`]) and forwarded to
/// [`Self::get`]; the adapter MUST refuse to cross tenant boundaries.
///
/// ## Empty state
///
/// An engagement that has not yet been seeded returns an **empty**
/// [`crate::view::twin_view::TwinStateView`] (not [`Phase3PortError::NotFound`]).
/// The endpoint is read-only and is allowed to be called before the
/// first BAS / discovery run has populated the twin.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait TwinPort: Send + Sync {
    /// Snapshot the digital twin bound to `(tenant_id, engagement_id)`.
    async fn get(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<crate::view::twin_view::TwinStateView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Threat-intel port (sharded bloom IOC store + STIX/TAXII feeds)
// ---------------------------------------------------------------------------

/// Threat-intelligence indicator-check port.
///
/// Wraps the `sx-intel-ioc` sharded bloom store (and, when configured, the
/// `sx-intel-feeds` STIX/TAXII ingest pipeline) behind a thin HTTP-facing
/// trait. The HTTP surface only ever sees the trait object — the concrete
/// `IocStore` is owned by the monolith adapter and reachable exclusively
/// through this port.
///
/// ## Semantics
///
/// - `known = true` means the indicator hit the bloom filter and is
///   treated as a probable IOC; the underlying filter may produce false
///   positives bounded by its configured FPR.
/// - `known = false` is authoritative: the filter never produces false
///   negatives.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
/// In particular, an unparseable `kind` surfaces as
/// [`Phase3PortError::Invalid`] (mapped to `422 Unprocessable`).
#[async_trait]
pub trait IntelCheckPort: Send + Sync {
    /// Probe `req` against the IOC store and return whether the indicator
    /// is known.
    async fn check(
        &self,
        req: crate::view::intel_view::IntelCheckRequest,
    ) -> Result<crate::view::intel_view::IntelCheckResponse, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Red Team port (AI adversary chain composer)
// ---------------------------------------------------------------------------

/// AI Red Team chain-composer port.
///
/// Wraps `sx_autonomy::redteam::compose` behind a thin HTTP-facing trait.
/// The HTTP surface validates the request (non-empty engagement id,
/// `max_steps` in `1..=14`) before dispatching; the adapter is responsible
/// for looking up the engagement, deriving a `TargetSpec` from its scope,
/// and projecting the composed `AttackChain` into a
/// [`crate::view::redteam_view::RedteamChainView`].
///
/// ## Endpoint
///
/// - `POST /v1/redteam/chain` — compose a kill chain for `engagement_id`.
///   RBAC: `redteam:compose`.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
/// In particular, a missing engagement surfaces as
/// [`Phase3PortError::NotFound`].
#[async_trait]
pub trait RedteamPort: Send + Sync {
    /// Compose an attack chain for the given tenant + engagement.
    async fn compose(
        &self,
        tenant_id: &str,
        req: crate::view::redteam_view::RedteamComposeRequest,
    ) -> Result<crate::view::redteam_view::RedteamChainView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Predictive port (GBDT finding-risk classifier)
// ---------------------------------------------------------------------------

/// Predictive finding-risk classifier port.
///
/// Wraps `sx_ml::predictive::PredictiveModel` behind a thin HTTP-facing
/// trait. The HTTP surface only ever sees the trait object — the concrete
/// forest, scaler, and finding/asset lookups are owned by the monolith
/// adapter and reachable exclusively through this port.
///
/// ## Endpoint
///
/// - `POST /v1/ml/predict/finding` — score a finding by uuid. The adapter
///   resolves the finding (plus its asset) through the repository ports,
///   extracts `FindingFeatures`, and runs `PredictiveModel::predict`.
///   RBAC: `ml:predict`.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
/// A missing finding (or its asset) surfaces as
/// [`Phase3PortError::NotFound`].
#[async_trait]
pub trait PredictivePort: Send + Sync {
    /// Score the finding identified by `finding_id` under `tenant_id`.
    async fn predict(
        &self,
        tenant_id: &str,
        finding_id: &str,
    ) -> Result<crate::view::predictive_view::PredictResponse, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Customer-facing auth (signup / verify-email / forgot-password /
// reset-password)
// ---------------------------------------------------------------------------

/// Customer-facing authentication port.
///
/// Backs the four **public** (unauthenticated) endpoints under
/// `/v1/auth/*` that customers use to self-service their account:
///
/// - [`Self::signup`]           — create an inactive user + verification token.
/// - [`Self::verify_email`]     — activate the user, consume the token.
/// - [`Self::forgot_password`]  — mint a reset token (always returns `Ok`).
/// - [`Self::reset_password`]   — rotate the password hash, consume the token.
///
/// ## Security contract
///
/// - Every method returns [`Result<OkView, Phase3PortError>`]. Successful
///   responses never reveal whether an email exists.
/// - The verification + reset tokens are opaque adapter-minted strings.
/// - Implementations MUST NOT log password plaintexts or token values.
/// - Tokens have a finite lifetime (24h in the bundled in-memory adapter).
///
/// Errors collapse into [`Phase3PortError`] so the HTTP layer reuses the
/// existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait CustomerAuthPort: Send + Sync {
    /// Create a new inactive user + issue a verification token.
    async fn signup(
        &self,
        req: crate::view::customer_auth_view::SignupRequest,
    ) -> Result<crate::view::customer_auth_view::OkView, Phase3PortError>;

    /// Exchange a verification token for activation.
    async fn verify_email(
        &self,
        req: crate::view::customer_auth_view::VerifyEmailRequest,
    ) -> Result<crate::view::customer_auth_view::OkView, Phase3PortError>;

    /// Mint a password-reset token. Always returns `Ok` regardless of
    /// whether the email exists (anti-enumeration).
    async fn forgot_password(
        &self,
        req: crate::view::customer_auth_view::ForgotPasswordRequest,
    ) -> Result<crate::view::customer_auth_view::OkView, Phase3PortError>;

    /// Exchange a valid reset token for a new password hash.
    async fn reset_password(
        &self,
        req: crate::view::customer_auth_view::ResetPasswordRequest,
    ) -> Result<crate::view::customer_auth_view::OkView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Copilot port (single-turn LLM chat)
// ---------------------------------------------------------------------------

/// AI Copilot chat port.
///
/// Wraps the `sx-remediation` `LlmClient` behind a thin HTTP-facing trait
/// so the API surface never imports the concrete Claude client (or any
/// LLM client). The composition root binds an `Arc<dyn CopilotPort>` into
/// [`crate::state::AppState`]; the adapter applies a prompt-shape policy
/// (rejecting prompts that look like they carry credentials) before
/// dispatching the completion request.
///
/// ## Endpoint
///
/// - `POST /v1/copilot/chat` — single-turn chat. RBAC: `copilot:use`.
///
/// ## Security contract
///
/// - Implementations MUST NOT log the prompt body or the reply text — only
///   their lengths.
/// - Implementations MUST reject prompts whose shape resembles a secret
///   (api_key / password / token markers) before sending them upstream.
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait CopilotPort: Send + Sync {
    /// Send `prompt` to the LLM backend and return the assistant reply
    /// plus the model identifier.
    ///
    /// `tenant_id` is required so that the adapter can route any
    /// state-changing actions the prompt declares (see the
    /// `propose:` prefix handling in the monolith adapter) through the
    /// human-in-loop approval queue. Pure-Q&A prompts ignore the
    /// argument and forward straight to the LLM client.
    ///
    /// `user_id` is the acting subject; the adapter records it (with the
    /// prompt/response hashes and model id) to the copilot-decision audit
    /// trail required by ADR-0004 §Decision item 7.
    async fn chat(
        &self,
        tenant_id: &str,
        user_id: &str,
        prompt: &str,
    ) -> Result<crate::view::copilot_view::CopilotChatResponse, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Graphsage risk-score read port (periodic ML job cache)
// ---------------------------------------------------------------------------

/// Read-only access to the latest `GraphSAGE` risk scores written by the
/// periodic graphsage adapter job.
///
/// The job runs every `interval_secs` (default 900s / 15 min), rebuilds a
/// [`sx_ml::graphsage::SimpleGraph`] from the tenant's findings + assets,
/// runs a 2-layer forward pass, and stores the per-asset embedding norm in
/// a shared `Arc<Mutex<HashMap<String, f64>>>`. This port exposes the read
/// half so HTTP controllers (or other adapters) can look up an asset's
/// current score without touching the cache directly.
///
/// `None` indicates the asset is not yet in the cache — either because the
/// job has not run yet or because the asset disappeared between ticks. The
/// port is synchronous because the underlying cache lookup is an O(1) hash
/// probe under a short-lived mutex guard; no I/O occurs.
pub trait GraphsageRiskPort: Send + Sync {
    /// Return the latest score for `asset_id`, or `None` if absent.
    fn get(&self, asset_id: &str) -> Option<f64>;
}

// ---------------------------------------------------------------------------
// Engagement state-transition port (pause / resume / abort / complete)
// ---------------------------------------------------------------------------

/// Engagement finite-state-machine transition port.
///
/// Surfaces the four operator-driven transitions on an engagement
/// aggregate behind a thin HTTP-facing trait so the API surface never
/// imports `sx-engagement`. Each method maps onto a single edge in the
/// engagement state machine — illegal edges surface as
/// [`EngagementPortError::Forbidden`].
///
/// ## State machine (recap)
///
/// - `Draft   -> Active | Aborted`
/// - `Active  -> Paused | Completed | Aborted`
/// - `Paused  -> Active  | Aborted`
/// - `Completed` and `Aborted` are terminal.
///
/// So:
/// - [`Self::pause`]    is valid only from `Active`.
/// - [`Self::resume`]   is valid only from `Paused`.
/// - [`Self::complete`] is valid only from `Active`.
/// - [`Self::abort`]    is valid from `Draft`, `Active`, or `Paused`.
///
/// ## Errors
///
/// - Missing engagement -> [`EngagementPortError::NotFound`].
/// - Invalid transition for the current state ->
///   [`EngagementPortError::Forbidden`] with a descriptive message (the
///   HTTP layer mints a `403 Forbidden`).
/// - Adapter / dependency failure ->
///   [`EngagementPortError::Dependency`] or [`EngagementPortError::Internal`].
#[async_trait]
pub trait EngagementTransitionPort: Send + Sync {
    /// Start a `Draft` engagement — move it to `Active`.
    ///
    /// Distinct from [`resume`](Self::resume) (which only re-activates a
    /// previously-`Paused` engagement). The domain FSM permits the
    /// `Draft → Active` edge directly; this is the operator-triggered
    /// "start the engagement" transition.
    async fn activate(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError>;

    /// Move an engagement from `Active` to `Paused`.
    async fn pause(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError>;

    /// Move an engagement from `Paused` back to `Active`.
    async fn resume(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError>;

    /// Move an engagement from `Draft` / `Active` / `Paused` to `Aborted`.
    ///
    /// `reason` is forwarded to audit. The HTTP surface validates length
    /// (1..=2000 chars) before dispatching.
    async fn abort(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        reason: &str,
    ) -> Result<EngagementView, EngagementPortError>;

    /// Move an engagement from `Active` to `Completed`.
    async fn complete(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<EngagementView, EngagementPortError>;
}

// ---------------------------------------------------------------------------
// Roles port (IAM role CRUD + per-user role assignment)
// ---------------------------------------------------------------------------

/// Role administration port.
///
/// Backs the four `/v1/admin/roles*` endpoints:
///
/// - [`Self::list`]   — list every role bound to the caller's tenant.
/// - [`Self::create`] — provision a fresh role with the requested
///   permissions. Idempotent on `(tenant_id, name)`: re-creating a role
///   with an identical name surfaces as [`Phase3PortError::Invalid`]
///   carrying the marker `"role already exists"`, which the controller
///   translates into HTTP `409 Conflict`.
/// - [`Self::delete`] — remove a role by id. Returns
///   [`Phase3PortError::NotFound`] when the id does not match a role in
///   the tenant.
/// - [`Self::assign`] — replace the role-id list bound to a user.
///   Idempotent — re-assigning the same set is a no-op. Unknown role ids
///   surface as [`Phase3PortError::Invalid`].
///
/// Errors collapse into [`Phase3PortError`] so the HTTP layer reuses the
/// existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait RolesPort: Send + Sync {
    /// List every role bound to `tenant_id`.
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::roles_view::ListRolesResponseView, Phase3PortError>;

    /// Create a new role under `tenant_id`. Idempotent on duplicate
    /// `(tenant_id, name)` — surfaces as [`Phase3PortError::Invalid`]
    /// with the marker `"role already exists"`.
    async fn create(
        &self,
        tenant_id: &str,
        req: crate::view::roles_view::CreateRoleRequestView,
    ) -> Result<crate::view::roles_view::RoleView, Phase3PortError>;

    /// Delete the role identified by `role_id` from `tenant_id`. Returns
    /// [`Phase3PortError::NotFound`] when no such role exists.
    async fn delete(&self, tenant_id: &str, role_id: &str) -> Result<(), Phase3PortError>;

    /// Assign the supplied role ids to `user_id` under `tenant_id`,
    /// replacing the previous binding. Returns the projection echoed by
    /// the controller.
    async fn assign(
        &self,
        tenant_id: &str,
        user_id: &str,
        req: crate::view::roles_view::AssignRolesRequestView,
    ) -> Result<crate::view::roles_view::AssignRolesResponseView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Asset write port (POST / PATCH / DELETE /v1/assets)
// ---------------------------------------------------------------------------

/// Asset write-side repository.
///
/// Mirrors [`AssetRepositoryPort`] but exposes the mutating half of the
/// asset lifecycle: create, partial update, delete. Kept on a separate
/// trait so read-only callers (and tests) can continue to depend on
/// [`AssetRepositoryPort`] without picking up the wider write surface.
///
/// ## Tenant scoping
///
/// Every method takes the caller's `tenant_id`. Implementations MUST
/// refuse to cross tenant boundaries; an asset that exists in a different
/// tenant surfaces as [`EngagementPortError::NotFound`].
///
/// ## Idempotency
///
/// [`Self::create`] is idempotent on the `(engagement_id, identifier)`
/// pair under a given tenant: a second create with the same pair returns
/// [`EngagementPortError::Conflict`]. The controller maps that into the
/// HTTP `409 Conflict` envelope.
#[async_trait]
pub trait AssetWritePort: Send + Sync {
    /// Create a new asset under `tenant_id`. Returns the persisted view.
    async fn create(
        &self,
        tenant_id: &str,
        req: crate::view::asset_view::CreateAssetRequest,
    ) -> Result<crate::view::asset_view::AssetView, EngagementPortError>;

    /// Apply a partial update to the asset identified by `id`. Fields
    /// absent from `req` are preserved.
    async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        req: crate::view::asset_view::UpdateAssetRequest,
    ) -> Result<crate::view::asset_view::AssetView, EngagementPortError>;

    /// Delete the asset identified by `id`. Returns
    /// [`EngagementPortError::NotFound`] when the asset does not exist.
    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), EngagementPortError>;
}

// ---------------------------------------------------------------------------
// Audit query port (search + NDJSON export)
// ---------------------------------------------------------------------------

/// Audit-log search + export port.
///
/// Wraps the in-process audit buffer behind a thin HTTP-facing trait so the
/// API surface never imports the concrete sink. The composition root binds
/// an `Arc<dyn AuditQueryPort>` into [`crate::state::AppState`]; the
/// adapter is responsible for projecting `sx_audit::AuditEntry` rows into
/// the wire [`crate::view::audit_view::AuditEntryView`].
///
/// ## Endpoints
///
/// - `GET /v1/audit/search?since=&action=&actor=&limit=` — paginated
///   search. RBAC: `audit:read`.
/// - `GET /v1/audit/export?format=ndjson&since=` — stream NDJSON. RBAC:
///   `audit:read`. The adapter MUST cap exports at
///   [`crate::view::audit_view::MAX_EXPORT_ENTRIES`] entries per response.
///
/// ## Filter semantics
///
/// All filters are AND-combined. `since` is an inclusive RFC 3339
/// lower-bound on `ts`. `action` is an exact match against the snake-case
/// action code. `actor` is an exact match against the projected
/// `kind:id` actor string.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
/// Malformed `since` surfaces as [`Phase3PortError::Invalid`].
#[async_trait]
pub trait AuditQueryPort: Send + Sync {
    /// Search the audit buffer with the given filters.
    async fn search(
        &self,
        query: crate::view::audit_view::AuditSearchQuery,
    ) -> Result<crate::view::audit_view::AuditSearchResponse, Phase3PortError>;

    /// Snapshot the audit buffer (filtered by `since` if supplied) and
    /// return an NDJSON-encoded byte buffer — one JSON object per line,
    /// newline-terminated.
    ///
    /// Implementations MUST cap output at
    /// [`crate::view::audit_view::MAX_EXPORT_ENTRIES`] entries.
    async fn export_ndjson(&self, since: Option<String>) -> Result<Vec<u8>, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Audit replay port (time-travel debugging, P3-009)
// ---------------------------------------------------------------------------

/// Audit-replay / time-travel port.
///
/// Backs the `GET /v1/audit/replay` and `GET /v1/audit/diff` endpoints. The
/// adapter is responsible for tenant scoping, chain integrity verification,
/// and projecting the resulting `sx_audit::ReplayTimeline` / `StateDiff`
/// into the wire DTOs.
///
/// ## Endpoints
///
/// - `GET /v1/audit/replay?entity_type=&entity_id=&from=&to=` — ordered
///   timeline. RBAC: `audit:read`.
/// - `GET /v1/audit/diff?entity_type=&entity_id=&from=&to=` — before /
///   after snapshot pair. RBAC: `audit:read`.
///
/// ## Semantics
///
/// `entity_type` is one of `engagement`, `finding`, `user`, `asset`. Any
/// other value surfaces as [`Phase3PortError::Invalid`]. `from` and `to`
/// are RFC 3339 timestamps; for `replay` both are optional, for `diff`
/// both are required and `from <= to`.
///
/// ## Multi-tenancy
///
/// The caller's tenant id is the single source of truth — the adapter
/// MUST refuse to surface rows from other tenants regardless of any
/// query parameter the caller supplies.
#[async_trait]
pub trait AuditReplayPort: Send + Sync {
    /// Reconstruct the ordered timeline of mutations for
    /// `(entity_type, entity_id)` scoped to `tenant_id`.
    async fn replay(
        &self,
        tenant_id: &str,
        query: crate::view::audit_view::AuditReplayQuery,
    ) -> Result<crate::view::audit_view::AuditReplayResponse, Phase3PortError>;

    /// Diff `(entity_type, entity_id)` between two timestamps.
    async fn diff(
        &self,
        tenant_id: &str,
        query: crate::view::audit_view::AuditDiffQuery,
    ) -> Result<crate::view::audit_view::AuditDiffResponse, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// External audit-chain anchoring port (P1-015)
// ---------------------------------------------------------------------------

/// External audit-chain anchoring port.
///
/// Backs the two anchoring endpoints exposed by
/// [`crate::controller::audit_anchor`]:
///
/// - `GET /v1/audit/anchors` — paginated list of the caller-tenant's
///   anchor runs, newest-first. RBAC: `audit:read`.
/// - `POST /v1/audit/anchors/verify/{run_id}` — re-verify a persisted
///   anchor run against the per-tenant operator-pinned CA cert. RBAC:
///   `audit:read`.
///
/// ## Multi-tenancy
///
/// The caller's tenant id (sourced from the bearer token) is the single
/// source of truth. The adapter MUST refuse to surface or verify rows
/// from any other tenant; cross-tenant lookups surface as
/// [`Phase3PortError::Forbidden`].
///
/// ## Critical events on signature failure
///
/// The verify call goes through the same `AnchorRunner::verify_run`
/// path as the periodic scheduler: an invalid signature emits an
/// `sx-audit` CRITICAL event via the in-process sink before surfacing
/// the failure to the HTTP layer.
///
/// ## Wire-shape contract
///
/// `payload_bytes` (the verbatim TSA reply blob) is **never** projected
/// onto the wire — the engineering bar mandates that the raw bytes
/// never leave the server. The adapter substitutes
/// `payload_size_bytes` so callers can sanity-check the row is non-
/// empty without ever seeing the bytes.
#[async_trait]
pub trait AuditAnchorPort: Send + Sync {
    /// List the caller-tenant's anchor runs, newest-first.
    async fn list(
        &self,
        tenant_id: &str,
        query: crate::view::audit_anchor_view::AuditAnchorListQuery,
    ) -> Result<crate::view::audit_anchor_view::AuditAnchorListResponse, Phase3PortError>;

    /// Re-verify a persisted run. `run_id` is the path parameter from
    /// `POST /v1/audit/anchors/verify/{run_id}` rendered as a UUID
    /// string.
    async fn verify(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<crate::view::audit_anchor_view::AuditAnchorVerifyResponse, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Finding bulk-update + export port
// ---------------------------------------------------------------------------

/// Wire form of the export format requested by
/// [`FindingBulkPort::export`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingExportFormat {
    /// One JSON object per line, newline-terminated.
    Ndjson,
    /// RFC-4180-flavoured CSV with a leading header row.
    Csv,
}

impl FindingExportFormat {
    /// Canonical lower-case wire name. Used by the controller for content
    /// negotiation and error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ndjson => "ndjson",
            Self::Csv => "csv",
        }
    }

    /// Parse a wire string into the enum. Returns `None` for any value
    /// outside the accepted set — the controller surfaces this as a
    /// 422 Unprocessable.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.eq_ignore_ascii_case("ndjson") {
            Some(Self::Ndjson)
        } else if raw.eq_ignore_ascii_case("csv") {
            Some(Self::Csv)
        } else {
            None
        }
    }
}

/// Bulk finding-update + streaming export port.
///
/// Wraps the per-id [`FindingRepositoryPort::update_status`] surface and
/// the read-side list iterator behind a thin trait. The composition root
/// binds an `Arc<dyn FindingBulkPort>` into [`crate::state::AppState`];
/// the controller delegates to it for `POST /v1/findings/bulk-update`
/// and `GET /v1/findings/export`.
///
/// ## Bounds
///
/// - [`Self::bulk_update`] callers must trim ids to
///   [`crate::view::finding_view::MAX_BULK_IDS`] before invoking; the
///   controller enforces this with `validator::Validate`.
/// - [`Self::export`] implementations MUST cap output at
///   [`crate::view::finding_view::MAX_EXPORT_ROWS`] rows.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer reuses
/// the existing translation table — see [`crate::controller::map_phase3`].
/// Malformed `since` surfaces as [`Phase3PortError::Invalid`].
#[async_trait]
pub trait FindingBulkPort: Send + Sync {
    /// Update every id in `req` to the supplied status. Returns a
    /// breakdown of `updated` / `failed` counts plus per-id errors.
    async fn bulk_update(
        &self,
        tenant_id: &str,
        req: crate::view::finding_view::BulkUpdateFindingsRequest,
    ) -> Result<crate::view::finding_view::BulkUpdateResponse, Phase3PortError>;

    /// Snapshot the finding store (filtered by `since` if supplied) and
    /// project it into the requested wire format.
    ///
    /// - `Ndjson` — one [`crate::view::finding_view::FindingView`] JSON
    ///   object per line, newline-terminated.
    /// - `Csv`    — RFC 4180-flavoured CSV with a leading header row.
    async fn export(
        &self,
        tenant_id: &str,
        format: FindingExportFormat,
        since: Option<String>,
    ) -> Result<Vec<u8>, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Tenant write port (POST / PATCH / DELETE /v1/admin/tenants)
// ---------------------------------------------------------------------------

/// Admin tenant-administration write port.
///
/// Backs the three operator-only endpoints under `/v1/admin/tenants*`:
///
/// - [`Self::create`] — provision a fresh tenant from a
///   [`crate::view::tenant_view::CreateTenantRequest`]. Slug uniqueness is
///   enforced at the adapter; a duplicate surfaces as
///   [`Phase3PortError::Invalid`] carrying the marker `"tenant exists"`
///   (the controller maps that into HTTP `409 Conflict`).
/// - [`Self::update`] — partial update of a tenant by id. Fields absent
///   from the request preserve the previous values.
/// - [`Self::delete`] — remove a tenant by id. Returns
///   [`Phase3PortError::NotFound`] when the id is unknown.
///
/// All wire shapes echo [`TenantSummaryView`] so the response shape is
/// identical to `GET /v1/tenants/me`.
///
/// Errors collapse into [`Phase3PortError`] so the HTTP layer can reuse
/// the existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait TenantWritePort: Send + Sync {
    /// Create a new tenant from `req`. Returns the persisted projection.
    async fn create(
        &self,
        req: crate::view::tenant_view::CreateTenantRequest,
    ) -> Result<TenantSummaryView, Phase3PortError>;

    /// Apply a partial update to the tenant identified by `id`. Fields
    /// absent from `req` are preserved.
    async fn update(
        &self,
        id: &str,
        req: crate::view::tenant_view::UpdateTenantRequest,
    ) -> Result<TenantSummaryView, Phase3PortError>;

    /// Delete the tenant identified by `id`. Returns
    /// [`Phase3PortError::NotFound`] when the id does not match a tenant.
    async fn delete(&self, id: &str) -> Result<(), Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Engagement clone port (POST /v1/engagements/{id}/clone)
// ---------------------------------------------------------------------------

/// Engagement-cloning port.
///
/// Backs `POST /v1/engagements/{id}/clone` — produces a fresh `Draft`
/// engagement that inherits its scope + window-duration from the source.
///
/// ## Semantics
///
/// - The clone always lands in `Draft` status; the source is left
///   untouched.
/// - The clone receives a freshly-minted uuid; the source uuid is
///   preserved on the source engagement.
/// - The clone's `scope` is a verbatim copy of the source's scope.
/// - The clone's window is shifted forward so it starts at "now" and
///   preserves the source's `(end - start)` duration verbatim.
/// - When `req.new_name` is supplied the clone uses it as the name (the
///   HTTP surface has already validated `1..=200` chars). When `None`,
///   the adapter mints the default `"{source.name} (clone)"`.
///
/// ## Method name
///
/// The trait method is intentionally named `clone_engagement` (not
/// `clone`) because `clone` is the canonical method name on
/// [`std::clone::Clone`] and the two would collide on any `&self`
/// receiver that also derives [`Clone`].
///
/// ## Errors
///
/// - [`EngagementPortError::NotFound`] — the source id does not match
///   any engagement under `tenant_id`.
/// - [`EngagementPortError::Invalid`] — `tenant_id` or `source_id` are
///   not parseable uuids.
/// - [`EngagementPortError::Dependency`] / [`EngagementPortError::Internal`]
///   — repository or adapter failures.
#[async_trait]
pub trait EngagementClonePort: Send + Sync {
    /// Clone the engagement identified by `source_id` under `tenant_id`.
    ///
    /// Returns the freshly-minted `Draft` projection. Method is named
    /// `clone_engagement` rather than `clone` to avoid collision with
    /// [`std::clone::Clone::clone`].
    async fn clone_engagement(
        &self,
        tenant_id: &str,
        source_id: &str,
        req: CloneEngagementRequest,
    ) -> Result<EngagementView, EngagementPortError>;
}

// ---------------------------------------------------------------------------
// Asset bulk-import port (`POST /v1/assets/bulk-import`)
// ---------------------------------------------------------------------------

/// Asset bulk-import port.
///
/// Wraps the per-row [`AssetWritePort::create`] surface behind a thin
/// HTTP-facing trait. The HTTP surface validates the
/// [`crate::view::asset_view::BulkImportRequest`] (format ∈ {`json`,
/// `csv`}, body length bounded by
/// [`crate::view::asset_view::BULK_IMPORT_MAX_BODY_BYTES`]) before
/// dispatching; the adapter is responsible for parsing the payload, capping
/// it at [`crate::view::asset_view::BULK_IMPORT_MAX_ROWS`], and counting
/// `created` / `skipped` / `errors` per row.
///
/// ## Semantics
///
/// - One row per asset.
/// - Duplicate `(engagement_id, identifier)` pairs are recorded as
///   `skipped`, not `errors` — the import is idempotent on duplicate input.
/// - Malformed bodies (bad JSON, malformed CSV header) surface as
///   [`Phase3PortError::Invalid`] (mapped to HTTP `400 Bad Request` at the
///   controller; see [`crate::controller::asset_bulk`]).
/// - Per-row validation failures are recorded under
///   [`crate::view::asset_view::BulkImportResponse::errors`] and do not
///   abort the overall import.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait AssetBulkImportPort: Send + Sync {
    /// Parse the supplied payload, dispatch each row to the underlying
    /// asset writer, and return the per-row outcome breakdown.
    async fn import(
        &self,
        tenant_id: &str,
        req: crate::view::asset_view::BulkImportRequest,
    ) -> Result<crate::view::asset_view::BulkImportResponse, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Remediation-tracking port (PATCH/DELETE /v1/findings/{id}/remediation)
// ---------------------------------------------------------------------------

/// Remediation-link tracking port.
///
/// Records the operator-supplied PR / ticket / comment triple alongside a
/// finding. The HTTP surface validates wire shape (scheme = https, allow-
/// listed hosts / markers, at-least-one URL) before dispatching; the
/// adapter is only responsible for upsert + audit fields.
///
/// ## Endpoints
///
/// - `PATCH  /v1/findings/{id}/remediation` — upsert the link.
///   RBAC: `findings:write`.
/// - `DELETE /v1/findings/{id}/remediation` — drop the link.
///   RBAC: `findings:write`. Returns
///   [`Phase3PortError::NotFound`] when no link exists.
///
/// ## Errors
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer reuses the
/// existing translation table — see [`crate::controller::map_phase3`].
#[async_trait]
pub trait RemediationTrackingPort: Send + Sync {
    /// Persist (upsert) the remediation link for `(tenant_id, finding_id)`.
    ///
    /// `actor_id` is the caller's user id — recorded as `linked_by` and
    /// echoed back in the response projection.
    async fn link(
        &self,
        tenant_id: &str,
        finding_id: &str,
        actor_id: &str,
        req: crate::view::finding_view::RemediationLinkRequest,
    ) -> Result<crate::view::finding_view::RemediationLinkView, Phase3PortError>;

    /// Drop the remediation link bound to `(tenant_id, finding_id)`.
    ///
    /// Returns [`Phase3PortError::NotFound`] when no link is currently
    /// recorded for that finding.
    async fn unlink(&self, tenant_id: &str, finding_id: &str) -> Result<(), Phase3PortError>;
}

// ---------------------------------------------------------------------------
// MFA port (TOTP enroll / verify / disable / status)
// ---------------------------------------------------------------------------

/// TOTP MFA self-service port.
///
/// Backs the four authenticated endpoints under `/v1/mfa/*` that
/// customers use to manage their own second factor:
///
/// - [`Self::enroll`]  — generate a fresh secret + recovery codes.
/// - [`Self::verify`]  — confirm enrollment (or step-up verify).
/// - [`Self::disable`] — remove MFA after proving possession.
/// - [`Self::status`]  — report current enrollment state.
///
/// ## Errors
///
/// Errors collapse into [`IamError`] so the HTTP layer can share the
/// existing translation table — see [`crate::controller::map_iam`]:
/// invalid codes surface as [`IamError::InvalidCredentials`], unknown
/// users / not-enrolled callers map to [`IamError::InvalidCredentials`]
/// to avoid revealing enrollment state under verify.
#[async_trait]
pub trait MfaPort: Send + Sync {
    /// Generate a fresh TOTP secret + 6 recovery codes for `user_id`.
    ///
    /// Returns the enrollment payload **exactly once** — the adapter
    /// stores only the SHA-256 hash of each recovery code. Re-enrolling
    /// rotates the secret and invalidates any prior pending enrollment.
    async fn enroll(
        &self,
        user_id: &str,
    ) -> Result<crate::view::mfa_view::EnrollResponse, sx_iam::IamError>;

    /// Verify `code` against the user's TOTP secret OR an unused
    /// recovery code.
    ///
    /// On the first successful verification the adapter marks the user
    /// as fully enrolled (so subsequent `status` calls report
    /// `enrolled = true`). On failure returns
    /// [`IamError::InvalidCredentials`].
    async fn verify(&self, user_id: &str, code: &str) -> Result<(), sx_iam::IamError>;

    /// Remove the user's MFA enrollment after verifying `code`.
    ///
    /// `code` must be a currently-valid TOTP or an unused recovery
    /// code; failure to verify rejects the disable request.
    async fn disable(&self, user_id: &str, code: &str) -> Result<(), sx_iam::IamError>;

    /// Report the current MFA enrollment + last-verified state.
    async fn status(
        &self,
        user_id: &str,
    ) -> Result<crate::view::mfa_view::MfaStatusView, sx_iam::IamError>;
}

// ---------------------------------------------------------------------------
// WebAuthn / FIDO2 port (P1-002 — passkey MFA register + login)
// ---------------------------------------------------------------------------

/// FIDO2 / `WebAuthn` passkey MFA port.
///
/// Backs the four endpoints under `/v1/auth/mfa/webauthn/{register,login}/{start,finish}`:
///
/// - [`Self::register_start`]  — issue a `CreationChallengeResponse` for
///   an authenticated user enrolling a new passkey.
/// - [`Self::register_finish`] — verify the authenticator attestation
///   and persist the credential row.
/// - [`Self::login_start`]     — issue a `RequestChallengeResponse`
///   keyed to the (yet-unauthenticated) user's email; the response
///   embeds an opaque `state_id` the client returns on `login/finish`.
/// - [`Self::login_finish`]    — verify the assertion, bump the
///   signature counter, and mint a fresh access/refresh token pair
///   carrying the `cred_id` claim (credential-bound JWT).
///
/// ## State handling
///
/// The IAM use cases return non-`Serialize` opaque state
/// (`PasskeyRegistration` / `PasskeyAuthentication`). The adapter owns
/// a short-lived state cache keyed by a freshly-minted `state_id`
/// (UUID v4, sub-five-minute TTL). The HTTP layer only sees the
/// opaque id and never touches the state machine internals.
///
/// ## Multi-tenant
///
/// `register_start` and `register_finish` infer tenant from the bearer
/// claim; `login_start` and `login_finish` derive tenant from the
/// supplied email (user lookup happens inside the adapter). Mismatched
/// relying-party configurations are returned as
/// [`IamError::Config`] so the operator sees the misconfiguration.
///
/// ## Errors
///
/// All errors collapse into [`IamError`] for the existing HTTP
/// translation table (`crate::controller::map_iam`):
/// - failed verification / unknown credential → [`IamError::InvalidCredentials`].
/// - missing relying-party config / malformed origin → [`IamError::Config`].
/// - storage failure → [`IamError::Repository`].
#[async_trait]
pub trait WebauthnPort: Send + Sync {
    /// Issue a registration challenge for `user_id` (authenticated).
    /// Returns the opaque server-side `state_id` and the
    /// `CreationChallengeResponse` JSON for the browser.
    async fn register_start(
        &self,
        tenant_id: &str,
        user_id: &str,
        user_name: &str,
    ) -> Result<crate::view::webauthn_view::RegisterStartResponse, sx_iam::IamError>;

    /// Complete a registration ceremony — verify attestation, persist
    /// the credential row, return the new credential id.
    async fn register_finish(
        &self,
        tenant_id: &str,
        user_id: &str,
        req: crate::view::webauthn_view::RegisterFinishRequest,
        label: Option<String>,
    ) -> Result<crate::view::webauthn_view::RegisterFinishResponse, sx_iam::IamError>;

    /// Issue a login challenge for the user identified by `email`.
    /// Unknown users return `Err(IamError::InvalidCredentials)` so the
    /// HTTP layer cannot be used to probe enrolment.
    async fn login_start(
        &self,
        email: &str,
    ) -> Result<crate::view::webauthn_view::LoginStartResponse, sx_iam::IamError>;

    /// Complete a login ceremony — verify the assertion, bump the
    /// counter, mint a fresh access/refresh token pair carrying the
    /// `cred_id` claim.
    async fn login_finish(
        &self,
        req: crate::view::webauthn_view::LoginFinishRequest,
    ) -> Result<crate::view::webauthn_view::LoginFinishResponse, sx_iam::IamError>;

    // -------------------------------------------------------------------
    // HIGH-002 — AAGUID policy + MDS3 management surface
    // -------------------------------------------------------------------

    /// List the tenant's AAGUID policy rows. Backs
    /// `GET /v1/iam/webauthn/aaguid-policy`.
    async fn list_aaguid_policy(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::webauthn_view::AaguidPolicyListResponse, sx_iam::IamError>;

    /// Upsert a single AAGUID policy row. Backs
    /// `PUT /v1/iam/webauthn/aaguid-policy/{aaguid}`.
    async fn put_aaguid_policy(
        &self,
        tenant_id: &str,
        set_by: &str,
        aaguid: &str,
        req: crate::view::webauthn_view::PutAaguidPolicyRequest,
    ) -> Result<crate::view::webauthn_view::AaguidPolicyView, sx_iam::IamError>;

    /// Delete an AAGUID policy row (idempotent — returns Ok if absent).
    /// Backs `DELETE /v1/iam/webauthn/aaguid-policy/{aaguid}`.
    async fn delete_aaguid_policy(
        &self,
        tenant_id: &str,
        aaguid: &str,
    ) -> Result<(), sx_iam::IamError>;

    /// Status of the local MDS3 cache. Backs
    /// `GET /v1/iam/webauthn/mds-status`.
    async fn mds_status(
        &self,
    ) -> Result<crate::view::webauthn_view::MdsStatusView, sx_iam::IamError>;

    /// Force-refresh the local MDS3 cache. Returns the post-refresh
    /// status. Backs `POST /v1/iam/webauthn/mds-refresh`. Admin-gated.
    async fn mds_refresh(
        &self,
    ) -> Result<crate::view::webauthn_view::MdsStatusView, sx_iam::IamError>;

    /// List the credentials for `user_id` together with their AAGUID
    /// and authenticator-name (resolved against the local MDS cache).
    /// Backs `GET /v1/iam/webauthn/credentials`.
    async fn list_user_credentials(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<crate::view::webauthn_view::CredentialListResponse, sx_iam::IamError>;
}

// ---------------------------------------------------------------------------
// Log-ingest port (POST /v1/logs/ingest, GET /v1/logs)
// ---------------------------------------------------------------------------

/// Error surface for the log-ingest port.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LogIngestError {
    #[error("unknown source: {0}")]
    UnknownSource(String),
    #[error("invalid payload: {0}")]
    Invalid(String),
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Risk-Based Authentication (RBA) port (P1-003)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RbaActionWire {
    Allow,
    StepUpMfa,
    Block,
}

#[derive(Debug, Clone)]
pub struct RbaEvaluateInput {
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub email: String,
    pub ip: String,
    pub device_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RbaEvaluateOutput {
    pub score: i32,
    pub action: RbaActionWire,
    pub reason: String,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RbaPortError {
    #[error("forbidden")]
    Forbidden,
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// OCSF log ingestion + listing port.
#[async_trait]
pub trait LogIngestPort: Send + Sync {
    async fn ingest_one(
        &self,
        tenant_id: &str,
        source: &str,
        payload: &str,
    ) -> Result<(), LogIngestError>;

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<crate::view::log_ingest_view::OcsfEventView>, LogIngestError>;
}

// ---------------------------------------------------------------------------
// Per-tenant log-ingest rate limiter port (MED-001)
// ---------------------------------------------------------------------------

/// Snapshot of the per-bucket state for a single decision (admit or
/// throttle). Mirrors `sx_log_ingest::rate_limit::RateDecision` while
/// keeping the API crate free of a hard dep on the ingest crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRateLimitDecision {
    /// Whether the call was admitted.
    pub allowed: bool,
    /// Bucket capacity (burst ceiling).
    pub limit: u32,
    /// Tokens left after this call (always 0 when throttled).
    pub remaining: u32,
    /// Unix-epoch seconds at which the bucket is expected to be full.
    pub reset_at_unix_secs: u64,
    /// Whole seconds the client should wait before retrying (0 when
    /// admitted).
    pub retry_after_secs: u64,
}

/// Snapshot of the effective rates for one tenant. Returned from the
/// admin tier-set endpoint so the operator can confirm the mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRateLimitTierSnapshot {
    /// Effective steady-state events/sec.
    pub per_sec_rate: u32,
    /// Effective burst ceiling.
    pub burst: u32,
}

/// Error surface for the log-ingest rate limiter port.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LogRateLimitError {
    /// The tier name was not one of `free`, `pro`, `enterprise`.
    #[error("invalid tier: {0}")]
    InvalidTier(String),
    /// The override rate failed validation.
    #[error("invalid override: {0}")]
    InvalidOverride(String),
    /// Internal failure (lock poisoning, etc).
    #[error("internal: {0}")]
    Internal(String),
}

/// Per-tenant log-ingest rate-limiter port (MED-001).
///
/// `try_acquire` is called on every `POST /v1/logs/ingest`; admin
/// `set_tier` is called from
/// `PUT /v1/admin/log-ingest/tiers/{tenant_id}`.
pub trait LogRateLimitPort: Send + Sync {
    /// Attempt to consume one token for the supplied `(tenant_id,
    /// endpoint)` pair. Returns the decision the controller projects
    /// into `X-RateLimit-*` headers.
    fn try_acquire(&self, tenant_id: &str, endpoint: &str) -> LogRateLimitDecision;

    /// Set the tier (and optional override) for one tenant. Returns the
    /// effective rates post-mutation.
    fn set_tier(
        &self,
        tenant_id: &str,
        tier: &str,
        override_rate_per_sec: Option<u32>,
    ) -> Result<LogRateLimitTierSnapshot, LogRateLimitError>;

    /// Read the active tier name + override (if any) for a tenant.
    /// Returns the default tier when the tenant has no recorded
    /// override.
    fn tier_of(&self, tenant_id: &str) -> (String, Option<u32>);
}

// ---------------------------------------------------------------------------
// Prowler v4 native-JSON CSPM import port (P1-009)
// ---------------------------------------------------------------------------

/// Error type for the Prowler-import port.
///
/// Kept narrow on purpose so the controller can return precise HTTP codes
/// (413 for `TooLarge`, 422 for `Malformed`, 403 for `CrossTenant`).
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProwlerImportPortError {
    /// Upload exceeded the configured size limit.
    #[error("upload too large: {actual} bytes > {limit}")]
    TooLarge {
        /// Bytes received.
        actual: u64,
        /// Configured cap.
        limit: u64,
    },
    /// Payload could not be parsed as Prowler v4 native JSON.
    #[error("malformed: {0}")]
    Malformed(String),
    /// The importing tenant does not own every referenced cloud account.
    #[error("cross-tenant: {0}")]
    CrossTenant(String),
    /// Internal failure (sink write, audit, etc.).
    #[error("internal: {0}")]
    Internal(String),
}

/// Prowler v4 native-JSON CSPM ingest port (P1-009).
///
/// Backed in production by an adapter that wraps
/// [`sx_discovery::prowler_import::ImportProwlerUseCase`] plus a
/// background-worker dispatch so the HTTP request returns inside the 5 s
/// budget regardless of payload size. The in-memory stub in
/// [`crate::router`] tests returns a deterministic empty receipt.
#[async_trait]
pub trait ProwlerImportPort: Send + Sync {
    /// Ingest a Prowler v4 native-JSON report on behalf of `tenant_id`.
    /// `actor` is a free-form identifier (`user:alice`, `svc:ci-bot`)
    /// recorded in the audit log; `bytes` is the raw upload body
    /// (size enforced upstream by `RequestBodyLimitLayer` plus the
    /// per-call cap inside the use case).
    async fn import(
        &self,
        tenant_id: &str,
        actor: &str,
        bytes: &[u8],
    ) -> Result<crate::view::prowler_import_view::ProwlerImportResponse, ProwlerImportPortError>;
}

// ---------------------------------------------------------------------------
// Vulnerability scanner ingest port (P0-002)
// ---------------------------------------------------------------------------

/// Credentialed vulnerability-scanner ingest port (P0-002).
#[async_trait]
pub trait VulnIngestPort: Send + Sync {
    async fn import(
        &self,
        tenant_id: &str,
        source: &str,
        payload: &[u8],
    ) -> Result<crate::view::vuln_ingest_view::VulnImportResponse, Phase3PortError>;

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<crate::view::vuln_ingest_view::VulnImportView>, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// SCIM 2.0 provisioning port (P0-005 + MED-005 rotation/scoping)
// ---------------------------------------------------------------------------

/// Resolved bearer-token authentication context (MED-005).
///
/// Returned by [`ScimProvisionPort::authenticate`] so every downstream
/// SCIM handler can enforce scope without re-hitting the token store.
/// `tenant_id` is the same value the previous `authenticate` returned;
/// `scopes` is the immutable grant list bound at mint time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimAuthContext {
    /// Tenant id the token belongs to.
    pub tenant_id: String,
    /// Scopes granted at mint time. `default-deny`: an empty list
    /// authorises nothing.
    pub scopes: Vec<sx_scim::ScimScope>,
    /// Token id (uuid) — surfaced to the audit log so SCIM events can
    /// be tied back to a specific credential, not just the tenant.
    pub token_id: String,
}

/// SCIM 2.0 provisioning + token-admin port.
///
/// Backs the eight `/scim/v2/...` endpoints plus the per-tenant token
/// admin surface. The HTTP layer dispatches every request through this
/// single trait so the monolith adapter owns:
///
/// - constant-time bearer-token verification (`subtle::ConstantTimeEq`),
/// - the underlying `ScimProvisioner` (in-memory or Postgres),
/// - the audit log row written on every CREATE / UPDATE / DELETE.
///
/// Bearer-token verification happens **inside** [`Self::authenticate`];
/// every other method takes the tenant id the caller already authorised
/// against. The controller therefore looks like:
///
/// ```text
/// let tenant = port.authenticate(&bearer).await?;
/// let resp   = port.create_user(&tenant, body).await?;
/// ```
///
/// The HTTP layer maps [`sx_scim::ScimError`] into the SCIM-format error
/// envelope (`urn:ietf:params:scim:api:messages:2.0:Error`).
#[async_trait]
pub trait ScimProvisionPort: Send + Sync {
    /// Validate a bearer token.
    ///
    /// Returns a [`ScimAuthContext`] carrying the resolved tenant id
    /// plus the immutable scope grant bound at mint time. Implementations
    /// MUST use a constant-time hash comparison (`subtle::ConstantTimeEq`)
    /// and MUST NOT log the plaintext token. Tokens that are revoked,
    /// expired, or past their post-rotation grace window MUST return
    /// [`sx_scim::ScimError::Expired`] or [`sx_scim::ScimError::Unauthorised`]
    /// respectively.
    async fn authenticate(&self, bearer: &str) -> Result<ScimAuthContext, sx_scim::ScimError>;

    /// Create a SCIM user. Writes an audit row on success.
    async fn create_user(
        &self,
        tenant_id: &str,
        user: sx_scim::schema::user::ScimUser,
    ) -> Result<sx_scim::schema::user::ScimUser, sx_scim::ScimError>;

    /// Fetch a SCIM user by id.
    async fn get_user(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<sx_scim::schema::user::ScimUser, sx_scim::ScimError>;

    /// Replace a SCIM user (PUT semantics). Writes an audit row on success.
    async fn replace_user(
        &self,
        tenant_id: &str,
        id: &str,
        user: sx_scim::schema::user::ScimUser,
    ) -> Result<sx_scim::schema::user::ScimUser, sx_scim::ScimError>;

    /// Soft-delete a SCIM user (flips `active = false`). Writes an audit
    /// row on success.
    async fn delete_user(&self, tenant_id: &str, id: &str) -> Result<(), sx_scim::ScimError>;

    /// List + filter SCIM users.
    async fn list_users(
        &self,
        tenant_id: &str,
        query: sx_scim::service::provisioner::ListUsersQuery,
    ) -> Result<sx_scim::service::provisioner::ListUsersResult, sx_scim::ScimError>;

    /// Create a SCIM group. Writes an audit row on success.
    async fn create_group(
        &self,
        tenant_id: &str,
        group: sx_scim::schema::group::ScimGroup,
    ) -> Result<sx_scim::schema::group::ScimGroup, sx_scim::ScimError>;

    /// Fetch a SCIM group by id.
    async fn get_group(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<sx_scim::schema::group::ScimGroup, sx_scim::ScimError>;

    /// List + filter SCIM groups.
    async fn list_groups(
        &self,
        tenant_id: &str,
        query: sx_scim::service::provisioner::ListUsersQuery,
    ) -> Result<sx_scim::service::provisioner::ListGroupsResult, sx_scim::ScimError>;

    // --- Admin token surface (used by the dashboard) --------------------

    /// Mint a new SCIM bearer token for `tenant_id` (MED-005).
    ///
    /// `scopes` MUST be non-empty (default-deny). `ttl_days` is the
    /// optional rotation cadence override; when `None`, the
    /// [`sx_scim::ScimRotationPolicy::DEFAULT_CADENCE`] (90 days) is
    /// applied. Returns the plaintext value **once**; only its SHA-256
    /// hash is persisted.
    async fn mint_token(
        &self,
        tenant_id: &str,
        name: &str,
        scopes: Vec<sx_scim::ScimScope>,
        ttl_days: Option<u32>,
    ) -> Result<(crate::view::scim_view::ScimTokenView, String), sx_scim::ScimError>;

    /// Rotate an existing SCIM token (MED-005).
    ///
    /// Mints a brand-new token that inherits the original token's
    /// `scopes`, `ttl_days`, and `name`, then sets a `retire_at`
    /// timestamp on the original equal to `now + grace_window`
    /// (default 7 days). Within the grace window both old and new
    /// tokens authenticate; afterwards the old token returns
    /// [`sx_scim::ScimError::Expired`].
    ///
    /// Returns the new token's view + plaintext value.
    async fn rotate_token(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<(crate::view::scim_view::ScimTokenView, String), sx_scim::ScimError>;

    /// List every SCIM token issued for `tenant_id`.
    async fn list_tokens(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::view::scim_view::ScimTokenView>, sx_scim::ScimError>;

    /// Revoke a SCIM token by id (MED-005). Revocation is immediate —
    /// the token returns `Unauthorised` from the next request onward,
    /// regardless of grace-window state.
    async fn revoke_token(&self, tenant_id: &str, id: &str) -> Result<(), sx_scim::ScimError>;
}

// ---------------------------------------------------------------------------
// Copilot approval port (P1-012 human-in-loop gate for state-changing actions)
// ---------------------------------------------------------------------------

/// Thin HTTP-facing trait over [`sx_collab::copilot_approval::CopilotApprovalService`].
///
/// Wraps the queue + lifecycle so the API surface never imports the
/// concrete in-memory store. The composition root binds an
/// `Arc<dyn CopilotApprovalPort>` into [`crate::state::AppState`]; the
/// adapter additionally appends every transition to the `sx-audit`
/// tamper-evident chain.
///
/// ## Endpoints
///
/// - `GET  /v1/copilot/approvals`                  — list pending. RBAC: `copilot:review`.
/// - `POST /v1/copilot/approvals/{token}/decide`   — approve / reject.  RBAC: `copilot:review`.
///
/// ## Error contract
///
/// Failures collapse into [`Phase3PortError`] so the HTTP layer can share
/// the existing translation table — see [`crate::controller::map_phase3`].
/// A reject decision without a reason maps to
/// [`Phase3PortError::Invalid`], a stale token maps to
/// [`Phase3PortError::NotFound`], an expired token maps to
/// [`Phase3PortError::Invalid("approval expired")`], and an
/// already-decided token maps to
/// [`Phase3PortError::Invalid("approval already decided")`].
#[async_trait]
pub trait CopilotApprovalPort: Send + Sync {
    /// Queue a fresh proposal. The adapter stamps the audit chain with
    /// the proposed action before returning the token.
    async fn propose(
        &self,
        tenant_id: &str,
        proposer: sx_collab::copilot_approval::CopilotProposer,
        action: sx_collab::copilot_approval::ProposedAction,
    ) -> Result<sx_collab::copilot_approval::ApprovalToken, Phase3PortError>;

    /// Resolve `token` to a terminal state. The adapter stamps the audit
    /// chain with the decision before returning the outcome.
    async fn decide(
        &self,
        tenant_id: &str,
        token: sx_collab::copilot_approval::ApprovalToken,
        decision: sx_collab::copilot_approval::Decision,
        reviewer: &str,
        reason: Option<String>,
    ) -> Result<sx_collab::copilot_approval::DecisionOutcome, Phase3PortError>;

    /// List pending approvals scoped to `tenant_id`.
    async fn list_pending(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<sx_collab::copilot_approval::PendingApproval>, Phase3PortError>;

    /// Inspect any single approval (terminal or pending) by token.
    async fn inspect(
        &self,
        tenant_id: &str,
        token: sx_collab::copilot_approval::ApprovalToken,
    ) -> Result<sx_collab::copilot_approval::ApprovalSnapshot, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// RBA port (P1-003)
// ---------------------------------------------------------------------------

/// RBA port — single front door used by the login flow and the admin
/// dashboard. The login-flow path MUST always audit, even on `allow`.
#[async_trait]
pub trait RbaPort: Send + Sync {
    async fn evaluate(&self, input: RbaEvaluateInput) -> Result<RbaEvaluateOutput, RbaPortError>;

    /// List the most recent decisions for `tenant_id`.
    ///
    /// LOW-007: when `include_signals` is `true` the adapter populates
    /// the per-decision `signals` field with the per-signal sub-score /
    /// weight / weighted breakdown. The HTTP controller passes `true`
    /// only when the caller holds the `admin:users` capability so a
    /// regular operator cannot enumerate raw scoring inputs.
    async fn list_decisions(
        &self,
        tenant_id: &str,
        limit: u32,
        include_signals: bool,
    ) -> Result<Vec<crate::view::rba_view::RbaDecisionView>, RbaPortError>;

    async fn get_config(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::rba_view::RbaConfigView, RbaPortError>;

    async fn put_config(
        &self,
        tenant_id: &str,
        cfg: crate::view::rba_view::RbaConfigView,
    ) -> Result<crate::view::rba_view::RbaConfigView, RbaPortError>;

    /// List every enrolled device fingerprint for `(tenant, user)`
    /// (HIGH-001 follow-up). Powers the dashboard's "all my devices"
    /// view per the `rba_known_devices_tenant_user_idx` index.
    async fn list_known_devices(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<crate::view::rba_view::KnownDevicesResponse, RbaPortError>;

    /// Revoke a single device fingerprint (idempotent — revoking an
    /// already-revoked fingerprint succeeds).
    async fn revoke_known_device(
        &self,
        tenant_id: &str,
        user_id: &str,
        fp_hash: &str,
    ) -> Result<(), RbaPortError>;
}

// ---------------------------------------------------------------------------
// Remediation outcomes port (P1-011)
// ---------------------------------------------------------------------------

/// Read-only HTTP-side port over the `sx_remediation` outcome tracker.
#[async_trait]
pub trait RemediationOutcomesPort: Send + Sync {
    async fn metrics(
        &self,
        tenant_id: &str,
        window_days: u32,
    ) -> Result<crate::view::remediation_outcomes_view::RemediationMetricsView, Phase3PortError>;

    async fn list_regressions(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<crate::view::remediation_outcomes_view::RegressionListView, Phase3PortError>;
}

// ---------------------------------------------------------------------------
// Hunt port (P3-006)
// ---------------------------------------------------------------------------

/// Errors surfaced by [`HuntPort`].
///
/// Mirrors the three failure modes of `sx_hunt::HuntError` so the
/// controller does not depend on the hunt crate's umbrella error type
/// directly. `Invalid` covers both parse and compile failures (`400`);
/// `Dependency` is the ClickHouse-side execution failure (`502`);
/// `Internal` covers anything else.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HuntPortError {
    /// User-facing validation failure (parse or compile error).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Upstream (ClickHouse) failure.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Anything else.
    #[error("internal: {0}")]
    Internal(String),
}

/// Threat-hunting HTTP port.
///
/// Backs `POST /v1/hunt/query`. Implementations MUST:
///
/// * Parse the analyst's query through `sx_hunt::parse`.
/// * Compile it for the given tenant — every emitted SQL statement
///   carries an auto-injected `tenant_id = {tenant:String}` predicate.
/// * Execute against the configured backend (ClickHouse HTTP) using
///   named parameters; **never** by string-interpolating values into SQL.
/// * Append one audit entry per query attempt (success, parse error,
///   compile error, execution error).
#[async_trait]
pub trait HuntPort: Send + Sync {
    /// Execute one analyst query.
    async fn query(
        &self,
        tenant_id: &str,
        user_id: &str,
        raw_query: &str,
    ) -> Result<crate::view::hunt_view::HuntQueryResponse, HuntPortError>;
}

// ---------------------------------------------------------------------------
// AI security audit port (AI-SEC-001)
// ---------------------------------------------------------------------------

/// Errors surfaced by the AI-audit endpoints.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AiAuditPortError {
    /// The requested resource was not found.
    #[error("not found")]
    NotFound,
    /// Caller-supplied input is invalid.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The action is not authorized for this caller / target (e.g. an
    /// out-of-scope probe target).
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// A backing dependency (asset source, audit sink) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Catch-all internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

/// AI security audit port (AI-SEC-001). Backs the `/v1/ai-audit/*` surface.
///
/// All methods are tenant-scoped via the caller's JWT claim; the controller
/// resolves `tenant_id` from the authenticated user and never trusts a URL
/// or query string for it. Write actions additionally carry the acting
/// `actor` so the adapter can append a copilot-decision audit record.
#[async_trait]
pub trait AiAuditPort: Send + Sync {
    /// List the AI assets inventoried for the tenant.
    async fn list_assets(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::ai_audit_view::AiAssetListResponse, AiAuditPortError>;

    /// Build the tenant's AI-BOM (CycloneDX-ML-style).
    async fn aibom(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::ai_audit_view::AiBomView, AiAuditPortError>;

    /// List the built-in AI governance controls.
    async fn list_controls(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::ai_audit_view::AiControlListResponse, AiAuditPortError>;

    /// Run a full AI audit for the tenant on behalf of `actor` and return
    /// the report. The adapter records the run to the copilot-decision
    /// audit sink.
    async fn run_audit(
        &self,
        tenant_id: &str,
        actor: &str,
    ) -> Result<crate::view::ai_audit_view::AiAuditReportView, AiAuditPortError>;

    /// Run a red-team audit against a config-registered **external** LLM
    /// target (AI-SEC-002). The target's host must be in scope of the named
    /// Active, in-window, approved engagement, or the call is rejected with
    /// [`AiAuditPortError::Forbidden`]. `target_id` must name an entry in
    /// `ai_copilot.external_targets`.
    async fn run_external_audit(
        &self,
        tenant_id: &str,
        actor: &str,
        engagement_id: &str,
        target_id: &str,
    ) -> Result<crate::view::ai_audit_view::AiAuditReportView, AiAuditPortError>;
}

// ---------------------------------------------------------------------------
// UEBA port (P2-005)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum UebaPortError {
    #[error("not found")]
    NotFound,
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[async_trait]
pub trait UebaPort: Send + Sync {
    async fn get_baseline(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<crate::view::ueba_view::UebaBaselineView, UebaPortError>;

    async fn list_anomalies(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<crate::view::ueba_view::UebaAnomalyView>, UebaPortError>;
}

// ---------------------------------------------------------------------------
// Pentest port (PENTEST-001) — combined penetration & vulnerability testing
// ---------------------------------------------------------------------------

/// Errors surfaced by the combined pentest orchestration endpoints.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PentestPortError {
    /// The requested run does not exist for the caller's tenant.
    #[error("not found")]
    NotFound,
    /// Caller-supplied input was invalid (empty scope, bad phase, etc.).
    #[error("invalid: {0}")]
    Invalid(String),
    /// The run was refused by the engagement scope / kill-switch gate.
    #[error("denied: {0}")]
    Denied(String),
    /// Backing orchestrator / subsystem failure.
    #[error("internal: {0}")]
    Internal(String),
}

/// Combined penetration & vulnerability testing orchestration port.
///
/// Backs the `/v1/pentest/*` surface. Reads are tenant-scoped; the write
/// (`run`) also carries the authenticated actor for audit + report
/// attribution.
#[async_trait]
pub trait PentestPort: Send + Sync {
    /// Launch a combined pentest engagement and return its completed (or
    /// aborted) run.
    async fn run(
        &self,
        tenant_id: &str,
        actor: &str,
        request: crate::view::pentest_view::PentestRunRequestDto,
    ) -> Result<crate::view::pentest_view::PentestRunView, PentestPortError>;

    /// Fetch one run by id.
    async fn get_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<crate::view::pentest_view::PentestRunView, PentestPortError>;

    /// List the most recent runs, newest first, capped at `limit`.
    async fn list_runs(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<crate::view::pentest_view::PentestRunSummaryView>, PentestPortError>;
}

// ---------------------------------------------------------------------------
// UEBA admin port (HIGH-010) — freeze / unfreeze / snapshot per-user baseline
// ---------------------------------------------------------------------------

/// Errors surfaced by the UEBA admin freeze-mode endpoints (HIGH-010).
#[derive(Debug, Clone, thiserror::Error)]
pub enum UebaAdminPortError {
    /// No baseline exists for the requested `(tenant, user)` — cannot
    /// freeze a non-existent baseline.
    #[error("not found")]
    NotFound,
    /// The requested transition is not legal from the current state
    /// (e.g. `unfreeze` while not Frozen).
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
    /// Caller-supplied input is invalid (empty id, etc.).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Backing store / underlying adapter failure.
    #[error("internal: {0}")]
    Internal(String),
}

/// UEBA admin port (HIGH-010 anti-poisoning).
///
/// Backs:
/// - `POST /v1/admin/ueba/baseline/{user_id}/freeze`
/// - `POST /v1/admin/ueba/baseline/{user_id}/unfreeze`
/// - `GET  /v1/admin/ueba/baseline/{user_id}/snapshot`
///
/// All methods are tenant-scoped via the caller's JWT claim; the controller
/// resolves `tenant_id` from the authenticated user and never trusts a URL
/// or query string for it.
#[async_trait]
pub trait UebaAdminPort: Send + Sync {
    /// Freeze the per-user baseline. Captures the current live counters
    /// as a snapshot and gates future writes against the live baseline.
    async fn freeze(
        &self,
        tenant_id: &str,
        user_id: &str,
        actor: Option<&str>,
        reason: Option<&str>,
    ) -> Result<crate::view::ueba_admin_view::BaselineStateView, UebaAdminPortError>;

    /// Unfreeze a previously-frozen baseline. Runs the drift detector
    /// against the snapshot and routes findings to SOC. Flips state back
    /// to `Active`.
    async fn unfreeze(
        &self,
        tenant_id: &str,
        user_id: &str,
        actor: Option<&str>,
        reason: Option<&str>,
    ) -> Result<crate::view::ueba_admin_view::BaselineStateView, UebaAdminPortError>;

    /// Report the current state + (optional) snapshot.
    async fn snapshot(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<crate::view::ueba_admin_view::BaselineStateView, UebaAdminPortError>;
}

// ---------------------------------------------------------------------------
// Device-trust port (P2-008)
// ---------------------------------------------------------------------------

/// Device-trust port — backs the `/v1/device-trust/*` HTTP surface.
///
/// The trait re-exports the canonical shapes from
/// [`sx_device_trust`] so controllers and adapters share one source of
/// truth for policy, posture, and snapshot models. Concrete adapters
/// (in `services/sx-monolith`) own per-tenant policy storage and the
/// rolling snapshot ring; this port is the only thing the HTTP layer
/// ever sees.
///
/// ## Endpoints
///
/// - `GET /v1/device-trust/policy`   — returns the active policy for
///   the caller's tenant. Permissive default when none has been set.
/// - `PUT /v1/device-trust/policy`   — replaces the policy. Requires
///   the `admin:users` permission.
/// - `GET /v1/device-trust/sessions` — lists recent posture snapshots,
///   newest-first, capped at `limit`.
///
/// ## Errors
///
/// Failures collapse into [`sx_device_trust::service::DeviceTrustError`]
/// so the HTTP layer can map them via a dedicated translation table —
/// see [`crate::controller::map_device_trust`].
#[async_trait]
pub trait DeviceTrustPort: Send + Sync + std::fmt::Debug {
    /// Fetch the active policy for `tenant_id`. Returns the permissive
    /// default when none has been stored.
    async fn get_policy(
        &self,
        tenant_id: &str,
    ) -> Result<sx_device_trust::PosturePolicy, sx_device_trust::service::DeviceTrustError>;

    /// Replace the policy bound to `tenant_id`.
    async fn put_policy(
        &self,
        tenant_id: &str,
        policy: sx_device_trust::PosturePolicy,
    ) -> Result<sx_device_trust::PosturePolicy, sx_device_trust::service::DeviceTrustError>;

    /// Evaluate `posture` against the tenant's policy without mutating
    /// state. Used by the middleware to compute the per-request status.
    async fn evaluate(
        &self,
        tenant_id: &str,
        posture: &sx_device_trust::PostureClaims,
    ) -> Result<sx_device_trust::DeviceTrustDecision, sx_device_trust::service::DeviceTrustError>;

    /// Persist a posture observation. The adapter bounds the retained
    /// per-tenant snapshot count internally.
    async fn record_snapshot(
        &self,
        tenant_id: &str,
        snapshot: sx_device_trust::service::PostureSnapshot,
    ) -> Result<(), sx_device_trust::service::DeviceTrustError>;

    /// List recent snapshots, newest-first, capped at `limit`.
    async fn list_snapshots(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<
        Vec<sx_device_trust::service::PostureSnapshot>,
        sx_device_trust::service::DeviceTrustError,
    >;

    /// Posture-JWT signing secret used by the middleware.
    fn jwt_secret(&self) -> Vec<u8>;
}

// ---------------------------------------------------------------------------
// SOAR low-code workflow builder port (P3-005)
// ---------------------------------------------------------------------------

/// Errors surfaced by the SOAR HTTP layer. Translated to [`crate::error::ApiError`]
/// via [`crate::controller::map_soar`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum SoarPortError {
    /// Workflow / run uuid does not exist for the caller's tenant.
    #[error("not found")]
    NotFound,
    /// Caller-supplied payload failed semantic validation (e.g. malformed
    /// uuid, action chain out of bounds).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Internal failure (executor port error, poisoned mutex, etc.).
    #[error("internal: {0}")]
    Internal(String),
}

/// SOAR port — backs the `/v1/soar/*` HTTP surface.
///
/// All methods are tenant-scoped: a workflow created under tenant `A`
/// is invisible to tenant `B` and cannot be invoked via URL guessing.
#[async_trait]
pub trait SoarPort: Send + Sync {
    /// Persist a new workflow for `tenant_id`.
    async fn create_workflow(
        &self,
        tenant_id: &str,
        req: crate::view::soar_view::CreateWorkflowRequest,
    ) -> Result<crate::view::soar_view::WorkflowView, SoarPortError>;

    /// Fetch a previously created workflow.
    async fn get_workflow(
        &self,
        tenant_id: &str,
        workflow_id: &str,
    ) -> Result<crate::view::soar_view::WorkflowView, SoarPortError>;

    /// List workflows for `tenant_id`, capped at `limit` rows.
    ///
    /// Returns the narrow [`crate::view::soar_view::WorkflowSummaryView`]
    /// projection (id, name, version, created_at). Default implementation
    /// returns an empty vector so existing adapter types stay
    /// source-compatible.
    async fn list_workflows(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<Vec<crate::view::soar_view::WorkflowSummaryView>, SoarPortError> {
        let _ = (tenant_id, limit);
        Ok(Vec::new())
    }

    /// Execute a workflow once and return the run log row.
    async fn run_workflow(
        &self,
        tenant_id: &str,
        workflow_id: &str,
        event: sx_soar::TriggerEvent,
    ) -> Result<crate::view::soar_view::WorkflowRunView, SoarPortError>;

    /// Fetch a previously executed run.
    async fn get_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<crate::view::soar_view::WorkflowRunView, SoarPortError>;
}

// ---------------------------------------------------------------------------
// SAML 2.0 Service Provider port (P0-004)
// ---------------------------------------------------------------------------

/// Errors surfaced by the SAML SP port.
///
/// Coarse-grained on purpose: the HTTP layer must not distinguish
/// "bad signature" from "wrong audience" or "replay" in a way that
/// helps an attacker calibrate a forgery.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SamlPortError {
    /// SAML SP feature is disabled or not configured for this tenant.
    #[error("disabled: {0}")]
    Disabled(String),
    /// Tenant id was unknown or the IdP record was missing.
    #[error("not found")]
    NotFound,
    /// Assertion / response was structurally malformed, signature
    /// invalid, audience wrong, time-window failed, or the response
    /// was a replay. Collapsed to a single variant by design.
    #[error("rejected")]
    Rejected,
    /// Dependency (storage, replay-cache, ...) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// DLP port (P2-006)
// ---------------------------------------------------------------------------

/// Wire-layer detector kind. Mirrors `sx_dlp::DlpMatchKind` so the port
/// keeps its public schema independent of the implementation crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpDetectorKind {
    /// Credit card number (issuer prefix + Luhn).
    CreditCard,
    /// US Social Security Number.
    SsnUs,
    /// AWS access key id.
    AwsAccessKey,
    /// AWS secret access key (40-char base64 heuristic).
    AwsSecretKey,
    /// GitHub personal access token.
    GithubPat,
    /// JSON Web Token.
    Jwt,
    /// PEM-encoded private key armor header.
    PemPrivateKey,
    /// Email address.
    Email,
    /// North-American phone number.
    Phone,
    /// GCP service-account credential.
    GcpServiceAccount,
    /// Slack bot / user / app token.
    SlackToken,
    /// Named-entity-recognition hit.
    NamedEntity,
}

/// HIGH-004 per-signal evidence row carried on the wire so the
/// dashboard can render the *why* of a finding (regex match,
/// Luhn check, entropy band, NER-context cue).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlpSignalView {
    /// Stable signal identifier (`regex_match` / `luhn_check` /
    /// `entropy_band` / `ner_context`).
    pub kind: String,
    /// `[0.0, 1.0]` sub-score this signal contributed before weighting.
    pub sub_score: f32,
    /// Calibrated fusion weight applied to `sub_score` (0.40 / 0.30 /
    /// 0.15 / 0.15).
    pub weight: f32,
    /// Short human-readable rationale (e.g. `"luhn ok"`).
    pub rationale: String,
}

/// One detector hit projected onto the wire.
///
/// TOP5-#3-P2-003 added the same finding-enrichment surface
/// (`cwe[]` / `mitre_attack[]` / `compliance` / `enrichment_confidence`)
/// that
/// [`crate::view::scan_view::ScanFinding`] carries — so DLP detection
/// events emitted by `POST /v1/dlp/scan` and `GET /v1/dlp/history`
/// reach the wire with the canonical Phase 1 payload. Empty fields
/// serialise as omitted JSON keys via `skip_serializing_if`, keeping
/// legacy clients (and the LOW-009 explainability dashboard) compatible.
///
/// `cvss` is intentionally absent from the DLP surface — DLP is a
/// detection (sensitive data present in a scanned payload), not a
/// vulnerability proof. See
/// [`sx_core::reference::dlp_enrichment`] §"CVSS posture for DLP".
//
// `Eq` is intentionally NOT derived: the enrichment payload now embeds
// MITRE ATT&CK structs and CWE / NIST string newtypes whose
// `PartialEq` is sufficient, but the enrichment design mirrors the
// `ScanFinding` shape that already dropped `Eq` for the same reason —
// keeping the trait set consistent across the API crate avoids a
// downstream `Eq` requirement leaking back in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlpMatchView {
    /// Detector category.
    pub kind: DlpDetectorKind,
    /// Byte offset into the payload.
    pub offset: usize,
    /// Match length in bytes.
    pub length: usize,
    /// Redacted preview safe for logs / dashboards.
    pub redacted_preview: String,
    /// HIGH-004 fused multi-signal confidence in `[0.0, 1.0]`.
    /// `0.0` when no fusion ran (legacy producers).
    #[serde(default)]
    pub confidence: f32,
    /// HIGH-004 per-signal explainability breakdown.
    /// Empty when fusion has not been applied to the match.
    #[serde(default)]
    pub signals: Vec<DlpSignalView>,

    // ----- enrichment payload (TOP5-#3-P2-003) ---------------------------
    /// CWE identifiers describing the underlying weakness class(es)
    /// — e.g. CWE-311 for `credit_card`, CWE-798 for cloud credentials,
    /// CWE-359 for `ssn_us`. Populated by the adapter via
    /// [`sx_core::reference::dlp_enrichment::dlp_enrichment`]; informational
    /// kinds (`email` / `phone` / `named_entity`) leave it empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<sx_core::value_object::cwe::CweId>,
    /// MITRE ATT&CK techniques / sub-techniques this finding maps to
    /// — most DLP variants map onto T1552 Unsecured Credentials and
    /// its sub-techniques (T1552.001 Credentials In Files,
    /// T1552.004 Private Keys).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_attack: Vec<sx_core::value_object::mitre_attack::MitreAttackTechnique>,
    /// Compliance-framework control mappings (NIST 800-53 / PCI DSS /
    /// HIPAA primarily for the DLP family; ISO 27001 / SOC 2 left empty
    /// unless the canonical table grows them).
    #[serde(
        default,
        skip_serializing_if = "sx_core::value_object::compliance::ComplianceTags::is_empty"
    )]
    pub compliance: sx_core::value_object::compliance::ComplianceTags,
    /// Detector confidence projected onto the canonical
    /// [`sx_core::entity::finding::Finding::confidence`] shape
    /// (`Option<f64>`). Distinct from the existing `confidence: f32`
    /// field above — the legacy `confidence` field is the **fusion**
    /// score consumed by the explainability dashboard; this
    /// `enrichment_confidence` is the wire projection auditors and SOC
    /// pipelines expect on every enriched finding. Same numeric value,
    /// widened to f64 to match the canonical Finding shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment_confidence: Option<f64>,

    // ----- source-aware location (TOP5-#3 Phase 3) -----------------------
    /// 1-indexed source line, for line-oriented DLP inputs (config
    /// files, YAML / TOML / JSON payloads). Passes through onto the
    /// SARIF `region.startLine` field when the detection is projected
    /// onto a [`sx_core::entity::finding::Finding`]. Raw / network
    /// payloads leave it `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-indexed source column, paired with [`Self::line`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// Per-category roll-up emitted by a scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlpKindSummaryView {
    /// Detector kind.
    pub kind: DlpDetectorKind,
    /// How many matches of this kind were found.
    pub count: usize,
}

/// `POST /v1/dlp/scan` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlpScanResultView {
    /// Scan id (uuid v7).
    pub id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// RFC 3339 timestamp.
    pub finished_at: String,
    /// Payload length in bytes (not chars).
    pub bytes_scanned: usize,
    /// Total matches across categories.
    pub total_matches: usize,
    /// Per-category summary.
    pub summary: Vec<DlpKindSummaryView>,
    /// Full hit list.
    pub matches: Vec<DlpMatchView>,
}

/// Per-tenant detector configuration on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlpDetectorConfigView {
    /// Owning tenant.
    pub tenant_id: String,
    /// Enabled detector kinds — order is implementation-defined but stable.
    pub enabled: Vec<DlpDetectorKind>,
    /// HIGH-004 per-tenant minimum-confidence threshold in `[0.0, 1.0]`.
    /// Findings whose fused multi-signal confidence falls below the
    /// threshold are dropped silently before reaching the wire.
    #[serde(default)]
    pub min_confidence: f32,
}

/// Wire shape for the per-tenant HIGH-004 confidence-threshold admin endpoint.
///
/// (`GET|PUT /v1/admin/dlp/thresholds`). Carried separately from
/// [`DlpDetectorConfigView`] because operators with `admin:dlp` may
/// update the threshold without touching the detector enable list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlpThresholdView {
    /// Owning tenant.
    pub tenant_id: String,
    /// Minimum fused confidence in `[0.0, 1.0]` for a finding to be
    /// emitted. Default is `0.0` (permissive — every finding emitted).
    pub min_confidence: f32,
}

/// Port-level error contract for the DLP surface.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DlpPortError {
    /// Payload exceeded the 10 MB hard cap.
    #[error("payload too large: {bytes} bytes (max {max})")]
    PayloadTooLarge {
        /// Reported payload size.
        bytes: usize,
        /// Hard cap copied from the implementation crate.
        max: usize,
    },
    /// Caller-side validation failure (empty tenant / empty body / etc).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Implementation-side internal error.
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// GRC port (P2-009 — Vanta / Drata / ServiceNow outbound integration)
// ---------------------------------------------------------------------------

/// Errors surfaced by [`GrcPort`].
///
/// Collapses both the config-store side (lookup, validation, secret
/// resolution) and the connector side (rate limit, unauthorized,
/// transport) into a single error enum so the HTTP layer can map them
/// via a dedicated translation table — see
/// [`crate::controller::grc::map_grc`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum GrcPortError {
    /// No GRC connection configured for `(tenant_id, kind)`.
    #[error("not found")]
    NotFound,
    /// Caller-supplied request was malformed (unknown kind, missing
    /// payload, ServiceNow row missing `instance_url`, ...).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Upstream rejected on authn/authz grounds, **or** the secret store
    /// refused the lookup.
    #[error("unauthorized")]
    Unauthorized,
    /// Upstream rate-limited the push. The dispatcher already retried —
    /// the API surface presents the exhausted budget as a dependency
    /// failure.
    #[error("rate limited")]
    RateLimited,
    /// Underlying transport / dependency failure (HTTP timeout, secrets
    /// backend unavailable, ...).
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error or unhandled internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Plugin marketplace + SDK port (P3-007)
// ---------------------------------------------------------------------------

/// Errors surfaced by [`PluginsPort`].
///
/// Collapsed into [`crate::error::ApiError`] by
/// [`crate::controller::map_plugins`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum PluginsPortError {
    /// `(tenant_id, plugin_id)` not found.
    #[error("not found")]
    NotFound,
    /// Request rejected — bad URL scheme, invalid event kind, etc.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Underlying dependency (storage, DEK pipeline) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error / unhandled internal state.
    #[error("internal: {0}")]
    Internal(String),
}

/// Outcome handed back from a successful ACS verification. The HTTP
/// layer projects this onto either a JSON body or a redirect with a
/// session cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAcsOutcome {
    /// Tenant the IdP record was scoped to.
    pub tenant_id: String,
    /// User's email (mapped from SAML `NameID`).
    pub email: String,
    /// Roles derived from the `Group` SAML attribute.
    pub roles: Vec<String>,
    /// `AuthnStatement/@SessionIndex` — preserved for SLO.
    pub session_index: Option<String>,
    /// Assertion's `Conditions/@NotOnOrAfter` — the hard session ceiling.
    pub not_on_or_after: time::OffsetDateTime,
}

/// SAML SP port — backs the `/v1/auth/saml/{metadata,acs,logout}`
/// endpoints.
///
/// Backed in production by `sx_iam::service::saml::*` plus a per-tenant
/// IdP-config repository (stored in `iam_saml_idp_config`). Disabled
/// deployments install a stub that returns
/// [`SamlPortError::Disabled`] from every method.
#[async_trait]
pub trait SamlSpPort: Send + Sync + std::fmt::Debug {
    /// Return the SP's metadata XML document for the configured entity
    /// id.
    async fn metadata(&self) -> Result<String, SamlPortError>;

    /// Process a SAML `<Response>` arriving on the ACS endpoint.
    ///
    /// * `tenant_id_hint` — optional tenant override carried in the form
    ///   body (multi-tenant deployments key off this to pick the IdP).
    /// * `saml_response_b64` — the base64-encoded `<Response>` XML.
    /// * `relay_state` — opaque echo from the IdP; the port treats it as
    ///   a session-binding token if it can.
    async fn process_acs(
        &self,
        tenant_id_hint: Option<&str>,
        saml_response_b64: &str,
        relay_state: Option<&str>,
    ) -> Result<SamlAcsOutcome, SamlPortError>;

    /// Build a SAML `LogoutRequest` for the user identified by
    /// `(tenant_id, name_id)`. The HTTP layer redirects the user agent
    /// to the returned URL.
    async fn build_logout(
        &self,
        tenant_id: &str,
        name_id: &str,
        session_index: Option<&str>,
    ) -> Result<String, SamlPortError>;
}

/// Error surface for the SAML IdP admin port.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SamlIdpAdminPortError {
    /// The submitted config failed validation (bad URL, unknown signing
    /// algorithm, cert length out of range, …). Maps to `422`.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Storage / dependency failure. Maps to `500`.
    #[error("internal: {0}")]
    Internal(String),
}

/// Per-tenant SAML IdP configuration admin port (P0-004).
///
/// Backs `GET` / `PUT /v1/admin/saml/idp`. Independent of the
/// [`SamlSpPort`] enabled/disabled flag so an operator can author the IdP
/// record (durably) before flipping `saml.enabled = true`. The adapter
/// persists to `saml_idp_config` when a database is wired and keeps the
/// live SP adapter's in-memory record cache in sync.
#[async_trait]
pub trait SamlIdpAdminPort: Send + Sync + std::fmt::Debug {
    /// Return the IdP config for `tenant_id`, or `None` when unset.
    async fn get_idp(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::view::saml_view::SamlIdpConfigView>, SamlIdpAdminPortError>;

    /// Upsert the IdP config for `tenant_id` and return the stored value.
    async fn set_idp(
        &self,
        tenant_id: &str,
        config: crate::view::saml_view::SamlIdpConfigView,
    ) -> Result<crate::view::saml_view::SamlIdpConfigView, SamlIdpAdminPortError>;
}

/// DLP HTTP port — backs `POST /v1/dlp/scan` and `GET|PUT /v1/dlp/config`.
#[async_trait]
pub trait DlpPort: Send + Sync {
    /// Scan a single payload for sensitive content. The adapter is
    /// expected to never persist the raw payload.
    async fn scan(
        &self,
        tenant_id: &str,
        payload: &[u8],
    ) -> Result<DlpScanResultView, DlpPortError>;

    /// Fetch the active per-tenant detector configuration.
    async fn get_config(&self, tenant_id: &str) -> Result<DlpDetectorConfigView, DlpPortError>;

    /// Replace the tenant's detector configuration. `min_confidence` is
    /// optional; pass `None` to leave the existing threshold untouched
    /// (HIGH-004 — the dedicated `/v1/admin/dlp/thresholds` endpoint is
    /// preferred for confidence-only updates).
    async fn put_config(
        &self,
        tenant_id: &str,
        enabled: Vec<DlpDetectorKind>,
        min_confidence: Option<f32>,
    ) -> Result<DlpDetectorConfigView, DlpPortError>;

    /// HIGH-004 — fetch the per-tenant confidence threshold (admin
    /// surface). Backs `GET /v1/admin/dlp/thresholds`.
    async fn get_threshold(&self, tenant_id: &str) -> Result<DlpThresholdView, DlpPortError>;

    /// HIGH-004 — replace the per-tenant confidence threshold (admin
    /// surface). Backs `PUT /v1/admin/dlp/thresholds`. The implementation
    /// clamps `min_confidence` into `[0.0, 1.0]`.
    async fn put_threshold(
        &self,
        tenant_id: &str,
        min_confidence: f32,
    ) -> Result<DlpThresholdView, DlpPortError>;
}

/// GRC integration port — backs the `/v1/grc/*` HTTP surface.
///
/// Three call sites are wired:
///
/// - `upsert_config` — `POST /v1/grc/configs` writes the per-tenant
///   connection row and the supplied secret into the configured
///   [`sx_secrets::SecretsProvider`].
/// - `test_connection` — `POST /v1/grc/configs/{kind}/test` resolves
///   the row + secret and probes the connector with a synthetic
///   evidence push so the dashboard can validate the operator-supplied
///   token.
/// - `push` — `POST /v1/grc/push` dispatches a single evidence or
///   finding payload through the exponential-backoff +
///   dead-letter pipeline in `sx-integrations`.
#[async_trait]
pub trait GrcPort: Send + Sync + std::fmt::Debug {
    /// Upsert the per-tenant GRC connection row.
    ///
    /// The caller hands the API token / password inline; the adapter
    /// rewrites it to the configured secrets backend at
    /// `tenants/{tenant_id}/grc/{kind}/secret` and persists only the
    /// path on the row.
    async fn upsert_config(
        &self,
        tenant_id: &str,
        req: crate::view::grc_view::GrcConfigUpsertRequest,
    ) -> Result<crate::view::grc_view::GrcConfigView, GrcPortError>;

    /// List every connection row for `tenant_id`. Used by the dashboard
    /// to render the connection table.
    async fn list_configs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::view::grc_view::GrcConfigView>, GrcPortError>;

    /// Probe the connection for `(tenant_id, kind)`. The adapter
    /// resolves the row, fetches the secret, constructs the connector,
    /// and pushes a synthetic evidence record. The connector outcome
    /// is surfaced as [`crate::view::grc_view::GrcConnectionTestView`].
    async fn test_connection(
        &self,
        tenant_id: &str,
        kind: &str,
    ) -> Result<crate::view::grc_view::GrcConnectionTestView, GrcPortError>;

    /// Dispatch an evidence or finding push to the connector configured
    /// for `(tenant_id, kind)`.
    async fn push(
        &self,
        tenant_id: &str,
        req: crate::view::grc_view::GrcPushRequest,
    ) -> Result<crate::view::grc_view::GrcPushOutcomeView, GrcPortError>;
}

/// Plugin marketplace + SDK port.
///
/// Backs the four `/v1/plugins/*` endpoints. Every method is
/// tenant-scoped — the controller derives `tenant_id` from the caller's
/// JWT claims, never from URL / body input. Adapters are expected to
/// surface install + uninstall + dispatch events on the audit log; the
/// controller adds a `tracing::info!(target = "audit", …)` event on top
/// for the structured audit chain.
#[async_trait]
pub trait PluginsPort: Send + Sync + std::fmt::Debug {
    /// List every plugin registered for `tenant_id`, newest-first.
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<sx_plugins::RegisteredPlugin>, PluginsPortError>;

    /// Install a fresh plugin. The adapter mints a [`sx_plugins::PluginId`]
    /// and persists the encrypted secret.
    async fn install(
        &self,
        tenant_id: &str,
        manifest: sx_plugins::PluginManifest,
        secret: secrecy::SecretString,
    ) -> Result<sx_plugins::RegisteredPlugin, PluginsPortError>;

    /// Uninstall a previously-registered plugin.
    async fn uninstall(
        &self,
        tenant_id: &str,
        plugin_id: sx_plugins::PluginId,
    ) -> Result<(), PluginsPortError>;

    /// Return the most recent `limit` dispatches for `plugin_id`,
    /// newest-first. Used by the dashboard's plugin-detail page.
    async fn list_dispatches(
        &self,
        tenant_id: &str,
        plugin_id: sx_plugins::PluginId,
        limit: usize,
    ) -> Result<Vec<sx_plugins::DispatchRecord>, PluginsPortError>;
}

// ---------------------------------------------------------------------------
// Cloud-drift port (P2-004)
// ---------------------------------------------------------------------------

/// Errors returned by the cloud-drift port.
///
/// Collapsed shape so the HTTP layer's `map_cloud_drift` table can stay
/// tiny. Concrete adapters (in `services/sx-monolith`) translate richer
/// underlying error types from `sx_cloud::drift` into these variants.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CloudDriftPortError {
    /// The requested resource (baseline / scan) does not exist for the
    /// caller's tenant.
    #[error("not found")]
    NotFound,
    /// Caller-supplied input failed validation past the HTTP boundary
    /// (e.g. base64-decoded payload too large, unknown format string).
    #[error("invalid: {0}")]
    Invalid(String),
    /// A downstream dependency (cloud-inventory fan-out, parser) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Internal invariant violation. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),
}

/// Cloud-drift port — backs the `/v1/cloud/drift/*` HTTP surface (P2-004).
///
/// Concrete adapters wrap [`sx_cloud::drift::CloudDriftService`] and the
/// live-inventory connectors so the controller can:
///
/// 1. Upload an IaC baseline (Terraform JSON or CloudFormation YAML) and
///    receive a freshly minted id.
/// 2. List baselines available to the caller's tenant.
/// 3. Trigger a scan: fetch the live cloud inventory, diff against the
///    selected baseline, persist + return the resulting drift entries.
/// 4. Read previously detected drift entries (optionally filtered by
///    asset).
///
/// All methods are tenant-scoped — the adapter must never return a
/// baseline or drift entry that belongs to a different tenant.
#[async_trait]
pub trait CloudDriftPort: Send + Sync {
    /// Persist a baseline document. `format` must be one of
    /// `"terraform_json"` or `"cloudformation_yaml"`. `payload` is the raw
    /// (already-decoded) IaC document. Returns the newly minted baseline
    /// summary.
    async fn upload_baseline(
        &self,
        tenant_id: &str,
        name: &str,
        format: &str,
        payload: Vec<u8>,
    ) -> Result<crate::view::cloud_drift_view::UploadBaselineResponse, CloudDriftPortError>;

    /// List baselines available to `tenant_id`, ordered by name.
    async fn list_baselines(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::cloud_drift_view::ListBaselinesResponse, CloudDriftPortError>;

    /// Run a drift scan: fetch the live cloud inventory for `tenant_id` /
    /// `engagement_id`, diff against `baseline_id` (or the tenant's most
    /// recent baseline when `None`), persist the entries, return them.
    async fn scan(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        baseline_id: Option<&str>,
    ) -> Result<crate::view::cloud_drift_view::DriftScanResponse, CloudDriftPortError>;

    /// Read drift entries previously detected for `tenant_id`, optionally
    /// filtered by `asset_filter` substring (matched against
    /// `resource_id`).
    async fn list_drift(
        &self,
        tenant_id: &str,
        asset_filter: Option<&str>,
    ) -> Result<crate::view::cloud_drift_view::DriftListResponse, CloudDriftPortError>;
}

// ---------------------------------------------------------------------------
// IR playbooks port (P3-004)
// ---------------------------------------------------------------------------

/// Errors returned by the IR-playbooks port.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum IrPlaybookPortError {
    #[error("not found")]
    NotFound,
    #[error("illegal step transition: {0}")]
    IllegalStepTransition(String),
    #[error("illegal incident transition: {0}")]
    IllegalIncidentTransition(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// P1-004 — Automated compliance evidence collector.
// ---------------------------------------------------------------------------

/// Error surface for [`ComplianceEvidencePort`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum ComplianceEvidencePortError {
    #[error("not found")]
    NotFound,
    #[error("forbidden")]
    Forbidden,
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("dependency: {0}")]
    Dependency(String),
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Risk tuning port — P1-014 (per-tenant risk weights + thresholds)
// ---------------------------------------------------------------------------

/// Errors surfaced by [`RiskTuningPort`].
///
/// The HTTP layer translates these into [`crate::error::ApiError`] via
/// [`crate::controller::map_risk_tuning`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum RiskTuningPortError {
    /// Per-field or cross-field validation failed (sum out of band,
    /// non-monotone thresholds, range violation, empty tenant id).
    /// Maps to HTTP `422 Unprocessable Entity`.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Downstream dependency failure (DB, queue, audit sink). Maps to
    /// HTTP `502 Bad Gateway`.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Logic error that should be unreachable in production. Maps to
    /// HTTP `500 Internal Server Error`.
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Bug-bounty bridge port (P3-010)
// ---------------------------------------------------------------------------

/// Errors surfaced by [`BugBountyPort`].
///
/// Collapses both the config-store side (lookup, validation, secret
/// resolution) and the connector side (rate limit, unauthorized,
/// transport) into a single error enum so the HTTP layer can map them
/// via a dedicated translation table — see
/// [`crate::controller::bugbounty::map_bugbounty`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum BugBountyPortError {
    /// No bug-bounty connection configured for the
    /// `(tenant_id, platform, program_handle)` tuple.
    #[error("not found")]
    NotFound,
    /// Caller-supplied request was malformed (unknown platform, missing
    /// `api_username` for HackerOne, severity below the HIGH floor, …).
    #[error("invalid: {0}")]
    Invalid(String),
    /// Upstream rejected on authn/authz grounds (bad token on push,
    /// signature mismatch on ingest, secret store refused the lookup).
    #[error("unauthorized")]
    Unauthorized,
    /// Upstream rate-limited the push. The dispatcher already retried —
    /// the API surface presents the exhausted budget as a dependency
    /// failure.
    #[error("rate limited")]
    RateLimited,
    /// Underlying transport / dependency failure (HTTP timeout, secrets
    /// backend unavailable, ...).
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error or unhandled internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// API DAST — Postman collection replay (P2-013)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiDastFindingView {
    pub check_id: String,
    pub severity: String,
    pub method: String,
    pub url: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_item: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiDastScanResultView {
    pub scan_id: String,
    pub tenant_id: String,
    pub collection_name: String,
    pub base_url: String,
    pub started_at: String,
    pub ended_at: String,
    pub requests_sent: u32,
    pub findings: Vec<ApiDastFindingView>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ApiDastPortError {
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("dependency: {0}")]
    Dependency(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// IR-playbooks port — backs the `/v1/ir/*` HTTP surface (P3-004).
#[async_trait]
#[allow(clippy::too_many_arguments)] // update_step covers tenant + actor + 5 mutable step fields
pub trait IrPlaybooksPort: Send + Sync + std::fmt::Debug {
    async fn list_playbooks(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::ir_view::ListPlaybooksResponse, IrPlaybookPortError>;

    async fn open_incident(
        &self,
        tenant_id: &str,
        actor: &str,
        playbook_id: &str,
        title: &str,
        severity: Option<&str>,
    ) -> Result<crate::view::ir_view::IncidentView, IrPlaybookPortError>;

    async fn get_incident(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<crate::view::ir_view::IncidentView, IrPlaybookPortError>;

    async fn update_step(
        &self,
        tenant_id: &str,
        actor: &str,
        incident_id: &str,
        step_id: &str,
        status: Option<&str>,
        owner: Option<&str>,
        reason: Option<&str>,
        evidence: Option<&str>,
    ) -> Result<crate::view::ir_view::IncidentView, IrPlaybookPortError>;
}

/// Compliance evidence collector port. Backs `/v1/compliance/evidence/*`.
#[async_trait]
pub trait ComplianceEvidencePort: Send + Sync {
    async fn collect(
        &self,
        tenant_id: &str,
        period_start: Option<&str>,
        period_end: Option<&str>,
    ) -> Result<
        crate::view::compliance_evidence_view::CollectEvidenceResponseView,
        ComplianceEvidencePortError,
    >;

    async fn list_bundles(
        &self,
        tenant_id: &str,
    ) -> Result<
        crate::view::compliance_evidence_view::ListBundlesResponseView,
        ComplianceEvidencePortError,
    >;

    async fn download_bundle(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<
        crate::view::compliance_evidence_view::DownloadBundleResponseView,
        ComplianceEvidencePortError,
    >;
}

/// API DAST port — backs `POST /v1/discovery/dast/scan`.
#[async_trait]
pub trait ApiDastPort: Send + Sync + std::fmt::Debug {
    async fn scan(
        &self,
        tenant_id: &str,
        collection: &[u8],
        base_url: &str,
        bearer: Option<secrecy::SecretString>,
        idor_probe_ids: Vec<String>,
    ) -> Result<ApiDastScanResultView, ApiDastPortError>;

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<ApiDastScanResultView>, ApiDastPortError>;
}
/// Bug-bounty bridge port — backs the `/v1/integrations/bugbounty/*`
/// HTTP surface (P3-010).
///
/// Four call sites are wired:
///
/// - `upsert_config` — `POST /v1/integrations/bugbounty/configs` writes
///   the per-tenant per-platform connection row and the supplied
///   secrets (API token + inbound webhook HMAC) into the configured
///   [`sx_secrets::SecretsProvider`].
/// - `list_configs` — `GET /v1/integrations/bugbounty/configs` returns
///   every connection for the caller's tenant.
/// - `push` — `POST /v1/integrations/bugbounty/push` dispatches a
///   triaged finding to the platform as an internal draft note. The
///   adapter enforces the severity ≥ HIGH floor locally.
/// - `inbound` — `POST /v1/integrations/bugbounty/inbound/{platform}`
///   verifies the platform-supplied HMAC signature over the raw body
///   (constant-time), maps the payload to a canonical finding tagged
///   `bugbounty.<platform>.researcher_<id>`, dedupes against the
///   tenant's existing findings (TF-IDF cosine ≥ 0.85), and emits the
///   audit event.
#[async_trait]
pub trait BugBountyPort: Send + Sync + std::fmt::Debug {
    /// Upsert the per-tenant per-platform connection row.
    async fn upsert_config(
        &self,
        tenant_id: &str,
        req: crate::view::bugbounty_view::BugBountyConfigUpsertRequest,
    ) -> Result<crate::view::bugbounty_view::BugBountyConfigView, BugBountyPortError>;

    /// List every configured connection for `tenant_id`.
    async fn list_configs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::view::bugbounty_view::BugBountyConfigView>, BugBountyPortError>;

    /// Push a triaged finding as an internal draft note. The adapter
    /// validates the severity floor and translates the connector outcome
    /// into the view shape.
    async fn push(
        &self,
        tenant_id: &str,
        req: crate::view::bugbounty_view::BugBountyPushRequest,
    ) -> Result<crate::view::bugbounty_view::BugBountyPushOutcomeView, BugBountyPortError>;

    /// Verify the inbound webhook signature, map to a canonical
    /// finding, dedupe against existing findings, and surface the
    /// outcome. `body_bytes` is the *raw* request body (the controller
    /// reads it before any JSON deserialisation so the bytes hashed
    /// match the bytes the platform signed).
    async fn inbound(
        &self,
        tenant_id: &str,
        platform: &str,
        signature_header: Option<&str>,
        body_bytes: axum::body::Bytes,
    ) -> Result<crate::view::bugbounty_view::BugBountyInboundOutcomeView, BugBountyPortError>;
}

/// Per-tenant risk-model tuning port (P1-014).
///
/// Backs the three `/v1/risk/config*` endpoints:
///
/// - [`Self::get_override`]   — the sparse stored override (defaults
///   only when no row exists).
/// - [`Self::put_override`]   — replace the sparse override, record the
///   audit diff, enqueue an idempotent recompute. Admin RBAC is
///   enforced at the controller layer; the port itself trusts the
///   caller. The `actor` argument carries the bearer-less sub-claim
///   so the audit sink can attribute the write — **never** the bearer.
/// - [`Self::get_effective`]  — the merged effective config (defaults
///   ⊕ override).
/// - [`Self::defaults`]       — the platform-default effective config
///   used by `GET /v1/risk/config` when no override row exists.
///
/// Every method takes `tenant_id` explicitly so the implementation can
/// enforce cross-tenant isolation regardless of where the caller's
/// scope was resolved.
#[async_trait]
pub trait RiskTuningPort: Send + Sync {
    /// Fetch the per-tenant sparse override row. Absent rows are
    /// surfaced as the empty override (every field `None`).
    async fn get_override(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::risk_tuning_view::TenantRiskConfigView, RiskTuningPortError>;

    /// Replace the per-tenant override row, record the audit diff,
    /// and enqueue an idempotent recompute. Returns the merged
    /// effective config the scorer will use from now on.
    async fn put_override(
        &self,
        tenant_id: &str,
        actor: Option<String>,
        req: crate::view::risk_tuning_view::TenantRiskConfigView,
    ) -> Result<crate::view::risk_tuning_view::EffectiveRiskConfigView, RiskTuningPortError>;

    /// Fetch the merged effective config — defaults ⊕ stored override.
    async fn get_effective(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::risk_tuning_view::EffectiveRiskConfigView, RiskTuningPortError>;

    /// Defaults-only effective config — the answer to "what would the
    /// scorer use for a tenant with no override row?".
    fn defaults(&self) -> crate::view::risk_tuning_view::EffectiveRiskConfigView;
}

// ---------------------------------------------------------------------------
// Admin user list port (nav-gap fixes)
// ---------------------------------------------------------------------------

/// Admin user-listing port — backs `GET /v1/admin/users`.
///
/// Read-side companion to [`CreateUserPort`]. Returns the narrow
/// [`crate::view::admin_view::AdminUserSummaryView`] projection scoped to
/// the authenticated tenant. Adapters MUST refuse cross-tenant reads;
/// the controller passes the tenant from the bearer claims verbatim.
#[async_trait]
pub trait AdminUserListPort: Send + Sync {
    /// List users for `tenant_id`, capped at `limit` rows, skipping the
    /// first `offset`. Default returns an empty vector so existing
    /// adapter types stay source-compatible.
    async fn list_users(
        &self,
        tenant_id: &str,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<crate::view::admin_view::AdminUserSummaryView>, Phase3PortError> {
        let _ = (tenant_id, limit, offset);
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Intel feed status port (nav-gap fixes)
// ---------------------------------------------------------------------------

/// Intel-feed status port — backs `GET /v1/intel/feeds`.
///
/// Surfaces the per-feed poll status (mirrors the `intel_feed_status`
/// row from `sx-intel-feeds`) so the dashboard can render a feed health
/// table. Adapters MUST scope to the supplied `tenant_id`; the in-memory
/// flavour in the monolith reads from the shared in-process registry.
#[async_trait]
pub trait IntelFeedStatusPort: Send + Sync {
    /// List configured intel feeds and their last-poll / last-success
    /// timestamps for `tenant_id`. Default returns an empty vector so
    /// existing adapter types stay source-compatible.
    async fn list_feeds(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::view::intel_view::FeedStatusView>, Phase3PortError> {
        let _ = tenant_id;
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Device registry port (nav-gap fixes)
// ---------------------------------------------------------------------------

/// Device registry port — backs `GET /v1/notifications/devices`.
///
/// Read-side surface over the per-user push device registry that lives
/// in `sx-webhooks` (P3-008). The controller derives `tenant_id` from
/// the bearer claims and the `user_id` from either a query parameter or
/// the caller's own `sub`; adapters MUST refuse to leak cross-tenant
/// devices regardless of the supplied id pair.
#[async_trait]
pub trait DeviceRegistryPort: Send + Sync {
    /// List devices registered for `(tenant_id, user_id)`. Default
    /// returns an empty vector so existing adapter types stay
    /// source-compatible.
    async fn list_devices(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<crate::view::admin_view::DeviceSummaryView>, Phase3PortError> {
        let _ = (tenant_id, user_id);
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// DEK rotation admin port (CRIT-003)
// ---------------------------------------------------------------------------

/// Per-tenant DEK rotation admin port — backs the two operator-only
/// endpoints under `/v1/admin/secrets/*`:
///
/// - `POST /v1/admin/secrets/rotate-dek` — start (or resume) a
///   rotation for `tenant_id`.
/// - `GET  /v1/admin/secrets/rotation-progress` — report the latest
///   checkpoint for `tenant_id`.
///
/// Both require the `admin:secrets` permission, enforced at the
/// controller layer. The adapter forwards to the rotation orchestrator
/// in `sx-secrets`; that orchestrator emits one audit event per batch
/// + lifecycle transition via the `sx-audit` sink wired at the
/// composition root, so every operator-initiated rotation is auditable
/// end-to-end.
///
/// ## Tenant scoping
///
/// The `tenant_id` argument is the *target* of the rotation. The
/// controller derives the *caller* tenant from the bearer claims and
/// passes it through the request body; the adapter MUST verify the
/// caller has `admin:secrets` and refuse cross-tenant rotations unless
/// the caller is a platform-wide super-admin (`*:*` permission).
///
/// ## Error mapping
///
/// - [`Phase3PortError::NotFound`] — no rotation row exists for the
///   tenant (only on `rotation_progress`).
/// - [`Phase3PortError::Invalid`] — request validation failure (bad
///   UUID, target_version below current, etc.).
/// - [`Phase3PortError::Dependency`] — KMS / store failure surfaced
///   from the orchestrator (`DekRotationError::Kms` /
///   `DekRotationError::Store`).
/// - [`Phase3PortError::Internal`] — illegal-transition or
///   verification-mismatch surfaces; these are programmer errors and
///   should be re-tried only after operator triage.
#[async_trait]
pub trait DekRotationAdminPort: Send + Sync {
    /// Start (or resume) a rotation for `tenant_id`.
    ///
    /// Returns the freshly-stamped checkpoint so the caller sees the
    /// initial progress row without an extra round-trip.
    async fn rotate_dek(
        &self,
        tenant_id: &str,
        target_version: Option<u32>,
    ) -> Result<crate::view::secrets_admin_view::RotationProgressView, Phase3PortError> {
        let _ = (tenant_id, target_version);
        Err(Phase3PortError::Invalid("dek rotation disabled".into()))
    }

    /// Report the latest checkpoint for `tenant_id`. Returns
    /// [`Phase3PortError::NotFound`] when no rotation has ever run.
    async fn rotation_progress(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::secrets_admin_view::RotationProgressView, Phase3PortError> {
        let _ = tenant_id;
        Err(Phase3PortError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// CRIT-004 — OIDC RP-initiated + back-channel + front-channel logout, plus
// SAML back-channel logout receiver. All four entry points share the same
// coarse error surface so the wire never distinguishes "bad signature" from
// "wrong issuer" — an attacker would otherwise be able to probe IdP trust
// state through differential responses.
// ---------------------------------------------------------------------------

/// Errors surfaced by the logout ports.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LogoutPortError {
    /// The feature (OIDC or SAML logout) is disabled in configuration.
    #[error("disabled: {0}")]
    Disabled(String),
    /// The supplied `logout_token` / `LogoutRequest` failed verification,
    /// or the session-state lookup did not produce a record we can act
    /// on. Coarse-grained on purpose.
    #[error("rejected")]
    Rejected,
    /// Replay-cache rejected a duplicate token / request.
    #[error("replay")]
    Replay,
    /// Dependency (storage, replay cache, ...) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Output of a successful RP-initiated logout. The HTTP layer either
/// 302s to the IdP `end_session_endpoint` URL or, for JSON clients,
/// hands the URL back in the body so the client can navigate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRpLogoutRedirect {
    /// Absolute URL the user agent must be redirected to. Carries the
    /// `id_token_hint`, `post_logout_redirect_uri`, and CSRF `state`.
    pub url: String,
    /// CSRF `state` value the SP echoed into the URL. The HTTP layer
    /// MUST persist this against the user's session so the IdP's
    /// `?state=...` echo can be verified when the user agent returns.
    pub state: String,
}

/// OIDC RP-initiated logout port.
///
/// Backed by `sx_iam::service::logout::build_rp_logout_redirect` plus
/// the monolith's session registry. Disabled deployments install a stub
/// that returns [`LogoutPortError::Disabled`].
#[async_trait]
pub trait OidcRpLogoutPort: Send + Sync {
    /// Build the IdP `end_session_endpoint` redirect for the session
    /// identified by `session_id` (typically the `jti` of the bearer
    /// token that arrived on the request). On success the adapter MUST
    /// also revoke the local session — the IdP terminates its side; the
    /// SP must not leave a dangling session record on its own side.
    async fn initiate(&self, session_id: &str) -> Result<OidcRpLogoutRedirect, LogoutPortError>;
}

/// OIDC back-channel logout port.
///
/// Backed by `sx_iam::service::logout::verify_logout_token` plus the
/// monolith's per-session registry + replay cache. Disabled
/// deployments install a stub that returns
/// [`LogoutPortError::Disabled`].
#[async_trait]
pub trait OidcBackchannelLogoutPort: Send + Sync {
    /// Process a back-channel `logout_token`. Returns `Ok(())` on
    /// successful revocation; per spec, the HTTP layer then returns a
    /// `200 OK` with no body.
    async fn process(&self, logout_token: &str) -> Result<(), LogoutPortError>;
}

/// OIDC front-channel logout port — Keycloak-style iframe receiver.
///
/// The IdP loads an iframe at the SP's front-channel endpoint, passing
/// the `sid` claim of the session being terminated. The SP MUST revoke
/// the session and respond `200 OK` with `Cache-Control: no-store`.
#[async_trait]
pub trait OidcFrontchannelLogoutPort: Send + Sync {
    /// Revoke the session whose IdP-side identifier is `sid`. Idempotent.
    async fn revoke_by_sid(&self, sid: &str) -> Result<(), LogoutPortError>;
}

/// SAML back-channel logout port — accepts a SAML `<LogoutRequest>` on
/// the back-channel binding (i.e. server-to-server, not via the user
/// agent). The adapter MUST verify the embedded XML Signature against
/// the configured IdP certificate before acting on the request.
#[async_trait]
pub trait SamlBackchannelLogoutPort: Send + Sync {
    /// Process a SAML `LogoutRequest`. `tenant_id_hint` selects the
    /// per-tenant IdP record; `logout_request_xml` is the raw XML body
    /// the IdP POSTed. Returns `Ok(())` on successful revocation.
    async fn process(
        &self,
        tenant_id_hint: Option<&str>,
        logout_request_xml: &str,
    ) -> Result<(), LogoutPortError>;
}

/// OIDC discovery-document port — backs
/// `GET /.well-known/openid-configuration`.
///
/// The dashboard / IdP-side back-channel client reads this document to
/// discover the SP's endpoints and supported features.
#[async_trait]
pub trait OidcDiscoveryPort: Send + Sync {
    /// Return the discovery document as a [`serde_json::Value`] so the
    /// HTTP layer can serve it without re-parsing.
    async fn document(&self) -> Result<serde_json::Value, LogoutPortError>;
}

// ---------------------------------------------------------------------------
// HIGH-009 — Kubernetes admission webhook (blocking mode) port.
// ---------------------------------------------------------------------------

/// Error returned by the K8s admission port.
///
/// The mapping is intentionally narrow: an admission webhook MUST
/// always return a fast, deterministic verdict to the apiserver. Any
/// internal failure surfaces as `Internal`; the controller decides
/// whether to fail open (200 + allow) or surface a 500 — the current
/// policy is fail-open at the controller level so a transient internal
/// hiccup does not brick the cluster.
#[derive(Debug, Clone, thiserror::Error)]
pub enum K8sAdmissionPortError {
    /// The inbound payload was malformed.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Internal failure (engine error, audit-sink crash, etc.).
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// HIGH-006 — Falco rule overrides admin port
// ---------------------------------------------------------------------------

/// Error surface for the Falco override admin port.
///
/// Failures collapse into a small fixed-shape set so the controller's
/// translation table (`crate::controller::map_runtime_overrides`)
/// stays trivial.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RuntimeOverridesPortError {
    /// Caller-supplied input is structurally valid (passed validator)
    /// but semantically wrong (e.g. `action` is not one of
    /// `allow`/`deny`/`escalate`/`downgrade`). Maps to `422`.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Underlying store unavailable (Postgres timeout, audit-sink
    /// failure). Maps to `503`.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Unexpected internal failure (mutex poisoning, serialisation
    /// glitch). Maps to `500`.
    #[error("internal: {0}")]
    Internal(String),
}

/// Port serving `POST /v1/runtime/k8s/admit`.
///
/// The adapter wraps a [`sx_discovery::k8s_admission::AdmissionEngine`]
/// plus the per-tenant rule-pack policy and the audit sink. The
/// controller is intentionally a thin shim: it deserialises the
/// `AdmissionReview` envelope, calls [`Self::admit`], and returns the
/// resulting envelope as JSON.
#[async_trait]
pub trait K8sAdmissionPort: Send + Sync {
    /// Evaluate `review` for `tenant_id` and return the response
    /// envelope. The adapter is responsible for writing one audit row
    /// per decision (allow OR deny).
    async fn admit(
        &self,
        tenant_id: &str,
        review: sx_discovery::k8s_admission::AdmissionReview,
    ) -> Result<sx_discovery::k8s_admission::AdmissionReview, K8sAdmissionPortError>;

    /// Return the active admission policy for `tenant_id` — the stored
    /// override, or the recommended baseline when the tenant has set
    /// none. Backs `GET /v1/admin/runtime/k8s/policies`.
    async fn get_policy(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::k8s_admission_view::K8sAdmissionPolicyView, K8sAdmissionPortError>;

    /// Replace the admission policy for `tenant_id` and return the stored
    /// result. Persisted durably when a database is wired, and applied to
    /// the live engine immediately. Backs `PUT /v1/admin/runtime/k8s/policies`.
    async fn set_policy(
        &self,
        tenant_id: &str,
        policy: crate::view::k8s_admission_view::K8sAdmissionPolicyView,
    ) -> Result<crate::view::k8s_admission_view::K8sAdmissionPolicyView, K8sAdmissionPortError>;
}

/// Per-tenant Falco rule override admin surface (HIGH-006).
///
/// Backs three endpoints:
///
/// - `GET    /v1/admin/runtime/falco/overrides`
/// - `PUT    /v1/admin/runtime/falco/overrides`
/// - `DELETE /v1/admin/runtime/falco/overrides`
///
/// Every mutation is audit-logged at the adapter (port impl) layer —
/// the controller never invokes the audit sink directly.
#[async_trait]
pub trait RuntimeFalcoOverridesPort: Send + Sync {
    /// List every override row for `tenant_id`. Order is unspecified
    /// — the runtime evaluator handles wildcard-vs-exact precedence.
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<crate::view::runtime_view::FalcoOverrideListResponse, RuntimeOverridesPortError>;

    /// Upsert one row. Idempotent on `(tenant_id, rule_name,
    /// subkey)`. `actor` is the operator UUID extracted from the
    /// authenticated claims; the adapter persists it as `set_by` and
    /// includes it in the audit row.
    async fn upsert(
        &self,
        tenant_id: &str,
        actor: &str,
        req: crate::view::runtime_view::PutFalcoOverrideRequest,
    ) -> Result<crate::view::runtime_view::FalcoOverrideView, RuntimeOverridesPortError>;

    /// Delete one row. Idempotent — returns `removed=false` if the row
    /// was not present (still recorded in the audit log so an
    /// attacker cannot probe row existence silently).
    async fn delete(
        &self,
        tenant_id: &str,
        actor: &str,
        req: crate::view::runtime_view::DeleteFalcoOverrideRequest,
    ) -> Result<crate::view::runtime_view::DeleteFalcoOverrideResponse, RuntimeOverridesPortError>;
}

// MED-003 — Webhook signing-key rotation admin port
// ---------------------------------------------------------------------------

/// Errors surfaced by the webhook key rotation admin port.
///
/// Failures collapse into a small fixed-shape set so the controller's
/// translation table stays trivial. The wire never distinguishes
/// `Disabled` from `Dependency` beyond the HTTP status code so an
/// attacker cannot probe per-tenant rotation status.
#[derive(Debug, Clone, thiserror::Error)]
pub enum WebhookKeyRotationPortError {
    /// The rotation stack has not been wired in for this deployment.
    /// Maps to 422 Unprocessable.
    #[error("disabled: {0}")]
    Disabled(String),
    /// The supplied request was malformed (bad tenant id, etc.). Maps
    /// to 422 Unprocessable.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Underlying store / cipher / audit sink failed. Maps to 502 Bad
    /// Gateway.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Internal programmer error. Maps to 500.
    #[error("internal: {0}")]
    Internal(String),
}

/// Per-tenant outbound webhook signing-key rotation admin port (MED-003).
///
/// Backs `POST /v1/admin/webhooks/keys/rotate`. The route is gated by
/// the `admin:webhooks` permission at the controller layer. The
/// adapter forwards to [`sx_webhooks::WebhookKeyRotator::force_rotate`]
/// in production deployments; the default disabled adapter surfaces a
/// deterministic `Disabled` error so the route stays reachable for RBAC
/// smoke-tests until a real store is provisioned.
#[async_trait]
pub trait WebhookKeyRotationAdminPort: Send + Sync {
    /// Force-rotate the signing key for `tenant_id` immediately. The
    /// `actor` argument carries the operator's subject claim from the
    /// bearer token so the audit log can attribute the rotation.
    /// Default impl returns [`WebhookKeyRotationPortError::Disabled`]
    /// so existing adapter types stay source-compatible.
    async fn force_rotate(
        &self,
        tenant_id: &str,
        actor: Option<String>,
    ) -> Result<
        crate::view::webhooks_admin_view::RotateWebhookKeyResponse,
        WebhookKeyRotationPortError,
    > {
        let _ = (tenant_id, actor);
        Err(WebhookKeyRotationPortError::Disabled(
            "webhook key rotation disabled".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// MED-004 — OIDC `client_secret_jwt` + secret rotation + JWKS publish
// ---------------------------------------------------------------------------

/// Error returned by the MED-004 OIDC client ports.
///
/// Mirrors [`Phase3PortError`] but is dedicated so HTTP mapping for the
/// OAuth2 token endpoint can return the canonical `invalid_client` /
/// `invalid_request` error codes instead of the generic Phase-3 envelope.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OidcClientPortError {
    /// `client_assertion` failed validation (signature, aud, exp, jti,
    /// alg, or iss/sub mismatch).
    #[error("invalid_client")]
    InvalidClient,
    /// The grant type / client_assertion_type combo is unsupported.
    #[error("unsupported_grant: {0}")]
    UnsupportedGrant(String),
    /// The submitted form was malformed.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    /// Resource (client_id) does not exist.
    #[error("not found")]
    NotFound,
    /// Dependency (repository, secrets backend) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// OAuth2 token endpoint — `POST /v1/oauth/token` with grant
/// `client_credentials` and client auth via `client_secret_jwt`
/// (MED-004).
#[async_trait]
pub trait OidcClientTokenPort: Send + Sync {
    /// Validate the assertion + mint an access token.
    ///
    /// `tenant_hint` is `None` for the public endpoint; deployments
    /// that key tokens per tenant resolve the tenant from the
    /// assertion's `iss` (which equals `client_id`) → repository
    /// lookup.
    async fn issue(
        &self,
        tenant_hint: Option<&str>,
        req: crate::view::oidc_client_view::OAuthTokenRequest,
    ) -> Result<crate::view::oidc_client_view::OAuthTokenResponse, OidcClientPortError>;
}

/// Admin endpoint — `POST /v1/admin/oidc/clients/{client_id}/rotate-secret`
/// (MED-004).
#[async_trait]
pub trait OidcClientRotatePort: Send + Sync {
    /// Rotate the secret for `client_id` in `tenant_id`. The returned
    /// view carries the freshly minted plaintext secret which the
    /// adapter MUST audit via `sx-audit` before returning.
    async fn rotate(
        &self,
        tenant_id: &str,
        client_id: &str,
        actor: &str,
    ) -> Result<crate::view::oidc_client_view::RotateClientSecretResponse, OidcClientPortError>;
}

/// JWKS publish — `GET /.well-known/jwks.json` (MED-004).
#[async_trait]
pub trait JwksPublishPort: Send + Sync {
    /// Return the current published JWKS snapshot.
    async fn jwks(&self) -> Result<serde_json::Value, OidcClientPortError>;
}

// ---------------------------------------------------------------------------
// Readiness (SELL-P1-05 — observability)
// ---------------------------------------------------------------------------

/// Result of one dependency's readiness check, surfaced by `GET /readyz`.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessCheck {
    /// Dependency name (e.g. `"database"`, `"process"`).
    pub name: String,
    /// Whether the dependency is ready to serve.
    pub ok: bool,
    /// Optional human-readable detail (never secrets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Aggregate readiness report. `ready` is the AND of every check's `ok`.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReport {
    /// `true` only when every dependency check passed.
    pub ready: bool,
    /// Per-dependency breakdown.
    pub checks: Vec<ReadinessCheck>,
}

impl ReadinessReport {
    /// Build a report, computing `ready` as the conjunction of the checks.
    #[must_use]
    pub fn from_checks(checks: Vec<ReadinessCheck>) -> Self {
        let ready = checks.iter().all(|c| c.ok);
        Self { ready, checks }
    }
}

/// Readiness probe backing `GET /readyz`. Implementations check the
/// process's critical dependencies (database connectivity, …) so an
/// orchestrator only routes traffic once the instance can actually serve.
#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    /// Run every dependency check and aggregate the result.
    async fn check(&self) -> ReadinessReport;
}

/// Trivial readiness probe that always reports ready with a single
/// `process` check. Used for the in-memory/dev default and in tests.
#[derive(Debug, Default)]
pub struct AlwaysReady;

#[async_trait]
impl ReadinessProbe for AlwaysReady {
    async fn check(&self) -> ReadinessReport {
        ReadinessReport::from_checks(vec![ReadinessCheck {
            name: "process".to_owned(),
            ok: true,
            detail: None,
        }])
    }
}
