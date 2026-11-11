//! Log-ingest controller — OCSF ingestion + listing + admin tier
//! management (MED-001).
//!
//! Three routes:
//!
//! - `POST /v1/logs/ingest` — submit a raw payload + source-type token
//!   (RBAC: `logs:write`). Gated by a per-tenant token-bucket
//!   ([`crate::port::LogRateLimitPort`]). Successful calls echo the
//!   bucket headroom in `X-RateLimit-{Limit,Remaining,Reset}` headers;
//!   exhaustion returns HTTP 429 with `Retry-After` + the same trio.
//! - `GET  /v1/logs?limit=N` — list the most-recent ingested OCSF events
//!   for the caller's tenant (RBAC: `logs:read`).
//! - `PUT  /v1/admin/log-ingest/tiers/{tenant_id}` — admin sets a
//!   tenant's tier (and optional override rate). RBAC: `admin:tenants`.
//!   Audit-logged via tracing at the controller layer.
//!
//! Both data-plane handlers delegate to [`crate::port::LogIngestPort`].
//! Tier management goes through [`crate::port::LogRateLimitPort`]. The
//! concrete adapters live in
//! `services/sx-monolith/src/adapters/log_ingest.rs`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sx_core::reference::log_ingest_enrichment::{
    rate_limit_enrichment, LogIngestEnrichment, RATE_LIMIT_FINDING_TITLE, RATE_LIMIT_RULE_ID_DOTTED,
};
use sx_iam::domain::Permission;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::{FindingRepositoryPort, LogIngestError, LogRateLimitDecision, LogRateLimitError};
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::finding_view::FindingView;
use crate::view::log_ingest_view::{
    IngestLogRequest, IngestLogResponse, ListLogsResponse, SetTenantTierRequest,
    TenantTierResponse, LIST_MAX_LIMIT,
};

/// Endpoint label fed to the rate-limiter so a tenant's bulk path and
/// single-event path can have independent buckets if/when bulk lands.
const INGEST_ENDPOINT_LABEL: &str = "/v1/logs/ingest";

/// Cardinality window for the synthetic rate-limit finding (TOP5-#3
/// P2-008). A burst of N throttled requests inside the same window
/// produces exactly one finding row regardless of N. 15 minutes was the
/// PO call: short enough that operators see "fresh" alerts, long enough
/// that a 1k-rps burst does not page the SOC 60 times.
const RATE_LIMIT_FINDING_WINDOW_SECS: u64 = 900;

/// Namespace bytes for the SHA-256-based deterministic UUIDs the
/// rate-limit emitter mints. Mixed into every derive so a future
/// reuse of the helper for a different finding family cannot
/// accidentally collide with rate-limit ids.
const RATE_LIMIT_FINDING_NAMESPACE: &[u8] = b"sentinelx/log-ingest/rate-limit-finding";

/// Namespace for the system-internal engagement uuid we mint per
/// tenant. Stable across restarts; identical input → identical output,
/// so FOUND-001's `ON CONFLICT (id) DO NOTHING` collapses repeats.
const SYSTEM_ENGAGEMENT_NAMESPACE: &[u8] = b"sentinelx/log-ingest/system-engagement";

/// Namespace for the system-internal asset uuid we mint per
/// `(tenant, endpoint)`. The synthetic finding still needs an
/// `asset_id`; a per-endpoint placeholder keeps the schema FK
/// requirement satisfied for the in-memory adapter and surfaces a
/// stable referent in the wire payload.
const SYSTEM_ASSET_NAMESPACE: &[u8] = b"sentinelx/log-ingest/system-asset";

/// Query string for `GET /v1/logs`.
#[derive(Debug, Deserialize)]
pub struct ListLogsQuery {
    /// Newest-first cap. Defaults to 50; clamped to [`LIST_MAX_LIMIT`].
    pub limit: Option<u32>,
}

/// `POST /v1/logs/ingest` — accept one raw event for parsing + storage.
///
/// Always returns rate-limit headers (success and throttle both). On
/// throttle, `Retry-After` is included and the body is the standard
/// `ApiError` 429 envelope.
pub async fn ingest(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<IngestLogRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "logs:write")?;
    let decision = state
        .log_rate_limit
        .try_acquire(scope.tenant_id.as_str(), INGEST_ENDPOINT_LABEL);
    let headers = rate_limit_headers(&decision);
    if !decision.allowed {
        // 429 + Retry-After + the rate-limit trio. The envelope body
        // mirrors any other 429 in this surface so dashboard clients
        // can rely on a single shape.
        tracing::warn!(
            target: "controller.log_ingest.ingest.throttled",
            tenant_id = %scope.tenant_id.as_str(),
            user_id = %user.claims.sub,
            limit = decision.limit,
            retry_after_secs = decision.retry_after_secs,
            "log ingest throttled by per-tenant rate limiter",
        );
        // TOP5-#3 P2-008: materialise a synthetic Finding so the burst
        // does not vanish behind the 429. We MUST NOT block the response
        // on the insert — operators value the Retry-After turnaround
        // over the audit trail's persistence latency — so spawn it. The
        // finding id is deterministic over
        // `(tenant_id, endpoint, 15-minute window)`; FOUND-001's
        // `ON CONFLICT (id) DO NOTHING` collapses a 1000-request burst
        // into one row.
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let view = rate_limit_finding_view(
            scope.tenant_id.as_str(),
            INGEST_ENDPOINT_LABEL,
            &decision,
            now_unix,
        );
        let repo = Arc::clone(&state.findings);
        let view_id = view.id.clone();
        tokio::spawn(async move {
            if let Err(e) = repo.insert(view).await {
                tracing::warn!(
                    target: "controller.log_ingest.ingest.finding_emit_failed",
                    finding_id = %view_id,
                    error = %e,
                    "failed to insert rate-limit finding; 429 already returned",
                );
            }
        });
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            headers,
            Json(ApiResponse::ok(ThrottledIngestBody {
                accepted: 0,
                retry_after_secs: decision.retry_after_secs,
            })),
        )
            .into_response());
    }
    state
        .log_ingest
        .ingest_one(scope.tenant_id.as_str(), &req.source, &req.payload)
        .await
        .map_err(map_log_ingest)?;
    Ok((
        StatusCode::OK,
        headers,
        Json(ApiResponse::ok(IngestLogResponse { accepted: 1 })),
    )
        .into_response())
}

/// Throttle-only body used when the limiter rejects the call. Kept
/// internal so the success path's wire shape stays unchanged.
#[derive(Debug, serde::Serialize)]
struct ThrottledIngestBody {
    accepted: u32,
    retry_after_secs: u64,
}

// ---------------------------------------------------------------------------
// TOP5-#3 P2-008 — rate-limit finding emitter helpers.
// ---------------------------------------------------------------------------

/// Compute the 15-minute window-start (unix seconds) the `now_unix`
/// timestamp falls into. Used to bucket the deterministic finding id so
/// a burst of N throttled requests collapses to one row.
///
/// The integer-division truncation is the bucketing primitive — it is
/// the explicit semantic, not a precision concern — so the clippy lint
/// is silenced.
#[must_use]
#[allow(clippy::integer_division)]
pub(crate) fn rate_limit_window_start(now_unix: u64) -> u64 {
    (now_unix / RATE_LIMIT_FINDING_WINDOW_SECS) * RATE_LIMIT_FINDING_WINDOW_SECS
}

/// Deterministic finding id for the synthetic rate-limit row.
///
/// Hashes `(tenant_id, endpoint, window_start)` under a fixed namespace
/// and clamps the result into a UUID-v5 string. Stable across restarts;
/// identical input → identical output; calls inside the same window
/// from the same tenant + endpoint produce the same id, which collides
/// with the `id PRIMARY KEY` on the Postgres adapter and is no-op'd via
/// `ON CONFLICT (id) DO NOTHING`.
#[must_use]
pub(crate) fn rate_limit_finding_id(
    tenant_id: &str,
    endpoint: &str,
    window_start_unix: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RATE_LIMIT_FINDING_NAMESPACE);
    hasher.update([0xFF]);
    hasher.update(tenant_id.as_bytes());
    hasher.update([0xFF]);
    hasher.update(endpoint.as_bytes());
    hasher.update([0xFF]);
    hasher.update(window_start_unix.to_be_bytes());
    sha256_to_uuid_v5(&hasher.finalize()).to_string()
}

/// Deterministic "system-internal" engagement uuid for one tenant.
///
/// Stamped on `metadata.engagement_id`; FOUND-001's Postgres adapter
/// requires the value to be a parseable UUID. The same value is minted
/// for every rate-limit finding emitted on behalf of the tenant so an
/// operator can pivot from any single finding to the rolled-up
/// "system events" engagement view (once a dashboard surface for that
/// exists). The default sx-monolith composition does not auto-create
/// the engagement row — operators wiring this against the Postgres
/// adapter MUST seed it; for the in-memory adapter (and the integration
/// test) the value is purely opaque.
fn system_engagement_id(tenant_id: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(SYSTEM_ENGAGEMENT_NAMESPACE);
    hasher.update([0xFF]);
    hasher.update(tenant_id.as_bytes());
    sha256_to_uuid_v5(&hasher.finalize())
}

/// Deterministic asset uuid for one `(tenant, endpoint)` pair.
///
/// Same rationale as [`system_engagement_id`] — the wire shape demands
/// an `asset_id`; we mint a stable placeholder rather than leak `None`
/// through a column that downstream consumers treat as required.
fn system_asset_id(tenant_id: &str, endpoint: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(SYSTEM_ASSET_NAMESPACE);
    hasher.update([0xFF]);
    hasher.update(tenant_id.as_bytes());
    hasher.update([0xFF]);
    hasher.update(endpoint.as_bytes());
    sha256_to_uuid_v5(&hasher.finalize())
}

/// Clamp a SHA-256 digest into the UUID-v5 form. Equivalent in spirit
/// to `Uuid::new_v5` without enabling the `v5` cargo feature on the
/// workspace `uuid` crate. Mirrors the helper used in
/// `sx-report::renderer::stix`.
fn sha256_to_uuid_v5(digest: &[u8]) -> Uuid {
    let mut bytes = [0u8; 16];
    if let Some(prefix) = digest.get(..16) {
        bytes.copy_from_slice(prefix);
    }
    // Set version to 5 (xxxxxxxx-xxxx-5xxx-xxxx-xxxxxxxxxxxx).
    if let Some(b6) = bytes.get_mut(6) {
        *b6 = (*b6 & 0x0F) | 0x50;
    }
    // Set variant to RFC 4122 (10xxxxxx).
    if let Some(b8) = bytes.get_mut(8) {
        *b8 = (*b8 & 0x3F) | 0x80;
    }
    Uuid::from_bytes(bytes)
}

/// Compose the canonical synthetic [`FindingView`] for a rate-limit
/// rejection.
///
/// Severity = `medium` (operational signal, not a vuln). CVSS left as
/// `None` — see [`rate_limit_enrichment`] / "don't fabricate". The
/// description embeds the tier-bound limit and the observed retry-after
/// but deliberately does NOT echo any request body content; the
/// limiter never sees the payload here, and even if a future variant
/// did, redaction is the safer default.
///
/// `metadata` carries:
/// - `engagement_id`: required by FOUND-001's Postgres adapter.
/// - `rule_id`: `"MED001.RATE_LIMITER.REJECT"` (TOP5-#3 Phase 3 dotted form).
/// - `confidence`: `1.0` (decision is observed, not inferred).
/// - `endpoint`, `window_start_unix`, `limit`, `retry_after_secs`,
///   `cwe[]`, `mitre_attack[]`, `compliance` — projected from the
///   shared enrichment table so any future SARIF / SOC adapter can
///   reuse the same JSON shape.
#[must_use]
pub(crate) fn rate_limit_finding_view(
    tenant_id: &str,
    endpoint: &str,
    decision: &LogRateLimitDecision,
    now_unix: u64,
) -> FindingView {
    let window_start = rate_limit_window_start(now_unix);
    let id = rate_limit_finding_id(tenant_id, endpoint, window_start);
    let engagement_id = system_engagement_id(tenant_id);
    let asset_id = system_asset_id(tenant_id, endpoint);
    let enrichment = rate_limit_enrichment();
    let metadata =
        build_rate_limit_metadata(engagement_id, endpoint, window_start, decision, &enrichment);
    let timestamp = rfc3339_from_unix(now_unix);
    let description = format!(
        "Per-tenant log ingest rate limiter rejected a request \
         (endpoint={endpoint}, limit={limit}, retry_after_secs={retry_after}, \
         window_start_unix={window_start}). Request body intentionally not recorded.",
        limit = decision.limit,
        retry_after = decision.retry_after_secs,
    );
    FindingView {
        id,
        tenant_id: tenant_id.to_owned(),
        asset_id: asset_id.to_string(),
        severity: "medium".to_owned(),
        status: "open".to_owned(),
        title: RATE_LIMIT_FINDING_TITLE.to_owned(),
        description,
        cvss: None,
        cve_id: None,
        first_seen: timestamp.clone(),
        last_seen: timestamp,
        metadata: Some(metadata),
    }
}

/// Build the `metadata` JSON object for the synthetic finding. Split
/// out so the unit tests can pin every key independently of the wire
/// composition above.
fn build_rate_limit_metadata(
    engagement_id: Uuid,
    endpoint: &str,
    window_start_unix: u64,
    decision: &LogRateLimitDecision,
    enrichment: &LogIngestEnrichment,
) -> serde_json::Value {
    let cwe: Vec<String> = enrichment.cwe.iter().map(ToString::to_string).collect();
    let mitre: Vec<serde_json::Value> = enrichment
        .mitre_attack
        .iter()
        .map(|t| {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "tactic".to_owned(),
                serde_json::Value::String(t.tactic.clone()),
            );
            obj.insert(
                "technique".to_owned(),
                serde_json::Value::String(t.technique.clone()),
            );
            if let Some(sub) = &t.subtechnique {
                obj.insert(
                    "subtechnique".to_owned(),
                    serde_json::Value::String(sub.clone()),
                );
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    let nist: Vec<String> = enrichment
        .compliance
        .nist_800_53
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect();
    // TOP5-#3 Phase 3: dotted-form on the wire; alias-map keeps the
    // legacy colon-form resolving on receive-side lookups.
    serde_json::json!({
        "engagement_id": engagement_id.to_string(),
        "rule_id": RATE_LIMIT_RULE_ID_DOTTED,
        "confidence": 1.0,
        "endpoint": endpoint,
        "window_start_unix": window_start_unix,
        "window_secs": RATE_LIMIT_FINDING_WINDOW_SECS,
        "limit": decision.limit,
        "retry_after_secs": decision.retry_after_secs,
        "cwe": cwe,
        "mitre_attack": mitre,
        "compliance": {
            "nist_800_53": nist,
        },
    })
}

/// Format `unix_secs` as an RFC 3339 timestamp (UTC). Defaults to the
/// unix epoch on overflow so the finding still serialises rather than
/// failing the spawn.
fn rfc3339_from_unix(unix_secs: u64) -> String {
    let secs = i64::try_from(unix_secs).unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

/// Test-only seam: allow the integration test in
/// `tests/rate_limit_emits_finding.rs` to drive the same emit helper
/// the production controller path uses, without standing up the full
/// axum `AppState`.
#[doc(hidden)]
#[must_use]
pub fn __test_emit_rate_limit_finding(
    tenant_id: &str,
    endpoint: &str,
    decision: &LogRateLimitDecision,
    now_unix: u64,
) -> FindingView {
    rate_limit_finding_view(tenant_id, endpoint, decision, now_unix)
}

/// Test-only seam: surface the production endpoint label so the
/// integration test pins the same `(tenant, endpoint, window)` triple
/// without hardcoding the string.
#[doc(hidden)]
#[must_use]
pub fn __test_ingest_endpoint_label() -> &'static str {
    INGEST_ENDPOINT_LABEL
}

/// Test-only seam: surface the window size so the integration test
/// can compute its own window-boundary timestamps.
#[doc(hidden)]
#[must_use]
pub fn __test_rate_limit_window_secs() -> u64 {
    RATE_LIMIT_FINDING_WINDOW_SECS
}

/// Spawn a background insert for a synthetic rate-limit finding. Shared
/// across the controller path and the integration test so both observe
/// the same warn-on-failure behaviour. The returned `JoinHandle` is
/// kept private to the integration test — the controller drops it and
/// lets tokio reap the task.
#[doc(hidden)]
pub fn __test_spawn_finding_insert(
    repo: Arc<dyn FindingRepositoryPort>,
    view: FindingView,
) -> tokio::task::JoinHandle<()> {
    let view_id = view.id.clone();
    tokio::spawn(async move {
        if let Err(e) = repo.insert(view).await {
            tracing::warn!(
                target: "controller.log_ingest.ingest.finding_emit_failed",
                finding_id = %view_id,
                error = %e,
                "failed to insert rate-limit finding (test seam)",
            );
        }
    })
}

/// `GET /v1/logs?limit=N` — list recent OCSF events for the tenant.
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Query(query): Query<ListLogsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "logs:read")?;
    let limit = query.limit.unwrap_or(50).min(LIST_MAX_LIMIT);
    let items = state
        .log_ingest
        .list(scope.tenant_id.as_str(), limit as usize)
        .await
        .map_err(map_log_ingest)?;
    Ok(Json(ApiResponse::ok(ListLogsResponse { items })))
}

/// `PUT /v1/admin/log-ingest/tiers/{tenant_id}` — set the tier for one tenant.
///
/// Optional override. Gated on `admin:tenants` since raising/lowering
/// an ingest budget is a billing-adjacent admin operation.
/// Audit-logged at the controller layer via `tracing`.
pub async fn set_tenant_tier(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(tenant_id): Path<String>,
    ValidatedJson(req): ValidatedJson<SetTenantTierRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:tenants")?;
    let snapshot = state
        .log_rate_limit
        .set_tier(&tenant_id, &req.tier, req.override_rate_per_sec)
        .map_err(map_log_rate_limit)?;
    tracing::info!(
        target: "audit",
        action = "log_ingest.tier.updated",
        tenant_id = %tenant_id,
        actor = %user.claims.sub,
        actor_tenant_id = %user.claims.tenant_id,
        tier = %req.tier,
        override_rate_per_sec = ?req.override_rate_per_sec,
        effective_per_sec_rate = snapshot.per_sec_rate,
        effective_burst = snapshot.burst,
        "log_ingest.tier.updated",
    );
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(TenantTierResponse {
            tenant_id,
            tier: req.tier,
            override_rate_per_sec: req.override_rate_per_sec,
            effective_per_sec_rate: snapshot.per_sec_rate,
            effective_burst: snapshot.burst,
        })),
    ))
}

/// Build the `X-RateLimit-{Limit,Remaining,Reset}` (+ optional
/// `Retry-After`) header trio from a port decision.
fn rate_limit_headers(decision: &LogRateLimitDecision) -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(4);
    insert_u64(&mut headers, "x-ratelimit-limit", u64::from(decision.limit));
    insert_u64(
        &mut headers,
        "x-ratelimit-remaining",
        u64::from(decision.remaining),
    );
    insert_u64(
        &mut headers,
        "x-ratelimit-reset",
        decision.reset_at_unix_secs,
    );
    if !decision.allowed {
        insert_u64(
            &mut headers,
            header::RETRY_AFTER.as_str(),
            decision.retry_after_secs,
        );
    }
    headers
}

fn insert_u64(headers: &mut HeaderMap, name: &str, value: u64) {
    if let (Ok(name), Ok(value)) = (
        axum::http::HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(&value.to_string()),
    ) {
        headers.insert(name, value);
    }
}

/// Translate a [`LogIngestError`] into the appropriate [`ApiError`].
pub fn map_log_ingest(err: LogIngestError) -> ApiError {
    match err {
        LogIngestError::UnknownSource(m) => ApiError::Unprocessable(format!("unknown source: {m}")),
        LogIngestError::Invalid(m) => ApiError::Unprocessable(m),
        LogIngestError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`LogRateLimitError`] into the appropriate [`ApiError`].
pub fn map_log_rate_limit(err: LogRateLimitError) -> ApiError {
    match err {
        LogRateLimitError::InvalidTier(m) => ApiError::Unprocessable(format!("invalid tier: {m}")),
        LogRateLimitError::InvalidOverride(m) => {
            ApiError::Unprocessable(format!("invalid override: {m}"))
        }
        LogRateLimitError::Internal(m) => ApiError::Internal(m),
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    fn ingest_requires_logs_write() {
        let u = user(vec!["logs:read"]);
        assert!(matches!(
            require_permission(&u, "logs:write"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn list_requires_logs_read() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "logs:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn wildcard_logs_action_allowed() {
        let u = user(vec!["logs:*"]);
        assert!(require_permission(&u, "logs:read").is_ok());
        assert!(require_permission(&u, "logs:write").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "logs:read").is_ok());
        assert!(require_permission(&u, "logs:write").is_ok());
    }

    #[test]
    fn set_tenant_tier_requires_admin_tenants() {
        let u = user(vec!["logs:write"]);
        assert!(matches!(
            require_permission(&u, "admin:tenants"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn admin_tenants_wildcard_allows_set_tenant_tier() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:tenants").is_ok());
    }

    #[test]
    fn unknown_source_maps_to_unprocessable() {
        let mapped = map_log_ingest(LogIngestError::UnknownSource("nope".into()));
        assert!(matches!(mapped, ApiError::Unprocessable(_)));
    }

    #[test]
    fn invalid_maps_to_unprocessable() {
        let mapped = map_log_ingest(LogIngestError::Invalid("bad".into()));
        assert!(matches!(mapped, ApiError::Unprocessable(_)));
    }

    #[test]
    fn internal_maps_to_internal() {
        let mapped = map_log_ingest(LogIngestError::Internal("boom".into()));
        assert!(matches!(mapped, ApiError::Internal(_)));
    }

    #[test]
    fn rate_limit_invalid_tier_maps_to_unprocessable() {
        let mapped = map_log_rate_limit(LogRateLimitError::InvalidTier("ultra".into()));
        assert!(matches!(mapped, ApiError::Unprocessable(_)));
    }

    #[test]
    fn rate_limit_invalid_override_maps_to_unprocessable() {
        let mapped = map_log_rate_limit(LogRateLimitError::InvalidOverride("zero".into()));
        assert!(matches!(mapped, ApiError::Unprocessable(_)));
    }

    #[test]
    fn rate_limit_internal_maps_to_internal() {
        let mapped = map_log_rate_limit(LogRateLimitError::Internal("boom".into()));
        assert!(matches!(mapped, ApiError::Internal(_)));
    }

    #[test]
    fn rate_limit_headers_carry_full_trio_on_allow() {
        let d = LogRateLimitDecision {
            allowed: true,
            limit: 200,
            remaining: 199,
            reset_at_unix_secs: 1_750_000_000,
            retry_after_secs: 0,
        };
        let h = rate_limit_headers(&d);
        assert_eq!(h.get("x-ratelimit-limit").unwrap(), "200");
        assert_eq!(h.get("x-ratelimit-remaining").unwrap(), "199");
        assert_eq!(h.get("x-ratelimit-reset").unwrap(), "1750000000");
        assert!(h.get(header::RETRY_AFTER).is_none());
    }

    #[test]
    fn rate_limit_headers_include_retry_after_on_throttle() {
        let d = LogRateLimitDecision {
            allowed: false,
            limit: 200,
            remaining: 0,
            reset_at_unix_secs: 1_750_000_000,
            retry_after_secs: 1,
        };
        let h = rate_limit_headers(&d);
        assert_eq!(h.get("x-ratelimit-remaining").unwrap(), "0");
        assert_eq!(h.get(header::RETRY_AFTER).unwrap(), "1");
    }
}
