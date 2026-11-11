//! Route composition.
//!
//! [`build_router`] is the single entry point sibling crates (notably the
//! `services/sx-monolith` binary) use to construct the `axum::Router` they
//! intend to serve. The function:
//!
//! 1. Registers controllers under their stable URL paths.
//! 2. Stacks middleware in the order documented on
//!    [`crate::middleware`].
//! 3. Returns a `Router<()>` with state already attached.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::controller;
use crate::middleware::auth::{auth_middleware, AuthConfig, AuthState};
use crate::middleware::cors::{build_cors_layer, CorsConfig};
use crate::middleware::device_posture::{device_posture_middleware, DevicePostureState};
use crate::middleware::rate_limit::{rate_limit_middleware, RateLimitState};
use crate::middleware::request_id::request_id_middleware;
use crate::middleware::{sensitive_headers, trace};
use crate::state::AppState;

/// CORS configuration the caller supplies at boot. Re-exported from
/// [`crate::middleware::cors`].
pub use crate::middleware::cors::CorsConfig as ApiCorsConfig;

/// Construct the API router.
pub fn build_router(state: AppState) -> Router {
    let cors_cfg = default_cors_config();
    build_router_with_cors(state, &cors_cfg)
}

/// Same as [`build_router`] but accepts an explicit CORS configuration.
pub fn build_router_with_cors(state: AppState, cors_cfg: &CorsConfig) -> Router {
    let authed = Router::new()
        .route("/v1/tenants/me", get(controller::tenant::me))
        .route("/v1/auth/logout", post(controller::auth::logout))
        // CRIT-004 — OIDC RP-initiated logout. Authenticated: the
        // bearer claims identify the local session we revoke before
        // redirecting to the IdP `end_session_endpoint`.
        .route(
            "/v1/auth/oidc/logout",
            get(controller::logout::oidc_rp_logout),
        )
        .route(
            "/v1/engagements",
            get(controller::engagement::list).post(controller::engagement::create),
        )
        .route(
            "/v1/engagements/:id",
            get(controller::engagement::get_one).patch(controller::engagement::update),
        )
        .route("/v1/assets", get(controller::asset::list))
        .route("/v1/assets/:id", get(controller::asset::get_one))
        .route("/v1/findings", get(controller::finding::list))
        .route("/v1/findings/:id", get(controller::finding::get_one))
        .route(
            "/v1/findings/:id/status",
            patch(controller::finding::update_status),
        )
        .route(
            "/v1/findings/:id/remediation",
            patch(controller::findings_remediation::link)
                .delete(controller::findings_remediation::unlink),
        )
        .route(
            "/v1/findings/bulk-update",
            post(controller::findings_bulk::bulk_update),
        )
        .route(
            "/v1/findings/export",
            get(controller::findings_bulk::export),
        )
        .route("/v1/risk/calculate", post(controller::risk::calculate))
        .route(
            "/v1/risk/engagement/:engagement_id",
            post(controller::risk::calculate_for_engagement),
        )
        // P1-014 — per-tenant risk-model tuning (weights + thresholds).
        // PUT requires the `risk:tune` admin permission; reads are open
        // to any authenticated user in the tenant.
        .route(
            "/v1/risk/config",
            get(controller::risk_tuning::get_config)
                .put(controller::risk_tuning::put_config),
        )
        .route(
            "/v1/risk/config/effective",
            get(controller::risk_tuning::get_effective),
        )
        .route("/v1/discovery/runs", post(controller::discovery::run))
        // P2-012 — chaos engineering admin surface. RBAC + non-prod
        // gate are enforced inside the controller via
        // `sx_chaos::admin::ChaosAdminService`.
        .route(
            "/v1/chaos/config",
            get(controller::chaos::get_config).put(controller::chaos::put_config),
        )
        // P2-013 — API DAST (Postman collection replay).
        .route(
            "/v1/discovery/dast/scan",
            post(controller::dast::scan),
        )
        .route(
            "/v1/discovery/dast/scans",
            get(controller::dast::list),
        )
        .route("/v1/safety/kill-switch", post(controller::killswitch::trip))
        .route("/v1/bas/run", post(controller::bas::run))
        .route("/v1/bas/runs", get(controller::bas::list_runs))
        .route("/v1/bas/chains", get(controller::bas_chain::list_chains))
        .route(
            "/v1/bas/chains/:id/run",
            post(controller::bas_chain::start_run),
        )
        .route(
            "/v1/bas/chains/runs/:id",
            get(controller::bas_chain::get_run),
        )
        .route(
            "/v1/scans/http-headers",
            post(controller::scan::http_headers),
        )
        .route("/v1/scans", get(controller::scan::list))
        // TOP5-#3-P2-SARIF-API + QC-SCAN-2026-06-25 fix c — unified
        // detail dispatcher. axum 0.7 (matchit 0.7) does not support a
        // `<param>.<literal>` pattern in a single path segment, so the
        // user-facing `/v1/scans/{id}` and `/v1/scans/{id}.sarif` URLs
        // share a single capture (`:any_id`). The dispatcher handler
        // inspects the trailing `.sarif` suffix and routes to the SARIF
        // exporter or the JSON detail response respectively.
        // Same auth + tenant scoping as the JSON list endpoint.
        .route(
            "/v1/scans/:any_id",
            get(controller::scan::get_scan_dispatch),
        )
        .route(
            "/v1/bas/approvals",
            post(controller::bas::record_approval).get(controller::bas::list_approvals),
        )
        .route(
            "/v1/graph/attack-paths",
            post(controller::graph::attack_paths),
        )
        .route("/v1/reports", get(controller::report::list))
        .route("/v1/reports/render", post(controller::report::render))
        .route("/v1/reports/diff", post(controller::report::diff))
        .route(
            "/v1/reports/branding",
            get(controller::branding::get).put(controller::branding::put),
        )
        .route(
            "/v1/reports/schedules",
            get(controller::report_schedule::list).post(controller::report_schedule::create),
        )
        .route(
            "/v1/reports/schedules/:id",
            axum::routing::delete(controller::report_schedule::delete),
        )
        .route(
            "/v1/reports/comprehensive",
            get(controller::comprehensive_report::get),
        )
        .route(
            "/v1/remediation/advisories",
            post(controller::remediation::advisories),
        )
        .route(
            "/v1/compliance/frameworks/:framework",
            get(controller::compliance::list_framework),
        )
        .route(
            "/v1/compliance/map",
            post(controller::compliance::map_finding),
        )
        .route(
            "/v1/compliance/evidence/collect",
            post(controller::compliance_evidence::collect),
        )
        .route(
            "/v1/compliance/evidence/bundles",
            get(controller::compliance_evidence::list_bundles),
        )
        .route(
            "/v1/compliance/evidence/bundles/:id/download",
            get(controller::compliance_evidence::download_bundle),
        )
        .route(
            "/v1/ml/predict/triage",
            post(controller::ml::predict_triage),
        )
        .route(
            "/v1/cloud/inventory",
            get(controller::cloud::list_inventory_get).post(controller::cloud::list_inventory),
        )
        .route("/v1/autonomy/pr", post(controller::autonomy::propose_pr))
        .route(
            "/v1/autonomy/threat-network",
            post(controller::autonomy::submit_threat),
        )
        .route(
            "/v1/autonomy/validation/schedules",
            post(controller::autonomy::schedule_validation),
        )
        .route(
            "/v1/autonomy/validation/schedules/:engine_id",
            delete(controller::autonomy::cancel_validation),
        )
        .route("/v1/collab/tokens", post(controller::collab::allocate))
        .route(
            "/v1/collab/tokens/:token/callbacks",
            get(controller::collab::lookup),
        )
        .route(
            "/v1/admin/users",
            get(controller::admin::list_users).post(controller::admin::create_user),
        )
        .route("/v1/soc/alerts", get(controller::soc::list_alerts))
        .route("/v1/soc/events", post(controller::soc::submit_event))
        .route(
            "/v1/twin/engagement/:engagement_id",
            get(controller::twin::get_twin),
        )
        .route("/v1/intel/check", post(controller::intel::check_indicator))
        .route("/v1/intel/feeds", get(controller::intel::list_feeds))
        .route(
            "/v1/ml/predict/finding",
            post(controller::predictive::predict),
        )
        .route("/v1/redteam/chain", post(controller::redteam::compose))
        .route("/v1/copilot/chat", post(controller::copilot::chat))
        .route(
            "/v1/admin/roles",
            get(controller::roles::list).post(controller::roles::create),
        )
        .route(
            "/v1/admin/roles/:role_id",
            delete(controller::roles::delete),
        )
        .route(
            "/v1/admin/users/:user_id/roles",
            post(controller::roles::assign),
        )
        .route(
            "/v1/engagements/:id/activate",
            post(controller::engagement::activate),
        )
        .route(
            "/v1/engagements/:id/pause",
            post(controller::engagement::pause),
        )
        .route(
            "/v1/engagements/:id/resume",
            post(controller::engagement::resume),
        )
        .route(
            "/v1/engagements/:id/abort",
            post(controller::engagement::abort),
        )
        .route(
            "/v1/engagements/:id/complete",
            post(controller::engagement::complete),
        )
        .route(
            "/v1/engagements/:id/clone",
            post(controller::engagement::clone_engagement),
        )
        .route("/v1/audit", get(controller::audit::list_alias))
        .route("/v1/audit/search", get(controller::audit::search))
        .route("/v1/audit/export", get(controller::audit::export_ndjson))
        .route("/v1/audit/replay", get(controller::audit::replay))
        .route("/v1/audit/diff", get(controller::audit::diff))
        // P1-015 — external audit-chain anchor read endpoints.
        .route(
            "/v1/audit/anchors",
            get(controller::audit_anchor::list),
        )
        .route(
            "/v1/audit/anchors/verify/:run_id",
            post(controller::audit_anchor::verify),
        )
        .route("/v1/assets", post(controller::assets::create))
        .route(
            "/v1/assets/:id",
            patch(controller::assets::update).delete(controller::assets::delete),
        )
        .route(
            "/v1/assets/bulk-import",
            post(controller::asset_bulk::import),
        )
        .route(
            "/v1/admin/tenants",
            get(controller::tenants::list).post(controller::tenants::create),
        )
        .route(
            "/v1/admin/tenants/:id",
            patch(controller::tenants::update).delete(controller::tenants::delete),
        )
        .route("/v1/mfa/enroll", post(controller::mfa::enroll))
        .route("/v1/mfa/verify", post(controller::mfa::verify))
        .route("/v1/mfa/disable", post(controller::mfa::disable))
        .route("/v1/mfa/status", get(controller::mfa::status))
        // P1-002 — FIDO2 / WebAuthn passkey MFA. Register endpoints are
        // authenticated (enrolling a passkey on an existing session);
        // login endpoints live on the public router below.
        .route(
            "/v1/auth/mfa/webauthn/register/start",
            post(controller::webauthn::register_start),
        )
        .route(
            "/v1/auth/mfa/webauthn/register/finish",
            post(controller::webauthn::register_finish),
        )
        // HIGH-002 — AAGUID blocklist + FIDO MDS3 metadata service.
        .route(
            "/v1/iam/webauthn/aaguid-policy",
            get(controller::webauthn::list_aaguid_policy),
        )
        .route(
            "/v1/iam/webauthn/aaguid-policy/:aaguid",
            put(controller::webauthn::put_aaguid_policy)
                .delete(controller::webauthn::delete_aaguid_policy),
        )
        .route(
            "/v1/iam/webauthn/mds-status",
            get(controller::webauthn::mds_status),
        )
        .route(
            "/v1/iam/webauthn/mds-refresh",
            post(controller::webauthn::mds_refresh),
        )
        .route(
            "/v1/iam/webauthn/credentials",
            get(controller::webauthn::list_user_credentials),
        )
        .route("/v1/logs/ingest", post(controller::log_ingest::ingest))
        .route("/v1/logs", get(controller::log_ingest::list))
        // MED-001 — per-tenant log-ingest rate-limit tier admin.
        .route(
            "/v1/admin/log-ingest/tiers/:tenant_id",
            put(controller::log_ingest::set_tenant_tier),
        )
        .route("/v1/vuln/import", post(controller::vuln_ingest::import))
        .route(
            "/v1/vuln/imports",
            get(controller::vuln_ingest::list_imports),
        )
        // P1-009 — Prowler v4 native-JSON CSPM import (GCP + Azure).
        .route(
            "/v1/discovery/prowler/import",
            post(controller::prowler_import::import),
        )
        // CRIT-003 — per-tenant DEK rotation admin endpoints.
        .route(
            "/v1/admin/secrets/rotate-dek",
            post(controller::secrets_admin::rotate_dek),
        )
        .route(
            "/v1/admin/secrets/rotation-progress",
            get(controller::secrets_admin::rotation_progress),
        )
        // MED-003 — per-tenant outbound webhook HMAC signing-key
        // rotation. Requires `admin:webhooks`; mints a fresh kid and
        // schedules the previous key for retirement after the
        // configured grace window.
        .route(
            "/v1/admin/webhooks/keys/rotate",
            post(controller::webhooks_admin::rotate_webhook_key),
        )
        // HIGH-006 — per-tenant Falco rule allow/deny override admin
        // surface. Single resource path; verb-multiplexed (GET/PUT/DELETE)
        // because the row key (`rule_name`, `subkey`) carries the wildcard
        // `*` which does not round-trip cleanly through a URL path
        // component in every reverse proxy. The DELETE handler reads the
        // key from the JSON body to match.
        .route(
            "/v1/admin/runtime/falco/overrides",
            get(controller::runtime::list_falco_overrides)
                .put(controller::runtime::put_falco_override)
                .delete(controller::runtime::delete_falco_override),
        )
        // MED-004 — admin rotates the shared secret of an OIDC
        // confidential client. Requires `iam:write`.
        .route(
            "/v1/admin/oidc/clients/:client_id/rotate-secret",
            post(controller::oidc_client::rotate_client_secret),
        )
        .route(
            "/v1/admin/scim/tokens",
            get(controller::scim::admin_list_tokens)
                .post(controller::scim::admin_create_token),
        )
        .route(
            "/v1/admin/scim/tokens/:id",
            delete(controller::scim::admin_revoke_token),
        )
        .route(
            "/v1/admin/scim/tokens/:id/rotate",
            post(controller::scim::admin_rotate_token),
        )
        .route(
            "/v1/admin/scim/users",
            get(controller::scim::admin_list_users),
        )
        .route(
            "/v1/copilot/approvals",
            get(controller::copilot_approval::list_pending),
        )
        .route(
            "/v1/copilot/approvals/:token/decide",
            post(controller::copilot_approval::decide),
        )
        .route(
            "/v1/rba/users/{user_id}/devices",
            get(controller::rba::list_known_devices),
        )
        .route(
            "/v1/rba/users/{user_id}/devices/{fp_hash}",
            axum::routing::delete(controller::rba::revoke_known_device),
        )
        .route("/v1/rba/decisions", get(controller::rba::list_decisions))
        .route(
            "/v1/rba/config",
            get(controller::rba::get_config).put(controller::rba::put_config),
        )
        .route(
            "/v1/cloud/blast-radius",
            post(controller::blast_radius::compute),
        )
        .route(
            "/v1/remediation/outcomes/metrics",
            get(controller::remediation_outcomes::metrics),
        )
        .route(
            "/v1/remediation/outcomes/regressions",
            get(controller::remediation_outcomes::regressions),
        )
        .route(
            "/v1/ueba/baselines/:user_id",
            get(controller::ueba::get_baseline),
        )
        .route("/v1/ueba/anomalies", get(controller::ueba::list_anomalies))
        .route(
            "/v1/pentest/runs",
            post(controller::pentest::run).get(controller::pentest::list_runs),
        )
        .route("/v1/pentest/runs/:id", get(controller::pentest::get_run))
        // HIGH-010 — UEBA freeze-mode admin endpoints.
        .route(
            "/v1/admin/ueba/baseline/:user_id/freeze",
            post(controller::ueba_admin::freeze),
        )
        .route(
            "/v1/admin/ueba/baseline/:user_id/unfreeze",
            post(controller::ueba_admin::unfreeze),
        )
        .route(
            "/v1/admin/ueba/baseline/:user_id/snapshot",
            get(controller::ueba_admin::snapshot),
        )
        .route(
            "/v1/soar/workflows",
            get(controller::soar::list_workflows).post(controller::soar::create_workflow),
        )
        .route(
            "/v1/soar/workflows/:id",
            get(controller::soar::get_workflow),
        )
        .route(
            "/v1/soar/workflows/:id/run",
            post(controller::soar::run_workflow),
        )
        .route("/v1/soar/runs/:id", get(controller::soar::get_run))
        .route(
            "/v1/device-trust/policy",
            get(controller::device_trust::get_policy)
                .put(controller::device_trust::put_policy),
        )
        .route(
            "/v1/device-trust/sessions",
            get(controller::device_trust::list_sessions),
        )
        // P2-006 — DLP content inspection adapter.
        .route("/v1/dlp/scan", post(controller::dlp::scan))
        .route(
            "/v1/dlp/config",
            get(controller::dlp::get_config).put(controller::dlp::put_config),
        )
        // HIGH-004 — per-tenant DLP fusion threshold (admin surface).
        .route(
            "/v1/admin/dlp/thresholds",
            get(controller::dlp::get_threshold).put(controller::dlp::put_threshold),
        )
        // P2-009 — GRC outbound integration (Vanta / Drata / ServiceNow).
        .route(
            "/v1/grc/configs",
            get(controller::grc::list_configs).post(controller::grc::upsert_config),
        )
        .route(
            "/v1/grc/configs/:kind/test",
            post(controller::grc::test_connection),
        )
        .route("/v1/grc/push", post(controller::grc::push))
        // P3-007 — plugin marketplace + SDK.
        .route(
            "/v1/plugins",
            get(controller::plugins::list),
        )
        .route(
            "/v1/plugins/install",
            post(controller::plugins::install),
        )
        .route(
            "/v1/plugins/:id",
            delete(controller::plugins::uninstall),
        )
        .route(
            "/v1/plugins/:id/dispatches",
            get(controller::plugins::list_dispatches),
        )
        // P2-004 — cloud drift detection vs IaC baseline.
        .route(
            "/v1/cloud/drift/baselines",
            post(controller::cloud_drift::upload_baseline)
                .get(controller::cloud_drift::list_baselines),
        )
        .route(
            "/v1/cloud/drift/scan",
            post(controller::cloud_drift::scan),
        )
        .route(
            "/v1/cloud/drift/findings",
            get(controller::cloud_drift::list_findings),
        )
        // P3-004 — in-app IR playbooks (NIST SP 800-61 Rev 2).
        .route(
            "/v1/ir/playbooks",
            get(controller::ir_playbooks::list_playbooks),
        )
        .route(
            "/v1/ir/incidents",
            post(controller::ir_playbooks::open_incident),
        )
        .route(
            "/v1/ir/incidents/:id",
            get(controller::ir_playbooks::get_incident),
        )
        .route(
            "/v1/ir/incidents/:id/steps/:step",
            patch(controller::ir_playbooks::update_step),
        )
        // P3-010 — bug-bounty bridge (HackerOne + Bugcrowd).
        .route(
            "/v1/integrations/bugbounty/configs",
            get(controller::bugbounty::list_configs)
                .post(controller::bugbounty::upsert_config),
        )
        .route(
            "/v1/integrations/bugbounty/push",
            post(controller::bugbounty::push),
        )
        // P3-006 — Threat-hunting KQL/SPL-like query surface.
        .route(
            "/v1/hunt/query",
            post(controller::hunt::query),
        )
        // AI-SEC-001 — comprehensive AI security audit surface.
        .route("/v1/ai-audit/assets", get(controller::ai_audit::list_assets))
        .route("/v1/ai-audit/aibom", get(controller::ai_audit::get_aibom))
        .route("/v1/ai-audit/controls", get(controller::ai_audit::list_controls))
        .route("/v1/ai-audit/run", post(controller::ai_audit::run_audit))
        .route(
            "/v1/ai-audit/run-external",
            post(controller::ai_audit::run_external_audit),
        )
        // Nav-gap fix — list registered push devices (P3-008 read-side).
        .route(
            "/v1/notifications/devices",
            get(controller::notifications::list_devices),
        );

    // SCIM 2.0 surface (RFC 7644). Lives at ROOT (`/scim/v2/...`), NOT under `/v1`.
    let scim = Router::new()
        .route(
            "/scim/v2/Users",
            post(controller::scim::create_user).get(controller::scim::list_users),
        )
        .route(
            "/scim/v2/Users/:id",
            get(controller::scim::get_user)
                .put(controller::scim::replace_user)
                .delete(controller::scim::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            post(controller::scim::create_group).get(controller::scim::list_groups),
        )
        .route("/scim/v2/Groups/:id", get(controller::scim::get_group));

    let public = Router::new()
        .route("/healthz", get(controller::health::healthz))
        .route("/readyz", get(controller::health::readyz))
        .route("/metrics", get(controller::metrics::scrape))
        .route("/openapi.json", get(controller::openapi::schema))
        .route("/v1/auth/login", post(controller::auth::login))
        .route("/v1/auth/refresh", post(controller::auth::refresh))
        .route(
            "/v1/auth/oidc/exchange",
            post(controller::auth::exchange_oidc),
        )
        // SAML 2.0 SP endpoints (P0-004). All public — the SAML
        // bindings handle their own authentication via the IdP
        // signature on the assertion (ACS) or via the SP-side IdP
        // record lookup (metadata + SLO).
        .route("/v1/auth/saml/metadata", get(controller::saml::metadata))
        .route("/v1/auth/saml/acs", post(controller::saml::acs))
        .route("/v1/auth/saml/logout", get(controller::saml::slo))
        // P0-004 — per-tenant SAML IdP config admin (normal auth + RBAC).
        .route(
            "/v1/admin/saml/idp",
            get(controller::saml_admin::get_idp).put(controller::saml_admin::put_idp),
        )
        // CRIT-004 — OIDC back-channel + front-channel logout receivers
        // and the matching SAML back-channel receiver. The discovery
        // document advertises these so IdPs (Okta, Keycloak, ...) can
        // auto-configure their trust on top of an SP that supports them.
        .route(
            "/v1/auth/oidc/back-channel-logout",
            post(controller::logout::oidc_backchannel_logout),
        )
        .route(
            "/v1/auth/oidc/front-channel-logout",
            get(controller::logout::oidc_frontchannel_logout),
        )
        .route(
            "/v1/auth/saml/back-channel-logout",
            post(controller::logout::saml_backchannel_logout),
        )
        .route(
            "/.well-known/openid-configuration",
            get(controller::logout::openid_configuration),
        )
        // MED-004 — OAuth2 token endpoint + JWKS publication. Public
        // (the JWT assertion in the body is the credential on `/token`;
        // `/jwks.json` is fundamentally public).
        .route(
            "/v1/oauth/token",
            post(controller::oidc_client::issue_client_token),
        )
        .route(
            "/.well-known/jwks.json",
            get(controller::oidc_client::jwks),
        )
        // Customer-facing self-service auth. Public (unauthenticated)
        // but rate-limited via the shared `rate_limit_middleware` below.
        .route("/v1/auth/signup", post(controller::customer_auth::signup))
        .route(
            "/v1/auth/verify-email",
            post(controller::customer_auth::verify_email),
        )
        .route(
            "/v1/auth/forgot-password",
            post(controller::customer_auth::forgot_password),
        )
        .route(
            "/v1/auth/reset-password",
            post(controller::customer_auth::reset_password),
        )
        // P1-002 — WebAuthn passkey login (unauthenticated; the ceremony
        // establishes the session). Rate-limited via the shared
        // middleware below.
        .route(
            "/v1/auth/mfa/webauthn/login/start",
            post(controller::webauthn::login_start),
        )
        .route(
            "/v1/auth/mfa/webauthn/login/finish",
            post(controller::webauthn::login_finish),
        )
        // P2-016 — container-runtime security (Falco) webhook. Public:
        // the request is self-authenticated by the per-tenant HMAC-SHA256
        // signature carried in `X-Sentinelx-Runtime-Signature`. Bypass
        // is configured in [`crate::middleware::auth::AuthConfig::default`]
        // so the bearer-token middleware does not 401 the inbound webhook.
        .route(
            "/v1/runtime/falco/alerts",
            post(controller::runtime::ingest),
        )
        // HIGH-009 — Kubernetes admission webhook (blocking mode).
        // Public: the in-cluster apiserver authenticates itself via the
        // cluster-CA-signed TLS handshake the `ValidatingWebhookConfiguration`
        // pins (cert-manager injects the `caBundle` at install time —
        // see `deploy/helm/sx-admission`). Tenant is resolved from the
        // `X-Sentinelx-Tenant` header set by the install-time
        // `MutatingWebhookConfiguration`.
        .route(
            "/v1/runtime/k8s/admit",
            post(controller::k8s_admission::admit),
        )
        // HIGH-009 — per-tenant admission policy admin surface. Normal
        // auth + RBAC (runtime:read / runtime:write), unlike the
        // apiserver-facing /admit route above.
        .route(
            "/v1/admin/runtime/k8s/policies",
            get(controller::k8s_admission::get_policy)
                .put(controller::k8s_admission::put_policy),
        )
        // P3-010 — Bug-bounty inbound webhook. Public because the
        // platform authenticates itself by signing the raw body with
        // the per-tenant per-platform HMAC secret. The path carries
        // the platform identifier (`hackerone` / `bugcrowd`); the
        // `tenant_id` query parameter identifies the tenant.
        .route(
            "/v1/integrations/bugbounty/inbound/:platform",
            post(controller::bugbounty::inbound),
        );

    let timeout = state.server_cfg.request_timeout;
    let body_limit = usize_from_u64(state.server_cfg.max_body_bytes);

    let auth_cfg = Arc::new(AuthConfig::default());
    let auth_state = AuthState {
        validator: state.token_validator.clone(),
        cfg: auth_cfg,
    };
    let rl_state = RateLimitState {
        cfg: state.rate_limit_cfg.clone(),
        state: state.rate_limiter.clone(),
    };
    // Device-posture state: clones the trait-object port handle so the
    // middleware can run `evaluate` without re-locking shared state.
    let posture_state = DevicePostureState::new(state.device_trust.clone());

    // P2-012 — chaos engineering middleware state. The shared registry is
    // a cheap `Arc` clone so layering chaos near the outside of the stack
    // is essentially free when chaos is disabled.
    let chaos_state =
        sx_chaos::http::ChaosHttpState::new(sx_chaos::SharedChaosRegistry::clone(&state.chaos));

    Router::new()
        .merge(public)
        .merge(authed)
        .merge(scim)
        // Innermost (applied last, runs closest to handler).
        .layer(axum::middleware::from_fn_with_state(rl_state, rate_limit_middleware))
        // Device-posture is layered AFTER auth so the bearer claims are
        // already populated by the time the posture decoder runs.
        // Pass-through semantics: missing header is fine, tampered
        // header attaches an `Untrusted` decision but does not block.
        .layer(axum::middleware::from_fn_with_state(
            posture_state,
            device_posture_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(auth_state, auth_middleware))
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout))
        .layer(build_cors_layer(cors_cfg))
        .layer(trace::layer())
        .layer(axum::middleware::from_fn(request_id_middleware))
        .layer(sensitive_headers::layer())
        // P2-012 — chaos HTTP middleware. Outermost: runs before auth
        // so synthetic faults exercise the entire request pipeline.
        // No-op when the registry is disabled (default).
        .layer(axum::middleware::from_fn_with_state(
            chaos_state,
            sx_chaos::http::chaos_middleware,
        ))
        .with_state(state)
}

fn usize_from_u64(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn default_cors_config() -> CorsConfig {
    CorsConfig::default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use sx_config::schema::server::ServerConfig;
    use sx_iam::model::claims::{AccessClaims, TokenType};
    use sx_iam::IamError;
    use tower::ServiceExt;

    use super::*;
    use crate::middleware::rate_limit::{RateLimitConfig, RateLimiterState};
    use crate::port::{
        ApprovalPort, AssetRepositoryPort, AuthenticateUserInput, AuthenticateUserPort,
        AutonomyEngineId, BasRunPort, BlastRadiusPort, CalculateRiskPort, CloudInventoryPort,
        CollabAllocateTokenPort, CollabLookupCallbacksPort, ComplianceFrameworkPort,
        CreateUserPort, CustomerAuthPort, DiscoveryPortError, EngagementPortError,
        EngagementServicePort, FindingRepositoryPort, GraphAttackPathsPort, KillSwitchPort,
        KillSwitchTrigger, LogoutPort, MlTriagePredictPort, OidcExchangePort, Phase3PortError,
        ProposePrInput, ProposePrOutcome, ProposePrPort, RefreshTokenPort,
        RemediationAdvisoriesPort, ReportDiffPort, ReportRenderPort, RiskPortError, RiskTuningPort,
        RiskTuningPortError, RunDiscoveryPort, ScheduleValidationInput, ScheduleValidationPort,
        SubmitThreatInput, SubmitThreatObservationPort, SubmitThreatOutcome, TenantRepositoryPort,
        TenantSummaryView, ValidateTokenPort,
    };
    use crate::view::admin_view::{CreateUserRequestView, CreateUserResponseView};
    use crate::view::asset_view::AssetView;
    use crate::view::auth_view::OidcExchangeRequest;
    use crate::view::auth_view::TokenView;
    use crate::view::bas_view::{
        ApprovalView, BasRunRequestView, BasRunResponseView, RecordApprovalRequest,
    };
    use crate::view::blast_radius_view::BlastRadiusResponseView;
    use crate::view::cloud_view::{CloudInventoryRequestView, CloudInventoryResponseView};
    use crate::view::collab_view::{
        CollabAllocateTokenRequestView, CollabAllocateTokenResponseView,
        CollabCallbacksResponseView,
    };
    use crate::view::compliance_view::{
        ComplianceFrameworkResponseView, ComplianceMapRequestView, ComplianceMapResponseView,
    };
    use crate::view::customer_auth_view::{
        ForgotPasswordRequest, OkView, ResetPasswordRequest, SignupRequest, VerifyEmailRequest,
    };
    use crate::view::engagement_view::{
        CreateEngagementView, EngagementView, UpdateEngagementView,
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
    use crate::view::risk_tuning_view::{
        EffectiveRiskConfigView, RiskThresholdsView, RiskWeightsView, TenantRiskConfigView,
    };
    use crate::view::risk_view::{
        CalculateEngagementRiskRequest, CalculateRiskRequest, CalculateRiskView,
        EngagementRiskBreakdownView, RiskBreakdownView, SeverityCounts,
    };

    struct StubAuthn;
    #[async_trait]
    impl AuthenticateUserPort for StubAuthn {
        async fn authenticate(&self, _i: AuthenticateUserInput) -> Result<TokenView, IamError> {
            Ok(TokenView::bearer("a", "r", 60))
        }
    }
    struct StubValidator {
        accept: bool,
        /// Permission strings minted into every accepted token's claims.
        /// Empty mirrors the historical least-privilege stub; a non-empty
        /// list lets a success-path router test exercise an endpoint now
        /// gated behind `require_permission`.
        permissions: Vec<String>,
    }
    #[async_trait]
    impl ValidateTokenPort for StubValidator {
        async fn validate(&self, _t: &str) -> Result<AccessClaims, IamError> {
            if self.accept {
                Ok(AccessClaims {
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
                    permissions: self
                        .permissions
                        .iter()
                        .filter_map(|p| sx_iam::domain::Permission::parse(p).ok())
                        .collect(),

                    cred_id: None,
                })
            } else {
                Err(IamError::InvalidToken)
            }
        }
    }
    struct StubRefresh;
    #[async_trait]
    impl RefreshTokenPort for StubRefresh {
        async fn refresh(&self, _t: &str) -> Result<TokenView, IamError> {
            Ok(TokenView::bearer("a", "r", 60))
        }
    }
    struct StubOidcExchange {
        accept: bool,
    }
    #[async_trait]
    impl OidcExchangePort for StubOidcExchange {
        async fn exchange(&self, _r: OidcExchangeRequest) -> Result<TokenView, Phase3PortError> {
            if self.accept {
                Ok(TokenView::bearer("oidc-a", "oidc-r", 60))
            } else {
                Err(Phase3PortError::Forbidden("verify failed".into()))
            }
        }
    }
    struct StubLogout;
    #[async_trait]
    impl LogoutPort for StubLogout {
        async fn revoke(&self, _jti: &str) -> Result<(), IamError> {
            Ok(())
        }
    }
    struct StubEngagements;
    #[async_trait]
    impl EngagementServicePort for StubEngagements {
        async fn create(
            &self,
            _t: &str,
            _r: CreateEngagementView,
        ) -> Result<EngagementView, EngagementPortError> {
            Err(EngagementPortError::Internal("stub".into()))
        }
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<EngagementView>, EngagementPortError> {
            Ok(vec![])
        }
        async fn get(&self, _t: &str, _i: &str) -> Result<EngagementView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn update(
            &self,
            _t: &str,
            _i: &str,
            _r: UpdateEngagementView,
        ) -> Result<EngagementView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
    }
    struct StubKillSwitch;
    #[async_trait]
    impl KillSwitchPort for StubKillSwitch {
        async fn trip(&self, _t: KillSwitchTrigger) -> Result<(), EngagementPortError> {
            Ok(())
        }
        async fn is_tripped(&self) -> Result<bool, EngagementPortError> {
            Ok(false)
        }
    }
    struct StubRisk;
    #[async_trait]
    impl CalculateRiskPort for StubRisk {
        async fn calculate(
            &self,
            _r: CalculateRiskRequest,
        ) -> Result<CalculateRiskView, RiskPortError> {
            Ok(CalculateRiskView {
                engagement_id: "e".into(),
                composite_score: 0.0,
                components: RiskBreakdownView {
                    cvss: 0.0,
                    epss: 0.0,
                    exposure: 0.0,
                    criticality: 0.0,
                },
            })
        }

        async fn calculate_engagement(
            &self,
            _t: &str,
            engagement_id: &str,
            _r: CalculateEngagementRiskRequest,
        ) -> Result<EngagementRiskBreakdownView, RiskPortError> {
            Ok(EngagementRiskBreakdownView {
                engagement_id: engagement_id.to_owned(),
                total_findings: 0,
                scored: 0,
                max_score: 0.0,
                average_score: 0.0,
                severity_counts: SeverityCounts::default(),
                top: vec![],
            })
        }
    }
    // P1-014 — risk-tuning port stub. Echoes the empty override on
    // read, echoes whatever the caller PUTs on write (no validation,
    // no persistence) — sufficient for router smoke tests.
    fn stub_default_weights() -> RiskWeightsView {
        RiskWeightsView {
            w_severity: 0.25,
            w_exploit: 0.20,
            w_exposure: 0.15,
            w_criticality: 0.20,
            w_business_impact: 0.15,
            w_chain: 0.05,
        }
    }
    fn stub_default_thresholds() -> RiskThresholdsView {
        RiskThresholdsView {
            low: 25.0,
            med: 50.0,
            high: 75.0,
            crit: 90.0,
        }
    }
    struct StubRiskTuning;
    #[async_trait]
    impl RiskTuningPort for StubRiskTuning {
        async fn get_override(
            &self,
            _tenant_id: &str,
        ) -> Result<TenantRiskConfigView, RiskTuningPortError> {
            Ok(TenantRiskConfigView::default())
        }
        async fn put_override(
            &self,
            _tenant_id: &str,
            _actor: Option<String>,
            req: TenantRiskConfigView,
        ) -> Result<EffectiveRiskConfigView, RiskTuningPortError> {
            Ok(EffectiveRiskConfigView {
                weights: req.weights.unwrap_or_else(stub_default_weights),
                thresholds: req.thresholds.unwrap_or_else(stub_default_thresholds),
            })
        }
        async fn get_effective(
            &self,
            _tenant_id: &str,
        ) -> Result<EffectiveRiskConfigView, RiskTuningPortError> {
            Ok(EffectiveRiskConfigView {
                weights: stub_default_weights(),
                thresholds: stub_default_thresholds(),
            })
        }
        fn defaults(&self) -> EffectiveRiskConfigView {
            EffectiveRiskConfigView {
                weights: stub_default_weights(),
                thresholds: stub_default_thresholds(),
            }
        }
    }
    struct StubDiscovery;
    #[async_trait]
    impl RunDiscoveryPort for StubDiscovery {
        async fn run(&self, _t: &str, _e: &str) -> Result<String, DiscoveryPortError> {
            Ok("run-1".into())
        }
    }
    struct StubAssets;
    #[async_trait]
    impl AssetRepositoryPort for StubAssets {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<AssetView>, EngagementPortError> {
            Ok(vec![])
        }
        async fn get(&self, _t: &str, _i: &str) -> Result<AssetView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
    }
    struct StubFindings;
    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(vec![])
        }
        async fn get(&self, _t: &str, _i: &str) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn update_status(
            &self,
            _t: &str,
            _i: &str,
            _s: &str,
            _c: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            Ok(view)
        }
    }
    struct StubTenants;
    #[async_trait]
    impl TenantRepositoryPort for StubTenants {
        async fn get(&self, _i: &str) -> Result<TenantSummaryView, EngagementPortError> {
            Ok(TenantSummaryView {
                id: "t".into(),
                name: "t".into(),
                slug: "t".into(),
                is_active: true,
            })
        }
    }

    struct StubBas;
    #[async_trait]
    impl BasRunPort for StubBas {
        async fn run(&self, _r: BasRunRequestView) -> Result<BasRunResponseView, Phase3PortError> {
            Ok(BasRunResponseView {
                simulation_id: "sim-1".into(),
                outcome: "simulated".into(),
                evidence_count: 0,
            })
        }
    }
    struct StubBasHistory;
    #[async_trait]
    impl crate::port::BasRunHistoryPort for StubBasHistory {
        async fn record(
            &self,
            _entry: crate::view::bas_view::BasRunHistoryView,
        ) -> Result<(), Phase3PortError> {
            Ok(())
        }
        async fn list(
            &self,
            _engagement_id: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<crate::view::bas_view::BasRunHistoryView>, Phase3PortError> {
            Ok(vec![])
        }
    }
    struct StubBasChain;
    #[async_trait]
    impl crate::port::BasChainPort for StubBasChain {
        async fn list_catalogue(
            &self,
        ) -> Result<Vec<crate::view::bas_view::LateralChainView>, Phase3PortError> {
            Ok(vec![])
        }
        async fn start_run(
            &self,
            tenant_id: String,
            chain_id: String,
            req: crate::view::bas_view::StartChainRunRequest,
        ) -> Result<crate::view::bas_view::ChainRunView, Phase3PortError> {
            Ok(crate::view::bas_view::ChainRunView {
                run_id: "00000000-0000-0000-0000-000000000000".into(),
                tenant_id,
                engagement_id: req.engagement_id,
                chain_id,
                status: "completed".into(),
                steps: vec![],
                started_at: "1970-01-01T00:00:00Z".into(),
                finished_at: Some("1970-01-01T00:00:00Z".into()),
            })
        }
        async fn get_run(
            &self,
            _tenant_id: &str,
            _run_id: &str,
        ) -> Result<crate::view::bas_view::ChainRunView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }
    struct StubHttpHeaderScanner;
    #[async_trait]
    impl crate::port::HttpHeaderScannerPort for StubHttpHeaderScanner {
        async fn run(
            &self,
            _req: crate::view::scan_view::HttpHeaderScanRequest,
            _tenant_id: String,
        ) -> Result<crate::view::scan_view::ScanRecord, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
        async fn list(
            &self,
            _engagement_id: Option<&str>,
            _limit: usize,
        ) -> Result<Vec<crate::view::scan_view::ScanRecord>, Phase3PortError> {
            Ok(vec![])
        }
        async fn get(
            &self,
            _tenant_id: &str,
            _scan_id: &str,
        ) -> Result<Option<crate::view::scan_view::ScanRecord>, Phase3PortError> {
            Ok(None)
        }
    }
    struct StubApprovals;
    #[async_trait]
    impl ApprovalPort for StubApprovals {
        async fn record(
            &self,
            req: RecordApprovalRequest,
        ) -> Result<ApprovalView, Phase3PortError> {
            Ok(ApprovalView {
                engagement_id: req.engagement_id,
                technique_id: req.technique_id,
                approver_email: req.approver_email,
                reason: req.reason,
                recorded_at: "1970-01-01T00:00:00Z".into(),
            })
        }
        async fn list(&self, _e: &str) -> Result<Vec<ApprovalView>, Phase3PortError> {
            Ok(vec![])
        }
        async fn count_distinct_approvers(
            &self,
            _e: &str,
            _t: &str,
        ) -> Result<u32, Phase3PortError> {
            Ok(0)
        }
    }
    struct StubGraph;
    #[async_trait]
    impl GraphAttackPathsPort for StubGraph {
        async fn search(
            &self,
            _r: GraphAttackPathsRequestView,
        ) -> Result<GraphAttackPathsResponseView, Phase3PortError> {
            Ok(GraphAttackPathsResponseView {
                paths: vec![],
                engine: "memory".to_owned(),
                degraded: false,
            })
        }
    }
    struct StubBlastRadius;
    #[async_trait]
    impl BlastRadiusPort for StubBlastRadius {
        async fn compute(
            &self,
            _tenant_id: &str,
            seed_asset_id: &str,
            max_depth: u8,
        ) -> Result<BlastRadiusResponseView, Phase3PortError> {
            Ok(BlastRadiusResponseView {
                seed_asset_id: seed_asset_id.to_owned(),
                max_depth,
                decay_base: 0.6,
                impacted: Vec::new(),
                total_score: 0.0,
                cached: false,
            })
        }
    }
    struct StubReport;
    #[async_trait]
    impl ReportRenderPort for StubReport {
        async fn render(
            &self,
            _r: ReportRenderRequestView,
        ) -> Result<ReportRenderResponseView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }
    struct StubComprehensiveReport;
    #[async_trait]
    impl crate::port::ComprehensiveReportPort for StubComprehensiveReport {
        async fn generate(
            &self,
            tenant_id: &str,
        ) -> Result<
            crate::view::comprehensive_report_view::ComprehensiveReportView,
            crate::port::ComprehensiveReportPortError,
        > {
            Ok(
                crate::view::comprehensive_report_view::ComprehensiveReportView {
                    generated_at: "1970-01-01T00:00:00Z".to_owned(),
                    tenant_id: tenant_id.to_owned(),
                    total_findings: 0,
                    posture_score: 100,
                    by_severity: Vec::new(),
                    compliance: Vec::new(),
                    markdown: "# Report".to_owned(),
                },
            )
        }
    }
    struct StubReportSchedule;
    #[async_trait]
    impl crate::port::ReportSchedulePort for StubReportSchedule {
        async fn list(
            &self,
            _tenant_id: &str,
        ) -> Result<
            Vec<crate::view::report_schedule_view::ReportScheduleView>,
            crate::port::ReportSchedulePortError,
        > {
            Ok(Vec::new())
        }
        async fn create(
            &self,
            _tenant_id: &str,
            req: crate::view::report_schedule_view::CreateReportScheduleRequest,
        ) -> Result<
            crate::view::report_schedule_view::ReportScheduleView,
            crate::port::ReportSchedulePortError,
        > {
            Ok(crate::view::report_schedule_view::ReportScheduleView {
                id: "stub-schedule".to_owned(),
                engagement_id: Some(req.engagement_id),
                format: req.format,
                cron_expr: req.cron_expr,
                recipients: req.recipients,
                enabled: true,
                next_run_at: "1970-01-01T00:00:00Z".to_owned(),
            })
        }
        async fn delete(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<(), crate::port::ReportSchedulePortError> {
            Ok(())
        }
    }
    struct StubBranding;
    #[async_trait]
    impl crate::port::BrandingPort for StubBranding {
        async fn get(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::branding_view::BrandingView, crate::port::BrandingPortError>
        {
            Ok(crate::view::branding_view::BrandingView {
                logo_png_base64: None,
                primary_color_hex: "#C71920".to_owned(),
                cover_md: None,
                footer_md: None,
            })
        }
        async fn set(
            &self,
            _tenant_id: &str,
            _actor: &str,
            req: crate::view::branding_view::SetBrandingRequest,
        ) -> Result<crate::view::branding_view::BrandingView, crate::port::BrandingPortError>
        {
            Ok(crate::view::branding_view::BrandingView {
                logo_png_base64: req.logo_png_base64,
                primary_color_hex: req.primary_color_hex,
                cover_md: req.cover_md,
                footer_md: req.footer_md,
            })
        }
    }
    struct StubReportDiff;
    #[async_trait]
    impl ReportDiffPort for StubReportDiff {
        async fn compute(
            &self,
            _r: ReportDiffRequestView,
        ) -> Result<ReportDiffResponseView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }
    struct StubRemediation;
    #[async_trait]
    impl RemediationAdvisoriesPort for StubRemediation {
        async fn advisories(
            &self,
            _r: RemediationAdvisoriesRequestView,
        ) -> Result<RemediationAdvisoriesResponseView, Phase3PortError> {
            Ok(RemediationAdvisoriesResponseView { advisories: vec![] })
        }
    }
    struct StubCompliance;
    #[async_trait]
    impl ComplianceFrameworkPort for StubCompliance {
        async fn list_framework(
            &self,
            framework: &str,
        ) -> Result<ComplianceFrameworkResponseView, Phase3PortError> {
            Ok(ComplianceFrameworkResponseView {
                framework: framework.to_owned(),
                controls: vec![],
            })
        }
        async fn map_finding(
            &self,
            req: ComplianceMapRequestView,
        ) -> Result<ComplianceMapResponseView, Phase3PortError> {
            Ok(ComplianceMapResponseView {
                finding_id: req.finding_id,
                controls: vec![],
            })
        }
    }
    struct StubComplianceEvidence;
    #[async_trait]
    impl crate::port::ComplianceEvidencePort for StubComplianceEvidence {
        async fn collect(
            &self,
            _tenant_id: &str,
            _period_start: Option<&str>,
            _period_end: Option<&str>,
        ) -> Result<
            crate::view::compliance_evidence_view::CollectEvidenceResponseView,
            crate::port::ComplianceEvidencePortError,
        > {
            Ok(
                crate::view::compliance_evidence_view::CollectEvidenceResponseView {
                    run_id: "00000000-0000-0000-0000-000000000000".into(),
                    bundle_key: "tenant/stub/bundles/x.zip".into(),
                    bundle_sha256: "0".repeat(64),
                    files: 0,
                },
            )
        }
        async fn list_bundles(
            &self,
            _tenant_id: &str,
        ) -> Result<
            crate::view::compliance_evidence_view::ListBundlesResponseView,
            crate::port::ComplianceEvidencePortError,
        > {
            Ok(
                crate::view::compliance_evidence_view::ListBundlesResponseView {
                    bundles: Vec::new(),
                },
            )
        }
        async fn download_bundle(
            &self,
            _tenant_id: &str,
            _run_id: &str,
        ) -> Result<
            crate::view::compliance_evidence_view::DownloadBundleResponseView,
            crate::port::ComplianceEvidencePortError,
        > {
            Err(crate::port::ComplianceEvidencePortError::NotFound)
        }
    }
    struct StubMl;
    #[async_trait]
    impl MlTriagePredictPort for StubMl {
        async fn predict(
            &self,
            _r: MlTriagePredictRequestView,
        ) -> Result<MlTriagePredictResponseView, Phase3PortError> {
            Ok(MlTriagePredictResponseView {
                label: "unknown".into(),
                probability: 0.0,
            })
        }
    }
    struct StubCloudInventory;
    #[async_trait]
    impl CloudInventoryPort for StubCloudInventory {
        async fn list(
            &self,
            _r: CloudInventoryRequestView,
        ) -> Result<CloudInventoryResponseView, Phase3PortError> {
            Ok(CloudInventoryResponseView { resources: vec![] })
        }
    }

    struct StubCollabAlloc;
    #[async_trait]
    impl CollabAllocateTokenPort for StubCollabAlloc {
        async fn allocate(
            &self,
            _r: CollabAllocateTokenRequestView,
        ) -> Result<CollabAllocateTokenResponseView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }
    struct StubCollabLookup;
    #[async_trait]
    impl CollabLookupCallbacksPort for StubCollabLookup {
        async fn lookup(
            &self,
            token: &str,
        ) -> Result<CollabCallbacksResponseView, Phase3PortError> {
            Ok(CollabCallbacksResponseView {
                token: token.to_owned(),
                callbacks: vec![],
            })
        }
    }
    struct StubProposePr;
    #[async_trait]
    impl ProposePrPort for StubProposePr {
        async fn propose(&self, _r: ProposePrInput) -> Result<ProposePrOutcome, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }
    struct StubSubmitThreat;
    #[async_trait]
    impl SubmitThreatObservationPort for StubSubmitThreat {
        async fn submit(
            &self,
            _r: SubmitThreatInput,
        ) -> Result<SubmitThreatOutcome, Phase3PortError> {
            Ok(SubmitThreatOutcome {
                accepted: true,
                submitted_count: 0,
            })
        }
    }
    struct StubScheduleValidation;
    #[async_trait]
    impl ScheduleValidationPort for StubScheduleValidation {
        async fn schedule(
            &self,
            _r: ScheduleValidationInput,
        ) -> Result<AutonomyEngineId, Phase3PortError> {
            Ok(AutonomyEngineId("engine-stub".to_owned()))
        }
        async fn cancel(&self, _id: &AutonomyEngineId) -> Result<(), Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }
    struct StubCreateUser;
    #[async_trait]
    impl CreateUserPort for StubCreateUser {
        async fn create(
            &self,
            req: CreateUserRequestView,
        ) -> Result<CreateUserResponseView, Phase3PortError> {
            Ok(CreateUserResponseView {
                id: "00000000-0000-0000-0000-00000000abcd".to_owned(),
                tenant_id: req.tenant_id,
                email: req.email,
                roles: req.roles,
                created_at: "1970-01-01T00:00:00Z".to_owned(),
            })
        }
    }
    struct StubCustomerAuth;
    #[async_trait]
    impl CustomerAuthPort for StubCustomerAuth {
        async fn signup(&self, _r: SignupRequest) -> Result<OkView, Phase3PortError> {
            Ok(OkView::ok())
        }
        async fn verify_email(&self, _r: VerifyEmailRequest) -> Result<OkView, Phase3PortError> {
            Ok(OkView::ok())
        }
        async fn forgot_password(
            &self,
            _r: ForgotPasswordRequest,
        ) -> Result<OkView, Phase3PortError> {
            Ok(OkView::ok())
        }
        async fn reset_password(
            &self,
            _r: ResetPasswordRequest,
        ) -> Result<OkView, Phase3PortError> {
            Ok(OkView::ok())
        }
    }

    struct StubSoc;
    #[async_trait]
    impl crate::port::SocPort for StubSoc {
        async fn list_alerts(
            &self,
            _tenant_id: Option<&str>,
        ) -> Result<Vec<crate::view::soc_view::SocAlertView>, Phase3PortError> {
            Ok(Vec::new())
        }
        async fn submit_event(&self, _event: serde_json::Value) -> Result<u32, Phase3PortError> {
            Ok(0)
        }
    }

    struct StubTwin;
    #[async_trait]
    impl crate::port::TwinPort for StubTwin {
        async fn get(
            &self,
            _tenant_id: &str,
            _engagement_id: &str,
        ) -> Result<crate::view::twin_view::TwinStateView, Phase3PortError> {
            Ok(crate::view::twin_view::TwinStateView {
                assets: Vec::new(),
                edges: Vec::new(),
                compromised_ids: Vec::new(),
            })
        }
    }

    struct StubIntelCheck;
    #[async_trait]
    impl crate::port::IntelCheckPort for StubIntelCheck {
        async fn check(
            &self,
            _req: crate::view::intel_view::IntelCheckRequest,
        ) -> Result<crate::view::intel_view::IntelCheckResponse, Phase3PortError> {
            Ok(crate::view::intel_view::IntelCheckResponse {
                known: false,
                source: None,
                last_seen: None,
            })
        }
    }

    struct StubPredictive;
    #[async_trait]
    impl crate::port::PredictivePort for StubPredictive {
        async fn predict(
            &self,
            _tenant_id: &str,
            _finding_id: &str,
        ) -> Result<crate::view::predictive_view::PredictResponse, Phase3PortError> {
            Ok(crate::view::predictive_view::PredictResponse {
                probability: 0.5,
                confidence: 0.0,
                risk_band: "medium".into(),
            })
        }
    }

    struct StubRedteam;
    #[async_trait]
    impl crate::port::RedteamPort for StubRedteam {
        async fn compose(
            &self,
            _tenant_id: &str,
            _req: crate::view::redteam_view::RedteamComposeRequest,
        ) -> Result<crate::view::redteam_view::RedteamChainView, Phase3PortError> {
            Ok(crate::view::redteam_view::RedteamChainView {
                steps: Vec::new(),
                chain_score: 1e-6,
            })
        }
    }

    struct StubCopilot;
    #[async_trait]
    impl crate::port::CopilotPort for StubCopilot {
        async fn chat(
            &self,
            _tenant_id: &str,
            _user_id: &str,
            _prompt: &str,
        ) -> Result<crate::view::copilot_view::CopilotChatResponse, Phase3PortError> {
            Ok(crate::view::copilot_view::CopilotChatResponse {
                reply: "stub".into(),
                model: "stub".into(),
            })
        }
    }

    struct StubCopilotApproval;
    #[async_trait]
    impl crate::port::CopilotApprovalPort for StubCopilotApproval {
        async fn propose(
            &self,
            _tenant_id: &str,
            _proposer: sx_collab::copilot_approval::CopilotProposer,
            _action: sx_collab::copilot_approval::ProposedAction,
        ) -> Result<sx_collab::copilot_approval::ApprovalToken, Phase3PortError> {
            Ok(sx_collab::copilot_approval::ApprovalToken::new_random())
        }
        async fn decide(
            &self,
            _tenant_id: &str,
            token: sx_collab::copilot_approval::ApprovalToken,
            decision: sx_collab::copilot_approval::Decision,
            reviewer: &str,
            reason: Option<String>,
        ) -> Result<sx_collab::copilot_approval::DecisionOutcome, Phase3PortError> {
            Ok(sx_collab::copilot_approval::DecisionOutcome {
                token,
                status: match decision {
                    sx_collab::copilot_approval::Decision::Approve => {
                        sx_collab::copilot_approval::ApprovalStatus::Approved
                    }
                    sx_collab::copilot_approval::Decision::Reject => {
                        sx_collab::copilot_approval::ApprovalStatus::Rejected
                    }
                },
                reviewer: sx_collab::copilot_approval::UserId(reviewer.to_owned()),
                reason,
                decided_at: "1970-01-01T00:00:00Z".into(),
            })
        }
        async fn list_pending(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<sx_collab::copilot_approval::PendingApproval>, Phase3PortError> {
            Ok(Vec::new())
        }
        async fn inspect(
            &self,
            _tenant_id: &str,
            _token: sx_collab::copilot_approval::ApprovalToken,
        ) -> Result<sx_collab::copilot_approval::ApprovalSnapshot, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }

    struct StubGraphsageRisk;
    impl crate::port::GraphsageRiskPort for StubGraphsageRisk {
        fn get(&self, _asset_id: &str) -> Option<f64> {
            None
        }
    }

    struct StubEngagementTransitions;
    #[async_trait]
    impl crate::port::EngagementTransitionPort for StubEngagementTransitions {
        async fn activate(
            &self,
            _t: &str,
            _i: &str,
        ) -> Result<crate::view::engagement_view::EngagementView, crate::port::EngagementPortError>
        {
            Err(crate::port::EngagementPortError::NotFound)
        }
        async fn pause(
            &self,
            _t: &str,
            _i: &str,
        ) -> Result<crate::view::engagement_view::EngagementView, crate::port::EngagementPortError>
        {
            Err(crate::port::EngagementPortError::NotFound)
        }
        async fn resume(
            &self,
            _t: &str,
            _i: &str,
        ) -> Result<crate::view::engagement_view::EngagementView, crate::port::EngagementPortError>
        {
            Err(crate::port::EngagementPortError::NotFound)
        }
        async fn abort(
            &self,
            _t: &str,
            _i: &str,
            _r: &str,
        ) -> Result<crate::view::engagement_view::EngagementView, crate::port::EngagementPortError>
        {
            Err(crate::port::EngagementPortError::NotFound)
        }
        async fn complete(
            &self,
            _t: &str,
            _i: &str,
        ) -> Result<crate::view::engagement_view::EngagementView, crate::port::EngagementPortError>
        {
            Err(crate::port::EngagementPortError::NotFound)
        }
    }

    struct StubEngagementClone;
    #[async_trait]
    impl crate::port::EngagementClonePort for StubEngagementClone {
        async fn clone_engagement(
            &self,
            _t: &str,
            _s: &str,
            _r: crate::view::engagement_view::CloneEngagementRequest,
        ) -> Result<crate::view::engagement_view::EngagementView, crate::port::EngagementPortError>
        {
            Err(crate::port::EngagementPortError::NotFound)
        }
    }

    struct StubRoles;
    #[async_trait]
    impl crate::port::RolesPort for StubRoles {
        async fn list(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::roles_view::ListRolesResponseView, Phase3PortError> {
            Ok(crate::view::roles_view::ListRolesResponseView { roles: Vec::new() })
        }
        async fn create(
            &self,
            _tenant_id: &str,
            _req: crate::view::roles_view::CreateRoleRequestView,
        ) -> Result<crate::view::roles_view::RoleView, Phase3PortError> {
            Err(Phase3PortError::Internal("stub".into()))
        }
        async fn delete(&self, _tenant_id: &str, _role_id: &str) -> Result<(), Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
        async fn assign(
            &self,
            _tenant_id: &str,
            _user_id: &str,
            _req: crate::view::roles_view::AssignRolesRequestView,
        ) -> Result<crate::view::roles_view::AssignRolesResponseView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }

    struct StubAssetWrite;
    #[async_trait]
    impl crate::port::AssetWritePort for StubAssetWrite {
        async fn create(
            &self,
            _tenant_id: &str,
            _req: crate::view::asset_view::CreateAssetRequest,
        ) -> Result<crate::view::asset_view::AssetView, crate::port::EngagementPortError> {
            Err(crate::port::EngagementPortError::NotFound)
        }
        async fn update(
            &self,
            _tenant_id: &str,
            _id: &str,
            _req: crate::view::asset_view::UpdateAssetRequest,
        ) -> Result<crate::view::asset_view::AssetView, crate::port::EngagementPortError> {
            Err(crate::port::EngagementPortError::NotFound)
        }
        async fn delete(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<(), crate::port::EngagementPortError> {
            Err(crate::port::EngagementPortError::NotFound)
        }
    }

    struct StubProwlerImport;
    #[async_trait]
    impl crate::port::ProwlerImportPort for StubProwlerImport {
        async fn import(
            &self,
            tenant_id: &str,
            _actor: &str,
            bytes: &[u8],
        ) -> Result<
            crate::view::prowler_import_view::ProwlerImportResponse,
            crate::port::ProwlerImportPortError,
        > {
            Ok(crate::view::prowler_import_view::ProwlerImportResponse {
                id: "stub-prowler-import".into(),
                tenant_id: tenant_id.into(),
                upload_digest: format!("stub-digest-len-{}", bytes.len()),
                upload_bytes: bytes.len() as u64,
                parsed: 0,
                written: 0,
                rejected_cross_tenant: 0,
                deduplicated: 0,
                kev_uplifts_applied: 0,
                unmapped_check_ids: 0,
                accepted_at: "2027-01-01T00:00:00Z".into(),
            })
        }
    }

    struct StubVulnIngest;
    #[async_trait]
    impl crate::port::VulnIngestPort for StubVulnIngest {
        async fn import(
            &self,
            tenant_id: &str,
            source: &str,
            _payload: &[u8],
        ) -> Result<crate::view::vuln_ingest_view::VulnImportResponse, Phase3PortError> {
            Ok(crate::view::vuln_ingest_view::VulnImportResponse {
                import: crate::view::vuln_ingest_view::VulnImportView {
                    id: "stub-import-id".into(),
                    tenant_id: tenant_id.into(),
                    source: source.into(),
                    asset_count: 0,
                    finding_count: 0,
                    ingested_at: "2027-01-01T00:00:00Z".into(),
                    status: "ok".into(),
                },
                duplicates_dropped: 0,
                parse_errors: 0,
            })
        }
        async fn list(
            &self,
            _tenant_id: &str,
            _limit: usize,
        ) -> Result<Vec<crate::view::vuln_ingest_view::VulnImportView>, Phase3PortError> {
            Ok(Vec::new())
        }
    }

    struct StubAssetBulk;
    #[async_trait]
    impl crate::port::AssetBulkImportPort for StubAssetBulk {
        async fn import(
            &self,
            _tenant_id: &str,
            _req: crate::view::asset_view::BulkImportRequest,
        ) -> Result<crate::view::asset_view::BulkImportResponse, Phase3PortError> {
            Ok(crate::view::asset_view::BulkImportResponse {
                created: 0,
                skipped: 0,
                errors: Vec::new(),
            })
        }
    }

    struct StubFindingBulk;
    #[async_trait]
    impl crate::port::FindingBulkPort for StubFindingBulk {
        async fn bulk_update(
            &self,
            _tenant_id: &str,
            _req: crate::view::finding_view::BulkUpdateFindingsRequest,
        ) -> Result<crate::view::finding_view::BulkUpdateResponse, Phase3PortError> {
            Ok(crate::view::finding_view::BulkUpdateResponse {
                updated: 0,
                failed: 0,
                errors: Vec::new(),
            })
        }
        async fn export(
            &self,
            _tenant_id: &str,
            _format: crate::port::FindingExportFormat,
            _since: Option<String>,
        ) -> Result<Vec<u8>, Phase3PortError> {
            Ok(Vec::new())
        }
    }

    struct StubTenantWrite;
    #[async_trait]
    impl crate::port::TenantWritePort for StubTenantWrite {
        async fn create(
            &self,
            _req: crate::view::tenant_view::CreateTenantRequest,
        ) -> Result<TenantSummaryView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
        async fn update(
            &self,
            _id: &str,
            _req: crate::view::tenant_view::UpdateTenantRequest,
        ) -> Result<TenantSummaryView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
        async fn delete(&self, _id: &str) -> Result<(), Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }

    struct StubAuditQuery;
    #[async_trait]
    impl crate::port::AuditQueryPort for StubAuditQuery {
        async fn search(
            &self,
            _query: crate::view::audit_view::AuditSearchQuery,
        ) -> Result<crate::view::audit_view::AuditSearchResponse, Phase3PortError> {
            Ok(crate::view::audit_view::AuditSearchResponse {
                items: Vec::new(),
                has_more: false,
            })
        }
        async fn export_ndjson(&self, _since: Option<String>) -> Result<Vec<u8>, Phase3PortError> {
            Ok(Vec::new())
        }
    }

    struct StubAuditReplay;
    #[async_trait]
    impl crate::port::AuditReplayPort for StubAuditReplay {
        async fn replay(
            &self,
            _tenant_id: &str,
            query: crate::view::audit_view::AuditReplayQuery,
        ) -> Result<crate::view::audit_view::AuditReplayResponse, Phase3PortError> {
            Ok(crate::view::audit_view::AuditReplayResponse {
                entity_type: query.entity_type,
                entity_id: query.entity_id,
                chain_verified: true,
                chain_error: None,
                events: Vec::new(),
            })
        }
        async fn diff(
            &self,
            _tenant_id: &str,
            query: crate::view::audit_view::AuditDiffQuery,
        ) -> Result<crate::view::audit_view::AuditDiffResponse, Phase3PortError> {
            Ok(crate::view::audit_view::AuditDiffResponse {
                entity_type: query.entity_type,
                entity_id: query.entity_id,
                from_ts: query.from,
                to_ts: query.to,
                before: None,
                after: None,
                chain_verified: true,
                chain_error: None,
            })
        }
    }

    struct StubRemediationTracking;
    #[async_trait]
    impl crate::port::RemediationTrackingPort for StubRemediationTracking {
        async fn link(
            &self,
            _tenant_id: &str,
            _finding_id: &str,
            _actor_id: &str,
            _req: crate::view::finding_view::RemediationLinkRequest,
        ) -> Result<crate::view::finding_view::RemediationLinkView, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
        async fn unlink(&self, _tenant_id: &str, _finding_id: &str) -> Result<(), Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }

    struct StubLogIngest;
    #[async_trait]
    impl crate::port::LogIngestPort for StubLogIngest {
        async fn ingest_one(
            &self,
            _tenant_id: &str,
            _source: &str,
            _payload: &str,
        ) -> Result<(), crate::port::LogIngestError> {
            Ok(())
        }
        async fn list(
            &self,
            _tenant_id: &str,
            _limit: usize,
        ) -> Result<Vec<crate::view::log_ingest_view::OcsfEventView>, crate::port::LogIngestError>
        {
            Ok(Vec::new())
        }
    }

    /// MED-001 router-level test stub — always admits so the existing
    /// log-ingest router tests keep their pre-MED-001 behaviour. The
    /// real bucket adapter lives in `sx-monolith::adapters::log_ingest`.
    struct StubLogRateLimit;
    impl crate::port::LogRateLimitPort for StubLogRateLimit {
        fn try_acquire(
            &self,
            _tenant_id: &str,
            _endpoint: &str,
        ) -> crate::port::LogRateLimitDecision {
            crate::port::LogRateLimitDecision {
                allowed: true,
                limit: 1_000,
                remaining: 999,
                reset_at_unix_secs: 0,
                retry_after_secs: 0,
            }
        }
        fn set_tier(
            &self,
            _tenant_id: &str,
            tier: &str,
            override_rate_per_sec: Option<u32>,
        ) -> Result<crate::port::LogRateLimitTierSnapshot, crate::port::LogRateLimitError> {
            let per_sec = override_rate_per_sec.unwrap_or(match tier {
                "pro" => 1_000,
                "enterprise" => 10_000,
                _ => 100,
            });
            Ok(crate::port::LogRateLimitTierSnapshot {
                per_sec_rate: per_sec,
                burst: per_sec.saturating_mul(2),
            })
        }
        fn tier_of(&self, _tenant_id: &str) -> (String, Option<u32>) {
            ("free".into(), None)
        }
    }

    /// Test SCIM port backed by the real `InMemoryScimProvisioner` from
    /// `sx-scim`.
    struct StubScim {
        provisioner: sx_scim::service::provisioner::InMemoryScimProvisioner,
    }
    impl StubScim {
        fn new() -> Self {
            Self {
                provisioner: sx_scim::service::provisioner::InMemoryScimProvisioner::new(),
            }
        }
    }
    #[async_trait]
    impl crate::port::ScimProvisionPort for StubScim {
        async fn authenticate(
            &self,
            bearer: &str,
        ) -> Result<crate::port::ScimAuthContext, sx_scim::ScimError> {
            if bearer == "scim_test_bearer" {
                Ok(crate::port::ScimAuthContext {
                    tenant_id: "t".into(),
                    scopes: vec![
                        sx_scim::ScimScope::UsersRead,
                        sx_scim::ScimScope::UsersWrite,
                        sx_scim::ScimScope::GroupsRead,
                        sx_scim::ScimScope::GroupsWrite,
                    ],
                    token_id: "tok-stub".into(),
                })
            } else {
                Err(sx_scim::ScimError::Unauthorised)
            }
        }
        async fn create_user(
            &self,
            tenant_id: &str,
            user: sx_scim::schema::user::ScimUser,
        ) -> Result<sx_scim::schema::user::ScimUser, sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.create_user(tenant_id, user).await
        }
        async fn get_user(
            &self,
            tenant_id: &str,
            id: &str,
        ) -> Result<sx_scim::schema::user::ScimUser, sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.get_user(tenant_id, id).await
        }
        async fn replace_user(
            &self,
            tenant_id: &str,
            id: &str,
            u: sx_scim::schema::user::ScimUser,
        ) -> Result<sx_scim::schema::user::ScimUser, sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.replace_user(tenant_id, id, u).await
        }
        async fn delete_user(&self, tenant_id: &str, id: &str) -> Result<(), sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.delete_user(tenant_id, id).await
        }
        async fn list_users(
            &self,
            tenant_id: &str,
            q: sx_scim::service::provisioner::ListUsersQuery,
        ) -> Result<sx_scim::service::provisioner::ListUsersResult, sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.list_users(tenant_id, q).await
        }
        async fn create_group(
            &self,
            tenant_id: &str,
            g: sx_scim::schema::group::ScimGroup,
        ) -> Result<sx_scim::schema::group::ScimGroup, sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.create_group(tenant_id, g).await
        }
        async fn get_group(
            &self,
            tenant_id: &str,
            id: &str,
        ) -> Result<sx_scim::schema::group::ScimGroup, sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.get_group(tenant_id, id).await
        }
        async fn list_groups(
            &self,
            tenant_id: &str,
            q: sx_scim::service::provisioner::ListUsersQuery,
        ) -> Result<sx_scim::service::provisioner::ListGroupsResult, sx_scim::ScimError> {
            use sx_scim::service::provisioner::ScimProvisioner;
            self.provisioner.list_groups(tenant_id, q).await
        }
        async fn mint_token(
            &self,
            _t: &str,
            _name: &str,
            _scopes: Vec<sx_scim::ScimScope>,
            _ttl_days: Option<u32>,
        ) -> Result<(crate::view::scim_view::ScimTokenView, String), sx_scim::ScimError> {
            Ok((
                crate::view::scim_view::ScimTokenView {
                    id: "tid".into(),
                    tenant_id: "t".into(),
                    name: "n".into(),
                    scopes: vec!["scim:users:read".into()],
                    status: crate::view::scim_view::ScimTokenStatus::Active,
                    created_at: "2026-01-01T00:00:00Z".into(),
                    activated_at: "2026-01-01T00:00:00Z".into(),
                    expires_at: "2026-04-01T00:00:00Z".into(),
                    retired_at: None,
                    revoked_at: None,
                    last_used_at: None,
                },
                "scim_plaintext".into(),
            ))
        }
        async fn rotate_token(
            &self,
            _t: &str,
            _id: &str,
        ) -> Result<(crate::view::scim_view::ScimTokenView, String), sx_scim::ScimError> {
            Ok((
                crate::view::scim_view::ScimTokenView {
                    id: "tid-rotated".into(),
                    tenant_id: "t".into(),
                    name: "n".into(),
                    scopes: vec!["scim:users:read".into()],
                    status: crate::view::scim_view::ScimTokenStatus::Active,
                    created_at: "2026-01-02T00:00:00Z".into(),
                    activated_at: "2026-01-02T00:00:00Z".into(),
                    expires_at: "2026-04-02T00:00:00Z".into(),
                    retired_at: None,
                    revoked_at: None,
                    last_used_at: None,
                },
                "scim_rotated".into(),
            ))
        }
        async fn list_tokens(
            &self,
            _t: &str,
        ) -> Result<Vec<crate::view::scim_view::ScimTokenView>, sx_scim::ScimError> {
            Ok(vec![])
        }
        async fn revoke_token(&self, _t: &str, _id: &str) -> Result<(), sx_scim::ScimError> {
            Ok(())
        }
    }

    struct StubRba;
    #[async_trait]
    impl crate::port::RbaPort for StubRba {
        async fn evaluate(
            &self,
            _input: crate::port::RbaEvaluateInput,
        ) -> Result<crate::port::RbaEvaluateOutput, crate::port::RbaPortError> {
            Ok(crate::port::RbaEvaluateOutput {
                score: 0,
                action: crate::port::RbaActionWire::Allow,
                reason: "stub".into(),
            })
        }
        async fn list_decisions(
            &self,
            _tenant_id: &str,
            _limit: u32,
            _include_signals: bool,
        ) -> Result<Vec<crate::view::rba_view::RbaDecisionView>, crate::port::RbaPortError>
        {
            Ok(Vec::new())
        }
        async fn get_config(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::rba_view::RbaConfigView, crate::port::RbaPortError> {
            Ok(crate::view::rba_view::RbaConfigView {
                allow_threshold: 30,
                block_threshold: 70,
                weights: crate::view::rba_view::RbaWeightsView {
                    w_ip_geo: 0.4,
                    w_velocity: 0.4,
                    w_business_hours: 0.2,
                    w_device_fp: 0.0,
                    w_mfa_recent: 0.0,
                    w_success_rate: 0.0,
                    w_impossible_travel: 0.0,
                },
                feature_flags: crate::view::rba_view::RbaFeatureFlagsView::default(),
                business_tz: "UTC".into(),
                business_hours_start: 9,
                business_hours_end: 18,
            })
        }
        async fn put_config(
            &self,
            _tenant_id: &str,
            cfg: crate::view::rba_view::RbaConfigView,
        ) -> Result<crate::view::rba_view::RbaConfigView, crate::port::RbaPortError> {
            Ok(cfg)
        }
        async fn list_known_devices(
            &self,
            _tenant_id: &str,
            _user_id: &str,
        ) -> Result<crate::view::rba_view::KnownDevicesResponse, crate::port::RbaPortError>
        {
            Ok(crate::view::rba_view::KnownDevicesResponse {
                devices: Vec::new(),
            })
        }
        async fn revoke_known_device(
            &self,
            _tenant_id: &str,
            _user_id: &str,
            _fp_hash: &str,
        ) -> Result<(), crate::port::RbaPortError> {
            Ok(())
        }
    }

    struct StubRemediationOutcomes;
    #[async_trait]
    impl crate::port::RemediationOutcomesPort for StubRemediationOutcomes {
        async fn metrics(
            &self,
            tenant_id: &str,
            window_days: u32,
        ) -> Result<crate::view::remediation_outcomes_view::RemediationMetricsView, Phase3PortError>
        {
            Ok(
                crate::view::remediation_outcomes_view::RemediationMetricsView {
                    tenant_id: tenant_id.to_owned(),
                    window_seconds: i64::from(window_days) * 86_400,
                    mttr_by_severity: Vec::new(),
                    regression_rate: 0.0,
                    top_regressing: Vec::new(),
                    closure_count: 0,
                    regression_count: 0,
                },
            )
        }
        async fn list_regressions(
            &self,
            _tenant_id: &str,
            _limit: u32,
        ) -> Result<crate::view::remediation_outcomes_view::RegressionListView, Phase3PortError>
        {
            Ok(crate::view::remediation_outcomes_view::RegressionListView::default())
        }
    }

    struct StubUeba;
    #[async_trait]
    impl crate::port::UebaPort for StubUeba {
        async fn get_baseline(
            &self,
            _tenant_id: &str,
            user_id: &str,
        ) -> Result<crate::view::ueba_view::UebaBaselineView, crate::port::UebaPortError> {
            Ok(crate::view::ueba_view::UebaBaselineView {
                tenant_id: None,
                user_id: user_id.to_owned(),
                login_hour_counts: vec![0; 24],
                ip_prefixes: std::collections::BTreeMap::new(),
                accessed_assets: std::collections::BTreeMap::new(),
                updated_at: None,
            })
        }
        async fn list_anomalies(
            &self,
            _tenant_id: &str,
            _limit: usize,
        ) -> Result<Vec<crate::view::ueba_view::UebaAnomalyView>, crate::port::UebaPortError>
        {
            Ok(Vec::new())
        }
    }

    struct StubUebaAdmin;
    #[async_trait]
    impl crate::port::UebaAdminPort for StubUebaAdmin {
        async fn freeze(
            &self,
            tenant_id: &str,
            user_id: &str,
            _actor: Option<&str>,
            _reason: Option<&str>,
        ) -> Result<crate::view::ueba_admin_view::BaselineStateView, crate::port::UebaAdminPortError>
        {
            Ok(crate::view::ueba_admin_view::BaselineStateView {
                tenant_id: tenant_id.to_owned(),
                user_id: user_id.to_owned(),
                state: crate::view::ueba_admin_view::BaselineStateCode::Frozen,
                snapshot: None,
            })
        }
        async fn unfreeze(
            &self,
            tenant_id: &str,
            user_id: &str,
            _actor: Option<&str>,
            _reason: Option<&str>,
        ) -> Result<crate::view::ueba_admin_view::BaselineStateView, crate::port::UebaAdminPortError>
        {
            Ok(crate::view::ueba_admin_view::BaselineStateView {
                tenant_id: tenant_id.to_owned(),
                user_id: user_id.to_owned(),
                state: crate::view::ueba_admin_view::BaselineStateCode::Active,
                snapshot: None,
            })
        }
        async fn snapshot(
            &self,
            tenant_id: &str,
            user_id: &str,
        ) -> Result<crate::view::ueba_admin_view::BaselineStateView, crate::port::UebaAdminPortError>
        {
            Ok(crate::view::ueba_admin_view::BaselineStateView {
                tenant_id: tenant_id.to_owned(),
                user_id: user_id.to_owned(),
                state: crate::view::ueba_admin_view::BaselineStateCode::Learning,
                snapshot: None,
            })
        }
    }

    struct StubSoar;
    #[async_trait]
    impl crate::port::SoarPort for StubSoar {
        async fn create_workflow(
            &self,
            tenant_id: &str,
            req: crate::view::soar_view::CreateWorkflowRequest,
        ) -> Result<crate::view::soar_view::WorkflowView, crate::port::SoarPortError> {
            Ok(crate::view::soar_view::WorkflowView {
                id: "00000000-0000-0000-0000-000000000000".into(),
                tenant_id: tenant_id.to_owned(),
                name: req.name,
                definition: req.definition,
                enabled: req.enabled,
            })
        }
        async fn get_workflow(
            &self,
            tenant_id: &str,
            workflow_id: &str,
        ) -> Result<crate::view::soar_view::WorkflowView, crate::port::SoarPortError> {
            Ok(crate::view::soar_view::WorkflowView {
                id: workflow_id.to_owned(),
                tenant_id: tenant_id.to_owned(),
                name: "stub".into(),
                definition: sx_soar::WorkflowGraph {
                    nodes: vec![sx_soar::Node::Trigger {
                        id: "t".into(),
                        trigger: sx_soar::Trigger::Any,
                    }],
                    edges: vec![],
                },
                enabled: true,
            })
        }
        async fn run_workflow(
            &self,
            tenant_id: &str,
            workflow_id: &str,
            _event: sx_soar::TriggerEvent,
        ) -> Result<crate::view::soar_view::WorkflowRunView, crate::port::SoarPortError> {
            Ok(crate::view::soar_view::WorkflowRunView {
                id: "00000000-0000-0000-0000-000000000001".into(),
                tenant_id: tenant_id.to_owned(),
                workflow_id: workflow_id.to_owned(),
                trigger_payload: serde_json::Value::Null,
                status: "skipped".into(),
                node_results: Vec::new(),
                started_at: "1970-01-01T00:00:00Z".into(),
                finished_at: "1970-01-01T00:00:00Z".into(),
            })
        }
        async fn get_run(
            &self,
            tenant_id: &str,
            run_id: &str,
        ) -> Result<crate::view::soar_view::WorkflowRunView, crate::port::SoarPortError> {
            Ok(crate::view::soar_view::WorkflowRunView {
                id: run_id.to_owned(),
                tenant_id: tenant_id.to_owned(),
                workflow_id: "00000000-0000-0000-0000-000000000000".into(),
                trigger_payload: serde_json::Value::Null,
                status: "ok".into(),
                node_results: Vec::new(),
                started_at: "1970-01-01T00:00:00Z".into(),
                finished_at: "1970-01-01T00:00:00Z".into(),
            })
        }
    }

    struct StubMfa;
    #[async_trait]
    impl crate::port::MfaPort for StubMfa {
        async fn enroll(
            &self,
            _user_id: &str,
        ) -> Result<crate::view::mfa_view::EnrollResponse, IamError> {
            Ok(crate::view::mfa_view::EnrollResponse {
                secret_base32: "JBSWY3DPEHPK3PXP".into(),
                otpauth_uri: "otpauth://totp/SentinelX:test".into(),
                recovery_codes: Vec::new(),
            })
        }
        async fn verify(&self, _user_id: &str, _code: &str) -> Result<(), IamError> {
            Ok(())
        }
        async fn disable(&self, _user_id: &str, _code: &str) -> Result<(), IamError> {
            Ok(())
        }
        async fn status(
            &self,
            _user_id: &str,
        ) -> Result<crate::view::mfa_view::MfaStatusView, IamError> {
            Ok(crate::view::mfa_view::MfaStatusView {
                enrolled: false,
                last_verified_at: None,
            })
        }
    }

    struct StubWebauthn;
    #[async_trait]
    impl crate::port::WebauthnPort for StubWebauthn {
        async fn register_start(
            &self,
            _tenant_id: &str,
            _user_id: &str,
            _user_name: &str,
        ) -> Result<crate::view::webauthn_view::RegisterStartResponse, IamError> {
            Ok(crate::view::webauthn_view::RegisterStartResponse {
                state_id: "stub-state".into(),
                challenge: serde_json::json!({}),
            })
        }
        async fn register_finish(
            &self,
            _tenant_id: &str,
            _user_id: &str,
            _req: crate::view::webauthn_view::RegisterFinishRequest,
            _label: Option<String>,
        ) -> Result<crate::view::webauthn_view::RegisterFinishResponse, IamError> {
            Ok(crate::view::webauthn_view::RegisterFinishResponse {
                cred_id: "stub-cred-id".into(),
            })
        }
        async fn login_start(
            &self,
            _email: &str,
        ) -> Result<crate::view::webauthn_view::LoginStartResponse, IamError> {
            Ok(crate::view::webauthn_view::LoginStartResponse {
                state_id: "stub-state".into(),
                challenge: serde_json::json!({}),
            })
        }
        async fn login_finish(
            &self,
            _req: crate::view::webauthn_view::LoginFinishRequest,
        ) -> Result<crate::view::webauthn_view::LoginFinishResponse, IamError> {
            Ok(crate::view::webauthn_view::LoginFinishResponse {
                access_token: "stub-access".into(),
                refresh_token: "stub-refresh".into(),
                expires_in: 900,
                cred_id: "stub-cred-id".into(),
            })
        }
        async fn list_aaguid_policy(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::webauthn_view::AaguidPolicyListResponse, IamError> {
            Ok(crate::view::webauthn_view::AaguidPolicyListResponse {
                rows: Vec::new(),
                allowlist_mode: false,
            })
        }
        async fn put_aaguid_policy(
            &self,
            _tenant_id: &str,
            _set_by: &str,
            aaguid: &str,
            req: crate::view::webauthn_view::PutAaguidPolicyRequest,
        ) -> Result<crate::view::webauthn_view::AaguidPolicyView, IamError> {
            Ok(crate::view::webauthn_view::AaguidPolicyView {
                aaguid: aaguid.to_owned(),
                action: req.action,
                reason: req.reason,
                set_by: "00000000-0000-0000-0000-000000000000".into(),
                set_at: "1970-01-01T00:00:00Z".into(),
            })
        }
        async fn delete_aaguid_policy(
            &self,
            _tenant_id: &str,
            _aaguid: &str,
        ) -> Result<(), IamError> {
            Ok(())
        }
        async fn mds_status(&self) -> Result<crate::view::webauthn_view::MdsStatusView, IamError> {
            Ok(crate::view::webauthn_view::MdsStatusView {
                last_refresh: None,
                total_entries: 0,
                root_cert_fingerprint: String::new(),
                is_stale: true,
            })
        }
        async fn mds_refresh(&self) -> Result<crate::view::webauthn_view::MdsStatusView, IamError> {
            Ok(crate::view::webauthn_view::MdsStatusView {
                last_refresh: None,
                total_entries: 0,
                root_cert_fingerprint: String::new(),
                is_stale: true,
            })
        }
        async fn list_user_credentials(
            &self,
            _tenant_id: &str,
            _user_id: &str,
        ) -> Result<crate::view::webauthn_view::CredentialListResponse, IamError> {
            Ok(crate::view::webauthn_view::CredentialListResponse {
                credentials: Vec::new(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct StubDlp;
    #[async_trait]
    impl crate::port::DlpPort for StubDlp {
        async fn scan(
            &self,
            tenant_id: &str,
            payload: &[u8],
        ) -> Result<crate::port::DlpScanResultView, crate::port::DlpPortError> {
            Ok(crate::port::DlpScanResultView {
                id: "00000000-0000-0000-0000-000000000000".into(),
                tenant_id: tenant_id.to_owned(),
                finished_at: "1970-01-01T00:00:00Z".into(),
                bytes_scanned: payload.len(),
                total_matches: 0,
                summary: Vec::new(),
                matches: Vec::new(),
            })
        }
        async fn get_config(
            &self,
            tenant_id: &str,
        ) -> Result<crate::port::DlpDetectorConfigView, crate::port::DlpPortError> {
            Ok(crate::port::DlpDetectorConfigView {
                tenant_id: tenant_id.to_owned(),
                enabled: Vec::new(),
                min_confidence: 0.0,
            })
        }
        async fn put_config(
            &self,
            tenant_id: &str,
            enabled: Vec<crate::port::DlpDetectorKind>,
            min_confidence: Option<f32>,
        ) -> Result<crate::port::DlpDetectorConfigView, crate::port::DlpPortError> {
            Ok(crate::port::DlpDetectorConfigView {
                tenant_id: tenant_id.to_owned(),
                enabled,
                min_confidence: min_confidence.unwrap_or(0.0),
            })
        }
        async fn get_threshold(
            &self,
            tenant_id: &str,
        ) -> Result<crate::port::DlpThresholdView, crate::port::DlpPortError> {
            Ok(crate::port::DlpThresholdView {
                tenant_id: tenant_id.to_owned(),
                min_confidence: 0.0,
            })
        }
        async fn put_threshold(
            &self,
            tenant_id: &str,
            min_confidence: f32,
        ) -> Result<crate::port::DlpThresholdView, crate::port::DlpPortError> {
            Ok(crate::port::DlpThresholdView {
                tenant_id: tenant_id.to_owned(),
                min_confidence,
            })
        }
    }

    #[derive(Debug, Default)]
    struct StubDeviceTrust;
    #[async_trait]
    impl crate::port::DeviceTrustPort for StubDeviceTrust {
        async fn get_policy(
            &self,
            _tenant_id: &str,
        ) -> Result<sx_device_trust::PosturePolicy, sx_device_trust::service::DeviceTrustError>
        {
            Ok(sx_device_trust::PosturePolicy::permissive())
        }
        async fn put_policy(
            &self,
            _tenant_id: &str,
            policy: sx_device_trust::PosturePolicy,
        ) -> Result<sx_device_trust::PosturePolicy, sx_device_trust::service::DeviceTrustError>
        {
            Ok(policy)
        }
        async fn evaluate(
            &self,
            _tenant_id: &str,
            _posture: &sx_device_trust::PostureClaims,
        ) -> Result<sx_device_trust::DeviceTrustDecision, sx_device_trust::service::DeviceTrustError>
        {
            Ok(sx_device_trust::DeviceTrustDecision::trusted())
        }
        async fn record_snapshot(
            &self,
            _tenant_id: &str,
            _snapshot: sx_device_trust::service::PostureSnapshot,
        ) -> Result<(), sx_device_trust::service::DeviceTrustError> {
            Ok(())
        }
        async fn list_snapshots(
            &self,
            _tenant_id: &str,
            _limit: usize,
        ) -> Result<
            Vec<sx_device_trust::service::PostureSnapshot>,
            sx_device_trust::service::DeviceTrustError,
        > {
            Ok(Vec::new())
        }
        fn jwt_secret(&self) -> Vec<u8> {
            b"stub-device-trust-secret--------".to_vec()
        }
    }

    #[derive(Debug, Default)]
    struct StubSamlSp;
    #[async_trait]
    impl crate::port::SamlSpPort for StubSamlSp {
        async fn metadata(&self) -> Result<String, crate::port::SamlPortError> {
            Err(crate::port::SamlPortError::Disabled(
                "SAML stub: disabled".into(),
            ))
        }
        async fn process_acs(
            &self,
            _tenant_id_hint: Option<&str>,
            _saml_response_b64: &str,
            _relay_state: Option<&str>,
        ) -> Result<crate::port::SamlAcsOutcome, crate::port::SamlPortError> {
            Err(crate::port::SamlPortError::Disabled(
                "SAML stub: disabled".into(),
            ))
        }
        async fn build_logout(
            &self,
            _tenant_id: &str,
            _name_id: &str,
            _session_index: Option<&str>,
        ) -> Result<String, crate::port::SamlPortError> {
            Err(crate::port::SamlPortError::Disabled(
                "SAML stub: disabled".into(),
            ))
        }
    }

    #[derive(Debug)]
    struct StubSamlIdpAdmin;
    #[async_trait]
    impl crate::port::SamlIdpAdminPort for StubSamlIdpAdmin {
        async fn get_idp(
            &self,
            _tenant_id: &str,
        ) -> Result<
            Option<crate::view::saml_view::SamlIdpConfigView>,
            crate::port::SamlIdpAdminPortError,
        > {
            Ok(None)
        }
        async fn set_idp(
            &self,
            _tenant_id: &str,
            config: crate::view::saml_view::SamlIdpConfigView,
        ) -> Result<crate::view::saml_view::SamlIdpConfigView, crate::port::SamlIdpAdminPortError>
        {
            Ok(config)
        }
    }

    // CRIT-004 stubs.
    #[derive(Debug, Default)]
    struct StubOidcRpLogout;
    #[async_trait]
    impl crate::port::OidcRpLogoutPort for StubOidcRpLogout {
        async fn initiate(
            &self,
            _session_id: &str,
        ) -> Result<crate::port::OidcRpLogoutRedirect, crate::port::LogoutPortError> {
            Err(crate::port::LogoutPortError::Disabled(
                "OIDC RP-initiated logout disabled".into(),
            ))
        }
    }

    #[derive(Debug, Default)]
    struct StubOidcBackchannelLogout;
    #[async_trait]
    impl crate::port::OidcBackchannelLogoutPort for StubOidcBackchannelLogout {
        async fn process(&self, _logout_token: &str) -> Result<(), crate::port::LogoutPortError> {
            Err(crate::port::LogoutPortError::Disabled(
                "OIDC back-channel logout disabled".into(),
            ))
        }
    }

    #[derive(Debug, Default)]
    struct StubOidcFrontchannelLogout;
    #[async_trait]
    impl crate::port::OidcFrontchannelLogoutPort for StubOidcFrontchannelLogout {
        async fn revoke_by_sid(&self, _sid: &str) -> Result<(), crate::port::LogoutPortError> {
            Err(crate::port::LogoutPortError::Disabled(
                "OIDC front-channel logout disabled".into(),
            ))
        }
    }

    #[derive(Debug, Default)]
    struct StubSamlBackchannelLogout;
    #[async_trait]
    impl crate::port::SamlBackchannelLogoutPort for StubSamlBackchannelLogout {
        async fn process(
            &self,
            _tenant_id_hint: Option<&str>,
            _logout_request_xml: &str,
        ) -> Result<(), crate::port::LogoutPortError> {
            Err(crate::port::LogoutPortError::Disabled(
                "SAML back-channel logout disabled".into(),
            ))
        }
    }

    #[derive(Debug, Default)]
    struct StubOidcDiscovery;
    #[async_trait]
    impl crate::port::OidcDiscoveryPort for StubOidcDiscovery {
        async fn document(&self) -> Result<serde_json::Value, crate::port::LogoutPortError> {
            Ok(serde_json::json!({
                "issuer": "https://sx.example.com",
                "backchannel_logout_supported": true,
                "frontchannel_logout_supported": true,
            }))
        }
    }

    #[derive(Debug, Default)]
    struct StubGrc;
    #[async_trait]
    impl crate::port::GrcPort for StubGrc {
        async fn upsert_config(
            &self,
            tenant_id: &str,
            req: crate::view::grc_view::GrcConfigUpsertRequest,
        ) -> Result<crate::view::grc_view::GrcConfigView, crate::port::GrcPortError> {
            Ok(crate::view::grc_view::GrcConfigView {
                tenant_id: tenant_id.to_owned(),
                kind: req.kind,
                instance_url: req.instance_url,
                user: req.user,
                secret_path: format!("tenants/{tenant_id}/grc/stub/secret"),
                created_at: "2027-01-01T00:00:00Z".into(),
            })
        }
        async fn list_configs(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<crate::view::grc_view::GrcConfigView>, crate::port::GrcPortError> {
            Ok(Vec::new())
        }
        async fn test_connection(
            &self,
            _tenant_id: &str,
            kind: &str,
        ) -> Result<crate::view::grc_view::GrcConnectionTestView, crate::port::GrcPortError>
        {
            Ok(crate::view::grc_view::GrcConnectionTestView {
                kind: kind.to_owned(),
                ok: true,
                error_code: None,
            })
        }
        async fn push(
            &self,
            _tenant_id: &str,
            req: crate::view::grc_view::GrcPushRequest,
        ) -> Result<crate::view::grc_view::GrcPushOutcomeView, crate::port::GrcPortError> {
            let source_ref = match req.resource {
                crate::view::grc_view::GrcPushResource::Evidence => req
                    .evidence
                    .as_ref()
                    .map(|e| e.id.clone())
                    .unwrap_or_default(),
                crate::view::grc_view::GrcPushResource::Finding => req
                    .finding
                    .as_ref()
                    .map(|f| f.id.clone())
                    .unwrap_or_default(),
            };
            Ok(crate::view::grc_view::GrcPushOutcomeView {
                kind: req.kind,
                resource: req.resource.as_wire().to_owned(),
                source_ref,
                upstream_id: None,
                url: None,
            })
        }
    }

    #[derive(Debug, Default)]
    struct StubPlugins;
    #[async_trait]
    impl crate::port::PluginsPort for StubPlugins {
        async fn list(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<sx_plugins::RegisteredPlugin>, crate::port::PluginsPortError> {
            Ok(Vec::new())
        }
        async fn install(
            &self,
            tenant_id: &str,
            manifest: sx_plugins::PluginManifest,
            _secret: secrecy::SecretString,
        ) -> Result<sx_plugins::RegisteredPlugin, crate::port::PluginsPortError> {
            Ok(sx_plugins::RegisteredPlugin {
                id: sx_plugins::PluginId::new(),
                tenant_id: tenant_id.to_owned(),
                name: manifest.name,
                vendor: manifest.vendor,
                version: manifest.version,
                webhook_url: manifest.webhook_url,
                supported_events: manifest.supported_events,
                required_scopes: manifest.required_scopes,
                enabled: true,
                registered_at: "1970-01-01T00:00:00Z".to_owned(),
            })
        }
        async fn uninstall(
            &self,
            _tenant_id: &str,
            _plugin_id: sx_plugins::PluginId,
        ) -> Result<(), crate::port::PluginsPortError> {
            Ok(())
        }
        async fn list_dispatches(
            &self,
            _tenant_id: &str,
            _plugin_id: sx_plugins::PluginId,
            _limit: usize,
        ) -> Result<Vec<sx_plugins::DispatchRecord>, crate::port::PluginsPortError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug, Default)]
    struct StubIr;
    #[async_trait]
    impl crate::port::IrPlaybooksPort for StubIr {
        async fn list_playbooks(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::ir_view::ListPlaybooksResponse, crate::port::IrPlaybookPortError>
        {
            Ok(crate::view::ir_view::ListPlaybooksResponse { items: Vec::new() })
        }
        async fn open_incident(
            &self,
            tenant_id: &str,
            _actor: &str,
            playbook_id: &str,
            title: &str,
            severity: Option<&str>,
        ) -> Result<crate::view::ir_view::IncidentView, crate::port::IrPlaybookPortError> {
            Ok(crate::view::ir_view::IncidentView {
                id: "00000000-0000-0000-0000-000000000000".to_owned(),
                tenant_id: tenant_id.to_owned(),
                playbook_id: playbook_id.to_owned(),
                state: "open".to_owned(),
                title: title.to_owned(),
                severity: severity.map(str::to_owned),
                steps: Vec::new(),
                audit: Vec::new(),
                opened_at: "2026-01-01T00:00:00Z".to_owned(),
                updated_at: "2026-01-01T00:00:00Z".to_owned(),
            })
        }
        async fn get_incident(
            &self,
            _tenant_id: &str,
            _incident_id: &str,
        ) -> Result<crate::view::ir_view::IncidentView, crate::port::IrPlaybookPortError> {
            Err(crate::port::IrPlaybookPortError::NotFound)
        }
        async fn update_step(
            &self,
            _tenant_id: &str,
            _actor: &str,
            _incident_id: &str,
            _step_id: &str,
            _status: Option<&str>,
            _owner: Option<&str>,
            _reason: Option<&str>,
            _evidence: Option<&str>,
        ) -> Result<crate::view::ir_view::IncidentView, crate::port::IrPlaybookPortError> {
            Err(crate::port::IrPlaybookPortError::NotFound)
        }
    }

    #[derive(Debug, Default)]
    struct StubCloudDrift;
    #[async_trait]
    impl crate::port::CloudDriftPort for StubCloudDrift {
        async fn upload_baseline(
            &self,
            _tenant_id: &str,
            name: &str,
            format: &str,
            _payload: Vec<u8>,
        ) -> Result<
            crate::view::cloud_drift_view::UploadBaselineResponse,
            crate::port::CloudDriftPortError,
        > {
            Ok(crate::view::cloud_drift_view::UploadBaselineResponse {
                id: "00000000-0000-0000-0000-000000000000".to_owned(),
                name: name.to_owned(),
                format: format.to_owned(),
                resource_count: 0,
            })
        }
        async fn list_baselines(
            &self,
            _tenant_id: &str,
        ) -> Result<
            crate::view::cloud_drift_view::ListBaselinesResponse,
            crate::port::CloudDriftPortError,
        > {
            Ok(crate::view::cloud_drift_view::ListBaselinesResponse { items: Vec::new() })
        }
        async fn scan(
            &self,
            _tenant_id: &str,
            _engagement_id: &str,
            baseline_id: Option<&str>,
        ) -> Result<
            crate::view::cloud_drift_view::DriftScanResponse,
            crate::port::CloudDriftPortError,
        > {
            Ok(crate::view::cloud_drift_view::DriftScanResponse {
                baseline_id: baseline_id
                    .unwrap_or("00000000-0000-0000-0000-000000000000")
                    .to_owned(),
                entries: Vec::new(),
            })
        }
        async fn list_drift(
            &self,
            _tenant_id: &str,
            _asset_filter: Option<&str>,
        ) -> Result<
            crate::view::cloud_drift_view::DriftListResponse,
            crate::port::CloudDriftPortError,
        > {
            Ok(crate::view::cloud_drift_view::DriftListResponse { items: Vec::new() })
        }
    }

    fn make_runtime_falco_stub() -> sx_runtime::FalcoIngestService {
        use sx_runtime::{NullAuditSink, TenantKeyStore};
        let provider: Arc<dyn sx_secrets::SecretsProvider> =
            Arc::new(sx_secrets::InMemoryProvider::new());
        let store = TenantKeyStore::new(provider);
        sx_runtime::FalcoIngestService::new(store, Arc::new(NullAuditSink))
    }

    /// HIGH-009 — admission webhook port stub. Uses the in-process
    /// engine + a permissive empty rule pack so router tests that
    /// hit `/v1/runtime/k8s/admit` always see `allowed=true`.
    #[derive(Debug)]
    struct StubK8sAdmission {
        engine: sx_discovery::k8s_admission::AdmissionEngine,
    }

    impl StubK8sAdmission {
        fn new() -> Self {
            use sx_discovery::k8s_admission::{
                AdmissionEngine, InMemoryTenantRulePolicy, NullK8sAdmissionAuditSink,
            };
            let policy = Arc::new(InMemoryTenantRulePolicy::new());
            let audit = Arc::new(NullK8sAdmissionAuditSink);
            Self {
                engine: AdmissionEngine::new(policy, audit),
            }
        }
    }

    #[async_trait]
    impl crate::port::K8sAdmissionPort for StubK8sAdmission {
        async fn admit(
            &self,
            tenant_id: &str,
            review: sx_discovery::k8s_admission::AdmissionReview,
        ) -> Result<sx_discovery::k8s_admission::AdmissionReview, crate::port::K8sAdmissionPortError>
        {
            self.engine
                .evaluate(tenant_id, review)
                .await
                .map_err(|e| crate::port::K8sAdmissionPortError::Invalid(e.to_string()))
        }

        async fn get_policy(
            &self,
            _tenant_id: &str,
        ) -> Result<
            crate::view::k8s_admission_view::K8sAdmissionPolicyView,
            crate::port::K8sAdmissionPortError,
        > {
            Ok(crate::view::k8s_admission_view::K8sAdmissionPolicyView {
                pss_profile: None,
                no_privileged: false,
                no_host_network: false,
                no_latest_tag: false,
                mandatory_labels: Vec::new(),
                namespace_optouts: Vec::new(),
                dry_run: false,
            })
        }

        async fn set_policy(
            &self,
            _tenant_id: &str,
            policy: crate::view::k8s_admission_view::K8sAdmissionPolicyView,
        ) -> Result<
            crate::view::k8s_admission_view::K8sAdmissionPolicyView,
            crate::port::K8sAdmissionPortError,
        > {
            Ok(policy)
        }
    }

    /// Empty in-memory stub for [`crate::port::RuntimeFalcoOverridesPort`]
    /// — every method returns an empty/no-op result so router unit
    /// tests can mount the route surface without wiring a real adapter.
    #[derive(Debug, Default)]
    struct StubRuntimeFalcoOverrides;

    #[async_trait]
    impl crate::port::RuntimeFalcoOverridesPort for StubRuntimeFalcoOverrides {
        async fn list(
            &self,
            _tenant_id: &str,
        ) -> Result<
            crate::view::runtime_view::FalcoOverrideListResponse,
            crate::port::RuntimeOverridesPortError,
        > {
            Ok(crate::view::runtime_view::FalcoOverrideListResponse { rows: Vec::new() })
        }

        async fn upsert(
            &self,
            _tenant_id: &str,
            actor: &str,
            req: crate::view::runtime_view::PutFalcoOverrideRequest,
        ) -> Result<
            crate::view::runtime_view::FalcoOverrideView,
            crate::port::RuntimeOverridesPortError,
        > {
            Ok(crate::view::runtime_view::FalcoOverrideView {
                rule_name: req.rule_name,
                subkey: req.subkey,
                action: req.action,
                reason: req.reason,
                set_by: actor.to_owned(),
                set_at: "1970-01-01T00:00:00Z".to_owned(),
            })
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _actor: &str,
            _req: crate::view::runtime_view::DeleteFalcoOverrideRequest,
        ) -> Result<
            crate::view::runtime_view::DeleteFalcoOverrideResponse,
            crate::port::RuntimeOverridesPortError,
        > {
            Ok(crate::view::runtime_view::DeleteFalcoOverrideResponse { removed: false })
        }
    }

    /// MED-004 — empty `OidcClientTokenPort` stub. Every call rejects
    /// with `InvalidClient` so router-level tests can mount the route
    /// without wiring a real adapter.
    #[derive(Debug, Default)]
    struct StubOidcClientToken;

    #[async_trait]
    impl crate::port::OidcClientTokenPort for StubOidcClientToken {
        async fn issue(
            &self,
            _tenant_hint: Option<&str>,
            _req: crate::view::oidc_client_view::OAuthTokenRequest,
        ) -> Result<
            crate::view::oidc_client_view::OAuthTokenResponse,
            crate::port::OidcClientPortError,
        > {
            Err(crate::port::OidcClientPortError::InvalidClient)
        }
    }

    /// MED-004 — `OidcClientRotatePort` stub. Returns a deterministic
    /// shape so router-level tests can mount the route.
    #[derive(Debug, Default)]
    struct StubOidcClientRotate;

    #[async_trait]
    impl crate::port::OidcClientRotatePort for StubOidcClientRotate {
        async fn rotate(
            &self,
            _tenant_id: &str,
            client_id: &str,
            _actor: &str,
        ) -> Result<
            crate::view::oidc_client_view::RotateClientSecretResponse,
            crate::port::OidcClientPortError,
        > {
            Ok(crate::view::oidc_client_view::RotateClientSecretResponse {
                client_id: client_id.to_owned(),
                new_secret: "stub-secret".to_owned(),
                previous_expires_at: "1970-01-08T00:00:00Z".to_owned(),
                rotated_at: "1970-01-01T00:00:00Z".to_owned(),
            })
        }
    }

    /// MED-004 — `JwksPublishPort` stub. Returns an empty `keys` array
    /// so the route serves the canonical empty-JWKS shape during tests.
    #[derive(Debug, Default)]
    struct StubJwksPublish;

    #[async_trait]
    impl crate::port::JwksPublishPort for StubJwksPublish {
        async fn jwks(&self) -> Result<serde_json::Value, crate::port::OidcClientPortError> {
            Ok(serde_json::json!({ "keys": [] }))
        }
    }

    #[derive(Debug, Default)]
    struct StubApiDast;
    #[async_trait]
    impl crate::port::ApiDastPort for StubApiDast {
        async fn scan(
            &self,
            tenant_id: &str,
            _collection: &[u8],
            base_url: &str,
            _bearer: Option<secrecy::SecretString>,
            _idor_probe_ids: Vec<String>,
        ) -> Result<crate::port::ApiDastScanResultView, crate::port::ApiDastPortError> {
            Ok(crate::port::ApiDastScanResultView {
                scan_id: "00000000-0000-0000-0000-000000000000".to_owned(),
                tenant_id: tenant_id.to_owned(),
                collection_name: "stub".to_owned(),
                base_url: base_url.to_owned(),
                started_at: "1970-01-01T00:00:00Z".to_owned(),
                ended_at: "1970-01-01T00:00:00Z".to_owned(),
                requests_sent: 0,
                findings: Vec::new(),
            })
        }
        async fn list(
            &self,
            _tenant_id: &str,
            _limit: usize,
        ) -> Result<Vec<crate::port::ApiDastScanResultView>, crate::port::ApiDastPortError>
        {
            Ok(Vec::new())
        }
    }

    #[derive(Debug, Default)]
    struct StubBugBounty;
    #[async_trait]
    impl crate::port::BugBountyPort for StubBugBounty {
        async fn upsert_config(
            &self,
            tenant_id: &str,
            req: crate::view::bugbounty_view::BugBountyConfigUpsertRequest,
        ) -> Result<crate::view::bugbounty_view::BugBountyConfigView, crate::port::BugBountyPortError>
        {
            Ok(crate::view::bugbounty_view::BugBountyConfigView {
                tenant_id: tenant_id.to_owned(),
                platform: req.platform.clone(),
                program_handle: req.program_handle.clone(),
                api_username: req.api_username.clone(),
                token_secret_path: format!(
                    "tenants/{tenant_id}/bb/{}/{}/token",
                    req.platform, req.program_handle
                ),
                webhook_secret_path: format!(
                    "tenants/{tenant_id}/bb/{}/{}/webhook",
                    req.platform, req.program_handle
                ),
                created_at: "2027-01-01T00:00:00Z".into(),
            })
        }
        async fn list_configs(
            &self,
            _tenant_id: &str,
        ) -> Result<
            Vec<crate::view::bugbounty_view::BugBountyConfigView>,
            crate::port::BugBountyPortError,
        > {
            Ok(Vec::new())
        }
        async fn push(
            &self,
            _tenant_id: &str,
            req: crate::view::bugbounty_view::BugBountyPushRequest,
        ) -> Result<
            crate::view::bugbounty_view::BugBountyPushOutcomeView,
            crate::port::BugBountyPortError,
        > {
            Ok(crate::view::bugbounty_view::BugBountyPushOutcomeView {
                platform: req.platform,
                source_ref: req.finding.id,
                upstream_id: None,
                url: None,
            })
        }
        async fn inbound(
            &self,
            _tenant_id: &str,
            platform: &str,
            _signature_header: Option<&str>,
            _body_bytes: axum::body::Bytes,
        ) -> Result<
            crate::view::bugbounty_view::BugBountyInboundOutcomeView,
            crate::port::BugBountyPortError,
        > {
            Ok(crate::view::bugbounty_view::BugBountyInboundOutcomeView {
                platform: platform.to_owned(),
                source: format!("bugbounty.{platform}.researcher_stub"),
                researcher_id: "stub".to_owned(),
                report_id: "stub".to_owned(),
                deduplicated: false,
                dedup_existing_id: None,
            })
        }
    }

    #[derive(Debug, Default)]
    struct StubHunt;
    #[async_trait]
    impl crate::port::HuntPort for StubHunt {
        async fn query(
            &self,
            _tenant_id: &str,
            _user_id: &str,
            _raw_query: &str,
        ) -> Result<crate::view::hunt_view::HuntQueryResponse, crate::port::HuntPortError> {
            #[allow(clippy::literal_string_with_formatting_args)] // ClickHouse parameter placeholder, not Rust format
            let compiled_sql = "SELECT * FROM events_raw WHERE tenant_id = {tenant:String} LIMIT 10000 FORMAT JSONEachRow".to_owned();
            Ok(crate::view::hunt_view::HuntQueryResponse {
                rows: Vec::new(),
                compiled_sql,
                table: "events_raw".to_owned(),
                row_count: 0,
            })
        }
    }

    #[derive(Debug, Default)]
    struct StubAiAudit;
    #[async_trait]
    impl crate::port::AiAuditPort for StubAiAudit {
        async fn list_assets(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::ai_audit_view::AiAssetListResponse, crate::port::AiAuditPortError>
        {
            Ok(crate::view::ai_audit_view::AiAssetListResponse { assets: Vec::new() })
        }

        async fn aibom(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::ai_audit_view::AiBomView, crate::port::AiAuditPortError> {
            Ok(crate::view::ai_audit_view::AiBomView {
                bom_format: "CycloneDX".to_owned(),
                spec_version: "1.6".to_owned(),
                version: 1,
                components: Vec::new(),
            })
        }

        async fn list_controls(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::view::ai_audit_view::AiControlListResponse, crate::port::AiAuditPortError>
        {
            Ok(crate::view::ai_audit_view::AiControlListResponse {
                controls: Vec::new(),
            })
        }

        async fn run_audit(
            &self,
            _tenant_id: &str,
            _actor: &str,
        ) -> Result<crate::view::ai_audit_view::AiAuditReportView, crate::port::AiAuditPortError>
        {
            Ok(crate::view::ai_audit_view::AiAuditReportView {
                assets: Vec::new(),
                aibom: crate::view::ai_audit_view::AiBomView {
                    bom_format: "CycloneDX".to_owned(),
                    spec_version: "1.6".to_owned(),
                    version: 1,
                    components: Vec::new(),
                },
                probe_results: Vec::new(),
                modelfile_findings: Vec::new(),
                control_evidence: Vec::new(),
            })
        }

        async fn run_external_audit(
            &self,
            _tenant_id: &str,
            _actor: &str,
            _engagement_id: &str,
            _target_id: &str,
        ) -> Result<crate::view::ai_audit_view::AiAuditReportView, crate::port::AiAuditPortError>
        {
            Ok(crate::view::ai_audit_view::AiAuditReportView {
                assets: Vec::new(),
                aibom: crate::view::ai_audit_view::AiBomView {
                    bom_format: "CycloneDX".to_owned(),
                    spec_version: "1.6".to_owned(),
                    version: 1,
                    components: Vec::new(),
                },
                probe_results: Vec::new(),
                modelfile_findings: Vec::new(),
                control_evidence: Vec::new(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct StubPentest;
    #[async_trait]
    impl crate::port::PentestPort for StubPentest {
        async fn run(
            &self,
            tenant_id: &str,
            actor: &str,
            request: crate::view::pentest_view::PentestRunRequestDto,
        ) -> Result<crate::view::pentest_view::PentestRunView, crate::port::PentestPortError>
        {
            Ok(crate::view::pentest_view::PentestRunView {
                id: "stub-run".to_owned(),
                tenant_id: tenant_id.to_owned(),
                engagement_id: request.engagement_id,
                name: request.name,
                actor: actor.to_owned(),
                status: "completed".to_owned(),
                started_at: "1970-01-01T00:00:00Z".to_owned(),
                finished_at: Some("1970-01-01T00:00:01Z".to_owned()),
                phases: Vec::new(),
                findings: Vec::new(),
                narratives: Vec::new(),
                finding_count: 0,
                validated_count: 0,
                report: None,
            })
        }
        async fn get_run(
            &self,
            _tenant_id: &str,
            _run_id: &str,
        ) -> Result<crate::view::pentest_view::PentestRunView, crate::port::PentestPortError>
        {
            Err(crate::port::PentestPortError::NotFound)
        }
        async fn list_runs(
            &self,
            _tenant_id: &str,
            _limit: usize,
        ) -> Result<
            Vec<crate::view::pentest_view::PentestRunSummaryView>,
            crate::port::PentestPortError,
        > {
            Ok(Vec::new())
        }
    }

    // Nav-gap-fix stubs (return empty rows so the routes are reachable
    // but the data plane stays inert in router-level tests).

    #[derive(Debug, Default)]
    struct StubAdminUserList;
    #[async_trait]
    impl crate::port::AdminUserListPort for StubAdminUserList {}

    #[derive(Debug, Default)]
    struct StubIntelFeedStatus;
    #[async_trait]
    impl crate::port::IntelFeedStatusPort for StubIntelFeedStatus {}

    #[derive(Debug, Default)]
    struct StubDeviceRegistry;
    #[async_trait]
    impl crate::port::DeviceRegistryPort for StubDeviceRegistry {}

    /// CRIT-003 — DEK rotation admin stub. The router-level test state
    /// uses the trait's default `Invalid` / `NotFound` surfaces so the
    /// routes are reachable but the data plane stays inert. The real
    /// adapter lives in `sx-monolith::adapters::secrets_admin`.
    #[derive(Debug, Default)]
    struct StubDekRotationAdmin;
    #[async_trait]
    impl crate::port::DekRotationAdminPort for StubDekRotationAdmin {}

    /// MED-003 — webhook key rotation admin stub. The router-level test
    /// state uses the trait's default `Disabled` surface so the route is
    /// reachable but the data plane stays inert. The real adapter lives
    /// in `sx-monolith::adapters::webhooks_admin`.
    #[derive(Debug, Default)]
    struct StubWebhookKeyRotationAdmin;
    #[async_trait]
    impl crate::port::WebhookKeyRotationAdminPort for StubWebhookKeyRotationAdmin {}

    /// Audit-anchor stub returning empty rows. Added here because the
    /// router-level test state stub predates P1-015 and the field was
    /// not back-filled when the trait landed.
    #[derive(Debug, Default)]
    struct StubAuditAnchor;
    #[async_trait]
    impl crate::port::AuditAnchorPort for StubAuditAnchor {
        async fn list(
            &self,
            _tenant_id: &str,
            _query: crate::view::audit_anchor_view::AuditAnchorListQuery,
        ) -> Result<
            crate::view::audit_anchor_view::AuditAnchorListResponse,
            crate::port::Phase3PortError,
        > {
            Ok(crate::view::audit_anchor_view::AuditAnchorListResponse {
                items: Vec::new(),
                has_more: false,
            })
        }
        async fn verify(
            &self,
            _tenant_id: &str,
            _run_id: &str,
        ) -> Result<
            crate::view::audit_anchor_view::AuditAnchorVerifyResponse,
            crate::port::Phase3PortError,
        > {
            Err(crate::port::Phase3PortError::NotFound)
        }
    }

    fn make_state(accept_token: bool) -> AppState {
        make_state_with_oidc(accept_token, true, &[])
    }

    /// Build router state whose accepted bearer carries `perms` — used by
    /// success-path tests for endpoints now gated by `require_permission`.
    fn make_state_with_perms(perms: &[&str]) -> AppState {
        make_state_with_oidc(true, true, perms)
    }

    fn make_state_with_oidc(accept_token: bool, accept_oidc: bool, perms: &[&str]) -> AppState {
        AppState {
            readiness: Arc::new(crate::port::AlwaysReady),
            authn: Arc::new(StubAuthn),
            token_validator: Arc::new(StubValidator {
                accept: accept_token,
                permissions: perms.iter().map(|s| (*s).to_owned()).collect(),
            }),
            refresh: Arc::new(StubRefresh),
            logout: Arc::new(StubLogout),
            oidc_exchange: Arc::new(StubOidcExchange {
                accept: accept_oidc,
            }),
            oidc_rp_logout: Arc::new(StubOidcRpLogout),
            oidc_backchannel_logout: Arc::new(StubOidcBackchannelLogout),
            oidc_frontchannel_logout: Arc::new(StubOidcFrontchannelLogout),
            oidc_discovery: Arc::new(StubOidcDiscovery),
            saml_backchannel_logout: Arc::new(StubSamlBackchannelLogout),
            engagements: Arc::new(StubEngagements),
            kill_switch: Arc::new(StubKillSwitch),
            risk: Arc::new(StubRisk),
            risk_tuning: Arc::new(StubRiskTuning),
            discovery: Arc::new(StubDiscovery),
            assets: Arc::new(StubAssets),
            findings: Arc::new(StubFindings),
            tenants: Arc::new(StubTenants),
            bas: Arc::new(StubBas),
            bas_history: Arc::new(StubBasHistory),
            bas_chain: Arc::new(StubBasChain),
            http_header_scanner: Arc::new(StubHttpHeaderScanner),
            approvals: Arc::new(StubApprovals),
            graph: Arc::new(StubGraph),
            blast_radius: Arc::new(StubBlastRadius),
            report: Arc::new(StubReport),
            branding: Arc::new(StubBranding),
            report_schedules: Arc::new(StubReportSchedule),
            comprehensive_report: Arc::new(StubComprehensiveReport),
            report_diff: Arc::new(StubReportDiff),
            remediation: Arc::new(StubRemediation),
            compliance: Arc::new(StubCompliance),
            compliance_evidence: Arc::new(StubComplianceEvidence),
            ml: Arc::new(StubMl),
            cloud_inventory: Arc::new(StubCloudInventory),
            propose_pr: Arc::new(StubProposePr),
            submit_threat: Arc::new(StubSubmitThreat),
            schedule_validation: Arc::new(StubScheduleValidation),
            collab_alloc: Arc::new(StubCollabAlloc),
            collab_lookup: Arc::new(StubCollabLookup),
            create_user: Arc::new(StubCreateUser),
            customer_auth: Arc::new(StubCustomerAuth),
            soc: Arc::new(StubSoc),
            twin: Arc::new(StubTwin),
            intel_check: Arc::new(StubIntelCheck),
            predictive: Arc::new(StubPredictive),
            redteam: Arc::new(StubRedteam),
            copilot: Arc::new(StubCopilot),
            copilot_approval: Arc::new(StubCopilotApproval),
            engagement_transitions: Arc::new(StubEngagementTransitions),
            engagement_clone: Arc::new(StubEngagementClone),
            roles: Arc::new(StubRoles),
            asset_write: Arc::new(StubAssetWrite),
            asset_bulk: Arc::new(StubAssetBulk),
            finding_bulk: Arc::new(StubFindingBulk),
            tenant_write: Arc::new(StubTenantWrite),
            audit_query: Arc::new(StubAuditQuery),
            audit_replay: Arc::new(StubAuditReplay),
            remediation_tracking: Arc::new(StubRemediationTracking),
            mfa: Arc::new(StubMfa),
            webauthn: Arc::new(StubWebauthn),
            log_ingest: Arc::new(StubLogIngest),
            log_rate_limit: Arc::new(StubLogRateLimit),
            vuln_ingest: Arc::new(StubVulnIngest),
            prowler_import: Arc::new(StubProwlerImport),
            scim: Arc::new(StubScim::new()),
            rba: Arc::new(StubRba),
            remediation_outcomes: Arc::new(StubRemediationOutcomes),
            ueba: Arc::new(StubUeba),
            ueba_admin: Arc::new(StubUebaAdmin),
            soar: Arc::new(StubSoar),
            device_trust: Arc::new(StubDeviceTrust),
            saml_sp: Arc::new(StubSamlSp),
            saml_idp_admin: Arc::new(StubSamlIdpAdmin),
            dlp: Arc::new(StubDlp),
            grc: Arc::new(StubGrc),
            plugins: Arc::new(StubPlugins),
            cloud_drift: Arc::new(StubCloudDrift),
            ir: Arc::new(StubIr),
            runtime_falco: Arc::new(make_runtime_falco_stub()),
            k8s_admission: Arc::new(StubK8sAdmission::new()),
            runtime_falco_overrides: Arc::new(StubRuntimeFalcoOverrides),
            oidc_client_token: Arc::new(StubOidcClientToken),
            oidc_client_rotate: Arc::new(StubOidcClientRotate),
            jwks_publish: Arc::new(StubJwksPublish),
            api_dast: Arc::new(StubApiDast),
            bugbounty: Arc::new(StubBugBounty),
            hunt: Arc::new(StubHunt),
            ai_audit: Arc::new(StubAiAudit),
            pentest: Arc::new(StubPentest),
            graphsage_risk: Arc::new(StubGraphsageRisk),
            admin_user_list: Arc::new(StubAdminUserList),
            intel_feed_status: Arc::new(StubIntelFeedStatus),
            device_registry: Arc::new(StubDeviceRegistry),
            audit_anchor: Arc::new(StubAuditAnchor),
            dek_rotation_admin: Arc::new(StubDekRotationAdmin),
            webhook_key_rotation_admin: Arc::new(StubWebhookKeyRotationAdmin),
            chaos: Arc::new(sx_chaos::ChaosRegistry::disabled()),
            chaos_admin: sx_chaos::admin::ChaosAdminService::new(
                Arc::new(sx_chaos::ChaosRegistry::disabled()),
                Arc::new(sx_chaos::admin::InMemoryChaosAuditSink::new()),
            ),
            server_cfg: Arc::new(ServerConfig {
                bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                shutdown_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(10),
                max_body_bytes: 1_048_576,
                rate_limit: sx_config::schema::server::RateLimitConfig {
                    limit_per_minute: 6_000,
                    burst: 1_000,
                    enabled: false,
                },
            }),
            rate_limit_cfg: Arc::new(RateLimitConfig {
                limit_per_minute: 6_000,
                burst: 1_000,
                enabled: false,
            }),
            rate_limiter: Arc::new(RateLimiterState::new()),
            // TOP5-#3 Phase 3 — safe default so router tests exercise the
            // production `AppState` shape.
            release_channel_cfg: Arc::new(
                sx_config::schema::release_channel::ReleaseChannelConfig::default(),
            ),
        }
    }

    #[tokio::test]
    async fn healthz_is_unauthenticated() {
        let router = build_router(make_state(false));
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/v1/nope")
            .header("authorization", "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn request_id_propagated_when_present() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/healthz")
            .header("x-request-id", "deadbeefdeadbeefdeadbeefdeadbeef")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        let echoed = res.headers().get("x-request-id").unwrap().to_str().unwrap();
        assert_eq!(echoed, "deadbeefdeadbeefdeadbeefdeadbeef");
    }

    #[tokio::test]
    async fn request_id_injected_when_absent() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        let injected = res.headers().get("x-request-id").unwrap().to_str().unwrap();
        assert_eq!(injected.len(), 32);
    }

    #[tokio::test]
    async fn auth_required_returns_unauthorized_without_bearer() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/v1/engagements")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exchange_oidc_returns_400_on_invalid_body() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/oidc/exchange")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        // Validation rejects the missing `id_token` field — 400 Bad Request.
        assert!(
            res.status() == StatusCode::BAD_REQUEST
                || res.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "expected 400 or 422 for invalid body, got {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn exchange_oidc_returns_401_on_verify_failure() {
        let router = build_router(make_state_with_oidc(true, false, &[]));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/oidc/exchange")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id_token":"not-a-real-token"}"#))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        // Phase3PortError::Forbidden maps to 403 Forbidden in the API.
        // OidcExchangePort.exchange rejecting the token surfaces here.
        assert!(
            res.status() == StatusCode::FORBIDDEN || res.status() == StatusCode::UNAUTHORIZED,
            "expected 401/403 for verify failure, got {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn exchange_oidc_returns_200_on_accept() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/oidc/exchange")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"id_token":"any-non-empty"}"#))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn blast_radius_rejects_invalid_body() {
        let router = build_router(make_state_with_perms(&["graph:read"]));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/cloud/blast-radius")
            .header("authorization", "Bearer x")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        // Missing required fields → 400 or 422.
        assert!(
            res.status() == StatusCode::BAD_REQUEST
                || res.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "expected 400/422 for empty body, got {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn blast_radius_rejects_excessive_depth() {
        let router = build_router(make_state_with_perms(&["graph:read"]));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/cloud/blast-radius")
            .header("authorization", "Bearer x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"seed_asset_id":"a1","max_depth":6}"#))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert!(
            res.status() == StatusCode::BAD_REQUEST
                || res.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "depth above MAX must be rejected, got {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn blast_radius_returns_structured_response() {
        let router = build_router(make_state_with_perms(&["graph:read"]));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/cloud/blast-radius")
            .header("authorization", "Bearer x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"seed_asset_id":"asset-1","max_depth":3}"#))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "expected 200 OK");
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"]["seed_asset_id"], "asset-1");
        assert_eq!(v["data"]["max_depth"], 3);
        assert!(v["data"]["impacted"].is_array());
        assert!(v["data"]["decay_base"].as_f64().is_some());
        assert!(v["data"]["total_score"].as_f64().is_some());
        assert_eq!(v["data"]["cached"], false);
    }

    #[tokio::test]
    async fn blast_radius_requires_auth() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/cloud/blast-radius")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"seed_asset_id":"a","max_depth":1}"#))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn remediation_outcomes_metrics_returns_envelope_with_window() {
        let router = build_router(make_state_with_perms(&["remediation:read"]));
        let req = Request::builder()
            .uri("/v1/remediation/outcomes/metrics?window_days=7")
            .header("authorization", "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"]["window_seconds"], 7 * 86_400);
        assert_eq!(v["data"]["closure_count"], 0);
    }

    #[tokio::test]
    async fn remediation_outcomes_metrics_defaults_window_when_absent() {
        let router = build_router(make_state_with_perms(&["remediation:read"]));
        let req = Request::builder()
            .uri("/v1/remediation/outcomes/metrics")
            .header("authorization", "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"]["window_seconds"], 30 * 86_400);
    }

    #[tokio::test]
    async fn remediation_outcomes_regressions_returns_empty_items_envelope() {
        let router = build_router(make_state_with_perms(&["remediation:read"]));
        let req = Request::builder()
            .uri("/v1/remediation/outcomes/regressions?limit=10")
            .header("authorization", "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["data"]["items"].is_array());
        assert_eq!(v["data"]["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn remediation_outcomes_metrics_requires_auth() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/v1/remediation/outcomes/metrics")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn json_envelope_carries_request_id_after_middleware() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/healthz")
            .header("x-request-id", "1234567890abcdef1234567890abcdef")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["meta"]["request_id"], "1234567890abcdef1234567890abcdef");
        assert_eq!(v["data"]["status"], "ok");
    }

    #[tokio::test]
    async fn logs_ingest_requires_auth() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/logs/ingest")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"source":"cloudtrail","payload":"{}"}"#))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logs_list_requires_auth() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/v1/logs?limit=10")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // ------------------------------------------------------------------
    // SCIM 2.0 (P0-005) integration coverage
    // ------------------------------------------------------------------

    const SCIM_BEARER: &str = "scim_test_bearer";

    fn scim_req(method: &str, path: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path).header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {SCIM_BEARER}"),
        );
        if body.is_some() {
            b = b.header(axum::http::header::CONTENT_TYPE, "application/json");
        }
        let body = match body {
            Some(v) => Body::from(serde_json::to_vec(&v).unwrap()),
            None => Body::empty(),
        };
        b.body(body).unwrap()
    }

    async fn read_scim_body(res: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
        if bytes.is_empty() {
            return serde_json::json!({});
        }
        serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}))
    }

    #[tokio::test]
    async fn scim_create_user_returns_201_with_scim_content_type() {
        let router = build_router(make_state(true));
        let req = scim_req(
            "POST",
            "/scim/v2/Users",
            Some(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "alice@example.com",
            })),
        );
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let ct = res
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            ct.starts_with("application/scim+json"),
            "Content-Type was {ct}",
        );
        let body = read_scim_body(res).await;
        assert_eq!(body["userName"], "alice@example.com");
        assert!(body["id"].is_string());
        assert!(body["schemas"].is_array());
    }

    #[tokio::test]
    async fn scim_missing_bearer_returns_scim_error_envelope() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("GET")
            .uri("/scim/v2/Users")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = read_scim_body(res).await;
        assert_eq!(
            body["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:Error"
        );
        assert_eq!(body["status"], "401");
    }

    #[tokio::test]
    async fn scim_wrong_bearer_returns_401() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("GET")
            .uri("/scim/v2/Users")
            .header(axum::http::header::AUTHORIZATION, "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logs_ingest_with_bearer_but_no_perm_returns_403() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/logs/ingest")
            .header("authorization", "Bearer x")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"source":"cloudtrail","payload":"{}"}"#))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn logs_list_with_bearer_but_no_perm_returns_403() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/v1/logs?limit=10")
            .header("authorization", "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn vuln_imports_route_requires_auth() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/v1/vuln/imports")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn vuln_import_route_requires_auth() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("POST")
            .uri("/v1/vuln/import")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn vuln_imports_get_forbids_caller_without_permission() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .uri("/v1/vuln/imports")
            .header("authorization", "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn scim_full_user_crud_round_trip() {
        let router = build_router(make_state(true));

        // CREATE
        let res = router
            .clone()
            .oneshot(scim_req(
                "POST",
                "/scim/v2/Users",
                Some(serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "bob",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = read_scim_body(res).await;
        let id = created["id"].as_str().unwrap().to_owned();

        // GET
        let res = router
            .clone()
            .oneshot(scim_req("GET", &format!("/scim/v2/Users/{id}"), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let got = read_scim_body(res).await;
        assert_eq!(got["userName"], "bob");

        // PUT
        let res = router
            .clone()
            .oneshot(scim_req(
                "PUT",
                &format!("/scim/v2/Users/{id}"),
                Some(serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "bob",
                    "displayName": "Robert",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let updated = read_scim_body(res).await;
        assert_eq!(updated["displayName"], "Robert");

        // DELETE — soft delete via `active = false`
        let res = router
            .clone()
            .oneshot(scim_req("DELETE", &format!("/scim/v2/Users/{id}"), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // GET after delete should still return the resource with `active = false`.
        let res = router
            .oneshot(scim_req("GET", &format!("/scim/v2/Users/{id}"), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let after = read_scim_body(res).await;
        assert_eq!(after["active"], false);
    }

    #[tokio::test]
    async fn scim_list_users_with_filter_returns_envelope() {
        let router = build_router(make_state(true));
        for name in ["alice", "bob", "carol"] {
            let res = router
                .clone()
                .oneshot(scim_req(
                    "POST",
                    "/scim/v2/Users",
                    Some(serde_json::json!({
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": name,
                    })),
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::CREATED);
        }
        let res = router
            .oneshot(scim_req(
                "GET",
                "/scim/v2/Users?filter=userName%20sw%20%22a%22",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = read_scim_body(res).await;
        assert_eq!(
            body["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        );
        assert_eq!(body["totalResults"], 1);
        assert_eq!(body["Resources"][0]["userName"], "alice");
    }

    #[tokio::test]
    async fn scim_duplicate_user_name_returns_409_uniqueness() {
        let router = build_router(make_state(true));
        let body = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice",
        });
        let r1 = router
            .clone()
            .oneshot(scim_req("POST", "/scim/v2/Users", Some(body.clone())))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::CREATED);
        let r2 = router
            .oneshot(scim_req("POST", "/scim/v2/Users", Some(body)))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::CONFLICT);
        let err = read_scim_body(r2).await;
        assert_eq!(err["scimType"], "uniqueness");
    }

    #[tokio::test]
    async fn scim_invalid_filter_returns_400_invalid_filter() {
        let router = build_router(make_state(true));
        let res = router
            .oneshot(scim_req("GET", "/scim/v2/Users?filter=not+a+filter", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = read_scim_body(res).await;
        assert_eq!(body["scimType"], "invalidFilter");
    }

    #[tokio::test]
    async fn scim_group_crud_round_trip() {
        let router = build_router(make_state(true));
        let res = router
            .clone()
            .oneshot(scim_req(
                "POST",
                "/scim/v2/Groups",
                Some(serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "displayName": "engineers",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let g = read_scim_body(res).await;
        let id = g["id"].as_str().unwrap().to_owned();

        let res = router
            .clone()
            .oneshot(scim_req("GET", &format!("/scim/v2/Groups/{id}"), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(read_scim_body(res).await["displayName"], "engineers");

        // GET /scim/v2/Groups list envelope
        let res = router
            .oneshot(scim_req("GET", "/scim/v2/Groups", None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let env = read_scim_body(res).await;
        assert_eq!(env["totalResults"], 1);
        assert_eq!(
            env["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        );
    }

    // -----------------------------------------------------------------
    // Device-trust integration smoke tests (P2-008)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn device_trust_get_policy_returns_permissive_default() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("GET")
            .uri("/v1/device-trust/policy")
            .header(axum::http::header::AUTHORIZATION, "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Permissive policy ⇒ empty allow-list + empty rules array.
        assert_eq!(v["data"]["rules"], serde_json::json!([]));
        assert_eq!(v["data"]["os_allow_list"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn device_trust_put_policy_requires_admin_users_permission() {
        // The stub validator returns no permissions, so PUT must 403.
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("PUT")
            .uri("/v1/device-trust/policy")
            .header(axum::http::header::AUTHORIZATION, "Bearer x")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"os_allow_list":["macOS"],"os_block_list":[],"minimum_os_versions":{},"edr_vendor_allow_list":[],"max_screen_lock_minutes":15,"rules":["require_edr"]}"#,
            ))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn device_trust_list_sessions_empty_by_default() {
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("GET")
            .uri("/v1/device-trust/sessions")
            .header(axum::http::header::AUTHORIZATION, "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"]["items"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn missing_posture_header_does_not_block_request() {
        // The middleware is pass-through: requests without
        // `X-Sentinelx-Device-Posture` should still hit the handler.
        let router = build_router(make_state(true));
        let req = Request::builder()
            .method("GET")
            .uri("/v1/device-trust/policy")
            .header(axum::http::header::AUTHORIZATION, "Bearer x")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
