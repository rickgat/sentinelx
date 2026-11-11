//! [`AppState`] — the bundle of trait objects every handler sees.
//!
//! `AppState` is `Clone` (cheap — every field is an `Arc`) so axum can pass
//! it by value to each handler. Concrete implementations are wired up at
//! the composition root (`services/sx-monolith`); the API layer only ever
//! sees the trait-object form.
//!
//! `RateLimiterState` is also held here so the rate-limit middleware can
//! be configured per [`crate::router::build_router`] invocation.

use std::sync::Arc;

use sx_config::schema::release_channel::ReleaseChannelConfig;
use sx_config::schema::server::ServerConfig;

use crate::middleware::rate_limit::{RateLimitConfig, RateLimiterState};
use crate::port::{
    AdminUserListPort, AiAuditPort, ApiDastPort, ApprovalPort, AssetBulkImportPort,
    AssetRepositoryPort, AssetWritePort, AuditAnchorPort, AuditQueryPort, AuditReplayPort,
    AuthenticateUserPort, BasChainPort, BasRunHistoryPort, BasRunPort, BlastRadiusPort,
    BrandingPort, BugBountyPort, CalculateRiskPort, CloudDriftPort, CloudInventoryPort,
    CollabAllocateTokenPort, CollabLookupCallbacksPort, ComplianceEvidencePort,
    ComplianceFrameworkPort, ComprehensiveReportPort, CopilotApprovalPort, CopilotPort,
    CreateUserPort, CustomerAuthPort, DekRotationAdminPort, DeviceRegistryPort, DeviceTrustPort,
    DlpPort, EngagementClonePort, EngagementServicePort, EngagementTransitionPort, FindingBulkPort,
    FindingRepositoryPort, GraphAttackPathsPort, GraphsageRiskPort, GrcPort, HuntPort,
    IntelCheckPort, IntelFeedStatusPort, IrPlaybooksPort, JwksPublishPort, K8sAdmissionPort,
    KillSwitchPort, LogIngestPort, LogRateLimitPort, LogoutPort, MfaPort, MlTriagePredictPort,
    OidcBackchannelLogoutPort, OidcClientRotatePort, OidcClientTokenPort, OidcDiscoveryPort,
    OidcExchangePort, OidcFrontchannelLogoutPort, OidcRpLogoutPort, PentestPort, PluginsPort,
    PredictivePort, ProposePrPort, ProwlerImportPort, RbaPort, ReadinessProbe, RedteamPort,
    RefreshTokenPort, RemediationAdvisoriesPort, RemediationOutcomesPort, RemediationTrackingPort,
    ReportDiffPort, ReportRenderPort, ReportSchedulePort, RiskTuningPort, RolesPort,
    RunDiscoveryPort, RuntimeFalcoOverridesPort, SamlBackchannelLogoutPort, SamlIdpAdminPort,
    SamlSpPort, ScheduleValidationPort, ScimProvisionPort, SoarPort, SocPort,
    SubmitThreatObservationPort, TenantRepositoryPort, TenantWritePort, TwinPort, UebaAdminPort,
    UebaPort, ValidateTokenPort, VulnIngestPort, WebauthnPort, WebhookKeyRotationAdminPort,
};

/// Shared application state passed to every handler.
#[derive(Clone)]
pub struct AppState {
    /// Readiness probe backing `GET /readyz` (SELL-P1-05): checks critical
    /// dependencies (database connectivity, …) so an orchestrator only
    /// routes traffic once the instance can actually serve.
    pub readiness: Arc<dyn ReadinessProbe>,
    /// Login / token issuance.
    pub authn: Arc<dyn AuthenticateUserPort>,
    /// Bearer token validation.
    pub token_validator: Arc<dyn ValidateTokenPort>,
    /// Refresh-token use case.
    pub refresh: Arc<dyn RefreshTokenPort>,
    /// Logout / session revocation.
    pub logout: Arc<dyn LogoutPort>,
    /// OIDC `id_token` exchange — verify + issue SX tokens.
    pub oidc_exchange: Arc<dyn OidcExchangePort>,
    /// CRIT-004 — OIDC RP-initiated logout (redirect to IdP
    /// `end_session_endpoint`).
    pub oidc_rp_logout: Arc<dyn OidcRpLogoutPort>,
    /// CRIT-004 — OIDC back-channel logout (IdP→SP server-to-server
    /// `logout_token`).
    pub oidc_backchannel_logout: Arc<dyn OidcBackchannelLogoutPort>,
    /// CRIT-004 — OIDC front-channel logout (iframe-driven revocation by
    /// `sid`).
    pub oidc_frontchannel_logout: Arc<dyn OidcFrontchannelLogoutPort>,
    /// CRIT-004 — OIDC discovery document
    /// (`/.well-known/openid-configuration`).
    pub oidc_discovery: Arc<dyn OidcDiscoveryPort>,
    /// CRIT-004 — SAML back-channel logout receiver.
    pub saml_backchannel_logout: Arc<dyn SamlBackchannelLogoutPort>,

    /// MED-004 — OAuth2 `client_credentials` + `client_secret_jwt`
    /// token endpoint. Backs `POST /v1/oauth/token`.
    pub oidc_client_token: Arc<dyn OidcClientTokenPort>,
    /// MED-004 — admin port for rotating an OIDC client's shared secret.
    /// Backs `POST /v1/admin/oidc/clients/{client_id}/rotate-secret`.
    pub oidc_client_rotate: Arc<dyn OidcClientRotatePort>,
    /// MED-004 — public JWKS document publication.
    /// Backs `GET /.well-known/jwks.json`.
    pub jwks_publish: Arc<dyn JwksPublishPort>,

    /// Engagement use cases.
    pub engagements: Arc<dyn EngagementServicePort>,
    /// Engagement state-machine transitions (pause / resume / abort / complete).
    pub engagement_transitions: Arc<dyn EngagementTransitionPort>,
    /// Engagement cloning port — backs `POST /v1/engagements/{id}/clone`.
    pub engagement_clone: Arc<dyn EngagementClonePort>,
    /// Kill-switch.
    pub kill_switch: Arc<dyn KillSwitchPort>,
    /// Composite risk calculation.
    pub risk: Arc<dyn CalculateRiskPort>,
    /// P1-014 — Per-tenant risk-model tuning (weights + thresholds).
    /// Backs `GET/PUT /v1/risk/config` and `GET /v1/risk/config/effective`.
    pub risk_tuning: Arc<dyn RiskTuningPort>,
    /// Discovery runs.
    pub discovery: Arc<dyn RunDiscoveryPort>,

    /// Asset reads.
    pub assets: Arc<dyn AssetRepositoryPort>,
    /// Finding reads + status updates.
    pub findings: Arc<dyn FindingRepositoryPort>,
    /// Tenant reads.
    pub tenants: Arc<dyn TenantRepositoryPort>,

    /// Phase-3 — Breach & Attack Simulation run port.
    pub bas: Arc<dyn BasRunPort>,
    /// Phase-3 — persistent BAS approval store backing the two-person rule.
    pub approvals: Arc<dyn ApprovalPort>,
    /// Phase-3 — persistent BAS run-history store, backs `GET /v1/bas/runs`.
    pub bas_history: Arc<dyn BasRunHistoryPort>,
    /// P2-015 — Lateral-movement chain replay port. Backs
    /// `GET /v1/bas/chains`, `POST /v1/bas/chains/{id}/run`, and
    /// `GET /v1/bas/chains/runs/{id}`.
    pub bas_chain: Arc<dyn BasChainPort>,
    /// Phase-3.5 — passive HTTP-header scanner. Backs `POST/GET /v1/scans`.
    pub http_header_scanner: Arc<dyn crate::port::HttpHeaderScannerPort>,
    /// Phase-3 — Graph attack-paths search port.
    pub graph: Arc<dyn GraphAttackPathsPort>,
    /// P1-010 — Cloud blast-radius computation port. Backs
    /// `POST /v1/cloud/blast-radius`.
    pub blast_radius: Arc<dyn BlastRadiusPort>,
    /// Phase-3 — Report rendering port.
    pub report: Arc<dyn ReportRenderPort>,
    /// P2-002 — per-tenant report branding (MSSP white-label). Backs
    /// `GET`/`PUT /v1/reports/branding`; shared with the report renderer.
    pub branding: Arc<dyn BrandingPort>,
    /// P2-001 — scheduled-report distribution. Backs
    /// `GET`/`POST`/`DELETE /v1/reports/schedules`; shared with the
    /// background scheduler tick loop.
    pub report_schedules: Arc<dyn ReportSchedulePort>,
    /// Comprehensive cross-module report. Backs
    /// `GET /v1/reports/comprehensive`.
    pub comprehensive_report: Arc<dyn ComprehensiveReportPort>,
    /// P2-003 — Differential report (week-over-week) port.
    pub report_diff: Arc<dyn ReportDiffPort>,
    /// Phase-3 — Remediation advisories lookup port.
    pub remediation: Arc<dyn RemediationAdvisoriesPort>,
    /// Phase-3 — Compliance framework + finding-to-control mapping port.
    pub compliance: Arc<dyn ComplianceFrameworkPort>,
    /// P1-004 — Automated compliance evidence collector port. Backs the
    /// `/v1/compliance/evidence/*` HTTP surface.
    pub compliance_evidence: Arc<dyn ComplianceEvidencePort>,
    /// Phase-3 — ML triage-prediction port.
    pub ml: Arc<dyn MlTriagePredictPort>,
    /// Phase-3.5 — Cloud-inventory fan-out port.
    pub cloud_inventory: Arc<dyn CloudInventoryPort>,

    /// Autonomy — auto-remediation pull-request proposal port.
    pub propose_pr: Arc<dyn ProposePrPort>,
    /// Autonomy — anonymised threat-network observation-submission port.
    pub submit_threat: Arc<dyn SubmitThreatObservationPort>,
    /// Autonomy — continuous-validation engine scheduling port.
    pub schedule_validation: Arc<dyn ScheduleValidationPort>,

    /// Phase-3.5 — Out-of-band collaborator token allocation port.
    pub collab_alloc: Arc<dyn CollabAllocateTokenPort>,
    /// Phase-3.5 — Out-of-band collaborator callback-lookup port.
    pub collab_lookup: Arc<dyn CollabLookupCallbacksPort>,

    /// Admin — operator-driven user provisioning port.
    pub create_user: Arc<dyn CreateUserPort>,
    /// Customer-facing auth — signup / verify-email / forgot-password /
    /// reset-password. Backs the four public `/v1/auth/*` endpoints
    /// customers use to self-service their account.
    pub customer_auth: Arc<dyn CustomerAuthPort>,

    /// Phase-3.5+ — SOC alert correlator + buffered sink read port.
    pub soc: Arc<dyn SocPort>,
    /// Phase-3.5+ — Cyber digital-twin read port.
    pub twin: Arc<dyn TwinPort>,
    /// Phase-3.5+ — IOC bloom-backed indicator lookup port.
    pub intel_check: Arc<dyn IntelCheckPort>,
    /// Phase-3.5+ — GBDT-backed per-finding risk prediction port.
    pub predictive: Arc<dyn PredictivePort>,
    /// Phase-3.5+ — MITRE ATT&CK chain composer port.
    pub redteam: Arc<dyn RedteamPort>,
    /// Phase-3.5+ — LLM-backed copilot chat port.
    pub copilot: Arc<dyn CopilotPort>,
    /// P1-012 — Copilot human-in-loop approval queue port.
    pub copilot_approval: Arc<dyn CopilotApprovalPort>,
    /// Phase-3.5+ — GraphSAGE-derived per-asset risk score read port.
    pub graphsage_risk: Arc<dyn GraphsageRiskPort>,
    /// Admin — IAM roles + permissions CRUD port.
    pub roles: Arc<dyn RolesPort>,
    /// Asset write-side port (POST/PATCH/DELETE /v1/assets).
    pub asset_write: Arc<dyn AssetWritePort>,
    /// Asset bulk-import port (POST /v1/assets/bulk-import).
    pub asset_bulk: Arc<dyn AssetBulkImportPort>,
    /// Finding bulk-update + export port — backs
    /// `POST /v1/findings/bulk-update` and `GET /v1/findings/export`.
    pub finding_bulk: Arc<dyn FindingBulkPort>,
    /// Tenant write-side port (POST/PATCH/DELETE /v1/admin/tenants).
    pub tenant_write: Arc<dyn TenantWritePort>,
    /// Remediation-link tracking port — backs
    /// `PATCH/DELETE /v1/findings/{id}/remediation`.
    pub remediation_tracking: Arc<dyn RemediationTrackingPort>,
    /// Audit log search + NDJSON export read port.
    pub audit_query: Arc<dyn AuditQueryPort>,
    /// Audit replay (time-travel) port — backs `GET /v1/audit/replay`
    /// and `GET /v1/audit/diff` (P3-009).
    pub audit_replay: Arc<dyn AuditReplayPort>,
    /// External audit-chain anchoring port (P1-015) — backs
    /// `GET /v1/audit/anchors` and
    /// `POST /v1/audit/anchors/verify/{run_id}`.
    pub audit_anchor: Arc<dyn AuditAnchorPort>,
    /// TOTP MFA self-service port — backs `/v1/mfa/*`.
    pub mfa: Arc<dyn MfaPort>,
    /// FIDO2 / WebAuthn passkey MFA port (P1-002) — backs
    /// `/v1/auth/mfa/webauthn/{register,login}/{start,finish}`.
    pub webauthn: Arc<dyn WebauthnPort>,
    pub log_ingest: Arc<dyn LogIngestPort>,
    /// MED-001 — per-tenant log-ingest token-bucket rate limiter. Backs
    /// `POST /v1/logs/ingest` (admit/throttle on every call) and
    /// `PUT /v1/admin/log-ingest/tiers/{tenant_id}` (admin tier set).
    pub log_rate_limit: Arc<dyn LogRateLimitPort>,
    pub vuln_ingest: Arc<dyn VulnIngestPort>,
    /// P1-009 — Prowler v4 native-JSON CSPM import port. Backs
    /// `POST /v1/discovery/prowler/import`.
    pub prowler_import: Arc<dyn ProwlerImportPort>,
    pub scim: Arc<dyn ScimProvisionPort>,
    pub rba: Arc<dyn RbaPort>,
    pub remediation_outcomes: Arc<dyn RemediationOutcomesPort>,
    pub ueba: Arc<dyn UebaPort>,
    /// HIGH-010 — UEBA frozen-baseline admin port. Backs the
    /// `/v1/admin/ueba/baseline/{user_id}/{freeze,unfreeze,snapshot}`
    /// surface. The default adapter wraps the in-memory
    /// `FreezeAwareUebaService` and surfaces audit + drift findings
    /// via the injected sinks.
    pub ueba_admin: Arc<dyn UebaAdminPort>,
    /// P3-005 — SOAR low-code workflow builder port. Backs the
    /// `/v1/soar/*` HTTP surface.
    pub soar: Arc<dyn SoarPort>,
    pub device_trust: Arc<dyn DeviceTrustPort>,
    /// SAML 2.0 Service Provider port (P0-004). Disabled by default;
    /// the composition root installs a stub adapter that surfaces
    /// `SamlPortError::Disabled` so the three SAML endpoints return a
    /// deterministic 422 when the operator has not configured it.
    pub saml_sp: Arc<dyn SamlSpPort>,
    /// P0-004 — per-tenant SAML IdP configuration admin port. Backs
    /// `GET`/`PUT /v1/admin/saml/idp`; independent of the SP enabled flag
    /// so operators can author the IdP record (durably) before enabling
    /// SAML sign-in.
    pub saml_idp_admin: Arc<dyn SamlIdpAdminPort>,
    /// P2-006 — DLP content-inspection port.
    pub dlp: Arc<dyn DlpPort>,
    /// P2-009 — GRC outbound integration port. Backs `/v1/grc/*`
    /// (configs CRUD, configs/{id}/test, push).
    pub grc: Arc<dyn GrcPort>,
    /// P3-007 — plugin marketplace + SDK port. Backs `/v1/plugins/*`.
    pub plugins: Arc<dyn PluginsPort>,
    /// P2-004 — Cloud drift detection vs IaC baseline. Backs
    /// `/v1/cloud/drift/*`.
    pub cloud_drift: Arc<dyn CloudDriftPort>,
    /// P3-004 — In-app IR playbooks (NIST SP 800-61 Rev 2). Backs
    /// `/v1/ir/*`.
    pub ir: Arc<dyn IrPlaybooksPort>,

    /// P2-012 — chaos engineering registry (opt-in, OFF by default).
    pub chaos: sx_chaos::SharedChaosRegistry,
    /// P2-012 — admin service backing `GET/PUT /v1/chaos/config`.
    pub chaos_admin: sx_chaos::admin::ChaosAdminService,

    /// P2-016 — container-runtime security (Falco) ingestion facade.
    pub runtime_falco: Arc<sx_runtime::FalcoIngestService>,
    /// HIGH-009 — Kubernetes admission webhook (blocking mode) port.
    /// Backs `POST /v1/runtime/k8s/admit`.
    pub k8s_admission: Arc<dyn K8sAdmissionPort>,
    /// HIGH-006 — per-tenant Falco rule allow/deny override admin port.
    /// Backs `GET/PUT/DELETE /v1/admin/runtime/falco/overrides`.
    pub runtime_falco_overrides: Arc<dyn RuntimeFalcoOverridesPort>,

    /// P2-013 — API DAST (Postman collection replay) port. Backs
    /// `/v1/discovery/dast/*`.
    pub api_dast: Arc<dyn ApiDastPort>,
    /// P3-010 — Bug-bounty bridge (HackerOne + Bugcrowd). Backs
    /// `/v1/integrations/bugbounty/*` (configs CRUD, push, inbound webhook).
    pub bugbounty: Arc<dyn BugBountyPort>,
    /// P3-006 — Threat-hunting KQL/SPL-like query port. Backs
    /// `POST /v1/hunt/query`.
    pub hunt: Arc<dyn HuntPort>,
    /// AI-SEC-001 — comprehensive AI security audit port. Backs the
    /// `/v1/ai-audit/*` surface (inventory, AI-BOM, controls, run).
    pub ai_audit: Arc<dyn AiAuditPort>,
    /// PENTEST-001 — combined penetration & vulnerability testing
    /// orchestration port. Backs `/v1/pentest/*`.
    pub pentest: Arc<dyn PentestPort>,

    /// Nav-gap fixes — admin user-listing port. Backs
    /// `GET /v1/admin/users`.
    pub admin_user_list: Arc<dyn AdminUserListPort>,
    /// Nav-gap fixes — intel-feed status read port. Backs
    /// `GET /v1/intel/feeds`.
    pub intel_feed_status: Arc<dyn IntelFeedStatusPort>,
    /// Nav-gap fixes — push device registry read port. Backs
    /// `GET /v1/notifications/devices`.
    pub device_registry: Arc<dyn DeviceRegistryPort>,

    /// CRIT-003 — per-tenant DEK rotation admin port. Backs
    /// `POST /v1/admin/secrets/rotate-dek` and
    /// `GET /v1/admin/secrets/rotation-progress`. The default adapter
    /// surfaces `Phase3PortError::Invalid("dek rotation disabled")`
    /// so operators see a deterministic message when the rotation
    /// stack has not been wired in.
    pub dek_rotation_admin: Arc<dyn DekRotationAdminPort>,

    /// MED-003 — per-tenant outbound webhook signing-key rotation
    /// admin port. Backs `POST /v1/admin/webhooks/keys/rotate`. The
    /// default adapter surfaces
    /// `WebhookKeyRotationPortError::Disabled` until the production
    /// rotation stack (signing-key store + envelope cipher + audit
    /// sink) is wired in.
    pub webhook_key_rotation_admin: Arc<dyn WebhookKeyRotationAdminPort>,

    /// HTTP server configuration (timeouts, bind addr, body limit).
    pub server_cfg: Arc<ServerConfig>,
    /// Rate-limit configuration (limits per minute, burst).
    pub rate_limit_cfg: Arc<RateLimitConfig>,
    /// In-memory rate-limiter state (per-key token buckets).
    pub rate_limiter: Arc<RateLimiterState>,
    /// Release-channel / SARIF `tool.driver` metadata (TOP5-#3 Phase 3).
    /// Consumed by the `GET /v1/scans/{id}.sarif` endpoint to populate
    /// `runs[].tool.driver.organization` and `.downloadUri`.
    pub release_channel_cfg: Arc<ReleaseChannelConfig>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("server_cfg", &self.server_cfg)
            .field("rate_limit_cfg", &self.rate_limit_cfg)
            .finish_non_exhaustive()
    }
}
