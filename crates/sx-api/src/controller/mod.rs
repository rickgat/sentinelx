//! HTTP controllers — `axum` handler functions, organised per resource.
//!
//! Controllers are intentionally thin: they parse the request via
//! extractors, call a single use case via an `AppState` port, and project
//! the result into a view.

pub mod admin;
pub mod ai_audit;
pub mod asset;
pub mod asset_bulk;
pub mod assets;
pub mod audit;
pub mod audit_anchor;
pub mod auth;
pub mod autonomy;
pub mod bas;
pub mod bas_chain;
pub mod blast_radius;
pub mod branding;
pub mod bugbounty;
pub mod chaos;
pub mod cloud;
pub mod cloud_drift;
pub mod collab;
pub mod compliance;
pub mod compliance_evidence;
pub mod comprehensive_report;
pub mod copilot;
pub mod copilot_approval;
pub mod customer_auth;
pub mod dast;
pub mod device_trust;
pub mod discovery;
pub mod dlp;
pub mod engagement;
pub mod finding;
pub mod findings_bulk;
pub mod findings_remediation;
pub mod graph;
pub mod grc;
pub mod health;
pub mod hunt;
pub mod intel;
pub mod ir_playbooks;
/// HIGH-009 — Kubernetes admission webhook (blocking mode).
pub mod k8s_admission;
pub mod killswitch;
pub mod log_ingest;
pub mod logout;
pub mod metrics;
pub mod mfa;
pub mod ml;
pub mod notifications;
/// MED-004 — OIDC `client_secret_jwt` token endpoint + JWKS publish +
/// secret rotation.
pub mod oidc_client;
pub mod openapi;
pub mod pentest;
pub mod plugins;
pub mod predictive;
pub mod prowler_import;
pub mod rba;
pub mod redteam;
pub mod remediation;
pub mod remediation_outcomes;
pub mod report;
pub mod report_schedule;
pub mod risk;
pub mod risk_tuning;
pub mod roles;
pub mod runtime;
pub mod saml;
pub mod saml_admin;
pub mod scan;
pub mod scim;
pub mod secrets_admin;
pub mod soar;
pub mod soc;
pub mod tenant;
pub mod tenants;
pub mod twin;
pub mod ueba;
pub mod ueba_admin;
pub mod vuln_ingest;
pub mod webauthn;
pub mod webhooks_admin;

use sx_iam::IamError;

use crate::error::ApiError;
use crate::port::{
    AiAuditPortError, CloudDriftPortError, ComplianceEvidencePortError, DiscoveryPortError,
    EngagementPortError, HuntPortError, PentestPortError, Phase3PortError, PluginsPortError,
    RbaPortError, RiskPortError, RiskTuningPortError, SoarPortError, UebaAdminPortError,
    UebaPortError, WebhookKeyRotationPortError,
};

/// Translate an [`IamError`] into the appropriate [`ApiError`].
pub fn map_iam(err: IamError) -> ApiError {
    match err {
        IamError::InvalidCredentials | IamError::TokenExpired | IamError::InvalidToken => {
            ApiError::Unauthorized
        }
        IamError::AccountLocked | IamError::Forbidden { .. } => ApiError::Forbidden,
        IamError::Conflict(m) => ApiError::Conflict(m),
        IamError::Internal(m) | IamError::Config(m) => ApiError::Internal(m),
        IamError::Repository(m) => ApiError::Dependency(m),
    }
}

/// Translate an [`EngagementPortError`] into the appropriate [`ApiError`].
pub fn map_engagement(err: EngagementPortError) -> ApiError {
    match err {
        EngagementPortError::NotFound => ApiError::NotFound,
        EngagementPortError::Forbidden => ApiError::Forbidden,
        EngagementPortError::Conflict(m) => ApiError::Conflict(m),
        EngagementPortError::Invalid(m) => ApiError::Unprocessable(m),
        EngagementPortError::Dependency(m) => ApiError::Dependency(m),
        EngagementPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`RiskPortError`] into the appropriate [`ApiError`].
pub fn map_risk(err: RiskPortError) -> ApiError {
    match err {
        RiskPortError::NotFound => ApiError::NotFound,
        RiskPortError::Invalid(m) => ApiError::Unprocessable(m),
        RiskPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`RiskTuningPortError`] into the appropriate [`ApiError`].
///
/// `Invalid` collapses to `422 Unprocessable Entity` so a tenant who
/// PUTs an out-of-band weight vector gets the same envelope as any
/// other validation failure. `Dependency` (DB / queue / audit-sink
/// failure) maps to `503 Service Unavailable` so SREs see "this is not
/// your fault" client-side.
pub fn map_risk_tuning(err: RiskTuningPortError) -> ApiError {
    match err {
        RiskTuningPortError::Invalid(m) => ApiError::Unprocessable(m),
        RiskTuningPortError::Dependency(m) => ApiError::Dependency(m),
        RiskTuningPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`DiscoveryPortError`] into the appropriate [`ApiError`].
pub fn map_discovery(err: DiscoveryPortError) -> ApiError {
    match err {
        DiscoveryPortError::Forbidden(_) => ApiError::Forbidden,
        DiscoveryPortError::Invalid(m) => ApiError::Unprocessable(m),
        DiscoveryPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`Phase3PortError`] into the appropriate [`ApiError`].
///
/// Shared by every Phase-3 controller (`bas`, `graph`, `report`,
/// `remediation`, `compliance`, `ml`).
pub fn map_phase3(err: Phase3PortError) -> ApiError {
    match err {
        Phase3PortError::NotFound => ApiError::NotFound,
        Phase3PortError::Forbidden(_) => ApiError::Forbidden,
        Phase3PortError::Invalid(m) => ApiError::Unprocessable(m),
        Phase3PortError::Dependency(m) => ApiError::Dependency(m),
        Phase3PortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate an [`RbaPortError`] into the appropriate [`ApiError`].
pub fn map_rba(err: RbaPortError) -> ApiError {
    match err {
        RbaPortError::Forbidden => ApiError::Forbidden,
        RbaPortError::Invalid(m) => ApiError::Unprocessable(m),
        RbaPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`UebaPortError`] into the appropriate [`ApiError`].
pub fn map_ueba(err: UebaPortError) -> ApiError {
    match err {
        UebaPortError::NotFound => ApiError::NotFound,
        UebaPortError::Invalid(m) => ApiError::Unprocessable(m),
        UebaPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`UebaAdminPortError`] into the appropriate [`ApiError`].
///
/// `InvalidTransition` collapses to `409 Conflict` because the caller's
/// request is well-formed but conflicts with the current resource state
/// (e.g. unfreezing while not Frozen).
pub fn map_ueba_admin(err: UebaAdminPortError) -> ApiError {
    match err {
        UebaAdminPortError::NotFound => ApiError::NotFound,
        UebaAdminPortError::InvalidTransition(m) => ApiError::Conflict(m),
        UebaAdminPortError::Invalid(m) => ApiError::Unprocessable(m),
        UebaAdminPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`PentestPortError`] (PENTEST-001) into the appropriate
/// [`ApiError`].
///
/// A scope / kill-switch denial collapses to `403 Forbidden`; invalid
/// input to `422 Unprocessable`.
pub fn map_pentest(err: PentestPortError) -> ApiError {
    match err {
        PentestPortError::NotFound => ApiError::NotFound,
        PentestPortError::Invalid(m) => ApiError::Unprocessable(m),
        PentestPortError::Denied(_) => ApiError::Forbidden,
        PentestPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`SoarPortError`] into the appropriate [`ApiError`].
pub fn map_soar(err: SoarPortError) -> ApiError {
    match err {
        SoarPortError::NotFound => ApiError::NotFound,
        SoarPortError::Invalid(m) => ApiError::Unprocessable(m),
        SoarPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`PluginsPortError`] into the appropriate [`ApiError`].
pub fn map_plugins(err: PluginsPortError) -> ApiError {
    match err {
        PluginsPortError::NotFound => ApiError::NotFound,
        PluginsPortError::Invalid(m) => ApiError::Unprocessable(m),
        PluginsPortError::Dependency(m) => ApiError::Dependency(m),
        PluginsPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`CloudDriftPortError`] into the appropriate [`ApiError`].
pub fn map_cloud_drift(err: CloudDriftPortError) -> ApiError {
    match err {
        CloudDriftPortError::NotFound => ApiError::NotFound,
        CloudDriftPortError::Invalid(m) => ApiError::Unprocessable(m),
        CloudDriftPortError::Dependency(m) => ApiError::Dependency(m),
        CloudDriftPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`ComplianceEvidencePortError`] into the appropriate
/// [`ApiError`].
pub fn map_compliance_evidence(err: ComplianceEvidencePortError) -> ApiError {
    match err {
        ComplianceEvidencePortError::NotFound => ApiError::NotFound,
        ComplianceEvidencePortError::Forbidden => ApiError::Forbidden,
        ComplianceEvidencePortError::Invalid(m) => ApiError::Unprocessable(m),
        ComplianceEvidencePortError::Dependency(m) => ApiError::Dependency(m),
        ComplianceEvidencePortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`HuntPortError`] into the appropriate [`ApiError`].
///
/// Parse / compile failures surface as `422 Unprocessable`; ClickHouse
/// transport errors as `502 Bad Gateway` (via `Dependency`); anything
/// else as `500 Internal`.
pub fn map_hunt(err: HuntPortError) -> ApiError {
    match err {
        HuntPortError::Invalid(m) => ApiError::Unprocessable(m),
        HuntPortError::Dependency(m) => ApiError::Dependency(m),
        HuntPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Map a [`crate::port::BrandingPortError`] onto the HTTP error surface.
pub fn map_branding(err: crate::port::BrandingPortError) -> ApiError {
    use crate::port::BrandingPortError;
    match err {
        BrandingPortError::Invalid(m) => ApiError::Unprocessable(m),
        BrandingPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate an [`AiAuditPortError`] (AI-SEC-001) into the appropriate
/// [`ApiError`].
///
/// `Forbidden` collapses to `403` (e.g. an out-of-scope probe target);
/// `Dependency` to `503`; everything else as documented.
pub fn map_ai_audit(err: AiAuditPortError) -> ApiError {
    match err {
        AiAuditPortError::NotFound => ApiError::NotFound,
        AiAuditPortError::Invalid(m) => ApiError::Unprocessable(m),
        AiAuditPortError::Forbidden(_) => ApiError::Forbidden,
        AiAuditPortError::Dependency(m) => ApiError::Dependency(m),
        AiAuditPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Translate a [`WebhookKeyRotationPortError`] (MED-003) into the appropriate [`ApiError`].
///
/// `Disabled` and `Invalid` both collapse to `422 Unprocessable` so
/// the wire never distinguishes "feature off" from "bad request"
/// beyond the body.
pub fn map_webhook_key_rotation(err: WebhookKeyRotationPortError) -> ApiError {
    match err {
        WebhookKeyRotationPortError::Disabled(m) | WebhookKeyRotationPortError::Invalid(m) => {
            ApiError::Unprocessable(m)
        }
        WebhookKeyRotationPortError::Dependency(m) => ApiError::Dependency(m),
        WebhookKeyRotationPortError::Internal(m) => ApiError::Internal(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iam_errors_map_predictably() {
        assert!(matches!(
            map_iam(IamError::InvalidCredentials),
            ApiError::Unauthorized
        ));
        assert!(matches!(
            map_iam(IamError::TokenExpired),
            ApiError::Unauthorized
        ));
        assert!(matches!(
            map_iam(IamError::InvalidToken),
            ApiError::Unauthorized
        ));
        assert!(matches!(
            map_iam(IamError::AccountLocked),
            ApiError::Forbidden
        ));
        assert!(matches!(
            map_iam(IamError::forbidden("x")),
            ApiError::Forbidden
        ));
        assert!(matches!(
            map_iam(IamError::repository("x")),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_iam(IamError::internal("x")),
            ApiError::Internal(_)
        ));
        assert!(matches!(
            map_iam(IamError::config("x")),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn phase3_errors_map_predictably() {
        assert!(matches!(
            map_phase3(Phase3PortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_phase3(Phase3PortError::Forbidden("x".into())),
            ApiError::Forbidden
        ));
        assert!(matches!(
            map_phase3(Phase3PortError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_phase3(Phase3PortError::Dependency("x".into())),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_phase3(Phase3PortError::Internal("x".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn rba_errors_map_predictably() {
        assert!(matches!(
            map_rba(RbaPortError::Forbidden),
            ApiError::Forbidden
        ));
        assert!(matches!(
            map_rba(RbaPortError::Invalid("bad".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_rba(RbaPortError::Internal("boom".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn ueba_errors_map_predictably() {
        assert!(matches!(
            map_ueba(UebaPortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_ueba(UebaPortError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_ueba(UebaPortError::Internal("x".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn ueba_admin_errors_map_predictably() {
        assert!(matches!(
            map_ueba_admin(UebaAdminPortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_ueba_admin(UebaAdminPortError::InvalidTransition("x".into())),
            ApiError::Conflict(_)
        ));
        assert!(matches!(
            map_ueba_admin(UebaAdminPortError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_ueba_admin(UebaAdminPortError::Internal("x".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn plugins_errors_map_predictably() {
        assert!(matches!(
            map_plugins(PluginsPortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_plugins(PluginsPortError::Invalid("bad".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_plugins(PluginsPortError::Dependency("db".into())),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_plugins(PluginsPortError::Internal("oops".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn cloud_drift_errors_map_predictably() {
        assert!(matches!(
            map_cloud_drift(CloudDriftPortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_cloud_drift(CloudDriftPortError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_cloud_drift(CloudDriftPortError::Dependency("x".into())),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_cloud_drift(CloudDriftPortError::Internal("x".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn engagement_errors_map_predictably() {
        assert!(matches!(
            map_engagement(EngagementPortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_engagement(EngagementPortError::Forbidden),
            ApiError::Forbidden
        ));
        assert!(matches!(
            map_engagement(EngagementPortError::Conflict("x".into())),
            ApiError::Conflict(_)
        ));
        assert!(matches!(
            map_engagement(EngagementPortError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_engagement(EngagementPortError::Dependency("x".into())),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_engagement(EngagementPortError::Internal("x".into())),
            ApiError::Internal(_)
        ));
    }
}
