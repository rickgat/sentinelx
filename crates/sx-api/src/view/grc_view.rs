//! Request/response DTOs for the `/v1/grc/*` HTTP surface (P2-009).
//!
//! Three endpoints are surfaced:
//!
//! * `POST /v1/grc/configs` — upsert a per-tenant GRC connection.
//! * `POST /v1/grc/configs/{kind}/test` — fire a no-op connectivity
//!   probe so the dashboard can confirm an operator-supplied token
//!   works.
//! * `POST /v1/grc/push` — dispatch a single evidence or finding
//!   payload to the connector configured for the tenant.
//!
//! Wire keys are snake_case to match the rest of the `/v1/*` surface.
//! Secret material (`secret`) is wrapped in
//! [`secrecy::SecretString`] on the request side so the `Debug` impl
//! never leaks it into a log line.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/grc/configs` request body.
///
/// The caller hands the operator's API token (Vanta / Drata) or the
/// basic-auth password (ServiceNow) inline; the adapter writes it to
/// the configured [`sx_secrets::SecretsProvider`] under the
/// `tenants/{tenant_id}/grc/{kind}/secret` path and persists only the
/// path on the connection row.
#[derive(Deserialize, Validate)]
pub struct GrcConfigUpsertRequest {
    /// Connector kind as a wire string (`vanta` / `drata` / `servicenow`).
    #[validate(length(min = 1, max = 64))]
    pub kind: String,
    /// ServiceNow only — instance URL, e.g. `https://acme.service-now.com`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 512))]
    pub instance_url: Option<String>,
    /// ServiceNow only — basic-auth user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 256))]
    pub user: Option<String>,
    /// Vanta / Drata bearer key OR ServiceNow basic-auth password.
    /// Held in [`SecretString`] so the `Debug` impl redacts it.
    pub secret: SecretString,
}

impl std::fmt::Debug for GrcConfigUpsertRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrcConfigUpsertRequest")
            .field("kind", &self.kind)
            .field("instance_url", &self.instance_url)
            .field("user", &self.user)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// `POST /v1/grc/configs` response body.
///
/// Mirrors the persisted row but redacts the actual secret — the
/// caller only ever sees the *path* into the secret store, not the
/// value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrcConfigView {
    /// Tenant uuid the row belongs to.
    pub tenant_id: String,
    /// Connector kind (wire string).
    pub kind: String,
    /// ServiceNow only — instance URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_url: Option<String>,
    /// ServiceNow only — basic-auth user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Stable secret-store path the connection row references.
    pub secret_path: String,
    /// RFC 3339 timestamp the row was upserted.
    pub created_at: String,
}

/// `POST /v1/grc/configs/{kind}/test` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrcConnectionTestView {
    /// Connector kind tested.
    pub kind: String,
    /// `true` when the probe round-trip succeeded.
    pub ok: bool,
    /// Stable error code surfaced when `ok = false`. One of `transport`,
    /// `format`, `unauthorized`, `rate_limited`, `unimplemented`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Resource the caller wants to push. Maps onto
/// [`sx_integrations::grc::GrcAuditResource`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GrcPushResource {
    /// A compliance evidence record.
    Evidence,
    /// A finding lifecycle update.
    Finding,
}

impl GrcPushResource {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Finding => "finding",
        }
    }
}

/// `POST /v1/grc/push` request body.
///
/// `kind` selects the connector. `resource` selects evidence vs.
/// finding. `evidence` / `finding` carry the canonical shape — the
/// adapter projects it into
/// [`sx_integrations::grc::ComplianceEvidence`] or
/// [`sx_integrations::grc::FindingState`] depending on `resource`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct GrcPushRequest {
    /// Target connector kind (wire string).
    #[validate(length(min = 1, max = 64))]
    pub kind: String,
    /// Resource type — `evidence` or `finding`.
    pub resource: GrcPushResource,
    /// Canonical evidence payload — required when `resource = evidence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<GrcEvidenceInput>,
    /// Canonical finding payload — required when `resource = finding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<GrcFindingInput>,
}

/// Inline evidence payload — same shape as
/// [`sx_integrations::grc::ComplianceEvidence`] minus `tenant_id`,
/// which is supplied from the bearer claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrcEvidenceInput {
    /// Stable evidence id — used as the upstream upsert key.
    pub id: String,
    /// Framework identifier — `soc2`, `iso27001`, ...
    pub framework: String,
    /// Control identifier inside the framework.
    pub control_id: String,
    /// Free-form reference to the originating finding (uuid).
    pub finding_ref: String,
    /// Free-form reference to the observation that produced the finding.
    pub observation_ref: String,
    /// RFC 3339 timestamp the evidence was collected.
    pub collected_at: String,
}

/// Inline finding payload — same shape as
/// [`sx_integrations::grc::FindingState`] minus `tenant_id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrcFindingInput {
    /// Finding uuid.
    pub id: String,
    /// Severity (`info`, `low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// Lifecycle status (`open`, `triaged`, `accepted`, `closed`).
    pub status: String,
    /// Short title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// RFC 3339 first-seen timestamp.
    pub first_seen: String,
    /// RFC 3339 last-seen timestamp.
    pub last_seen: String,
}

/// `POST /v1/grc/push` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrcPushOutcomeView {
    /// Connector kind that was pushed to.
    pub kind: String,
    /// Resource pushed (wire string).
    pub resource: String,
    /// SentinelX-side identifier the dispatcher echoed back.
    pub source_ref: String,
    /// Upstream identifier minted by the GRC platform when the vendor
    /// returns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
    /// Canonical URL of the upserted resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn upsert_request_debug_redacts_secret() {
        let req = GrcConfigUpsertRequest {
            kind: "vanta".into(),
            instance_url: None,
            user: None,
            secret: SecretString::from("vanta-shh".to_owned()),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("vanta-shh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn upsert_request_deserialises_kind_and_secret() {
        let s = r#"{
            "kind": "vanta",
            "secret": "vanta-shh"
        }"#;
        let req: GrcConfigUpsertRequest = serde_json::from_str(s).expect("deserialise");
        assert_eq!(req.kind, "vanta");
        assert_eq!(req.secret.expose_secret(), "vanta-shh");
    }

    #[test]
    fn push_request_round_trips_evidence_branch() {
        let s = r#"{
            "kind": "vanta",
            "resource": "evidence",
            "evidence": {
                "id": "ev-1",
                "framework": "soc2",
                "control_id": "CC6.1",
                "finding_ref": "f-1",
                "observation_ref": "obs-1",
                "collected_at": "2027-01-01T00:00:00Z"
            }
        }"#;
        let req: GrcPushRequest = serde_json::from_str(s).expect("deserialise");
        assert_eq!(req.kind, "vanta");
        assert_eq!(req.resource, GrcPushResource::Evidence);
        assert!(req.finding.is_none());
        assert_eq!(req.evidence.as_ref().expect("ev").id, "ev-1");
    }

    #[test]
    fn config_view_omits_optional_fields_when_empty() {
        let v = GrcConfigView {
            tenant_id: "t-1".into(),
            kind: "vanta".into(),
            instance_url: None,
            user: None,
            secret_path: "tenants/t-1/grc/vanta/secret".into(),
            created_at: "2027-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&v).expect("serialise");
        assert!(json.contains("\"secret_path\":\"tenants/t-1/grc/vanta/secret\""));
        assert!(!json.contains("instance_url"));
        assert!(!json.contains("\"user\":"));
    }

    #[test]
    fn push_resource_wire_is_stable() {
        assert_eq!(GrcPushResource::Evidence.as_wire(), "evidence");
        assert_eq!(GrcPushResource::Finding.as_wire(), "finding");
    }

    #[test]
    fn test_view_serialises_error_code_when_failed() {
        let v = GrcConnectionTestView {
            kind: "drata".into(),
            ok: false,
            error_code: Some("unimplemented".into()),
        };
        let json = serde_json::to_string(&v).expect("serialise");
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("\"error_code\":\"unimplemented\""));
    }
}
