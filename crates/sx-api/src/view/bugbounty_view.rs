//! Request/response DTOs for the `/v1/integrations/bugbounty/*` HTTP
//! surface (P3-010).
//!
//! Four endpoints:
//!
//! * `POST /v1/integrations/bugbounty/configs`         — upsert a
//!   per-tenant per-platform connection (HackerOne or Bugcrowd).
//! * `GET  /v1/integrations/bugbounty/configs`         — list the
//!   tenant's configured connections.
//! * `POST /v1/integrations/bugbounty/push`            — push a
//!   triaged finding (severity ≥ HIGH) as an internal draft note.
//! * `POST /v1/integrations/bugbounty/inbound/{platform}` —
//!   webhook delivery from the platform (HMAC-SHA256 verified).
//!
//! Wire keys are snake_case. Secret material (API tokens, webhook
//! HMAC secrets) travels inside [`secrecy::SecretString`] on request so
//! the [`std::fmt::Debug`] impl never leaks the value into a log.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/integrations/bugbounty/configs` request body.
///
/// The operator hands the API token (and, for HackerOne, the API
/// username) plus an inbound webhook HMAC secret inline. The adapter
/// writes both to the configured [`sx_secrets::SecretsProvider`] under
/// per-platform-scoped paths and persists only the *paths* on the row.
#[derive(Deserialize, Validate)]
pub struct BugBountyConfigUpsertRequest {
    /// Platform wire string — `hackerone` or `bugcrowd`.
    #[validate(length(min = 1, max = 32))]
    pub platform: String,
    /// Program handle / engagement uuid the credentials authorize. Used
    /// as the third component of the row key.
    #[validate(length(min = 1, max = 128))]
    pub program_handle: String,
    /// HackerOne API username. Required when `platform = hackerone`;
    /// ignored for `bugcrowd`. Not a secret — it identifies the API
    /// user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 128))]
    pub api_username: Option<String>,
    /// API token (HackerOne basic-auth password or Bugcrowd bearer).
    pub api_token: SecretString,
    /// Inbound webhook HMAC-SHA256 secret. Verified against the
    /// platform-supplied signature header on every `/inbound/{platform}`
    /// delivery.
    pub webhook_secret: SecretString,
}

impl std::fmt::Debug for BugBountyConfigUpsertRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BugBountyConfigUpsertRequest")
            .field("platform", &self.platform)
            .field("program_handle", &self.program_handle)
            .field("api_username", &self.api_username)
            .field("api_token", &"<redacted>")
            .field("webhook_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// `POST/GET /v1/integrations/bugbounty/configs` response body.
///
/// Mirrors the persisted row — the operator only ever sees the *paths*
/// into the secret store, never the values themselves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugBountyConfigView {
    /// Tenant uuid the row belongs to.
    pub tenant_id: String,
    /// Platform wire string.
    pub platform: String,
    /// Program handle the credentials authorize.
    pub program_handle: String,
    /// HackerOne only — API username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_username: Option<String>,
    /// Stable path into the secret store where the API token lives.
    pub token_secret_path: String,
    /// Stable path into the secret store where the webhook HMAC secret
    /// lives.
    pub webhook_secret_path: String,
    /// RFC 3339 timestamp the row was upserted.
    pub created_at: String,
}

/// `POST /v1/integrations/bugbounty/push` request body.
///
/// The caller hands the canonical triaged-finding shape inline; the
/// adapter enforces the severity ≥ HIGH floor and rejects anything
/// lower with a 422.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct BugBountyPushRequest {
    /// Platform wire string.
    #[validate(length(min = 1, max = 32))]
    pub platform: String,
    /// Program handle the note attaches to. The adapter looks the
    /// matching row up by `(tenant_id, platform, program_handle)`.
    #[validate(length(min = 1, max = 128))]
    pub program_handle: String,
    /// Triaged finding being pushed.
    pub finding: BugBountyFindingInput,
}

/// Inline triaged-finding payload mirroring
/// [`sx_integrations::bugbounty::TriagedFinding`] minus `tenant_id`,
/// which is supplied from the bearer claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugBountyFindingInput {
    /// Finding uuid.
    pub id: String,
    /// Short title.
    pub title: String,
    /// Long-form description (markdown).
    pub description: String,
    /// Severity wire string — `high` or `critical`.
    pub severity: String,
}

/// `POST /v1/integrations/bugbounty/push` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugBountyPushOutcomeView {
    /// Platform pushed to.
    pub platform: String,
    /// SentinelX-side finding id (echoed for correlation).
    pub source_ref: String,
    /// Upstream identifier minted by the platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
    /// Canonical URL of the upserted internal note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// `POST /v1/integrations/bugbounty/inbound/{platform}` response body.
///
/// The handler returns 200 on accepted-and-mapped, 200 with `deduplicated`
/// when the payload matched an existing finding, and surfaces signature
/// errors as 401, malformed payloads as 422.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugBountyInboundOutcomeView {
    /// Platform the delivery came from.
    pub platform: String,
    /// Stable source tag minted for the report:
    /// `bugbounty.<platform>.researcher_<id>`.
    pub source: String,
    /// Upstream researcher identifier.
    pub researcher_id: String,
    /// Upstream report identifier.
    pub report_id: String,
    /// `true` when the candidate matched an existing finding (TF-IDF
    /// cosine ≥ 0.85) and was *not* minted as a new finding.
    pub deduplicated: bool,
    /// Id of the existing finding the candidate matched against — set
    /// only when `deduplicated = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_existing_id: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn upsert_request_debug_redacts_secrets() {
        let req = BugBountyConfigUpsertRequest {
            platform: "hackerone".into(),
            program_handle: "acme".into(),
            api_username: Some("ops".into()),
            api_token: SecretString::from("h1-token-shh".to_owned()),
            webhook_secret: SecretString::from("hmac-shh".to_owned()),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("h1-token-shh"), "leaked: {dbg}");
        assert!(!dbg.contains("hmac-shh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("ops"));
    }

    #[test]
    fn upsert_request_deserialises_minimum_payload() {
        let s = r#"{
            "platform": "bugcrowd",
            "program_handle": "acme-public",
            "api_token": "bc-token",
            "webhook_secret": "hmac-secret"
        }"#;
        let req: BugBountyConfigUpsertRequest = serde_json::from_str(s).expect("deserialise");
        assert_eq!(req.platform, "bugcrowd");
        assert_eq!(req.program_handle, "acme-public");
        assert!(req.api_username.is_none());
        assert_eq!(req.api_token.expose_secret(), "bc-token");
        assert_eq!(req.webhook_secret.expose_secret(), "hmac-secret");
    }

    #[test]
    fn config_view_omits_optional_fields_when_empty() {
        let v = BugBountyConfigView {
            tenant_id: "t-1".into(),
            platform: "bugcrowd".into(),
            program_handle: "acme".into(),
            api_username: None,
            token_secret_path: "tenants/t-1/bb/bugcrowd/acme/token".into(),
            webhook_secret_path: "tenants/t-1/bb/bugcrowd/acme/webhook".into(),
            created_at: "2027-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&v).expect("serialise");
        assert!(json.contains("\"token_secret_path\""));
        assert!(json.contains("\"webhook_secret_path\""));
        assert!(!json.contains("api_username"));
    }

    #[test]
    fn push_request_round_trips() {
        let s = r#"{
            "platform": "hackerone",
            "program_handle": "acme",
            "finding": {
                "id": "f-1",
                "title": "RCE on /upload",
                "description": "SSTI via template engine",
                "severity": "critical"
            }
        }"#;
        let req: BugBountyPushRequest = serde_json::from_str(s).expect("deserialise");
        assert_eq!(req.platform, "hackerone");
        assert_eq!(req.finding.id, "f-1");
        assert_eq!(req.finding.severity, "critical");
    }

    #[test]
    fn inbound_outcome_serialises_dedup_when_set() {
        let v = BugBountyInboundOutcomeView {
            platform: "hackerone".into(),
            source: "bugbounty.hackerone.researcher_42".into(),
            researcher_id: "42".into(),
            report_id: "98765".into(),
            deduplicated: true,
            dedup_existing_id: Some("f-existing".into()),
        };
        let json = serde_json::to_string(&v).expect("serialise");
        assert!(json.contains("\"deduplicated\":true"));
        assert!(json.contains("\"dedup_existing_id\":\"f-existing\""));
    }

    #[test]
    fn inbound_outcome_omits_dedup_id_when_unique() {
        let v = BugBountyInboundOutcomeView {
            platform: "hackerone".into(),
            source: "bugbounty.hackerone.researcher_42".into(),
            researcher_id: "42".into(),
            report_id: "98765".into(),
            deduplicated: false,
            dedup_existing_id: None,
        };
        let json = serde_json::to_string(&v).expect("serialise");
        assert!(json.contains("\"deduplicated\":false"));
        assert!(!json.contains("dedup_existing_id"));
    }
}
