//! Pattern matchers, one per category.
//!
//! Every matcher returns a `Vec<DlpMatch>`; the orchestrator (see
//! [`crate::service`]) joins all categories into a single
//! [`crate::service::DlpScanResult`].
//!
//! Adding a new category is intentionally local:
//!
//! 1. Add a variant to [`DlpMatchKind`].
//! 2. Add a new sub-module with a `pub fn scan(text: &str) -> Vec<DlpMatch>`.
//! 3. Register it in [`crate::service::InMemoryDlpService::scan_text`].

use serde::{Deserialize, Serialize};

use crate::signals::SignalEvidence;

pub mod aws_access_key;
pub mod aws_secret_key;
pub mod credit_card;
pub mod email;
pub mod gcp_service_account;
pub mod github_pat;
pub mod jwt;
pub mod ner;
pub mod pem_private_key;
pub mod phone;
pub mod slack_token;
pub mod ssn_us;

/// Category emitted by a pattern matcher.
///
/// String form (in JSON) uses `snake_case` names that are stable across
/// versions: dashboards and integrations rely on these literal values.
///
/// `Default` is the first variant (`CreditCard`) and is only here to
/// support `DlpMatch::default()` (HIGH-004 added optional fusion fields,
/// which means callers occasionally want `..Default::default()` in
/// struct-update syntax). The default value is never observed in
/// practice — every emitter sets the kind explicitly.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DlpMatchKind {
    #[default]
    /// PAN / credit card number that passed both an issuer-prefix check
    /// and the Luhn checksum.
    CreditCard,
    /// US Social Security Number in `AAA-GG-SSSS` form, with the
    /// "never assigned" areas/groups stripped.
    SsnUs,
    /// AWS access key id (20 chars, `AKIA…` / `ASIA…`).
    AwsAccessKey,
    /// AWS secret access key heuristic (40-char base64 / `[A-Za-z0-9/+=]`).
    AwsSecretKey,
    /// GitHub personal access token (`ghp_…`, `gho_…`, `ghu_…`,
    /// `ghs_…`, `ghr_…`).
    GithubPat,
    /// JSON Web Token (three base64url segments separated by `.`).
    Jwt,
    /// PEM-encoded private key block.
    PemPrivateKey,
    /// Email address (RFC 5322 lite, common form).
    Email,
    /// North-American phone number (`+1 555-867-5309` or local form).
    Phone,
    /// GCP service-account JSON or private-key block.
    GcpServiceAccount,
    /// Slack bot / user / app token (`xoxb-…`, `xoxa-…`, `xoxp-…`, `xoxs-…`).
    SlackToken,
    /// Named-entity recognition hit (PERSON / ORG / LOC heuristic).
    NamedEntity,
}

impl DlpMatchKind {
    /// Short stable string used in logs / metrics labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreditCard => "credit_card",
            Self::SsnUs => "ssn_us",
            Self::AwsAccessKey => "aws_access_key",
            Self::AwsSecretKey => "aws_secret_key",
            Self::GithubPat => "github_pat",
            Self::Jwt => "jwt",
            Self::PemPrivateKey => "pem_private_key",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::GcpServiceAccount => "gcp_service_account",
            Self::SlackToken => "slack_token",
            Self::NamedEntity => "named_entity",
        }
    }
}

/// One match in a scanned payload.
///
/// HIGH-004 extended the shape with optional `confidence` + `signals`
/// fields. Both default to "no fusion ran" so legacy producers/consumers
/// keep working without code changes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DlpMatch {
    /// Category the match belongs to.
    pub kind: DlpMatchKind,
    /// Byte offset into the payload where the match begins.
    pub offset: usize,
    /// Length (bytes) of the matched run.
    pub length: usize,
    /// Redacted preview suitable for logs / dashboards.
    /// See [`crate::preview::redact`] for the exact rule.
    pub redacted_preview: String,
    /// Fused multi-signal confidence in `[0.0, 1.0]` (HIGH-004).
    /// `0.0` for callers that emit raw matches without running fusion;
    /// the orchestrator overwrites this on every emitted finding.
    #[serde(default)]
    pub confidence: f32,
    /// Per-signal explainability breakdown (HIGH-004). Empty when fusion
    /// has not been applied to the match yet.
    #[serde(default)]
    pub signals: Vec<SignalEvidence>,
    /// 1-indexed source line, for line-oriented inputs (TOP5-#3 Phase 3).
    /// When the scan source is a file / config / log the detector may
    /// resolve the byte [`Self::offset`] to a (line, column) pair; when
    /// the input is a raw payload (network body / envelope), it stays
    /// `None`. Passes through the wire type `DlpMatchView` onto the
    /// SARIF `region.startLine` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-indexed source column, paired with [`Self::line`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn kind_as_str_is_stable() {
        assert_eq!(DlpMatchKind::CreditCard.as_str(), "credit_card");
        assert_eq!(DlpMatchKind::SsnUs.as_str(), "ssn_us");
        assert_eq!(DlpMatchKind::AwsAccessKey.as_str(), "aws_access_key");
        assert_eq!(DlpMatchKind::AwsSecretKey.as_str(), "aws_secret_key");
        assert_eq!(DlpMatchKind::GithubPat.as_str(), "github_pat");
        assert_eq!(DlpMatchKind::Jwt.as_str(), "jwt");
        assert_eq!(DlpMatchKind::PemPrivateKey.as_str(), "pem_private_key");
    }

    #[test]
    fn kind_serialises_as_snake_case() {
        let v = serde_json::to_string(&DlpMatchKind::AwsAccessKey).expect("serialise");
        assert_eq!(v, "\"aws_access_key\"");
    }
}
