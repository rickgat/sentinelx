//! Autonomy DTOs.
//!
//! Wire-shape request and response types for the three autonomy
//! endpoints:
//!
//! - `POST /v1/autonomy/pr` — propose an auto-remediation pull request.
//! - `POST /v1/autonomy/threat-network` — submit anonymised threat
//!   observations.
//! - `POST /v1/autonomy/validation/schedules` — schedule a continuous
//!   validation engine.
//! - `DELETE /v1/autonomy/validation/schedules/{engine_id}` — cancel a
//!   scheduled engine (uses no request body).
//!
//! Validation lives entirely in this module so the controller layer is
//! free to focus on RBAC and port dispatch.

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use validator::{Validate, ValidationError};

/// `POST /v1/autonomy/pr` request body.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ProposePrRequestView {
    /// Tenant uuid the request runs under.
    #[validate(length(min = 1))]
    pub tenant_id: String,
    /// Finding the proposed PR addresses.
    #[validate(length(min = 1))]
    pub finding_id: String,
    /// GitHub repository owner. Restricted to `[A-Za-z0-9._-]+` to match
    /// GitHub's own slug grammar.
    #[validate(custom(function = "validate_github_slug"))]
    pub repo_owner: String,
    /// GitHub repository name. Same grammar as `repo_owner`.
    #[validate(custom(function = "validate_github_slug"))]
    pub repo_name: String,
    /// Target branch — refused if it matches the autonomy
    /// protected-branch list inside the adapter.
    #[validate(length(min = 1, max = 100))]
    pub target_branch: String,
    /// PR title.
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    /// PR description (becomes the augmented PR body).
    #[validate(length(min = 1))]
    pub description: String,
    /// File changes that make up the proposed diff. Must be non-empty.
    #[validate(length(min = 1))]
    #[validate(nested)]
    pub changes: Vec<ProposePrChangeView>,
}

/// One file change inside [`ProposePrRequestView`].
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ProposePrChangeView {
    /// Repo-relative file path.
    #[validate(length(min = 1, max = 1024))]
    pub path: String,
    /// Full new file content (can be empty for deletions in future).
    pub new_content: String,
}

/// `POST /v1/autonomy/pr` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposePrResponseView {
    /// PR number assigned by GitHub.
    pub pull_request_number: u64,
    /// Canonical URL of the opened PR.
    pub url: String,
}

/// `POST /v1/autonomy/threat-network` request body.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SubmitThreatRequestView {
    /// Tenant uuid (consent owner).
    #[validate(length(min = 1))]
    pub tenant_id: String,
    /// RFC 3339 timestamp of when the tenant recorded their consent.
    #[validate(custom(function = "validate_rfc3339"))]
    pub consented_at: String,
    /// Sharing scope — one of `vulnerability_frequency`, `ioc_match`.
    #[validate(custom(function = "validate_scope"))]
    pub scope: String,
    /// Observations to submit.
    #[validate(length(min = 1))]
    #[validate(nested)]
    pub observations: Vec<ThreatObservationView>,
}

/// One observation inside [`SubmitThreatRequestView`].
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ThreatObservationView {
    /// CVE identifier observed.
    #[validate(length(min = 1, max = 64))]
    pub cve_id: String,
    /// Coarse asset-kind classifier (hashed before transmission).
    #[validate(length(min = 1, max = 256))]
    pub asset_kind: String,
    /// Count of assets in this category exhibiting the CVE. Must be > 0.
    #[validate(range(min = 1))]
    pub count: u32,
}

/// `POST /v1/autonomy/threat-network` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitThreatResponseView {
    /// Whether the upstream ledger accepted the batch.
    pub accepted: bool,
    /// Number of observations submitted.
    pub submitted_count: u32,
}

/// `POST /v1/autonomy/validation/schedules` request body.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ScheduleValidationRequestView {
    /// Tenant uuid.
    #[validate(length(min = 1))]
    pub tenant_id: String,
    /// Engagement uuid.
    #[validate(length(min = 1))]
    pub engagement_id: String,
    /// Interval between ticks, in seconds. Bounded to `60..=86_400`.
    #[validate(range(min = 60, max = 86_400))]
    pub interval_secs: u64,
    /// Technique ids to dispatch every tick.
    #[validate(length(min = 1))]
    pub technique_ids: Vec<String>,
}

/// `POST /v1/autonomy/validation/schedules` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleValidationResponseView {
    /// Opaque engine identifier; supply this to the `DELETE` route to
    /// cancel.
    pub engine_id: String,
}

/// Accept only the GitHub-compatible slug grammar `^[A-Za-z0-9._-]+$`.
fn validate_github_slug(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("github_slug_empty"));
    }
    let ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(ValidationError::new("github_slug_invalid"))
    }
}

/// Parse `value` as an RFC 3339 timestamp; reject otherwise.
fn validate_rfc3339(value: &str) -> Result<(), ValidationError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| ValidationError::new("invalid_rfc3339"))
}

/// Accept only the two threat-network sharing scopes the public API
/// surfaces today.
fn validate_scope(value: &str) -> Result<(), ValidationError> {
    match value {
        "vulnerability_frequency" | "ioc_match" => Ok(()),
        _ => Err(ValidationError::new("invalid_scope")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_pr() -> ProposePrRequestView {
        ProposePrRequestView {
            tenant_id: "t".into(),
            finding_id: "f".into(),
            repo_owner: "acme".into(),
            repo_name: "site".into(),
            target_branch: "develop".into(),
            title: "fix".into(),
            description: "body".into(),
            changes: vec![ProposePrChangeView {
                path: "a".into(),
                new_content: "x\n".into(),
            }],
        }
    }

    #[test]
    fn pr_accepts_well_formed_request() {
        assert!(baseline_pr().validate().is_ok());
    }

    #[test]
    fn pr_rejects_invalid_repo_owner_chars() {
        let mut req = baseline_pr();
        req.repo_owner = "bad owner!".into();
        let err = req.validate().unwrap_err();
        let field_errors = err.field_errors();
        assert!(field_errors.contains_key("repo_owner"));
    }

    #[test]
    fn pr_rejects_invalid_repo_name_chars() {
        let mut req = baseline_pr();
        req.repo_name = "n@me".into();
        assert!(req.validate().is_err());
    }

    #[test]
    fn pr_accepts_slug_with_dots_dashes_underscores() {
        let mut req = baseline_pr();
        req.repo_owner = "a.b-c_d".into();
        req.repo_name = "x.y-z_0".into();
        assert!(req.validate().is_ok());
    }

    #[test]
    fn pr_rejects_empty_target_branch() {
        let mut req = baseline_pr();
        req.target_branch = String::new();
        assert!(req.validate().is_err());
    }

    #[test]
    fn pr_rejects_target_branch_over_100_chars() {
        let mut req = baseline_pr();
        req.target_branch = "x".repeat(101);
        assert!(req.validate().is_err());
    }

    #[test]
    fn pr_accepts_target_branch_at_max() {
        let mut req = baseline_pr();
        req.target_branch = "x".repeat(100);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn pr_rejects_empty_changes() {
        let mut req = baseline_pr();
        req.changes.clear();
        assert!(req.validate().is_err());
    }

    fn baseline_threat() -> SubmitThreatRequestView {
        SubmitThreatRequestView {
            tenant_id: "t".into(),
            consented_at: "2026-05-30T00:00:00Z".into(),
            scope: "vulnerability_frequency".into(),
            observations: vec![ThreatObservationView {
                cve_id: "CVE-2024-99999".into(),
                asset_kind: "web-server".into(),
                count: 1,
            }],
        }
    }

    #[test]
    fn threat_accepts_well_formed_request() {
        assert!(baseline_threat().validate().is_ok());
    }

    #[test]
    fn threat_accepts_both_scopes() {
        for scope in ["vulnerability_frequency", "ioc_match"] {
            let mut req = baseline_threat();
            req.scope = scope.into();
            assert!(req.validate().is_ok(), "expected {scope} to validate");
        }
    }

    #[test]
    fn threat_rejects_unknown_scope() {
        let mut req = baseline_threat();
        req.scope = "other".into();
        assert!(req.validate().is_err());
    }

    #[test]
    fn threat_rejects_invalid_consented_at() {
        let mut req = baseline_threat();
        req.consented_at = "not a date".into();
        assert!(req.validate().is_err());
    }

    #[test]
    fn threat_accepts_rfc3339_with_offset() {
        let mut req = baseline_threat();
        req.consented_at = "2026-05-30T12:34:56+07:00".into();
        assert!(req.validate().is_ok());
    }

    #[test]
    fn threat_rejects_zero_count() {
        let mut req = baseline_threat();
        req.observations[0].count = 0;
        assert!(req.validate().is_err());
    }

    #[test]
    fn threat_rejects_empty_observations() {
        let mut req = baseline_threat();
        req.observations.clear();
        assert!(req.validate().is_err());
    }

    fn baseline_schedule() -> ScheduleValidationRequestView {
        ScheduleValidationRequestView {
            tenant_id: "t".into(),
            engagement_id: "e".into(),
            interval_secs: 600,
            technique_ids: vec!["t1".into()],
        }
    }

    #[test]
    fn schedule_accepts_well_formed_request() {
        assert!(baseline_schedule().validate().is_ok());
    }

    #[test]
    fn schedule_rejects_interval_below_60() {
        let mut req = baseline_schedule();
        req.interval_secs = 59;
        assert!(req.validate().is_err());
    }

    #[test]
    fn schedule_rejects_interval_above_86400() {
        let mut req = baseline_schedule();
        req.interval_secs = 86_401;
        assert!(req.validate().is_err());
    }

    #[test]
    fn schedule_accepts_interval_at_bounds() {
        for secs in [60u64, 86_400u64] {
            let mut req = baseline_schedule();
            req.interval_secs = secs;
            assert!(req.validate().is_ok(), "expected {secs}s to validate");
        }
    }

    #[test]
    fn schedule_rejects_empty_techniques() {
        let mut req = baseline_schedule();
        req.technique_ids.clear();
        assert!(req.validate().is_err());
    }
}
