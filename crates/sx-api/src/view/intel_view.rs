//! Threat-intelligence indicator check DTOs.
//!
//! Backs `POST /v1/intel/check`, which the SOC tooling calls to ask
//! "is this indicator (ip / domain / url / hash) known to SentinelX's
//! intel store?". The wire shape is intentionally stringly-typed so the
//! API crate never has to depend on the concrete enums in `sx-intel-ioc`
//! or `sx-intel-feeds` — the adapter layer parses [`Self::kind`] into
//! whichever enum variant it needs.
//!
//! ## Accepted `kind` values
//!
//! | Wire token       | Semantic                                |
//! |------------------|-----------------------------------------|
//! | `ipv4`           | IPv4 literal (e.g. `198.51.100.7`)      |
//! | `ipv6`           | IPv6 literal (e.g. `2001:db8::1`)       |
//! | `domain`         | Fully-qualified domain name             |
//! | `url`            | Absolute URL                            |
//! | `hash:sha256`    | SHA-256 hex digest (64 lowercase chars) |
//!
//! Anything else is rejected at the boundary with `422 Unprocessable`.
//! The validator runs before the controller is invoked, so the adapter
//! can assume the kind is well-formed.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/intel/check` request body.
///
/// Carries the indicator [`Self::kind`] (one of the strings in the table
/// at the module docs) and the raw [`Self::value`] payload — interpreted
/// according to the kind by the adapter.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct IntelCheckRequest {
    /// Indicator kind — must parse to one of `ipv4`, `ipv6`, `domain`,
    /// `url`, or `hash:sha256`. Validation runs at the extractor layer
    /// before the controller sees the request.
    #[validate(custom(function = "validate_intel_kind"))]
    pub kind: String,
    /// Raw indicator value — IP literal, FQDN, absolute URL, or
    /// lowercased hex digest. Bounded `[1, 2048]` so we never hash an
    /// empty string or an unreasonably large payload.
    #[validate(length(min = 1, max = 2048))]
    pub value: String,
}

/// `POST /v1/intel/check` response body.
///
/// `known = true` means the indicator hit the sharded bloom filter and
/// is treated as a probable IOC (the filter may produce false positives
/// bounded by its configured FPR — see [`sx_intel_ioc::DEFAULT_FPR`]).
/// `known = false` is authoritative: the filter never produces false
/// negatives.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntelCheckResponse {
    /// Whether the indicator is known to the IOC store.
    pub known: bool,
    /// Optional source / feed label the indicator was ingested from. The
    /// canned demo seed labels every entry with the same source string
    /// (`"sentinelx-canned"`); real STIX/TAXII ingest would propagate the
    /// upstream feed name verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional RFC 3339 timestamp the indicator was last observed at.
    /// `None` when the underlying bloom filter has no temporal metadata
    /// for the entry (which is the default for the canned demo seed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

/// Per-feed poll status projection.
///
/// Backs `GET /v1/intel/feeds`. Mirrors the `intel_feed_status` row
/// kept by the `sx-intel-feeds` orchestrator (see
/// [`sx_intel_feeds::FeedStatus`]) and the dashboard renders it as a
/// per-feed health table.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FeedStatusView {
    /// Operator-assigned feed identifier (e.g. `alienvault-otx`).
    pub name: String,
    /// Feed kind (`taxii`, `epss`, `kev`, `nvd`, `commercial`).
    pub kind: String,
    /// RFC 3339 timestamp of the most recent poll, success or failure.
    /// `None` when the feed has never been polled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_poll_at: Option<String>,
    /// RFC 3339 timestamp of the most recent successful poll. `None`
    /// when the feed has never succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    /// Number of errors observed in the trailing 24 h.
    pub error_count_24h: u32,
}

/// Validate that `value` is one of the canonical kind strings.
///
/// Centralised here so the controller and the adapter agree on the
/// accepted vocabulary; see the module docs for the full table.
fn validate_intel_kind(value: &str) -> Result<(), validator::ValidationError> {
    match value {
        "ipv4" | "ipv6" | "domain" | "url" | "hash:sha256" => Ok(()),
        _ => Err(validator::ValidationError::new("intel_kind")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_known_kinds() {
        for kind in ["ipv4", "ipv6", "domain", "url", "hash:sha256"] {
            assert!(
                validate_intel_kind(kind).is_ok(),
                "kind `{kind}` should be accepted"
            );
        }
    }

    #[test]
    fn rejects_unknown_kinds() {
        for kind in ["", "ipv5", "hash", "hash:md5", "HASH:SHA256", "garbage"] {
            assert!(
                validate_intel_kind(kind).is_err(),
                "kind `{kind}` should be rejected"
            );
        }
    }

    #[test]
    fn request_validator_runs_kind_check() {
        let bad = IntelCheckRequest {
            kind: "garbage".into(),
            value: "x".into(),
        };
        assert!(bad.validate().is_err());

        let ok = IntelCheckRequest {
            kind: "domain".into(),
            value: "evil.example".into(),
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn response_round_trips_through_json() {
        let resp = IntelCheckResponse {
            known: true,
            source: Some("sentinelx-canned".into()),
            last_seen: Some("1970-01-01T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: IntelCheckResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.known, resp.known);
        assert_eq!(back.source, resp.source);
        assert_eq!(back.last_seen, resp.last_seen);
    }

    #[test]
    fn response_omits_none_fields() {
        let resp = IntelCheckResponse {
            known: false,
            source: None,
            last_seen: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("source"));
        assert!(!json.contains("last_seen"));
        assert!(json.contains("\"known\":false"));
    }
}
