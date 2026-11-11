//! Commercial threat-intel feed abstraction.
//!
//! Adds a uniform [`CommercialIntelFeed`] trait that paid-feed adapters
//! (Mandiant, `CrowdStrike`, ...) implement. The adapters live in sibling
//! modules ([`crate::mandiant`], [`crate::crowdstrike`]) — this module
//! only defines the shared surface.
//!
//! ## Design
//!
//! Commercial providers ship richer indicator metadata than free STIX
//! feeds: TLP markings, multi-source attribution, and TTP references back
//! to their own incident/cluster IDs. We capture that in
//! [`EnrichedIndicator`] without trying to be a full superset of every
//! vendor's schema — the adapters keep a "schema-light" parse, extracting
//! the fields we promise downstream and ignoring the rest.
//!
//! Per-tenant license verification, scheduling, and persistence are
//! deliberately out of scope; this layer only models the transport.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::indicator::IndicatorKind;

/// Traffic Light Protocol marking attached to a commercial indicator.
///
/// Defaults to [`Tlp::Amber`] when the source omits the field — most
/// commercial feeds treat their output as TLP:AMBER by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tlp {
    /// TLP:WHITE — disclosure unlimited.
    White,
    /// TLP:GREEN — community-wide sharing allowed.
    Green,
    /// TLP:AMBER — limited disclosure, restricted to participants.
    Amber,
    /// TLP:RED — not for disclosure, restricted to participants only.
    Red,
}

impl Tlp {
    /// Parse a TLP marking from a free-form vendor string. Tolerates
    /// `tlp:amber`, `TLP-RED`, `green`, etc. Unknown values fall back to
    /// [`Tlp::Amber`] (the more-restrictive of the common defaults).
    #[must_use]
    pub fn parse_lenient(raw: &str) -> Self {
        let normalized = raw
            .trim()
            .trim_start_matches("tlp:")
            .trim_start_matches("TLP:")
            .trim_start_matches("tlp-")
            .trim_start_matches("TLP-")
            .to_ascii_lowercase();
        match normalized.as_str() {
            "white" | "clear" => Self::White,
            "green" => Self::Green,
            "red" => Self::Red,
            _ => Self::Amber,
        }
    }
}

/// A commercial threat-intel indicator with enrichment metadata.
///
/// Mirrors the subset of fields every commercial provider supplies. The
/// `sources` vector lets us preserve attribution when multiple providers
/// agree on the same observable, and `ttp_refs` links back to the
/// vendor's MITRE ATT&CK techniques or proprietary cluster IDs (e.g.
/// FIN7, BEAR-LIKE-1234).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichedIndicator {
    /// Observable kind (reused from the free-feed normalization).
    pub kind: IndicatorKind,
    /// Literal observable value (lowercased hashes, normalized URLs, …).
    pub value: String,
    /// Traffic Light Protocol marking.
    pub tlp: Tlp,
    /// Confidence in 0..=100. `None` when the source omitted it.
    pub confidence: Option<u8>,
    /// Provider IDs that supplied or corroborated this indicator
    /// (e.g. `["mandiant"]`, `["crowdstrike", "mandiant"]`).
    pub sources: Vec<String>,
    /// Earliest observation timestamp from the provider.
    pub first_seen: OffsetDateTime,
    /// Latest observation timestamp from the provider.
    pub last_seen: OffsetDateTime,
    /// TTP references — MITRE technique IDs (`T1059.001`) or vendor
    /// cluster identifiers, captured verbatim.
    pub ttp_refs: Vec<String>,
}

/// Errors surfaced by [`CommercialIntelFeed`] implementations.
#[derive(Debug, Error)]
pub enum IntelError {
    /// Underlying HTTP transport failure.
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),
    /// Server responded with a non-2xx status that the adapter could not
    /// recover from (after any internal retry policy).
    #[error("{vendor} returned status {status}")]
    Status {
        /// Vendor identifier (e.g. `"mandiant"`, `"crowdstrike"`).
        vendor: &'static str,
        /// HTTP status code surfaced.
        status: u16,
    },
    /// Authentication failed (401/403 after refresh retry).
    #[error("{vendor} authentication failed")]
    Unauthorized {
        /// Vendor identifier.
        vendor: &'static str,
    },
    /// Response body could not be decoded.
    #[error("{vendor} response decode error: {message}")]
    Decode {
        /// Vendor identifier.
        vendor: &'static str,
        /// Human-readable explanation; provider payloads NEVER appear
        /// here, only structural messages.
        message: String,
    },
    /// Configuration was rejected at construction time.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// A URL could not be constructed from configured base + path.
    #[error("invalid URL: {0}")]
    Url(String),
}

impl IntelError {
    /// Build a [`IntelError::Decode`] from any [`std::fmt::Display`] without
    /// echoing provider payload back into the message.
    pub(crate) fn decode<E: std::fmt::Display>(vendor: &'static str, err: E) -> Self {
        Self::Decode {
            vendor,
            message: err.to_string(),
        }
    }
}

/// Uniform surface implemented by every commercial intel feed adapter.
///
/// Adapters are constructed disabled-by-default; the caller is expected
/// to gate construction behind `enabled: true` + presence of credentials
/// in their configuration before invoking the trait.
#[async_trait]
pub trait CommercialIntelFeed: Send + Sync {
    /// Stable provider identifier used in `sources`, metrics labels, and
    /// log fields. Must be ASCII lowercase, e.g. `"mandiant"`.
    fn provider_id(&self) -> &'static str;

    /// Fetch indicators published or updated on/after `since`.
    ///
    /// Implementations must paginate internally and return the full set.
    /// Authentication, retry, and pagination are the adapter's
    /// responsibility — the caller only sees a flat `Vec`.
    async fn fetch_since(
        &self,
        since: OffsetDateTime,
    ) -> Result<Vec<EnrichedIndicator>, IntelError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tlp_parse_lenient_handles_common_spellings() {
        assert_eq!(Tlp::parse_lenient("white"), Tlp::White);
        assert_eq!(Tlp::parse_lenient("tlp:green"), Tlp::Green);
        assert_eq!(Tlp::parse_lenient("TLP:RED"), Tlp::Red);
        assert_eq!(Tlp::parse_lenient("TLP-AMBER"), Tlp::Amber);
        assert_eq!(Tlp::parse_lenient("clear"), Tlp::White);
        // Unknown defaults to Amber.
        assert_eq!(Tlp::parse_lenient("PURPLE"), Tlp::Amber);
        assert_eq!(Tlp::parse_lenient(""), Tlp::Amber);
    }

    #[test]
    fn enriched_indicator_round_trips_through_json() {
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let ind = EnrichedIndicator {
            kind: IndicatorKind::Domain,
            value: "evil.example".to_string(),
            tlp: Tlp::Amber,
            confidence: Some(85),
            sources: vec!["mandiant".to_string()],
            first_seen: ts,
            last_seen: ts,
            ttp_refs: vec!["T1071.001".to_string()],
        };
        let json = serde_json::to_string(&ind).unwrap();
        let back: EnrichedIndicator = serde_json::from_str(&json).unwrap();
        assert_eq!(ind, back);
    }

    #[test]
    fn intel_error_decode_never_echoes_raw_payload() {
        let err = IntelError::decode("mandiant", "missing field `value`");
        let msg = format!("{err}");
        assert!(msg.contains("mandiant"));
        assert!(msg.contains("decode error"));
    }
}
