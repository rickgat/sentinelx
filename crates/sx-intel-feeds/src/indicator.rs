//! Normalised indicator record produced by both STIX and TAXII flows.
//!
//! Downstream consumers (the ingest pipeline, the graph store, the risk
//! engine) only need to depend on [`Indicator`] — they never have to know
//! whether the record originated from a STIX bundle parsed off disk or a
//! TAXII collection paged off the network.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// What kind of observable an [`Indicator`] carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum IndicatorKind {
    /// IPv4 address literal.
    Ipv4,
    /// IPv6 address literal.
    Ipv6,
    /// Fully qualified domain name.
    Domain,
    /// Absolute URL.
    Url,
    /// File hash with explicit algorithm tag.
    FileHash(HashKind),
    /// Email address (RFC 5321 mailbox-ish — full validation lives upstream).
    Email,
}

impl IndicatorKind {
    /// Canonical lowercase key for this kind, matching the `tenant_iocs.kind`
    /// CHECK domain (`ipv4`, `ipv6`, `domain`, `url`, `email`,
    /// `file_hash_md5`, `file_hash_sha1`, `file_hash_sha256`). Used by the
    /// Postgres repository adapter so the persisted key never drifts from the
    /// in-memory repository's `(tenant, kind, value)` dedupe key.
    #[must_use]
    pub const fn as_db_str(&self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::FileHash(HashKind::Md5) => "file_hash_md5",
            Self::FileHash(HashKind::Sha1) => "file_hash_sha1",
            Self::FileHash(HashKind::Sha256) => "file_hash_sha256",
        }
    }
}

/// Hash algorithms surfaced by STIX `file:hashes.*` patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashKind {
    /// MD5 digest (legacy, included for completeness).
    Md5,
    /// SHA-1 digest (legacy).
    Sha1,
    /// SHA-256 digest (preferred).
    Sha256,
}

/// A normalised threat-intel observable.
///
/// Fields mirror the STIX 2.1 `indicator` SDO subset we actually care about,
/// with the `pattern` already resolved into a strongly-typed `kind`/`value`
/// pair. Labels are STIX `labels` — opaque strings that downstream rule
/// engines may key off (e.g. `"malicious-activity"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    /// The kind of observable carried by `value`.
    pub kind: IndicatorKind,
    /// The literal observable (e.g. `198.51.100.7`, `evil.example`,
    /// `https://bad.example/p`, the lowercased hex digest, …).
    pub value: String,
    /// Confidence on `0..=100`, mirroring STIX's `confidence` field.
    /// `None` if the source omitted it.
    pub confidence: Option<u8>,
    /// Earliest time the indicator is considered valid (STIX `valid_from`).
    pub valid_from: OffsetDateTime,
    /// Latest time the indicator is considered valid (STIX `valid_until`).
    /// `None` if the source did not set an expiry.
    pub valid_until: Option<OffsetDateTime>,
    /// STIX `labels` carried verbatim.
    pub labels: Vec<String>,
}

impl Indicator {
    /// Construct a new indicator. Convenience for tests and adapter glue.
    #[must_use]
    pub fn new(
        kind: IndicatorKind,
        value: impl Into<String>,
        confidence: Option<u8>,
        valid_from: OffsetDateTime,
        valid_until: Option<OffsetDateTime>,
        labels: Vec<String>,
    ) -> Self {
        Self {
            kind,
            value: value.into(),
            confidence,
            valid_from,
            valid_until,
            labels,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn indicator_round_trips_through_json() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let ind = Indicator::new(
            IndicatorKind::FileHash(HashKind::Sha256),
            "a".repeat(64),
            Some(80),
            now,
            None,
            vec!["malicious-activity".to_owned()],
        );
        let json = serde_json::to_string(&ind).unwrap();
        let back: Indicator = serde_json::from_str(&json).unwrap();
        assert_eq!(ind, back);
    }

    #[test]
    fn indicator_kind_serializes_simple_variants_without_payload() {
        let json = serde_json::to_string(&IndicatorKind::Ipv4).unwrap();
        assert!(json.contains("ipv4"), "got {json}");
    }

    #[test]
    fn as_db_str_covers_every_kind_and_matches_sql_check_domain() {
        // These eight strings are the `tenant_iocs.kind` CHECK domain in
        // `20270101001200__create_tenant_iocs.sql`. If a new IndicatorKind
        // is added, this test forces a matching SQL migration + mapping.
        let cases = [
            (IndicatorKind::Ipv4, "ipv4"),
            (IndicatorKind::Ipv6, "ipv6"),
            (IndicatorKind::Domain, "domain"),
            (IndicatorKind::Url, "url"),
            (IndicatorKind::Email, "email"),
            (IndicatorKind::FileHash(HashKind::Md5), "file_hash_md5"),
            (IndicatorKind::FileHash(HashKind::Sha1), "file_hash_sha1"),
            (
                IndicatorKind::FileHash(HashKind::Sha256),
                "file_hash_sha256",
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_db_str(), expected, "mapping drift for {kind:?}");
        }
    }
}
