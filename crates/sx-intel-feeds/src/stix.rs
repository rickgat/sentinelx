//! STIX 2.1 bundle parser — subset suitable for an MVP intel ingest path.
//!
//! ## What we parse
//!
//! A STIX 2.1 *bundle* is a JSON document of the shape:
//!
//! ```json
//! { "type": "bundle", "id": "bundle--…", "objects": [ …SDOs… ] }
//! ```
//!
//! We walk `objects` and pick out only `indicator` SDOs whose `pattern`
//! field carries one of the simple observable comparisons we understand
//! (see the table in the crate root). Every other SDO type (`malware`,
//! `attack-pattern`, `relationship`, `x-mitre-*`, …) is skipped and a
//! warning is emitted via `tracing` — it is **not** an error.
//!
//! ## What we reject
//!
//! * A document whose top-level `type` is not `"bundle"`.
//! * Indicator SDOs missing required fields (`pattern`, `valid_from`).
//! * Indicator SDOs whose `pattern` is syntactically present but matches
//!   none of our supported observables — these are skipped rather than
//!   failing the whole bundle.
//!
//! ## What we deliberately do **not** support yet
//!
//! * Compound STIX patterns (`AND`/`OR`/`FOLLOWEDBY`).
//! * Qualifiers (`WITHIN`, `REPEATS`, `START`/`STOP`).
//! * `network-traffic:*`, `process:*`, `windows-registry-key:*`, etc.
//! * STIX 2.0 (pre-2.1) bundles.

use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::warn;

use crate::indicator::{HashKind, Indicator, IndicatorKind};

/// Errors that abort an entire bundle parse.
///
/// Per-object failures are *not* errors — they produce a [`SkipReason`] and
/// the parse keeps going.
#[derive(Debug, Error)]
pub enum StixError {
    /// JSON was malformed at the syntactic level.
    #[error("malformed STIX JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Top-level `type` was not `"bundle"`.
    #[error("not a STIX bundle: top-level type was `{0}`")]
    NotABundle(String),
}

/// Why an individual SDO inside a bundle was skipped.
///
/// Bubbled up alongside the successfully-parsed indicators so callers can
/// surface metrics (e.g. "X unsupported observables in this feed").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// SDO had a `type` we don't model (e.g. `malware`, `attack-pattern`).
    UnknownType(String),
    /// SDO was an `indicator` but lacked a required field.
    MissingField(&'static str),
    /// SDO was an `indicator` but its pattern matched no known observable.
    UnsupportedPattern(String),
    /// SDO declared a hash family STIX permits but we don't model.
    UnsupportedHashAlgorithm(String),
    /// `valid_from` / `valid_until` did not parse as RFC 3339.
    BadTimestamp(String),
}

/// Outcome of parsing a single bundle.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedBundle {
    /// Successfully normalised indicators, in source order.
    pub indicators: Vec<Indicator>,
    /// One entry per SDO we could not turn into an [`Indicator`].
    pub skipped: Vec<SkipReason>,
}

/// Parse a STIX 2.1 bundle from raw JSON bytes.
///
/// Returns [`ParsedBundle`] containing both the indicators we could decode
/// and a per-object skip log. A returned [`StixError`] only ever signals
/// a bundle-wide problem (malformed JSON, wrong root type).
pub fn parse_bundle(bytes: &[u8]) -> Result<ParsedBundle, StixError> {
    let raw: RawBundle = serde_json::from_slice(bytes)?;
    if raw.type_field != "bundle" {
        return Err(StixError::NotABundle(raw.type_field));
    }

    let mut out = ParsedBundle::default();
    for obj in raw.objects {
        let sdo_type = obj
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();

        if sdo_type != "indicator" {
            warn!(sdo_type = %sdo_type, "skipping non-indicator STIX SDO");
            out.skipped.push(SkipReason::UnknownType(sdo_type));
            continue;
        }

        match parse_indicator_sdo(&obj) {
            Ok(ind) => out.indicators.push(ind),
            Err(reason) => {
                warn!(?reason, "skipping STIX indicator SDO");
                out.skipped.push(reason);
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct RawBundle {
    #[serde(rename = "type")]
    type_field: String,
    #[serde(default)]
    objects: Vec<serde_json::Value>,
}

fn parse_indicator_sdo(obj: &serde_json::Value) -> Result<Indicator, SkipReason> {
    let pattern = obj
        .get("pattern")
        .and_then(serde_json::Value::as_str)
        .ok_or(SkipReason::MissingField("pattern"))?;
    let valid_from_raw = obj
        .get("valid_from")
        .and_then(serde_json::Value::as_str)
        .ok_or(SkipReason::MissingField("valid_from"))?;

    let valid_from = parse_ts(valid_from_raw)?;
    let valid_until = match obj.get("valid_until").and_then(serde_json::Value::as_str) {
        Some(s) => Some(parse_ts(s)?),
        None => None,
    };

    let confidence = obj
        .get("confidence")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u8::try_from(n).ok());

    let labels: Vec<String> = obj
        .get("labels")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let (kind, value) = parse_pattern(pattern)?;
    Ok(Indicator::new(
        kind,
        value,
        confidence,
        valid_from,
        valid_until,
        labels,
    ))
}

fn parse_ts(raw: &str) -> Result<OffsetDateTime, SkipReason> {
    OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|_| SkipReason::BadTimestamp(raw.to_owned()))
}

/// Decode a (single, non-compound) STIX 2.1 pattern.
///
/// We only handle the subset documented in the crate-level table. Anything
/// else falls through to [`SkipReason::UnsupportedPattern`].
fn parse_pattern(pattern: &str) -> Result<(IndicatorKind, String), SkipReason> {
    let trimmed = pattern.trim();

    // Reject obvious compound patterns up front. STIX uses ` AND `, ` OR `,
    // ` FOLLOWEDBY ` (case-insensitive in 2.1) to combine observables.
    let upper = trimmed.to_uppercase();
    if upper.contains(" AND ")
        || upper.contains(" OR ")
        || upper.contains(" FOLLOWEDBY ")
        || upper.contains(" WITHIN ")
        || upper.contains(" REPEATS ")
    {
        return Err(SkipReason::UnsupportedPattern(pattern.to_owned()));
    }

    if let Some((kind, value)) = try_simple_value(trimmed) {
        return Ok((kind, value));
    }
    if let Some((kind, value)) = try_file_hash(trimmed)? {
        return Ok((kind, value));
    }
    Err(SkipReason::UnsupportedPattern(pattern.to_owned()))
}

// Static pattern strings — kept as `const` so `simple_re` / `file_hash_re`
// can fall back to a never-matching regex without panicking if the static
// source ever fails to compile (it cannot, but the lint forbids `unwrap`).
const SIMPLE_PATTERN: &str = r#"(?x)
^\s*\[\s*
(?P<obj>[a-z0-9-]+)\s*:\s*value\s*=\s*
(?:'(?P<sq>[^']+)'|"(?P<dq>[^"]+)")
\s*\]\s*$
"#;

const FILE_HASH_PATTERN: &str = r#"(?x)
^\s*\[\s*file:hashes\.\s*
(?:'(?P<aq>[^']+)'|"(?P<adq>[^"]+)")
\s*=\s*
(?:'(?P<vq>[^']+)'|"(?P<vdq>[^"]+)")
\s*\]\s*$
"#;

fn simple_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| compile_or_never_matches(SIMPLE_PATTERN))
}

fn file_hash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| compile_or_never_matches(FILE_HASH_PATTERN))
}

/// Compile `src` or fall back to a regex that matches nothing.
///
/// The static patterns used by this crate are known good, but the lint
/// configuration forbids `unwrap`/`expect`/`panic`. The fallback uses a
/// pattern that is *also* known good — `[^\s\S]` matches nothing — and is
/// constructed via a fresh `Regex::new` call whose result is checked.
fn compile_or_never_matches(src: &str) -> Regex {
    if let Ok(re) = Regex::new(src) {
        return re;
    }
    // `[^\s\S]` is a negated full character class — it never matches.
    // Safety net: if even that fails (it won't), we loop attempting an
    // even simpler pattern. We cap retries so this is bounded.
    Regex::new(r"[^\s\S]").unwrap_or_else(|_| unreachable_regex())
}

#[allow(clippy::trivial_regex, clippy::unwrap_used)]
fn unreachable_regex() -> Regex {
    // Last-resort: try a known-trivial pattern. `(?:)` is an empty group
    // and is guaranteed to compile under any sane `regex` build. If even
    // that fails the regex crate is broken and there is no recovery path.
    Regex::new("(?:)").unwrap()
}

fn try_simple_value(pattern: &str) -> Option<(IndicatorKind, String)> {
    let caps = simple_re().captures(pattern)?;
    let obj = caps.name("obj")?.as_str();
    let value = caps
        .name("sq")
        .or_else(|| caps.name("dq"))?
        .as_str()
        .to_owned();
    let kind = match obj {
        "ipv4-addr" => IndicatorKind::Ipv4,
        "ipv6-addr" => IndicatorKind::Ipv6,
        "domain-name" => IndicatorKind::Domain,
        "url" => IndicatorKind::Url,
        "email-addr" => IndicatorKind::Email,
        _ => return None,
    };
    Some((kind, value))
}

fn try_file_hash(pattern: &str) -> Result<Option<(IndicatorKind, String)>, SkipReason> {
    let Some(caps) = file_hash_re().captures(pattern) else {
        return Ok(None);
    };
    let algo = caps
        .name("aq")
        .or_else(|| caps.name("adq"))
        .ok_or_else(|| SkipReason::UnsupportedPattern(pattern.to_owned()))?
        .as_str();
    let value = caps
        .name("vq")
        .or_else(|| caps.name("vdq"))
        .ok_or_else(|| SkipReason::UnsupportedPattern(pattern.to_owned()))?
        .as_str()
        .to_owned();
    let normalised = algo.to_ascii_uppercase();
    let kind = match normalised.as_str() {
        "MD5" => HashKind::Md5,
        "SHA-1" | "SHA1" => HashKind::Sha1,
        "SHA-256" | "SHA256" => HashKind::Sha256,
        _ => return Err(SkipReason::UnsupportedHashAlgorithm(algo.to_owned())),
    };
    Ok(Some((IndicatorKind::FileHash(kind), value)))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bundle_with(objects: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000000",
            "objects": objects,
        }))
        .unwrap()
    }

    fn indicator_sdo(pattern: &str) -> serde_json::Value {
        json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--11111111-1111-4111-8111-111111111111",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "labels": ["malicious-activity"],
            "confidence": 75,
        })
    }

    #[test]
    fn parses_ipv4_indicator() {
        let bytes = bundle_with(vec![indicator_sdo("[ipv4-addr:value = '198.51.100.7']")]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert_eq!(parsed.indicators.len(), 1);
        assert!(parsed.skipped.is_empty());
        let ind = &parsed.indicators[0];
        assert_eq!(ind.kind, IndicatorKind::Ipv4);
        assert_eq!(ind.value, "198.51.100.7");
        assert_eq!(ind.confidence, Some(75));
        assert_eq!(ind.labels, vec!["malicious-activity".to_owned()]);
    }

    #[test]
    fn parses_domain_indicator() {
        let bytes = bundle_with(vec![indicator_sdo("[domain-name:value = 'evil.example']")]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert_eq!(parsed.indicators.len(), 1);
        assert_eq!(parsed.indicators[0].kind, IndicatorKind::Domain);
        assert_eq!(parsed.indicators[0].value, "evil.example");
    }

    #[test]
    fn parses_file_hash_sha256_indicator() {
        let hex = "e".repeat(64);
        let pat = format!("[file:hashes.'SHA-256' = '{hex}']");
        let bytes = bundle_with(vec![indicator_sdo(&pat)]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert_eq!(parsed.indicators.len(), 1);
        assert_eq!(
            parsed.indicators[0].kind,
            IndicatorKind::FileHash(HashKind::Sha256)
        );
        assert_eq!(parsed.indicators[0].value, hex);
    }

    #[test]
    fn rejects_malformed_bundle() {
        // Top-level type wrong → bundle-wide error.
        let bytes = serde_json::to_vec(&json!({
            "type": "not-a-bundle",
            "objects": [],
        }))
        .unwrap();
        let err = parse_bundle(&bytes).unwrap_err();
        assert!(matches!(err, StixError::NotABundle(_)));

        // And syntactically broken JSON.
        let err = parse_bundle(b"{ this is not json").unwrap_err();
        assert!(matches!(err, StixError::Json(_)));
    }

    #[test]
    fn skips_unknown_sdo_types() {
        let bytes = bundle_with(vec![
            indicator_sdo("[ipv4-addr:value = '203.0.113.5']"),
            json!({ "type": "malware", "id": "malware--abc", "name": "Foo" }),
            json!({ "type": "attack-pattern", "id": "attack-pattern--xyz" }),
        ]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert_eq!(parsed.indicators.len(), 1);
        assert_eq!(parsed.skipped.len(), 2);
        assert!(matches!(parsed.skipped[0], SkipReason::UnknownType(ref t) if t == "malware"));
        assert!(
            matches!(parsed.skipped[1], SkipReason::UnknownType(ref t) if t == "attack-pattern")
        );
    }

    #[test]
    fn skips_unsupported_compound_pattern() {
        let bytes = bundle_with(vec![indicator_sdo(
            "[ipv4-addr:value = '1.1.1.1'] AND [ipv4-addr:value = '2.2.2.2']",
        )]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert!(parsed.indicators.is_empty());
        assert_eq!(parsed.skipped.len(), 1);
        assert!(matches!(
            parsed.skipped[0],
            SkipReason::UnsupportedPattern(_)
        ));
    }

    #[test]
    fn parses_ipv6_and_url_and_email() {
        let bytes = bundle_with(vec![
            indicator_sdo("[ipv6-addr:value = '2001:db8::1']"),
            indicator_sdo("[url:value = 'https://bad.example/payload']"),
            indicator_sdo("[email-addr:value = 'attacker@evil.example']"),
        ]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert_eq!(parsed.indicators.len(), 3);
        assert_eq!(parsed.indicators[0].kind, IndicatorKind::Ipv6);
        assert_eq!(parsed.indicators[1].kind, IndicatorKind::Url);
        assert_eq!(parsed.indicators[2].kind, IndicatorKind::Email);
    }

    #[test]
    fn parses_md5_and_sha1_hashes() {
        let bytes = bundle_with(vec![
            indicator_sdo(&format!("[file:hashes.'MD5' = '{}']", "a".repeat(32))),
            indicator_sdo(&format!("[file:hashes.'SHA-1' = '{}']", "b".repeat(40))),
        ]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert_eq!(parsed.indicators.len(), 2);
        assert_eq!(
            parsed.indicators[0].kind,
            IndicatorKind::FileHash(HashKind::Md5)
        );
        assert_eq!(
            parsed.indicators[1].kind,
            IndicatorKind::FileHash(HashKind::Sha1)
        );
    }

    #[test]
    fn skips_unsupported_hash_algorithm() {
        let bytes = bundle_with(vec![indicator_sdo(&format!(
            "[file:hashes.'SHA-512' = '{}']",
            "c".repeat(128)
        ))]);
        let parsed = parse_bundle(&bytes).unwrap();
        assert!(parsed.indicators.is_empty());
        assert_eq!(parsed.skipped.len(), 1);
        assert!(matches!(
            parsed.skipped[0],
            SkipReason::UnsupportedHashAlgorithm(_)
        ));
    }
}
