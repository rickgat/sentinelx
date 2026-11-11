//! AWS access-key id matcher.
//!
//! AWS access-key ids are 20-character uppercase alphanumeric strings
//! beginning with one of the well-known prefixes:
//!
//! - `AKIA` — long-lived IAM user access key.
//! - `ASIA` — STS temporary access key.
//! - `AIDA` — IAM user identifier.
//! - `AROA` — IAM role identifier.
//! - `ANPA` / `ANVA` — managed-policy / VPC identifiers (still secret-like).
//!
//! The matcher anchors on word boundaries to avoid splitting mid-token.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b").unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            Regex::new(r"AKIA[A-Z0-9]{16}").unwrap()
        })
    })
}

/// Scan `text` for AWS access-key ids.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::AwsAccessKey,
            offset: m.start(),
            length: s.len(),
            redacted_preview: redact(s),
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn finds_akia_token() {
        let t = "key=AKIAIOSFODNN7EXAMPLE rest";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::AwsAccessKey);
        assert_eq!(
            &t[m[0].offset..m[0].offset + m[0].length],
            "AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[test]
    fn finds_asia_token() {
        let t = "session: ASIAEXAMPLETOKENXYZ1";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::AwsAccessKey);
    }

    #[test]
    fn rejects_short_runs() {
        // 19 chars after prefix — too short.
        assert!(scan("AKIAIOSFODNN7EXAMPL").is_empty());
        // No prefix at all.
        assert!(scan("XXXXIOSFODNN7EXAMPLE").is_empty());
    }

    #[test]
    fn rejects_lowercase() {
        // AWS keys are uppercase only.
        assert!(scan("akiaiosfodnn7example").is_empty());
    }
}
