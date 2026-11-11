//! GitHub personal-access-token matcher.
//!
//! Modern GitHub tokens carry a stable prefix:
//!
//! - `ghp_` — personal access token (classic).
//! - `gho_` — OAuth user-to-server token.
//! - `ghu_` — GitHub App user-to-server token.
//! - `ghs_` — GitHub App server-to-server token.
//! - `ghr_` — GitHub App refresh token.
//!
//! Tokens issued since 2021 are 36–40 chars long after the prefix. We
//! accept 30–80 to absorb future format drift without missing real
//! exposures.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{30,80}\b").unwrap_or_else(|_| {
            #[allow(clippy::expect_used)]
            Regex::new(r"ghp_[A-Za-z0-9]+").expect("fallback regex")
        })
    })
}

/// Scan `text` for GitHub PATs.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::GithubPat,
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
    fn finds_classic_ghp() {
        let t = "token=ghp_ABCDEFGHIJ1234567890abcdef1234567890ABCD end";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::GithubPat);
    }

    #[test]
    fn finds_app_server_token() {
        let t = "ghs_ABCDEFGHIJ1234567890abcdef1234567890ABCD";
        let m = scan(t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn rejects_unknown_prefix() {
        let t = "ghz_ABCDEFGHIJ1234567890abcdef1234567890ABCD";
        assert!(scan(t).is_empty());
    }

    #[test]
    fn rejects_short_runs() {
        let t = "ghp_short";
        assert!(scan(t).is_empty());
    }
}
