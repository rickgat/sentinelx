//! Slack token matcher.
//!
//! Slack tokens follow `xox[abprs]-<digits>-<digits>-<digits>-<alphanum>`:
//!
//! - `xoxa-…` — workspace access.
//! - `xoxb-…` — bot user OAuth.
//! - `xoxp-…` — user OAuth.
//! - `xoxr-…` — refresh token.
//! - `xoxs-…` — Slack-issued service token.
//!
//! Lengths vary, but every segment is at least 10 chars. We require at
//! least three `-`-separated segments after the prefix to avoid catching
//! `xoxb-deadbeef` placeholders in code samples.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bxox[abprs]-[A-Za-z0-9]{10,}-[A-Za-z0-9]{10,}-[A-Za-z0-9]{10,}\b")
            .unwrap_or_else(|_| {
                #[allow(clippy::expect_used)]
                Regex::new(r"xox[abprs]-[A-Za-z0-9-]+").expect("fallback regex")
            })
    })
}

/// Scan `text` for Slack tokens.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::SlackToken,
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
    fn finds_bot_token() {
        let t = concat!("tok=xox", "b-1234567890-1234567890-abcDEFghIJKlmNOPqrsTUvwx end");
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::SlackToken);
    }

    #[test]
    fn finds_user_token() {
        let t = concat!("xox", "p-1234567890-2345678901-abcdefghij1234567890");
        let m = scan(t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn rejects_placeholder() {
        let t = concat!("xox", "b-short");
        assert!(scan(t).is_empty());
    }

    #[test]
    fn rejects_two_segments() {
        let t = concat!("xox", "b-1234567890-abcdefghij1234567890");
        assert!(scan(t).is_empty());
    }
}
