//! Email address matcher (RFC 5322 lite).
//!
//! Covers the common form `local@domain.tld` with practical character
//! classes — enough to catch leaks in logs / payloads without claiming
//! 5322 conformance.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+\b")
            .unwrap_or_else(|_| {
                #[allow(clippy::expect_used)]
                Regex::new(r"\S+@\S+\.\S+").expect("fallback regex")
            })
    })
}

/// Scan `text` for email addresses.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::Email,
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
    fn finds_canonical_email() {
        let t = "contact: alice@example.com please";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::Email);
        assert_eq!(
            &t[m[0].offset..m[0].offset + m[0].length],
            "alice@example.com"
        );
    }

    #[test]
    fn finds_email_with_plus() {
        let t = "subaddr: alice+spam@example.co.uk";
        let m = scan(t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn rejects_no_dot_domain() {
        let t = "alice@example";
        assert!(scan(t).is_empty());
    }

    #[test]
    fn rejects_lone_at() {
        let t = "this @ that";
        assert!(scan(t).is_empty());
    }
}
