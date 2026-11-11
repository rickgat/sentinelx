//! PEM-encoded private-key block matcher.
//!
//! Matches the standard armor header:
//!
//! ```text
//! -----BEGIN <kind> PRIVATE KEY-----
//! ```
//!
//! Where `<kind>` is empty / `RSA` / `EC` / `DSA` / `OPENSSH` /
//! `ENCRYPTED`. We match only the header so multi-line payloads are
//! reported by a single hit anchored at the header offset.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Fallback uses the wider armor header pattern (no key-kind
        // alternation) so we still match `BEGIN ... PRIVATE KEY-----` runs
        // even if the alternation fails to compile in a stripped build.
        #[allow(clippy::trivial_regex)]
        let fallback = Regex::new("-----BEGIN PRIVATE KEY-----");
        Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
            .unwrap_or_else(|_| {
                #[allow(clippy::unwrap_used)]
                fallback.unwrap()
            })
    })
}

/// Scan `text` for PEM private-key headers.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::PemPrivateKey,
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
    fn finds_rsa_header() {
        let t = "leaked:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::PemPrivateKey);
    }

    #[test]
    fn finds_openssh_header() {
        let t = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let m = scan(t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn finds_generic_header() {
        let t = "-----BEGIN PRIVATE KEY-----";
        let m = scan(t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn ignores_public_key_header() {
        let t = "-----BEGIN PUBLIC KEY-----";
        assert!(scan(t).is_empty());
    }
}
