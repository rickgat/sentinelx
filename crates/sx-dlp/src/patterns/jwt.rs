//! JSON Web Token matcher.
//!
//! A JWT is three base64url segments separated by `.`:
//!
//! - Header: minimal JSON, 8+ chars in base64url.
//! - Payload: variable; 8+ chars.
//! - Signature: HMAC / RSA / ECDSA digest in base64url.
//!
//! We anchor on word boundaries so a `.jwt` filename does not match.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
            .unwrap_or_else(|_| {
                #[allow(clippy::expect_used)]
                Regex::new(r"eyJ[A-Za-z0-9_.-]+").expect("fallback regex")
            })
    })
}

/// Scan `text` for JWTs.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::Jwt,
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
    fn finds_canonical_jwt() {
        // Tiny but well-formed JWT (alg=HS256, payload, sig).
        let t = "auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJlMTIz end";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::Jwt);
    }

    #[test]
    fn rejects_two_segment_run() {
        let t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9";
        assert!(scan(t).is_empty());
    }

    #[test]
    fn rejects_non_jwt_text() {
        let t = "Bearer not.a.jwt";
        assert!(scan(t).is_empty());
    }
}
