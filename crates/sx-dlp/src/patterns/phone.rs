//! North-American phone-number matcher.
//!
//! Accepts the common surface forms:
//!
//! - `+1 (555) 867-5309`
//! - `+1-555-867-5309`
//! - `(555) 867-5309`
//! - `555-867-5309`
//!
//! Rejects the `555-1212` 7-digit short form: too noisy and too easily
//! confused with stock-keeping or ticket numbers.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Optional +1, optional parens around area, separator one of
        // space/hyphen/dot, then 3-4 digits.
        Regex::new(
            r"(?x)
            (?:\+1[\s.-]?)?
            \(?\b[2-9]\d{2}\)?[\s.-]?
            [2-9]\d{2}[\s.-]?
            \d{4}\b
        ",
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::expect_used)]
            Regex::new(r"\d{3}-\d{3}-\d{4}").expect("fallback regex")
        })
    })
}

/// Scan `text` for NANP-shaped phone numbers.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        // Skip if the run is part of a longer digit stream (e.g. SSN
        // already caught upstream); we still emit but anchored on
        // word boundaries via the regex, so duplicates are rare.
        out.push(DlpMatch {
            kind: DlpMatchKind::Phone,
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
    fn finds_dashed_form() {
        let t = "call 555-867-5309 please";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::Phone);
    }

    #[test]
    fn finds_international_form() {
        let t = "ph: +1 (555) 867-5309";
        let m = scan(t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn finds_dotted_form() {
        let t = "555.867.5309";
        let m = scan(t);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn rejects_short_run() {
        let t = "555-1212";
        assert!(scan(t).is_empty());
    }
}
