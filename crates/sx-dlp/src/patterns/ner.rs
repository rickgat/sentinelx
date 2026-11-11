//! Lightweight named-entity recognition.
//!
//! Full-strength NER would require a CRF / transformer model — out of
//! scope for the inline MVP. We implement a heuristic instead:
//!
//! - Capitalised bi-/tri-grams (`First Last`, `First Middle Last`) are
//!   flagged as `NamedEntity`.
//! - Single-token capitalised words at sentence-start are *not* flagged
//!   (too noisy).
//! - Tokens shorter than 3 chars are skipped (initials).
//!
//! This is intentionally coarse — the trait surface allows swapping in a
//! richer NER pass without touching the controller.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Two or three Title-Case tokens separated by single spaces.
        // Each token: leading capital + 2+ lowercase letters.
        Regex::new(r"\b[A-Z][a-z]{2,}(?:\s[A-Z][a-z]{2,}){1,2}\b").unwrap_or_else(|_| {
            #[allow(clippy::expect_used)]
            Regex::new(r"[A-Z][a-z]+ [A-Z][a-z]+").expect("fallback regex")
        })
    })
}

/// Scan `text` for capitalised name-like runs.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::NamedEntity,
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
    fn finds_bigram_name() {
        let t = "Patient: Alice Smith requested records";
        let m = scan(t);
        assert!(!m.is_empty());
        assert_eq!(m[0].kind, DlpMatchKind::NamedEntity);
    }

    #[test]
    fn finds_trigram_name() {
        let t = "Defendant Bobby Henry Tables appeared";
        let m = scan(t);
        assert!(!m.is_empty());
    }

    #[test]
    fn ignores_single_word_caps() {
        let t = "Today the weather is nice.";
        // "Today" alone should not flag.
        assert!(scan(t).is_empty());
    }

    #[test]
    fn ignores_short_tokens() {
        let t = "Mr Al rang";
        assert!(scan(t).is_empty());
    }
}
