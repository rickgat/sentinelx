//! AWS secret access-key heuristic.
//!
//! AWS secret access keys are 40-character base64 strings (`[A-Za-z0-9/+=]`).
//! Free-form text frequently contains 40-char runs that pass a naive
//! regex; we therefore add a Shannon-entropy floor before emitting a hit.
//!
//! ## Entropy gate
//!
//! Real secrets are very nearly uniform: their per-character entropy sits
//! above 4.5 bits for 40-char runs. English text and base64-of-text fall
//! well below that. Setting the cutoff at 4.0 catches realistic keys
//! without flooding the operator with false positives.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Look for 40-char base64-alphabet runs. Boundary chars
        // exclude the base64 *content* alphabet (A-Z, a-z, 0-9, /, +)
        // but allow `=` so secrets sitting after `KEY=` are still
        // detected. We do not anchor on `\b` since `/` and `+` are
        // non-word characters and would break the simple word-boundary
        // semantics regex provides.
        Regex::new(r"(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40,40}=*)(?:$|[^A-Za-z0-9/+])")
            .unwrap_or_else(|_| {
                #[allow(clippy::expect_used)]
                Regex::new(r"[A-Za-z0-9/+=]{40}").expect("fallback regex")
            })
    })
}

/// Per-character Shannon entropy (base 2) of `s`. Empty strings return
/// `0.0`. Used as the secret-vs-noise gate.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();
    for &b in s.as_bytes() {
        let entry = counts.entry(b).or_insert(0);
        *entry = entry.saturating_add(1);
    }
    let len = s.len() as f64;
    let mut h = 0.0_f64;
    for c in counts.values() {
        if *c == 0 {
            continue;
        }
        let p = f64::from(*c) / len;
        h -= p * p.log2();
    }
    h
}

/// Minimum per-character Shannon entropy required for an emission.
pub const MIN_ENTROPY_BITS: f64 = 4.0;

/// Scan `text` for AWS-secret-shaped runs.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for caps in re().captures_iter(text) {
        let Some(m) = caps.get(1) else { continue };
        let s = m.as_str();
        // Skip runs that are clearly part of larger base64 blobs (PEM
        // bodies, JWT signatures) — those are caught by dedicated
        // matchers and would otherwise produce noise here.
        if shannon_entropy(s) < MIN_ENTROPY_BITS {
            continue;
        }
        out.push(DlpMatch {
            kind: DlpMatchKind::AwsSecretKey,
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
    fn entropy_of_uniform_run_exceeds_floor() {
        // 40-char realistic secret.
        let s = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(shannon_entropy(s) > MIN_ENTROPY_BITS);
    }

    #[test]
    fn entropy_of_repeated_chars_is_zero() {
        assert!(shannon_entropy("aaaaaaaaaa").abs() < 1e-6);
    }

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert!(shannon_entropy("").abs() < 1e-6);
    }

    #[test]
    fn finds_canonical_secret() {
        let t = "AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY end";
        let hits = scan(t);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, DlpMatchKind::AwsSecretKey);
    }

    #[test]
    fn rejects_low_entropy_run() {
        // 40 identical characters — no entropy.
        let t = format!("x={} y", "A".repeat(40));
        assert!(scan(&t).is_empty());
    }

    #[test]
    fn rejects_short_runs() {
        let t = "secret=abc123";
        assert!(scan(t).is_empty());
    }
}
