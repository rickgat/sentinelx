//! GCP service-account credential matcher.
//!
//! Two surface forms exist:
//!
//! 1. A JSON file with `"type": "service_account"` and a `"private_key"`
//!    field. We anchor on the `"type"` field — exact-string scan, so the
//!    JSON does not have to be valid for us to flag it.
//! 2. A bare `client_email` ending in `iam.gserviceaccount.com`. This
//!    catches credentials posted in messages without the surrounding
//!    JSON wrapper.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn type_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Allows any amount of whitespace between fields. The fallback is
        // the same shape without whitespace — both parse cleanly.
        #[allow(clippy::trivial_regex)]
        let fallback = Regex::new(r#""type":"service_account""#);
        Regex::new(r#""type"\s*:\s*"service_account""#).unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            fallback.unwrap()
        })
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[a-z0-9][a-z0-9._-]{0,61}@[a-z0-9-]+\.iam\.gserviceaccount\.com\b")
            .unwrap_or_else(|_| {
                #[allow(clippy::expect_used)]
                Regex::new(r"\S+@\S+\.iam\.gserviceaccount\.com").expect("fallback regex")
            })
    })
}

/// Scan `text` for GCP service-account credentials.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for m in type_re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::GcpServiceAccount,
            offset: m.start(),
            length: s.len(),
            redacted_preview: redact(s),
            ..Default::default()
        });
    }
    for m in email_re().find_iter(text) {
        let s = m.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::GcpServiceAccount,
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
    fn finds_json_type_field() {
        let t = r#"{"type": "service_account", "project_id": "x"}"#;
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::GcpServiceAccount);
    }

    #[test]
    fn finds_iam_email() {
        let t = "client_email: terraform@my-prj.iam.gserviceaccount.com";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::GcpServiceAccount);
    }

    #[test]
    fn rejects_generic_email() {
        let t = "alice@example.com";
        assert!(scan(t).is_empty());
    }

    #[test]
    fn rejects_unrelated_json() {
        let t = r#"{"type": "user"}"#;
        assert!(scan(t).is_empty());
    }
}
