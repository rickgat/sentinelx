//! NER-context signal — keyword cue within ±32 chars of the span.
//!
//! The spec deliberately rules out a heavyweight NER crate (no new
//! tokeniser, no model). Instead we look for kind-specific keyword cues
//! inside a 32-byte window on either side of the candidate match. The
//! window size matches what the spec calls "tiny regex-based context
//! check".
//!
//! Cue dictionary (case-insensitive, substring match):
//!
//! | Kind | Cues |
//! |---|---|
//! | `CreditCard` | `card`, `pan`, `credit`, `visa`, `mastercard`, `amex`, `discover`, `cc#`, `cc:` |
//! | `SsnUs` | `ssn`, `social security`, `social_security`, `tax id` |
//! | `AwsAccessKey`, `AwsSecretKey` | `aws_access`, `aws_secret`, `access key`, `secret access`, `s3` |
//! | `GithubPat` | `github`, `gh_token`, `personal access`, `pat=` |
//! | `Jwt` | `bearer`, `authorization`, `jwt`, `token=` |
//! | `PemPrivateKey` | `private key`, `begin private`, `id_rsa`, `id_ed25519`, `pem` |
//! | `Email` | `email`, `mailto:`, `from:`, `to:`, `cc:`, `bcc:`, `@` |
//! | `Phone` | `phone`, `mobile`, `cell`, `tel:`, `call` |
//! | `GcpServiceAccount` | `service_account`, `gcp`, `google`, `cloud.google` |
//! | `SlackToken` | `slack`, `xoxb`, `xoxa`, `xoxp`, `webhook` |
//! | `NamedEntity` | `patient`, `customer`, `name:`, `dear`, `attn:` |
//!
//! A cue hit lifts the signal to `1.0`. Absence of any cue scores `0.0`.
//! A partial match (only a weak cue like a bare `:`) is not awarded.
//!
//! Window: 32 bytes either side, clipped to the payload boundary.

use super::{DlpSignal, SignalContext, SignalEvidence, SignalKind};
use crate::patterns::DlpMatchKind;

/// Window size (one side) used by the keyword scan.
pub const CONTEXT_WINDOW_BYTES: usize = 32;

/// NER-context signal.
#[derive(Debug, Default, Clone, Copy)]
pub struct ContextSignal;

/// Per-kind cue list. Lower-case ASCII; the scan is also lower-cased.
#[must_use]
pub const fn cues_for(kind: DlpMatchKind) -> &'static [&'static str] {
    match kind {
        DlpMatchKind::CreditCard => &[
            "card",
            "pan",
            "credit",
            "visa",
            "mastercard",
            "amex",
            "discover",
            "cc#",
            "cc:",
            "cc =",
            "cc=",
            "card number",
            "card no",
        ],
        DlpMatchKind::SsnUs => &[
            "ssn",
            "social security",
            "social_security",
            "tax id",
            "tax-id",
            "taxid",
        ],
        DlpMatchKind::AwsAccessKey | DlpMatchKind::AwsSecretKey => &[
            "aws_access",
            "aws_secret",
            "access key",
            "access_key",
            "secret access",
            "secret_access",
            "aws_session",
            "s3",
            "aws",
        ],
        DlpMatchKind::GithubPat => &[
            "github",
            "gh_token",
            "personal access",
            "personal_access",
            "pat=",
            "gh ",
            "git ",
        ],
        DlpMatchKind::Jwt => &[
            "bearer",
            "authorization",
            "authorisation",
            "jwt",
            "token=",
            "id_token",
            "access_token",
        ],
        DlpMatchKind::PemPrivateKey => &[
            "private key",
            "begin private",
            "id_rsa",
            "id_ed25519",
            "pem",
            "ssh-rsa",
        ],
        DlpMatchKind::Email => &[
            "email", "e-mail", "mailto:", "from:", "to:", "cc:", "bcc:", "@", "reply-to",
        ],
        DlpMatchKind::Phone => &["phone", "mobile", "cell", "tel:", "tel.", "call ", "fax"],
        DlpMatchKind::GcpServiceAccount => &[
            "service_account",
            "gcp",
            "google",
            "cloud.google",
            "iam.gserviceaccount",
        ],
        DlpMatchKind::SlackToken => &[
            "slack",
            "xoxb",
            "xoxa",
            "xoxp",
            "xoxs",
            "webhook",
            "incoming-webhook",
        ],
        DlpMatchKind::NamedEntity => &[
            "patient", "customer", "name:", "dear ", "attn:", "mr.", "ms.", "mrs.", "dr.",
        ],
    }
}

impl DlpSignal for ContextSignal {
    fn kind(&self) -> SignalKind {
        SignalKind::NerContext
    }

    fn evaluate(&self, ctx: &SignalContext<'_>) -> SignalEvidence {
        let cues = cues_for(ctx.kind);
        let left = ctx.left(CONTEXT_WINDOW_BYTES).to_ascii_lowercase();
        let right = ctx.right(CONTEXT_WINDOW_BYTES).to_ascii_lowercase();
        for cue in cues {
            if left.contains(cue) || right.contains(cue) {
                return SignalEvidence::new(
                    SignalKind::NerContext,
                    1.0,
                    format!("cue '{cue}' in ±{CONTEXT_WINDOW_BYTES}B window"),
                );
            }
        }
        SignalEvidence::new(SignalKind::NerContext, 0.0, "no context cue in window")
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pan_with_card_cue_fires() {
        let t = "card number: 4111111111111111";
        let ctx = SignalContext::new(t, 13, 29, DlpMatchKind::CreditCard);
        let e = ContextSignal.evaluate(&ctx);
        assert!((e.sub_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn pan_without_cue_zero() {
        let t = "order id 4111111111111111";
        let ctx = SignalContext::new(t, 9, 25, DlpMatchKind::CreditCard);
        let e = ContextSignal.evaluate(&ctx);
        assert!(e.sub_score.abs() < f32::EPSILON);
    }

    #[test]
    fn ssn_with_cue_on_right_fires() {
        let t = "123-45-6789 (ssn)";
        let ctx = SignalContext::new(t, 0, 11, DlpMatchKind::SsnUs);
        let e = ContextSignal.evaluate(&ctx);
        assert!((e.sub_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn cue_outside_window_does_not_fire() {
        // 40+ bytes between cue and match → outside the 32-byte window.
        let t = "ssn was redacted long ago in another sentence very far indeed 123-45-6789";
        let pos = t.find("123").unwrap();
        let ctx = SignalContext::new(t, pos, pos + 11, DlpMatchKind::SsnUs);
        let e = ContextSignal.evaluate(&ctx);
        assert!(e.sub_score.abs() < f32::EPSILON);
    }

    #[test]
    fn email_at_sign_cue_is_self_evident() {
        let t = "alice@example.com";
        let ctx = SignalContext::new(t, 0, t.len(), DlpMatchKind::Email);
        // '@' is in the match itself, which is inside left+right windows only
        // when adjacent. For email kind we treat the presence of '@' anywhere
        // in the ±32 window as a cue.
        let e = ContextSignal.evaluate(&ctx);
        // The match itself contains '@' so the right window starts after the
        // match — that window would be empty. Left window before the match
        // is empty too. So no cue → zero. The test below covers the cue case.
        assert!(e.sub_score.abs() < f32::EPSILON);

        let t2 = "from: alice@example.com";
        let ctx2 = SignalContext::new(t2, 6, t2.len(), DlpMatchKind::Email);
        let e2 = ContextSignal.evaluate(&ctx2);
        assert!((e2.sub_score - 1.0).abs() < f32::EPSILON);
    }
}
