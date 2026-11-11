//! Per-match DLP risk signals (HIGH-004).
//!
//! Each [`DlpSignal`] reads an inspector hit + the surrounding payload
//! and emits a sub-score in `[0.0, 1.0]`. The orchestrator fuses the
//! enabled signal set with a calibrated logistic blend
//! (see [`crate::detector::DlpDetector`]) into a per-finding confidence,
//! so the runtime can drop low-quality regex hits before they hit the
//! audit trail.
//!
//! This trait surface mirrors the per-signal abstraction shipped in
//! `crates/sx-rba/src/signals/mod.rs` (HIGH-001) — same shape, same
//! testability, same "swap signals on/off per tenant" handle.
//!
//! ## The four canonical signals
//!
//! | Kind | Weight | What it asserts |
//! |---|---|---|
//! | [`SignalKind::RegexMatch`] | `0.40` | The literal-pattern matcher fired. |
//! | [`SignalKind::LuhnCheck`] | `0.30` | Digits pass the Luhn checksum (PAN only). |
//! | [`SignalKind::EntropyBand`] | `0.15` | Shannon entropy falls in the kind's "looks-random" band. |
//! | [`SignalKind::NerContext`] | `0.15` | A context cue (e.g. `card number:`) sits within ±32 chars. |
//!
//! Weights sum to `1.00`. Per-kind signal sets are wired in
//! [`crate::detector::DlpDetector`] — e.g. SSN does not get a Luhn
//! signal because there is no checksum for SSNs.

use serde::{Deserialize, Serialize};

use crate::patterns::DlpMatchKind;

pub mod context;
pub mod entropy;
pub mod luhn;
pub mod regex_match;

/// Stable identifier for each signal. Used in the JSON explainability
/// payload and as the toggle key for per-tenant on/off rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// The literal-pattern matcher (regex) reported a hit.
    RegexMatch,
    /// The Luhn checksum passed — PAN-only.
    LuhnCheck,
    /// Shannon entropy of the match falls within the kind's expected band.
    EntropyBand,
    /// A natural-language context cue sits within ±32 chars of the span.
    NerContext,
}

impl SignalKind {
    /// Stable string form used in logs / metric labels / JSON keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegexMatch => "regex_match",
            Self::LuhnCheck => "luhn_check",
            Self::EntropyBand => "entropy_band",
            Self::NerContext => "ner_context",
        }
    }

    /// Canonical fusion weight for the signal. The four weights sum to
    /// `1.00` so a fully-firing 4-signal blend tops out at `1.00` before
    /// the logistic calibration.
    #[must_use]
    pub const fn weight(self) -> f32 {
        match self {
            Self::RegexMatch => 0.40,
            Self::LuhnCheck => 0.30,
            // EntropyBand + NerContext both at 0.15 — fold into one arm
            // to satisfy clippy::match_same_arms. The four-signal split
            // 0.40 / 0.30 / 0.15 / 0.15 is documented in
            // `crate::detector` and asserted by `weights_sum_to_one`.
            Self::EntropyBand | Self::NerContext => 0.15,
        }
    }
}

/// Per-signal evidence emitted by [`DlpSignal::evaluate`] and carried on
/// the wire so the customer-facing dashboard can show *why* a finding
/// was raised.
///
/// `sub_score` is clamped to `[0.0, 1.0]` by [`Self::new`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalEvidence {
    /// Which signal produced this row.
    pub kind: SignalKind,
    /// `[0.0, 1.0]` sub-score this signal contributed.
    pub sub_score: f32,
    /// Weight applied during fusion — useful when a dashboard wants to
    /// reconstruct the blended score on its own.
    pub weight: f32,
    /// Short human-readable rationale (e.g. `"luhn ok"`, `"entropy=3.81 in band"`).
    pub rationale: String,
}

impl SignalEvidence {
    /// Construct a clamped evidence row.
    #[must_use]
    pub fn new(kind: SignalKind, sub_score: f32, rationale: impl Into<String>) -> Self {
        let s = if sub_score.is_nan() {
            0.0
        } else {
            sub_score.clamp(0.0, 1.0)
        };
        Self {
            kind,
            sub_score: s,
            weight: kind.weight(),
            rationale: rationale.into(),
        }
    }
}

/// View into the surrounding payload + the candidate match. Handed to
/// every [`DlpSignal::evaluate`] call so signals can examine context
/// without re-running the regex.
#[derive(Debug, Clone, Copy)]
pub struct SignalContext<'a> {
    /// The full payload being scanned.
    pub text: &'a str,
    /// The (start, end) byte offsets of the candidate match in `text`.
    pub span: (usize, usize),
    /// The matched substring (`&text[span.0..span.1]`).
    pub matched: &'a str,
    /// Which DLP kind we are scoring — drives kind-specific behaviour
    /// in some signals (e.g. expected entropy band).
    pub kind: DlpMatchKind,
}

impl<'a> SignalContext<'a> {
    /// Build a context, clipping the span to `text` boundaries.
    #[must_use]
    pub fn new(text: &'a str, start: usize, end: usize, kind: DlpMatchKind) -> Self {
        let max = text.len();
        let s = start.min(max);
        let e = end.min(max).max(s);
        let matched = text.get(s..e).unwrap_or("");
        Self {
            text,
            span: (s, e),
            matched,
            kind,
        }
    }

    /// Return up to `n` bytes of context to the left of the span.
    #[must_use]
    pub fn left(&self, n: usize) -> &'a str {
        let start = self.span.0.saturating_sub(n);
        self.text.get(start..self.span.0).unwrap_or("")
    }

    /// Return up to `n` bytes of context to the right of the span.
    #[must_use]
    pub fn right(&self, n: usize) -> &'a str {
        let end = self.span.1.saturating_add(n).min(self.text.len());
        self.text.get(self.span.1..end).unwrap_or("")
    }
}

/// Polymorphic DLP signal — the small contract every signal collector
/// satisfies.
pub trait DlpSignal: Send + Sync {
    /// Which signal this is — used for weight lookup, feature flags and
    /// the explainability payload.
    fn kind(&self) -> SignalKind;
    /// Compute the `[0.0, 1.0]` sub-score for `ctx`. Implementations
    /// must clamp out-of-range values and must NEVER panic.
    fn evaluate(&self, ctx: &SignalContext<'_>) -> SignalEvidence;
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn signal_kind_strings_are_stable() {
        assert_eq!(SignalKind::RegexMatch.as_str(), "regex_match");
        assert_eq!(SignalKind::LuhnCheck.as_str(), "luhn_check");
        assert_eq!(SignalKind::EntropyBand.as_str(), "entropy_band");
        assert_eq!(SignalKind::NerContext.as_str(), "ner_context");
    }

    #[test]
    fn weights_sum_to_one() {
        let w = SignalKind::RegexMatch.weight()
            + SignalKind::LuhnCheck.weight()
            + SignalKind::EntropyBand.weight()
            + SignalKind::NerContext.weight();
        assert!((w - 1.0).abs() < 1e-6, "weights must sum to 1.0, got {w}");
    }

    #[test]
    fn evidence_clamps_score() {
        let e = SignalEvidence::new(SignalKind::RegexMatch, 1.5, "over");
        assert!((e.sub_score - 1.0).abs() < f32::EPSILON);
        let e = SignalEvidence::new(SignalKind::RegexMatch, -0.5, "under");
        assert!(e.sub_score.abs() < f32::EPSILON);
        let e = SignalEvidence::new(SignalKind::RegexMatch, f32::NAN, "nan");
        assert!(e.sub_score.abs() < f32::EPSILON);
    }

    #[test]
    fn context_left_right_clip_to_bounds() {
        let t = "abcdefghij";
        let ctx = SignalContext::new(t, 4, 6, DlpMatchKind::CreditCard);
        assert_eq!(ctx.matched, "ef");
        assert_eq!(ctx.left(2), "cd");
        assert_eq!(ctx.right(2), "gh");
        // Asking for more than exists is fine.
        assert_eq!(ctx.left(100), "abcd");
        assert_eq!(ctx.right(100), "ghij");
    }

    #[test]
    fn context_handles_oob_span() {
        let t = "short";
        let ctx = SignalContext::new(t, 99, 200, DlpMatchKind::Email);
        // Both clamped to text.len(); span is degenerate but safe.
        assert_eq!(ctx.matched, "");
        assert_eq!(ctx.span, (5, 5));
    }
}
