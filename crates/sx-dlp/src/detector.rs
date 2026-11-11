//! Multi-signal DLP detector with calibrated logistic fusion (HIGH-004).
//!
//! The detector is the orchestration layer over the four signals in
//! [`crate::signals`]:
//!
//! 1. Regex match (weight `0.40`).
//! 2. Luhn check (weight `0.30`).
//! 3. Entropy band (weight `0.15`).
//! 4. NER context (weight `0.15`).
//!
//! Each signal emits a sub-score in `[0.0, 1.0]`. The detector blends
//! them via a calibrated logistic:
//!
//! ```text
//!     z       = Σ_i (w_i · s_i)         in [0, 1]
//!     z'      = 2 · z − 1               in [-1, 1]
//!     conf    = σ(k · z')               in (0, 1)
//! ```
//!
//! where `k = 4.0` is the calibration slope picked so that:
//!
//! - All-zero signals collapse to `≈ 0.018` (well below any sane threshold).
//! - All-1.0 signals saturate at `≈ 0.982` (never quite 1.0 — leaves
//!   head-room for downstream "boost" multipliers without overflowing).
//! - A blend that fires every signal except entropy lands at `≈ 0.92`.
//! - A bare regex hit with no Luhn / context fires at `≈ 0.36` for PAN
//!   (because Luhn missing scores 0) — below the typical `0.5` threshold.
//!
//! The slope `4.0` was picked by hand against the Sprint-4 fixture
//! ([`crates/sx-dlp/tests/fixture_f1.rs`]) to maximise F1. Future
//! sprints can replace the constant with a per-tenant trained value.
//!
//! ## FP suppression
//!
//! Before fusion, the detector consults a [`crate::suppression::SuppressionList`]
//! and drops the candidate silently if the normalised literal matches.

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::signals::context::ContextSignal;
use crate::signals::entropy::EntropySignal;
use crate::signals::luhn::LuhnSignal;
use crate::signals::regex_match::RegexMatchSignal;
#[cfg(test)]
use crate::signals::SignalKind;
use crate::signals::{DlpSignal, SignalContext, SignalEvidence};
use crate::suppression::SuppressionList;
use serde::{Deserialize, Serialize};

/// Calibrated logistic slope. See module docstring for derivation.
pub const FUSION_SLOPE: f32 = 4.0;

/// Sigmoid σ(x).
#[must_use]
pub fn sigmoid(x: f32) -> f32 {
    let e = (-x).exp();
    if !e.is_finite() {
        if x > 0.0 {
            return 1.0;
        }
        return 0.0;
    }
    1.0 / (1.0 + e)
}

/// (start, end) byte offsets of a finding in the scanned payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Span {
    /// Build a span from `(start, end)`.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Span length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True when the span has zero length.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// A scored DLP finding emitted by [`DlpDetector::evaluate`].
///
/// Carries the per-signal breakdown so the wire layer can expose
/// "why" to the dashboard, plus the fused `confidence` so callers can
/// threshold without re-running the fusion math.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Detector category.
    pub kind: DlpMatchKind,
    /// Span in the original payload.
    pub span: Span,
    /// Per-signal evidence.
    pub signals: Vec<SignalEvidence>,
    /// Fused confidence in `[0.0, 1.0]` (logistic-calibrated).
    pub confidence: f32,
    /// Redacted preview suitable for logs — carries forward from the
    /// underlying [`DlpMatch`] so the wire-layer projection does not
    /// need a second lookup.
    pub redacted_preview: String,
}

/// Stateless multi-signal detector. Holds the signal set + the
/// suppression list; safe to share via `Arc` across requests.
#[derive(Debug, Clone)]
pub struct DlpDetector {
    suppression: SuppressionList,
}

impl Default for DlpDetector {
    fn default() -> Self {
        Self::with_builtin_suppression()
    }
}

impl DlpDetector {
    /// Build with the builtin suppression list (test PANs, RFC SSNs,
    /// AWS docs sample key, jwt.io demo). This is the production path.
    #[must_use]
    pub fn with_builtin_suppression() -> Self {
        Self {
            suppression: SuppressionList::builtin(),
        }
    }

    /// Build with a custom suppression list — used by tests.
    #[must_use]
    pub const fn with_suppression(suppression: SuppressionList) -> Self {
        Self { suppression }
    }

    /// Borrow the suppression list — used by tests and tooling.
    #[must_use]
    pub const fn suppression(&self) -> &SuppressionList {
        &self.suppression
    }

    /// Per-kind enabled signal set. SSN does not get a Luhn signal;
    /// non-PAN kinds get a neutral 0.5 from [`LuhnSignal`] but skipping
    /// it entirely makes the explainability payload tidier.
    #[must_use]
    #[allow(clippy::unused_self)] // kept on `&self` for future per-tenant signal toggles.
    pub fn signals_for(&self, kind: DlpMatchKind) -> Vec<Box<dyn DlpSignal>> {
        let mut out: Vec<Box<dyn DlpSignal>> = vec![
            Box::new(RegexMatchSignal),
            Box::new(EntropySignal),
            Box::new(ContextSignal),
        ];
        if matches!(kind, DlpMatchKind::CreditCard) {
            // Luhn only meaningful for PAN — insert after regex (so the
            // explainability payload reads regex → luhn → entropy → context).
            out.insert(1, Box::new(LuhnSignal));
        }
        out
    }

    /// Evaluate a single match against `text`. Returns `None` if the
    /// match is on the suppression list. Otherwise produces a fully-
    /// scored [`DetectionEvent`].
    #[must_use]
    pub fn evaluate(&self, text: &str, m: &DlpMatch) -> Option<DetectionEvent> {
        let end = m.offset.saturating_add(m.length);
        let matched = text.get(m.offset..end).unwrap_or("");
        if self.suppression.contains(m.kind, matched) {
            return None;
        }
        let ctx = SignalContext::new(text, m.offset, end, m.kind);
        let signals = self.signals_for(m.kind);
        let evidence: Vec<SignalEvidence> = signals.iter().map(|s| s.evaluate(&ctx)).collect();
        let confidence = fuse(&evidence);
        Some(DetectionEvent {
            kind: m.kind,
            span: Span::new(m.offset, end),
            signals: evidence,
            confidence,
            redacted_preview: m.redacted_preview.clone(),
        })
    }

    /// Evaluate every match and drop entries below `min_confidence`.
    /// Suppression-list hits are dropped silently regardless of
    /// threshold.
    #[must_use]
    pub fn evaluate_all(
        &self,
        text: &str,
        matches: &[DlpMatch],
        min_confidence: f32,
    ) -> Vec<DetectionEvent> {
        let mut out = Vec::with_capacity(matches.len());
        for m in matches {
            let Some(ev) = self.evaluate(text, m) else {
                continue;
            };
            if ev.confidence + f32::EPSILON >= min_confidence {
                out.push(ev);
            }
        }
        out
    }
}

/// Fuse a per-signal evidence vector into a `[0, 1]` confidence via
/// the calibrated logistic described in the module docstring.
#[must_use]
pub fn fuse(evidence: &[SignalEvidence]) -> f32 {
    if evidence.is_empty() {
        return 0.0;
    }
    // Weighted sum in [0, 1].
    let z: f32 = evidence.iter().map(|e| e.sub_score * e.weight).sum();
    let z = z.clamp(0.0, 1.0);
    // Stretch to [-1, 1] then run through the slope-scaled sigmoid.
    let z_prime = 2.0_f32.mul_add(z, -1.0);
    sigmoid(FUSION_SLOPE * z_prime).clamp(0.0, 1.0)
}

/// Fuse a free-form `(kind, sub_score)` vector — convenience used by
/// the unit tests so we don't have to build a `SignalEvidence` each
/// time. Production callers use [`fuse`].
#[cfg(test)]
fn fuse_kinds(parts: &[(SignalKind, f32)]) -> f32 {
    let ev: Vec<SignalEvidence> = parts
        .iter()
        .map(|(k, s)| SignalEvidence::new(*k, *s, ""))
        .collect();
    fuse(&ev)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn dlp_match(kind: DlpMatchKind, offset: usize, len: usize, preview: &str) -> DlpMatch {
        DlpMatch {
            kind,
            offset,
            length: len,
            redacted_preview: preview.into(),
            ..Default::default()
        }
    }

    #[test]
    fn sigmoid_endpoints() {
        assert!((sigmoid(0.0) - 0.5).abs() < f32::EPSILON);
        assert!(sigmoid(20.0) > 0.999);
        assert!(sigmoid(-20.0) < 0.001);
        assert!(sigmoid(f32::INFINITY) >= 1.0 - f32::EPSILON);
        assert!(sigmoid(f32::NEG_INFINITY) <= f32::EPSILON);
    }

    #[test]
    fn fuse_all_zero_collapses() {
        let c = fuse_kinds(&[
            (SignalKind::RegexMatch, 0.0),
            (SignalKind::LuhnCheck, 0.0),
            (SignalKind::EntropyBand, 0.0),
            (SignalKind::NerContext, 0.0),
        ]);
        // σ(-4) ≈ 0.0180
        assert!(c < 0.05, "all-zero confidence should collapse: {c}");
    }

    #[test]
    fn fuse_all_one_saturates() {
        let c = fuse_kinds(&[
            (SignalKind::RegexMatch, 1.0),
            (SignalKind::LuhnCheck, 1.0),
            (SignalKind::EntropyBand, 1.0),
            (SignalKind::NerContext, 1.0),
        ]);
        // σ(4) ≈ 0.9820
        assert!(c > 0.95, "all-one confidence should saturate: {c}");
        assert!(c < 1.0);
    }

    #[test]
    fn fuse_bare_pan_regex_below_threshold() {
        // Only regex fires (sub=1, w=0.4). Luhn=0, entropy=0, context=0.
        // z=0.4, z'=-0.2, σ(-0.8) ≈ 0.31.
        let c = fuse_kinds(&[
            (SignalKind::RegexMatch, 1.0),
            (SignalKind::LuhnCheck, 0.0),
            (SignalKind::EntropyBand, 0.0),
            (SignalKind::NerContext, 0.0),
        ]);
        assert!(c < 0.5, "bare regex w/o luhn must stay below 0.5: {c}");
    }

    #[test]
    fn fuse_regex_plus_luhn_passes_threshold() {
        // Regex + Luhn fire fully → z=0.7, z'=0.4, σ(1.6) ≈ 0.83.
        let c = fuse_kinds(&[
            (SignalKind::RegexMatch, 1.0),
            (SignalKind::LuhnCheck, 1.0),
            (SignalKind::EntropyBand, 0.0),
            (SignalKind::NerContext, 0.0),
        ]);
        assert!(c > 0.7);
    }

    #[test]
    fn fuse_three_signals_high_confidence() {
        // Regex + Luhn + context (no entropy)
        let c = fuse_kinds(&[
            (SignalKind::RegexMatch, 1.0),
            (SignalKind::LuhnCheck, 1.0),
            (SignalKind::EntropyBand, 0.0),
            (SignalKind::NerContext, 1.0),
        ]);
        assert!(c > 0.9, "three-signal fire: {c}");
    }

    #[test]
    fn fuse_empty_evidence_zero() {
        assert!(fuse(&[]).abs() < f32::EPSILON);
    }

    #[test]
    fn detector_skips_suppression_list() {
        let det = DlpDetector::with_builtin_suppression();
        let text = "card 4111111111111111 ok";
        let m = dlp_match(DlpMatchKind::CreditCard, 5, 16, "4111**11");
        // 4111111111111111 is a builtin test PAN — must be suppressed.
        assert!(det.evaluate(text, &m).is_none());
    }

    #[test]
    fn detector_emits_event_with_signals() {
        let det = DlpDetector::with_suppression(SuppressionList::empty());
        // Use a Luhn-valid PAN NOT in the builtin list.
        let text = "card number: 4539578763621486 thanks";
        let m = dlp_match(DlpMatchKind::CreditCard, 13, 16, "4539****86");
        let ev = det.evaluate(text, &m).unwrap();
        assert_eq!(ev.kind, DlpMatchKind::CreditCard);
        assert_eq!(ev.span, Span::new(13, 29));
        // All four signals on PAN.
        assert_eq!(ev.signals.len(), 4);
        let kinds: Vec<SignalKind> = ev.signals.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SignalKind::RegexMatch));
        assert!(kinds.contains(&SignalKind::LuhnCheck));
        assert!(kinds.contains(&SignalKind::EntropyBand));
        assert!(kinds.contains(&SignalKind::NerContext));
        // With every signal firing, confidence should be high.
        assert!(
            ev.confidence > 0.7,
            "expected high confidence, got {}",
            ev.confidence
        );
    }

    #[test]
    fn detector_threshold_drops_low_confidence() {
        let det = DlpDetector::with_suppression(SuppressionList::empty());
        // Random 16-digit run with a Luhn-VALID checksum but no context cue
        // and no Luhn signal would only fire weakly.
        // We construct an SSN match (3 signals) without context to land low.
        let text = "ref 555-12-3456 end";
        let m = dlp_match(DlpMatchKind::SsnUs, 4, 11, "555-***56");
        let events = det.evaluate_all(text, std::slice::from_ref(&m), 0.0);
        let low = events[0].confidence;
        let dropped = det.evaluate_all(text, &[m], low + 0.1);
        assert!(dropped.is_empty(), "threshold above confidence must drop");
    }

    #[test]
    fn detector_ssn_only_three_signals() {
        let det = DlpDetector::with_suppression(SuppressionList::empty());
        let text = "ssn: 555-12-3456 end";
        let m = dlp_match(DlpMatchKind::SsnUs, 5, 11, "555-***56");
        let ev = det.evaluate(text, &m).unwrap();
        // SSN gets regex + entropy + context (no Luhn).
        assert_eq!(ev.signals.len(), 3);
        let has_luhn = ev.signals.iter().any(|s| s.kind == SignalKind::LuhnCheck);
        assert!(!has_luhn, "SSN must not get a Luhn signal");
    }

    #[test]
    fn detection_event_serialises_with_signals() {
        let det = DlpDetector::with_suppression(SuppressionList::empty());
        let text = "card number: 4539578763621486";
        let m = dlp_match(DlpMatchKind::CreditCard, 13, 16, "4539****86");
        let ev = det.evaluate(text, &m).unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        // Explainability payload includes per-signal breakdown.
        assert!(json.contains("\"signals\""));
        assert!(json.contains("\"regex_match\""));
        assert!(json.contains("\"luhn_check\""));
        assert!(json.contains("\"confidence\""));
    }
}
