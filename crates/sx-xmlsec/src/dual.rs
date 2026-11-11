//! PHASE-2A: shadow-mode `DualVerifier`.
//!
//! Runs **two** [`XmlDsigVerifier`] implementations on the same input,
//! compares their results, and emits structured tracing events +
//! Prometheus counters whenever they disagree. One side is declared
//! *authoritative* — its result is what `verify` returns — and the other
//! runs purely for observation.
//!
//! ## Why shadow-mode
//!
//! Per `docs/plans/top5-1-xmldsig-replacement.md` §2.1 the migration
//! strategy is shadow-mode: hand-rolled and libxmlsec1 verifiers run
//! side-by-side for ≥4 weeks, mismatches surface via telemetry, and
//! cutover is gated on "zero disagreements for 14 consecutive days
//! against real production traffic." Returning the authoritative
//! side's result unchanged keeps blast radius minimal — the shadow
//! side is observation-only until PHASE-2B's gate cutover.
//!
//! ## Mismatch classification
//!
//! Three kinds, mirroring the senior plan's §2.2 Class A / B classifier:
//!
//! * `both_accept_differ` — both verifiers returned `Ok` but the
//!   `VerifyOutcome` fields differ. PHASE-2A only compares the
//!   stable `signature_valid` boolean (PHASE-1C's `VerifyOutcome`
//!   carries that plus `signed_node_xpath`; we deliberately omit the
//!   XPath comparison until PHASE-2B because the hand-rolled side
//!   does not populate it yet). The downstream comparator widens to
//!   more fields in PHASE-2B once both sides agree on the field set.
//! * `primary_only_accept` — primary `Ok`, secondary `Err`. In
//!   [`VerifierMode::PrimaryAuthoritative`] this is the "shadow
//!   rejected what production accepted" alarm class.
//! * `secondary_only_accept` — primary `Err`, secondary `Ok`. In
//!   [`VerifierMode::PrimaryAuthoritative`] this is the "shadow
//!   accepted what production rejected" class.
//!
//! When **both** verifiers agree (both `Ok` with equal compared
//! fields, or both `Err`) no event is emitted and no counter is
//! incremented. This keeps the disagreement signal high-S/N during
//! the shadow window — the Class C "both err, different variant"
//! noise is folded into the silent-success bucket because PHASE-2A
//! only compares variants at the `Ok`/`Err` level (the planner's
//! §2.2 explicitly allows this — "different layers may reject
//! first; both must return Err" is sufficient).
//!
//! ## Dormant in PHASE-2A
//!
//! PHASE-2A ships this dispatcher dormant. The production SAML SP
//! path in `sx-iam`'s `verify_assertion` still calls the hand-rolled
//! verifier directly. PHASE-2A's `verifier_factory` constructs the
//! `DualVerifier` so PHASE-2B's gate cutover has a wired surface to
//! flip; until then this code path is exercised only by
//! `crates/sx-xmlsec/tests/dual.rs`.

use std::time::Duration;

use metrics::counter;
use tracing::warn;

use crate::error::XmlSecError;
use crate::verifier::{SamlSpConfig, VerifyOutcome, XmlDsigVerifier};

/// Prometheus counter name emitted by [`DualVerifier`] on every disagreement.
///
/// The single label `kind` carries one of the three values defined by
/// [`MismatchKind::as_label`]. The counter is described once via
/// `sx_telemetry::metrics::register_business_metrics` so the Prometheus
/// exporter emits `# HELP` / `# TYPE` lines for it before any traffic is
/// processed.
pub const METRIC_XMLDSIG_SHADOW_MISMATCH: &str = "xmldsig_shadow_mismatch_total";

/// Which side of a [`DualVerifier`] pair is authoritative — i.e.
/// whose result is returned to the caller.
///
/// Shadow-mode rollout per the senior plan §2.2 starts at
/// [`PrimaryAuthoritative`](Self::PrimaryAuthoritative) (the
/// hand-rolled production path stays authoritative; libxmlsec1 runs
/// for observation). PHASE-2B flips a per-tenant fraction to
/// [`SecondaryAuthoritative`](Self::SecondaryAuthoritative) as a
/// confidence-building reverse shadow before global cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierMode {
    /// `primary.verify(...)` result is returned; `secondary` runs
    /// purely for observation. Mismatches are logged and counted but
    /// never surfaced to the caller. This is the safe default during
    /// the shadow window.
    PrimaryAuthoritative,
    /// `secondary.verify(...)` result is returned; `primary` runs
    /// purely for observation. PHASE-2B's reverse-shadow stage uses
    /// this to validate the libxmlsec1 side end-to-end before the
    /// final cutover.
    SecondaryAuthoritative,
}

/// One of three structured mismatch categories. Used as the `kind`
/// label on the Prometheus counter and as the event name fragment on
/// the tracing event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchKind {
    /// Both verifiers returned `Ok` but the compared
    /// [`VerifyOutcome`] fields differ. PHASE-2A compares only
    /// `signature_valid` — wider field parity arrives in PHASE-2B.
    BothAcceptDiffer,
    /// Primary returned `Ok`, secondary returned `Err`. In
    /// `PrimaryAuthoritative` mode this is the Class A alarm class
    /// from the senior plan §2.2.
    PrimaryOnlyAccept,
    /// Primary returned `Err`, secondary returned `Ok`. In
    /// `PrimaryAuthoritative` mode this is the Class B alarm class
    /// from the senior plan §2.2.
    SecondaryOnlyAccept,
}

impl MismatchKind {
    /// Stable lowercase snake_case label for the
    /// [`METRIC_XMLDSIG_SHADOW_MISMATCH`] counter's `kind` dimension.
    /// Mirrored verbatim in the tracing event name suffix.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::BothAcceptDiffer => "both_accept_differ",
            Self::PrimaryOnlyAccept => "primary_only_accept",
            Self::SecondaryOnlyAccept => "secondary_only_accept",
        }
    }
}

/// Shadow-mode dispatcher that runs **two** verifiers and compares
/// their results.
///
/// Construct via [`Self::new`]. The `mode` field selects which side's
/// result is authoritative — see [`VerifierMode`] for the semantics.
///
/// ## Concurrency
///
/// PHASE-2A invokes both verifiers **sequentially** on the calling
/// thread. Concurrent dispatch (via `tokio::spawn_blocking` /
/// `rayon::join`) is a future optimisation — for the shadow window
/// the extra latency of running both is acceptable (~5 ms median per
/// the senior plan §4 R4 budget) and serial dispatch keeps the
/// implementation reviewable and the test surface deterministic.
pub struct DualVerifier<A: XmlDsigVerifier, B: XmlDsigVerifier> {
    primary: A,
    secondary: B,
    mode: VerifierMode,
}

impl<A: XmlDsigVerifier, B: XmlDsigVerifier> DualVerifier<A, B> {
    /// Construct a new `DualVerifier`.
    ///
    /// `primary` and `secondary` are positional; the
    /// [`VerifierMode`] picks which side is authoritative regardless
    /// of position. The conventional wiring during the shadow window
    /// is `primary = hand-rolled`, `secondary = layered xmlsec1`,
    /// `mode = PrimaryAuthoritative` (so the production result stays
    /// unchanged).
    pub const fn new(primary: A, secondary: B, mode: VerifierMode) -> Self {
        Self {
            primary,
            secondary,
            mode,
        }
    }

    /// Borrow the primary verifier (test introspection).
    #[must_use]
    pub const fn primary(&self) -> &A {
        &self.primary
    }

    /// Borrow the secondary verifier (test introspection).
    #[must_use]
    pub const fn secondary(&self) -> &B {
        &self.secondary
    }

    /// The configured authoritative side.
    #[must_use]
    pub const fn mode(&self) -> VerifierMode {
        self.mode
    }

    /// Classify a pair of verifier results, returning `Some(kind)`
    /// when they disagree and `None` when they agree.
    ///
    /// Disagreement matrix (PHASE-2A scope — `signature_valid` only):
    ///
    /// | primary | secondary | classification |
    /// |---|---|---|
    /// | `Ok(a)` | `Ok(b)` if `a.signature_valid == b.signature_valid` | agree → `None` |
    /// | `Ok(a)` | `Ok(b)` otherwise | [`MismatchKind::BothAcceptDiffer`] |
    /// | `Ok(_)` | `Err(_)` | [`MismatchKind::PrimaryOnlyAccept`] |
    /// | `Err(_)` | `Ok(_)` | [`MismatchKind::SecondaryOnlyAccept`] |
    /// | `Err(_)` | `Err(_)` | agree → `None` (variant divergence is Class C — ignored in PHASE-2A) |
    const fn classify(
        primary: &Result<VerifyOutcome, XmlSecError>,
        secondary: &Result<VerifyOutcome, XmlSecError>,
    ) -> Option<MismatchKind> {
        match (primary, secondary) {
            (Ok(a), Ok(b)) => {
                if a.signature_valid == b.signature_valid {
                    None
                } else {
                    Some(MismatchKind::BothAcceptDiffer)
                }
            }
            (Ok(_), Err(_)) => Some(MismatchKind::PrimaryOnlyAccept),
            (Err(_), Ok(_)) => Some(MismatchKind::SecondaryOnlyAccept),
            (Err(_), Err(_)) => None,
        }
    }

    /// Emit the structured tracing event + Prometheus counter for a
    /// disagreement classification.
    ///
    /// The event name is `xmldsig.shadow.mismatch.<kind>` (one of
    /// the three labels in [`MismatchKind::as_label`]). The Prometheus
    /// counter is `xmldsig_shadow_mismatch_total{kind="..."}`. Both
    /// telemetry sinks are emitted from the same call site so an
    /// alert on the counter has a tail-correlated tracing event to
    /// pivot to.
    fn report_mismatch(&self, kind: MismatchKind) {
        let kind_label = kind.as_label();
        let primary_name = self.primary.name();
        let secondary_name = self.secondary.name();

        // The static `event!` macro family doesn't accept dynamic
        // event names, so the three classifications are dispatched
        // explicitly. Each branch records the same field set so a
        // log-aggregation query can union them.
        match kind {
            MismatchKind::BothAcceptDiffer => warn!(
                event = "xmldsig.shadow.mismatch.both_accept_differ",
                kind = kind_label,
                primary = primary_name,
                secondary = secondary_name,
                "shadow-mode: both verifiers accepted but VerifyOutcome fields differ",
            ),
            MismatchKind::PrimaryOnlyAccept => warn!(
                event = "xmldsig.shadow.mismatch.primary_only_accept",
                kind = kind_label,
                primary = primary_name,
                secondary = secondary_name,
                "shadow-mode: primary accepted, secondary rejected",
            ),
            MismatchKind::SecondaryOnlyAccept => warn!(
                event = "xmldsig.shadow.mismatch.secondary_only_accept",
                kind = kind_label,
                primary = primary_name,
                secondary = secondary_name,
                "shadow-mode: primary rejected, secondary accepted",
            ),
        }

        counter!(METRIC_XMLDSIG_SHADOW_MISMATCH, "kind" => kind_label).increment(1);
    }
}

impl<A: XmlDsigVerifier, B: XmlDsigVerifier> std::fmt::Debug for DualVerifier<A, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DualVerifier")
            .field("primary_name", &self.primary.name())
            .field("secondary_name", &self.secondary.name())
            .field("mode", &self.mode)
            .finish()
    }
}

impl<A: XmlDsigVerifier, B: XmlDsigVerifier> XmlDsigVerifier for DualVerifier<A, B> {
    fn verify(
        &self,
        xml: &[u8],
        cfg: &SamlSpConfig,
        audience: &str,
        skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError> {
        // Run BOTH verifiers on the same input. Errors are captured
        // — neither side short-circuits the other. The authoritative
        // result is selected at the end based on `mode`; the other
        // side is observation-only.
        let primary_result = self.primary.verify(xml, cfg, audience, skew);
        let secondary_result = self.secondary.verify(xml, cfg, audience, skew);

        // Classify + report ONLY on disagreement. Agreement is the
        // happy-path silent-success bucket; emitting an event there
        // would dominate the metric stream and obscure the alarm
        // classes during the shadow window.
        if let Some(kind) = Self::classify(&primary_result, &secondary_result) {
            self.report_mismatch(kind);
        }

        // Return the authoritative side's result unmodified. The
        // shadow side is purely observational in PHASE-2A.
        match self.mode {
            VerifierMode::PrimaryAuthoritative => primary_result,
            VerifierMode::SecondaryAuthoritative => secondary_result,
        }
    }

    fn name(&self) -> &'static str {
        // Distinct from either inner name so the shadow-mode
        // classifier (and any downstream metric that labels by
        // `verifier_name`) can tell a DualVerifier-wired call site
        // apart from a single-verifier one. The `dual:` prefix is
        // load-bearing — the `verifier_factory` integration test
        // asserts on it as the discriminator between shadow-mode
        // and direct dispatch.
        "dual:shadow"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Unit-test verifier whose result is fully driven by the
    /// constructor. Behavioural tests in `tests/dual.rs` use the same
    /// shape; this duplicate exists so the classify/report paths can
    /// be exercised without an integration-test crate boundary.
    #[derive(Debug, Clone)]
    struct StubVerifier {
        name: &'static str,
        result: Result<VerifyOutcome, XmlSecError>,
    }

    impl XmlDsigVerifier for StubVerifier {
        fn verify(
            &self,
            _xml: &[u8],
            _cfg: &SamlSpConfig,
            _audience: &str,
            _skew: Duration,
        ) -> Result<VerifyOutcome, XmlSecError> {
            self.result.clone()
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn outcome(name: &'static str, signature_valid: bool) -> VerifyOutcome {
        VerifyOutcome {
            verifier_name: name,
            signature_valid,
            signed_node_xpath: None,
            name_id: String::new(),
            not_on_or_after_unix: None,
        }
    }

    #[test]
    fn classify_both_ok_equal_signature_valid_agrees() {
        let p: Result<VerifyOutcome, XmlSecError> = Ok(outcome("p", true));
        let s: Result<VerifyOutcome, XmlSecError> = Ok(outcome("s", true));
        assert_eq!(
            DualVerifier::<StubVerifier, StubVerifier>::classify(&p, &s),
            None
        );
    }

    #[test]
    fn classify_both_ok_differ_signature_valid() {
        let p: Result<VerifyOutcome, XmlSecError> = Ok(outcome("p", true));
        let s: Result<VerifyOutcome, XmlSecError> = Ok(outcome("s", false));
        assert_eq!(
            DualVerifier::<StubVerifier, StubVerifier>::classify(&p, &s),
            Some(MismatchKind::BothAcceptDiffer),
        );
    }

    #[test]
    fn classify_primary_ok_secondary_err() {
        let p: Result<VerifyOutcome, XmlSecError> = Ok(outcome("p", true));
        let s: Result<VerifyOutcome, XmlSecError> = Err(XmlSecError::SignatureInvalid);
        assert_eq!(
            DualVerifier::<StubVerifier, StubVerifier>::classify(&p, &s),
            Some(MismatchKind::PrimaryOnlyAccept),
        );
    }

    #[test]
    fn classify_secondary_ok_primary_err() {
        let p: Result<VerifyOutcome, XmlSecError> = Err(XmlSecError::SignatureInvalid);
        let s: Result<VerifyOutcome, XmlSecError> = Ok(outcome("s", true));
        assert_eq!(
            DualVerifier::<StubVerifier, StubVerifier>::classify(&p, &s),
            Some(MismatchKind::SecondaryOnlyAccept),
        );
    }

    #[test]
    fn classify_both_err_same_variant_agrees() {
        let p = Err::<VerifyOutcome, _>(XmlSecError::SignatureInvalid);
        let s = Err::<VerifyOutcome, _>(XmlSecError::SignatureInvalid);
        assert_eq!(
            DualVerifier::<StubVerifier, StubVerifier>::classify(&p, &s),
            None
        );
    }

    #[test]
    fn classify_both_err_different_variant_still_agrees() {
        // Per the senior plan §2.2 Class C is silent in PHASE-2A —
        // different variants are folded into the silent-success
        // bucket. PHASE-2B widens the comparator.
        let p = Err::<VerifyOutcome, _>(XmlSecError::SignatureInvalid);
        let s = Err::<VerifyOutcome, _>(XmlSecError::VerifyFailed("x".to_owned()));
        assert_eq!(
            DualVerifier::<StubVerifier, StubVerifier>::classify(&p, &s),
            None
        );
    }

    #[test]
    fn mismatch_kind_labels_are_stable() {
        assert_eq!(
            MismatchKind::BothAcceptDiffer.as_label(),
            "both_accept_differ"
        );
        assert_eq!(
            MismatchKind::PrimaryOnlyAccept.as_label(),
            "primary_only_accept"
        );
        assert_eq!(
            MismatchKind::SecondaryOnlyAccept.as_label(),
            "secondary_only_accept"
        );
    }

    #[test]
    fn dual_verifier_name_is_dual_shadow() {
        let p = StubVerifier {
            name: "handrolled",
            result: Ok(outcome("handrolled", true)),
        };
        let s = StubVerifier {
            name: "xmlsec1",
            result: Ok(outcome("xmlsec1", true)),
        };
        let dv = DualVerifier::new(p, s, VerifierMode::PrimaryAuthoritative);
        assert_eq!(dv.name(), "dual:shadow");
    }
}
