//! SAML SP attack observer (TOP5-#3-P2-004).
//!
//! The SP verifier in [`super::fuzz_entry`] rejects every known XML
//! Signature attack shape (XSW, XEE, transform-bypass, C14N violation)
//! via the coarse [`super::SamlError`] surface. Today those rejections
//! only surface in IAM auth logs — auditors expect them in the canonical
//! Findings store as evidence-of-attempt evidence trail (PCI / SOC 2).
//!
//! This module introduces a thin observer trait the verifier-adjacent
//! layer can call when it classifies a rejection as one of the four
//! well-known attack shapes. The monolith adapter implements the trait
//! and translates the event into a `Finding` inserted via
//! `FindingRepositoryPort::insert`. The translation deliberately lives
//! in the adapter so this crate retains a `sx-core`-only dependency
//! envelope (no `sx-api`).
//!
//! The verifier never *invents* detection — every signal flows from
//! existing rejection points in [`super::fuzz_entry::pre_parse_gates`]
//! and the multi-`<Assertion>` defence in [`super::response`].
//! Classification of [`SamlError`] → [`SamlAttackKind`] is performed by
//! [`classify_attack`], which inspects the [`SamlError::XmlMalformed`]
//! message tag the gate layer emits.

use std::sync::Arc;

use super::SamlError;

/// One detected SAML attack class.
///
/// Variants map 1:1 onto the four enrichment rows curated in
/// `sx_core::reference::saml_attack_enrichment`. New attack families
/// should land alongside a new enrichment row, not as a renamed variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlAttackKind {
    /// XML Signature Wrapping — multiple `<Assertion>` / `<Signature>`
    /// elements, or a `Reference URI` that does not bind the signed
    /// subtree.
    Xsw,
    /// XML External Entity — the document contained a DOCTYPE / DTD
    /// declaration. The gate refuses DOCTYPE outright.
    Xee,
    /// Transform allow-list violation — XSLT, XPath, or an unknown
    /// transform URI in the `<Transform>` chain. This is the classic
    /// signature-bypass shape: smuggle hostile bytes through a transform
    /// the digest does not cover.
    TransformBypass,
    /// C14N policy violation — legacy `xml-c14n` (non-exclusive),
    /// mixed canonicalisation versions, default-namespace
    /// re-declaration inside `<SignedInfo>`, or missing
    /// `CanonicalizationMethod`. Strictly weaker than a wrapping attack
    /// (digest can still be enforced) so rated Medium downstream.
    C14nViolation,
}

impl SamlAttackKind {
    /// Legacy colon-form `metadata.rule_id`. Retained for backward-compat
    /// receive-side lookups (external SIEM rules may still pin these
    /// exact strings — the FOUND-001 contract specifies the set).
    /// Emitters use [`SamlAttackKind::rule_id_dotted`] as of TOP5-#3
    /// Phase 3.
    #[must_use]
    pub const fn rule_id(self) -> &'static str {
        match self {
            Self::Xsw => "saml:xsw-detected",
            Self::Xee => "saml:xee-detected",
            Self::TransformBypass => "saml:transform-bypass-detected",
            Self::C14nViolation => "saml:c14n-violation",
        }
    }

    /// Canonical dotted-form `metadata.rule_id` (TOP5-#3 Phase 3). Every
    /// fresh emit MUST use this shape. Mirrors the constants in
    /// [`sx_core::reference::saml_attack_enrichment`].
    #[must_use]
    pub const fn rule_id_dotted(self) -> &'static str {
        match self {
            Self::Xsw => "SAML.XSW",
            Self::Xee => "SAML.XEE",
            Self::TransformBypass => "SAML.TRANSFORM_BYPASS",
            Self::C14nViolation => "SAML.C14N",
        }
    }
}

/// Event payload handed to a [`SamlAttackObserver`] when a rejection
/// classifies as one of the well-known shapes.
///
/// Field names mirror the canonical `Finding` fields the adapter will
/// emit. `detected_at_unix` is supplied by the caller (rather than read
/// off `SystemTime::now()` inside the observer) so test fixtures can
/// drive deterministic idempotency hashing.
#[derive(Debug, Clone)]
pub struct SamlAttackEvent {
    /// Tenant id (uuid string) of the SP that rejected the response.
    pub tenant_id: String,
    /// Detected attack class.
    pub kind: SamlAttackKind,
    /// IdP `EntityID` (Issuer) the attack came from. May be empty when
    /// the gate refused the document before `Issuer` was parseable.
    pub idp_issuer: String,
    /// Unix-epoch seconds the rejection happened. Used to bucket
    /// idempotency by day (UTC midnight) so a flood of XSW attempts
    /// from the same IdP on the same day collapses to one finding.
    pub detected_at_unix: i64,
}

/// Trait the SAML SP adapter implements to surface attack rejections as
/// `Finding` rows.
///
/// `Send + Sync` so the verifier-adjacent layer can hold the observer
/// behind an `Arc<dyn …>` without a separate spawn boundary. The
/// `notify` method is intentionally synchronous + infallible — the
/// observer must not propagate I/O errors into the verifier (the
/// rejection still stands; surfacing the finding is a best-effort
/// side-effect).
pub trait SamlAttackObserver: Send + Sync {
    /// Record an attack detection.
    ///
    /// Implementations MUST NOT block the calling thread on remote
    /// I/O. The monolith adapter dispatches via the
    /// `FindingRepositoryPort::insert` async surface inside a
    /// `tokio::spawn` so the SP-verifier hot path stays bounded.
    fn notify(&self, event: SamlAttackEvent);
}

/// No-op observer for unwired call sites.
///
/// Used by composition roots that have not wired the monolith adapter
/// (typically integration tests for other SAML scenarios). Equivalent
/// to "no Finding surfaces"; the gate-level rejection is unchanged.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSamlAttackObserver;

impl SamlAttackObserver for NoopSamlAttackObserver {
    fn notify(&self, _event: SamlAttackEvent) {
        // Intentionally empty — see type doc.
    }
}

/// Type alias for the verifier-side handle on the observer. Keeping
/// this in one place avoids `Arc<dyn SamlAttackObserver>` repeated
/// across every call site.
pub type SharedSamlAttackObserver = Arc<dyn SamlAttackObserver>;

/// Classify a [`SamlError`] returned by the SP verifier into a
/// well-known [`SamlAttackKind`].
///
/// The mapping is purely syntactic — the gate layer in
/// [`super::fuzz_entry::pre_parse_gates`] emits stable
/// [`SamlError::XmlMalformed`] tags; this function inspects those tags.
/// Returns `None` for errors that are NOT one of the four curated
/// attack shapes (signature mismatch alone, replay, generic
/// XmlMalformed without a wrapping/XEE/transform/C14N marker).
///
/// # Why classify here, not in the gate
///
/// The fuzz harness (`docs/security/saml-xmldsig-fuzzing.md`) drives
/// the gate layer directly with the 21-test corpus; adding a side
/// channel inside the gate would muddy the contract that gates return
/// `SamlError` and only `SamlError`. The observer wiring lives one
/// layer up, classifies the existing error, and surfaces the Finding.
#[must_use]
pub fn classify_attack(error: &SamlError) -> Option<SamlAttackKind> {
    match error {
        // Multiple top-level <Assertion> elements — classical XSW.
        SamlError::MultipleAssertions => Some(SamlAttackKind::Xsw),
        SamlError::XmlMalformed(msg) => classify_xml_malformed(msg),
        // Signature alone could be many things — refuse to invent a
        // class.  Time-window, audience, replay are protocol errors,
        // not attack shapes.
        SamlError::SignatureInvalid
        | SamlError::AudienceMismatch
        | SamlError::TimeWindow
        | SamlError::ReplayAssertion => None,
    }
}

/// Inspect a `SamlError::XmlMalformed` message for the curated
/// attack-class markers. Markers are exact substrings of the strings
/// emitted by [`super::fuzz_entry::pre_parse_gates`] — adding a new
/// gate message there MUST be accompanied by a new branch here.
fn classify_xml_malformed(msg: &str) -> Option<SamlAttackKind> {
    if msg.contains("DOCTYPE/DTD rejected") {
        return Some(SamlAttackKind::Xee);
    }
    if msg.contains("multiple <Signature>")
        || msg.contains("Reference URI does not resolve")
        || msg.contains("Reference URI must be same-document")
        || msg.contains("Reference URI missing")
    {
        return Some(SamlAttackKind::Xsw);
    }
    if msg.starts_with("transform forbidden") {
        return Some(SamlAttackKind::TransformBypass);
    }
    if msg.starts_with("C14N strict") {
        return Some(SamlAttackKind::C14nViolation);
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn classify_multiple_assertions_is_xsw() {
        assert_eq!(
            classify_attack(&SamlError::MultipleAssertions),
            Some(SamlAttackKind::Xsw)
        );
    }

    #[test]
    fn classify_doctype_is_xee() {
        let e = SamlError::XmlMalformed("DOCTYPE/DTD rejected".into());
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::Xee));
    }

    #[test]
    fn classify_xslt_transform_is_transform_bypass() {
        let e = SamlError::XmlMalformed("transform forbidden: XSLT".into());
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::TransformBypass));
    }

    #[test]
    fn classify_xpath_transform_is_transform_bypass() {
        let e = SamlError::XmlMalformed("transform forbidden: XPath".into());
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::TransformBypass));
    }

    #[test]
    fn classify_unknown_transform_is_transform_bypass() {
        let e = SamlError::XmlMalformed(
            "transform forbidden: unknown URI http://attacker/transform".into(),
        );
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::TransformBypass));
    }

    #[test]
    fn classify_c14n_legacy_is_c14n_violation() {
        let e =
            SamlError::XmlMalformed("C14N strict: legacy xml-c14n (non-exclusive) rejected".into());
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::C14nViolation));
    }

    #[test]
    fn classify_c14n_mixed_is_c14n_violation() {
        let e = SamlError::XmlMalformed(
            "C14N strict: mixed canonicalisation versions in one document".into(),
        );
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::C14nViolation));
    }

    #[test]
    fn classify_c14n_default_ns_is_c14n_violation() {
        let e = SamlError::XmlMalformed(
            "C14N strict: default namespace re-declared in SignedInfo".into(),
        );
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::C14nViolation));
    }

    #[test]
    fn classify_multiple_signatures_is_xsw() {
        let e = SamlError::XmlMalformed("multiple <Signature> elements".into());
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::Xsw));
    }

    #[test]
    fn classify_reference_uri_drift_is_xsw() {
        let e =
            SamlError::XmlMalformed("Reference URI does not resolve to embedded Assertion".into());
        assert_eq!(classify_attack(&e), Some(SamlAttackKind::Xsw));
        let e2 = SamlError::XmlMalformed("Reference URI must be same-document fragment".into());
        assert_eq!(classify_attack(&e2), Some(SamlAttackKind::Xsw));
        let e3 = SamlError::XmlMalformed("Reference URI missing".into());
        assert_eq!(classify_attack(&e3), Some(SamlAttackKind::Xsw));
    }

    #[test]
    fn classify_signature_invalid_is_none() {
        // A signature mismatch alone could be a bad cert, a stale
        // assertion, an algorithm downgrade — the policy decision is to
        // NOT auto-classify it as an attack.
        assert!(classify_attack(&SamlError::SignatureInvalid).is_none());
    }

    #[test]
    fn classify_time_window_is_none() {
        assert!(classify_attack(&SamlError::TimeWindow).is_none());
    }

    #[test]
    fn classify_replay_is_none() {
        // Replay is its own protocol error with its own surface; not
        // an "attack class" in the FOUND-001 enumeration.
        assert!(classify_attack(&SamlError::ReplayAssertion).is_none());
    }

    #[test]
    fn classify_unrelated_malformed_is_none() {
        let e = SamlError::XmlMalformed("utf8: stream did not contain valid UTF-8".into());
        assert!(classify_attack(&e).is_none());
    }

    #[test]
    fn rule_id_strings_are_stable() {
        // FOUND-001 wire contract.
        assert_eq!(SamlAttackKind::Xsw.rule_id(), "saml:xsw-detected");
        assert_eq!(SamlAttackKind::Xee.rule_id(), "saml:xee-detected");
        assert_eq!(
            SamlAttackKind::TransformBypass.rule_id(),
            "saml:transform-bypass-detected"
        );
        assert_eq!(
            SamlAttackKind::C14nViolation.rule_id(),
            "saml:c14n-violation"
        );
    }

    #[test]
    fn rule_id_dotted_strings_are_stable() {
        // TOP5-#3 Phase 3 wire contract — every fresh emit uses these.
        assert_eq!(SamlAttackKind::Xsw.rule_id_dotted(), "SAML.XSW");
        assert_eq!(SamlAttackKind::Xee.rule_id_dotted(), "SAML.XEE");
        assert_eq!(
            SamlAttackKind::TransformBypass.rule_id_dotted(),
            "SAML.TRANSFORM_BYPASS"
        );
        assert_eq!(SamlAttackKind::C14nViolation.rule_id_dotted(), "SAML.C14N");
        // Dotted-form invariant: contains a `.` separator.
        for k in [
            SamlAttackKind::Xsw,
            SamlAttackKind::Xee,
            SamlAttackKind::TransformBypass,
            SamlAttackKind::C14nViolation,
        ] {
            assert!(k.rule_id_dotted().contains('.'));
        }
    }

    #[test]
    fn noop_observer_does_not_panic() {
        let obs = NoopSamlAttackObserver;
        obs.notify(SamlAttackEvent {
            tenant_id: "t1".into(),
            kind: SamlAttackKind::Xsw,
            idp_issuer: "https://idp".into(),
            detected_at_unix: 0,
        });
    }
}
