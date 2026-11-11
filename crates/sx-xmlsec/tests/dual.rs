//! TOP5-#1-PHASE-2A: behavioural tests for [`DualVerifier`].
//!
//! These tests live in `tests/` (integration-test crate) so they
//! exercise the public re-exports from `sx_xmlsec::*` the same way
//! the PHASE-2B cutover and the `verifier_factory` in `sx-iam` will.
//!
//! ## Why a hand-rolled tracing subscriber
//!
//! `tracing-test` is not in the workspace dev-dep set (see
//! `crates/sx-xmlsec/Cargo.toml`). A custom `Subscriber` is light
//! enough — we only need to:
//!
//! 1. Capture each event's *name* / *target* (the only field the
//!    `DualVerifier::report_mismatch` call site discriminates on).
//! 2. Count totals so the test can assert "exactly one" or "zero"
//!    events.
//!
//! The captured names are filtered to `xmldsig.shadow.mismatch.*`
//! (matched against the structured `event` field the producer
//! emits). Other events from upstream subscribers are ignored — the
//! test does not assert on the broader log stream.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sx_xmlsec::{
    DualVerifier, MismatchKind, SamlSpConfig, VerifierMode, VerifyOutcome, XmlDsigVerifier,
    XmlSecError,
};
use tracing::field::{Field, Visit};
use tracing::subscriber::with_default;
use tracing::{Event, Metadata, Subscriber};

// ---------------------------------------------------------------
// Stub verifier — fully driven by the constructor's `result` field.
// ---------------------------------------------------------------

#[derive(Debug, Clone)]
struct StubVerifier {
    name: &'static str,
    result: Result<VerifyOutcome, XmlSecError>,
}

impl StubVerifier {
    // `XmlSecError` carries `String` in some variants (`thiserror`
    // derived `Drop` semantics propagate through), so a wholesale
    // `const fn` here would require the caller to pass only the
    // unit-carrying variants. Stay non-const — these constructors
    // are test-only and only ever run once per test.
    #[allow(clippy::missing_const_for_fn)]
    fn err(name: &'static str, err: XmlSecError) -> Self {
        Self {
            name,
            result: Err(err),
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    fn ok(name: &'static str, signature_valid: bool) -> Self {
        Self {
            name,
            result: Ok(VerifyOutcome {
                verifier_name: name,
                signature_valid,
                signed_node_xpath: None,
                name_id: String::new(),
                not_on_or_after_unix: None,
            }),
        }
    }
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

// ---------------------------------------------------------------
// Tracing capture — matches events whose `event` field starts with
// `xmldsig.shadow.mismatch.`. The captured value is the full field
// (e.g. `xmldsig.shadow.mismatch.primary_only_accept`).
// ---------------------------------------------------------------

#[derive(Default)]
struct EventCapture {
    captured: Mutex<Vec<String>>,
}

impl EventCapture {
    fn names(&self) -> Vec<String> {
        // `lock().unwrap()` is acceptable here: the mutex is local
        // to the test and not contended by panicking threads.
        self.captured.lock().unwrap().clone()
    }
}

/// Visits an event's fields, collecting the value of the `event`
/// field (a `&str`) into `out` if present. Other fields are
/// ignored. We use `record_str` so the producer's `event = "..."`
/// literal is captured verbatim.
struct EventFieldVisitor<'a> {
    out: &'a mut Option<String>,
}

impl Visit for EventFieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "event" {
            *self.out = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // Some tracing macros route `record_debug` even for string
        // literals. Mirror the `record_str` logic so the test is
        // robust to macro-expansion details.
        if field.name() == "event" {
            *self.out = Some(format!("{value:?}").trim_matches('"').to_owned());
        }
    }
}

/// Minimal subscriber that:
///
/// * always reports interest in every callsite (`enabled` returns
///   `true`) so the producer never short-circuits on filter checks,
/// * inspects each event's `event` field via [`EventFieldVisitor`],
/// * appends matching names to the shared capture buffer.
///
/// Span-related callbacks (`new_span` / `record` / `enter` / `exit`)
/// are no-ops because `DualVerifier::report_mismatch` does not open
/// spans.
struct CaptureSubscriber {
    capture: Arc<EventCapture>,
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::Id {
        // ID is irrelevant — we never read it back.
        tracing::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut event_field: Option<String> = None;
        let mut visitor = EventFieldVisitor {
            out: &mut event_field,
        };
        event.record(&mut visitor);
        if let Some(name) = event_field {
            if name.starts_with("xmldsig.shadow.mismatch.") {
                // `lock().unwrap()` is acceptable here: the mutex
                // is local to the test and not contended by
                // panicking threads.
                self.capture.lock_push(&name);
            }
        }
    }

    fn enter(&self, _span: &tracing::Id) {}
    fn exit(&self, _span: &tracing::Id) {}
}

/// Internal helper — pushes a captured event name onto the shared
/// buffer. Defined as a trait method so the call-site at
/// `Subscriber::event` stays readable.
trait LockPush {
    fn lock_push(&self, value: &str);
}

impl LockPush for Arc<EventCapture> {
    fn lock_push(&self, value: &str) {
        // `lock().unwrap()` is acceptable here: the mutex is local
        // to the test and not contended by panicking threads.
        self.captured.lock().unwrap().push(value.to_owned());
    }
}

fn cfg() -> SamlSpConfig {
    SamlSpConfig {
        entity_id: "https://sp.example/metadata".to_owned(),
        sso_url: "https://idp.example/sso".to_owned(),
        slo_url: None,
        x509_cert_pem: String::new(),
    }
}

/// Run `f` with a fresh `CaptureSubscriber`, returning the captured
/// event names.
fn capture_events<F: FnOnce()>(f: F) -> Vec<String> {
    let capture = Arc::new(EventCapture::default());
    let subscriber = CaptureSubscriber {
        capture: Arc::clone(&capture),
    };
    with_default(subscriber, f);
    capture.names()
}

// ---------------------------------------------------------------
// Tests
// ---------------------------------------------------------------

#[test]
fn agree_ok_emits_no_event() {
    // Both verifiers accept; signature_valid matches. No mismatch
    // event should be emitted.
    let primary = StubVerifier::ok("p", true);
    let secondary = StubVerifier::ok("s", true);
    let dv = DualVerifier::new(primary, secondary, VerifierMode::PrimaryAuthoritative);

    let events = capture_events(|| {
        let r = dv.verify(b"<x/>", &cfg(), "aud", Duration::from_secs(0));
        assert!(r.is_ok());
    });

    assert!(
        events.is_empty(),
        "agreement (both Ok) must emit no mismatch event, got {events:?}"
    );
}

#[test]
fn agree_err_emits_no_event() {
    // Both verifiers reject with the same variant. PHASE-2A's
    // classifier treats this as agreement — no event.
    let primary = StubVerifier::err("p", XmlSecError::SignatureInvalid);
    let secondary = StubVerifier::err("s", XmlSecError::SignatureInvalid);
    let dv = DualVerifier::new(primary, secondary, VerifierMode::PrimaryAuthoritative);

    let events = capture_events(|| {
        let r = dv.verify(b"<x/>", &cfg(), "aud", Duration::from_secs(0));
        assert!(r.is_err());
    });

    assert!(
        events.is_empty(),
        "agreement (both Err same variant) must emit no mismatch event, got {events:?}"
    );
}

#[test]
fn primary_ok_secondary_err_logs_mismatch() {
    // Primary accepts, secondary rejects. Exactly one
    // `primary_only_accept` event MUST be emitted. Under
    // PrimaryAuthoritative the returned result is the primary's
    // Ok — primary wins regardless of the disagreement.
    let primary = StubVerifier::ok("p", true);
    let secondary = StubVerifier::err("s", XmlSecError::SignatureInvalid);
    let dv = DualVerifier::new(primary, secondary, VerifierMode::PrimaryAuthoritative);

    let mut returned: Option<Result<VerifyOutcome, XmlSecError>> = None;
    let events = capture_events(|| {
        returned = Some(dv.verify(b"<x/>", &cfg(), "aud", Duration::from_secs(0)));
    });

    assert_eq!(
        events,
        vec![format!(
            "xmldsig.shadow.mismatch.{}",
            MismatchKind::PrimaryOnlyAccept.as_label()
        )],
        "expected exactly one primary_only_accept event"
    );
    let r = returned.expect("verify must have been called");
    assert!(
        r.is_ok(),
        "PrimaryAuthoritative + primary-Ok must return Ok"
    );
}

#[test]
fn secondary_ok_primary_err_logs_mismatch() {
    // Primary rejects, secondary accepts. Exactly one
    // `secondary_only_accept` event MUST be emitted. Under
    // PrimaryAuthoritative the returned result is the primary's
    // Err — primary wins.
    let primary = StubVerifier::err("p", XmlSecError::SignatureInvalid);
    let secondary = StubVerifier::ok("s", true);
    let dv = DualVerifier::new(primary, secondary, VerifierMode::PrimaryAuthoritative);

    let mut returned: Option<Result<VerifyOutcome, XmlSecError>> = None;
    let events = capture_events(|| {
        returned = Some(dv.verify(b"<x/>", &cfg(), "aud", Duration::from_secs(0)));
    });

    assert_eq!(
        events,
        vec![format!(
            "xmldsig.shadow.mismatch.{}",
            MismatchKind::SecondaryOnlyAccept.as_label()
        )],
        "expected exactly one secondary_only_accept event"
    );
    let r = returned.expect("verify must have been called");
    assert!(
        r.is_err(),
        "PrimaryAuthoritative + primary-Err must return Err (primary wins)"
    );
}

#[test]
fn secondary_authoritative_mode_inverts() {
    // Same primary-err / secondary-ok input as the previous test,
    // but mode = SecondaryAuthoritative inverts the returned side.
    // The shadow-mode classifier still logs the disagreement (the
    // categorisation is about WHICH side accepted, not WHO won) —
    // but the returned `Result` reflects the secondary's Ok.
    let primary = StubVerifier::err("p", XmlSecError::SignatureInvalid);
    let secondary = StubVerifier::ok("s", true);
    let dv = DualVerifier::new(primary, secondary, VerifierMode::SecondaryAuthoritative);

    let mut returned: Option<Result<VerifyOutcome, XmlSecError>> = None;
    let events = capture_events(|| {
        returned = Some(dv.verify(b"<x/>", &cfg(), "aud", Duration::from_secs(0)));
    });

    assert_eq!(
        events,
        vec![format!(
            "xmldsig.shadow.mismatch.{}",
            MismatchKind::SecondaryOnlyAccept.as_label()
        )],
        "mismatch classification is mode-invariant"
    );
    let r = returned.expect("verify must have been called");
    assert!(
        r.is_ok(),
        "SecondaryAuthoritative + secondary-Ok must return Ok (secondary wins)"
    );
}
