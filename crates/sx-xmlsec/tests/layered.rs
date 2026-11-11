//! PHASE-1C integration tests for [`sx_xmlsec::LayeredVerifier`].
//!
//! These tests assert the wrapper's call-order contract using a stub
//! `XmlDsigVerifier` impl — no libxmlsec1 linkage required. They run
//! under the default `--no-default-features` build path so the
//! workspace-check job exercises them on every developer machine.
//!
//! The contract under test:
//!
//! 1. `gates_fail_short_circuits_before_inner` — if the gate closure
//!    returns `Err(PreParseRejected)`, the inner verifier is NEVER
//!    invoked. This is the defence-in-depth guarantee: a rejected
//!    document never reaches the (PHASE-2A) FFI surface.
//! 2. `gates_pass_invokes_inner` — if the gates pass, the inner
//!    verifier's result is returned verbatim. The wrapper is
//!    transparent on the happy path.
//! 3. `name_pass_through` — the wrapper reports the inner's `name()`,
//!    not a wrapper-specific label, so PHASE-2A's shadow-mode
//!    classifier attributes results to the underlying verifier.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sx_xmlsec::{LayeredVerifier, SamlSpConfig, VerifyOutcome, XmlDsigVerifier, XmlSecError};

/// Stub verifier that records whether `verify` was called. Used to
/// assert that gate-rejection short-circuits before the inner is
/// reached.
struct RecordingStub {
    name: &'static str,
    called: Arc<AtomicBool>,
}

impl XmlDsigVerifier for RecordingStub {
    fn verify(
        &self,
        _xml: &[u8],
        _cfg: &SamlSpConfig,
        _audience: &str,
        _skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError> {
        self.called.store(true, Ordering::SeqCst);
        Ok(VerifyOutcome {
            verifier_name: self.name,
            signature_valid: true,
            signed_node_xpath: None,
            name_id: String::new(),
            not_on_or_after_unix: None,
        })
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Stub verifier that panics if `verify` is invoked. Used to assert
/// the wrapper's short-circuit: if the gates reject, the inner MUST
/// never be reached.
struct PanickingStub {
    name: &'static str,
}

impl XmlDsigVerifier for PanickingStub {
    fn verify(
        &self,
        _xml: &[u8],
        _cfg: &SamlSpConfig,
        _audience: &str,
        _skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError> {
        panic!("inner verifier reached despite gate rejection — defence-in-depth contract violated")
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

fn dummy_cfg() -> SamlSpConfig {
    SamlSpConfig {
        entity_id: "https://sp.example.com/saml".to_owned(),
        sso_url: "https://idp.example.com/sso".to_owned(),
        slo_url: None,
        x509_cert_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".to_owned(),
    }
}

#[test]
fn gates_fail_short_circuits_before_inner() {
    let stub = PanickingStub { name: "xmlsec1" };
    let layered = LayeredVerifier::new(
        stub,
        Box::new(|_xml: &[u8]| {
            Err(XmlSecError::PreParseRejected(
                "DOCTYPE/DTD rejected".to_owned(),
            ))
        }),
    );

    let result = layered.verify(
        b"<doctype-laden xml/>",
        &dummy_cfg(),
        "https://sp.example.com/saml",
        Duration::from_secs(30),
    );

    match result {
        Err(XmlSecError::PreParseRejected(msg)) => {
            assert_eq!(msg, "DOCTYPE/DTD rejected");
        }
        other => panic!("expected PreParseRejected, got {other:?}"),
    }
}

#[test]
fn gates_pass_invokes_inner() {
    let called = Arc::new(AtomicBool::new(false));
    let stub = RecordingStub {
        name: "xmlsec1",
        called: Arc::clone(&called),
    };
    let layered = LayeredVerifier::new(stub, Box::new(|_xml: &[u8]| Ok(())));

    let result = layered.verify(
        b"<minimal/>",
        &dummy_cfg(),
        "https://sp.example.com/saml",
        Duration::from_secs(30),
    );

    let outcome = result.expect("gates passed, inner stub returned Ok");
    assert!(
        called.load(Ordering::SeqCst),
        "inner verifier was not invoked despite gates passing"
    );
    assert_eq!(outcome.verifier_name, "xmlsec1");
    assert!(outcome.signature_valid);
}

#[test]
fn name_pass_through() {
    let called = Arc::new(AtomicBool::new(false));
    let stub = RecordingStub {
        name: "xmlsec1",
        called,
    };
    let layered = LayeredVerifier::new(stub, Box::new(|_| Ok(())));
    assert_eq!(layered.name(), "xmlsec1");
}
