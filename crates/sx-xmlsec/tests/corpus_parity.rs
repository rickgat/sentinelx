//! TOP5-#1-PHASE-2B: HIGH-003 corpus parity test.
//!
//! Replays every adversarial XML fixture from the HIGH-003 SAML fuzz
//! corpus through BOTH verifier shapes — hand-rolled and
//! `LayeredVerifier(XmlSec1Verifier)` — and asserts both reject the
//! input. Per the senior plan §3.1 and the planning doc
//! `docs/plans/top5-1-xmldsig-replacement.md` §3, the corpus is a
//! NEGATIVE test: every shape MUST be rejected by both layers. A
//! disagreement (one accepts, the other rejects) is a hard failure
//! and would block the PHASE-2B cutover SLO.
//!
//! ## Corpus location
//!
//! Fixtures live at:
//!
//! ```text
//! crates/sx-iam/fuzz/corpus/saml_response_fuzz/*.xml
//! ```
//!
//! This is the same corpus the HIGH-003 libFuzzer harness consumes
//! (`crates/sx-iam/fuzz/fuzz_targets/saml_response_fuzz.rs`). A future
//! PHASE-3 extension can wire the existing fuzz harness through the
//! `DualVerifier` for ongoing differential validation; this test
//! provides the deterministic per-shape parity report ahead of that.
//!
//! Corpus contents (18 fixtures as of TOP5-#1-PHASE-2B):
//!
//! * **XSW**: `xsw1.xml` … `xsw8.xml` (8 Somorovsky/Schwenk shapes)
//! * **XEE**: `xee1_billion_laughs.xml`, `xee2_external_entity.xml`,
//!   `xee3_parameter_entity.xml`, `xee4_quadratic_blowup.xml` (4)
//! * **Transform abuse**: `transform1_xslt.xml`, `transform2_xpath.xml`,
//!   `transform3_unknown_uri.xml`, `transform4_mixed_c14n.xml` (4)
//! * **Misc**: `replay_same_assertion.xml`,
//!   `self_signed_attacker_ca.xml` (2)
//!
//! ## Gating
//!
//! The test is gated under `cfg(all(feature = "xmlsec1", target_os =
//! "linux"))` — same as the PHASE-1B integration tests in
//! `tests/verifier_core.rs`. macOS dev workstations and the
//! default-feature CI lane skip this test entirely; the Linux CI lane
//! that apt-installs `libxmlsec1-dev` runs it. The hand-rolled
//! verifier surface is exercised through the
//! `sx_iam::service::saml::HandRolledVerifier` adapter (PHASE-2A);
//! `LayeredVerifier(XmlSec1Verifier)` exercises the gate-layered
//! libxmlsec1 path.
//!
//! ## Rejection-reason agreement
//!
//! The test emits a structured per-shape report (via `println!` —
//! captured by `cargo test` output) listing:
//!
//! * shape name
//! * hand-rolled error variant
//! * xmlsec1 error variant
//! * agreement status (both rejected = pass; disagreement = fail)
//!
//! The variant strings need NOT match exactly — the senior plan §2.2
//! explicitly says "different layers may reject first; both must
//! return Err" is sufficient for parity. This test enforces the
//! `Err`/`Err` invariant and reports variants for human review.

#![cfg(all(feature = "xmlsec1", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use sx_xmlsec::{
    LayeredVerifier, SamlSpConfig as XmlSecSamlSpConfig, XmlDsigVerifier, XmlSec1Verifier,
};

/// Locate the corpus directory relative to the workspace root via
/// `CARGO_MANIFEST_DIR`. `sx-xmlsec`'s manifest dir is
/// `<workspace>/crates/sx-xmlsec/`; the corpus lives at
/// `<workspace>/crates/sx-iam/fuzz/corpus/saml_response_fuzz/`.
fn corpus_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // drop "sx-xmlsec"
    p.push("sx-iam");
    p.push("fuzz");
    p.push("corpus");
    p.push("saml_response_fuzz");
    p
}

/// Enumerate every `*.xml` file in the corpus, sorted by name so the
/// per-shape report is deterministic.
fn corpus_shapes() -> Vec<(String, Vec<u8>)> {
    let dir = corpus_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
        })
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    entries
        .into_iter()
        .map(|e| {
            let path = e.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|err| panic!("read corpus file {}: {err}", path.display()));
            (name, bytes)
        })
        .collect()
}

/// Stub SP config used for every shape — the corpus is exclusively
/// negative input that the pre-parse gates reject BEFORE the
/// cryptographic layer touches the cert. A placeholder PEM is fine
/// because the gate layer rejects every shape before
/// `verify_xmlsec1` reaches `xmlSecOpenSSLAppKeyLoadMemory`.
fn stub_cfg() -> XmlSecSamlSpConfig {
    XmlSecSamlSpConfig {
        entity_id: "https://sp.example/saml".to_owned(),
        sso_url: "https://idp.example/sso".to_owned(),
        slo_url: None,
        x509_cert_pem: String::new(),
    }
}

/// Categorise an error into a stable label for the per-shape report.
/// Hand-rolled and xmlsec1 errors use distinct enum types; this
/// reduces both to a comparable label.
fn label_xmlsec(err: &sx_xmlsec::XmlSecError) -> &'static str {
    use sx_xmlsec::XmlSecError;
    match err {
        XmlSecError::PreParseRejected(_) => "PreParseRejected",
        XmlSecError::XmlParseFailed(_) => "XmlParseFailed",
        XmlSecError::SignatureInvalid => "SignatureInvalid",
        XmlSecError::VerifyFailed(_) => "VerifyFailed",
        XmlSecError::KeysMngrFailed => "KeysMngrFailed",
        XmlSecError::DsigCtxFailed => "DsigCtxFailed",
        XmlSecError::InitFailed => "InitFailed",
    }
}

fn label_saml(err: &sx_iam::service::saml::SamlError) -> &'static str {
    use sx_iam::service::saml::SamlError;
    match err {
        SamlError::XmlMalformed(_) => "XmlMalformed",
        SamlError::SignatureInvalid => "SignatureInvalid",
        SamlError::AudienceMismatch => "AudienceMismatch",
        SamlError::TimeWindow => "TimeWindow",
        SamlError::ReplayAssertion => "ReplayAssertion",
        SamlError::MultipleAssertions => "MultipleAssertions",
    }
}

/// PHASE-2B contract test: every fixture in the HIGH-003 corpus must
/// be rejected by BOTH the hand-rolled verifier (via the PHASE-2A
/// adapter in `sx_iam::service::saml::HandRolledVerifier`) AND the
/// gate-layered libxmlsec1 verifier (`LayeredVerifier` over
/// `XmlSec1Verifier` with the `pre_parse_gates`-derived closure from
/// `sx_iam::service::saml::make_preparse_gates_closure`).
///
/// Per-shape report is emitted on stdout so a human reviewer can see
/// the rejection variant each layer attributed the failure to — useful
/// for the cutover SLO review.
#[test]
fn high003_corpus_rejected_by_both_verifiers() {
    use sx_iam::service::saml::{
        make_preparse_gates_closure, verify_assertion as iam_verify_assertion, SamlSigningAlgo,
        SamlSpConfig as IamSamlSpConfig,
    };

    let iam_cfg = IamSamlSpConfig {
        entity_id: "https://sp.example/saml".to_owned(),
        sso_url: "https://idp.example/sso".to_owned(),
        slo_url: None,
        x509_cert_pem: String::new(),
        signing_algo: SamlSigningAlgo::Sha256,
    };

    // Construct the layered libxmlsec1 verifier ONCE. The init
    // lifetime is shared across all shapes; this matches the
    // production composition root posture where `EnabledSamlAdapter`
    // holds one `Arc<dyn XmlDsigVerifier>` for the whole process.
    let xmlsec1 = match XmlSec1Verifier::new() {
        Ok(v) => v,
        // Init may legitimately fail on a host where libxmlsec1 is
        // installed but the OpenSSL backend is missing. Treat that as
        // a skip rather than a failure — the test cannot run, and the
        // test author would prefer to know about it explicitly via the
        // emitted log line rather than a confusing panic message.
        Err(sx_xmlsec::XmlSecError::InitFailed) => {
            println!(
                "corpus_parity: libxmlsec1 init failed (likely missing OpenSSL backend); skipping"
            );
            return;
        }
        Err(e) => panic!("unexpected xmlsec1 init error: {e:?}"),
    };
    let layered = LayeredVerifier::new(xmlsec1, make_preparse_gates_closure());

    let shapes = corpus_shapes();
    assert!(
        !shapes.is_empty(),
        "corpus directory contained no *.xml fixtures; check the path"
    );

    println!(
        "\n--- HIGH-003 corpus parity report ({} shapes) ---",
        shapes.len()
    );
    println!(
        "{:<36} | {:<22} | {:<22} | {}",
        "shape", "hand-rolled", "xmlsec1 (layered)", "agreement"
    );
    println!("{}", "-".repeat(110));

    let mut all_pass = true;
    for (name, bytes) in shapes {
        // Hand-rolled side: exercise the existing `verify_assertion`
        // path directly (the same surface PHASE-2A's
        // HandRolledVerifier adapter wraps). The corpus is UTF-8 XML;
        // `from_utf8` is sound — but fall back to a "non-utf8" label
        // for the rare malformed fixture that doesn't parse as UTF-8.
        let handrolled_result = match std::str::from_utf8(&bytes) {
            Ok(s) => iam_verify_assertion(&iam_cfg, s, &iam_cfg.entity_id, Duration::from_secs(60)),
            Err(_) => Err(sx_iam::service::saml::SamlError::XmlMalformed(
                "non-utf8".to_owned(),
            )),
        };

        // Layered xmlsec1 side: byte-level gates run FIRST (closure
        // injected at construction time); on rejection the FFI body is
        // never reached. The gate layer is the same one the production
        // `verify_saml_response` byte-input entry point uses.
        let layered_result = layered.verify(
            &bytes,
            &stub_cfg(),
            &stub_cfg().entity_id,
            Duration::from_secs(60),
        );

        let handrolled_label = match &handrolled_result {
            Ok(_) => "ACCEPTED",
            Err(e) => label_saml(e),
        };
        let layered_label = match &layered_result {
            Ok(_) => "ACCEPTED",
            Err(e) => label_xmlsec(e),
        };

        let both_rejected = handrolled_result.is_err() && layered_result.is_err();
        let agreement = if both_rejected {
            "OK"
        } else if handrolled_result.is_ok() && layered_result.is_err() {
            "DISAGREE handrolled-accept"
        } else if handrolled_result.is_err() && layered_result.is_ok() {
            "DISAGREE xmlsec1-accept"
        } else {
            "DISAGREE both-accept"
        };

        println!("{name:<36} | {handrolled_label:<22} | {layered_label:<22} | {agreement}",);

        if !both_rejected {
            all_pass = false;
        }
    }

    println!("{}", "-".repeat(110));
    assert!(
        all_pass,
        "HIGH-003 corpus parity broke — at least one shape was accepted by one or both verifiers. \
         See per-shape report above. PHASE-2B cutover SLO requires every corpus shape to be \
         rejected by both layers."
    );
}
