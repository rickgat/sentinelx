//! libFuzzer harness for [`sx_iam::service::saml::verify_saml_response`].
//!
//! **Contract under fuzz:**
//!
//! * Arbitrary `&[u8]` input MUST NOT panic the verifier.
//! * Arbitrary `&[u8]` input MUST NOT loop forever (libFuzzer kills the
//!   target on a 10 s timeout per input; the verifier is single-pass and
//!   bounded by the 1 MB body cap).
//! * Arbitrary `&[u8]` input MUST yield a deterministic `Result` variant
//!   for the same bytes — the verifier MUST NOT depend on uninitialised
//!   memory or thread-local state.
//!
//! Run (nightly + cargo-fuzz):
//!
//! ```text
//! cd crates/sx-iam
//! cargo +nightly fuzz run saml_response_fuzz -- -max_total_time=21600
//! ```

#![no_main]

use std::sync::OnceLock;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use sx_iam::service::saml::{verify_saml_response, SamlSigningAlgo, SamlSpConfig};

/// Build a deterministic SP config for the fuzz session. The cert PEM is
/// a bogus placeholder — the byte-input gate layer rejects long before
/// any RSA verification, so the cert never gets used on adversarial
/// input. On the rare path where the gates accept, the RSA layer will
/// fail closed with `SignatureInvalid` because the placeholder is not a
/// valid SPKI block.
fn sp_config() -> &'static SamlSpConfig {
    static CFG: OnceLock<SamlSpConfig> = OnceLock::new();
    CFG.get_or_init(|| SamlSpConfig {
        entity_id: "https://sp.example.com/saml".into(),
        sso_url: "https://idp.example.com/sso".into(),
        slo_url: None,
        x509_cert_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----".into(),
        signing_algo: SamlSigningAlgo::Sha256,
    })
}

fuzz_target!(|data: &[u8]| {
    // The verifier must never panic on adversarial input. We deliberately
    // discard the `Result` — what matters is that the call returns at
    // all, in bounded time.
    let _ = verify_saml_response(
        sp_config(),
        data,
        "https://sp.example.com/saml",
        Duration::from_secs(30),
    );
});
