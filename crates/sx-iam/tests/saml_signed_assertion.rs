//! End-to-end signed-assertion fixtures for the SAML 2.0 SP (P0-004).
//!
//! Generates a fresh 2048-bit RSA keypair, serialises the public half as
//! an SPKI `-----BEGIN PUBLIC KEY-----` PEM block (which the verifier
//! accepts alongside the production `BEGIN CERTIFICATE` path), and then
//! constructs five SAML 2.0 `<Response>` fixtures:
//!
//! 1. Valid signed assertion — round-trips through
//!    [`sx_iam::service::saml::verify_assertion`] and
//!    [`sx_iam::service::saml::process_acs_response`].
//! 2. Expired (`NotOnOrAfter` in the past) — rejected with
//!    [`SamlError::TimeWindow`].
//! 3. Replay (same assertion id seen twice) — second call rejected with
//!    [`SamlError::ReplayAssertion`].
//! 4. Bad signature — body tampered after signing — rejected with
//!    [`SamlError::SignatureInvalid`].
//! 5. Clock skew within tolerance — assertion expired 20 s ago, skew is
//!    60 s, must pass.
//!
//! All fixtures are constructed in-memory (no on-disk XML); the goal is
//! to exercise the verifier's contract end-to-end without depending on a
//! particular `IdP`'s quirks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    // The fixture builder concatenates short `<saml:AttributeValue>`
    // fragments via `format!` inside `.map()` — chosen for readability
    // over the slightly faster fold pattern.
    clippy::format_collect,
    // The XML format strings use named substitutions for readability;
    // a couple of in-block `format!` invocations bind the same names
    // first then substitute, which lint-rules call out.
    clippy::uninlined_format_args
)]

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use pkcs8::EncodePublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use sx_iam::service::saml::{
    process_acs_response, verify_assertion, AttributeMapping, InMemoryReplayCache,
    InResponseToPolicy, SamlError, SamlSigningAlgo, SamlSpConfig,
};

// ---------------------------------------------------------------------------
// Keypair + fixture builder
// ---------------------------------------------------------------------------

fn keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let sk = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keypair");
    let pk = sk.to_public_key();
    (sk, pk)
}

fn pubkey_pem(pk: &RsaPublicKey) -> String {
    pk.to_public_key_pem(pkcs8::LineEnding::LF)
        .expect("spki pem")
}

#[derive(Clone)]
struct AssertionParams {
    audience: String,
    name_id: String,
    assertion_id: String,
    not_before: String,
    not_on_or_after: String,
    in_response_to: Option<String>,
    group_values: Vec<String>,
}

impl AssertionParams {
    fn default_now() -> Self {
        let now = time::OffsetDateTime::now_utc();
        Self {
            audience: "https://sp.example.com/saml".into(),
            name_id: "alice@example.com".into(),
            assertion_id: format!("_assert-{}", uuid_simple()),
            not_before: format_xs(now - time::Duration::minutes(1)),
            not_on_or_after: format_xs(now + time::Duration::minutes(5)),
            in_response_to: None,
            group_values: vec!["analyst".into(), "admin".into()],
        }
    }
}

fn uuid_simple() -> String {
    use rand::RngCore as _;
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn format_xs(dt: time::OffsetDateTime) -> String {
    let utc = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
    )
}

/// Build the inner `<Assertion>` XML for `params`. The Signature block
/// is filled in by [`sign_assertion`] after the digest + signature have
/// been computed.
fn build_assertion_xml(params: &AssertionParams) -> String {
    let group_xml = params
        .group_values
        .iter()
        .map(|v| format!("<saml:AttributeValue>{v}</saml:AttributeValue>"))
        .collect::<String>();
    format!(
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
ID=\"{id}\" IssueInstant=\"{ib}\" Version=\"2.0\">\
<saml:Issuer>https://idp.example.com</saml:Issuer>\
<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">{nameid}</saml:NameID></saml:Subject>\
<saml:Conditions NotBefore=\"{nb}\" NotOnOrAfter=\"{noa}\">\
<saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction>\
</saml:Conditions>\
<saml:AuthnStatement AuthnInstant=\"{ib}\" SessionIndex=\"session-1\">\
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>\
</saml:AuthnStatement>\
<saml:AttributeStatement>\
<saml:Attribute Name=\"Group\">{groups}</saml:Attribute>\
</saml:AttributeStatement>\
</saml:Assertion>",
        id = params.assertion_id,
        ib = params.not_before,
        nb = params.not_before,
        noa = params.not_on_or_after,
        nameid = params.name_id,
        aud = params.audience,
        groups = group_xml,
    )
}

fn sha256_b64(data: &[u8]) -> String {
    let h = Sha256::digest(data);
    B64_STANDARD.encode(h)
}

/// Sign `assertion_xml` and return the `<samlp:Response>` document that
/// wraps it. The signature is constructed manually:
///
/// 1. SHA-256 of the literal `<Assertion>...</Assertion>` byte slice
///    becomes `<DigestValue>`.
/// 2. The `<SignedInfo>` block is serialised verbatim, SHA-256'd, and
///    RSA-PKCS1-v1.5 signed. Result → `<SignatureValue>`.
/// 3. The `<Signature>` element is concatenated **between** the
///    `<Issuer>` and `<Subject>` children, mirroring the standard
///    enveloped-signature placement the verifier expects to find by
///    byte slice.
fn sign_response(sk: &RsaPrivateKey, params: &AssertionParams, response_id: &str) -> String {
    let assertion_xml = build_assertion_xml(params);
    let digest_b64 = sha256_b64(assertion_xml.as_bytes());

    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
<ds:Reference URI=\"#{aid}\">\
<ds:Transforms>\
<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\
<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
</ds:Transforms>\
<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
<ds:DigestValue>{dv}</ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>",
        aid = params.assertion_id,
        dv = digest_b64,
    );

    let signed_info_digest = Sha256::digest(signed_info.as_bytes());
    let mut rng = rand::thread_rng();
    let sig = sk
        .sign_with_rng(&mut rng, Pkcs1v15Sign::new::<Sha256>(), &signed_info_digest)
        .expect("rsa sign");
    let sig_b64 = B64_STANDARD.encode(sig);

    // The Signature is placed inside the Assertion (enveloped form).
    // We need to re-build the assertion to include it.
    let signature_xml = format!(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
{signed_info}\
<ds:SignatureValue>{sig}</ds:SignatureValue>\
</ds:Signature>",
        signed_info = signed_info,
        sig = sig_b64,
    );

    // Place the Signature immediately after the closing </saml:Issuer> tag.
    let inject_after = "</saml:Issuer>";
    let pos = assertion_xml.find(inject_after).expect("issuer marker") + inject_after.len();
    let mut signed_assertion = String::with_capacity(assertion_xml.len() + signature_xml.len());
    signed_assertion.push_str(&assertion_xml[..pos]);
    signed_assertion.push_str(&signature_xml);
    signed_assertion.push_str(&assertion_xml[pos..]);

    // Wrap in samlp:Response.
    let in_response_to_attr = params
        .in_response_to
        .as_deref()
        .map(|v| format!(" InResponseTo=\"{v}\""))
        .unwrap_or_default();
    format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
ID=\"{rid}\" Version=\"2.0\" IssueInstant=\"{ib}\"{irt}>\
<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://idp.example.com</saml:Issuer>\
{signed}\
</samlp:Response>",
        rid = response_id,
        ib = params.not_before,
        irt = in_response_to_attr,
        signed = signed_assertion,
    )
}

fn sp_config_with_pubkey(pk: &RsaPublicKey) -> SamlSpConfig {
    SamlSpConfig {
        entity_id: "https://sp.example.com/saml".into(),
        sso_url: "https://idp.example.com/sso".into(),
        slo_url: Some("https://idp.example.com/slo".into()),
        x509_cert_pem: pubkey_pem(pk),
        signing_algo: SamlSigningAlgo::Sha256,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn valid_signed_assertion_verifies() {
    let (sk, pk) = keypair();
    // Sanity: keypair must be ≥ 2048 bits so the RSA backend is happy.
    assert!(pk.size() * 8 >= 2048);
    let cfg = sp_config_with_pubkey(&pk);
    let params = AssertionParams::default_now();
    let response_xml = sign_response(&sk, &params, "_resp-1");

    let parsed = verify_assertion(&cfg, &response_xml, &cfg.entity_id, Duration::from_secs(30))
        .expect("valid signed assertion must verify");

    assert_eq!(parsed.name_id, "alice@example.com");
    assert_eq!(parsed.session_index.as_deref(), Some("session-1"));
    let groups = parsed.attributes.get("Group").expect("Group attr");
    assert_eq!(groups, &vec!["analyst".to_string(), "admin".to_string()]);
}

#[test]
fn expired_assertion_is_rejected_with_time_window() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let mut params = AssertionParams::default_now();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = format_xs(now - time::Duration::hours(2));
    params.not_on_or_after = format_xs(now - time::Duration::hours(1));
    let response_xml = sign_response(&sk, &params, "_resp-expired");

    let err = verify_assertion(&cfg, &response_xml, &cfg.entity_id, Duration::from_secs(30))
        .expect_err("expired assertion must be rejected");
    assert_eq!(err, SamlError::TimeWindow);
}

#[test]
fn bad_signature_is_rejected() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let params = AssertionParams::default_now();
    let response_xml = sign_response(&sk, &params, "_resp-tampered");

    // Tamper: change the NameID after the signature is in place. This
    // must invalidate the digest over the assertion bytes.
    let tampered = response_xml.replace("alice@example.com", "eve@example.com");
    assert_ne!(tampered, response_xml);

    let err = verify_assertion(&cfg, &tampered, &cfg.entity_id, Duration::from_secs(30))
        .expect_err("tampered assertion must be rejected");
    assert_eq!(err, SamlError::SignatureInvalid);
}

#[test]
fn clock_skew_inside_tolerance_passes() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let mut params = AssertionParams::default_now();
    let now = time::OffsetDateTime::now_utc();
    // Expired 20 s ago; 60 s of skew should still accept it.
    params.not_before = format_xs(now - time::Duration::minutes(5));
    params.not_on_or_after = format_xs(now - time::Duration::seconds(20));
    let response_xml = sign_response(&sk, &params, "_resp-skew");

    verify_assertion(&cfg, &response_xml, &cfg.entity_id, Duration::from_secs(60))
        .expect("inside clock skew tolerance — must verify");
}

#[test]
fn wrong_signing_key_is_rejected() {
    // Issuer signs, but verifier holds a different pubkey: classic
    // cert-mismatch path.
    let (sk_a, _) = keypair();
    let (_, pk_b) = keypair();
    let cfg = sp_config_with_pubkey(&pk_b);
    let params = AssertionParams::default_now();
    let response_xml = sign_response(&sk_a, &params, "_resp-wrongkey");

    let err = verify_assertion(&cfg, &response_xml, &cfg.entity_id, Duration::from_secs(30))
        .expect_err("wrong pubkey must reject");
    assert_eq!(err, SamlError::SignatureInvalid);
}

#[test]
fn audience_mismatch_is_rejected() {
    let (sk, pk) = keypair();
    let mut cfg = sp_config_with_pubkey(&pk);
    cfg.entity_id = "https://sp.other.example.com/saml".into();
    let params = AssertionParams::default_now();
    let response_xml = sign_response(&sk, &params, "_resp-aud");

    let err = verify_assertion(
        &cfg,
        &response_xml,
        "https://sp.other.example.com/saml",
        Duration::from_secs(30),
    )
    .expect_err("audience mismatch must reject");
    assert_eq!(err, SamlError::AudienceMismatch);
}

#[tokio::test]
async fn replay_same_assertion_is_rejected_on_second_attempt() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let params = AssertionParams::default_now();
    let response_xml = sign_response(&sk, &params, "_resp-replay");

    let replay_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let irt_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let mapping = AttributeMapping::default();

    // First attempt — accepted.
    let outcome = process_acs_response(
        &response_xml,
        &cfg,
        "t1",
        &cfg.entity_id,
        Duration::from_secs(30),
        &replay_cache,
        &irt_cache,
        InResponseToPolicy::Optional,
        &mapping,
    )
    .await
    .expect("first acs attempt must verify");
    assert_eq!(outcome.email, "alice@example.com");
    assert_eq!(
        outcome.roles,
        vec!["analyst".to_string(), "admin".to_string()]
    );

    // Second attempt — same assertion id — must be rejected as replay.
    let err = process_acs_response(
        &response_xml,
        &cfg,
        "t1",
        &cfg.entity_id,
        Duration::from_secs(30),
        &replay_cache,
        &irt_cache,
        InResponseToPolicy::Optional,
        &mapping,
    )
    .await
    .expect_err("replay must be rejected");
    assert_eq!(err, SamlError::ReplayAssertion);
}

#[tokio::test]
async fn in_response_to_required_rejects_idp_initiated() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let params = AssertionParams::default_now();
    let response_xml = sign_response(&sk, &params, "_resp-idp-init");

    let replay_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let irt_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let mapping = AttributeMapping::default();

    let err = process_acs_response(
        &response_xml,
        &cfg,
        "t1",
        &cfg.entity_id,
        Duration::from_secs(30),
        &replay_cache,
        &irt_cache,
        InResponseToPolicy::Required,
        &mapping,
    )
    .await
    .expect_err("idp-initiated under Required policy must reject");
    assert_eq!(err, SamlError::ReplayAssertion);
}

#[tokio::test]
async fn in_response_to_matches_outstanding_request() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let mut params = AssertionParams::default_now();
    let req_id = "_authn-req-42";
    params.in_response_to = Some(req_id.into());
    let response_xml = sign_response(&sk, &params, "_resp-irt");

    let replay_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let irt_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let mapping = AttributeMapping::default();

    // Stage the outstanding request id — the SP-initiated leg would do
    // this when it built the AuthnRequest.
    let _ = irt_cache
        .insert_if_absent(&format!("inresponseto:t1:{req_id}"))
        .await;

    let outcome = process_acs_response(
        &response_xml,
        &cfg,
        "t1",
        &cfg.entity_id,
        Duration::from_secs(30),
        &replay_cache,
        &irt_cache,
        InResponseToPolicy::Required,
        &mapping,
    )
    .await
    .expect("staged InResponseTo must verify");
    assert_eq!(outcome.email, "alice@example.com");
}

#[tokio::test]
async fn in_response_to_unknown_request_rejected() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let mut params = AssertionParams::default_now();
    params.in_response_to = Some("_authn-req-unknown".into());
    let response_xml = sign_response(&sk, &params, "_resp-irt-unknown");

    let replay_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let irt_cache: Arc<dyn sx_iam::service::saml::AssertionReplayCache> =
        Arc::new(InMemoryReplayCache::new(Duration::from_secs(300)));
    let mapping = AttributeMapping::default();

    let err = process_acs_response(
        &response_xml,
        &cfg,
        "t1",
        &cfg.entity_id,
        Duration::from_secs(30),
        &replay_cache,
        &irt_cache,
        InResponseToPolicy::Optional,
        &mapping,
    )
    .await
    .expect_err("unknown InResponseTo must reject");
    assert_eq!(err, SamlError::ReplayAssertion);
}
