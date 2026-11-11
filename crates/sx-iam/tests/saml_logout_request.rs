//! CRIT-004 — integration test for the SAML 2.0 back-channel
//! `<samlp:LogoutRequest>` receiver.
//!
//! Builds a fresh 2048-bit RSA key pair, hand-rolls a signed
//! `<samlp:LogoutRequest>` document with the standard enveloped XMLDSig
//! placement, and feeds it to:
//!
//! * [`sx_iam::service::saml::verify_logout_request_signature`] — must
//!   accept the well-formed document and reject the tampered one.
//! * [`sx_iam::service::logout::parse_saml_logout_request`] — must
//!   surface the `NameID` + `SessionIndex` for the downstream revoker.
//!
//! Replay protection on this binding is the caller's responsibility (it
//! reuses [`InMemoryReplayCache`] keyed by the `LogoutRequest` `ID`); we
//! exercise that path with a two-call assertion that the second insert
//! is a [`InsertOutcome::Duplicate`].

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::format_collect,
    clippy::doc_markdown
)]

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use pkcs8::EncodePublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest as _, Sha256};
use sx_iam::service::logout::parse_saml_logout_request;
use sx_iam::service::saml::{
    verify_logout_request_signature, AssertionReplayCache, InMemoryReplayCache, InsertOutcome,
    SamlError, SamlSigningAlgo, SamlSpConfig,
};

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

fn sha256_b64(data: &[u8]) -> String {
    let h = Sha256::digest(data);
    B64_STANDARD.encode(h)
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

fn random_id(prefix: &str) -> String {
    use rand::RngCore as _;
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    format!("{prefix}{}", hex::encode(buf))
}

/// Build a signed `<samlp:LogoutRequest>` document. The signature
/// algorithm is RSA-SHA256, the digest is SHA-256 over the literal
/// `<samlp:LogoutRequest>...</samlp:LogoutRequest>` byte slice, and the
/// `<ds:Signature>` block is placed immediately after `</saml:Issuer>`
/// (the enveloped-signature placement the verifier expects).
fn build_signed_logout_request(
    sk: &RsaPrivateKey,
    name_id: &str,
    session_index: Option<&str>,
) -> (String, String) {
    let id = random_id("_lr-");
    let issue_instant = format_xs(time::OffsetDateTime::now_utc());

    let session_index_xml = session_index
        .map(|s| format!("<samlp:SessionIndex>{s}</samlp:SessionIndex>"))
        .unwrap_or_default();

    // Compose the inner request — Signature placeholder is added later.
    let request_xml = format!(
        "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{ib}\" \
Destination=\"https://sp.example.com/v1/auth/saml/back-channel-logout\">\
<saml:Issuer>https://idp.example.com</saml:Issuer>\
<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">{name_id}</saml:NameID>\
{sess}\
</samlp:LogoutRequest>",
        id = id,
        ib = issue_instant,
        name_id = name_id,
        sess = session_index_xml,
    );

    // 1. Digest of the request bytes (the verifier digests this same
    //    slice on its side after stripping the enveloped Signature).
    let digest_b64 = sha256_b64(request_xml.as_bytes());

    // 2. Build SignedInfo + RSA-sign its digest.
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
<ds:Reference URI=\"#{rid}\">\
<ds:Transforms>\
<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\
<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
</ds:Transforms>\
<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
<ds:DigestValue>{dv}</ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>",
        rid = id,
        dv = digest_b64,
    );
    let signed_info_digest = Sha256::digest(signed_info.as_bytes());
    let mut rng = rand::thread_rng();
    let sig = sk
        .sign_with_rng(&mut rng, Pkcs1v15Sign::new::<Sha256>(), &signed_info_digest)
        .expect("rsa sign");
    let sig_b64 = B64_STANDARD.encode(sig);

    let signature_xml = format!(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
{signed_info}\
<ds:SignatureValue>{sig}</ds:SignatureValue>\
</ds:Signature>",
        signed_info = signed_info,
        sig = sig_b64,
    );

    // 3. Inject the Signature after </saml:Issuer> — enveloped form.
    let inject_after = "</saml:Issuer>";
    let pos = request_xml.find(inject_after).expect("issuer marker") + inject_after.len();
    let mut signed = String::with_capacity(request_xml.len() + signature_xml.len());
    signed.push_str(&request_xml[..pos]);
    signed.push_str(&signature_xml);
    signed.push_str(&request_xml[pos..]);

    (signed, id)
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
fn signed_logout_request_verifies_and_parses() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let (xml, id) = build_signed_logout_request(&sk, "alice@example.com", Some("session-77"));

    verify_logout_request_signature(&cfg, &xml).expect("signed LogoutRequest must verify");

    let parsed = parse_saml_logout_request(&xml).expect("parse");
    assert_eq!(parsed.id, id);
    assert_eq!(parsed.issuer, "https://idp.example.com");
    assert_eq!(parsed.name_id, "alice@example.com");
    assert_eq!(parsed.session_index.as_deref(), Some("session-77"));
}

#[test]
fn tampered_logout_request_is_rejected_with_signature_invalid() {
    let (sk, pk) = keypair();
    let cfg = sp_config_with_pubkey(&pk);
    let (xml, _id) = build_signed_logout_request(&sk, "alice@example.com", None);

    // Swap the NameID after signing — must invalidate the digest.
    let tampered = xml.replace("alice@example.com", "eve@example.com");
    assert_ne!(tampered, xml);

    let err = verify_logout_request_signature(&cfg, &tampered)
        .expect_err("tampered LogoutRequest must be rejected");
    assert_eq!(err, SamlError::SignatureInvalid);
}

#[tokio::test]
async fn replay_cache_rejects_second_logout_request_with_same_id() {
    let cache = InMemoryReplayCache::new(Duration::from_secs(60));
    let first = cache.insert_if_absent("_lr-id-1").await;
    assert_eq!(first, InsertOutcome::Inserted);
    let second = cache.insert_if_absent("_lr-id-1").await;
    assert_eq!(second, InsertOutcome::Duplicate);
}
