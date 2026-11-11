//! End-to-end TSA-anchoring fixture (P1-015).
//!
//! Each test drives the full [`sx_audit::anchor_run::AnchorRunner`]
//! pipeline:
//!
//! 1. Build a self-signed CA + a TSA keypair the CA endorses.
//! 2. Stand up a [`wiremock`] server that returns a SentinelX-flavoured
//!    TSA token signed by the TSA keypair (or a tampered variant).
//! 3. Wire a real [`JsonTsaClient`] at the wiremock URL.
//! 4. Run one anchoring tick and assert the verifier's verdict.
//!
//! The fixture token format is the JSON wrapper documented in
//! `crate::anchor_run` — production deployments will swap the wrapper
//! for a full CMS `SignedData` parser without changing this test
//! harness.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use sx_audit::anchor_external::SHA256_LEN;
use sx_audit::anchor_run::{
    canonical_payload, AnchorRunError, AnchorRunId, AnchorRunRepository, AnchorRunner,
    AuditAnchorRun, DefaultTsaTokenVerifier, InMemoryAnchorRunRepository, JsonTsaClient,
    RecordingCriticalEventSink, RunOutcome, TenantAnchorConfig,
};
use sx_core::value_object::ids::TenantId;

// ---------------------------------------------------------------------------
// Fixture helpers — keypair generation, signing, token assembly
// ---------------------------------------------------------------------------

struct CaFixture {
    /// PEM-encoded public key of the self-signed CA. The verifier pins
    /// to this string verbatim.
    ca_pem: String,
    /// Private signing key used to "issue" TSA certs.
    ca_sk: RsaPrivateKey,
}

struct TsaFixture {
    /// PEM SPKI representation of the TSA's public key — what we
    /// embed in the token's `tsa_cert_pem` field.
    tsa_cert_pem: String,
    /// TSA private key used to sign canonical payloads.
    tsa_sk: RsaPrivateKey,
    /// CA's signature over the TSA cert PEM (base64).
    ca_cert_signature_b64: String,
}

fn keypair(bits: usize) -> RsaPrivateKey {
    // ChaCha8 deterministic RNG would be ideal but RsaPrivateKey::new
    // accepts any rand::RngCore. We use OsRng for fast keys — the
    // tests just need a fresh keypair per run.
    let mut rng = rand::thread_rng();
    RsaPrivateKey::new(&mut rng, bits).expect("rsa keypair")
}

fn pub_pem(sk: &RsaPrivateKey) -> String {
    let pk: RsaPublicKey = sk.to_public_key();
    pk.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode pem")
}

fn sign_pkcs1_sha256(sk: &RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
    let signer = SigningKey::<Sha256>::new(sk.clone());
    let sig = signer.sign(msg);
    sig.to_bytes().to_vec()
}

fn build_ca() -> CaFixture {
    let ca_sk = keypair(2048);
    let ca_pem = pub_pem(&ca_sk);
    CaFixture { ca_pem, ca_sk }
}

fn build_tsa(ca: &CaFixture) -> TsaFixture {
    let tsa_sk = keypair(2048);
    let tsa_cert_pem = pub_pem(&tsa_sk);
    let ca_sig = sign_pkcs1_sha256(&ca.ca_sk, tsa_cert_pem.as_bytes());
    let ca_cert_signature_b64 = B64.encode(&ca_sig);
    TsaFixture {
        tsa_cert_pem,
        tsa_sk,
        ca_cert_signature_b64,
    }
}

/// Build the JSON token body the wiremock TSA server returns.
///
/// `merkle_root_override` lets the tampered-token test return a token
/// whose Merkle root differs from what the client sent — the verifier
/// MUST reject that case.
fn build_token_bytes(
    tsa: &TsaFixture,
    merkle_root: [u8; SHA256_LEN],
    serial: &str,
    gen_time: &str,
    merkle_root_override: Option<[u8; SHA256_LEN]>,
) -> Vec<u8> {
    let signed_root = merkle_root_override.unwrap_or(merkle_root);
    let merkle_root_hex = hex::encode(signed_root);
    let canon = canonical_payload(serial, gen_time, &merkle_root_hex);
    let sig = sign_pkcs1_sha256(&tsa.tsa_sk, &canon);
    let body = json!({
        "v": 1,
        "serial": serial,
        "gen_time": gen_time,
        "merkle_root_hex": merkle_root_hex,
        "tsa_cert_pem": tsa.tsa_cert_pem,
        "ca_cert_signature_b64": tsa.ca_cert_signature_b64,
        "signature_b64": B64.encode(&sig),
    });
    body.to_string().into_bytes()
}

fn tenant(n: u128) -> TenantId {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&n.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(bytes).into()
}

fn sample_chain_hashes() -> Vec<[u8; SHA256_LEN]> {
    // Three deterministic, distinct leaves — exercises the
    // duplicate-orphan rule inside `MerkleTreeBuilder` so the test
    // covers the non-power-of-two path too.
    vec![[0x10; SHA256_LEN], [0x20; SHA256_LEN], [0x30; SHA256_LEN]]
}

fn predicted_merkle_root() -> [u8; SHA256_LEN] {
    use sx_audit::anchor_external::MerkleTreeBuilder;
    MerkleTreeBuilder::new()
        .build(&sample_chain_hashes())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_once_with_valid_tsa_persists_and_returns_anchored() {
    let ca = build_ca();
    let tsa = build_tsa(&ca);
    let merkle = predicted_merkle_root();

    let server = MockServer::start().await;
    let token_bytes = build_token_bytes(&tsa, merkle, "0x000000ab", "2026-06-14T00:00:00Z", None);
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/timestamp-reply")
                .set_body_bytes(token_bytes),
        )
        .mount(&server)
        .await;

    let client = Arc::new(JsonTsaClient::new(format!("{}/tsr", server.uri())).unwrap());
    let verifier = Arc::new(DefaultTsaTokenVerifier);
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let runner = AnchorRunner::new(
        client,
        verifier,
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
    );

    let t = tenant(1);
    let cfg = TenantAnchorConfig {
        tenant_id: t,
        tsa_url: Some(format!("{}/tsr", server.uri())),
        pinned_ca_cert_pem: Some(ca.ca_pem.clone()),
        interval: TenantAnchorConfig::DEFAULT_INTERVAL,
    };

    let outcome = runner
        .run_once(
            &cfg,
            &sample_chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (1, 3),
        )
        .await
        .expect("anchored");

    let run_id = match outcome {
        RunOutcome::Anchored(id) => id,
        RunOutcome::Skipped(s) => panic!("expected anchored, got skipped: {s}"),
    };
    let row = repo
        .as_ref()
        .get_for_tenant(&t, &run_id)
        .await
        .expect("row");
    assert_eq!(row.tenant_id, t);
    assert_eq!(row.merkle_root, merkle);
    assert_eq!(row.tsa_serial, "0x000000ab");
    assert!(!row.payload_bytes.is_empty(), "payload bytes persisted");
    // Verification succeeded so no CRITICAL event should be emitted.
    let events = sink.events().await;
    assert!(events.is_empty(), "no critical events on happy path");
}

#[tokio::test]
async fn run_once_with_tampered_root_rejects_and_emits_critical() {
    let ca = build_ca();
    let tsa = build_tsa(&ca);
    let merkle = predicted_merkle_root();

    let server = MockServer::start().await;
    // Token signs a *different* root than what the client computed.
    let tampered = [0xFF; SHA256_LEN];
    let token_bytes = build_token_bytes(
        &tsa,
        merkle,
        "0x000000cc",
        "2026-06-14T01:00:00Z",
        Some(tampered),
    );
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token_bytes))
        .mount(&server)
        .await;

    let client = Arc::new(JsonTsaClient::new(format!("{}/tsr", server.uri())).unwrap());
    let verifier = Arc::new(DefaultTsaTokenVerifier);
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let runner = AnchorRunner::new(
        client,
        verifier,
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
    );

    let t = tenant(2);
    let cfg = TenantAnchorConfig {
        tenant_id: t,
        tsa_url: Some(format!("{}/tsr", server.uri())),
        pinned_ca_cert_pem: Some(ca.ca_pem.clone()),
        interval: TenantAnchorConfig::DEFAULT_INTERVAL,
    };

    let err = runner
        .run_once(
            &cfg,
            &sample_chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (4, 6),
        )
        .await
        .expect_err("tampered token must fail");
    assert!(matches!(err, AnchorRunError::Verification(_)));

    let events = sink.events().await;
    assert_eq!(events.len(), 1, "exactly one critical event");
    assert_eq!(events[0].0, t);
    assert!(events[0].1.contains("merkle"), "message references root");

    // No row should be persisted on failure.
    let listed = repo.as_ref().list_for_tenant(&t, 10).await.unwrap();
    assert!(listed.is_empty(), "failed run must not persist");
}

#[tokio::test]
async fn run_once_with_wrong_ca_rejects() {
    // The TSA is issued by `real_ca` but the *runner* pins to a
    // different "expired" / unrelated CA. Verification must fail at
    // the CA-cert-signature hop (acceptance criterion: "expired TSA
    // cert case" maps to a CA the operator no longer trusts).
    let real_ca = build_ca();
    let unrelated_ca = build_ca();
    let tsa = build_tsa(&real_ca);
    let merkle = predicted_merkle_root();

    let server = MockServer::start().await;
    let token_bytes = build_token_bytes(&tsa, merkle, "0x0000beef", "2026-06-14T02:00:00Z", None);
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token_bytes))
        .mount(&server)
        .await;

    let client = Arc::new(JsonTsaClient::new(format!("{}/tsr", server.uri())).unwrap());
    let verifier = Arc::new(DefaultTsaTokenVerifier);
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let runner = AnchorRunner::new(
        client,
        verifier,
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
    );

    let t = tenant(3);
    let cfg = TenantAnchorConfig {
        tenant_id: t,
        tsa_url: Some(format!("{}/tsr", server.uri())),
        // Pinned to the WRONG CA — simulates an expired / rotated
        // TSA whose issuing CA the operator no longer trusts.
        pinned_ca_cert_pem: Some(unrelated_ca.ca_pem.clone()),
        interval: TenantAnchorConfig::DEFAULT_INTERVAL,
    };

    let err = runner
        .run_once(
            &cfg,
            &sample_chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (7, 9),
        )
        .await
        .expect_err("wrong CA must fail");
    assert!(matches!(err, AnchorRunError::Verification(_)));
    let events = sink.events().await;
    assert_eq!(events.len(), 1);
    assert!(events[0].1.contains("verification failed"));
}

#[tokio::test]
async fn verify_run_re_verifies_persisted_row_against_pinned_ca() {
    let ca = build_ca();
    let tsa = build_tsa(&ca);
    let merkle = predicted_merkle_root();

    let server = MockServer::start().await;
    let token_bytes = build_token_bytes(&tsa, merkle, "0x0000feed", "2026-06-14T03:00:00Z", None);
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token_bytes))
        .mount(&server)
        .await;

    let client = Arc::new(JsonTsaClient::new(format!("{}/tsr", server.uri())).unwrap());
    let verifier = Arc::new(DefaultTsaTokenVerifier);
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let runner = AnchorRunner::new(
        client,
        verifier,
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
    );

    let t = tenant(4);
    let cfg = TenantAnchorConfig {
        tenant_id: t,
        tsa_url: Some(format!("{}/tsr", server.uri())),
        pinned_ca_cert_pem: Some(ca.ca_pem.clone()),
        interval: TenantAnchorConfig::DEFAULT_INTERVAL,
    };

    let outcome = runner
        .run_once(
            &cfg,
            &sample_chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (10, 12),
        )
        .await
        .expect("anchored");
    let run_id = match outcome {
        RunOutcome::Anchored(id) => id,
        RunOutcome::Skipped(_) => panic!("expected anchored"),
    };

    // Re-verify with the right CA — succeeds, returns parsed fields.
    let v = runner
        .verify_run(&t, &run_id, &ca.ca_pem)
        .await
        .expect("re-verify");
    assert_eq!(v.serial, "0x0000feed");
    assert_eq!(v.merkle_root, merkle);

    // Re-verify with the wrong CA — fails and emits CRITICAL.
    let other_ca = build_ca();
    let err = runner
        .verify_run(&t, &run_id, &other_ca.ca_pem)
        .await
        .expect_err("must fail on wrong CA");
    assert!(matches!(err, AnchorRunError::Verification(_)));
    let events = sink.events().await;
    assert_eq!(events.len(), 1, "re-verify failure emits exactly one event");
}

#[tokio::test]
async fn verify_run_rejects_cross_tenant_lookup() {
    let ca = build_ca();
    let tsa = build_tsa(&ca);
    let merkle = predicted_merkle_root();

    let server = MockServer::start().await;
    let token_bytes = build_token_bytes(&tsa, merkle, "0x00aabbcc", "2026-06-14T04:00:00Z", None);
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token_bytes))
        .mount(&server)
        .await;

    let client = Arc::new(JsonTsaClient::new(format!("{}/tsr", server.uri())).unwrap());
    let verifier = Arc::new(DefaultTsaTokenVerifier);
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let runner = AnchorRunner::new(
        client,
        verifier,
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
    );

    let t_owner = tenant(5);
    let t_attacker = tenant(6);
    let cfg = TenantAnchorConfig {
        tenant_id: t_owner,
        tsa_url: Some(format!("{}/tsr", server.uri())),
        pinned_ca_cert_pem: Some(ca.ca_pem.clone()),
        interval: TenantAnchorConfig::DEFAULT_INTERVAL,
    };

    let outcome = runner
        .run_once(
            &cfg,
            &sample_chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (1, 3),
        )
        .await
        .expect("anchored");
    let run_id = match outcome {
        RunOutcome::Anchored(id) => id,
        RunOutcome::Skipped(_) => panic!("expected anchored"),
    };

    // Attacker tenant attempts to verify owner's row — repo must
    // refuse with Forbidden, NOT NotFound (the API maps these
    // distinctly so telemetry can distinguish "missing" from
    // "tenant boundary violation").
    let err = runner
        .verify_run(&t_attacker, &run_id, &ca.ca_pem)
        .await
        .expect_err("cross-tenant must fail");
    assert!(matches!(err, AnchorRunError::Forbidden));

    // No critical event should be emitted — the failure is a tenant
    // boundary violation, not a signature failure.
    let events = sink.events().await;
    assert!(
        events.is_empty(),
        "cross-tenant lookup must not emit critical"
    );
}

#[tokio::test]
async fn run_once_with_empty_window_skips() {
    let ca = build_ca();
    let server = MockServer::start().await;
    // No TSA mock — the empty-window early-return must short-circuit
    // before any HTTP call. If the runner does call the TSA the test
    // surfaces wiremock's "no matching mock" 404 and the test fails.
    let _ = &server;

    let client = Arc::new(JsonTsaClient::new(format!("{}/tsr", server.uri())).unwrap());
    let verifier = Arc::new(DefaultTsaTokenVerifier);
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let runner = AnchorRunner::new(
        client,
        verifier,
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
    );

    let t = tenant(7);
    let cfg = TenantAnchorConfig {
        tenant_id: t,
        tsa_url: Some(format!("{}/tsr", server.uri())),
        pinned_ca_cert_pem: Some(ca.ca_pem.clone()),
        interval: TenantAnchorConfig::DEFAULT_INTERVAL,
    };
    let outcome = runner
        .run_once(
            &cfg,
            &[],
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (0, 0),
        )
        .await
        .unwrap();
    match outcome {
        RunOutcome::Skipped(_) => {}
        RunOutcome::Anchored(_) => panic!("empty window must be skipped"),
    }
}

#[tokio::test]
async fn audit_anchor_run_serialises_payload_as_base64() {
    // The on-the-wire / on-disk shape uses base64 for the payload
    // blob and hex for the merkle root. Round-trip through JSON to
    // confirm both serialisers see the same value.
    let run = AuditAnchorRun {
        run_id: AnchorRunId::new(),
        tenant_id: tenant(8),
        merkle_root: [0xAB; SHA256_LEN],
        tsa_serial: "0xdeadbeef".into(),
        tsa_gen_time: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        anchored_at: OffsetDateTime::from_unix_timestamp(1_700_000_001).unwrap(),
        payload_bytes: vec![1, 2, 3, 4, 5],
        quorum: None,
    };
    let s = serde_json::to_string(&run).unwrap();
    assert!(s.contains("\"merkle_root\":\""), "merkle as field");
    let parsed: AuditAnchorRun = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed, run);
}
