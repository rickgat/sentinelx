//! CRIT-006 integration tests — multi-TSA fallback, circuit breaker
//! integration, IR auto-fire, and queued retry recovery.
//!
//! Each test spins up one or more `wiremock` TSAs and drives the
//! [`ResilientAnchorRunner`] / [`AnchorQueueRetryer`] end-to-end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::needless_collect,
    clippy::doc_markdown
)]

use std::sync::Arc;
use std::time::Duration as StdDuration;

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
    AnchorRunError, AnchorRunRepository, AnchorRunner, DefaultTsaTokenVerifier,
    InMemoryAnchorRunRepository, RecordingCriticalEventSink,
};
use sx_audit::tsa_fallback::{
    audit_event, AnchorQueueRepository, AnchorQueueRetryer, AnchorQueueStatus, BreakerState,
    InMemoryAnchorQueueRepository, ManualClock, MultiTsaClient, MultiTsaConfig, OpenedIrIncident,
    QuorumSignatureStatus, RecordingIrIncidentSink, ResilientAnchorRunner, ResilientOutcome,
    TsaEndpoint,
};
use sx_core::value_object::ids::TenantId;

// ---------------------------------------------------------------------------
// Fixture helpers — keypair + token assembly (mirrors anchor_run_tsa.rs)
// ---------------------------------------------------------------------------

struct CaFixture {
    ca_pem: String,
    ca_sk: RsaPrivateKey,
}

struct TsaFixture {
    tsa_cert_pem: String,
    tsa_sk: RsaPrivateKey,
    ca_cert_signature_b64: String,
}

fn keypair(bits: usize) -> RsaPrivateKey {
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
    TsaFixture {
        tsa_cert_pem,
        tsa_sk,
        ca_cert_signature_b64: B64.encode(&ca_sig),
    }
}

fn build_token_bytes(
    tsa: &TsaFixture,
    merkle_root: [u8; SHA256_LEN],
    serial: &str,
    gen_time: &str,
) -> Vec<u8> {
    let merkle_root_hex = hex::encode(merkle_root);
    let canon = sx_audit::anchor_run::canonical_payload(serial, gen_time, &merkle_root_hex);
    let sig = sign_pkcs1_sha256(&tsa.tsa_sk, &canon);
    json!({
        "v": 1,
        "serial": serial,
        "gen_time": gen_time,
        "merkle_root_hex": merkle_root_hex,
        "tsa_cert_pem": tsa.tsa_cert_pem,
        "ca_cert_signature_b64": tsa.ca_cert_signature_b64,
        "signature_b64": B64.encode(&sig),
    })
    .to_string()
    .into_bytes()
}

fn tenant(n: u128) -> TenantId {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&n.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(bytes).into()
}

fn chain_hashes() -> Vec<[u8; SHA256_LEN]> {
    vec![[0x10; SHA256_LEN], [0x20; SHA256_LEN], [0x30; SHA256_LEN]]
}

fn predicted_root() -> [u8; SHA256_LEN] {
    use sx_audit::anchor_external::MerkleTreeBuilder;
    MerkleTreeBuilder::new().build(&chain_hashes()).unwrap()
}

// ---------------------------------------------------------------------------
// 1. Fallback cascade: primary times out -> backup1 takes over.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn primary_unreachable_backup1_takes_over() {
    // 3 wiremock servers; primary returns 503 (transient), backup1
    // returns a valid token, backup2 should never be hit.
    let ca = build_ca();
    let tsa_kp = build_tsa(&ca);
    let root = predicted_root();
    let token = build_token_bytes(&tsa_kp, root, "0xb1", "2026-06-14T00:00:00Z");

    let primary = MockServer::start().await;
    let backup1 = MockServer::start().await;
    let backup2 = MockServer::start().await;

    // Primary fails repeatedly.
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&primary)
        .await;
    // Backup1 succeeds with a valid token.
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token.clone()))
        .mount(&backup1)
        .await;
    // Backup2 mock returns 500 — but the test expects backup1 to win first.
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&backup2)
        .await;

    let cfg = MultiTsaConfig {
        tenant_id: tenant(1),
        primary: TsaEndpoint {
            url: format!("{}/tsr", primary.uri()),
            ca_pem: ca.ca_pem.clone(),
            label: Some("primary".to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups: vec![
            TsaEndpoint {
                url: format!("{}/tsr", backup1.uri()),
                ca_pem: ca.ca_pem.clone(),
                label: Some("backup1".to_owned()),
                timeout: StdDuration::from_secs(5),
            },
            TsaEndpoint {
                url: format!("{}/tsr", backup2.uri()),
                ca_pem: ca.ca_pem.clone(),
                label: Some("backup2".to_owned()),
                timeout: StdDuration::from_secs(5),
            },
        ],
        quorum_required: 1,
        quorum_total: 1,
    };

    let multi = Arc::new(MultiTsaClient::from_config(&cfg).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::new(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
    );

    let ca_clone = ca.ca_pem.clone();
    let outcome = runner
        .run_once_with_ca_resolver(
            &tenant(1),
            &|_label| Some(ca_clone.clone()),
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (1, 3),
        )
        .await
        .expect("fallback should succeed");
    match outcome {
        ResilientOutcome::Anchored(_) => {}
        other => panic!("expected Anchored, got {other:?}"),
    }

    // Primary breaker should have a failure logged; backup1 should
    // have a success logged.
    let snap_primary = multi.breaker(0).unwrap().snapshot().await;
    let snap_backup1 = multi.breaker(1).unwrap().snapshot().await;
    let snap_backup2 = multi.breaker(2).unwrap().snapshot().await;
    assert!(snap_primary.total_failures >= 1);
    assert_eq!(snap_backup1.total_successes, 1);
    // Backup2 should NEVER have been called.
    assert_eq!(snap_backup2.total_successes, 0);
    assert_eq!(snap_backup2.total_failures, 0);

    // No critical events on the successful cascade.
    let events = sink.events().await;
    assert!(events.is_empty(), "no critical events on fallback success");
    assert!(
        ir.incidents().await.is_empty(),
        "no IR incidents on fallback success"
    );
}

// ---------------------------------------------------------------------------
// 2. Primary times out, backup1 times out -> falls to backup2.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn primary_and_backup1_unreachable_backup2_wins() {
    let ca = build_ca();
    let tsa_kp = build_tsa(&ca);
    let root = predicted_root();
    let token = build_token_bytes(&tsa_kp, root, "0xb2", "2026-06-14T01:00:00Z");

    let primary = MockServer::start().await;
    let backup1 = MockServer::start().await;
    let backup2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(504))
        .mount(&backup1)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token))
        .mount(&backup2)
        .await;

    let cfg = MultiTsaConfig {
        tenant_id: tenant(2),
        primary: TsaEndpoint {
            url: format!("{}/tsr", primary.uri()),
            ca_pem: ca.ca_pem.clone(),
            label: Some("primary".to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups: vec![
            TsaEndpoint {
                url: format!("{}/tsr", backup1.uri()),
                ca_pem: ca.ca_pem.clone(),
                label: Some("backup1".to_owned()),
                timeout: StdDuration::from_secs(5),
            },
            TsaEndpoint {
                url: format!("{}/tsr", backup2.uri()),
                ca_pem: ca.ca_pem.clone(),
                label: Some("backup2".to_owned()),
                timeout: StdDuration::from_secs(5),
            },
        ],
        quorum_required: 1,
        quorum_total: 1,
    };

    let multi = Arc::new(MultiTsaClient::from_config(&cfg).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::new(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
    );

    let ca_clone = ca.ca_pem.clone();
    let outcome = runner
        .run_once_with_ca_resolver(
            &tenant(2),
            &|_label| Some(ca_clone.clone()),
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (4, 6),
        )
        .await
        .expect("fallback to backup2 should succeed");
    match outcome {
        ResilientOutcome::Anchored(_) => {}
        other => panic!("expected Anchored, got {other:?}"),
    }

    let snap0 = multi.breaker(0).unwrap().snapshot().await;
    let snap1 = multi.breaker(1).unwrap().snapshot().await;
    let snap2 = multi.breaker(2).unwrap().snapshot().await;
    assert!(snap0.total_failures >= 1);
    assert!(snap1.total_failures >= 1);
    assert_eq!(snap2.total_successes, 1);
}

// ---------------------------------------------------------------------------
// 3. All endpoints unreachable -> entry queued.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_endpoints_unreachable_enqueues_entry_and_emits_warn() {
    let ca = build_ca();
    let primary = MockServer::start().await;
    let backup = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&backup)
        .await;

    let cfg = MultiTsaConfig {
        tenant_id: tenant(3),
        primary: TsaEndpoint {
            url: format!("{}/tsr", primary.uri()),
            ca_pem: ca.ca_pem.clone(),
            label: Some("primary".to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups: vec![TsaEndpoint {
            url: format!("{}/tsr", backup.uri()),
            ca_pem: ca.ca_pem.clone(),
            label: Some("backup".to_owned()),
            timeout: StdDuration::from_secs(5),
        }],
        quorum_required: 1,
        quorum_total: 1,
    };

    let multi = Arc::new(MultiTsaClient::from_config(&cfg).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::new(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
    );

    let outcome = runner
        .run_once(
            &tenant(3),
            &ca.ca_pem,
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (7, 9),
        )
        .await
        .expect("queued outcome");
    match outcome {
        ResilientOutcome::Queued(_) => {}
        other => panic!("expected Queued, got {other:?}"),
    }

    // Pending entry recorded.
    let pending = queue.list_pending(&tenant(3), 10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, AnchorQueueStatus::Pending);
    // Critical event WARN-style: fallback_exhausted.
    let events = sink.events().await;
    assert!(events
        .iter()
        .any(|(_, msg)| msg.contains(audit_event::ANCHOR_FALLBACK_EXHAUSTED)));
    // No IR incident — transient failure mode.
    assert!(ir.incidents().await.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Invalid TSA signature -> CRITICAL + IR incident auto-opened.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_tsa_signature_emits_critical_and_opens_ir_incident() {
    // The primary returns a token whose embedded signature does not
    // validate against the pinned CA (we sign with `other_ca` then
    // pin to `real_ca`).
    let real_ca = build_ca();
    let other_ca = build_ca();
    let tsa_kp = build_tsa(&other_ca); // CA signature is from the wrong CA.
    let root = predicted_root();
    let token = build_token_bytes(&tsa_kp, root, "0xbad", "2026-06-14T02:00:00Z");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token))
        .mount(&server)
        .await;

    let cfg = MultiTsaConfig {
        tenant_id: tenant(4),
        primary: TsaEndpoint {
            url: format!("{}/tsr", server.uri()),
            ca_pem: real_ca.ca_pem.clone(),
            label: Some("primary".to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups: vec![],
        quorum_required: 1,
        quorum_total: 1,
    };

    let multi = Arc::new(MultiTsaClient::from_config(&cfg).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::new(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
    );

    let err = runner
        .run_once(
            &tenant(4),
            &real_ca.ca_pem,
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (10, 12),
        )
        .await
        .expect_err("must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("tsa signature invalid") || msg.contains("verification"),
        "unexpected: {msg}",
    );

    // CRITICAL event tagged with the audit code.
    let events = sink.events().await;
    assert!(
        events
            .iter()
            .any(|(_, msg)| msg.contains(audit_event::ANCHOR_TSA_SIGNATURE_INVALID)),
        "events: {events:?}",
    );
    // IR incident auto-opened.
    let incidents = ir.incidents().await;
    assert_eq!(incidents.len(), 1);
    let inc: &OpenedIrIncident = &incidents[0];
    assert_eq!(inc.tenant_id, tenant(4));
    assert_eq!(inc.playbook_id, "tsa-compromise");
    assert_eq!(inc.severity, "critical");
    // No persisted anchor row.
    let rows = repo.list_for_tenant(&tenant(4), 10).await.unwrap();
    assert!(rows.is_empty());
    // No queue entry (signature fail is NOT transient).
    let pending = queue.list_pending(&tenant(4), 10).await.unwrap();
    assert!(pending.is_empty());
}

// ---------------------------------------------------------------------------
// 5. Malformed response -> CRITICAL + IR incident (suggests MitM).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_response_emits_critical_and_opens_ir_incident() {
    let ca = build_ca();
    let server = MockServer::start().await;
    // Body that doesn't start with DER SEQUENCE -> classified as
    // ResponseMalformed by FreeTsaClient.
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"not-der".to_vec()))
        .mount(&server)
        .await;

    let cfg = MultiTsaConfig {
        tenant_id: tenant(5),
        primary: TsaEndpoint {
            url: format!("{}/tsr", server.uri()),
            ca_pem: ca.ca_pem.clone(),
            label: Some("primary".to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups: vec![],
        quorum_required: 1,
        quorum_total: 1,
    };

    let multi = Arc::new(MultiTsaClient::from_config(&cfg).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::new(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
    );

    let err = runner
        .run_once(
            &tenant(5),
            &ca.ca_pem,
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (13, 15),
        )
        .await
        .expect_err("malformed response must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("malformed") || msg.contains("verification"),
        "unexpected: {msg}"
    );

    // CRITICAL event + IR incident.
    let events = sink.events().await;
    assert!(events
        .iter()
        .any(|(_, m)| m.contains(audit_event::ANCHOR_TSA_RESPONSE_MALFORMED)));
    let incidents = ir.incidents().await;
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].playbook_id, "tsa-mitm");
}

// ---------------------------------------------------------------------------
// 6. Queued retry succeeds after primary recovers.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn queued_retry_recovers_when_primary_comes_back() {
    let ca = build_ca();
    let tsa_kp = build_tsa(&ca);
    let root = predicted_root();
    let token = build_token_bytes(&tsa_kp, root, "0xfeed", "2026-06-14T03:00:00Z");

    // Single TSA mock — initially 503, swapped to 200 mid-test.
    let server = MockServer::start().await;
    let fail_mock = Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1..); // at least one failure
    server.register(fail_mock).await;

    let cfg = MultiTsaConfig {
        tenant_id: tenant(6),
        primary: TsaEndpoint {
            url: format!("{}/tsr", server.uri()),
            ca_pem: ca.ca_pem.clone(),
            label: Some("primary".to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups: vec![],
        quorum_required: 1,
        quorum_total: 1,
    };

    let clock = Arc::new(ManualClock::new(
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
    ));
    let multi = Arc::new(MultiTsaClient::from_config_with_clock(&cfg, clock.clone() as _).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::with_clock(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
        clock.clone() as _,
    );

    // First attempt fails -> queued.
    let outcome = runner
        .run_once(
            &tenant(6),
            &ca.ca_pem,
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (1, 3),
        )
        .await
        .expect("queued");
    let qid = match outcome {
        ResilientOutcome::Queued(id) => id,
        other => panic!("expected Queued, got {other:?}"),
    };
    let pending = queue.list_pending(&tenant(6), 10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].queue_id, qid);

    // Reset mocks: now the server replies with a valid token.
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(token))
        .mount(&server)
        .await;

    // Wait for the primary's circuit breaker to recover. The breaker is
    // shared with the runner so an Open state would block the retry.
    // After 3 failures it's Open; advance past cool-down to HalfOpen so
    // the retry probe gets through.
    let snap_before = multi.breaker(0).unwrap().snapshot().await;
    if snap_before.state == BreakerState::Open {
        clock.advance(StdDuration::from_secs(61)).await;
    }

    // Run retry tick.
    let retryer = AnchorQueueRetryer::new(runner.clone());
    let ca_clone = ca.ca_pem.clone();
    let actions = retryer
        .tick(&|_tenant, _label| Some(ca_clone.clone()))
        .await
        .expect("tick ok");
    assert_eq!(actions.len(), 1, "exactly one pending row processed");
    assert_eq!(actions[0].0, qid);
    assert_eq!(actions[0].1, sx_audit::tsa_fallback::RetryAction::Recovered);

    // Queue row marked Recovered.
    let snapshot = queue.snapshot().await;
    assert_eq!(snapshot[0].status, AnchorQueueStatus::Recovered);
    // Anchor row persisted.
    let rows = repo.list_for_tenant(&tenant(6), 10).await.unwrap();
    assert_eq!(rows.len(), 1);
    // Recovery event emitted.
    let events = sink.events().await;
    assert!(events
        .iter()
        .any(|(_, m)| m.contains(audit_event::ANCHOR_QUEUE_RECOVERED)));
}

// ---------------------------------------------------------------------------
// 7. Queue retry window exhausted -> CRITICAL emitted, row marked Exhausted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn queue_retry_window_exhausted_emits_critical() {
    let ca = build_ca();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let cfg = MultiTsaConfig {
        tenant_id: tenant(7),
        primary: TsaEndpoint {
            url: format!("{}/tsr", server.uri()),
            ca_pem: ca.ca_pem.clone(),
            label: Some("primary".to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups: vec![],
        quorum_required: 1,
        quorum_total: 1,
    };

    let clock = Arc::new(ManualClock::new(
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
    ));
    let multi = Arc::new(MultiTsaClient::from_config_with_clock(&cfg, clock.clone() as _).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::with_clock(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
        clock.clone() as _,
    );

    let outcome = runner
        .run_once(
            &tenant(7),
            &ca.ca_pem,
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (1, 3),
        )
        .await
        .expect("queued");
    let qid = match outcome {
        ResilientOutcome::Queued(id) => id,
        other => panic!("expected Queued, got {other:?}"),
    };

    // Advance clock past the 24h retry window.
    clock.advance(StdDuration::from_secs(25 * 60 * 60)).await;

    let retryer = AnchorQueueRetryer::new(runner.clone());
    let ca_clone = ca.ca_pem.clone();
    let actions = retryer
        .tick(&|_tenant, _label| Some(ca_clone.clone()))
        .await
        .expect("tick ok");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].0, qid);
    assert_eq!(actions[0].1, sx_audit::tsa_fallback::RetryAction::Exhausted);

    let snap = queue.snapshot().await;
    assert_eq!(snap[0].status, AnchorQueueStatus::Exhausted);
    let events = sink.events().await;
    assert!(events
        .iter()
        .any(|(_, m)| m.contains(audit_event::ANCHOR_QUEUE_EXHAUSTED)));
}

// ---------------------------------------------------------------------------
// MED-002 quorum tests — anchor side + verify side
// ---------------------------------------------------------------------------
//
// These exercise the 2-of-3 quorum contract end-to-end:
//
// Anchor side:
//   * 3-of-3 all sign  → quorum met, record stores 3 Verified signatures
//   * 2-of-3 (1 unreachable) → quorum met (>=2), record stores 2 Verified + 1 Failed
//   * 1-of-3 (2 unreachable) → quorum NOT met, run is queued for retry
//
// Verify side (re-running `AnchorRunner::verify_run_quorum` on a persisted row):
//   * all 3 CAs supplied → all 3 verify
//   * 2 CAs supplied (one TSA decommissioned) → 2 verify, still meets quorum
//   * 1 CA supplied (two TSAs decommissioned) → quorum shortfall, errors

/// Build a multi-TSA fixture with `endpoints` (label, server URL, ca PEM)
/// tuples. Returns a wired `ResilientAnchorRunner` + repo + sinks so each
/// test can drive the runner end-to-end with minimal boilerplate.
fn wire_runner(
    endpoints: Vec<(&str, String, String)>,
) -> (
    ResilientAnchorRunner,
    Arc<InMemoryAnchorRunRepository>,
    Arc<RecordingCriticalEventSink>,
    Arc<InMemoryAnchorQueueRepository>,
    MultiTsaConfig,
) {
    assert!(!endpoints.is_empty());
    let (head_label, head_url, head_ca) = endpoints[0].clone();
    let backups: Vec<TsaEndpoint> = endpoints
        .iter()
        .skip(1)
        .map(|(label, url, ca)| TsaEndpoint {
            url: url.clone(),
            ca_pem: ca.clone(),
            label: Some((*label).to_owned()),
            timeout: StdDuration::from_secs(5),
        })
        .collect();
    let cfg = MultiTsaConfig {
        tenant_id: tenant(900),
        primary: TsaEndpoint {
            url: head_url,
            ca_pem: head_ca,
            label: Some(head_label.to_owned()),
            timeout: StdDuration::from_secs(5),
        },
        backups,
        quorum_required: 2,
        quorum_total: 3,
    };
    let multi = Arc::new(MultiTsaClient::from_config(&cfg).unwrap());
    let repo = Arc::new(InMemoryAnchorRunRepository::new());
    let queue = Arc::new(InMemoryAnchorQueueRepository::new());
    let sink = Arc::new(RecordingCriticalEventSink::new());
    let ir = Arc::new(RecordingIrIncidentSink::new());
    let runner = ResilientAnchorRunner::new(
        Arc::clone(&multi),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::clone(&sink) as _,
        Arc::clone(&ir) as _,
        Arc::clone(&queue) as _,
    );
    (runner, repo, sink, queue, cfg)
}

#[tokio::test]
async fn quorum_3_of_3_anchor_records_three_verified_signatures() {
    // Three TSAs all return valid tokens signed by the same CA. Quorum
    // is satisfied with all three Verified.
    let ca = build_ca();
    let tsa_a = build_tsa(&ca);
    let tsa_b = build_tsa(&ca);
    let tsa_c = build_tsa(&ca);
    let root = predicted_root();

    let srv_a = MockServer::start().await;
    let srv_b = MockServer::start().await;
    let srv_c = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_token_bytes(
            &tsa_a,
            root,
            "0x0a",
            "2026-06-14T00:00:00Z",
        )))
        .mount(&srv_a)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_token_bytes(
            &tsa_b,
            root,
            "0x0b",
            "2026-06-14T00:01:00Z",
        )))
        .mount(&srv_b)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_token_bytes(
            &tsa_c,
            root,
            "0x0c",
            "2026-06-14T00:02:00Z",
        )))
        .mount(&srv_c)
        .await;

    let (runner, repo, sink, _queue, _cfg) = wire_runner(vec![
        ("alpha", format!("{}/tsr", srv_a.uri()), ca.ca_pem.clone()),
        ("beta", format!("{}/tsr", srv_b.uri()), ca.ca_pem.clone()),
        ("gamma", format!("{}/tsr", srv_c.uri()), ca.ca_pem.clone()),
    ]);

    let ca_pem = ca.ca_pem.clone();
    let outcome = runner
        .run_once_quorum(
            &tenant(900),
            &|_label| Some(ca_pem.clone()),
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            (1, 3),
            2,
            3,
        )
        .await
        .expect("quorum met");
    let run_id = match outcome {
        ResilientOutcome::Anchored(id) => id,
        other => panic!("expected Anchored, got {other:?}"),
    };
    let row = repo.get_for_tenant(&tenant(900), &run_id).await.unwrap();
    let q = row.quorum.expect("quorum sidecar persisted");
    assert_eq!(q.required, 2);
    assert_eq!(q.total, 3);
    assert_eq!(q.signatures.len(), 3);
    let verified: Vec<_> = q
        .signatures
        .iter()
        .filter(|s| matches!(s.status, QuorumSignatureStatus::Verified))
        .collect();
    assert_eq!(verified.len(), 3, "all three verified");
    assert!(q.meets_quorum(), "3 verified satisfies 2-of-3");
    // No CRITICAL on the happy path.
    assert!(sink.events().await.is_empty());
}

#[tokio::test]
async fn quorum_2_of_3_anchor_with_one_unreachable_still_persists() {
    // Two TSAs return valid tokens, one returns 503. Quorum is exactly
    // satisfied (2 >= 2). The shortfall TSA shows up as a Failed slot.
    let ca = build_ca();
    let tsa_a = build_tsa(&ca);
    let tsa_b = build_tsa(&ca);
    let root = predicted_root();

    let srv_a = MockServer::start().await;
    let srv_b = MockServer::start().await;
    let srv_dead = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_token_bytes(
            &tsa_a,
            root,
            "0xaa",
            "2026-06-14T01:00:00Z",
        )))
        .mount(&srv_a)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_token_bytes(
            &tsa_b,
            root,
            "0xbb",
            "2026-06-14T01:01:00Z",
        )))
        .mount(&srv_b)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&srv_dead)
        .await;

    let (runner, repo, sink, _queue, _cfg) = wire_runner(vec![
        ("alpha", format!("{}/tsr", srv_a.uri()), ca.ca_pem.clone()),
        ("beta", format!("{}/tsr", srv_b.uri()), ca.ca_pem.clone()),
        ("dead", format!("{}/tsr", srv_dead.uri()), ca.ca_pem.clone()),
    ]);

    let ca_pem = ca.ca_pem.clone();
    let outcome = runner
        .run_once_quorum(
            &tenant(900),
            &|_label| Some(ca_pem.clone()),
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_010_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_013_600).unwrap(),
            (4, 6),
            2,
            3,
        )
        .await
        .expect("quorum met");
    let run_id = match outcome {
        ResilientOutcome::Anchored(id) => id,
        other => panic!("expected Anchored, got {other:?}"),
    };
    let row = repo.get_for_tenant(&tenant(900), &run_id).await.unwrap();
    let q = row.quorum.expect("quorum sidecar persisted");
    assert_eq!(q.required, 2);
    let verified = q.verified_count();
    assert_eq!(verified, 2, "exactly two verified");
    // The third slot is recorded — either Failed (TSA reachable but
    // 5xx surfaced as transport error) or NotAttempted (breaker Open).
    assert_eq!(q.signatures.len(), 3);
    let dead_slot = q
        .signatures
        .iter()
        .find(|s| s.label == "dead")
        .expect("dead slot present");
    assert!(
        matches!(
            dead_slot.status,
            QuorumSignatureStatus::Failed | QuorumSignatureStatus::NotAttempted
        ),
        "unreachable TSA recorded as Failed or NotAttempted, got {:?}",
        dead_slot.status,
    );
    assert!(q.meets_quorum(), "2 verified satisfies 2-of-3");
    // Quorum met → no CRITICAL.
    assert!(sink.events().await.is_empty());
}

#[tokio::test]
async fn quorum_1_of_3_anchor_below_threshold_queues_for_retry() {
    // Only one TSA succeeds; the other two are 503. With
    // quorum_required=2 we MUST refuse to persist and queue instead.
    let ca = build_ca();
    let tsa_a = build_tsa(&ca);
    let root = predicted_root();

    let srv_a = MockServer::start().await;
    let srv_dead1 = MockServer::start().await;
    let srv_dead2 = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(build_token_bytes(
            &tsa_a,
            root,
            "0xaa",
            "2026-06-14T02:00:00Z",
        )))
        .mount(&srv_a)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&srv_dead1)
        .await;
    Mock::given(method("POST"))
        .and(path("/tsr"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&srv_dead2)
        .await;

    let (runner, repo, sink, queue, _cfg) = wire_runner(vec![
        ("alpha", format!("{}/tsr", srv_a.uri()), ca.ca_pem.clone()),
        (
            "dead1",
            format!("{}/tsr", srv_dead1.uri()),
            ca.ca_pem.clone(),
        ),
        (
            "dead2",
            format!("{}/tsr", srv_dead2.uri()),
            ca.ca_pem.clone(),
        ),
    ]);

    let ca_pem = ca.ca_pem.clone();
    let outcome = runner
        .run_once_quorum(
            &tenant(900),
            &|_label| Some(ca_pem.clone()),
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_020_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_023_600).unwrap(),
            (7, 9),
            2,
            3,
        )
        .await
        .expect("queued");
    match outcome {
        ResilientOutcome::Queued(_) => {}
        other => panic!("expected Queued (quorum shortfall), got {other:?}"),
    }
    // No row persisted; the shortfall window must be retried, not
    // recorded with a partial quorum.
    let rows = repo.list_for_tenant(&tenant(900), 10).await.expect("list");
    assert!(rows.is_empty(), "no row persisted on quorum shortfall");
    let pending = queue
        .list_pending(&tenant(900), 10)
        .await
        .expect("list pending");
    assert_eq!(pending.len(), 1, "shortfall enqueued for retry");
    // Shortfall emits the dedicated CRITICAL audit event.
    let events = sink.events().await;
    assert!(
        events
            .iter()
            .any(|(_, m)| m.contains(audit_event::ANCHOR_QUORUM_SHORTFALL)),
        "ANCHOR_QUORUM_SHORTFALL event emitted, got {events:?}",
    );
}

// ---------------------------------------------------------------------------
// Verify side — re-running verify_run_quorum on a persisted row.
//
// The shape: anchor a 3-of-3 record once, then re-verify with various
// per-label CA resolvers to simulate TSAs going dark over time.
// ---------------------------------------------------------------------------

/// Anchor a fresh 3-of-3 row and return (`AnchorRunner` backed by the same
/// repo, run_id, ca_pem). The runner returned here is the *plain*
/// `AnchorRunner` (no fallback) — that's what backs the verify endpoint.
async fn anchor_three_of_three_fixture() -> (AnchorRunner, sx_audit::anchor_run::AnchorRunId, String)
{
    let ca = build_ca();
    let tsa_a = build_tsa(&ca);
    let tsa_b = build_tsa(&ca);
    let tsa_c = build_tsa(&ca);
    let root = predicted_root();

    let srv_a = MockServer::start().await;
    let srv_b = MockServer::start().await;
    let srv_c = MockServer::start().await;
    for (srv, tsa, serial, t) in [
        (&srv_a, &tsa_a, "0xaa", "2026-06-14T05:00:00Z"),
        (&srv_b, &tsa_b, "0xbb", "2026-06-14T05:01:00Z"),
        (&srv_c, &tsa_c, "0xcc", "2026-06-14T05:02:00Z"),
    ] {
        Mock::given(method("POST"))
            .and(path("/tsr"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(build_token_bytes(tsa, root, serial, t)),
            )
            .mount(srv)
            .await;
    }

    let (runner, repo, _sink, _queue, _cfg) = wire_runner(vec![
        ("alpha", format!("{}/tsr", srv_a.uri()), ca.ca_pem.clone()),
        ("beta", format!("{}/tsr", srv_b.uri()), ca.ca_pem.clone()),
        ("gamma", format!("{}/tsr", srv_c.uri()), ca.ca_pem.clone()),
    ]);
    let ca_pem = ca.ca_pem.clone();
    let outcome = runner
        .run_once_quorum(
            &tenant(900),
            &|_label| Some(ca_pem.clone()),
            &chain_hashes(),
            OffsetDateTime::from_unix_timestamp(1_700_030_000).unwrap(),
            OffsetDateTime::from_unix_timestamp(1_700_033_600).unwrap(),
            (10, 12),
            2,
            3,
        )
        .await
        .expect("anchored");
    let run_id = match outcome {
        ResilientOutcome::Anchored(id) => id,
        other => panic!("expected Anchored, got {other:?}"),
    };
    // The plain AnchorRunner reads from the same repo — that's the path
    // the verify endpoint uses.
    let plain_runner = AnchorRunner::new(
        Arc::new(sx_audit::anchor_run::JsonTsaClient::new("http://unused/tsr").unwrap()),
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo) as _,
        Arc::new(RecordingCriticalEventSink::new()) as _,
    );
    (plain_runner, run_id, ca.ca_pem)
}

#[tokio::test]
async fn quorum_verify_all_three_verify_against_pinned_cas() {
    let (runner, run_id, ca_pem) = anchor_three_of_three_fixture().await;
    let q = runner
        .verify_run_quorum(&tenant(900), &run_id, &|_label| Some(ca_pem.clone()))
        .await
        .expect("verify pass");
    assert_eq!(q.required, 2);
    assert_eq!(q.total, 3);
    assert_eq!(q.verified_count(), 3, "all three still verify");
    assert!(q.meets_quorum());
}

#[tokio::test]
async fn quorum_verify_two_pass_one_unknown_ca_still_meets_quorum() {
    let (runner, run_id, ca_pem) = anchor_three_of_three_fixture().await;
    // Simulate "gamma was decommissioned": no pinned CA for it.
    let q = runner
        .verify_run_quorum(&tenant(900), &run_id, &|label| {
            if label == "gamma" {
                None
            } else {
                Some(ca_pem.clone())
            }
        })
        .await
        .expect("quorum still met");
    assert_eq!(q.verified_count(), 2, "two still verify");
    assert!(q.meets_quorum(), "2 of 2-of-3 holds");
    let gamma = q
        .signatures
        .iter()
        .find(|s| s.label == "gamma")
        .expect("gamma slot present");
    assert!(matches!(gamma.status, QuorumSignatureStatus::Failed));
    assert!(
        gamma
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("no pinned CA")),
        "failure reason recorded: {gamma:?}",
    );
}

#[tokio::test]
async fn quorum_verify_one_pass_two_unknown_cas_fails_quorum() {
    let (runner, run_id, ca_pem) = anchor_three_of_three_fixture().await;
    // Two TSAs decommissioned simultaneously — only `alpha` resolves.
    let err = runner
        .verify_run_quorum(&tenant(900), &run_id, &|label| {
            if label == "alpha" {
                Some(ca_pem.clone())
            } else {
                None
            }
        })
        .await
        .expect_err("must error: quorum shortfall");
    match err {
        AnchorRunError::Verification(msg) => {
            assert!(
                msg.contains("quorum verify shortfall") || msg.contains("verified=1"),
                "expected shortfall reason, got: {msg}",
            );
        }
        other => panic!("expected Verification, got {other:?}"),
    }
}
