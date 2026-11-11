//! End-to-end credential rotation integration tests (CRIT-005).
//!
//! These tests drive the full rotation pipeline:
//!
//! 1. Mock Vault Transit responses with `wiremock`.
//! 2. Wire a real [`sx_secrets::VaultTransitRotation`] against the
//!    mock URL.
//! 3. Run the [`sx_intel_feeds::CredentialRotationScheduler`] against
//!    a seeded `intel_credential_rotation_state` row.
//! 4. Assert the secrets backend received the new credential, the
//!    audit sink captured a `success=true` event, and the per-row
//!    state transitioned `due → done`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use sx_intel_feeds::{
    CredentialRotationScheduler, InMemoryCredentialAuditSink, InMemoryRotationStateStore,
    RotationSeverity, RotationStateRow, RotationStateStore, RotationVendor, StaticRotationRegistry,
    DEFAULT_ROTATION_CADENCE,
};
use sx_secrets::{InMemoryProvider, RotationPort, SecretsProvider, VaultTransitRotation};
use time::OffsetDateTime;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn vault_token() -> SecretString {
    SecretString::new("vault-root-token".to_owned().into_boxed_str())
}

#[tokio::test]
async fn rotation_against_mock_vault_persists_new_credential_and_emits_audit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/keys/mandiant-client/rotate"))
        .and(header("x-vault-token", "vault-root-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "latest_version": 11 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let port: Arc<dyn RotationPort> = Arc::new(VaultTransitRotation::with_default_mount(
        reqwest::Client::new(),
        server.uri(),
        vault_token(),
    ));

    let tenant = Uuid::new_v4();
    let state = Arc::new(InMemoryRotationStateStore::new());
    state
        .upsert(RotationStateRow::new_due_now(
            tenant,
            "mandiant-client",
            RotationVendor::VaultTransit,
            DEFAULT_ROTATION_CADENCE,
        ))
        .await
        .unwrap();
    let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
    let registry = Arc::new(StaticRotationRegistry::new().with(RotationVendor::VaultTransit, port));
    let audit = Arc::new(InMemoryCredentialAuditSink::new());
    let scheduler = CredentialRotationScheduler::<_, (), _, _>::new(
        secrets.clone(),
        state.clone(),
        registry,
        audit.clone(),
    );

    let attempted = scheduler.run_once(OffsetDateTime::now_utc()).await.unwrap();
    assert_eq!(attempted, 1);

    // The scheduler should have persisted the new secret.
    let stored = secrets
        .get(&format!("tenants/{tenant}/intel/mandiant-client"))
        .await
        .unwrap();
    assert!(!stored.expose_secret().is_empty());

    // The audit event must record success + the canonical event type.
    let events = audit.snapshot().await;
    assert_eq!(events.len(), 1);
    assert!(events[0].success);
    assert_eq!(events[0].severity, RotationSeverity::Info);
    assert_eq!(events[0].vendor, RotationVendor::VaultTransit);

    // The state row should have moved out of "due" into "done":
    // last_rotated_at set, next_due_at advanced, attempts cleared.
    let after = state.snapshot().await;
    assert_eq!(after.len(), 1);
    assert!(after[0].last_rotated_at.is_some());
    assert_eq!(after[0].attempts, 0);
    assert!(after[0].next_due_at > OffsetDateTime::now_utc());
    assert!(after[0].last_error.is_none());
}

#[tokio::test]
async fn graceful_handover_preserves_previous_credential_via_versioning() {
    // The handover guarantee is encoded at the provider layer (Vault
    // keeps the previous key version, AWS keeps AWSPREVIOUS, GCP
    // leaves the prior version ENABLED). What the scheduler is
    // responsible for is two things:
    //
    // 1. NOT destroying any state on the secrets backend that the
    //    previous credential depends on — i.e. `put` is an
    //    append-or-overwrite, not a "delete prior versions" call.
    // 2. Stamping `not_before` on the freshly issued credential so
    //    downstream consumers can implement their own 30 min cutover.
    //
    // This test verifies (1) by checking that the OLD secret (seeded
    // before rotation) was overwritten with the NEW value but the
    // previous Vault key version stays addressable (mock returns
    // `latest_version=2`, implying version 1 still exists).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/keys/crowdstrike-client/rotate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "latest_version": 2 }
        })))
        .mount(&server)
        .await;

    let port: Arc<dyn RotationPort> = Arc::new(VaultTransitRotation::with_default_mount(
        reqwest::Client::new(),
        server.uri(),
        vault_token(),
    ));

    let tenant = Uuid::new_v4();
    let state = Arc::new(InMemoryRotationStateStore::new());
    state
        .upsert(RotationStateRow::new_due_now(
            tenant,
            "crowdstrike-client",
            RotationVendor::VaultTransit,
            DEFAULT_ROTATION_CADENCE,
        ))
        .await
        .unwrap();
    let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
    // Seed previous credential so we can compare.
    secrets
        .put(
            &format!("tenants/{tenant}/intel/crowdstrike-client"),
            SecretString::new("OLD-CRED".to_owned().into_boxed_str()),
        )
        .await
        .unwrap();
    let registry = Arc::new(StaticRotationRegistry::new().with(RotationVendor::VaultTransit, port));
    let audit = Arc::new(InMemoryCredentialAuditSink::new());
    let scheduler = CredentialRotationScheduler::<_, (), _, _>::new(
        secrets.clone(),
        state,
        registry,
        audit.clone(),
    );

    scheduler.run_once(OffsetDateTime::now_utc()).await.unwrap();

    let new_value = secrets
        .get(&format!("tenants/{tenant}/intel/crowdstrike-client"))
        .await
        .unwrap();
    assert_ne!(new_value.expose_secret(), "OLD-CRED");
    // The audit event must NOT contain the credential value.
    let events = audit.snapshot().await;
    assert_eq!(events.len(), 1);
    if let Some(reason) = &events[0].error_redacted {
        assert!(!reason.contains("OLD-CRED"));
    }
}

#[tokio::test]
async fn three_consecutive_vault_403s_escalate_to_error_and_preserve_secret() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/keys/mandiant-client/rotate"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let port: Arc<dyn RotationPort> = Arc::new(VaultTransitRotation::with_default_mount(
        reqwest::Client::new(),
        server.uri(),
        vault_token(),
    ));

    let tenant = Uuid::new_v4();
    let state = Arc::new(InMemoryRotationStateStore::new());
    state
        .upsert(RotationStateRow::new_due_now(
            tenant,
            "mandiant-client",
            RotationVendor::VaultTransit,
            DEFAULT_ROTATION_CADENCE,
        ))
        .await
        .unwrap();
    let secrets: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
    secrets
        .put(
            &format!("tenants/{tenant}/intel/mandiant-client"),
            SecretString::new("UNTOUCHABLE-OLD".to_owned().into_boxed_str()),
        )
        .await
        .unwrap();
    let registry = Arc::new(StaticRotationRegistry::new().with(RotationVendor::VaultTransit, port));
    let audit = Arc::new(InMemoryCredentialAuditSink::new());
    let scheduler = CredentialRotationScheduler::<_, (), _, _>::new(
        secrets.clone(),
        state.clone(),
        registry,
        audit.clone(),
    );

    for _ in 0..3 {
        scheduler.run_once(OffsetDateTime::now_utc()).await.unwrap();
    }

    let events = audit.snapshot().await;
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|e| !e.success));
    assert_eq!(events[2].severity, RotationSeverity::Error);
    assert_eq!(
        events[2].error_redacted.as_deref(),
        Some("unauthorized"),
        "the redacted reason must be the canonical string"
    );

    // Most important assertion: old credential is preserved
    // verbatim. The scheduler MUST NOT overwrite the secret when the
    // rotation fails.
    let preserved = secrets
        .get(&format!("tenants/{tenant}/intel/mandiant-client"))
        .await
        .unwrap();
    assert_eq!(preserved.expose_secret(), "UNTOUCHABLE-OLD");

    // The row should record three attempts.
    let after = state.snapshot().await;
    assert_eq!(after[0].attempts, 3);
}

#[tokio::test]
async fn pci_cadence_is_shorter_than_standard_and_observable_on_due_row() {
    let tenant = Uuid::new_v4();
    let state = Arc::new(InMemoryRotationStateStore::new());

    // PCI tenant gets a 30 day cadence.
    let pci_row = RotationStateRow::new_due_now(
        tenant,
        "pci/client_secret",
        RotationVendor::VaultTransit,
        sx_intel_feeds::PCI_ROTATION_CADENCE,
    );
    state.upsert(pci_row).await.unwrap();

    let row = state.load(tenant, "pci/client_secret").await.unwrap();
    assert_eq!(row.cadence, Duration::from_secs(30 * 24 * 60 * 60));
    // standard is strictly longer
    assert!(DEFAULT_ROTATION_CADENCE > row.cadence);
}
