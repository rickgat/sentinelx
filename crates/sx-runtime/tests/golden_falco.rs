//! Golden Falco JSON fixtures — assert the expected normalised finding
//! is emitted for each of the three canonical container-runtime alerts
//! called out by the P2-016 spec:
//!
//! 1. Privileged escape (`Launch Privileged Container`)
//! 2. Shell in container (`Terminal shell in container`)
//! 3. K8s admin token mount (`Read sensitive file untrusted (...token)`)

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;

use secrecy::SecretString;
use sx_runtime::{
    auth::sign_body_for_tests, AuditOutcome, FalcoIngestService, RecordingAuditSink,
    RuntimeSeverity, TenantKeyStore,
};
use sx_secrets::{InMemoryProvider, SecretsProvider};

const TENANT: &str = "tenant-golden";
const KEY: &str = "ingest-key-v1";

async fn fresh_service() -> (FalcoIngestService, RecordingAuditSink) {
    let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
    let store = TenantKeyStore::new(provider);
    store
        .put_key(TENANT, SecretString::from(KEY.to_owned()))
        .await
        .unwrap();
    let sink = RecordingAuditSink::new();
    let svc = FalcoIngestService::new(store, Arc::new(sink.clone()));
    (svc, sink)
}

fn load(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read fixture {}", path.display()))
}

async fn ingest(svc: &FalcoIngestService, body: &[u8]) -> sx_runtime::IngestionReport {
    let ts = 1_700_000_000;
    let sig = sign_body_for_tests(&SecretString::from(KEY.to_owned()), ts, body);
    svc.ingest(TENANT, ts, Some(&sig), body, ts).await.unwrap()
}

#[tokio::test]
async fn privileged_escape_emits_critical_finding() {
    let (svc, sink) = fresh_service().await;
    let body = load("privileged_escape.json");
    let report = ingest(&svc, &body).await;
    assert_eq!(report.accepted, 1);
    let f = &report.findings[0];
    assert_eq!(f.rule, "Launch Privileged Container");
    assert_eq!(f.severity, RuntimeSeverity::Critical);
    assert_eq!(f.tenant_id, TENANT);
    assert_eq!(f.namespace.as_deref(), Some("prod"));
    assert_eq!(f.pod_name.as_deref(), Some("web-7c4d-abc"));
    assert_eq!(
        f.container_image.as_deref(),
        Some("docker.io/library/nginx")
    );
    assert_eq!(
        f.asset_id.as_deref(),
        Some("k8s://prod/web-7c4d-abc/docker.io/library/nginx")
    );
    assert!(f.tags.iter().any(|t| t == "T1611"));

    let ev = &report.ocsf_events[0];
    // Process Activity / System Activity.
    assert_eq!(ev.class_uid, 1007);
    assert_eq!(ev.category_uid, 1);
    assert_eq!(ev.severity_id, 5); // OCSF Critical = 5
    assert_eq!(ev.metadata.tenant_id, TENANT);
    assert_eq!(ev.metadata.source_type, "falco");
    let names: Vec<&str> = ev.observables.iter().map(|o| o.name.as_str()).collect();
    assert!(names.contains(&"falco.rule"));
    assert!(names.contains(&"proc.name"));
    assert!(names.contains(&"container.image"));

    let audit = sink.snapshot().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].outcome, AuditOutcome::Accepted);
    assert_eq!(audit[0].alert_count, 1);
}

#[tokio::test]
async fn shell_in_container_emits_medium_finding() {
    let (svc, _sink) = fresh_service().await;
    let body = load("shell_in_container.json");
    let report = ingest(&svc, &body).await;
    let f = &report.findings[0];
    assert_eq!(f.rule, "Terminal shell in container");
    // Falco priority "Warning" -> Medium.
    assert_eq!(f.severity, RuntimeSeverity::Medium);
    assert_eq!(f.namespace.as_deref(), Some("staging"));
    assert_eq!(f.pod_name.as_deref(), Some("api-bb6cd-xyz"));
    assert_eq!(f.container_image.as_deref(), Some("alpine"));
    assert_eq!(
        f.asset_id.as_deref(),
        Some("k8s://staging/api-bb6cd-xyz/alpine")
    );
    assert!(f.tags.iter().any(|t| t == "T1059"));

    let ev = &report.ocsf_events[0];
    assert_eq!(ev.class_uid, 1007);
    assert_eq!(ev.severity_id, 3); // Medium
    assert!(ev
        .observables
        .iter()
        .any(|o| o.name == "proc.cmdline" && o.value == "bash -i"));
}

#[tokio::test]
async fn k8s_admin_token_mount_emits_critical_application_activity() {
    let (svc, _sink) = fresh_service().await;
    let body = load("k8s_admin_token_mount.json");
    let report = ingest(&svc, &body).await;
    let f = &report.findings[0];
    assert!(f.rule.starts_with("Read sensitive file untrusted"));
    assert_eq!(f.severity, RuntimeSeverity::Critical);
    assert_eq!(f.namespace.as_deref(), Some("kube-system"));
    assert_eq!(f.pod_name.as_deref(), Some("intruder-1"));
    assert_eq!(f.source, "k8s_audit");
    assert!(f.tags.iter().any(|t| t == "T1552.005"));

    let ev = &report.ocsf_events[0];
    // k8s_audit source -> Application Activity (6002, category 6).
    assert_eq!(ev.class_uid, 6002);
    assert_eq!(ev.category_uid, 6);
    assert_eq!(ev.severity_id, 5);
}

#[tokio::test]
async fn batched_array_emits_three_findings() {
    let (svc, sink) = fresh_service().await;
    // Compose all three fixtures into a single array body.
    let mut items: Vec<serde_json::Value> = Vec::new();
    for name in [
        "privileged_escape.json",
        "shell_in_container.json",
        "k8s_admin_token_mount.json",
    ] {
        items.push(serde_json::from_slice(&load(name)).unwrap());
    }
    let body = serde_json::to_vec(&items).unwrap();
    let report = ingest(&svc, &body).await;
    assert_eq!(report.alert_count, 3);
    assert_eq!(report.accepted, 3);
    let rules: Vec<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"Launch Privileged Container"));
    assert!(rules.contains(&"Terminal shell in container"));

    // Exactly one audit row for the whole batch.
    let audit = sink.snapshot().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].alert_count, 3);
    assert_eq!(audit[0].accepted, 3);
}
