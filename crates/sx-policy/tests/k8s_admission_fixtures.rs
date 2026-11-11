//! Golden `AdmissionReview` JSON fixtures, one per rule.
//!
//! Each test loads a hand-curated `AdmissionReview` from
//! `tests/fixtures/k8s_admission/<rule>.json`, runs the analyzer service, and
//! asserts the expected rule id fires. A final `clean_deployment` fixture
//! asserts that a fully-hardened workload produces *zero* findings.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)] // fixture tests

use std::sync::Arc;

use sx_policy::k8s_admission::{
    AdmissionReview, FindingSeverity, InMemoryK8sAdmissionService, K8sAdmissionService,
};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/k8s_admission");

fn load(name: &str) -> AdmissionReview {
    let path = format!("{FIXTURE_DIR}/{name}.json");
    let body = std::fs::read_to_string(&path).expect("fixture exists");
    serde_json::from_str(&body).expect("fixture parses as AdmissionReview")
}

async fn run(name: &str) -> AdmissionReview {
    let svc = InMemoryK8sAdmissionService::new(Arc::new(sx_policy::k8s_admission::SystemClock));
    svc.review("tenant-test", None, load(name))
        .await
        .expect("review succeeds")
}

fn has_rule(out: &AdmissionReview, rule_id: &str) -> bool {
    out.response
        .as_ref()
        .is_some_and(|r| r.findings.iter().any(|f| f.rule_id == rule_id))
}

#[tokio::test]
async fn fixture_privileged_fires() {
    let out = run("privileged").await;
    assert!(has_rule(&out, "k8s.pod.privileged"));
    assert!(!out.response.as_ref().unwrap().allowed);
}

#[tokio::test]
async fn fixture_host_network_fires() {
    let out = run("host_network").await;
    assert!(has_rule(&out, "k8s.pod.host_network"));
}

#[tokio::test]
async fn fixture_host_pid_fires() {
    let out = run("host_pid").await;
    assert!(has_rule(&out, "k8s.pod.host_pid"));
}

#[tokio::test]
async fn fixture_host_ipc_fires() {
    let out = run("host_ipc").await;
    assert!(has_rule(&out, "k8s.pod.host_ipc"));
}

#[tokio::test]
async fn fixture_host_path_fires() {
    let out = run("host_path").await;
    assert!(has_rule(&out, "k8s.pod.host_path"));
}

#[tokio::test]
async fn fixture_dangerous_capability_fires() {
    let out = run("dangerous_capability").await;
    assert!(has_rule(&out, "k8s.container.dangerous_capability"));
}

#[tokio::test]
async fn fixture_missing_seccomp_fires() {
    let out = run("missing_seccomp").await;
    assert!(has_rule(&out, "k8s.container.missing_seccomp"));
}

#[tokio::test]
async fn fixture_missing_apparmor_fires() {
    let out = run("missing_apparmor").await;
    assert!(has_rule(&out, "k8s.container.missing_apparmor"));
}

#[tokio::test]
async fn fixture_unsafe_sysctl_fires() {
    let out = run("unsafe_sysctl").await;
    assert!(has_rule(&out, "k8s.pod.unsafe_sysctl"));
}

#[tokio::test]
async fn fixture_untrusted_registry_fires() {
    let out = run("untrusted_registry").await;
    assert!(has_rule(&out, "k8s.container.untrusted_registry"));
}

#[tokio::test]
async fn fixture_latest_tag_fires() {
    let out = run("latest_tag").await;
    assert!(has_rule(&out, "k8s.container.latest_tag"));
}

#[tokio::test]
async fn fixture_missing_resource_limits_fires() {
    let out = run("missing_resource_limits").await;
    assert!(has_rule(&out, "k8s.container.missing_resource_limits"));
}

#[tokio::test]
async fn fixture_run_as_root_fires() {
    let out = run("run_as_root").await;
    assert!(has_rule(&out, "k8s.container.run_as_root"));
}

#[tokio::test]
async fn fixture_allow_privilege_escalation_fires() {
    let out = run("allow_privilege_escalation").await;
    assert!(has_rule(&out, "k8s.container.allow_privilege_escalation"));
}

#[tokio::test]
async fn fixture_read_only_root_fs_disabled_fires() {
    let out = run("read_only_root_fs_disabled").await;
    assert!(has_rule(&out, "k8s.container.read_only_root_fs_disabled"));
}

#[tokio::test]
async fn fixture_automount_sa_token_default_fires() {
    let out = run("automount_sa_token_default").await;
    assert!(has_rule(&out, "k8s.pod.automount_sa_token_default"));
}

#[tokio::test]
async fn fixture_clean_deployment_has_zero_findings() {
    let out = run("clean_deployment").await;
    let resp = out.response.as_ref().expect("response");
    assert!(
        resp.findings.is_empty(),
        "expected clean deployment, got {:?}",
        resp.findings
    );
    assert!(resp.allowed);
}

#[tokio::test]
async fn response_aggregates_warnings_and_max_severity() {
    // The `privileged` fixture should bubble a Critical warning into the response.
    let out = run("privileged").await;
    let resp = out.response.as_ref().expect("response");
    assert!(resp
        .warnings
        .iter()
        .any(|w| w.contains("k8s.pod.privileged")));
    let max = resp
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .expect("at least one finding");
    assert_eq!(max, FindingSeverity::Critical);
}
