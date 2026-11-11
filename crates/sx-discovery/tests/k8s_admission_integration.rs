//! HIGH-009 — integration tests for the K8s admission webhook engine.
//!
//! Exercises [`AdmissionEngine`] end-to-end with deterministic
//! `admission.k8s.io/v1` `AdmissionReview` fixtures so the engine is
//! covered without a real `kind` cluster on the dev box. Every fixture
//! is the verbatim JSON shape the apiserver POSTs to the webhook; the
//! tests prove the engine round-trips the wire envelope and produces
//! the response envelope the apiserver expects.

#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use sx_discovery::k8s_admission::{
    AdmissionEngine, AdmissionReview, InMemoryTenantRulePolicy, K8sAdmissionDecision, NoLatestTag,
    NoPrivileged, PodSecurityStandard, PssProfile, RecordingK8sAdmissionAuditSink, RulePack,
};

/// A privileged pod (CREATE) wrapped in the apiserver wire envelope.
/// The escape sequence and content match what `kube-apiserver` actually
/// sends — confirmed against the upstream
/// `staging/src/k8s.io/api/admission/v1/types.go` shape.
const FIXTURE_PRIVILEGED_POD: &str = r#"{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "resource": {"group": "", "version": "v1", "resource": "pods"},
        "name": "evil",
        "namespace": "default",
        "operation": "CREATE",
        "userInfo": {"username": "system:serviceaccount:default:default", "groups": ["system:authenticated"]},
        "object": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "evil", "namespace": "default"},
            "spec": {
                "containers": [
                    {
                        "name": "c1",
                        "image": "nginx:1.25",
                        "securityContext": {"privileged": true}
                    }
                ]
            }
        }
    }
}"#;

/// A compliant pod (CREATE) — runAsNonRoot + drop ALL + seccomp set.
const FIXTURE_COMPLIANT_POD: &str = r#"{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "00000000-0000-0000-0000-000000000001",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "resource": {"group": "", "version": "v1", "resource": "pods"},
        "name": "good",
        "namespace": "default",
        "operation": "CREATE",
        "userInfo": {"username": "alice"},
        "object": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "good", "namespace": "default", "labels": {"app": "good"}},
            "spec": {
                "containers": [
                    {
                        "name": "c1",
                        "image": "nginx:1.25.3@sha256:abc123def456",
                        "securityContext": {
                            "runAsNonRoot": true,
                            "allowPrivilegeEscalation": false,
                            "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"}
                        }
                    }
                ]
            }
        }
    }
}"#;

/// A pod scheduled into `kube-system`. The default `recommended` pack
/// opts this namespace out — the engine MUST allow regardless of the
/// pod's posture.
const FIXTURE_KUBE_SYSTEM_POD: &str = r#"{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "11111111-2222-3333-4444-555555555555",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "name": "kube-proxy",
        "namespace": "kube-system",
        "operation": "CREATE",
        "userInfo": {"username": "system:serviceaccount:kube-system:kube-proxy"},
        "object": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "kube-proxy", "namespace": "kube-system"},
            "spec": {
                "hostNetwork": true,
                "containers": [{"name": "kube-proxy", "image": "registry.k8s.io/kube-proxy:v1.30.0"}]
            }
        }
    }
}"#;

/// A latest-tag pod (CREATE).
const FIXTURE_LATEST_TAG_POD: &str = r#"{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "deadbeef-0000-4000-8000-000000000001",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "name": "mutable",
        "namespace": "default",
        "operation": "CREATE",
        "object": {
            "spec": {"containers": [{"name": "c1", "image": "nginx:latest"}]}
        }
    }
}"#;

fn build_engine(pack: RulePack) -> (AdmissionEngine, Arc<RecordingK8sAdmissionAuditSink>) {
    let policy = Arc::new(InMemoryTenantRulePolicy::new());
    policy.set_default(pack);
    let sink = Arc::new(RecordingK8sAdmissionAuditSink::new());
    (AdmissionEngine::new(policy, sink.clone()), sink)
}

#[tokio::test]
async fn integration_recommended_pack_denies_privileged_apiserver_fixture() {
    // Use the same `recommended` pack the production composition root
    // wires in by default. The fixture is the verbatim wire shape the
    // apiserver POSTs.
    let review: AdmissionReview =
        serde_json::from_str(FIXTURE_PRIVILEGED_POD).expect("fixture must parse");
    let (engine, sink) = build_engine(RulePack::recommended());
    let resp = engine.evaluate("t-tenant", review).await.unwrap();

    let r = resp.response.expect("response present");
    assert!(!r.allowed, "privileged pod must be denied");
    let s = r.status.expect("status block on deny");
    assert_eq!(s.code, 403);
    assert!(
        s.message.contains("privileged") || s.message.contains("pss-baseline"),
        "deny reason should reference the offending posture: {}",
        s.message
    );
    // The engine echoes the request uid so the apiserver can correlate.
    assert_eq!(r.uid, "705ab4f5-6393-11e8-b7cc-42010a800002");

    // One audit row was written; decision is Deny.
    assert_eq!(sink.len(), 1);
    let ev = &sink.events()[0];
    assert_eq!(ev.decision, K8sAdmissionDecision::Deny);
    assert_eq!(ev.retention_days, 90, "HIGH-009 retention is 90 days");
    assert!(ev.rule_id.is_some(), "deny audit row must carry rule id");
    assert!(
        ev.request.object.is_some(),
        "sanitised request payload retained"
    );
}

#[tokio::test]
async fn integration_compliant_pod_passes_pss_restricted() {
    // A fully-compliant pod with digest-pinned image, runAsNonRoot,
    // drop ALL, seccompProfile=RuntimeDefault — passes PSS restricted.
    let review: AdmissionReview =
        serde_json::from_str(FIXTURE_COMPLIANT_POD).expect("fixture must parse");
    let mut pack = RulePack::empty();
    pack.rules = vec![
        Arc::new(PodSecurityStandard::new(PssProfile::Restricted)),
        Arc::new(NoLatestTag),
    ];
    let (engine, sink) = build_engine(pack);
    let resp = engine.evaluate("t-tenant", review).await.unwrap();

    let r = resp.response.expect("response present");
    assert!(r.allowed, "compliant pod must be allowed");
    assert!(r.status.is_none());
    assert_eq!(sink.events()[0].decision, K8sAdmissionDecision::Allow);
}

#[tokio::test]
async fn integration_kube_system_optout_short_circuits_engine() {
    // Even with a privileged pod posture, the kube-system opt-out wins.
    // This protects the cluster from a bricking misconfiguration —
    // SentinelX MUST NOT deny a kube-proxy upgrade.
    let review: AdmissionReview =
        serde_json::from_str(FIXTURE_KUBE_SYSTEM_POD).expect("fixture must parse");
    let (engine, sink) = build_engine(RulePack::recommended());
    let resp = engine.evaluate("t-tenant", review).await.unwrap();

    let r = resp.response.expect("response present");
    assert!(r.allowed, "kube-system MUST be opted out");
    let ev = &sink.events()[0];
    assert_eq!(ev.decision, K8sAdmissionDecision::Allow);
    assert_eq!(
        ev.rule_id.as_deref(),
        Some("namespace_optout"),
        "audit row must attribute the allow to the opt-out",
    );
}

#[tokio::test]
async fn integration_dry_run_records_would_deny_and_allows() {
    // Dry-run mode: same input as the privileged-pod fixture, but the
    // engine returns allow + warning instead of deny. The audit row
    // records the would-be deny so an operator can preview enforcement.
    let review: AdmissionReview =
        serde_json::from_str(FIXTURE_PRIVILEGED_POD).expect("fixture must parse");
    let mut pack = RulePack::empty();
    pack.rules = vec![Arc::new(NoPrivileged)];
    pack.dry_run = true;
    let (engine, sink) = build_engine(pack);
    let resp = engine.evaluate("t-tenant", review).await.unwrap();

    let r = resp.response.expect("response present");
    assert!(r.allowed, "dry-run MUST always allow");
    let warnings = r.warnings.expect("dry-run must surface warnings");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("would-deny"));
    let ev = &sink.events()[0];
    assert_eq!(ev.decision, K8sAdmissionDecision::DryRunWouldDeny);
    assert_eq!(ev.rule_id.as_deref(), Some("no-privileged"));
    assert!(
        ev.reason
            .as_deref()
            .is_some_and(|r| r.contains("privileged")),
        "dry-run audit must carry the deny reason"
    );
}

#[tokio::test]
async fn integration_latest_tag_pod_denied_and_audited() {
    let review: AdmissionReview =
        serde_json::from_str(FIXTURE_LATEST_TAG_POD).expect("fixture must parse");
    let mut pack = RulePack::empty();
    pack.rules = vec![Arc::new(NoLatestTag)];
    let (engine, sink) = build_engine(pack);
    let resp = engine.evaluate("t-tenant", review).await.unwrap();

    let r = resp.response.expect("response present");
    assert!(!r.allowed);
    assert!(r.status.unwrap().message.contains("no-latest-tag"));
    let ev = &sink.events()[0];
    assert_eq!(ev.decision, K8sAdmissionDecision::Deny);
    assert_eq!(ev.rule_id.as_deref(), Some("no-latest-tag"));
}

#[tokio::test]
async fn integration_response_envelope_round_trips_through_serde() {
    // The apiserver expects the response wire shape: outer
    // `AdmissionReview` with `kind=AdmissionReview`, `apiVersion=admission.k8s.io/v1`,
    // and a populated `response` field. This integration test proves
    // the engine emits a JSON envelope that survives a full
    // serialise → deserialise round-trip.
    let review: AdmissionReview =
        serde_json::from_str(FIXTURE_COMPLIANT_POD).expect("fixture must parse");
    let (engine, _sink) = build_engine(RulePack::empty());
    let resp_envelope = engine.evaluate("t-tenant", review).await.unwrap();

    let json = serde_json::to_string(&resp_envelope).expect("serialise");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse back");
    assert_eq!(parsed["apiVersion"], "admission.k8s.io/v1");
    assert_eq!(parsed["kind"], "AdmissionReview");
    assert_eq!(parsed["response"]["allowed"], true);
    assert_eq!(
        parsed["response"]["uid"], "00000000-0000-0000-0000-000000000001",
        "response uid MUST echo request uid for apiserver correlation"
    );
}
