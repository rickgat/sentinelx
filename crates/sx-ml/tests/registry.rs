//! Tests for `InMemoryModelRegistry` and the training use cases.

// Integration tests: `expect` on Result is a deliberate assertion style; the
// one-element array literal is the simplest fixture seed.
#![allow(clippy::expect_used, clippy::iter_on_single_items)]

use secrecy::SecretString;
use std::collections::HashSet;
use std::sync::Arc;
use sx_ml::controller::predict_triage::PredictTriageUseCase;
use sx_ml::controller::train_triage::{TrainTriageConfig, TrainTriageUseCase};
use sx_ml::model::artifact::{ArtifactKind, ModelArtifact};
use sx_ml::model::metrics::ModelMetrics;
use sx_ml::prelude::*;

fn make_row(severity: f64, is_internal: bool) -> FeatureVector {
    let mut row = FeatureVector::new();
    row.insert("severity".to_string(), FeatureValue::Number(severity));
    row.insert("is_internal".to_string(), FeatureValue::Bool(is_internal));
    row
}

fn fixture_anonymiser() -> Arc<Anonymiser> {
    let pepper = SecretString::from("test-pepper".to_string());
    let drop: HashSet<String> = ["email".to_string()].into_iter().collect();
    let hash: HashSet<String> = HashSet::new();
    Arc::new(Anonymiser::new(pepper, drop, hash))
}

#[tokio::test]
async fn in_memory_registry_round_trip() {
    let reg = InMemoryModelRegistry::new();
    let artifact = ModelArtifact::new(
        "m1",
        "v1",
        ArtifactKind::Triage,
        ModelMetrics::default(),
        serde_json::json!({"hello": "world"}),
    );
    reg.register(artifact.clone()).await.expect("register");
    let cur = reg.current("m1").await.expect("current");
    assert_eq!(cur.as_ref().map(|a| &a.model_id), Some(&"m1".to_string()));
    let versions = reg.list_versions("m1").await.expect("list");
    assert_eq!(versions.len(), 1);
    // none for an unknown model
    assert!(reg.current("missing").await.expect("current").is_none());
}

#[tokio::test]
async fn train_triage_use_case_returns_artifact_with_metrics() {
    let anon = fixture_anonymiser();
    let reg: Arc<dyn ModelRegistry> = Arc::new(InMemoryModelRegistry::new());
    let uc = TrainTriageUseCase::new(
        anon,
        reg.clone(),
        "triage",
        "v0.1.0",
        TrainTriageConfig::default(),
    );
    let mut rows = Vec::new();
    for v in [0.1_f64, 0.2, 0.3, 0.4] {
        rows.push((make_row(v, true), Label::TruePositive));
    }
    for v in [0.8_f64, 0.9, 1.0, 1.1] {
        rows.push((make_row(v, false), Label::FalsePositive));
    }
    let artifact = uc.execute(rows).await.expect("train ok");
    assert_eq!(artifact.kind, ArtifactKind::Triage);
    assert_eq!(artifact.metrics.samples, 8);
    assert!(artifact.metrics.precision > 0.5);
    assert!(artifact.metrics.recall > 0.5);
}

#[tokio::test]
async fn predict_triage_use_case_uses_current_version() {
    let anon = fixture_anonymiser();
    let reg: Arc<dyn ModelRegistry> = Arc::new(InMemoryModelRegistry::new());
    let train = TrainTriageUseCase::new(
        anon.clone(),
        reg.clone(),
        "triage",
        "v0.1.0",
        TrainTriageConfig::default(),
    );
    let mut rows = Vec::new();
    for v in [0.1_f64, 0.2, 0.3, 0.4] {
        rows.push((make_row(v, true), Label::TruePositive));
    }
    for v in [0.8_f64, 0.9, 1.0, 1.1] {
        rows.push((make_row(v, false), Label::FalsePositive));
    }
    train.execute(rows).await.expect("train ok");

    let predict = PredictTriageUseCase::new(anon, reg);
    let label = predict
        .execute("triage", make_row(0.15, true))
        .await
        .expect("predict ok");
    assert_eq!(label, Label::TruePositive);
    let label = predict
        .execute("triage", make_row(1.0, false))
        .await
        .expect("predict ok");
    assert_eq!(label, Label::FalsePositive);
}
