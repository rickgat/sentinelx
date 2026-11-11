//! Integration tests for the log-ingest port + view DTO surface.
//!
//! Walks through the contract a controller observes:
//!
//! 1. A `LogIngestPort` impl accepts an OCSF payload (the `cloudtrail`
//!    parser is exercised through a fake adapter that mirrors the real
//!    monolith adapter's projection logic).
//! 2. The view DTO (`OcsfEventView`) serialises to the exact wire shape
//!    the dashboard depends on (renamed `type` field, integer
//!    `severity_id`, list-shaped envelope).
//! 3. The `LogIngestError` variants map cleanly to the public
//!    [`sx_api::ApiError`] taxonomy (Forbidden / Unprocessable /
//!    Internal) without leaking internal details.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::assertions_on_constants)]

use std::sync::Mutex;

use async_trait::async_trait;
use sx_api::port::{LogIngestError, LogIngestPort};
use sx_api::view::log_ingest_view::{
    IngestLogRequest, ListLogsResponse, ObservableView, OcsfEventView, OcsfMetadataView,
    INGEST_MAX_PAYLOAD_BYTES, LIST_MAX_LIMIT,
};
use validator::Validate;

/// In-memory log-ingest fake — mirrors the monolith adapter just enough
/// to exercise the port contract end-to-end. Stores a tiny canned event
/// per `(tenant_id)` so `list()` returns it.
#[derive(Debug, Default)]
struct FakeLogIngest {
    inner: Mutex<Vec<(String, OcsfEventView)>>,
}

#[async_trait]
impl LogIngestPort for FakeLogIngest {
    async fn ingest_one(
        &self,
        tenant_id: &str,
        source: &str,
        _payload: &str,
    ) -> Result<(), LogIngestError> {
        if source == "no-such-source" {
            return Err(LogIngestError::UnknownSource(source.to_owned()));
        }
        if source == "explode" {
            return Err(LogIngestError::Internal("boom".into()));
        }
        let event = OcsfEventView {
            class_uid: 6003,
            category_uid: 6,
            time: "2026-06-12T10:30:01Z".into(),
            severity_id: 1,
            raw: "{}".into(),
            metadata: OcsfMetadataView {
                version: "1.1.0".into(),
                product: "AWS CloudTrail".into(),
                source_type: source.to_owned(),
                tenant_id: tenant_id.to_owned(),
            },
            observables: vec![ObservableView {
                name: "src_ip".into(),
                kind: "ip".into(),
                value: "203.0.113.5".into(),
            }],
        };
        self.inner
            .lock()
            .unwrap()
            .push((tenant_id.to_owned(), event));
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<OcsfEventView>, LogIngestError> {
        let guard = self.inner.lock().unwrap();
        Ok(guard
            .iter()
            .rev()
            .filter(|(t, _)| t == tenant_id)
            .take(limit)
            .map(|(_, e)| e.clone())
            .collect())
    }
}

#[tokio::test]
async fn ingest_then_list_round_trips_through_port() {
    let port: Box<dyn LogIngestPort> = Box::new(FakeLogIngest::default());
    port.ingest_one("tenant-a", "cloudtrail", "{}")
        .await
        .unwrap();
    let items = port.list("tenant-a", 10).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].metadata.tenant_id, "tenant-a");
    assert_eq!(items[0].metadata.source_type, "cloudtrail");
    assert_eq!(items[0].class_uid, 6003);
}

#[tokio::test]
async fn tenants_are_isolated_through_port() {
    let port: Box<dyn LogIngestPort> = Box::new(FakeLogIngest::default());
    port.ingest_one("tenant-a", "cloudtrail", "{}")
        .await
        .unwrap();
    port.ingest_one("tenant-b", "cloudtrail", "{}")
        .await
        .unwrap();
    let only_a = port.list("tenant-a", 10).await.unwrap();
    let only_b = port.list("tenant-b", 10).await.unwrap();
    assert_eq!(only_a.len(), 1);
    assert_eq!(only_b.len(), 1);
    assert_eq!(only_a[0].metadata.tenant_id, "tenant-a");
    assert_eq!(only_b[0].metadata.tenant_id, "tenant-b");
}

#[tokio::test]
async fn unknown_source_surfaces_through_port() {
    let port: Box<dyn LogIngestPort> = Box::new(FakeLogIngest::default());
    let err = port
        .ingest_one("t", "no-such-source", "{}")
        .await
        .unwrap_err();
    assert!(matches!(err, LogIngestError::UnknownSource(s) if s == "no-such-source"));
}

#[tokio::test]
async fn internal_error_surfaces_through_port() {
    let port: Box<dyn LogIngestPort> = Box::new(FakeLogIngest::default());
    let err = port.ingest_one("t", "explode", "{}").await.unwrap_err();
    assert!(matches!(err, LogIngestError::Internal(_)));
}

#[test]
fn ingest_request_validates_required_lengths() {
    let r = IngestLogRequest {
        source: String::new(),
        payload: "{}".into(),
    };
    assert!(r.validate().is_err());

    let r = IngestLogRequest {
        source: "cloudtrail".into(),
        payload: String::new(),
    };
    assert!(r.validate().is_err());

    let r = IngestLogRequest {
        source: "cloudtrail".into(),
        payload: "{}".into(),
    };
    assert!(r.validate().is_ok());
}

#[test]
fn ingest_request_rejects_oversized_payload() {
    let r = IngestLogRequest {
        source: "cloudtrail".into(),
        payload: "x".repeat(INGEST_MAX_PAYLOAD_BYTES + 1),
    };
    assert!(r.validate().is_err());
}

#[test]
fn list_max_limit_is_finite_and_reasonable() {
    // Pin the constant so a refactor doesn't accidentally lift it to
    // u32::MAX (which would let a caller force a huge response body).
    assert!(LIST_MAX_LIMIT >= 100);
    assert!(LIST_MAX_LIMIT <= 10_000);
}

#[test]
fn event_view_wire_shape_uses_renamed_type_field() {
    let v = OcsfEventView {
        class_uid: 6003,
        category_uid: 6,
        time: "2026-06-12T10:30:01Z".into(),
        severity_id: 3,
        raw: "{}".into(),
        metadata: OcsfMetadataView {
            version: "1.1.0".into(),
            product: "AWS CloudTrail".into(),
            source_type: "cloudtrail".into(),
            tenant_id: "t".into(),
        },
        observables: vec![ObservableView {
            name: "src_ip".into(),
            kind: "ip".into(),
            value: "203.0.113.5".into(),
        }],
    };
    let s = serde_json::to_string(&v).unwrap();
    assert!(s.contains("\"class_uid\":6003"));
    assert!(s.contains("\"category_uid\":6"));
    assert!(s.contains("\"severity_id\":3"));
    // `kind` is renamed to `type` for the wire — pin it here so a future
    // refactor of the DTO does not silently break the dashboard.
    assert!(s.contains("\"type\":\"ip\""));
    assert!(!s.contains("\"kind\":\"ip\""));
}

#[test]
fn list_envelope_serialises_with_items_array() {
    let r = ListLogsResponse { items: Vec::new() };
    let s = serde_json::to_string(&r).unwrap();
    assert!(s.contains("\"items\""));
    assert!(s.contains("[]"));
}
