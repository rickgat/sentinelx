//! Drift-detection service interface + in-memory implementation.
//!
//! The service trait keeps the diff core out of the HTTP layer so the
//! monolith can swap in a database-backed implementation without
//! touching the controller. The default
//! [`InMemoryCloudDriftService`] is suitable for development /
//! standalone runs and for the unit + integration tests that ship with
//! this module.
//!
//! The diff implementation itself ([`DriftDetector::detect`]) is a
//! plain stateless function — exposed both as an associated method on
//! the service and as a free helper so callers that already have a
//! `(BaselineDoc, Vec<CloudResource>)` pair don't have to thread the
//! service through their call site.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

use super::baseline::{BaselineDoc, BaselineResource, ResourceType};
use super::severity::classify;
use super::DriftEntry;
use crate::model::CloudResource;

/// Errors produced by the drift service.
#[derive(Debug, Error)]
pub enum DetectDriftError {
    /// The baseline did not contain any resources of the supported
    /// types, so a diff cannot be computed.
    #[error("baseline is empty")]
    EmptyBaseline,
    /// Internal invariant violation. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),
}

/// Cloud-drift service abstraction.
///
/// Implementations are responsible for:
///
/// 1. Storing baselines keyed by `(tenant_id, baseline_id)` (for the
///    in-memory adapter; the production database adapter persists into
///    Postgres).
/// 2. Storing detected drift entries — newest detection wins per
///    `(tenant_id, baseline_id)` pair.
/// 3. Running [`Self::detect_drift`] against the supplied live state.
#[async_trait]
pub trait CloudDriftService: Send + Sync {
    /// Persist a baseline and return its newly minted id.
    async fn store_baseline(
        &self,
        tenant_id: Uuid,
        name: String,
        format: super::baseline::BaselineFormat,
        payload: Vec<u8>,
        doc: BaselineDoc,
    ) -> Result<Uuid, DetectDriftError>;

    /// List baselines available to `tenant_id`, newest-first.
    async fn list_baselines(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<StoredBaseline>, DetectDriftError>;

    /// Detect drift between `live` and the supplied baseline. Returns
    /// the freshly computed drift entries (also persisted so
    /// [`Self::list_drift`] can read them back).
    async fn detect_drift(
        &self,
        tenant_id: Uuid,
        baseline_id: Uuid,
        live: Vec<CloudResource>,
    ) -> Result<Vec<DriftEntry>, DetectDriftError>;

    /// List the most recently detected drift entries for `tenant_id`,
    /// optionally filtered by asset (resource id) substring.
    async fn list_drift(
        &self,
        tenant_id: Uuid,
        asset_filter: Option<&str>,
    ) -> Result<Vec<DriftEntry>, DetectDriftError>;
}

/// Stored baseline projection returned by [`CloudDriftService::list_baselines`].
#[derive(Debug, Clone)]
pub struct StoredBaseline {
    /// Database / store identifier.
    pub id: Uuid,
    /// Operator-supplied display name.
    pub name: String,
    /// Wire format of the original payload.
    pub format: super::baseline::BaselineFormat,
    /// Count of supported resources in the parsed document.
    pub resource_count: usize,
}

/// Stateless drift detector — exposed as a free helper so callers that
/// already have a `(BaselineDoc, Vec<CloudResource>)` pair don't need
/// the full service trait.
#[derive(Debug, Default)]
pub struct DriftDetector;

impl DriftDetector {
    /// Compute the per-attribute diff between `baseline` and `live`.
    ///
    /// Algorithm:
    ///
    /// 1. Group live resources by their canonical id (ARN).
    /// 2. For every baseline resource:
    ///    1. Find the matching live resource by canonical id.
    ///    2. If none, emit a single `(attribute = "<missing>")` entry.
    ///    3. Otherwise iterate the baseline attribute keys and emit one
    ///       drift entry per attribute that differs.
    /// 3. Any live resource that has *no* baseline counterpart is
    ///    emitted with `attribute = "<unmanaged>"`.
    #[must_use]
    pub fn detect(baseline: &BaselineDoc, live: &[CloudResource]) -> Vec<DriftEntry> {
        let mut entries: Vec<DriftEntry> = Vec::new();
        let live_by_id: HashMap<String, &CloudResource> =
            live.iter().map(|r| (r.id.clone(), r)).collect();
        let baseline_ids: std::collections::HashSet<String> = baseline
            .resources
            .iter()
            .map(|r| r.identifier.clone())
            .collect();

        for b in &baseline.resources {
            match live_by_id.get(&b.identifier) {
                Some(l) => diff_one(b, l, &mut entries),
                None => entries.push(DriftEntry {
                    resource_id: b.identifier.clone(),
                    resource_type: b.resource_type.as_terraform().to_owned(),
                    attribute: "<missing>".to_owned(),
                    baseline_value: serde_json::Value::Bool(true),
                    live_value: serde_json::Value::Null,
                    severity_hint: super::severity::DriftSeverity::High,
                }),
            }
        }

        // Surface unmanaged live resources whose type matches our
        // whitelist but for which no baseline exists. Other live
        // resources are silently ignored — the whitelist gate is the
        // only thing keeping the output volume sane.
        for l in live {
            if baseline_ids.contains(&l.id) {
                continue;
            }
            let Some(rt) = match_live_resource_type(l) else {
                continue;
            };
            entries.push(DriftEntry {
                resource_id: l.id.clone(),
                resource_type: rt.as_terraform().to_owned(),
                attribute: "<unmanaged>".to_owned(),
                baseline_value: serde_json::Value::Null,
                live_value: serde_json::Value::Bool(true),
                severity_hint: super::severity::DriftSeverity::Medium,
            });
        }

        entries
    }
}

/// Compute the per-attribute drift between one baseline resource and
/// one matching live resource, pushing entries into `out`.
fn diff_one(b: &BaselineResource, l: &CloudResource, out: &mut Vec<DriftEntry>) {
    let live_attrs = match &l.raw {
        serde_json::Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    for (k, baseline_v) in &b.attributes {
        let live_v = live_attrs
            .get(k)
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if values_equal(baseline_v, &live_v) {
            continue;
        }
        let severity = classify(b.resource_type, k, baseline_v, &live_v);
        out.push(DriftEntry {
            resource_id: b.identifier.clone(),
            resource_type: b.resource_type.as_terraform().to_owned(),
            attribute: k.clone(),
            baseline_value: baseline_v.clone(),
            live_value: live_v,
            severity_hint: severity,
        });
    }
}

/// JSON equality with one tweak: a baseline `null` matches a missing
/// live key (both surface as JSON null after the lookup above) so the
/// diff doesn't fire on every absent optional attribute.
fn values_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    if a.is_null() && b.is_null() {
        return true;
    }
    a == b
}

/// Best-effort mapping from the unified `CloudResource` to one of the
/// whitelisted resource types. Used when surfacing unmanaged live
/// resources.
fn match_live_resource_type(r: &CloudResource) -> Option<ResourceType> {
    match (r.service.as_str(), r.kind.as_str()) {
        ("s3", "bucket") => Some(ResourceType::AwsS3Bucket),
        ("iam", "role") => Some(ResourceType::AwsIamRole),
        ("ec2", "security_group" | "security-group") => Some(ResourceType::AwsSecurityGroup),
        _ => None,
    }
}

/// In-memory implementation backed by per-tenant `HashMap`s.
///
/// Resources are kept behind a single `Mutex`. Drift entries are
/// replaced wholesale every time [`Self::detect_drift`] is invoked for
/// a given `(tenant, baseline)` pair so the read side never returns
/// stale half-merges.
#[derive(Debug, Default)]
pub struct InMemoryCloudDriftService {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    baselines: HashMap<Uuid, BaselineRecord>,
    drift: HashMap<Uuid, Vec<DriftEntry>>,
}

#[derive(Debug, Clone)]
struct BaselineRecord {
    tenant_id: Uuid,
    name: String,
    format: super::baseline::BaselineFormat,
    #[allow(dead_code)]
    payload: Vec<u8>,
    doc: BaselineDoc,
}

impl InMemoryCloudDriftService {
    /// Construct an empty service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a baseline document by id, scoped to `tenant_id`.
    ///
    /// Exposed so adapters can re-run `detect_drift` against the live
    /// inventory without re-uploading the baseline.
    pub fn baseline_doc(&self, tenant_id: Uuid, baseline_id: Uuid) -> Option<BaselineDoc> {
        let g = self.state.lock().ok()?;
        let r = g.baselines.get(&baseline_id)?;
        if r.tenant_id != tenant_id {
            return None;
        }
        let doc = r.doc.clone();
        drop(g);
        Some(doc)
    }
}

#[async_trait]
impl CloudDriftService for InMemoryCloudDriftService {
    async fn store_baseline(
        &self,
        tenant_id: Uuid,
        name: String,
        format: super::baseline::BaselineFormat,
        payload: Vec<u8>,
        doc: BaselineDoc,
    ) -> Result<Uuid, DetectDriftError> {
        if doc.resources.is_empty() {
            return Err(DetectDriftError::EmptyBaseline);
        }
        let id = Uuid::new_v4();
        {
            let mut g = self
                .state
                .lock()
                .map_err(|_| DetectDriftError::Internal("baseline store poisoned".to_owned()))?;
            g.baselines.insert(
                id,
                BaselineRecord {
                    tenant_id,
                    name,
                    format,
                    payload,
                    doc,
                },
            );
        }
        Ok(id)
    }

    async fn list_baselines(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<StoredBaseline>, DetectDriftError> {
        let mut out: Vec<StoredBaseline> = {
            let g = self
                .state
                .lock()
                .map_err(|_| DetectDriftError::Internal("baseline store poisoned".to_owned()))?;
            g.baselines
                .iter()
                .filter(|(_, r)| r.tenant_id == tenant_id)
                .map(|(id, r)| StoredBaseline {
                    id: *id,
                    name: r.name.clone(),
                    format: r.format,
                    resource_count: r.doc.resources.len(),
                })
                .collect()
        };
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn detect_drift(
        &self,
        tenant_id: Uuid,
        baseline_id: Uuid,
        live: Vec<CloudResource>,
    ) -> Result<Vec<DriftEntry>, DetectDriftError> {
        let doc = self
            .baseline_doc(tenant_id, baseline_id)
            .ok_or(DetectDriftError::EmptyBaseline)?;
        let entries = DriftDetector::detect(&doc, &live);
        {
            let mut g = self
                .state
                .lock()
                .map_err(|_| DetectDriftError::Internal("drift store poisoned".to_owned()))?;
            g.drift.insert(baseline_id, entries.clone());
        }
        Ok(entries)
    }

    async fn list_drift(
        &self,
        tenant_id: Uuid,
        asset_filter: Option<&str>,
    ) -> Result<Vec<DriftEntry>, DetectDriftError> {
        // Hold the lock only long enough to clone matching entries; do
        // the sort below without the lock held.
        let mut out: Vec<DriftEntry> = {
            let g = self
                .state
                .lock()
                .map_err(|_| DetectDriftError::Internal("drift store poisoned".to_owned()))?;
            let mut acc: Vec<DriftEntry> = Vec::new();
            for (baseline_id, entries) in &g.drift {
                let Some(b) = g.baselines.get(baseline_id) else {
                    continue;
                };
                if b.tenant_id != tenant_id {
                    continue;
                }
                for e in entries {
                    if let Some(needle) = asset_filter {
                        if !e.resource_id.contains(needle) {
                            continue;
                        }
                    }
                    acc.push(e.clone());
                }
            }
            drop(g);
            acc
        };
        // Sort by severity desc then resource id asc for a deterministic
        // wire shape.
        out.sort_by(|a, b| {
            b.severity_hint
                .cmp(&a.severity_hint)
                .then_with(|| a.resource_id.cmp(&b.resource_id))
        });
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::drift::baseline::{BaselineFormat, BaselineResource};
    use crate::model::CloudProvider;

    fn baseline_with_bucket(acl: &str) -> BaselineDoc {
        let mut attrs = BTreeMap::new();
        attrs.insert("acl".to_owned(), json!(acl));
        BaselineDoc {
            resources: vec![BaselineResource {
                identifier: "arn:aws:s3:::evidence".to_owned(),
                resource_type: ResourceType::AwsS3Bucket,
                attributes: attrs,
            }],
        }
    }

    fn live_bucket(acl: &str) -> CloudResource {
        CloudResource {
            id: "arn:aws:s3:::evidence".into(),
            provider: CloudProvider::Aws,
            region: None,
            service: "s3".into(),
            kind: "bucket".into(),
            name: "evidence".into(),
            tags: BTreeMap::new(),
            raw: json!({ "acl": acl }),
        }
    }

    #[test]
    fn detector_finds_no_drift_when_attrs_match() {
        let baseline = baseline_with_bucket("private");
        let live = vec![live_bucket("private")];
        let entries = DriftDetector::detect(&baseline, &live);
        assert!(entries.is_empty());
    }

    #[test]
    fn detector_flags_bucket_made_public_as_critical() {
        let baseline = baseline_with_bucket("private");
        let live = vec![live_bucket("public-read")];
        let entries = DriftDetector::detect(&baseline, &live);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.attribute, "acl");
        assert_eq!(
            e.severity_hint,
            super::super::severity::DriftSeverity::Critical
        );
    }

    #[test]
    fn detector_flags_missing_resource() {
        let baseline = baseline_with_bucket("private");
        let live: Vec<CloudResource> = Vec::new();
        let entries = DriftDetector::detect(&baseline, &live);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attribute, "<missing>");
    }

    #[test]
    fn detector_flags_unmanaged_live_resource() {
        let baseline = BaselineDoc::empty();
        let live = vec![live_bucket("private")];
        let entries = DriftDetector::detect(&baseline, &live);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attribute, "<unmanaged>");
    }

    #[tokio::test]
    async fn store_then_detect_round_trips() {
        let svc = InMemoryCloudDriftService::new();
        let tenant = Uuid::new_v4();
        let baseline_id = svc
            .store_baseline(
                tenant,
                "main".into(),
                BaselineFormat::TerraformJson,
                b"{}".to_vec(),
                baseline_with_bucket("private"),
            )
            .await
            .unwrap();
        let entries = svc
            .detect_drift(tenant, baseline_id, vec![live_bucket("public-read")])
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        let listed = svc.list_drift(tenant, None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].severity_hint,
            super::super::severity::DriftSeverity::Critical
        );
    }

    #[tokio::test]
    async fn list_drift_isolates_tenants() {
        let svc = InMemoryCloudDriftService::new();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let id = svc
            .store_baseline(
                t1,
                "t1".into(),
                BaselineFormat::TerraformJson,
                b"{}".to_vec(),
                baseline_with_bucket("private"),
            )
            .await
            .unwrap();
        let _ = svc
            .detect_drift(t1, id, vec![live_bucket("public-read")])
            .await
            .unwrap();

        let other = svc.list_drift(t2, None).await.unwrap();
        assert!(other.is_empty(), "tenant 2 must see no drift from tenant 1");
        let own = svc.list_drift(t1, None).await.unwrap();
        assert_eq!(own.len(), 1);
    }

    #[tokio::test]
    async fn store_rejects_empty_doc() {
        let svc = InMemoryCloudDriftService::new();
        let err = svc
            .store_baseline(
                Uuid::new_v4(),
                "empty".into(),
                BaselineFormat::TerraformJson,
                b"{}".to_vec(),
                BaselineDoc::empty(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DetectDriftError::EmptyBaseline));
    }

    #[tokio::test]
    async fn asset_filter_narrows_listing() {
        let svc = InMemoryCloudDriftService::new();
        let tenant = Uuid::new_v4();
        let id = svc
            .store_baseline(
                tenant,
                "main".into(),
                BaselineFormat::TerraformJson,
                b"{}".to_vec(),
                baseline_with_bucket("private"),
            )
            .await
            .unwrap();
        let _ = svc
            .detect_drift(tenant, id, vec![live_bucket("public-read")])
            .await
            .unwrap();
        let none = svc
            .list_drift(tenant, Some("does-not-match"))
            .await
            .unwrap();
        assert!(none.is_empty());
        let some = svc.list_drift(tenant, Some("evidence")).await.unwrap();
        assert_eq!(some.len(), 1);
    }
}
