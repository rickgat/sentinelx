//! STIX 2.1 bundle renderer.
//!
//! Spec: <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>
//!
//! Each finding becomes one `vulnerability` SDO. The bundle id is a
//! deterministic `UUIDv5` derived from `(tenant_id, engagement_id)` so two
//! renderings of the same report produce the same bundle id.

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sx_core::value_object::ids::{EngagementId, TenantId};
use uuid::Uuid;

use crate::error::ReportError;
use crate::model::report::ReportContext;
use crate::model::report_finding::ReportFinding;
use crate::port::{Renderer, ReportArtifact, ReportFormat};

/// STIX 2.1 renderer.
#[derive(Debug, Default, Clone, Copy)]
pub struct StixRenderer;

impl StixRenderer {
    /// Construct a [`StixRenderer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Namespace bytes used to derive deterministic STIX object UUIDs.
///
/// We do not depend on the `uuid` crate's `v5` feature (not enabled at
/// the workspace level). Instead we synthesise a v5-shaped UUID by
/// hashing `(namespace || name)` with SHA-256 and clamping the version
/// and variant bits per RFC 4122 §4.3.
const STIX_NAMESPACE: [u8; 16] = [
    0xb8, 0x1a, 0x9f, 0x2c, 0x37, 0x4c, 0x4d, 0xc6, 0xa1, 0x4e, 0x90, 0x37, 0xee, 0x6a, 0x21, 0x77,
];

#[async_trait]
impl Renderer for StixRenderer {
    fn format(&self) -> ReportFormat {
        ReportFormat::Stix
    }

    async fn render(&self, ctx: &ReportContext) -> Result<ReportArtifact, ReportError> {
        let bundle_id = format!("bundle--{}", bundle_uuid(ctx.tenant_id, ctx.engagement_id));

        let mut objects: Vec<Value> = Vec::with_capacity(ctx.findings.len());
        for f in &ctx.findings {
            objects.push(vulnerability_sdo(f, &ctx.generated_at));
        }

        let bundle = json!({
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects,
        });

        let bytes =
            serde_json::to_vec_pretty(&bundle).map_err(|e| ReportError::json(e.to_string()))?;
        let filename = format!("findings-{}.stix.json", ctx.date_slug());
        ReportArtifact::new(ReportFormat::Stix, filename, bytes)
    }
}

fn bundle_uuid(tenant: TenantId, engagement: EngagementId) -> Uuid {
    let name = format!("{tenant}|{engagement}");
    derive_uuid(name.as_bytes())
}

/// Hash `(namespace || name)` with SHA-256, clamp the version (5) and
/// variant (RFC 4122) bits, return a [`Uuid`]. Equivalent in spirit to
/// `Uuid::new_v5` but without needing the `v5` cargo feature.
fn derive_uuid(name: &[u8]) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(STIX_NAMESPACE);
    hasher.update(name);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    if let Some(prefix) = digest.get(..16) {
        bytes.copy_from_slice(prefix);
    }
    // Set version to 5 (xxxxxxxx-xxxx-5xxx-xxxx-xxxxxxxxxxxx).
    if let Some(b6) = bytes.get_mut(6) {
        *b6 = (*b6 & 0x0F) | 0x50;
    }
    // Set variant to RFC 4122 (10xxxxxx).
    if let Some(b8) = bytes.get_mut(8) {
        *b8 = (*b8 & 0x3F) | 0x80;
    }
    Uuid::from_bytes(bytes)
}

fn vulnerability_sdo(f: &ReportFinding, generated_at: &time::OffsetDateTime) -> Value {
    let sdo_id = derive_uuid(f.id.to_string().as_bytes());
    let created = format_stix_timestamp(generated_at);

    let mut external_references = Vec::new();
    for r in &f.references {
        external_references.push(json!({
            "source_name": "sentinelx-reference",
            "url": r,
        }));
    }

    let mut obj = Map::new();
    obj.insert("type".to_owned(), Value::String("vulnerability".to_owned()));
    obj.insert("spec_version".to_owned(), Value::String("2.1".to_owned()));
    obj.insert(
        "id".to_owned(),
        Value::String(format!("vulnerability--{sdo_id}")),
    );
    obj.insert("created".to_owned(), Value::String(created.clone()));
    obj.insert("modified".to_owned(), Value::String(created));
    obj.insert("name".to_owned(), Value::String(f.title.clone()));
    if !f.description.is_empty() {
        obj.insert(
            "description".to_owned(),
            Value::String(f.description.clone()),
        );
    }
    if !external_references.is_empty() {
        obj.insert(
            "external_references".to_owned(),
            Value::Array(external_references),
        );
    }
    if let Some(cvss) = f.cvss_primary() {
        obj.insert("x_sentinelx_cvss".to_owned(), json!(format!("{cvss:.1}")));
    }
    obj.insert(
        "x_sentinelx_severity".to_owned(),
        Value::String(f.severity.to_string()),
    );
    obj.insert(
        "x_sentinelx_status".to_owned(),
        Value::String(f.status.clone()),
    );
    obj.insert(
        "x_sentinelx_asset".to_owned(),
        Value::String(f.asset_label.clone()),
    );
    Value::Object(obj)
}

fn format_stix_timestamp(dt: &time::OffsetDateTime) -> String {
    let utc = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::model::posture::PostureSummary;
    use sx_core::value_object::ids::FindingId;
    use sx_core::value_object::severity::Severity;
    use time::macros::datetime;
    use uuid::Uuid;

    fn finding() -> ReportFinding {
        ReportFinding::new(
            FindingId::from_uuid(Uuid::from_u128(0x1234)),
            "host.example.com",
            Severity::High,
            "Vulnerable component",
            "details",
            None,
            "discovered",
            vec!["https://example.com/cve".to_owned()],
        )
        .unwrap()
    }

    fn ctx_for(tenant: TenantId, engagement: EngagementId) -> ReportContext {
        ReportContext::new(
            tenant,
            engagement,
            "Acme",
            "Q2",
            "ops",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            vec![finding()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn stix_bundle_id_is_deterministic_from_tenant_engagement() {
        let tenant = TenantId::from_uuid(Uuid::from_u128(0xAA));
        let engagement = EngagementId::from_uuid(Uuid::from_u128(0xBB));
        let a = StixRenderer::new()
            .render(&ctx_for(tenant, engagement))
            .await
            .unwrap();
        let b = StixRenderer::new()
            .render(&ctx_for(tenant, engagement))
            .await
            .unwrap();
        let va: Value = serde_json::from_slice(&a.bytes).unwrap();
        let vb: Value = serde_json::from_slice(&b.bytes).unwrap();
        assert_eq!(va["id"], vb["id"], "bundle id must be stable");
        assert_eq!(va["type"], json!("bundle"));
        assert_eq!(va["spec_version"], json!("2.1"));

        // Different engagement id => different bundle id.
        let other = EngagementId::from_uuid(Uuid::from_u128(0xCC));
        let c = StixRenderer::new()
            .render(&ctx_for(tenant, other))
            .await
            .unwrap();
        let vc: Value = serde_json::from_slice(&c.bytes).unwrap();
        assert_ne!(va["id"], vc["id"]);
    }

    #[tokio::test]
    async fn stix_object_is_vulnerability_with_refs() {
        let tenant = TenantId::from_uuid(Uuid::from_u128(0xAA));
        let engagement = EngagementId::from_uuid(Uuid::from_u128(0xBB));
        let art = StixRenderer::new()
            .render(&ctx_for(tenant, engagement))
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&art.bytes).unwrap();
        let obj = &v["objects"][0];
        assert_eq!(obj["type"], json!("vulnerability"));
        assert!(obj["id"].as_str().unwrap().starts_with("vulnerability--"));
        assert_eq!(
            obj["external_references"][0]["url"],
            json!("https://example.com/cve")
        );
    }
}
