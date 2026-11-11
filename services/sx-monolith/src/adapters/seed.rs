//! Deterministic demo seeder.
//!
//! Only invoked when `bootstrap.enabled == true && bootstrap.seed_demo_data == true`
//! AND the Postgres adapter is disabled. Skipped otherwise.
//!
//! Every identifier and string is hard-coded so that two boots of the same
//! binary produce byte-identical state. This is a developer convenience —
//! production deployments must keep `seed_demo_data = false`.

use std::str::FromStr;
use std::sync::Arc;

use sx_api::port::TenantSummaryView;
use sx_api::view::asset_view::AssetView;
use sx_api::view::finding_view::FindingView;
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_engagement::model::engagement::{Engagement, EngagementStatus};
use sx_engagement::model::intensity::ScanIntensity;
use sx_engagement::model::scope_target::ScopeTarget;
use sx_engagement::model::window::TimeWindow;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::adapters::engagement::InMemoryEngagementRepository;
use crate::adapters::repository::{InMemoryAssets, InMemoryFindings, InMemoryTenants};

const ENGAGEMENT_A: &str = "e0000001-0000-0000-0000-000000000000";
const ENGAGEMENT_B: &str = "e0000002-0000-0000-0000-000000000000";
const ENGAGEMENT_C: &str = "e0000003-0000-0000-0000-000000000000";

const ASSET_1: &str = "a0000001-0000-0000-0000-000000000000";
const ASSET_2: &str = "a0000002-0000-0000-0000-000000000000";
const ASSET_3: &str = "a0000003-0000-0000-0000-000000000000";
const ASSET_4: &str = "a0000004-0000-0000-0000-000000000000";
const ASSET_5: &str = "a0000005-0000-0000-0000-000000000000";

const FINDING_1: &str = "f0000001-0000-0000-0000-000000000000";
const FINDING_2: &str = "f0000002-0000-0000-0000-000000000000";
const FINDING_3: &str = "f0000003-0000-0000-0000-000000000000";
const FINDING_4: &str = "f0000004-0000-0000-0000-000000000000";
const FINDING_5: &str = "f0000005-0000-0000-0000-000000000000";
const FINDING_6: &str = "f0000006-0000-0000-0000-000000000000";
const FINDING_7: &str = "f0000007-0000-0000-0000-000000000000";
const FINDING_8: &str = "f0000008-0000-0000-0000-000000000000";

/// Run the demo seed. Pushes 1 tenant, 3 engagements, 5 assets, 8 findings.
///
/// Returns the total number of records inserted (`1 + 3 + 5 + 8 = 17` on
/// the happy path; `1` if the tenant id was not a valid UUID and the
/// engagement/asset/finding inserts were short-circuited — the tenant
/// summary view is still landed by string key). The caller uses this
/// count to log a single "applied N records" line at startup so
/// operators can distinguish a successful demo seed from a no-op.
pub(crate) fn run(
    tenant_id: &str,
    tenant_name: &str,
    tenants: Arc<InMemoryTenants>,
    engagements: Arc<InMemoryEngagementRepository>,
    assets: Arc<InMemoryAssets>,
    findings: Arc<InMemoryFindings>,
) -> usize {
    let now = OffsetDateTime::now_utc();

    // --- Tenant ---------------------------------------------------------
    tenants.seed_one(TenantSummaryView {
        id: tenant_id.to_owned(),
        name: tenant_name.to_owned(),
        slug: "default".to_owned(),
        is_active: true,
    });
    let mut inserted: usize = 1;

    // --- Engagements ----------------------------------------------------
    let Some(tenant_uuid) = parse_tenant(tenant_id) else {
        // Tenant id wasn't a valid uuid — log and bail. We still leave the
        // tenant summary view above in place (it's a string-keyed lookup).
        tracing::warn!(
            target: "adapters.seed.skip",
            reason = "tenant id is not a valid uuid",
            "skipping demo data seed"
        );
        return inserted;
    };

    let window_start = now.saturating_sub(Duration::days(30));
    let window_end = now.saturating_add(Duration::days(60));
    let created_at = now.saturating_sub(Duration::days(30));
    let updated_at = now.saturating_sub(Duration::days(1));

    let scopes_a = vec![
        cidr_scope("10.0.0.0/24"),
        ScopeTarget::Domain("api.acme-bank.example".to_owned()),
    ];
    let scopes_b = vec![cidr_scope("10.42.0.0/16")];
    let scopes_c = vec![
        ScopeTarget::Arn("aws://123456789012".to_owned()),
        ScopeTarget::Arn("gcp://example-project".to_owned()),
    ];

    if let Some(e) = build_engagement(
        ENGAGEMENT_A,
        tenant_uuid,
        "Q3 External Pentest",
        EngagementStatus::Active,
        scopes_a,
        window_start,
        window_end,
        created_at,
        updated_at,
    ) {
        engagements.seed_one(e);
        inserted += 1;
    }
    if let Some(e) = build_engagement(
        ENGAGEMENT_B,
        tenant_uuid,
        "Internal Compliance Review",
        EngagementStatus::Draft,
        scopes_b,
        window_start,
        window_end,
        created_at,
        updated_at,
    ) {
        engagements.seed_one(e);
        inserted += 1;
    }
    if let Some(e) = build_engagement(
        ENGAGEMENT_C,
        tenant_uuid,
        "Cloud Posture Audit",
        EngagementStatus::Completed,
        scopes_c,
        window_start,
        window_end,
        created_at,
        updated_at,
    ) {
        engagements.seed_one(e);
        inserted += 1;
    }

    // --- Assets ---------------------------------------------------------
    let first_seen = rfc3339(now.saturating_sub(Duration::days(14)));
    let last_seen = rfc3339(now.saturating_sub(Duration::days(1)));

    for view in [
        asset_view(
            ASSET_1,
            tenant_id,
            ENGAGEMENT_A,
            "host",
            "api.acme-bank.example",
            "manual",
            &first_seen,
            &last_seen,
        ),
        asset_view(
            ASSET_2,
            tenant_id,
            ENGAGEMENT_A,
            "host",
            "cdn.acme-bank.example",
            "scan",
            &first_seen,
            &last_seen,
        ),
        asset_view(
            ASSET_3,
            tenant_id,
            ENGAGEMENT_A,
            "bucket",
            "arn:aws:s3:::acme-bank-public",
            "scan",
            &first_seen,
            &last_seen,
        ),
        asset_view(
            ASSET_4,
            tenant_id,
            ENGAGEMENT_A,
            "container",
            "oci://acme/api:1.42",
            "scan",
            &first_seen,
            &last_seen,
        ),
        asset_view(
            ASSET_5,
            tenant_id,
            ENGAGEMENT_A,
            "identity",
            "arn:aws:iam::123456789012:role/ApiServer",
            "scan",
            &first_seen,
            &last_seen,
        ),
    ] {
        assets.seed_one(view);
        inserted += 1;
    }

    // --- Findings -------------------------------------------------------
    for view in [
        finding_view(
            FINDING_1,
            tenant_id,
            ASSET_1,
            "critical",
            "open",
            "Unauthenticated RCE via vulnerable image library",
            "An outdated image-processing library allows unauthenticated remote code execution on the edge API.",
            Some(9.8),
            Some("CVE-2024-12345"),
            &first_seen,
            &last_seen,
            // Critical RCE on the customer-facing API → high business
            // impact, but no known multi-step chain yet.
            Some(serde_json::json!({"business_impact": 3.5})),
        ),
        finding_view(
            FINDING_2,
            tenant_id,
            ASSET_1,
            "high",
            "triaged",
            "TLS 1.0 supported on edge",
            "Edge load balancer still negotiates TLS 1.0; downgrade attacks are possible against legacy clients.",
            Some(7.4),
            Some("CVE-2023-45678"),
            &first_seen,
            &last_seen,
            None,
        ),
        finding_view(
            FINDING_3,
            tenant_id,
            ASSET_2,
            "high",
            "open",
            "Mixed-content references on edge CDN",
            "The CDN serves HTTPS pages that pull script tags over plain HTTP, enabling MITM script injection.",
            Some(7.2),
            None,
            &first_seen,
            &last_seen,
            None,
        ),
        finding_view(
            FINDING_4,
            tenant_id,
            ASSET_3,
            "critical",
            "open",
            "Public S3 bucket containing customer PII",
            "S3 bucket policy allows anonymous list+get; objects include name/email/phone records.",
            Some(9.1),
            None,
            &first_seen,
            &last_seen,
            // Public PII bucket → very high business impact and the
            // breach can be amplified by the over-privileged IAM role
            // (see FINDING_7) once chained.
            Some(serde_json::json!({"business_impact": 4.2, "chain_amplifier": 2.0})),
        ),
        finding_view(
            FINDING_5,
            tenant_id,
            ASSET_4,
            "medium",
            "open",
            "Container running as root",
            "The API container's runtime user is uid 0; combined with a host-mount this would allow escape.",
            Some(5.6),
            Some("CVE-2024-99999"),
            &first_seen,
            &last_seen,
            None,
        ),
        finding_view(
            FINDING_6,
            tenant_id,
            ASSET_4,
            "low",
            "closed",
            "Missing CIS Docker Bench compliance",
            "Image fails several CIS Docker Bench L1 checks; remediated by base-image bump in build 1.43.",
            Some(3.1),
            None,
            &first_seen,
            &last_seen,
            None,
        ),
        finding_view(
            FINDING_7,
            tenant_id,
            ASSET_5,
            "high",
            "triaged",
            "Over-privileged IAM role attached to API server",
            "ApiServer role carries `*:*` on production data buckets; should be scoped to the api-data prefix.",
            Some(7.8),
            None,
            &first_seen,
            &last_seen,
            // Lateral-movement primitive — the chain amplifier captures
            // that this finding is a force-multiplier for any RCE that
            // lands on the API server.
            Some(serde_json::json!({"chain_amplifier": 2.5})),
        ),
        finding_view(
            FINDING_8,
            tenant_id,
            ASSET_1,
            "info",
            "accepted",
            "Server header discloses framework version",
            "Server response header leaks the framework version; informational, accepted by app owner.",
            Some(2.1),
            None,
            &first_seen,
            &last_seen,
            None,
        ),
    ] {
        findings.seed_one(view);
        inserted += 1;
    }

    tracing::info!(
        target: "adapters.seed.complete",
        tenants = 1,
        engagements = 3,
        assets = 5,
        findings = 8,
        total = inserted,
        "demo data seeded"
    );
    inserted
}

fn parse_tenant(s: &str) -> Option<TenantId> {
    uuid::Uuid::from_str(s).ok().map(TenantId::from_uuid)
}

fn parse_engagement(s: &str) -> Option<EngagementId> {
    uuid::Uuid::from_str(s).ok().map(EngagementId::from_uuid)
}

fn cidr_scope(s: &str) -> ScopeTarget {
    // All seed CIDRs are well-formed literals; on a parse failure we
    // degrade to a domain-shaped scope so the engagement still has a
    // non-empty scope vector.
    s.parse::<ipnet::IpNet>()
        .map_or_else(|_| ScopeTarget::Domain(s.to_owned()), ScopeTarget::Cidr)
}

#[allow(clippy::too_many_arguments)] // builder fan-in; arguments are positional fields of a fixed-shape struct.
fn build_engagement(
    id: &str,
    tenant: TenantId,
    name: &str,
    status: EngagementStatus,
    scope: Vec<ScopeTarget>,
    window_start: OffsetDateTime,
    window_end: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
) -> Option<Engagement> {
    let eid = parse_engagement(id)?;
    let window = TimeWindow::new(window_start, window_end).ok()?;
    let draft = Engagement::new_draft(
        eid,
        tenant,
        name,
        scope,
        window,
        ScanIntensity::SafeInteractive,
        created_at,
    )
    .ok()?;
    Some(Engagement {
        status,
        updated_at,
        ..draft
    })
}

#[allow(clippy::too_many_arguments)] // structural builder; arguments mirror AssetView fields.
fn asset_view(
    id: &str,
    tenant_id: &str,
    engagement_id: &str,
    kind: &str,
    identifier: &str,
    source: &str,
    first_seen: &str,
    last_seen: &str,
) -> AssetView {
    AssetView {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        engagement_id: engagement_id.to_owned(),
        kind: kind.to_owned(),
        identifier: identifier.to_owned(),
        source: source.to_owned(),
        first_seen: first_seen.to_owned(),
        last_seen: last_seen.to_owned(),
        // Seed fixtures represent demo production assets.
        criticality: Some("production".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)] // structural builder; arguments mirror FindingView fields.
fn finding_view(
    id: &str,
    tenant_id: &str,
    asset_id: &str,
    severity: &str,
    status: &str,
    title: &str,
    description: &str,
    cvss: Option<f64>,
    cve_id: Option<&str>,
    first_seen: &str,
    last_seen: &str,
    metadata: Option<serde_json::Value>,
) -> FindingView {
    FindingView {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        asset_id: asset_id.to_owned(),
        severity: severity.to_owned(),
        status: status.to_owned(),
        title: title.to_owned(),
        description: description.to_owned(),
        cvss,
        cve_id: cve_id.map(str::to_owned),
        first_seen: first_seen.to_owned(),
        last_seen: last_seen.to_owned(),
        metadata,
    }
}

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_api::port::{AssetRepositoryPort, FindingRepositoryPort, TenantRepositoryPort};

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";

    #[tokio::test]
    async fn seed_run_inserts_expected_counts() {
        let tenants = Arc::new(InMemoryTenants::default());
        let engagements = Arc::new(InMemoryEngagementRepository::default());
        let assets = Arc::new(InMemoryAssets::default());
        let findings = Arc::new(InMemoryFindings::default());

        let total = run(
            TENANT,
            "Default Tenant",
            Arc::clone(&tenants),
            Arc::clone(&engagements),
            Arc::clone(&assets),
            Arc::clone(&findings),
        );
        assert_eq!(total, 1 + 3 + 5 + 8, "expected 17 seeded records total");

        // Tenant lookup
        let tenant_view = tenants.get(TENANT).await.unwrap();
        assert_eq!(tenant_view.name, "Default Tenant");

        // Engagements
        let tenant_uuid = parse_tenant(TENANT).unwrap();
        let engagement_rows = engagements.list(tenant_uuid, 0, 100);
        assert_eq!(engagement_rows.len(), 3);

        // Assets
        let asset_rows = assets.list(TENANT, 0, 100).await.unwrap();
        assert_eq!(asset_rows.len(), 5);

        // Findings
        let finding_rows = findings.list(TENANT, 0, 100).await.unwrap();
        assert_eq!(finding_rows.len(), 8);
    }
}
