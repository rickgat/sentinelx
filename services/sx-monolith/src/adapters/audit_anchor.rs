//! External audit-chain anchoring adapter — backs the
//! `GET /v1/audit/anchors` and `POST /v1/audit/anchors/verify/{run_id}`
//! endpoints (P1-015).
//!
//! ## Topology
//!
//! The adapter owns:
//!
//! 1. An [`InMemoryAnchorRunRepository`] holding `audit_anchor_runs`
//!    rows (the Postgres-backed adapter lives in `sx-storage` and
//!    enforces the RLS policy from the migration).
//! 2. A per-tenant CA-cert map, queried by `verify_run`. The map is
//!    seeded from `sx-config` at boot; tenants without a configured
//!    pinned CA cause `verify` to surface a deterministic 422 (and the
//!    list endpoint still works — listing rows is independent of
//!    re-verification).
//! 3. The shared [`AnchorRunner`] used by both the periodic scheduler
//!    and the verify endpoint, so an HTTP re-verify exercises the
//!    same code path as the background pipeline (including the
//!    CRITICAL-event emission on failure).
//!
//! ## Cross-tenant policy
//!
//! Tenant id comes exclusively from the bearer token via the API
//! layer. Cross-tenant lookups surface as
//! [`Phase3PortError::Forbidden`]; missing rows surface as
//! [`Phase3PortError::NotFound`].
//!
//! ## Wire-shape contract (engineering bar)
//!
//! - Raw `payload_bytes` NEVER leaves the server. The list projection
//!   substitutes `payload_size_bytes`; the verify projection returns
//!   only the parsed `(serial, gen_time, merkle_root)` triple.
//! - The adapter MUST NOT log the bytes either. The TSA reply is
//!   loaded into [`AnchorRunner::verify_run`] and discarded after the
//!   call returns.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{AuditAnchorPort, Phase3PortError};
use sx_api::view::audit_anchor_view::{
    AuditAnchorListQuery, AuditAnchorListResponse, AuditAnchorRunView, AuditAnchorVerifyResponse,
};
use sx_audit::anchor_external::{FreeTsaClient, TsaAnchorClient};
use sx_audit::anchor_run::{
    AnchorRunError, AnchorRunId, AnchorRunRepository, AnchorRunner, AuditAnchorRun,
    DefaultTsaTokenVerifier, InMemoryAnchorRunRepository, NoopCriticalEventSink,
};
use sx_core::value_object::ids::TenantId;
use time::format_description::well_known::Rfc3339;

/// Bundle exposing the anchoring trait object the composition root
/// stuffs into [`sx_api::AppState`].
#[derive(Clone)]
pub(crate) struct AuditAnchorBundle {
    /// HTTP-facing port wired into the API surface.
    pub(crate) audit_anchor: Arc<dyn AuditAnchorPort>,
    /// Shared repository handle — kept so the periodic scheduler (when
    /// wired) can write into the same backing store the HTTP surface
    /// reads from.
    #[allow(dead_code)]
    pub(crate) repo: Arc<dyn AnchorRunRepository>,
}

impl std::fmt::Debug for AuditAnchorBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditAnchorBundle").finish_non_exhaustive()
    }
}

/// Build a fresh in-memory bundle.
///
/// Pure (no I/O); the per-tenant pinned CA map is initially empty and
/// can be hydrated later by the composition root from `sx-config`.
pub(crate) fn build() -> AuditAnchorBundle {
    let repo: Arc<dyn AnchorRunRepository> = Arc::new(InMemoryAnchorRunRepository::new());
    // The TSA client and verifier collaborators are only exercised by
    // `verify_run`, which loads the persisted `payload_bytes` from the
    // repo — the FreeTsa transport itself never fires during a
    // verify-only request. The placeholder URL is therefore inert; if a
    // future caller wires up the periodic scheduler, the composition
    // root will substitute a real one.
    let tsa_client: Arc<dyn TsaAnchorClient> = Arc::new(
        FreeTsaClient::new("https://freetsa.org/tsr")
            .expect("freetsa client placeholder construction is infallible"),
    );
    let runner = AnchorRunner::new(
        tsa_client,
        Arc::new(DefaultTsaTokenVerifier),
        Arc::clone(&repo),
        Arc::new(NoopCriticalEventSink),
    );
    let port: Arc<dyn AuditAnchorPort> = Arc::new(AuditAnchorAdapter {
        runner,
        repo: Arc::clone(&repo),
        // Empty pinned-CA map at boot; production deployments swap in
        // a real map sourced from `TenantAnchorConfig`.
        pinned_ca_by_tenant: Arc::new(HashMap::new()),
    });
    AuditAnchorBundle {
        audit_anchor: port,
        repo,
    }
}

/// Concrete [`AuditAnchorPort`] implementation.
#[derive(Clone)]
pub(crate) struct AuditAnchorAdapter {
    runner: AnchorRunner,
    repo: Arc<dyn AnchorRunRepository>,
    /// Per-tenant pinned CA cert PEM, by tenant id. Empty by default;
    /// a `verify` call for a tenant absent from the map surfaces a
    /// deterministic 422 from this adapter (not from the verifier),
    /// so operators see a clear "no CA configured" message rather
    /// than a misleading "bad signature".
    pinned_ca_by_tenant: Arc<HashMap<TenantId, String>>,
}

impl std::fmt::Debug for AuditAnchorAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditAnchorAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl AuditAnchorPort for AuditAnchorAdapter {
    async fn list(
        &self,
        tenant_id: &str,
        query: AuditAnchorListQuery,
    ) -> Result<AuditAnchorListResponse, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let limit = query.effective_limit() as usize;
        // Fetch one extra so we can signal `has_more` without a count
        // query (the in-memory repo is cheap; for Postgres we'd add a
        // LIMIT N+1 helper).
        let raw = self
            .repo
            .list_for_tenant(&tenant, limit + 1)
            .await
            .map_err(map_anchor_error)?;
        let has_more = raw.len() > limit;
        let items: Vec<AuditAnchorRunView> = raw
            .into_iter()
            .take(limit)
            .map(project_run)
            .collect::<Result<Vec<_>, Phase3PortError>>()?;
        Ok(AuditAnchorListResponse { items, has_more })
    }

    async fn verify(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<AuditAnchorVerifyResponse, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let id: AnchorRunId = run_id
            .parse()
            .map_err(|err| Phase3PortError::Invalid(format!("run_id: {err}")))?;
        let pinned_pem = self
            .pinned_ca_by_tenant
            .get(&tenant)
            .ok_or_else(|| {
                Phase3PortError::Invalid(
                    "tenant has no pinned CA cert configured for re-verification".to_owned(),
                )
            })?
            .clone();
        let verification = self
            .runner
            .verify_run(&tenant, &id, &pinned_pem)
            .await
            .map_err(map_anchor_error)?;
        let gen_time = verification
            .gen_time
            .format(&Rfc3339)
            .map_err(|e| Phase3PortError::Internal(format!("format gen_time: {e}")))?;
        Ok(AuditAnchorVerifyResponse {
            run_id: id.to_string(),
            tsa_serial: verification.serial,
            tsa_gen_time: gen_time,
            merkle_root: hex::encode(verification.merkle_root),
            verified: true,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Translate a parsed [`AuditAnchorRun`] into the wire view.
///
/// `payload_bytes` is deliberately replaced by `payload_size_bytes`;
/// the verbatim bytes never leave the server.
fn project_run(row: AuditAnchorRun) -> Result<AuditAnchorRunView, Phase3PortError> {
    let tsa_gen_time = row
        .tsa_gen_time
        .format(&Rfc3339)
        .map_err(|e| Phase3PortError::Internal(format!("format tsa_gen_time: {e}")))?;
    let anchored_at = row
        .anchored_at
        .format(&Rfc3339)
        .map_err(|e| Phase3PortError::Internal(format!("format anchored_at: {e}")))?;
    Ok(AuditAnchorRunView {
        run_id: row.run_id.to_string(),
        merkle_root: hex::encode(row.merkle_root),
        tsa_serial: row.tsa_serial,
        tsa_gen_time,
        anchored_at,
        payload_size_bytes: row.payload_bytes.len() as u64,
    })
}

/// Defence-in-depth tenant parse; same shape as the audit-replay
/// adapter so the auth layer can't smuggle a bad claim through.
fn parse_tenant(raw: &str) -> Result<TenantId, Phase3PortError> {
    raw.parse::<TenantId>()
        .map_err(|err| Phase3PortError::Forbidden(format!("invalid tenant claim: {err}")))
}

/// Map [`AnchorRunError`] onto the API-layer error enum.
fn map_anchor_error(err: AnchorRunError) -> Phase3PortError {
    match err {
        AnchorRunError::NotFound => Phase3PortError::NotFound,
        AnchorRunError::Forbidden => Phase3PortError::Forbidden("cross-tenant access".to_owned()),
        AnchorRunError::Invalid(m) => Phase3PortError::Invalid(m),
        AnchorRunError::EmptyWindow => Phase3PortError::Invalid("empty window".to_owned()),
        // Verification failures map to 422 not 500 — the inputs were
        // structurally valid but the cryptographic check failed.
        AnchorRunError::Verification(m) => Phase3PortError::Invalid(format!("verification: {m}")),
        AnchorRunError::Anchor(m) => Phase3PortError::Dependency(format!("anchor: {m}")),
        AnchorRunError::Repository(m) => Phase3PortError::Dependency(format!("repository: {m}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sx_audit::anchor_external::SHA256_LEN;
    use sx_audit::anchor_run::{AnchorRunId, AuditAnchorRun};
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn tenant(n: u128) -> TenantId {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&n.to_be_bytes());
        bytes[6] = (bytes[6] & 0x0F) | 0x70;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        Uuid::from_bytes(bytes).into()
    }

    fn make_row(t: TenantId, anchored_at_secs: i64) -> AuditAnchorRun {
        AuditAnchorRun {
            run_id: AnchorRunId::new(),
            tenant_id: t,
            merkle_root: [0xAB; SHA256_LEN],
            tsa_serial: "0x1".into(),
            tsa_gen_time: OffsetDateTime::from_unix_timestamp(anchored_at_secs - 1).unwrap(),
            anchored_at: OffsetDateTime::from_unix_timestamp(anchored_at_secs).unwrap(),
            payload_bytes: vec![1, 2, 3, 4],
            quorum: None,
        }
    }

    #[tokio::test]
    async fn list_returns_only_caller_tenant_rows() {
        let bundle = build();
        let t1 = tenant(1);
        let t2 = tenant(2);
        bundle
            .repo
            .insert(make_row(t1, 1_700_000_100))
            .await
            .unwrap();
        bundle
            .repo
            .insert(make_row(t1, 1_700_000_200))
            .await
            .unwrap();
        bundle
            .repo
            .insert(make_row(t2, 1_700_000_300))
            .await
            .unwrap();

        let resp = bundle
            .audit_anchor
            .list(&t1.to_string(), AuditAnchorListQuery::default())
            .await
            .unwrap();
        assert_eq!(resp.items.len(), 2);
        // Both rows belong to t1.
        for it in &resp.items {
            assert!(!it.merkle_root.is_empty());
        }
        // payload_bytes never appears.
        let s = serde_json::to_string(&resp).unwrap();
        assert!(!s.contains("payload_bytes"));
        assert!(s.contains("payload_size_bytes"));
    }

    #[tokio::test]
    async fn list_caps_at_effective_limit_and_signals_has_more() {
        let bundle = build();
        let t = tenant(3);
        for i in 0..4i64 {
            bundle
                .repo
                .insert(make_row(t, 1_700_000_400 + i))
                .await
                .unwrap();
        }
        let resp = bundle
            .audit_anchor
            .list(&t.to_string(), AuditAnchorListQuery { limit: Some(2) })
            .await
            .unwrap();
        assert_eq!(resp.items.len(), 2);
        assert!(resp.has_more);
    }

    #[tokio::test]
    async fn list_with_malformed_tenant_returns_forbidden() {
        let bundle = build();
        let err = bundle
            .audit_anchor
            .list("not-a-uuid", AuditAnchorListQuery::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Forbidden(_)));
    }

    #[tokio::test]
    async fn verify_without_pinned_ca_returns_invalid() {
        // The default bundle has an empty CA map; verify must refuse
        // with a clear "no CA configured" message rather than reach
        // through to the verifier.
        let bundle = build();
        let t = tenant(4);
        let row = make_row(t, 1_700_000_500);
        let id = row.run_id;
        bundle.repo.insert(row).await.unwrap();
        let err = bundle
            .audit_anchor
            .verify(&t.to_string(), &id.to_string())
            .await
            .unwrap_err();
        match err {
            Phase3PortError::Invalid(m) => assert!(m.contains("pinned CA")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_with_malformed_run_id_returns_invalid() {
        let bundle = build();
        let t = tenant(5);
        let err = bundle
            .audit_anchor
            .verify(&t.to_string(), "not-a-uuid")
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }
}
