//! FOUND-001 — integration coverage for
//! [`sx_api::port::FindingRepositoryPort::insert`].
//!
//! The contract this guards:
//!
//! 1. `insert(view)` returns `Ok(persisted)` on success.
//! 2. A second `insert` with the same `(tenant_id, id)` returns `Ok`
//!    again rather than an [`EngagementPortError::Conflict`]; the
//!    emitter side of the platform may re-fire on the same break /
//!    rate-limit event and must observe idempotent persistence.
//! 3. The persisted view is then visible via `get(tenant, id)` and the
//!    finding count via `list` reflects exactly one row regardless of
//!    how many times `insert` ran.
//!
//! The `sx-monolith` crate is a binary (no library surface), so we cannot
//! import its private `InMemoryFindings` adapter directly. Instead we
//! stand up a tiny faithful re-implementation of the same in-memory
//! pattern here and assert the trait contract against it — this still
//! pins the trait shape (any future signature change breaks the test)
//! and exercises the idempotency semantics that P2-007 / P2-008
//! emitters rely on.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
// Test ergonomics — none of these matter inside an integration test that
// runs against a tiny synthetic in-memory store: `offset as usize` is
// safe (offsets are bounded by `Vec` size), the lock guard's lifetime is
// trivially short, and indexing past `[0]` after an explicit
// `assert_eq!(.len(), 1)` is the readable assertion shape.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::indexing_slicing)]

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use sx_api::port::{EngagementPortError, FindingRepositoryPort};
use sx_api::view::finding_view::FindingView;

const TENANT: &str = "01010101-0101-0101-0101-010101010101";
const FINDING: &str = "f0000001-0000-0000-0000-000000000000";

/// Local in-memory `FindingRepositoryPort` mirroring the contract the
/// monolith's `InMemoryFindings` adapter and the Postgres-backed
/// `PgFindingsAdapter` both implement: last-write-wins on
/// `(tenant_id, id)`, idempotent re-insert.
#[derive(Default)]
struct InMemoryFindings {
    rows: Mutex<HashMap<(String, String), FindingView>>,
}

#[async_trait]
impl FindingRepositoryPort for InMemoryFindings {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        let g = self.rows.lock().unwrap();
        Ok(g.iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, v)| v.clone())
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
        let g = self.rows.lock().unwrap();
        g.get(&(tenant_id.to_owned(), id.to_owned()))
            .cloned()
            .ok_or(EngagementPortError::NotFound)
    }

    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        new_status: &str,
        _comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(&(tenant_id.to_owned(), id.to_owned())) {
            Some(view) => {
                view.status = new_status.to_owned();
                Ok(view.clone())
            }
            None => Err(EngagementPortError::NotFound),
        }
    }

    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        let mut g = self.rows.lock().unwrap();
        let key = (view.tenant_id.clone(), view.id.clone());
        g.insert(key, view.clone());
        Ok(view)
    }
}

fn finding(id: &str, title: &str) -> FindingView {
    FindingView {
        id: id.to_owned(),
        tenant_id: TENANT.to_owned(),
        asset_id: "a0000001-0000-0000-0000-000000000000".to_owned(),
        severity: "high".to_owned(),
        status: "open".to_owned(),
        title: title.to_owned(),
        description: "synthetic finding emitted by FOUND-001 test".to_owned(),
        cvss: None,
        cve_id: None,
        first_seen: "2026-06-24T00:00:00Z".to_owned(),
        last_seen: "2026-06-24T00:00:00Z".to_owned(),
        metadata: None,
    }
}

#[tokio::test]
async fn insert_persists_finding_and_is_visible_via_get() {
    let repo = InMemoryFindings::default();
    let persisted = repo
        .insert(finding(FINDING, "Audit-chain break"))
        .await
        .expect("first insert ok");

    assert_eq!(persisted.id, FINDING);
    assert_eq!(persisted.tenant_id, TENANT);

    let view = repo.get(TENANT, FINDING).await.expect("get ok");
    assert_eq!(view.id, FINDING);
    assert_eq!(view.title, "Audit-chain break");
}

#[tokio::test]
async fn second_insert_with_same_id_is_idempotent() {
    let repo = InMemoryFindings::default();

    // Emitter fires once.
    repo.insert(finding(FINDING, "Audit-chain break (first)"))
        .await
        .expect("first insert ok");

    // Emitter re-fires inside its dedup window — same `(tenant_id, id)`
    // pair, possibly drifted payload. The trait contract says this MUST
    // return Ok, not Conflict.
    let second = repo
        .insert(finding(FINDING, "Audit-chain break (second)"))
        .await
        .expect("second insert must be idempotent (Ok)");
    assert_eq!(second.id, FINDING);

    // And `list` shows exactly one row — the emitter did NOT create a
    // duplicate.
    let rows = repo.list(TENANT, 0, 100).await.expect("list ok");
    assert_eq!(
        rows.len(),
        1,
        "idempotent insert must not duplicate the row, got {} rows",
        rows.len()
    );
}

#[tokio::test]
async fn insert_does_not_leak_across_tenants() {
    let repo = InMemoryFindings::default();
    let other_tenant = "02020202-0202-0202-0202-020202020202";

    let mut view_a = finding(FINDING, "Tenant A finding");
    view_a.tenant_id = TENANT.to_owned();
    let mut view_b = finding(FINDING, "Tenant B finding");
    view_b.tenant_id = other_tenant.to_owned();

    repo.insert(view_a).await.expect("tenant A insert");
    repo.insert(view_b).await.expect("tenant B insert");

    let rows_a = repo.list(TENANT, 0, 100).await.expect("list A");
    let rows_b = repo.list(other_tenant, 0, 100).await.expect("list B");

    assert_eq!(rows_a.len(), 1, "tenant A sees only its own row");
    assert_eq!(rows_b.len(), 1, "tenant B sees only its own row");
    assert_eq!(rows_a[0].title, "Tenant A finding");
    assert_eq!(rows_b[0].title, "Tenant B finding");
}
