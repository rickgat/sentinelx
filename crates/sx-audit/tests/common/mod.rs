//! Test helpers shared by all integration tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::significant_drop_tightening,
    clippy::items_after_statements,
    dead_code,
    unreachable_pub
)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use sx_audit::prelude::{Actor, AuditAction, AuditEntry, AuditError, AuditSink, NewAuditEvent};
use sx_core::value_object::ids::{TenantId, UserId};

/// Build a sample [`NewAuditEvent`] with a fixed timestamp for determinism.
pub fn sample_event(tenant: TenantId, action: AuditAction, seq_hint: u64) -> NewAuditEvent {
    let user = UserId::new();
    NewAuditEvent {
        tenant_id: tenant,
        actor: Actor::user(user)
            .with_ip("10.0.0.1")
            .with_user_agent("test/1.0"),
        action,
        resource_kind: "engagement".into(),
        resource_id: format!("res-{seq_hint}"),
        before: None,
        after: Some(serde_json::json!({"k": seq_hint})),
        request_id: format!("req-{seq_hint}"),
        ts: Some(OffsetDateTime::from_unix_timestamp(1_700_000_000_i64 + seq_hint as i64).unwrap()),
    }
}

/// Thread-safe in-memory [`AuditSink`] for integration tests.
#[derive(Debug, Default, Clone)]
pub struct InMemorySink {
    inner: Arc<Mutex<HashMap<TenantId, Vec<AuditEntry>>>>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self, tenant_id: TenantId) -> Vec<AuditEntry> {
        let g = self.inner.lock().await;
        g.get(&tenant_id).cloned().unwrap_or_default()
    }

    pub async fn tamper<F: FnOnce(&mut Vec<AuditEntry>)>(&self, tenant_id: TenantId, f: F) {
        let mut g = self.inner.lock().await;
        let v = g.entry(tenant_id).or_default();
        f(v);
    }
}

#[async_trait]
impl AuditSink for InMemorySink {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let mut g = self.inner.lock().await;
        let v = g.entry(entry.tenant_id).or_default();
        let expected_seq = v.last().map_or(1u64, |last| last.seq.saturating_add(1));
        if entry.seq != expected_seq {
            return Err(AuditError::Sink(format!(
                "out-of-order seq: expected {expected_seq}, got {}",
                entry.seq
            )));
        }
        v.push(entry.clone());
        Ok(())
    }

    async fn last_entry_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<AuditEntry>, AuditError> {
        let g = self.inner.lock().await;
        Ok(g.get(&tenant_id).and_then(|v| v.last().cloned()))
    }

    async fn read_range(
        &self,
        tenant_id: TenantId,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let g = self.inner.lock().await;
        let out = g
            .get(&tenant_id)
            .map(|v| {
                v.iter()
                    .filter(|e| e.seq >= from_seq && e.seq <= to_seq)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok(out)
    }
}
