//! [`RecordAuditEventUseCase`] — the public entry-point for appending an
//! audit event.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, instrument};

use sx_core::value_object::ids::TenantId;

use crate::chain::HashChain;
use crate::error::AuditError;
use crate::model::chain::GENESIS_PREV_HASH;
use crate::model::entry::AuditEntry;
use crate::service::chain_builder::{build_entry, NewAuditEvent};
use crate::service::sink::AuditSink;

/// Use-case that materialises a [`crate::service::chain_builder::NewAuditEvent`]
/// into a full [`AuditEntry`] and appends it to the [`AuditSink`].
///
/// Holds an in-process per-tenant async mutex around the read-then-append
/// critical section, so that two concurrent callers in the same process
/// will never race to assign the same `seq`. Cross-process safety is the
/// responsibility of the [`AuditSink`] implementation.
#[derive(Debug)]
pub struct RecordAuditEventUseCase {
    sink: Arc<dyn AuditSink>,
    /// Optional HMAC chain. When set, each appended entry is stamped
    /// with its `chain_hash` + `chain_prev_hash` before persistence.
    chain: Option<HashChain>,
    locks: Mutex<HashMap<TenantId, Arc<Mutex<()>>>>,
}

impl RecordAuditEventUseCase {
    /// Construct a new use-case bound to `sink`, **without** an HMAC
    /// chain anchor — only the SHA-256 chain is computed.
    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self {
            sink,
            chain: None,
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Construct a new use-case bound to `sink` AND an HMAC
    /// [`HashChain`]. Appended entries will be stamped with their HMAC
    /// `chain_hash` + `chain_prev_hash` before persistence.
    #[must_use]
    pub fn with_chain(sink: Arc<dyn AuditSink>, chain: HashChain) -> Self {
        Self {
            sink,
            chain: Some(chain),
            locks: Mutex::new(HashMap::new()),
        }
    }

    async fn lock_for(&self, tenant_id: TenantId) -> Arc<Mutex<()>> {
        let mut guard = self.locks.lock().await;
        guard
            .entry(tenant_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Append a single audit event. Returns the fully-formed entry that
    /// was written.
    #[instrument(skip(self, payload), fields(tenant = %payload.tenant_id))]
    pub async fn record(&self, payload: NewAuditEvent) -> Result<AuditEntry, AuditError> {
        let tenant_id = payload.tenant_id;
        let lock = self.lock_for(tenant_id).await;
        let _guard = lock.lock().await;

        let last = self.sink.last_entry_for_tenant(tenant_id).await?;
        let (seq, prev_hash, prev_chain_hash) =
            last.as_ref()
                .map_or((1u64, GENESIS_PREV_HASH, None), |prev| {
                    let chain_prev = if prev.chain_hash.is_empty() {
                        None
                    } else {
                        Some(prev.chain_hash.clone())
                    };
                    (prev.seq.saturating_add(1), prev.hash, chain_prev)
                });

        let mut entry = build_entry(seq, prev_hash, payload)?;
        if let Some(chain) = &self.chain {
            // Stamp the HMAC chain anchor. We deliberately leave the
            // SHA-256 hash already computed by `build_entry` in place.
            entry.chain_prev_hash = prev_chain_hash;
            entry.chain_hash = chain.step(entry.chain_prev_hash.as_deref(), &entry, seq)?;
        }
        self.sink.append(&entry).await?;
        debug!(
            seq = entry.seq,
            chain_hash_prefix = %entry
                .chain_hash
                .get(..16.min(entry.chain_hash.len()))
                .unwrap_or(""),
            "audit entry appended",
        );
        Ok(entry)
    }
}
