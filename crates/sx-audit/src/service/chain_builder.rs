//! Build a new [`AuditEntry`] given its predecessor hash and a fresh payload.

use time::OffsetDateTime;

use sx_core::value_object::ids::TenantId;

use crate::error::AuditError;
use crate::model::action::AuditAction;
use crate::model::actor::Actor;
use crate::model::chain::GENESIS_PREV_HASH;
use crate::model::entry::{AuditEntry, Hash};
use crate::service::hasher::compute_hash;

/// Caller-supplied payload for a new audit entry.
///
/// The crate fills in `seq`, `prev_hash`, `hash`, and (optionally) `ts`.
#[derive(Debug, Clone)]
pub struct NewAuditEvent {
    /// Tenant the event belongs to.
    pub tenant_id: TenantId,
    /// Principal that performed the action.
    pub actor: Actor,
    /// The action being recorded.
    pub action: AuditAction,
    /// Resource kind (e.g. `"engagement"`).
    pub resource_kind: String,
    /// Resource id (e.g. a UUID string).
    pub resource_id: String,
    /// Optional pre-image snapshot.
    pub before: Option<serde_json::Value>,
    /// Optional post-image snapshot.
    pub after: Option<serde_json::Value>,
    /// Originating request correlation id.
    pub request_id: String,
    /// Optional explicit timestamp; if `None`, [`OffsetDateTime::now_utc`]
    /// is used at build time.
    pub ts: Option<OffsetDateTime>,
}

/// Build a fresh, signed [`AuditEntry`] given the predecessor hash and
/// the next sequence number.
///
/// Pass [`GENESIS_PREV_HASH`] and `seq = 1` to construct the genesis
/// entry of a tenant's chain.
pub fn build_entry(
    seq: u64,
    prev_hash: Hash,
    payload: NewAuditEvent,
) -> Result<AuditEntry, AuditError> {
    let ts = payload.ts.unwrap_or_else(OffsetDateTime::now_utc);

    let mut entry = AuditEntry {
        seq,
        tenant_id: payload.tenant_id,
        ts,
        actor: payload.actor,
        action: payload.action,
        resource_kind: payload.resource_kind,
        resource_id: payload.resource_id,
        before: payload.before,
        after: payload.after,
        request_id: payload.request_id,
        prev_hash,
        hash: [0u8; 32],
        // HMAC chain fields are stamped by the sink (or left empty
        // when the sink is unaware of an HMAC chain).
        chain_hash: String::new(),
        chain_prev_hash: None,
    };

    let canonical = entry.to_canonical_bytes()?;
    entry.hash = compute_hash(&prev_hash, &canonical);
    Ok(entry)
}

/// Convenience: build a genesis entry (`seq = 1`, `prev_hash = [0u8; 32]`).
pub fn build_genesis(payload: NewAuditEvent) -> Result<AuditEntry, AuditError> {
    build_entry(1, GENESIS_PREV_HASH, payload)
}
