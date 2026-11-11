//! Curated re-exports for downstream callers.

pub use crate::chain::{ChainError, HashChain, CHAIN_HASH_HEX_LEN};
pub use crate::controller::record_event::RecordAuditEventUseCase;
pub use crate::controller::verify_chain::{verify_entries, VerifyChainUseCase};
pub use crate::error::AuditError;
pub use crate::model::action::AuditAction;
pub use crate::model::actor::{Actor, ActorKind};
pub use crate::model::chain::{verify_linkage, VerificationReport, GENESIS_PREV_HASH};
pub use crate::model::entry::{AuditEntry, Hash, HASH_LEN};
pub use crate::service::chain_builder::{build_entry, build_genesis, NewAuditEvent};
pub use crate::service::hasher::compute_hash;
pub use crate::service::sink::AuditSink;
pub use crate::time_travel::{
    AggregateId, AggregateKind, InMemoryTimeTravelService, ReplayTimeline, StateDiff,
    TimeTravelService, TimelineEvent,
};
