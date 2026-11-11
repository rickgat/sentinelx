//! Evidence-collector framework (TRD §28).
//!
//! This module is the backbone of automated compliance evidence
//! gathering inside `SentinelX`. It defines:
//!
//! * The [`EvidenceCollector`] trait — every concrete collector
//!   implements it.
//! * A [`CollectionContext`] passed into each collector so they can
//!   resolve their dependencies (database handles, audit log readers,
//!   feature flags, …) without taking a hard dependency on a global.
//! * A [`registry::CollectorRegistry`] that owns a vector of
//!   collectors and answers "who is due to fire now?".
//! * A small set of example collectors covering the three TRD §28.2
//!   archetypes: kill-switch attestation, audit-chain integrity,
//!   findings SLA compliance.
//!
//! The framework is intentionally storage-agnostic. A collector
//! returns an in-memory [`Evidence`] envelope; the monolith decides
//! where to land it (S3, local filesystem, …) at a layer above this
//! crate. That separation is what lets the same collectors run in CI
//! against mocked dependencies and in production against real ones.
//!
//! ## Reading order
//!
//! 1. [`types`] for the [`Evidence`] / [`EvidenceContentType`] shapes.
//! 2. [`schedule`] for the [`EvidenceSchedule`] cadence enum.
//! 3. [`registry::CollectorRegistry`] for dispatch semantics.
//! 4. [`sx_kill_switch_tested`], [`sx_audit_chain_integrity`],
//!    [`sx_findings_sla`] for end-to-end examples.

pub mod registry;
pub mod schedule;
pub mod sx_audit_chain_integrity;
pub mod sx_findings_sla;
pub mod sx_kill_switch_tested;
pub mod types;

use async_trait::async_trait;
use thiserror::Error;
use time::OffsetDateTime;

use crate::model::framework::Framework;

pub use registry::{CollectorRegistry, RegisteredCollector};
pub use schedule::{EvidenceSchedule, WeekdayCode};
pub use types::{sha256_of, Evidence, EvidenceContentType};

/// Error surface for an [`EvidenceCollector`].
///
/// Concrete collectors should map their internal failures into one of
/// these variants so the dispatcher and any retry layer above it can
/// uniformly distinguish "missing dependency" (transient configuration
/// problem) from "verification failed" (a real compliance finding).
#[derive(Debug, Error)]
pub enum CollectorError {
    /// A required runtime dependency was missing from the
    /// [`CollectionContext`] (typically a programmer error).
    #[error("missing dependency: {0}")]
    MissingDependency(&'static str),

    /// The collector executed but could not verify the underlying
    /// control posture (e.g. kill-switch was never tested, audit
    /// chain failed integrity check). This is a *real* compliance
    /// signal and must surface to the dashboard.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Encoding the evidence payload failed.
    #[error("payload encoding failed: {0}")]
    PayloadEncoding(String),

    /// Internal / programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Runtime context handed to every [`EvidenceCollector::collect`] call.
///
/// The context is intentionally lightweight — it carries the wall
/// clock and a collection-attempt identifier so collectors can stamp
/// their evidence deterministically without reaching for globals.
/// Concrete dependencies (database pools, audit-chain readers, …) are
/// injected at collector-construction time, not through this struct,
/// to keep the dispatcher type-erased.
#[derive(Debug, Clone)]
pub struct CollectionContext {
    /// Wall-clock time at which this collection cycle started.
    pub now: OffsetDateTime,
    /// Free-form identifier for this collection attempt; useful for
    /// joining evidence with the dispatcher's log line.
    pub attempt_id: String,
}

impl CollectionContext {
    /// Construct a new context.
    #[must_use]
    pub fn new(now: OffsetDateTime, attempt_id: impl Into<String>) -> Self {
        Self {
            now,
            attempt_id: attempt_id.into(),
        }
    }
}

/// Behaviour every concrete evidence collector must implement.
///
/// Collectors are stateless, `Send + Sync`, and cheap to call: the
/// dispatcher fans out across many of them per tick. Implementations
/// should keep `collect` short-running; anything heavier (e.g. PDF
/// rendering, S3 uploads) belongs in the layer *above* the collector.
#[async_trait]
pub trait EvidenceCollector: Send + Sync {
    /// Framework-local control identifier (e.g. `"SX-KILL-SWITCH-TESTED"`).
    fn control_id(&self) -> &'static str;

    /// Owning compliance framework — used by the registry to filter.
    fn framework(&self) -> Framework;

    /// Cadence at which this collector should fire.
    fn schedule(&self) -> EvidenceSchedule;

    /// Gather the evidence for this control.
    ///
    /// # Errors
    /// Returns [`CollectorError::VerificationFailed`] when the
    /// underlying compliance posture cannot be verified (this is the
    /// intended channel for surfacing real control failures), and
    /// [`CollectorError::MissingDependency`] / [`CollectorError::Internal`]
    /// for programmer errors.
    async fn collect(&self, ctx: &CollectionContext) -> Result<Evidence, CollectorError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use async_trait::async_trait;
    use time::macros::datetime;

    use super::*;

    /// A minimal collector used to assert the trait shape: object
    /// safety, `Send + Sync`, and async-trait wiring.
    struct NoopCollector;

    #[async_trait]
    impl EvidenceCollector for NoopCollector {
        fn control_id(&self) -> &'static str {
            "SX-NOOP"
        }
        fn framework(&self) -> Framework {
            Framework::Soc2
        }
        fn schedule(&self) -> EvidenceSchedule {
            EvidenceSchedule::Hourly
        }
        async fn collect(&self, ctx: &CollectionContext) -> Result<Evidence, CollectorError> {
            Ok(Evidence::new(
                "SX-NOOP",
                Framework::Soc2,
                ctx.now,
                EvidenceContentType::Json,
                b"{}".to_vec(),
                "0.0.0",
            ))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn collector_trait_is_object_safe_and_send_sync() {
        let c: Box<dyn EvidenceCollector> = Box::new(NoopCollector);
        let ctx = CollectionContext::new(datetime!(2026-06-12 00:00:00 UTC), "att-1");
        let ev = c.collect(&ctx).await.unwrap();
        assert_eq!(ev.control_id, "SX-NOOP");
        assert_eq!(ev.collector_version, "0.0.0");
        assert_eq!(ev.framework, Framework::Soc2);
    }

    #[test]
    fn collection_context_round_trip() {
        let ctx = CollectionContext::new(datetime!(2026-06-12 00:00:00 UTC), "att-9");
        assert_eq!(ctx.attempt_id, "att-9");
    }
}
