//! [`CollectorRegistry`] — the dispatcher for the evidence-collector
//! framework.
//!
//! The registry owns a vector of `Box<dyn EvidenceCollector>` and a
//! parallel `last_fired_at` clock per collector. On each tick the
//! orchestrator calls [`CollectorRegistry::dispatch`] with `now` and
//! gets back the subset of collectors whose [`EvidenceSchedule`]
//! fires at or before that timestamp.
//!
//! The registry is deliberately small — actual evidence persistence
//! (S3 sinks, signed manifests) lives in the layer *above* this
//! crate; the registry's only job is "who runs now?".

use std::collections::HashMap;

use time::OffsetDateTime;

use crate::collector::EvidenceCollector;

/// A collector registered with the [`CollectorRegistry`] alongside the
/// dispatcher-internal state required to schedule it.
///
/// Exposed publicly so callers walking the registry (e.g. for an
/// admin "list collectors" view) can see the per-collector schedule
/// without invoking the collector.
pub struct RegisteredCollector {
    /// The wrapped collector implementation.
    pub collector: Box<dyn EvidenceCollector>,
    /// The instant at which this collector last produced evidence, if any.
    pub last_fired_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for RegisteredCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredCollector")
            .field("control_id", &self.collector.control_id())
            .field("framework", &self.collector.framework())
            .field("schedule", &self.collector.schedule())
            .field("last_fired_at", &self.last_fired_at)
            .finish()
    }
}

/// Dispatcher that owns a vector of [`EvidenceCollector`] instances
/// and dispatches the subset that is due to fire on each tick.
#[derive(Debug, Default)]
pub struct CollectorRegistry {
    entries: Vec<RegisteredCollector>,
}

impl CollectorRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a new collector.
    ///
    /// The registry does *not* deduplicate by `control_id` — operators
    /// may legitimately register multiple collectors targeting the
    /// same control id (e.g. a fast/cheap variant and a slow/expensive
    /// variant). Callers that need uniqueness can enforce it at
    /// construction.
    pub fn register(&mut self, collector: Box<dyn EvidenceCollector>) {
        self.entries.push(RegisteredCollector {
            collector,
            last_fired_at: None,
        });
    }

    /// Number of registered collectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow the registered collectors for read-only inspection.
    #[must_use]
    pub fn entries(&self) -> &[RegisteredCollector] {
        &self.entries
    }

    /// Return the subset of collectors whose schedules fire at or
    /// before `due_now`.
    ///
    /// The returned vector is the *moved-out* collectors: callers that
    /// want to keep them in the registry must re-register them
    /// afterwards, typically via [`Self::register_many`]. This shape
    /// matches the dispatch contract in the task spec
    /// (`dispatch(...) -> Vec<Box<dyn EvidenceCollector>>`) and keeps
    /// the dispatcher honest about ownership semantics.
    ///
    /// In a long-running orchestrator the more ergonomic
    /// [`Self::due_indices`] / [`Self::mark_fired`] pair should be
    /// preferred (it keeps the registry intact and only updates the
    /// per-collector clock).
    pub fn dispatch(&mut self, due_now: OffsetDateTime) -> Vec<Box<dyn EvidenceCollector>> {
        let due = self.due_indices(due_now);
        // Walk in reverse so swap_remove indices stay valid.
        let mut taken: Vec<Box<dyn EvidenceCollector>> = Vec::with_capacity(due.len());
        for idx in due.into_iter().rev() {
            let entry = self.entries.swap_remove(idx);
            taken.push(entry.collector);
        }
        // Restore input order so callers see deterministic dispatch.
        taken.reverse();
        taken
    }

    /// Re-register many collectors at once (companion to
    /// [`Self::dispatch`]).
    pub fn register_many(&mut self, collectors: Vec<Box<dyn EvidenceCollector>>) {
        for c in collectors {
            self.register(c);
        }
    }

    /// Indices of registered entries whose schedule fires at/before `now`.
    ///
    /// Exposed so an orchestrator can drive the registry without
    /// taking ownership of the underlying collectors.
    #[must_use]
    pub fn due_indices(&self, now: OffsetDateTime) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| {
                if entry.collector.schedule().is_due(entry.last_fired_at, now) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Mark a registered entry as having fired at `at`. Indices outside
    /// the current registry length are silently ignored.
    pub fn mark_fired(&mut self, index: usize, at: OffsetDateTime) {
        if let Some(entry) = self.entries.get_mut(index) {
            entry.last_fired_at = Some(at);
        }
    }

    /// Mark every entry with the given `control_id` as having fired at
    /// `at`. Convenience helper for orchestrators that consumed
    /// collectors via [`Self::dispatch`] and reinserted them after
    /// running.
    pub fn mark_fired_by_control_id(&mut self, control_id: &str, at: OffsetDateTime) {
        for entry in &mut self.entries {
            if entry.collector.control_id() == control_id {
                entry.last_fired_at = Some(at);
            }
        }
    }

    /// Snapshot of last-fired-at clocks keyed by control id.
    ///
    /// Useful for tests and admin dashboards.
    #[must_use]
    pub fn clocks(&self) -> HashMap<&'static str, Option<OffsetDateTime>> {
        self.entries
            .iter()
            .map(|e| (e.collector.control_id(), e.last_fired_at))
            .collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use async_trait::async_trait;
    use time::macros::datetime;

    use super::*;
    use crate::collector::schedule::{EvidenceSchedule, WeekdayCode};
    use crate::collector::types::{Evidence, EvidenceContentType};
    use crate::collector::{CollectionContext, CollectorError};
    use crate::model::framework::Framework;

    struct Fake {
        control_id: &'static str,
        schedule: EvidenceSchedule,
        framework: Framework,
    }

    #[async_trait]
    impl EvidenceCollector for Fake {
        fn control_id(&self) -> &'static str {
            self.control_id
        }
        fn framework(&self) -> Framework {
            self.framework
        }
        fn schedule(&self) -> EvidenceSchedule {
            self.schedule
        }
        async fn collect(&self, ctx: &CollectionContext) -> Result<Evidence, CollectorError> {
            Ok(Evidence::new(
                self.control_id,
                self.framework,
                ctx.now,
                EvidenceContentType::Json,
                b"{}".to_vec(),
                "0.0.0",
            ))
        }
    }

    fn hourly() -> Box<dyn EvidenceCollector> {
        Box::new(Fake {
            control_id: "SX-HOURLY",
            schedule: EvidenceSchedule::Hourly,
            framework: Framework::Soc2,
        })
    }

    fn daily(hour: u8) -> Box<dyn EvidenceCollector> {
        Box::new(Fake {
            control_id: "SX-DAILY",
            schedule: EvidenceSchedule::Daily { hour_utc: hour },
            framework: Framework::Iso27001,
        })
    }

    fn weekly(weekday: WeekdayCode, hour: u8) -> Box<dyn EvidenceCollector> {
        Box::new(Fake {
            control_id: "SX-WEEKLY",
            schedule: EvidenceSchedule::Weekly {
                weekday,
                hour_utc: hour,
            },
            framework: Framework::Nist80053,
        })
    }

    #[test]
    fn registry_starts_empty() {
        let r = CollectorRegistry::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
    }

    #[test]
    fn dispatch_returns_due_collectors_only() {
        let mut r = CollectorRegistry::new();
        r.register(hourly());
        r.register(daily(8));
        // Now = Friday 2026-06-12, 09:00 UTC — both hourly + daily(8) fire.
        let due = r.dispatch(datetime!(2026-06-12 09:00:00 UTC));
        assert_eq!(due.len(), 2);
        // Registry was drained of those collectors.
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn dispatch_skips_collectors_not_yet_due() {
        let mut r = CollectorRegistry::new();
        r.register(daily(20)); // fires at 20:00 UTC
                               // last-fired clock is None, so we use the cold-start rule:
                               // "due if now is at/after target hour".
        let due = r.dispatch(datetime!(2026-06-12 10:00:00 UTC));
        assert!(due.is_empty());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn dispatch_respects_last_fired_clock() {
        let mut r = CollectorRegistry::new();
        r.register(hourly());
        // Mark as just fired at 09:00.
        r.mark_fired_by_control_id("SX-HOURLY", datetime!(2026-06-12 09:00:00 UTC));
        // 09:30 — not yet due (next tick is 10:00).
        assert!(r.dispatch(datetime!(2026-06-12 09:30:00 UTC)).is_empty());
        // 10:00 — due.
        let due = r.dispatch(datetime!(2026-06-12 10:00:00 UTC));
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn dispatch_weekly_only_on_target_weekday() {
        let mut r = CollectorRegistry::new();
        // Target Monday 08:00 UTC.
        r.register(weekly(WeekdayCode::Monday, 8));
        // Friday 2026-06-12 — beyond Monday, so cold-start fires.
        let due = r.dispatch(datetime!(2026-06-12 09:00:00 UTC));
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn register_many_round_trips_via_dispatch() {
        let mut r = CollectorRegistry::new();
        r.register(hourly());
        r.register(daily(0));
        let drained = r.dispatch(datetime!(2026-06-12 09:00:00 UTC));
        assert_eq!(drained.len(), 2);
        r.register_many(drained);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn clocks_snapshot_reflects_mark_fired() {
        let mut r = CollectorRegistry::new();
        r.register(hourly());
        let ts = datetime!(2026-06-12 09:00:00 UTC);
        r.mark_fired_by_control_id("SX-HOURLY", ts);
        let snap = r.clocks();
        assert_eq!(snap.get("SX-HOURLY").copied().flatten(), Some(ts));
    }
}
