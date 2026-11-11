//! End-to-end discovery use-case.
//!
//! Given an engagement (already loaded by the caller) and a [`ScanRequest`],
//! the use-case:
//!
//! 1. Runs the [`SafetyGate`] over the full request.
//! 2. For each target, picks the registered scanners whose capabilities
//!    accept the requested intensity and target kind.
//! 3. Drives the scanners with bounded concurrency.
//! 4. Aborts gracefully on a kill-switch trip mid-stream.

use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use time::OffsetDateTime;

use crate::contracts::{Engagement, ScanRequest, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::scan_result::ScanResult;
use crate::service::rate_limiter::RateLimiter;
use crate::service::registry::ScannerRegistry;
use crate::service::safety_gate::SafetyGate;
use crate::service::scanner::{ScanContext, Scanner, ScannerId};

/// Result of one [`RunDiscoveryUseCase::execute`] call.
#[derive(Debug, Default)]
pub struct RunDiscoveryOutput {
    /// All scan results produced — one per `(scanner, target)` pair that ran.
    pub results: Vec<ScanResult>,
    /// Per-target errors, if any. The use-case continues running other
    /// `(scanner, target)` combinations after a single failure.
    pub errors: Vec<(ScannerId, ScopeTarget, DiscoveryError)>,
    /// `true` iff the run was cut short by the kill switch.
    pub killed: bool,
}

/// End-to-end discovery use-case.
#[derive(Debug)]
pub struct RunDiscoveryUseCase {
    registry: Arc<ScannerRegistry>,
    gate: SafetyGate,
    rate_limiter: Arc<RateLimiter>,
    scanner_deadline: Duration,
    bounded_concurrency: usize,
}

impl RunDiscoveryUseCase {
    /// Build a new use-case.
    ///
    /// `scanner_deadline` is the per-target wall-clock budget; `bounded_concurrency`
    /// caps how many `(scanner, target)` futures run in parallel.
    pub fn new(
        registry: Arc<ScannerRegistry>,
        gate: SafetyGate,
        rate_limiter: Arc<RateLimiter>,
        scanner_deadline: Duration,
        bounded_concurrency: usize,
    ) -> Result<Self, DiscoveryError> {
        if bounded_concurrency == 0 {
            return Err(DiscoveryError::config("bounded_concurrency must be >= 1"));
        }
        Ok(Self {
            registry,
            gate,
            rate_limiter,
            scanner_deadline,
            bounded_concurrency,
        })
    }

    /// Execute the use-case.
    // Multi-phase orchestration (gate → scan → rate-limit → kill-switch +
    // structured trace per branch); flow is linear despite the lint score.
    #[allow(clippy::cognitive_complexity)]
    pub async fn execute(
        &self,
        engagement: &Engagement,
        req: &ScanRequest,
        only: Option<&[ScannerId]>,
    ) -> Result<RunDiscoveryOutput, DiscoveryError> {
        self.gate.check(engagement, req).await?;

        let kill = self.gate.kill_switch();
        let scopes = SafetyGate::scopes_for(engagement);
        let kill_signal = kill.subscribe(&scopes);

        let mut output = RunDiscoveryOutput::default();
        let mut work: Vec<(Arc<dyn Scanner>, ScopeTarget)> = Vec::new();
        for target in &req.targets {
            let mut candidates = self.registry.matching(req.intensity, target);
            if let Some(filter) = only {
                candidates.retain(|s| filter.iter().any(|id| *id == s.id()));
            }
            if candidates.is_empty() {
                tracing::warn!(
                    target = %target,
                    "no scanner matches target / intensity — skipping",
                );
            }
            for s in candidates {
                work.push((s, target.clone()));
            }
        }
        if work.is_empty() {
            return Ok(output);
        }

        let mut iter = work.into_iter();
        let mut in_flight = FuturesUnordered::new();
        loop {
            while in_flight.len() < self.bounded_concurrency {
                let Some((scanner, target)) = iter.next() else {
                    break;
                };
                let ctx = ScanContext {
                    tenant_id: req.tenant_id,
                    engagement_id: req.engagement_id,
                    intensity: req.intensity,
                    rate_limiter: Arc::clone(&self.rate_limiter),
                    kill_signal: Arc::clone(&kill_signal),
                    kill_scopes: scopes.clone(),
                    deadline: OffsetDateTime::now_utc()
                        + time::Duration::try_from(self.scanner_deadline)
                            .unwrap_or(time::Duration::seconds(30)),
                };
                let scanner_id = scanner.id();
                let t = target.clone();
                in_flight.push(async move {
                    let outcome = scanner.scan(ctx, t.clone()).await;
                    (scanner_id, t, outcome)
                });
            }
            if in_flight.is_empty() {
                break;
            }
            tokio::select! {
                () = kill_signal.notified() => {
                    output.killed = true;
                    tracing::warn!("kill switch tripped — aborting in-flight scans");
                    return Ok(output);
                }
                next = in_flight.next() => {
                    match next {
                        Some((id, target, Ok(r))) => {
                            tracing::info!(scanner_id = %id, target = %target, observations = r.observation_count(), "scan finished");
                            output.results.push(r);
                        }
                        Some((id, target, Err(e))) => {
                            tracing::warn!(scanner_id = %id, target = %target, error = %e, "scan failed");
                            output.errors.push((id, target, e));
                        }
                        None => break,
                    }
                }
            }
            // Pre-flight kill check between iterations.
            if kill.is_tripped(&scopes).await {
                output.killed = true;
                tracing::warn!("kill switch tripped between scans — stopping");
                return Ok(output);
            }
        }

        Ok(output)
    }
}
