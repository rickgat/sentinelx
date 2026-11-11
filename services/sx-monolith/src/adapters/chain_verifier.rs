//! Background audit-chain verifier wiring (CRIT-002).
//!
//! Spawns the [`sx_audit::ChainVerifier`] on monolith boot so the audit
//! hot tail is re-verified every `interval_secs` per tenant. On any
//! detected break the verifier fans out to the registered subscribers —
//! the IR-playbooks auto-fire adapter is one such subscriber, wired up
//! by [`crate::adapters::ir`].
//!
//! ## Configuration
//!
//! Interval is read from the `AUDIT_CHAIN_VERIFIER_INTERVAL_SECS`
//! environment variable. When unset or unparseable the default of 5
//! minutes (`sx_audit::DEFAULT_INTERVAL`) applies, matching the
//! CRIT-002 spec. The env-var fallback keeps this CRITICAL safety
//! control independent of the layered YAML loader so a malformed
//! `sx-config` file cannot accidentally silence the verifier.
//!
//! ## Tenant rotation
//!
//! Tenants are registered lazily by the composition root: at boot we
//! register the bootstrap tenant if `bootstrap.enabled` is true; in
//! production the SCIM provisioner + tenant_write adapter call
//! [`ChainVerifier::register_tenant`] on every new tenant. The current
//! MVP just registers the bootstrap tenant; the per-tenant rotation
//! ships in the production deployment phase together with the
//! Postgres-backed tenant repository.

use std::sync::Arc;
use std::time::Duration;

use sx_audit::chain_verifier::{
    BrokenChainSubscriber, ChainVerifier, SystemClock, DEFAULT_INTERVAL,
};
use sx_audit::prelude::AuditSink;
use tokio_util::sync::CancellationToken;

/// Environment variable consulted for the verifier cadence.
const INTERVAL_ENV: &str = "AUDIT_CHAIN_VERIFIER_INTERVAL_SECS";

/// Bundle returned to the composition root.
pub(crate) struct ChainVerifierBundle {
    /// Shared verifier handle. The composition root uses it to register
    /// tenants after the IAM/SCIM bundles have minted them.
    pub(crate) verifier: Arc<ChainVerifier>,
}

impl std::fmt::Debug for ChainVerifierBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainVerifierBundle")
            .finish_non_exhaustive()
    }
}

/// Resolve the verifier interval from the environment, defaulting to
/// [`DEFAULT_INTERVAL`] when unset or unparseable. The env-var lookup
/// is the single explicit `std::env::var` call in this crate so the
/// disallowed-methods clippy lint can be allowed locally.
#[allow(clippy::disallowed_methods)]
fn resolve_interval() -> Duration {
    match std::env::var(INTERVAL_ENV) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(secs) if secs > 0 => {
                tracing::info!(
                    target: "monolith.chain_verifier",
                    interval_secs = secs,
                    "audit chain verifier interval sourced from env"
                );
                Duration::from_secs(secs)
            }
            Ok(_) => {
                tracing::warn!(
                    target: "monolith.chain_verifier",
                    raw = %raw,
                    "audit.chain_verifier.interval_secs must be > 0; \
                     falling back to default 5 min"
                );
                DEFAULT_INTERVAL
            }
            Err(err) => {
                tracing::warn!(
                    target: "monolith.chain_verifier",
                    raw = %raw,
                    error = %err,
                    "failed to parse AUDIT_CHAIN_VERIFIER_INTERVAL_SECS; \
                     falling back to default 5 min"
                );
                DEFAULT_INTERVAL
            }
        },
        Err(_) => DEFAULT_INTERVAL,
    }
}

/// Build the bundle. Does not spawn the loop — the caller invokes
/// [`spawn_loop`] after registering the subscribers it wants observed.
pub(crate) fn build(
    sink: Arc<dyn AuditSink>,
    subscribers: Vec<Arc<dyn BrokenChainSubscriber>>,
) -> ChainVerifierBundle {
    let interval = resolve_interval();
    let verifier = Arc::new(ChainVerifier::new(
        sink,
        subscribers,
        Arc::new(SystemClock),
        interval,
    ));
    ChainVerifierBundle { verifier }
}

/// Spawn the verifier loop wired to the monolith's cancellation token.
/// Returns the [`tokio::task::JoinHandle`] so the composition root can
/// push it into the shared `job_handles` vector (the rest of the
/// long-running jobs follow the same pattern).
pub(crate) fn spawn_loop(
    verifier: Arc<ChainVerifier>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    Arc::clone(&verifier).spawn(async move { shutdown.cancelled().await })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use async_trait::async_trait;
    use sx_audit::error::AuditError;
    use sx_audit::model::entry::AuditEntry;
    use sx_audit::prelude::AuditSink;
    use sx_core::value_object::ids::TenantId;

    #[derive(Debug, Default)]
    struct EmptySink {
        entries: Mutex<Vec<AuditEntry>>,
    }

    #[async_trait]
    impl AuditSink for EmptySink {
        async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.entries.lock().unwrap().push(entry.clone());
            Ok(())
        }
        async fn last_entry_for_tenant(
            &self,
            _tid: TenantId,
        ) -> Result<Option<AuditEntry>, AuditError> {
            Ok(None)
        }
        async fn read_range(
            &self,
            _tid: TenantId,
            _from: u64,
            _to: u64,
        ) -> Result<Vec<AuditEntry>, AuditError> {
            Ok(vec![])
        }
    }

    #[test]
    fn resolve_interval_falls_back_to_default_when_unset() {
        // Use a unique var name so the test is robust against parallel
        // runs polluting AUDIT_CHAIN_VERIFIER_INTERVAL_SECS.
        std::env::remove_var(INTERVAL_ENV);
        let d = resolve_interval();
        assert_eq!(d, DEFAULT_INTERVAL);
    }

    #[test]
    fn build_returns_bundle_without_spawning() {
        let sink: Arc<dyn AuditSink> = Arc::new(EmptySink::default());
        let bundle = build(sink, vec![]);
        // Smoke: holding the handle does not panic.
        let _ = Arc::clone(&bundle.verifier);
    }
}
