//! Background outbound-webhook signing-key rotator job (MED-003).
//!
//! Drives [`sx_webhooks::WebhookKeyRotator::tick`] on a configured
//! cadence over a tenant id list. The job owns one `tokio::task` per
//! [`spawn`] invocation. On every tick:
//!
//! 1. Walks the per-tenant id list.
//! 2. Calls `rotator.tick(tenant_id, policy)` — the rotator is
//!    responsible for "is this tenant due?" checks, minting, retiring,
//!    and audit-emission.
//! 3. Logs the outcome at `info` for an operator-friendly trail (kid +
//!    reason only — no secret bytes).
//!
//! ## Tenant discovery
//!
//! For the MED-003 v1, the tenant list is the explicit set of keys in
//! `cfg.tenant_overrides` plus a single "default" tenant if no
//! overrides are set. A multi-tenant fan-out reading from `tenants`
//! lands once the per-tenant config table is wired in — same
//! follow-up shape as `intel_feeds_job`.
//!
//! ## Shutdown
//!
//! The returned [`JoinHandle`] runs forever; the caller drops it on
//! process shutdown. The composition root holds these handles in a
//! `Vec<JoinHandle<()>>` so they live for the binary lifetime.

use std::time::Duration;

use sx_config::schema::WebhookSigningRotationConfig;
use sx_webhooks::signing::rotator::RotationPolicy;
use sx_webhooks::WebhookKeyRotator;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};

/// Default placeholder tenant id used when the config supplies no
/// per-tenant overrides. Mirrors the same approach used by the
/// `intel_feeds_job` while the multi-tenant fan-out lands.
pub(crate) const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Spawn the background rotator. Returns `None` when
/// `cfg.enabled` is `false` so the composition root can simply
/// `let _ = spawn(...);`.
#[allow(dead_code)]
pub(crate) fn spawn(
    cfg: &WebhookSigningRotationConfig,
    rotator: WebhookKeyRotator,
) -> Option<JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }

    let tick_secs = cfg.tick_seconds.max(60);
    let cadence_days = cfg.cadence_days;
    let grace_days = cfg.grace_days;
    let tenant_ids: Vec<String> = if cfg.tenant_overrides.is_empty() {
        vec![DEFAULT_TENANT_ID.to_owned()]
    } else {
        cfg.tenant_overrides.keys().cloned().collect()
    };
    let per_tenant: Vec<(String, RotationPolicy)> = tenant_ids
        .into_iter()
        .map(|tid| {
            let ovr = cfg.tenant_overrides.get(&tid).copied();
            let (c, g) = ovr.map_or((cadence_days, grace_days), |o| {
                (o.cadence_days, o.grace_days)
            });
            (tid, RotationPolicy::from_days(c, g))
        })
        .collect();

    info!(
        target: "adapters.webhooks_rotation_job",
        tenants = per_tenant.len(),
        tick_secs,
        cadence_days,
        grace_days,
        "spawning outbound webhook signing-key rotator"
    );

    let handle = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(tick_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            for (tenant_id, policy) in &per_tenant {
                match rotator.tick(tenant_id, *policy).await {
                    Ok(Some(outcome)) => {
                        info!(
                            target: "adapters.webhooks_rotation_job",
                            tenant_id = %tenant_id,
                            new_kid = %outcome.new_kid,
                            previous_kid = outcome
                                .previous_kid
                                .as_ref()
                                .map_or("-", sx_webhooks::Kid::as_str),
                            "tick rotated tenant"
                        );
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(
                            target: "adapters.webhooks_rotation_job",
                            tenant_id = %tenant_id,
                            error = %e,
                            "tick rotation failed"
                        );
                    }
                }
            }
        }
    });
    Some(handle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sx_webhooks::signing::audit::{InMemoryRotationAuditSink, RotationAuditSink};
    use sx_webhooks::signing::secret_cipher::{PlaintextCipher, SecretCipher};
    use sx_webhooks::signing::store::SigningKeyStore;
    use sx_webhooks::InMemorySigningKeyStore;

    fn rotator() -> (WebhookKeyRotator, Arc<InMemoryRotationAuditSink>) {
        let store: Arc<dyn SigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
        let cipher: Arc<dyn SecretCipher> = Arc::new(PlaintextCipher);
        let audit_inner: Arc<InMemoryRotationAuditSink> =
            Arc::new(InMemoryRotationAuditSink::new());
        let audit: Arc<dyn RotationAuditSink> = audit_inner.clone();
        (WebhookKeyRotator::new(store, cipher, audit), audit_inner)
    }

    #[test]
    fn spawn_returns_none_when_disabled() {
        let cfg = WebhookSigningRotationConfig {
            enabled: false,
            ..Default::default()
        };
        let (rot, _audit) = rotator();
        let h = spawn(&cfg, rot);
        assert!(h.is_none());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_runs_first_tick_and_mints_default_tenant_key() {
        let cfg = WebhookSigningRotationConfig {
            enabled: true,
            tick_seconds: 60,
            ..Default::default()
        };
        let (rot, audit) = rotator();
        let h = spawn(&cfg, rot).expect("spawn must produce a handle when enabled");
        // Drive the first tick.
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        // Give the spawned task a moment to actually run after the
        // virtual clock advance.
        for _ in 0..16 {
            tokio::task::yield_now().await;
            if !audit.events().is_empty() {
                break;
            }
        }
        h.abort();
        let evs = audit.events();
        assert!(
            !evs.is_empty(),
            "background tick must mint the default tenant's first key"
        );
    }
}
