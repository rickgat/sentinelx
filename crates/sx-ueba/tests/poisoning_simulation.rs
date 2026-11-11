//! Integration test simulating a baseline-poisoning attempt (HIGH-010).
//!
//! Threat model:
//!
//! 1. The legitimate user `alice` has built a baseline of logins from the
//!    `10.20.0.0/16` prefix during business hours (UTC 9am).
//! 2. An attacker who already has `alice`'s credentials starts logging in
//!    from a brand-new `198.51.100.0/16` prefix at unusual hours (UTC 3am).
//! 3. Without freeze mode, the baseline would silently absorb the attacker
//!    traffic ("drift") and stop firing anomalies for the new pattern —
//!    classic ML-poisoning.
//! 4. With freeze mode engaged, scoring uses the snapshot captured before
//!    the attack started, so every attacker login keeps raising anomalies
//!    even after dozens of attempts.
//!
//! The test verifies the freeze-mode contract holds across all four
//! pillars:
//!
//! * snapshot capture (sample count + prefixes unchanged after attacker
//!   traffic);
//! * scoring against snapshot (attacker prefix still scored as
//!   anomalous);
//! * audit emission for every transition;
//! * drift detection on `Frozen → Active` surfaces the divergence even
//!   when the live baseline did NOT advance (the freeze invariant) — in
//!   this test the live baseline does not drift, so the drift detector
//!   should be silent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::items_after_statements
)]

use std::sync::Arc;

use sx_soc::ueba::service::{InMemoryUebaService, UebaService};
use sx_soc::UebaEvent;
use sx_ueba::{
    BaselineState, CapturingFindingPipelineSink, CapturingUebaAuditSink, FreezeAwareUebaService,
    FreezeAwareUebaServiceImpl, LEARNING_WARMUP_SAMPLES,
};
use time::macros::datetime;

const TENANT: &str = "tenant-incident-2027";
const USER: &str = "alice";
const LEGIT_IP: &str = "10.20.30.40";
const ATTACKER_IP: &str = "198.51.100.4";

fn legit_login(seq: u32) -> UebaEvent {
    let dt = datetime!(2027-01-01 9:00:00 UTC);
    let mut e = UebaEvent::new(USER, dt);
    e.tenant_id = Some(TENANT.into());
    e.event_id = Some(format!("legit-{seq}"));
    e.source_ip = Some(LEGIT_IP.into());
    e
}

fn attacker_login(seq: u32) -> UebaEvent {
    let dt = datetime!(2027-02-15 3:00:00 UTC);
    let mut e = UebaEvent::new(USER, dt);
    e.tenant_id = Some(TENANT.into());
    e.event_id = Some(format!("attacker-{seq}"));
    e.source_ip = Some(ATTACKER_IP.into());
    e
}

fn fresh_service() -> (
    FreezeAwareUebaServiceImpl,
    CapturingUebaAuditSink,
    CapturingFindingPipelineSink,
) {
    let inner: Arc<dyn UebaService> = Arc::new(InMemoryUebaService::new());
    let audit = CapturingUebaAuditSink::new();
    let findings = CapturingFindingPipelineSink::new();
    let svc = FreezeAwareUebaServiceImpl::new(inner)
        .with_audit(Arc::new(audit.clone()))
        .with_findings(Arc::new(findings.clone()));
    (svc, audit, findings)
}

#[tokio::test]
async fn freeze_mode_prevents_baseline_poisoning() {
    let (svc, audit, _findings) = fresh_service();

    // ---- Phase 1: legitimate warm-up & active baseline ----------------
    for i in 0..LEARNING_WARMUP_SAMPLES {
        svc.apply(legit_login(i)).await;
    }
    // Auto-promotion to Active should have landed.
    let view = svc.snapshot(TENANT, USER).await.expect("snapshot");
    assert_eq!(view.state, BaselineState::Active);
    let promotions = audit
        .drain()
        .into_iter()
        .filter(|e| e.from_state == BaselineState::Learning && e.to_state == BaselineState::Active)
        .count();
    assert_eq!(promotions, 1, "Learning → Active should auto-fire once");

    // ---- Phase 2: confirm pre-freeze scoring works on attacker IP -----
    let preview = attacker_login(0);
    let pre_freeze_anomaly = svc
        .check(&preview)
        .await
        .expect("attacker IP should fire pre-freeze");
    assert!(pre_freeze_anomaly
        .anomaly
        .dimensions
        .iter()
        .any(|d| d.dimension == "source_ip_prefix"));

    // ---- Phase 3: operator freezes the baseline -----------------------
    let frozen = svc
        .freeze(TENANT, USER, Some("op@sx"), Some("ic-1234"))
        .await
        .expect("freeze");
    assert_eq!(frozen.state, BaselineState::Frozen);
    let snap = frozen.snapshot.expect("frozen snapshot present");
    let snapshot_at_freeze = snap.login_hour_counts.clone();
    let snapshot_prefixes_at_freeze = snap.ip_prefixes.clone();

    // Confirm the freeze emitted an audit event with actor + reason.
    let evts = audit.drain();
    let freeze_evts: Vec<_> = evts
        .into_iter()
        .filter(|e| e.to_state == BaselineState::Frozen)
        .collect();
    assert_eq!(freeze_evts.len(), 1);
    assert_eq!(freeze_evts[0].actor.as_deref(), Some("op@sx"));
    assert_eq!(freeze_evts[0].reason.as_deref(), Some("ic-1234"));

    // ---- Phase 4: ATTACK — many logins from a new prefix --------------
    //
    // Without freeze the legitimate baseline would silently absorb the
    // 198.51.100.0/16 prefix after enough attempts and stop firing.
    // With freeze, every attempt is scored against the SNAPSHOT which
    // does not know that prefix, so every attempt keeps firing.
    const ATTACK_ATTEMPTS: u32 = 25;
    let mut attacker_anomalies = 0;
    for i in 0..ATTACK_ATTEMPTS {
        let evt = attacker_login(i);
        if let Some(an) = svc.check(&evt).await {
            if an
                .anomaly
                .dimensions
                .iter()
                .any(|d| d.dimension == "source_ip_prefix")
            {
                attacker_anomalies += 1;
            }
        }
        // Apply the attacker event — but because we are frozen, this MUST
        // NOT update the live baseline. The test asserts that below.
        svc.apply(evt).await;
    }

    assert_eq!(
        attacker_anomalies, ATTACK_ATTEMPTS,
        "freeze must keep raising IP-prefix anomalies for every attacker login"
    );

    // ---- Phase 5: confirm the snapshot did NOT drift -----------------
    //
    // The frozen snapshot is the source of truth while frozen. The
    // `apply` calls during the attack were silently dropped because of
    // the freeze invariant.
    let view2 = svc.snapshot(TENANT, USER).await.expect("snapshot");
    assert_eq!(view2.state, BaselineState::Frozen);
    let snap2 = view2.snapshot.expect("still snapshotted");
    assert_eq!(
        snap2.login_hour_counts, snapshot_at_freeze,
        "frozen snapshot histogram must not advance during freeze"
    );
    assert_eq!(
        snap2.ip_prefixes, snapshot_prefixes_at_freeze,
        "frozen snapshot prefixes must not absorb attacker traffic"
    );
    assert!(
        !snap2.ip_prefixes.contains_key("198.51.0.0/16"),
        "attacker /16 must NEVER have entered the snapshot"
    );

    // ---- Phase 6: operator unfreezes ----------------------------------
    let unfrozen = svc
        .unfreeze(TENANT, USER, Some("op@sx"), Some("contained"))
        .await
        .expect("unfreeze");
    assert_eq!(unfrozen.state, BaselineState::Active);
    assert!(unfrozen.snapshot.is_none());

    let evts2 = audit.drain();
    let unfreeze_evts: Vec<_> = evts2
        .into_iter()
        .filter(|e| e.from_state == BaselineState::Frozen && e.to_state == BaselineState::Active)
        .collect();
    assert_eq!(unfreeze_evts.len(), 1);
    assert_eq!(unfreeze_evts[0].reason.as_deref(), Some("contained"));
}

#[tokio::test]
async fn unfreeze_routes_drift_findings_when_live_baseline_diverged() {
    // Construct a scenario where the *inner* baseline diverged behind the
    // freeze-aware layer's back (e.g. an out-of-band ingestion path or
    // a sloppy migration). The drift detector should catch this on
    // unfreeze and route findings to SOC.
    let inner = Arc::new(InMemoryUebaService::new());
    let audit = CapturingUebaAuditSink::new();
    let findings = CapturingFindingPipelineSink::new();
    let svc = FreezeAwareUebaServiceImpl::new(inner.clone() as Arc<dyn UebaService>)
        .with_audit(Arc::new(audit.clone()))
        .with_findings(Arc::new(findings.clone()));

    // Warm up + activate.
    for i in 0..LEARNING_WARMUP_SAMPLES {
        svc.apply(legit_login(i)).await;
    }
    // Freeze.
    let _ = svc
        .freeze(TENANT, USER, Some("op@sx"), Some("contain"))
        .await
        .unwrap();
    let _ = audit.drain();

    // Out-of-band drift: write directly through the inner service,
    // bypassing the freeze-aware gate. This simulates a leaked write
    // (the threat model the drift detector is designed to surface).
    for i in 0..10 {
        let mut evt = attacker_login(100 + i);
        evt.event_id = Some(format!("ooo-drift-{i}"));
        // Direct apply — bypasses freeze.
        inner.apply(evt).await;
    }

    // Unfreeze — drift detector runs.
    let _ = svc
        .unfreeze(TENANT, USER, Some("op@sx"), Some("scan"))
        .await
        .unwrap();
    let routed = findings.drain();
    assert!(
        !routed.is_empty(),
        "out-of-band drift should produce >= 1 finding"
    );
    // The first routed finding should mention either the brand-new
    // prefix or the hour bucket.
    assert!(routed
        .iter()
        .any(|(_, _, f)| { f.dimension == "source_ip_prefix" || f.dimension == "hour_of_day" }));
}
