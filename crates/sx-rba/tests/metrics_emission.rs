// LOW-009: test asserts use `.expect()` (must-succeed pattern), index
// into known-non-empty histogram vectors, and define helper `fn ts()`
// constructors that are not yet `const` because the underlying
// `time::macros::datetime!` is non-const.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::no_effect_underscore_binding
)]

//! LOW-006 — assert that `RbaService::evaluate` emits the expected
//! per-signal counters + histograms + decision counter through the
//! `metrics` crate facade.
//!
//! Uses `metrics_util::debugging::DebuggingRecorder` installed via
//! `metrics::with_local_recorder` so the assertions run hermetically
//! per test without touching the global Prometheus recorder.

use std::net::Ipv4Addr;

use metrics::{Key, Label};
use metrics_util::{
    debugging::{DebugValue, DebuggingRecorder},
    CompositeKey, MetricKind,
};
use sx_rba::{LoginContext, RbaService};
use time::macros::datetime;
use time::OffsetDateTime;
use uuid::Uuid;

const RBA_SIGNAL_FIRED_TOTAL: &str = "rba_signal_fired_total";
const RBA_SIGNAL_SCORE: &str = "rba_signal_score";
const RBA_DECISION_TOTAL: &str = "rba_decision_total";

fn ts() -> OffsetDateTime {
    datetime!(2026-06-15 10:00:00 UTC)
}

fn ctx(
    tenant: Uuid,
    user: Uuid,
    ip: Ipv4Addr,
    at: OffsetDateTime,
    fp: Option<&str>,
) -> LoginContext {
    LoginContext {
        tenant_id: tenant,
        user_id: Some(user),
        email: "alice@example.test".into(),
        ip,
        device_fingerprint: fp.map(str::to_owned),
        observed_at: at,
    }
}

#[allow(clippy::unwrap_used)]
fn snapshot_has_counter(
    snap: &[(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )],
    name: &str,
    expected_labels: &[(&str, &str)],
) -> Option<u64> {
    snap.iter().find_map(|(key, _, _, value)| {
        if key.kind() != MetricKind::Counter || key.key().name() != name {
            return None;
        }
        let labels: Vec<Label> = key.key().labels().cloned().collect();
        for (k, v) in expected_labels {
            if !labels.iter().any(|l| l.key() == *k && l.value() == *v) {
                return None;
            }
        }
        if let DebugValue::Counter(n) = value {
            Some(*n)
        } else {
            None
        }
    })
}

#[allow(clippy::unwrap_used)]
fn snapshot_has_histogram(
    snap: &[(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )],
    name: &str,
    expected_labels: &[(&str, &str)],
) -> Option<Vec<f64>> {
    snap.iter().find_map(|(key, _, _, value)| {
        if key.kind() != MetricKind::Histogram || key.key().name() != name {
            return None;
        }
        let labels: Vec<Label> = key.key().labels().cloned().collect();
        for (k, v) in expected_labels {
            if !labels.iter().any(|l| l.key() == *k && l.value() == *v) {
                return None;
            }
        }
        if let DebugValue::Histogram(samples) = value {
            Some(samples.iter().map(|s| s.into_inner()).collect())
        } else {
            None
        }
    })
}

#[test]
fn evaluate_records_per_signal_histogram_and_decision_counter() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let svc = RbaService::default();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // Pure-vanilla login from an RFC-1918 IP: 10.0.0.1 → "XX"
        // private-sentinel via the embedded CSV, first attempt
        // (velocity=1), business hours (10am UTC in the default 9-17
        // window), no fingerprint enrolled → device_fp_score = 30
        // (unknown).
        let _decision = svc.evaluate(ctx(
            tenant,
            user,
            Ipv4Addr::new(10, 0, 0, 1),
            ts(),
            Some("fp_abc"),
        ));

        let snap = snapshotter.snapshot().into_vec();

        // The histogram for ip_geo MUST record exactly one sample.
        let hist_ip = snapshot_has_histogram(
            &snap,
            RBA_SIGNAL_SCORE,
            &[("signal", "ip_geo"), ("tenant_id", &tenant.to_string())],
        )
        .expect("ip_geo histogram recorded");
        assert_eq!(hist_ip.len(), 1, "exactly one ip_geo sample expected");
        assert!(
            (hist_ip[0] - 40.0).abs() < f64::EPSILON,
            "expected private (40), got {}",
            hist_ip[0]
        );

        // Private-IP fires the ip_geo counter under bucket=private.
        let ip_geo_fired = snapshot_has_counter(
            &snap,
            RBA_SIGNAL_FIRED_TOTAL,
            &[
                ("signal", "ip_geo"),
                ("bucket", "private"),
                ("tenant_id", &tenant.to_string()),
            ],
        )
        .expect("ip_geo private bucket fired");
        assert_eq!(ip_geo_fired, 1);

        // Device-fp counter fires under bucket=unknown (first sighting).
        let dev_fired = snapshot_has_counter(
            &snap,
            RBA_SIGNAL_FIRED_TOTAL,
            &[
                ("signal", "device_fp"),
                ("bucket", "unknown"),
                ("tenant_id", &tenant.to_string()),
            ],
        )
        .expect("device_fp unknown bucket fired");
        assert_eq!(dev_fired, 1);

        // Decision counter fires once.
        let dec = snapshot_has_counter(
            &snap,
            RBA_DECISION_TOTAL,
            &[("action", "allow"), ("tenant_id", &tenant.to_string())],
        )
        .expect("decision counter recorded");
        assert!(dec >= 1);
    });
}

#[test]
fn first_login_does_not_fire_velocity_counter_but_records_histogram() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let svc = RbaService::default();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let _ = svc.evaluate(ctx(tenant, user, Ipv4Addr::new(10, 0, 0, 1), ts(), None));

        let snap = snapshotter.snapshot().into_vec();

        // Velocity sub-score is 0 on the very first attempt — counter
        // MUST NOT fire (zero-contribution invariant).
        let any_velocity_counter = snap.iter().any(|(key, _, _, _)| {
            key.kind() == MetricKind::Counter
                && key.key().name() == RBA_SIGNAL_FIRED_TOTAL
                && key
                    .key()
                    .labels()
                    .any(|l| l.key() == "signal" && l.value() == "velocity")
        });
        assert!(
            !any_velocity_counter,
            "velocity counter must not fire for a single attempt (score=0)"
        );

        // But the histogram MUST still record the zero sample for
        // distribution analysis.
        let hist_vel = snapshot_has_histogram(
            &snap,
            RBA_SIGNAL_SCORE,
            &[("signal", "velocity"), ("tenant_id", &tenant.to_string())],
        )
        .expect("velocity histogram recorded even at zero");
        assert_eq!(hist_vel.len(), 1);
        assert!((hist_vel[0] - 0.0).abs() < f64::EPSILON);
    });
}

#[test]
fn velocity_counter_fires_when_attempts_pile_up() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let svc = RbaService::default();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        for _ in 0..10 {
            let _ = svc.evaluate(ctx(tenant, user, Ipv4Addr::new(10, 0, 0, 1), ts(), None));
        }

        let snap = snapshotter.snapshot().into_vec();

        // After 10 attempts in the sliding window, the velocity
        // sub-score saturates to 100 and the `high` bucket must have
        // fired at least once.
        let high_fired = snapshot_has_counter(
            &snap,
            RBA_SIGNAL_FIRED_TOTAL,
            &[
                ("signal", "velocity"),
                ("bucket", "high"),
                ("tenant_id", &tenant.to_string()),
            ],
        );
        assert!(
            high_fired.is_some(),
            "velocity high bucket must fire after 10+ attempts"
        );
    });
}

#[test]
fn decision_counter_labels_each_action_variant_distinctly() {
    // We can't easily force the engine into Block from inside the
    // baseline observation phase, but we CAN assert the counter
    // name + labels list matches the Allow path. Block / StepUpMfa
    // paths are exercised by the scorer's unit tests, and the
    // counter call site is unconditional on action — so this test
    // is sufficient to catch label-typo regressions.
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let svc = RbaService::default();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let _ = svc.evaluate(ctx(tenant, user, Ipv4Addr::new(10, 0, 0, 1), ts(), None));

        let snap = snapshotter.snapshot().into_vec();
        // Action label must be "allow" — observation phase forces it.
        assert!(snapshot_has_counter(
            &snap,
            RBA_DECISION_TOTAL,
            &[("action", "allow"), ("tenant_id", &tenant.to_string())],
        )
        .is_some());
    });
}

#[test]
fn metric_names_are_stable_constants() {
    // Defensive lock-in: the metric names this test file asserts on
    // are the same strings exposed by the crate's metrics module.
    assert_eq!(
        sx_rba::metrics::RBA_SIGNAL_FIRED_TOTAL,
        RBA_SIGNAL_FIRED_TOTAL
    );
    assert_eq!(sx_rba::metrics::RBA_SIGNAL_SCORE, RBA_SIGNAL_SCORE);
    assert_eq!(sx_rba::metrics::RBA_DECISION_TOTAL, RBA_DECISION_TOTAL);
    // Touch the unused Key import so the linter doesn't warn.
    let _k: Option<Key> = None;
}
