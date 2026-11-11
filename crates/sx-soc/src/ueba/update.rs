//! Baseline mutator.
//!
//! Single entry point — [`update_baseline_from_event`] — that folds one
//! [`UebaEvent`] into a [`UserBehaviorBaseline`]. Idempotent on duplicate
//! `event_id`s.

use time::OffsetDateTime;

use crate::ueba::baseline::{
    bag_record, ip_prefix_16, UebaEvent, UserBehaviorBaseline, MAX_ASSETS, MAX_IP_PREFIXES,
};

/// Apply `event` to `baseline` in-place.
///
/// Returns `true` if the baseline was actually mutated. Returns `false`
/// when the event was already applied previously (`event_id` already in
/// the recent-ids ring) or carried no signal across any tracked dimension.
pub fn update_baseline_from_event(baseline: &mut UserBehaviorBaseline, event: &UebaEvent) -> bool {
    if let Some(eid) = event.event_id.as_deref() {
        if baseline.already_seen(eid) {
            return false;
        }
    }

    let mut changed = false;

    // Hour-of-day bucket (UTC). `hour()` returns `u8` strictly in `0..=23`.
    let hour = event.occurred_at.hour();
    if let Some(slot) = baseline.login_hours_histogram.get_mut(usize::from(hour)) {
        *slot = slot.saturating_add(1);
        changed = true;
    }

    // /16 IP prefix.
    if let Some(ip) = event.source_ip.as_deref() {
        if let Some(prefix) = ip_prefix_16(ip) {
            let _ = bag_record(&mut baseline.ip_prefixes, prefix, MAX_IP_PREFIXES);
            changed = true;
        }
    }

    // Accessed asset.
    if let Some(asset) = event.asset_id.as_deref() {
        let _ = bag_record(&mut baseline.accessed_assets, asset.to_owned(), MAX_ASSETS);
        changed = true;
    }

    if changed {
        baseline.updated_at = Some(OffsetDateTime::now_utc());
        if let Some(eid) = event.event_id.as_deref() {
            baseline.remember_event_id(eid);
        }
    }

    changed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn evt_hour(hour: u8) -> UebaEvent {
        let dt = datetime!(2027-01-01 0:00:00 UTC)
            .replace_hour(hour)
            .unwrap();
        UebaEvent::new("u", dt)
    }

    #[test]
    fn updates_hour_bucket() {
        let mut b = UserBehaviorBaseline::new(None, "u");
        let mut e = evt_hour(9);
        e.event_id = Some("e1".into());
        assert!(update_baseline_from_event(&mut b, &e));
        assert_eq!(b.login_hours_histogram[9], 1);
    }

    #[test]
    fn duplicate_event_id_is_idempotent() {
        let mut b = UserBehaviorBaseline::new(None, "u");
        let mut e = evt_hour(9);
        e.event_id = Some("e1".into());
        assert!(update_baseline_from_event(&mut b, &e));
        assert!(!update_baseline_from_event(&mut b, &e));
        assert_eq!(b.login_hours_histogram[9], 1);
    }

    #[test]
    fn records_ip_prefix_and_asset() {
        let mut b = UserBehaviorBaseline::new(None, "u");
        let mut e = evt_hour(12);
        e.source_ip = Some("10.20.30.40".into());
        e.asset_id = Some("asset-1".into());
        assert!(update_baseline_from_event(&mut b, &e));
        assert!(b.ip_prefixes.contains_key("10.20.0.0/16"));
        assert!(b.accessed_assets.contains_key("asset-1"));
    }

    #[test]
    fn unknown_ip_does_not_record_prefix() {
        let mut b = UserBehaviorBaseline::new(None, "u");
        let mut e = evt_hour(0);
        e.source_ip = Some("not-an-ip".into());
        let _ = update_baseline_from_event(&mut b, &e);
        assert!(b.ip_prefixes.is_empty());
    }

    #[test]
    #[allow(clippy::integer_division)]
    fn many_events_keep_baseline_bounded() {
        let mut b = UserBehaviorBaseline::new(None, "u");
        for i in 0..500_u32 {
            let mut e = evt_hour(u8::try_from(i % 24).unwrap());
            e.event_id = Some(format!("e{i}"));
            e.source_ip = Some(format!("{}.{}.0.1", (i / 256) % 256, i % 256));
            e.asset_id = Some(format!("a{}", i % 250));
            let _ = update_baseline_from_event(&mut b, &e);
        }
        assert!(b.ip_prefixes.len() <= MAX_IP_PREFIXES);
        assert!(b.accessed_assets.len() <= MAX_ASSETS);
    }
}
