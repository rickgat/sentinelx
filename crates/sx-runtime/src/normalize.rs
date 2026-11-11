//! Falco -> OCSF projection.
//!
//! Falco describes runtime-security events that map most naturally to the
//! OCSF *System Activity* (`category_uid = 1`) family:
//!
//! - **Process Activity** (`class_uid = 1007`) for syscall-sourced rules
//!   (shell-in-container, privileged escape, secrets-read).
//! - **Application Activity** (`class_uid = 6002`) for `k8s_audit`-sourced
//!   rules (token-secret mount, role-binding mutation).
//!
//! The mapping is deterministic and side-effect-free — it never touches a
//! network or DB.

use sx_log_ingest::schema::ocsf::{Observable, OcsfEvent, OcsfMetadata};

use crate::alert::FalcoAlert;
use crate::finding::map_priority;

/// OCSF class id for Process Activity.
pub const OCSF_CLASS_PROCESS_ACTIVITY: i32 = 1007;
/// OCSF category id for System Activity.
pub const OCSF_CATEGORY_SYSTEM_ACTIVITY: i32 = 1;
/// OCSF class id for Application Activity.
pub const OCSF_CLASS_APPLICATION_ACTIVITY: i32 = 6002;
/// OCSF category id for Application Activity.
pub const OCSF_CATEGORY_APPLICATION_ACTIVITY: i32 = 6;

/// Project a Falco alert onto an OCSF event.
///
/// `tenant_id` is stamped into the metadata bundle. `received_at` is used
/// only when the alert itself did not carry a timestamp; the function is
/// otherwise a pure function of its inputs.
#[must_use]
pub fn falco_to_ocsf(alert: &FalcoAlert, tenant_id: &str, received_at: &str) -> OcsfEvent {
    let (class_uid, category_uid) = if alert.source == "k8s_audit" {
        (
            OCSF_CLASS_APPLICATION_ACTIVITY,
            OCSF_CATEGORY_APPLICATION_ACTIVITY,
        )
    } else {
        (OCSF_CLASS_PROCESS_ACTIVITY, OCSF_CATEGORY_SYSTEM_ACTIVITY)
    };

    let severity = map_priority(alert.priority).to_ocsf();
    let time = if alert.time.is_empty() {
        received_at.to_owned()
    } else {
        alert.time.clone()
    };

    // Raw payload — re-serialise the alert so we always have a stable,
    // round-trippable string. The ingest service caps this on persistence.
    let raw =
        serde_json::to_string(alert).unwrap_or_else(|_| "{\"error\":\"reserialise\"}".to_owned());

    let mut metadata = OcsfMetadata::new("Falco", "falco");
    tenant_id.clone_into(&mut metadata.tenant_id);

    let mut event = OcsfEvent::new(class_uid, category_uid, time, severity, raw, metadata);

    // Always carry the matched rule as a first-class observable so the
    // SOC correlator can pivot off it without parsing the raw payload.
    event = event.with_observable(Observable::new("falco.rule", "rule", &alert.rule));

    if let Some(v) = alert.field_str("proc.name") {
        event = event.with_observable(Observable::new("proc.name", "process", v));
    }
    if let Some(v) = alert.field_str("proc.cmdline") {
        event = event.with_observable(Observable::new("proc.cmdline", "process", v));
    }
    if let Some(v) = alert.field_str("user.name") {
        event = event.with_observable(Observable::new("user.name", "user", v));
    }
    if let Some(v) = alert
        .field_str("container.image.repository")
        .or_else(|| alert.field_str("container.image"))
    {
        event = event.with_observable(Observable::new("container.image", "container", v));
    }
    if let Some(v) = alert
        .field_str("k8s.pod.name")
        .or_else(|| alert.field_str("k8s.pod"))
    {
        event = event.with_observable(Observable::new("k8s.pod.name", "k8s_pod", v));
    }
    if let Some(v) = alert
        .field_str("k8s.ns.name")
        .or_else(|| alert.field_str("k8s.namespace.name"))
    {
        event = event.with_observable(Observable::new("k8s.ns.name", "k8s_namespace", v));
    }
    if let Some(host) = alert.hostname.as_deref() {
        event = event.with_observable(Observable::new("host.name", "hostname", host));
    }

    event.cap_raw();
    event
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn alert_json(source: &str, priority: &str) -> FalcoAlert {
        let v = serde_json::json!({
            "rule": "Terminal shell in container",
            "priority": priority,
            "output": "shell spawned",
            "time": "2026-06-12T10:30:01Z",
            "source": source,
            "output_fields": {
                "proc.name": "bash",
                "proc.cmdline": "bash -i",
                "user.name": "root",
                "container.image.repository": "nginx",
                "k8s.pod.name": "web-1",
                "k8s.ns.name": "prod"
            }
        });
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn syscall_alerts_become_process_activity() {
        let a = alert_json("syscall", "Warning");
        let e = falco_to_ocsf(&a, "t1", "1970-01-01T00:00:00Z");
        assert_eq!(e.class_uid, OCSF_CLASS_PROCESS_ACTIVITY);
        assert_eq!(e.category_uid, OCSF_CATEGORY_SYSTEM_ACTIVITY);
    }

    #[test]
    fn k8s_audit_alerts_become_application_activity() {
        let a = alert_json("k8s_audit", "Critical");
        let e = falco_to_ocsf(&a, "t1", "1970-01-01T00:00:00Z");
        assert_eq!(e.class_uid, OCSF_CLASS_APPLICATION_ACTIVITY);
        assert_eq!(e.category_uid, OCSF_CATEGORY_APPLICATION_ACTIVITY);
    }

    #[test]
    fn carries_matched_rule_as_observable() {
        let a = alert_json("syscall", "Warning");
        let e = falco_to_ocsf(&a, "t1", "1970-01-01T00:00:00Z");
        let rule_obs = e.observables.iter().find(|o| o.name == "falco.rule");
        assert!(rule_obs.is_some());
        assert_eq!(rule_obs.unwrap().value, "Terminal shell in container");
    }

    #[test]
    fn carries_proc_and_container_observables() {
        let a = alert_json("syscall", "Warning");
        let e = falco_to_ocsf(&a, "t1", "1970-01-01T00:00:00Z");
        let names: Vec<&str> = e.observables.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"proc.name"));
        assert!(names.contains(&"proc.cmdline"));
        assert!(names.contains(&"user.name"));
        assert!(names.contains(&"container.image"));
        assert!(names.contains(&"k8s.pod.name"));
        assert!(names.contains(&"k8s.ns.name"));
    }

    #[test]
    fn substitutes_received_at_when_time_missing() {
        let mut a = alert_json("syscall", "Notice");
        a.time = String::new();
        let e = falco_to_ocsf(&a, "t1", "2026-06-14T00:00:00Z");
        assert_eq!(e.time, "2026-06-14T00:00:00Z");
    }

    #[test]
    fn tenant_id_is_stamped_into_metadata() {
        let a = alert_json("syscall", "Notice");
        let e = falco_to_ocsf(&a, "tenant-42", "1970-01-01T00:00:00Z");
        assert_eq!(e.metadata.tenant_id, "tenant-42");
        assert_eq!(e.metadata.source_type, "falco");
        assert_eq!(e.metadata.product, "Falco");
    }
}
