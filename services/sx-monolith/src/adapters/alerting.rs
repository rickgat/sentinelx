//! Alerting policy engine (wires the incident-sink fan-out to findings).
//!
//! The vendor sinks (Jira / PagerDuty / Opsgenie / ServiceNow / Linear) and
//! the [`IncidentSinkFanOut`] already exist; what was missing was the policy
//! that decides *which* events alert and the hook that fires them. This
//! module adds a thin [`FindingRepositoryPort`] decorator: on every
//! persisted finding whose severity is at or above a configured threshold,
//! it fans an [`IncidentKind::FindingEmitted`] event out to every configured
//! sink (fire-and-forget — alerting never blocks or fails the insert).
//!
//! Default threshold is [`Severity::Critical`], matching the
//! "A `Critical` finding was just persisted" contract on
//! [`IncidentKind::FindingEmitted`].

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{EngagementPortError, FindingRepositoryPort};
use sx_api::view::finding_view::FindingView;
use sx_core::value_object::severity::Severity;
use sx_integrations::{IncidentEvent, IncidentKind};
use tracing::{info, warn};

use crate::adapters::incident_sinks::IncidentSinkFanOut;

/// Parse the wire severity string into the domain [`Severity`].
fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" | "informational" => Some(Severity::Info),
        _ => None,
    }
}

/// `FindingRepositoryPort` decorator that fires an incident alert on every
/// insert of a finding at or above `threshold`.
pub(crate) struct AlertingFindingRepo {
    inner: Arc<dyn FindingRepositoryPort>,
    fan_out: Arc<IncidentSinkFanOut>,
    threshold: Severity,
}

impl std::fmt::Debug for AlertingFindingRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertingFindingRepo")
            .field("threshold", &self.threshold)
            .field("sinks", &self.fan_out.len())
            .finish_non_exhaustive()
    }
}

impl AlertingFindingRepo {
    fn alert_for(&self, view: &FindingView) {
        if self.fan_out.is_empty() {
            return;
        }
        let Some(sev) = parse_severity(&view.severity) else {
            return;
        };
        if sev < self.threshold {
            return;
        }
        let event = IncidentEvent {
            kind: IncidentKind::FindingEmitted,
            severity: sev,
            tenant_id: view.tenant_id.clone(),
            title: {
                let mut t = format!("[{}] {}", view.severity.to_uppercase(), view.title);
                t.truncate(255);
                t
            },
            description: view.description.clone(),
            finding: Some(sx_integrations::FindingDigest {
                id: view.id.clone(),
                asset_id: view.asset_id.clone(),
                status: view.status.clone(),
                cve_id: view.cve_id.clone(),
            }),
            cvss: None,
            cwe: Vec::new(),
            mitre_attack: Vec::new(),
            compliance: sx_core::value_object::compliance::ComplianceTags::default(),
            source_url: None,
        };
        // Fire-and-forget: alerting must never block or fail the insert.
        let fan_out = Arc::clone(&self.fan_out);
        tokio::spawn(async move {
            let outcomes = fan_out.emit(&event).await;
            let failures = outcomes.iter().filter(|o| o.result.is_err()).count();
            if failures > 0 {
                warn!(
                    target: "adapters.alerting",
                    failures,
                    total = outcomes.len(),
                    "one or more incident sinks failed to receive the alert",
                );
            }
        });
    }
}

#[async_trait]
impl FindingRepositoryPort for AlertingFindingRepo {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        self.inner.list(tenant_id, offset, limit).await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
        self.inner.get(tenant_id, id).await
    }

    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        new_status: &str,
        comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        self.inner
            .update_status(tenant_id, id, new_status, comment)
            .await
    }

    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        let persisted = self.inner.insert(view).await?;
        self.alert_for(&persisted);
        Ok(persisted)
    }
}

/// Wrap `inner` with alerting when at least one sink is configured.
///
/// With no sinks the original port is returned unchanged (zero overhead),
/// so the composition root does not special-case the empty fan-out.
pub(crate) fn wrap(
    inner: Arc<dyn FindingRepositoryPort>,
    fan_out: IncidentSinkFanOut,
    threshold: Severity,
) -> Arc<dyn FindingRepositoryPort> {
    if fan_out.is_empty() {
        info!(
            target: "adapters.alerting",
            "no incident sinks configured — finding alerting disabled"
        );
        return inner;
    }
    info!(
        target: "adapters.alerting",
        threshold = %threshold,
        sinks = ?fan_out.names(),
        "finding alerting enabled"
    );
    Arc::new(AlertingFindingRepo {
        inner,
        fan_out: Arc::new(fan_out),
        threshold,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingRepo {
        inserted: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl FindingRepositoryPort for RecordingRepo {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(vec![])
        }
        async fn get(&self, _t: &str, _id: &str) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn update_status(
            &self,
            _t: &str,
            _id: &str,
            _s: &str,
            _c: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            self.inserted.lock().unwrap().push(view.id.clone());
            Ok(view)
        }
    }

    fn fv(sev: &str) -> FindingView {
        FindingView {
            id: "f1".into(),
            tenant_id: "t".into(),
            asset_id: "a".into(),
            severity: sev.into(),
            status: "open".into(),
            title: "SQLi".into(),
            description: "desc".into(),
            cvss: None,
            cve_id: None,
            first_seen: "1970-01-01T00:00:00Z".into(),
            last_seen: "1970-01-01T00:00:00Z".into(),
            metadata: None,
        }
    }

    #[test]
    fn severity_parsing_is_case_insensitive() {
        assert_eq!(parse_severity("CRITICAL"), Some(Severity::Critical));
        assert_eq!(parse_severity("info"), Some(Severity::Info));
        assert_eq!(parse_severity("nonsense"), None);
    }

    #[tokio::test]
    async fn empty_fanout_returns_inner_unchanged() {
        let inner: Arc<dyn FindingRepositoryPort> = Arc::new(RecordingRepo::default());
        let wrapped = wrap(
            Arc::clone(&inner),
            IncidentSinkFanOut::empty(),
            Severity::Critical,
        );
        // No sinks → same pointer, zero overhead.
        let out = wrapped.insert(fv("critical")).await.unwrap();
        assert_eq!(out.id, "f1");
    }

    #[tokio::test]
    async fn insert_delegates_and_returns_persisted() {
        let rec = Arc::new(RecordingRepo::default());
        let repo = AlertingFindingRepo {
            inner: rec.clone(),
            fan_out: Arc::new(IncidentSinkFanOut::empty()),
            threshold: Severity::Critical,
        };
        let out = repo.insert(fv("critical")).await.unwrap();
        assert_eq!(out.id, "f1");
        assert_eq!(rec.inserted.lock().unwrap().len(), 1);
    }
}
