//! [`FalcoIngestService`] — the public ingestion facade.
//!
//! Wires authentication, parsing, normalisation, finding emission, and
//! audit recording into a single use case the HTTP handler invokes.
//!
//! The service accepts a body shaped as either:
//!
//! - a single Falco alert object, or
//! - a JSON array of Falco alert objects (falcosidekick batching).
//!
//! Each accepted alert produces one normalised [`OcsfEvent`] and one
//! [`RuntimeFinding`]. The whole batch is summarised in a single audit
//! row.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sx_log_ingest::schema::ocsf::OcsfEvent;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::alert::FalcoAlert;
use crate::asset::{resolve_asset_id, AssetHint};
use crate::audit::{AuditOutcome, IngestionAuditEvent, IngestionAuditSink};
use crate::auth::verify_hmac;
use crate::error::RuntimeError;
use crate::finding::{map_priority, RuntimeFinding};
use crate::normalize::falco_to_ocsf;
use crate::override_audit::{OverrideAuditEvent, OverrideAuditSink};
use crate::override_store::OverrideStore;
use crate::overrides::{
    evaluate as evaluate_override, OverrideAction, OverrideDecision, RuleOverride,
};
use crate::tenant_key::TenantKeyStore;

/// Outcome of an accepted ingestion call: one [`RuntimeFinding`] +
/// one [`OcsfEvent`] per alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionReport {
    /// Findings emitted, one per accepted alert.
    pub findings: Vec<RuntimeFinding>,
    /// OCSF events emitted alongside the findings.
    pub ocsf_events: Vec<OcsfEvent>,
    /// Number of alerts the batch carried.
    pub alert_count: usize,
    /// Number of alerts accepted (= `findings.len()`).
    pub accepted: usize,
    /// Number of alerts rejected (typically `0` once the batch is
    /// authorised; non-zero only when alerts have undecodable
    /// priorities — currently impossible since `FalcoPriority` derive is
    /// total).
    pub rejected: usize,
    /// HIGH-006 — Number of alerts suppressed by a tenant-scoped
    /// `Deny` override. Independent of `rejected` (which is reserved
    /// for hard parse failures); suppressed alerts are an
    /// admin-policy decision and the audit row records the matching
    /// rule + subkey.
    #[serde(default)]
    pub suppressed: usize,
    /// HIGH-006 — Number of alerts whose severity was bumped by an
    /// `Escalate` override.
    #[serde(default)]
    pub escalated: usize,
    /// HIGH-006 — Number of alerts whose severity was dropped by a
    /// `Downgrade` override.
    #[serde(default)]
    pub downgraded: usize,
}

/// The Falco ingestion facade. Cheap to clone — every field is `Arc`.
#[derive(Clone)]
pub struct FalcoIngestService {
    key_store: TenantKeyStore,
    audit: Arc<dyn IngestionAuditSink>,
    /// HIGH-006 — Per-tenant override store. The `Arc<dyn …>` is
    /// `Send + Sync` so it can be cheaply cloned alongside the service.
    overrides: Arc<dyn OverrideStore>,
    /// HIGH-006 — Sink for override application audit rows.
    override_audit: Arc<dyn OverrideAuditSink>,
}

impl std::fmt::Debug for FalcoIngestService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FalcoIngestService").finish_non_exhaustive()
    }
}

impl FalcoIngestService {
    /// Construct a service backed by `key_store` for HMAC keys and
    /// `audit` for ingestion-batch rows.
    ///
    /// Override consultation is disabled — the HIGH-006 store is wired
    /// up as a [`crate::override_store::MemOverrideStore`] containing
    /// no rows and the override audit sink defaults to a no-op. Call
    /// [`FalcoIngestService::with_overrides`] to enable runtime
    /// policy enforcement.
    #[must_use]
    pub fn new(key_store: TenantKeyStore, audit: Arc<dyn IngestionAuditSink>) -> Self {
        Self {
            key_store,
            audit,
            overrides: Arc::new(crate::override_store::MemOverrideStore::new()),
            override_audit: Arc::new(crate::override_audit::NullOverrideAuditSink),
        }
    }

    /// Construct a service with an explicit HIGH-006 override store and
    /// audit sink. The composition root wires the production Postgres
    /// store + the hash-chained audit forwarder.
    #[must_use]
    pub fn with_overrides(
        key_store: TenantKeyStore,
        audit: Arc<dyn IngestionAuditSink>,
        overrides: Arc<dyn OverrideStore>,
        override_audit: Arc<dyn OverrideAuditSink>,
    ) -> Self {
        Self {
            key_store,
            audit,
            overrides,
            override_audit,
        }
    }

    /// Authenticate + ingest one batch of Falco alerts. The body bytes
    /// must be exactly what was signed; the caller is responsible for
    /// not mutating them before invoking the service.
    ///
    /// # Errors
    ///
    /// * [`RuntimeError::UnknownTenant`] — no signing key for the tenant.
    /// * [`RuntimeError::InvalidSignature`] — HMAC mismatch.
    /// * [`RuntimeError::ReplayWindowExceeded`] — timestamp outside the
    ///   replay window.
    /// * [`RuntimeError::BadPayload`] — body is not a Falco alert or
    ///   array of Falco alerts.
    /// * [`RuntimeError::Audit`] — the audit sink rejected the batch row.
    #[allow(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "ingest orchestrates auth → parse → override eval → audit; \
                  HIGH-006 added the override branch which pushed the function past \
                  default thresholds. Splitting further would just spray state."
    )]
    pub async fn ingest(
        &self,
        tenant_id: &str,
        timestamp: i64,
        signature_header: Option<&str>,
        body: &[u8],
        now: i64,
    ) -> Result<IngestionReport, RuntimeError> {
        // 1. Resolve tenant key + verify HMAC. Failures here are audited
        //    as `Rejected` with no body content recorded.
        let key = match self.key_store.key_for_tenant(tenant_id).await {
            Ok(k) => k,
            Err(e) => {
                self.audit_reject(tenant_id, 0, "unknown tenant").await?;
                return Err(e);
            }
        };

        if let Err(e) = verify_hmac(&key, timestamp, body, signature_header, now) {
            let reason = match e {
                RuntimeError::ReplayWindowExceeded => "replay window",
                _ => "signature",
            };
            self.audit_reject(tenant_id, 0, reason).await?;
            return Err(e);
        }

        // 2. Parse the body — single object or array.
        let alerts = match parse_body(body) {
            Ok(a) => a,
            Err(e) => {
                self.audit_reject(tenant_id, 0, "bad payload").await?;
                return Err(e);
            }
        };

        let alert_count = alerts.len();
        let received_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));

        let mut report = IngestionReport {
            findings: Vec::with_capacity(alert_count),
            ocsf_events: Vec::with_capacity(alert_count),
            alert_count,
            accepted: 0,
            rejected: 0,
            suppressed: 0,
            escalated: 0,
            downgraded: 0,
        };

        // HIGH-006 — Pre-load the tenant's overrides once for the whole
        // batch. Failure here drops to "no overrides" (pass-through) and
        // is logged; we never reject the batch because the override
        // table is unreachable.
        let overrides: Vec<RuleOverride> = match self.overrides.list_for_tenant(tenant_id).await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(
                    target: "sx_runtime",
                    tenant_id,
                    error = %err,
                    "override store unavailable; processing batch without overrides",
                );
                Vec::new()
            }
        };

        for alert in &alerts {
            let base_severity = map_priority(alert.priority);
            let decision = if overrides.is_empty() {
                OverrideDecision::PassThrough
            } else {
                evaluate_override(&overrides, alert, base_severity)
            };

            let (final_severity, override_audit_event) = match &decision {
                OverrideDecision::PassThrough => (base_severity, None),
                OverrideDecision::Applied {
                    action,
                    matched_subkey,
                    resolved_severity,
                } => {
                    let row_reason = overrides
                        .iter()
                        .find(|r| r.rule_name == alert.rule && &r.subkey == matched_subkey)
                        .map_or_else(String::new, |r| r.reason.clone());
                    let ev = OverrideAuditEvent::application(
                        tenant_id,
                        &alert.rule,
                        matched_subkey,
                        *action,
                        &row_reason,
                        base_severity,
                        *resolved_severity,
                    );
                    (resolved_severity.unwrap_or(base_severity), Some(ev))
                }
            };

            if decision.is_deny() {
                report.suppressed += 1;
                if let Some(ev) = override_audit_event {
                    if let Err(err) = self.override_audit.record(ev).await {
                        return Err(RuntimeError::Audit(err.to_string()));
                    }
                }
                tracing::info!(
                    target: "sx_runtime",
                    tenant_id,
                    rule = alert.rule,
                    "alert suppressed by tenant override",
                );
                continue;
            }

            // Either pass-through, escalated, or downgraded. Bookkeep
            // the escalate/downgrade counters before we drop the
            // decision.
            match &decision {
                OverrideDecision::Applied {
                    action: OverrideAction::Escalate,
                    ..
                } => report.escalated += 1,
                OverrideDecision::Applied {
                    action: OverrideAction::Downgrade,
                    ..
                } => report.downgraded += 1,
                _ => {}
            }

            if let Some(ev) = override_audit_event {
                if let Err(err) = self.override_audit.record(ev).await {
                    return Err(RuntimeError::Audit(err.to_string()));
                }
            }

            // Re-derive the OCSF event using the post-override severity
            // so downstream correlators see the operator's view rather
            // than Falco's raw priority.
            let mut ocsf = falco_to_ocsf(alert, tenant_id, &received_at);
            ocsf.severity_id = final_severity.to_ocsf().as_id();
            let hint = AssetHint::from_alert(alert);
            let asset_id = resolve_asset_id(&hint);
            let time = if alert.time.is_empty() {
                received_at.clone()
            } else {
                alert.time.clone()
            };
            let finding = RuntimeFinding {
                finding_id: Uuid::now_v7().to_string(),
                tenant_id: tenant_id.to_owned(),
                rule: alert.rule.clone(),
                severity: final_severity,
                time,
                asset_id,
                container_image: hint.image.map(str::to_owned),
                pod_name: hint.pod.map(str::to_owned),
                namespace: hint.namespace.map(str::to_owned),
                source: alert.source.clone(),
                tags: alert.tags.clone(),
                output: alert.output.clone(),
            };
            report.ocsf_events.push(ocsf);
            report.findings.push(finding);
            report.accepted += 1;
        }

        // 3. Record one audit row for the whole batch.
        let outcome = if report.rejected == 0 {
            AuditOutcome::Accepted
        } else if report.accepted == 0 {
            AuditOutcome::Rejected
        } else {
            AuditOutcome::Partial
        };
        let audit_ev = IngestionAuditEvent::new(
            tenant_id,
            report.alert_count,
            report.accepted,
            report.rejected,
            outcome,
            None,
        );
        if let Err(e) = self.audit.record(audit_ev).await {
            return Err(RuntimeError::Audit(e.to_string()));
        }

        tracing::info!(
            target: "sx_runtime",
            tenant_id,
            alert_count = report.alert_count,
            accepted = report.accepted,
            "runtime ingestion batch processed",
        );
        Ok(report)
    }

    async fn audit_reject(
        &self,
        tenant_id: &str,
        alert_count: usize,
        reason: &str,
    ) -> Result<(), RuntimeError> {
        let ev = IngestionAuditEvent::new(
            tenant_id,
            alert_count,
            0,
            alert_count,
            AuditOutcome::Rejected,
            Some(reason.to_owned()),
        );
        self.audit
            .record(ev)
            .await
            .map_err(|e| RuntimeError::Audit(e.to_string()))
    }
}

/// Parse the request body as either a single Falco alert or a JSON array
/// of alerts.
fn parse_body(body: &[u8]) -> Result<Vec<FalcoAlert>, RuntimeError> {
    // Try array first — Falco / falcosidekick batched delivery.
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| RuntimeError::BadPayload)?;
    match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(|v| serde_json::from_value::<FalcoAlert>(v).map_err(|_| RuntimeError::BadPayload))
            .collect(),
        v => {
            let alert: FalcoAlert =
                serde_json::from_value(v).map_err(|_| RuntimeError::BadPayload)?;
            Ok(vec![alert])
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::audit::RecordingAuditSink;
    use crate::auth::sign_body_for_tests;
    use secrecy::SecretString;
    use sx_secrets::{InMemoryProvider, SecretsProvider};

    fn store_with(tenant: &str, key: &str) -> TenantKeyStore {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store = TenantKeyStore::new(provider);
        let st = store.clone();
        let key = key.to_owned();
        let tenant = tenant.to_owned();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                st.put_key(&tenant, SecretString::from(key)).await.unwrap();
            });
        });
        store
    }

    fn body_single() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "rule": "Terminal shell in container",
            "priority": "Warning",
            "output": "shell spawned",
            "time": "2026-06-12T10:30:01Z",
            "source": "syscall",
            "output_fields": {
                "proc.name": "bash",
                "container.image.repository": "nginx",
                "k8s.pod.name": "web-1",
                "k8s.ns.name": "prod"
            }
        }))
        .unwrap()
    }

    fn body_array() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            {
                "rule": "Rule A",
                "priority": "Notice",
                "output": "a",
                "source": "syscall"
            },
            {
                "rule": "Rule B",
                "priority": "Critical",
                "output": "b",
                "source": "k8s_audit"
            }
        ]))
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ingest_single_alert_emits_one_finding() {
        let key = "k";
        let tenant = "t1";
        let store = store_with(tenant, key);
        let sink = RecordingAuditSink::new();
        let svc = FalcoIngestService::new(store, Arc::new(sink.clone()));
        let body = body_single();
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&SecretString::from(key.to_owned()), ts, &body);
        let report = svc.ingest(tenant, ts, Some(&sig), &body, ts).await.unwrap();
        assert_eq!(report.accepted, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.ocsf_events.len(), 1);
        assert_eq!(report.findings[0].rule, "Terminal shell in container");
        let audit = sink.snapshot().unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].outcome, AuditOutcome::Accepted);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ingest_array_emits_one_per_alert() {
        let key = "k";
        let tenant = "t1";
        let store = store_with(tenant, key);
        let sink = RecordingAuditSink::new();
        let svc = FalcoIngestService::new(store, Arc::new(sink.clone()));
        let body = body_array();
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&SecretString::from(key.to_owned()), ts, &body);
        let report = svc.ingest(tenant, ts, Some(&sig), &body, ts).await.unwrap();
        assert_eq!(report.accepted, 2);
        assert_eq!(
            report.findings[1].severity,
            crate::finding::RuntimeSeverity::Critical
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_tenant_is_rejected_and_audited() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store = TenantKeyStore::new(provider);
        let sink = RecordingAuditSink::new();
        let svc = FalcoIngestService::new(store, Arc::new(sink.clone()));
        let body = body_single();
        let err = svc
            .ingest("unknown", 1, Some("v1=ff"), &body, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::UnknownTenant));
        let audit = sink.snapshot().unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].outcome, AuditOutcome::Rejected);
        assert_eq!(audit[0].reason.as_deref(), Some("unknown tenant"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bad_signature_is_rejected_and_audited() {
        let key = "k";
        let tenant = "t1";
        let store = store_with(tenant, key);
        let sink = RecordingAuditSink::new();
        let svc = FalcoIngestService::new(store, Arc::new(sink.clone()));
        let body = body_single();
        let ts = 1_700_000_000;
        let err = svc
            .ingest(tenant, ts, Some("v1=deadbeef"), &body, ts)
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::InvalidSignature));
        let audit = sink.snapshot().unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].outcome, AuditOutcome::Rejected);
        assert_eq!(audit[0].reason.as_deref(), Some("signature"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn replay_window_rejected_and_audited() {
        let key = "k";
        let tenant = "t1";
        let store = store_with(tenant, key);
        let sink = RecordingAuditSink::new();
        let svc = FalcoIngestService::new(store, Arc::new(sink.clone()));
        let body = body_single();
        let ts = 1_000;
        let sig = sign_body_for_tests(&SecretString::from(key.to_owned()), ts, &body);
        let err = svc
            .ingest(tenant, ts, Some(&sig), &body, ts + 10_000)
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::ReplayWindowExceeded));
        let audit = sink.snapshot().unwrap();
        assert_eq!(audit[0].reason.as_deref(), Some("replay window"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_json_returns_bad_payload() {
        let key = "k";
        let tenant = "t1";
        let store = store_with(tenant, key);
        let sink = RecordingAuditSink::new();
        let svc = FalcoIngestService::new(store, Arc::new(sink.clone()));
        let body = b"not json".to_vec();
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&SecretString::from(key.to_owned()), ts, &body);
        let err = svc
            .ingest(tenant, ts, Some(&sig), &body, ts)
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::BadPayload));
    }
}
