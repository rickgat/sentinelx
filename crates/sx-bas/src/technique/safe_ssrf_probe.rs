//! `SafeSsrfProbe` — MITRE T1190.
//!
//! In a production wiring, this technique would POST to a target URL with a
//! header pointing at an out-of-band (OOB) collaborator base URL and then
//! wait for the OOB collaborator (`sx-collab`) to observe a callback — a
//! standard, non-destructive SSRF detection pattern.
//!
//! In **Phase-1** this stub:
//!
//! - validates `target_url` and `oob_base_url` are parseable,
//! - records the URL it WOULD have hit,
//! - returns [`StepResult::Simulated`] without performing any real I/O.
//!
//! Wiring a real HTTP client and `sx-collab` integration is **Phase-3.5**
//! and is gated by a `dangerous_execution` feature flag that is never
//! enabled in this crate.
//!
//! `max_mode = SafeInteractive`.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::simulation::{EvidenceRecord, SimulationStepContext, StepResult};
use crate::model::technique::{AttackTechnique, Capabilities, IntensityHint, MitreTag};

/// Safe-only SSRF probe stub.
#[derive(Debug, Clone)]
pub struct SafeSsrfProbe {
    target_url: String,
    oob_base_url: String,
}

impl SafeSsrfProbe {
    /// Construct a probe. URLs are validated lazily in `step`.
    #[must_use]
    pub const fn new(target_url: String, oob_base_url: String) -> Self {
        Self {
            target_url,
            oob_base_url,
        }
    }

    fn validate_urls(&self) -> Result<(String, String), BasError> {
        Self::validate_url(&self.target_url, "target_url")?;
        Self::validate_url(&self.oob_base_url, "oob_base_url")?;
        Ok((self.target_url.clone(), self.oob_base_url.clone()))
    }

    /// Minimal, dependency-free URL validation: must start with `http://` or
    /// `https://`, contain a non-empty host component, and contain no
    /// whitespace.
    ///
    /// We deliberately avoid pulling in the `url` crate here — full parsing
    /// is not needed for a phase-1 simulated stub, and the orchestrator
    /// performs its own validation upstream.
    fn validate_url(raw: &str, field: &str) -> Result<(), BasError> {
        let lowered = raw.trim();
        if lowered.chars().any(char::is_whitespace) {
            return Err(BasError::invalid_input(format!(
                "invalid {field}: contains whitespace",
            )));
        }
        let rest = if let Some(r) = lowered.strip_prefix("https://") {
            r
        } else if let Some(r) = lowered.strip_prefix("http://") {
            r
        } else {
            return Err(BasError::invalid_input(format!(
                "invalid {field}: must start with http:// or https://",
            )));
        };
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() {
            return Err(BasError::invalid_input(format!(
                "invalid {field}: missing host",
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl AttackTechnique for SafeSsrfProbe {
    fn id(&self) -> &'static str {
        "safe_ssrf_probe_v1"
    }

    fn mitre(&self) -> MitreTag {
        MitreTag::new("TA0001", "T1190", None)
    }

    fn max_mode(&self) -> AttackMode {
        AttackMode::SafeInteractive
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            intensity: IntensityHint::Medium,
            // Advertised intent — even though the stub does not actually
            // egress.
            network_egress: true,
            destructive: false,
        }
    }

    async fn step(&self, ctx: SimulationStepContext) -> Result<StepResult, BasError> {
        let (target, oob) = self.validate_urls()?;

        // Phase-1: short-circuit to Simulated. Real HTTP client wiring +
        // sx-collab integration is Phase-3.5 and is permanently disabled in
        // this crate.
        let mut details = HashMap::new();
        details.insert("target_url".to_owned(), target.clone());
        details.insert("oob_base_url".to_owned(), oob);
        details.insert("phase".to_owned(), "phase-1-simulated".to_owned());

        let record = EvidenceRecord {
            technique_id: self.id().to_owned(),
            mode: ctx.mode,
            tenant_id: ctx.tenant_id,
            engagement_id: ctx.engagement_id,
            summary: format!("safe_ssrf_probe would-hit target={target}"),
            details: details.clone(),
            recorded_at: time::OffsetDateTime::now_utc(),
        };
        ctx.evidence_sink.record(record).await?;

        Ok(StepResult::Simulated {
            summary: format!("safe_ssrf_probe simulated against {target}"),
            details,
        })
    }
}

#[cfg(test)]
// Tests use `panic!` for unexpected-variant assertions.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::SafeSsrfProbe;
    use crate::model::mode::AttackMode;
    use crate::model::simulation::{InMemoryEvidenceSink, SimulationStepContext, StepResult};
    use crate::model::technique::AttackTechnique;
    use std::sync::Arc;
    use sx_core::value_object::ids::{EngagementId, TenantId};
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Notify;

    fn ctx(sink: Arc<InMemoryEvidenceSink>) -> SimulationStepContext {
        SimulationStepContext {
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            mode: AttackMode::SafeInteractive,
            kill_switch_signal: Arc::new(Notify::new()),
            deadline: OffsetDateTime::now_utc() + Duration::seconds(30),
            evidence_sink: sink,
        }
    }

    #[tokio::test]
    async fn safe_ssrf_probe_returns_simulated_for_well_formed_url() {
        let t = SafeSsrfProbe::new(
            "https://victim.example/x".into(),
            "https://oob.example/y".into(),
        );
        let sink = Arc::new(InMemoryEvidenceSink::new());
        let out = t.step(ctx(sink.clone())).await.unwrap();
        match out {
            StepResult::Simulated { details, .. } => {
                assert_eq!(
                    details.get("target_url").unwrap(),
                    "https://victim.example/x"
                );
                assert_eq!(details.get("phase").unwrap(), "phase-1-simulated");
            }
            other => panic!("expected Simulated, got {other:?}"),
        }
        assert_eq!(sink.len().await, 1);
    }

    #[tokio::test]
    async fn safe_ssrf_probe_rejects_malformed_urls() {
        let t = SafeSsrfProbe::new("not-a-url".into(), "https://oob.example".into());
        let sink = Arc::new(InMemoryEvidenceSink::new());
        assert!(t.step(ctx(sink)).await.is_err());
    }
}
