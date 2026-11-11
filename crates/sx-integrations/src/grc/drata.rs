//! Drata REST connector — **stub**.
//!
//! Drata is intentionally a placeholder for this MVP — its connector
//! claims the [`GrcKind::Drata`] identity but returns
//! [`ConnectorError::Unimplemented`] for every push.
//!
//! When the production wiring lands (Drata API key + `connections/{id}`
//! REST endpoints), this connector will follow the same shape as
//! [`crate::grc::vanta::VantaConnector`].

use async_trait::async_trait;

use super::connector::{
    ComplianceEvidence, ConnectorError, FindingState, GrcConnector, GrcKind, PushOutcome,
};

/// Stub Drata connector. Every method returns
/// [`ConnectorError::Unimplemented`].
#[derive(Debug, Default, Clone)]
pub struct DrataConnector;

impl DrataConnector {
    /// Construct a Drata stub.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl GrcConnector for DrataConnector {
    fn kind(&self) -> GrcKind {
        GrcKind::Drata
    }

    async fn push_evidence(
        &self,
        _evidence: &ComplianceEvidence,
    ) -> Result<PushOutcome, ConnectorError> {
        Err(ConnectorError::Unimplemented)
    }

    async fn push_finding(&self, _finding: &FindingState) -> Result<PushOutcome, ConnectorError> {
        Err(ConnectorError::Unimplemented)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn evidence() -> ComplianceEvidence {
        ComplianceEvidence {
            id: "ev-1".into(),
            tenant_id: "t-1".into(),
            framework: "soc2".into(),
            control_id: "CC6.1".into(),
            finding_ref: "f-7".into(),
            observation_ref: "obs-3".into(),
            collected_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    fn finding() -> FindingState {
        FindingState {
            id: "f-9".into(),
            tenant_id: "t-1".into(),
            severity: "high".into(),
            status: "open".into(),
            title: "T".into(),
            description: "D".into(),
            first_seen: "2027-01-01T00:00:00Z".into(),
            last_seen: "2027-01-02T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn push_evidence_returns_unimplemented() {
        let c = DrataConnector::new();
        let err = c.push_evidence(&evidence()).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Unimplemented));
    }

    #[tokio::test]
    async fn push_finding_returns_unimplemented() {
        let c = DrataConnector::new();
        let err = c.push_finding(&finding()).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Unimplemented));
    }

    #[test]
    fn connector_kind_is_drata() {
        assert_eq!(DrataConnector::new().kind(), GrcKind::Drata);
    }
}
