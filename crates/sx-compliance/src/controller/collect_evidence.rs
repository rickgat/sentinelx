//! `CollectEvidenceUseCase` — append an [`Evidence`] record.

use async_trait::async_trait;
use time::OffsetDateTime;
use tracing::instrument;

use crate::error::ComplianceError;
use crate::model::evidence::Evidence;

/// Caller-supplied input for [`CollectEvidenceUseCase::execute`].
#[derive(Debug, Clone)]
pub struct CollectEvidenceInput {
    /// Control identifier this evidence supports.
    pub control_id: String,
    /// Free-form finding reference (typically a UUID).
    pub finding_ref: String,
    /// Free-form observation reference (e.g. scan run id).
    pub observation_ref: String,
}

/// Append-only writer for [`Evidence`] records.
///
/// Production implementations live downstream (Postgres in `sx-storage`).
/// Tests use an in-memory `Arc<Mutex<Vec<Evidence>>>` implementation.
#[async_trait]
pub trait EvidenceSink: Send + Sync + std::fmt::Debug {
    /// Persist `evidence`. The sink is append-only — implementations
    /// must not mutate or overwrite previously-stored records.
    async fn append(&self, evidence: &Evidence) -> Result<(), ComplianceError>;
}

/// Application use-case that stamps `collected_at` and writes to the sink.
#[derive(Debug)]
pub struct CollectEvidenceUseCase<S: EvidenceSink> {
    sink: S,
}

impl<S: EvidenceSink> CollectEvidenceUseCase<S> {
    /// Construct a use-case bound to `sink`.
    pub fn new(sink: S) -> Self {
        Self { sink }
    }

    /// Validate the input, stamp `collected_at = now()`, and append.
    ///
    /// Returns [`ComplianceError::InvalidInput`] when any of `control_id`,
    /// `finding_ref`, or `observation_ref` is empty after trimming.
    #[instrument(skip(self), fields(control = %input.control_id, finding = %input.finding_ref))]
    pub async fn execute(&self, input: CollectEvidenceInput) -> Result<Evidence, ComplianceError> {
        if input.finding_ref.trim().is_empty() {
            return Err(ComplianceError::invalid_input(
                "finding_ref must not be empty",
            ));
        }
        if input.control_id.trim().is_empty() {
            return Err(ComplianceError::invalid_input(
                "control_id must not be empty",
            ));
        }
        if input.observation_ref.trim().is_empty() {
            return Err(ComplianceError::invalid_input(
                "observation_ref must not be empty",
            ));
        }

        let evidence = Evidence::new(
            input.control_id,
            input.finding_ref,
            input.observation_ref,
            OffsetDateTime::now_utc(),
        );
        self.sink.append(&evidence).await?;
        Ok(evidence)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Debug, Default, Clone)]
    struct InMemorySink {
        store: Arc<Mutex<Vec<Evidence>>>,
    }

    impl InMemorySink {
        fn snapshot(&self) -> Vec<Evidence> {
            self.store.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl EvidenceSink for InMemorySink {
        async fn append(&self, evidence: &Evidence) -> Result<(), ComplianceError> {
            self.store.lock().unwrap().push(evidence.clone());
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn collect_evidence_appends_record() {
        let sink = InMemorySink::default();
        let uc = CollectEvidenceUseCase::new(sink.clone());
        let r = uc
            .execute(CollectEvidenceInput {
                control_id: "CC6.1".into(),
                finding_ref: "F-123".into(),
                observation_ref: "scan-42".into(),
            })
            .await
            .unwrap();
        assert_eq!(r.control_id, "CC6.1");
        let snap = sink.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].finding_ref, "F-123");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn collect_evidence_rejects_empty_finding_ref() {
        let sink = InMemorySink::default();
        let uc = CollectEvidenceUseCase::new(sink.clone());
        let r = uc
            .execute(CollectEvidenceInput {
                control_id: "CC6.1".into(),
                finding_ref: "   ".into(),
                observation_ref: "scan-42".into(),
            })
            .await;
        assert!(matches!(r, Err(ComplianceError::InvalidInput(_))));
        assert!(sink.snapshot().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn collect_evidence_rejects_empty_control_id() {
        let sink = InMemorySink::default();
        let uc = CollectEvidenceUseCase::new(sink.clone());
        let r = uc
            .execute(CollectEvidenceInput {
                control_id: String::new(),
                finding_ref: "F".into(),
                observation_ref: "scan-42".into(),
            })
            .await;
        assert!(matches!(r, Err(ComplianceError::InvalidInput(_))));
    }
}
