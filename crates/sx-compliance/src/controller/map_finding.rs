//! `MapFindingToControlsUseCase` — finding → affected controls.

use std::sync::Arc;

use tracing::instrument;

use crate::error::ComplianceError;
use crate::model::control::Control;
use crate::model::mapping::FindingCategory;
use crate::service::catalog::ControlCatalog;
use crate::service::mapper::ControlMapper;

/// Caller-supplied finding metadata, distilled to the subset the mapper
/// actually consumes.
#[derive(Debug, Clone)]
pub struct MapFindingInput {
    /// Identifier of the originating finding (free-form; usually a UUID
    /// string sourced from `sx-core::value_object::ids::FindingId`).
    pub finding_id: String,
    /// Category that classifies the finding.
    pub category: FindingCategory,
    /// Severity as a lowercase string — preserved in the output but not
    /// used by the mapper. Kept for future-extension and to round-trip
    /// cleanly through the CLI.
    pub severity_str: String,
}

/// Use-case result: the originating finding plus the controls it implicates.
#[derive(Debug, Clone)]
pub struct MapFindingOutput {
    /// Echoes [`MapFindingInput::finding_id`].
    pub finding_id: String,
    /// Controls that the finding implicates, in catalog order.
    pub controls: Vec<Control>,
}

/// Application use-case orchestrating [`ControlMapper`] for one finding.
#[derive(Debug, Clone)]
pub struct MapFindingToControlsUseCase {
    mapper: ControlMapper,
}

impl MapFindingToControlsUseCase {
    /// Construct a use-case bound to `catalog`.
    #[must_use]
    pub fn new(catalog: Arc<ControlCatalog>) -> Self {
        Self {
            mapper: ControlMapper::new(catalog),
        }
    }

    /// Execute the mapping. Returns [`ComplianceError::InvalidInput`] if
    /// `finding_id` is empty (whitespace counts as empty after trim).
    #[instrument(skip(self), fields(finding_id = %input.finding_id, category = %input.category))]
    pub fn execute(&self, input: &MapFindingInput) -> Result<MapFindingOutput, ComplianceError> {
        if input.finding_id.trim().is_empty() {
            return Err(ComplianceError::invalid_input(
                "finding_id must not be empty",
            ));
        }
        let controls = self.mapper.for_category(input.category);
        Ok(MapFindingOutput {
            finding_id: input.finding_id.clone(),
            controls,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn use_case() -> MapFindingToControlsUseCase {
        MapFindingToControlsUseCase::new(ControlCatalog::shared())
    }

    #[test]
    fn map_finding_use_case_returns_controls_for_known_category() {
        let input = MapFindingInput {
            finding_id: "F-123".into(),
            category: FindingCategory::Authentication,
            severity_str: "high".into(),
        };
        let out = use_case().execute(&input).unwrap();
        assert_eq!(out.finding_id, "F-123");
        assert!(!out.controls.is_empty());
    }

    #[test]
    fn map_finding_use_case_rejects_empty_finding_id() {
        let input = MapFindingInput {
            finding_id: "  ".into(),
            category: FindingCategory::Logging,
            severity_str: "low".into(),
        };
        let r = use_case().execute(&input);
        assert!(matches!(r, Err(ComplianceError::InvalidInput(_))));
    }

    #[test]
    fn map_finding_use_case_returns_nonempty_for_every_category() {
        // Documents the guarantee that no shipped category falls through
        // to an empty mapping — equivalent to the "no unmappable
        // category" check requested by the spec.
        let uc = use_case();
        for cat in FindingCategory::all() {
            let out = uc
                .execute(&MapFindingInput {
                    finding_id: "F".into(),
                    category: *cat,
                    severity_str: "info".into(),
                })
                .unwrap();
            assert!(
                !out.controls.is_empty(),
                "category {cat:?} produced no controls"
            );
        }
    }
}
