#![allow(dead_code)] // Phase-3.5: many fields are reserved for the next-turn wire-up.
//! Compliance adapter.
//!
//! Builds the `sx-compliance` composition-root bundle. The catalog is the
//! static, pure-in-process [`ControlCatalog`] (ISO 27001, SOC 2, PCI DSS,
//! HIPAA, NIST 800-53, CIS AWS Foundations). The mapper use case is
//! constructed against that shared catalog.

use std::sync::Arc;

use sx_compliance::controller::map_finding::MapFindingToControlsUseCase;
use sx_compliance::service::catalog::ControlCatalog;
use tracing::info;

/// Bundle returned by [`build`].
pub(crate) struct ComplianceBundle {
    /// Shared control catalog.
    pub catalog: Arc<ControlCatalog>,
    /// Finding → controls mapping use case.
    pub mapper_use_case: Arc<MapFindingToControlsUseCase>,
}

/// Build the compliance bundle.
#[allow(dead_code)] // parent composition root wires this in
pub(crate) fn build() -> ComplianceBundle {
    let catalog = Arc::new(ControlCatalog::new());
    let mapper_use_case = Arc::new(MapFindingToControlsUseCase::new(Arc::clone(&catalog)));

    info!(
        target = "adapters.compliance.built",
        catalog = "static",
        "compliance bundle constructed",
    );

    ComplianceBundle {
        catalog,
        mapper_use_case,
    }
}
