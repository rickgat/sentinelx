//! Admin use-case: install a new [`Scanner`] into the
//! [`ScannerRegistry`].

use std::sync::Arc;

use crate::error::DiscoveryError;
use crate::service::registry::ScannerRegistry;
use crate::service::scanner::Scanner;

/// Wraps the registry behind a tiny use-case so callers go through a
/// single entry point. The registry itself is borrowed mutably.
#[derive(Debug)]
pub struct RegisterScannerUseCase<'a> {
    registry: &'a mut ScannerRegistry,
}

impl<'a> RegisterScannerUseCase<'a> {
    /// Wrap a mutable registry borrow.
    #[must_use]
    pub const fn new(registry: &'a mut ScannerRegistry) -> Self {
        Self { registry }
    }

    /// Execute the use-case.
    pub fn execute(&mut self, scanner: Arc<dyn Scanner>) -> Result<(), DiscoveryError> {
        let id = scanner.id();
        tracing::info!(scanner_id = %id, "registering scanner");
        self.registry.register(scanner)
    }
}
