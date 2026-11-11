//! [`Control`] — a single compliance requirement.
//!
//! A control is a piece of structured catalog data: an identifier
//! (`A.8.2`, `CC6.1`, `2.2.1`, `AC-3`, …), the framework that owns it,
//! a human-readable title and description, and a family / domain tag
//! used by the [`crate::service::mapper::ControlMapper`].

use serde::{Deserialize, Serialize};

use crate::model::framework::Framework;

/// A single, immutable compliance control.
///
/// Controls are owned by the [`crate::service::catalog::ControlCatalog`]
/// and shared by `Arc<ControlCatalog>` to use-cases. Cloning is cheap
/// because the data is small and held entirely in static-like memory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Control {
    /// Framework-local identifier (e.g. `"A.8.2"`, `"CC6.1"`).
    pub id: String,
    /// Owning framework.
    pub framework: Framework,
    /// Short human title.
    pub title: String,
    /// Longer description / intent.
    pub description: String,
    /// Family / domain tag, used to group controls in reports
    /// (e.g. `"Access Control"`, `"Logging & Monitoring"`).
    pub family: String,
}

impl Control {
    /// Construct a new [`Control`].
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        framework: Framework,
        title: impl Into<String>,
        description: impl Into<String>,
        family: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            framework,
            title: title.into(),
            description: description.into(),
            family: family.into(),
        }
    }
}
