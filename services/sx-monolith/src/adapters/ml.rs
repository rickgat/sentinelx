#![allow(dead_code)] // Phase-3.5: many fields are reserved for the next-turn wire-up.
//! Machine-learning adapter.
//!
//! Builds the `sx-ml` composition-root bundle:
//!
//! - An in-memory [`ModelRegistry`] for trained-model lookups.
//! - An [`Anonymiser`] keyed by the tenant-scoped pepper. The configured
//!   drop-set covers the obvious direct identifiers (`email`, `src_ip`,
//!   `user_id`); the hash-set is empty by default — operators can opt
//!   specific categorical features into hashing through a Phase-3.5
//!   configuration switch.

use std::collections::HashSet;
use std::sync::Arc;

use secrecy::SecretString;
use sx_ml::service::anonymiser::Anonymiser;
use sx_ml::service::registry::{InMemoryModelRegistry, ModelRegistry};
use tracing::info;

/// Bundle returned by [`build`].
pub(crate) struct MlBundle {
    /// Trained-model lookup.
    pub registry: Arc<dyn ModelRegistry>,
    /// PII drop / hash pipeline applied to every feature row before
    /// training or scoring.
    pub anonymiser: Arc<Anonymiser>,
}

/// Build the ML bundle.
///
/// `pepper` is the platform-wide secret pepper used to hash sensitive
/// categorical features. It must be stable across process restarts so
/// rolling models stay comparable.
#[allow(dead_code)] // parent composition root wires this in
pub(crate) fn build(pepper: &SecretString) -> MlBundle {
    // Drop set: direct identifiers we never want a trainer to observe.
    let mut drop_fields = HashSet::with_capacity(3);
    drop_fields.insert("email".to_owned());
    drop_fields.insert("src_ip".to_owned());
    drop_fields.insert("user_id".to_owned());

    let anonymiser = Arc::new(Anonymiser::new(pepper.clone(), drop_fields, HashSet::new()));
    let registry: Arc<dyn ModelRegistry> = Arc::new(InMemoryModelRegistry::new());

    info!(
        target = "adapters.ml.built",
        drop_fields = 3,
        hash_fields = 0,
        "ml bundle constructed",
    );

    MlBundle {
        registry,
        anonymiser,
    }
}
