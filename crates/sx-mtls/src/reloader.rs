//! Hot-reloading certificate watcher.
//!
//! [`CertReloader`] keeps the last successfully loaded [`CertMaterial`]
//! behind a [`parking_lot::RwLock`] inside an [`Arc`]. A background
//! [`notify`] watcher reloads the chain whenever the configured
//! certificate file changes on disk; reload failures are logged but do
//! NOT clobber the currently-served chain.
//!
//! ## Atomicity
//!
//! Each successful reload replaces the entire [`CertMaterial`] under a
//! single write lock. Readers see either the old chain in full or the
//! new chain in full — never a half-applied update.
//!
//! ## Logging discipline
//!
//! The reloader only logs the certificate fingerprint and `not_after`
//! timestamp. Private-key bytes never reach `tracing`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;

use crate::error::MtlsError;
use crate::load::{load_pem_chain, CertMaterial};

/// Shared, hot-reloadable handle to a certificate chain.
///
/// Hold a clone of the [`CertReloader`] inside your TLS termination layer
/// and call [`CertReloader::current`] on every new connection to obtain
/// the currently-active material.
pub struct CertReloader {
    inner: Arc<Inner>,
    // Watcher is held to keep the background thread alive for the
    // lifetime of the reloader. Dropping `CertReloader` stops watching.
    _watcher: Option<RecommendedWatcher>,
}

struct Inner {
    cert_path: PathBuf,
    state: RwLock<Arc<CertMaterial>>,
}

impl std::fmt::Debug for CertReloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snapshot = self.inner.state.read();
        f.debug_struct("CertReloader")
            .field("cert_path", &self.inner.cert_path)
            .field("leaf_fingerprint_sha256", &snapshot.leaf_fingerprint_sha256)
            .field("leaf_not_after", &snapshot.leaf_not_after)
            .finish_non_exhaustive()
    }
}

impl CertReloader {
    /// Constructs a reloader that loads the chain from `cert_path` right
    /// now and then watches the file for changes.
    ///
    /// When `watch_filesystem` is `false`, only the manual
    /// [`Self::reload_now`] entry point will pick up changes — useful in
    /// tests where deterministic mtime-triggered reloads are easier than
    /// race-prone `notify` events.
    pub fn new(cert_path: impl Into<PathBuf>, watch_filesystem: bool) -> Result<Self, MtlsError> {
        let cert_path = cert_path.into();
        let material = load_pem_chain(&cert_path)?;
        let inner = Arc::new(Inner {
            cert_path,
            state: RwLock::new(Arc::new(material)),
        });

        let watcher = if watch_filesystem {
            Some(start_watcher(&inner)?)
        } else {
            None
        };

        Ok(Self {
            inner,
            _watcher: watcher,
        })
    }

    /// Returns a snapshot of the currently-loaded material. Cheap — the
    /// `Arc` is cloned under a brief read lock.
    pub fn current(&self) -> Arc<CertMaterial> {
        Arc::clone(&self.inner.state.read())
    }

    /// Re-reads the certificate file and swaps the loaded chain on
    /// success. Failures are returned to the caller AND emitted via
    /// `tracing::error!`; the previously-loaded chain remains in place.
    pub fn reload_now(&self) -> Result<(), MtlsError> {
        reload_into(&self.inner)
    }

    /// Returns the watched certificate path.
    pub fn cert_path(&self) -> &Path {
        &self.inner.cert_path
    }
}

fn start_watcher(inner: &Arc<Inner>) -> Result<RecommendedWatcher, MtlsError> {
    let watch_target = inner.cert_path.clone();
    let parent = watch_target
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let inner_for_cb = Arc::clone(inner);
    let handler = move |event: notify::Result<Event>| match event {
        Ok(evt) if evt.paths.iter().any(|p| p == &watch_target) => {
            if let Err(err) = reload_into(&inner_for_cb) {
                tracing::warn!(
                    target: "sx_mtls",
                    error = %err,
                    "hot-reload attempt failed; keeping previous chain"
                );
            }
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(
                target: "sx_mtls",
                error = %err,
                "filesystem watcher reported an error"
            );
        }
    };

    let mut watcher =
        notify::recommended_watcher(handler).map_err(|e| MtlsError::Watcher(e.to_string()))?;
    watcher
        .watch(&parent, RecursiveMode::NonRecursive)
        .map_err(|e| MtlsError::Watcher(e.to_string()))?;
    Ok(watcher)
}

fn reload_into(inner: &Inner) -> Result<(), MtlsError> {
    let fresh = load_pem_chain(&inner.cert_path)?;
    let new_fingerprint = fresh.leaf_fingerprint_sha256.clone();
    let new_not_after = fresh.leaf_not_after;
    {
        let mut guard = inner.state.write();
        *guard = Arc::new(fresh);
    }
    tracing::info!(
        target: "sx_mtls",
        path = %inner.cert_path.display(),
        fingerprint = %new_fingerprint,
        not_after = %new_not_after,
        "hot-reloaded mTLS certificate chain"
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::test_support::make_self_signed;

    #[test]
    fn reloader_initial_load_exposes_fingerprint() {
        let dir = tempdir().expect("tempdir");
        let (cert_pem, _) = make_self_signed(365);
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, cert_pem).expect("write cert");

        let reloader = CertReloader::new(&cert_path, false).expect("construct reloader");
        let snap = reloader.current();
        assert_eq!(snap.leaf_fingerprint_sha256.len(), 64);
        assert_eq!(reloader.cert_path(), cert_path.as_path());
    }

    #[test]
    fn reloader_swaps_chain_when_file_mtime_changes() {
        let dir = tempdir().expect("tempdir");
        let (cert_pem_a, _) = make_self_signed(365);
        let (cert_pem_b, _) = make_self_signed(180);
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, cert_pem_a).expect("write cert A");

        // Construct without the live filesystem watcher to keep the test
        // deterministic; we drive reload_now() explicitly.
        let reloader = CertReloader::new(&cert_path, false).expect("construct reloader");
        let fingerprint_a = reloader.current().leaf_fingerprint_sha256.clone();

        // Swap the file contents and trigger a manual reload.
        fs::write(&cert_path, cert_pem_b).expect("write cert B");
        reloader.reload_now().expect("reload_now must succeed");

        let fingerprint_b = reloader.current().leaf_fingerprint_sha256.clone();
        assert_ne!(
            fingerprint_a, fingerprint_b,
            "fingerprint must change after hot-reload"
        );
    }

    #[test]
    fn reloader_keeps_old_chain_on_failed_reload() {
        let dir = tempdir().expect("tempdir");
        let (cert_pem, _) = make_self_signed(365);
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, cert_pem).expect("write cert");

        let reloader = CertReloader::new(&cert_path, false).expect("construct reloader");
        let before = reloader.current().leaf_fingerprint_sha256.clone();

        // Corrupt the file. The reload must fail, but the in-memory chain
        // must remain untouched.
        fs::write(&cert_path, b"not a pem").expect("corrupt");
        let err = reloader
            .reload_now()
            .expect_err("corrupt reload must surface an error");
        assert!(matches!(err, MtlsError::EmptyPem { .. }), "got {err:?}");

        let after = reloader.current().leaf_fingerprint_sha256.clone();
        assert_eq!(before, after, "old chain must survive a failed reload");
    }
}
