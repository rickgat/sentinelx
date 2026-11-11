//! Integration test for M1 (SX-REVIEW-002 carry-over): the dev config must
//! ship with a short `server.shutdown_timeout` so a kill→restart cycle does
//! not stall on a 30-second drain window, while the production template must
//! preserve the long timeout that lets in-flight requests drain on SIGTERM.
//!
//! This test exercises the documented public loader entry point
//! (`sx_config::load_from`) rather than the inner schema deserializer so
//! that any regression in the YAML, the layered loader, or the
//! cross-field invariant checks is caught here.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use figment::Jail;
use sx_config::load_from;

/// Workspace-root `config/` directory. The test file lives at
/// `crates/sx-config/tests/`, so we walk two levels up from the crate's
/// `CARGO_MANIFEST_DIR` to reach the workspace root.
fn workspace_config_dir() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root must be two levels above the crate manifest")
        .join("config")
}

/// Loads a YAML via the public loader inside a `figment::Jail` so ambient
/// `SENTINELX__*` environment variables from the developer shell cannot
/// leak in and mask a regression in the YAML itself.
fn load_yaml(name: &str) -> sx_config::Settings {
    let path = workspace_config_dir().join(name);
    assert!(
        path.exists(),
        "expected workspace config file to exist: {}",
        path.display()
    );

    let mut loaded: Option<sx_config::Settings> = None;
    Jail::expect_with(|_jail| {
        // `Jail::expect_with` scrubs the environment of any `SENTINELX__*`
        // overrides set by the developer's shell, so the file is the sole
        // source of truth for this assertion.
        let settings = load_from(Some(&path)).map_err(|e| e.to_string())?;
        loaded = Some(settings);
        Ok(())
    });
    loaded.expect("Jail::expect_with populated the slot on success")
}

#[test]
fn dev_example_yaml_uses_short_shutdown_timeout() {
    let settings = load_yaml("sentinelx.dev.example.yaml");
    let timeout = settings.server.shutdown_timeout;
    assert!(
        timeout >= Duration::from_secs(1) && timeout <= Duration::from_secs(5),
        "dev example shutdown_timeout must be in [1s, 5s] for fast \
         kill->restart loops (M1); found {timeout:?}. If you intentionally \
         tuned this within the band, update the assertion. If you reverted \
         to 30s, see docs/SPRINT_HARDENING_HANDOFF.md §1 M1."
    );
}

#[test]
fn prod_template_yaml_keeps_long_shutdown_timeout() {
    let settings = load_yaml("sentinelx.example.yaml");
    let timeout = settings.server.shutdown_timeout;
    assert!(
        timeout >= Duration::from_secs(30),
        "production template shutdown_timeout must be >= 30s so in-flight \
         requests can drain on SIGTERM (M1 invariant); found {timeout:?}."
    );
}
