//! `SentinelX` monolith binary — composition root.
//!
//! Wires together every internal crate into a single runnable process:
//!
//! 1. `sx_config::load` parses configuration from layered YAML + env vars.
//! 2. `sx_telemetry::init` boots the tracing / metrics / OTLP stack.
//! 3. Concrete port adapters are constructed for every trait declared in
//!    [`sx_api::port`] and bundled into an [`sx_api::AppState`].
//! 4. The router is built and served until SIGINT / SIGTERM.
//!
//! Adapter wiring lives in [`adapters`] and is intentionally explicit so the
//! composition root remains easy to audit.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Binary crate: items in submodules are reachable only from `main.rs`, so
// the `unreachable_pub` lint and its clippy mirror `redundant_pub_crate`
// would force a choice between two false positives. Allow both at the bin
// level instead of decorating every adapter.
//
// The remaining `allow`s cover pedantic/nursery lints that fire on
// idiomatic in-memory adapter code (skip(offset as usize) on Vec, etc.).
// Each is documented inline next to the pattern that triggers it.
#![allow(
    unreachable_pub,
    clippy::redundant_pub_crate,
    // Phase-3 bundle constructors take `Arc`/Client/SecretString by value as
    // a documented ownership contract — they hand the value into a struct
    // field via `Arc::clone` or `clone`.
    clippy::needless_pass_by_value,
    // Doc backticks in DSL-style strings ("oci://", "AwsIamUser", …) are
    // intentionally unbacktick'd; the bin allow keeps them consistent.
    clippy::doc_markdown,
    // Some const fn candidates wrap trait method calls that cannot be const.
    clippy::missing_const_for_fn,
    // The composition root function is long by design — every sub-system has
    // its construction line.
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    // u64 pagination offsets pass into Iterator::skip(usize); on 64-bit
    // targets this is identity.
    clippy::cast_possible_truncation,
    // `MutexGuard` lifetimes in our two-step lock-and-borrow patterns.
    clippy::significant_drop_tightening,
    // Stub Result returns are kept for forward compatibility with the
    // Postgres adapters that replace these in-memory stubs.
    clippy::unnecessary_wraps,
    // `contains_key` + `insert` is intentional in the in-memory engagement
    // repository to mirror the Postgres `UPDATE … WHERE` semantics
    // (return NotFound when missing).
    clippy::map_entry,
    // `let Some(...) else` is more readable than `map_or_else` for these
    // short helpers.
    clippy::option_if_let_else,
    // Avoids a temporary allocation; clone_into is overkill for short
    // status strings.
    clippy::assigning_clones,
    // `Drop` on `MutexGuard` is intentionally significant in the lock
    // helpers.
    clippy::significant_drop_in_scrutinee,
    // Static, audited literals exercise `expect()` for documented
    // unreachable branches. The literal CVE id and rate-limiter config
    // here would only fail under a contract change in a sibling crate.
    clippy::expect_used,
)]
// Phase-3 test fixtures index into Vec results after asserting length —
// idiomatic for test code, but workspace lints deny indexing_slicing.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

mod adapters;
mod config_bridge;
mod telemetry_bridge;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use sx_api::build_router;
use sx_api::server::{serve, serve_with_tls};
use sx_config::schema::telemetry::LogLevel;

/// `sx-monolith` command-line arguments.
///
/// Kept intentionally tiny: the composition root takes its real
/// configuration from layered YAML + env vars (see `sx_config::load`).
/// Flags here exist only for operator ergonomics that cannot wait for
/// a config file edit + restart.
#[derive(Debug, Parser)]
#[command(
    name = "sx-monolith",
    bin_name = "sx-monolith",
    version,
    about = "SentinelX monolith — composition root binary",
    long_about = "Boots every internal crate into a single process. \
                  Configuration is loaded from the YAML file pointed at \
                  by SENTINELX_CONFIG (or the layered default search path) \
                  plus SENTINELX__* environment overrides."
)]
pub(crate) struct Args {
    /// Force the effective log level to `info`, overriding
    /// `telemetry.log_level` from the YAML config.
    ///
    /// Useful when the default `warn` dev config hides the
    /// "feature disabled; using in-memory stub" adapter-wiring
    /// messages and you want to confirm what is and isn't wired
    /// without editing the config file.
    #[arg(
        long,
        short = 'd',
        help = "Force log level to info regardless of telemetry.log_level config"
    )]
    pub(crate) diagnose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let settings = sx_config::load().context("load configuration")?;

    // M3 / SX-REVIEW-002: --diagnose forces info-level logging without
    // requiring a config file edit. The override is applied *before*
    // telemetry init so the very first log record honours the new
    // level.
    let override_level = args.diagnose.then_some(LogLevel::Info);
    let telemetry_cfg =
        telemetry_bridge::from_config_with_override(&settings.telemetry, override_level);
    let _guard = sx_telemetry::init(&telemetry_cfg).context("initialise telemetry")?;

    if args.diagnose {
        // Emit at warn so it surfaces even when the YAML config asks
        // for warn-or-above and override_level happens to coincide
        // with the configured level (idempotent --diagnose runs).
        tracing::warn!(
            target: "sx_monolith.diagnose",
            configured_level = ?settings.telemetry.log_level,
            effective_level = %telemetry_cfg.log_level,
            "--diagnose flag active: log level forced to info (overrides telemetry.log_level)",
        );
    }

    tracing::info!(
        service = %telemetry_cfg.service_name,
        environment = %telemetry_cfg.environment,
        bind = %settings.server.bind_addr,
        "sx-monolith starting",
    );

    let state = adapters::build_app_state(&settings)
        .await
        .context("build app state")?;
    let router = build_router(state);

    if settings.mtls.enabled {
        // Build the rustls server config from sx-mtls. The crate logs the
        // certificate fingerprint + expiry at load time; the composition
        // root deliberately never touches the chain or key bytes.
        let tls_config = sx_mtls::build_server_config(&settings.mtls)
            .map_err(|e| anyhow::anyhow!("mtls server config: {e}"))?;
        let arc_cfg = Arc::new(tls_config);
        let addr = settings.server.bind_addr;
        tracing::info!(bind = %addr, "tls enabled");
        serve_with_tls(router, addr, arc_cfg)
            .await
            .context("http server (tls)")?;
    } else {
        tracing::info!(bind = %settings.server.bind_addr, "tls disabled");
        serve(settings.server.clone(), router)
            .await
            .context("http server")?;
    }

    tracing::info!("sx-monolith stopped cleanly");
    Ok(())
}
