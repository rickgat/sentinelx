//! `SentinelX` in-cluster scan agent — entry point.
//!
//! The agent runs as a Kubernetes `DaemonSet`. It inventories the host
//! (OS / kernel / mounts / listening sockets / containers) and reports the
//! result over mTLS-protected HTTPS to a `SentinelX` collector on a fixed
//! interval. Phase-3.5 wires the inventory + signer + HTTPS client into a
//! single runtime loop with cooperative shutdown.

#![forbid(unsafe_code)]
#![allow(unreachable_pub, clippy::redundant_pub_crate)]

mod cli;
mod error;
mod fingerprint;
mod inventory;
mod reporter;
mod runtime;

use std::sync::Arc;

use clap::Parser;
use tokio::sync::Notify;

use cli::Cli;
use reporter::http_client::CollectorClient;
use reporter::signer::HmacSigner;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .with_target(false)
        .init();

    // The workspace forbids `std::env::var` to steer services toward
    // `sx-config`. The agent reads exactly one operational secret out of
    // the environment by design (the env var name itself is operator-supplied
    // via `--shared-secret-env`), so we exempt this callsite with a narrow
    // allow rather than pull in `sx-config` for a single lookup.
    #[allow(clippy::disallowed_methods)]
    let secret_str = std::env::var(&cli.shared_secret_env)
        .map_err(|_| anyhow::anyhow!("shared secret env var {} not set", cli.shared_secret_env))?;
    let signer = HmacSigner::new(secrecy::SecretString::from(secret_str))?;

    let mtls = match (cli.mtls_cert.clone(), cli.mtls_key.clone()) {
        (Some(c), Some(k)) => Some((c, k)),
        _ => None,
    };
    let collector = CollectorClient::new(
        cli.collector_url.clone(),
        signer,
        mtls,
        cli.allow_insecure_transport,
    )?;

    let cfg = runtime::main_loop::RuntimeConfig {
        collector,
        interval: std::time::Duration::from_secs(cli.interval_secs),
        failure_tolerance: cli.failure_tolerance,
        runtime_socket: cli.runtime_socket.clone(),
        shutdown: Arc::new(Notify::new()),
    };

    tracing::info!(
        collector = %cli.collector_url,
        interval_secs = cli.interval_secs,
        failure_tolerance = cli.failure_tolerance,
        allow_insecure = cli.allow_insecure_transport,
        "sx-agent starting"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(runtime::main_loop::run(cfg))?;
    tracing::info!("sx-agent stopped cleanly");
    Ok(())
}
