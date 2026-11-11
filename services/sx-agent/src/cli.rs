//! Command-line interface for `sx-agent`.
//!
//! All flags double as environment variables (`SX_AGENT_*`) so the same
//! binary can be configured from a Helm values file via container env, or
//! locally from an operator's shell.

use std::path::PathBuf;

/// `SentinelX` in-cluster scan agent.
#[derive(Debug, clap::Parser)]
#[command(version, about = "SentinelX in-cluster scan agent")]
pub struct Cli {
    /// Collector endpoint URL (must be https unless --allow-insecure-transport + localhost).
    #[arg(long, env = "SX_AGENT_COLLECTOR_URL")]
    pub collector_url: url::Url,

    /// Env var name containing the HMAC shared secret (>= 32 bytes after env lookup).
    #[arg(
        long,
        default_value = "SX_AGENT_SHARED_SECRET",
        env = "SX_AGENT_SHARED_SECRET_ENV"
    )]
    pub shared_secret_env: String,

    /// Optional mTLS client cert path (PEM).
    #[arg(long, env = "SX_AGENT_MTLS_CERT")]
    pub mtls_cert: Option<PathBuf>,

    /// Optional mTLS client key path (PEM).
    #[arg(long, env = "SX_AGENT_MTLS_KEY")]
    pub mtls_key: Option<PathBuf>,

    /// Collect/report interval in seconds.
    #[arg(long, default_value_t = 60, env = "SX_AGENT_INTERVAL_SECS")]
    pub interval_secs: u64,

    /// Consecutive 4xx tolerated before exit.
    #[arg(long, default_value_t = 5, env = "SX_AGENT_FAILURE_TOLERANCE")]
    pub failure_tolerance: u32,

    /// Path to the container runtime socket. Optional; if absent, container
    /// inventory is skipped.
    #[arg(long, env = "SX_AGENT_RUNTIME_SOCKET")]
    pub runtime_socket: Option<PathBuf>,

    /// Allow plain http to a localhost collector. Off in production.
    #[arg(long, env = "SX_AGENT_ALLOW_INSECURE_TRANSPORT")]
    pub allow_insecure_transport: bool,

    /// Bump tracing to DEBUG.
    #[arg(long, short)]
    pub verbose: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parses_required_args_with_defaults() {
        let cli = Cli::try_parse_from([
            "sx-agent",
            "--collector-url",
            "https://collector.example.invalid/v1/inventory",
        ])
        .unwrap();
        assert_eq!(
            cli.collector_url.as_str(),
            "https://collector.example.invalid/v1/inventory"
        );
        assert_eq!(cli.shared_secret_env, "SX_AGENT_SHARED_SECRET");
        assert!(cli.mtls_cert.is_none());
        assert!(cli.mtls_key.is_none());
        assert!(cli.runtime_socket.is_none());
        assert!(!cli.allow_insecure_transport);
        assert!(!cli.verbose);
    }

    #[test]
    fn cli_default_interval_is_60() {
        let cli = Cli::try_parse_from([
            "sx-agent",
            "--collector-url",
            "https://collector.example.invalid/v1/inventory",
        ])
        .unwrap();
        assert_eq!(cli.interval_secs, 60);
        assert_eq!(cli.failure_tolerance, 5);
    }
}
