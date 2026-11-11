//! # `sx` — the `SentinelX` operator CLI.
//!
//! The binary exposes a small set of sub-commands for operator-level
//! tasks: verifying audit log chains, listing compliance controls,
//! and mapping a finding category to the controls it implicates.
//!
//! See `sx --help` for the full sub-command list, and each
//! sub-command's `--help` for argument details.
//!
//! ## Output mode
//!
//! All commands accept a global `--json` flag that switches to a
//! machine-readable JSON output, suitable for piping into other
//! tooling. The default is a human-friendly Markdown / plain text
//! rendering.
//!
//! ## Logging
//!
//! Diagnostic logs go through `tracing` and default to `INFO`. Pass
//! `-v` / `--verbose` to bump to `DEBUG`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Binary crates have no external consumers, so `pub` items inside
// `main.rs`-rooted modules are unreachable to anyone but us; that's
// fine for a CLI and the lint is informational.
#![allow(unreachable_pub)]
#![allow(
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc
)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

mod cmd;
mod output;

use crate::cmd::{
    audit, audit_tail, compliance, evidence, hash_password, rotate_keys, secrets, tenant_bootstrap,
    ueba, version,
};
use crate::output::OutputFormat;

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(
    name = "sx",
    bin_name = "sx",
    version,
    about = "SentinelX operator CLI",
    long_about = "Operator utilities for SentinelX: audit chain verification, \
                  compliance control catalog, finding-to-control mapping."
)]
struct Cli {
    /// Emit machine-readable JSON output where supported.
    #[arg(long, global = true)]
    json: bool,

    /// Increase log verbosity to DEBUG.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit-log utilities.
    Audit {
        #[command(subcommand)]
        cmd: audit::AuditCommand,
    },
    /// Compliance control catalog + mapper utilities.
    Compliance {
        #[command(subcommand)]
        cmd: compliance::ComplianceCommand,
    },
    /// Collect per-control evidence artifacts (SOC 2, ISO 27001).
    Evidence(evidence::EvidenceArgs),
    /// Generate a fresh 32-byte secret and write `KEY=base64` to a file.
    RotateKeys(rotate_keys::RotateKeysArgs),
    /// Bootstrap a new tenant and emit a Day-1 env file.
    TenantBootstrap(tenant_bootstrap::TenantBootstrapArgs),
    /// Emit an Argon2id PHC string for a password (reads stdin if no flag).
    HashPassword(hash_password::HashPasswordArgs),
    /// Replay the tail of an audit log NDJSON dump.
    AuditTail(audit_tail::AuditTailArgs),
    /// Commercial intel credential rotation utilities (CRIT-005).
    Secrets {
        #[command(subcommand)]
        cmd: secrets::SecretsCommand,
    },
    /// UEBA freeze-mode operator hooks (HIGH-010).
    Ueba {
        #[command(subcommand)]
        cmd: ueba::UebaCommand,
    },
    /// Print the CLI version.
    Version,
}

fn init_tracing(verbose: bool) {
    let default_level = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level.to_string()));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let fmt = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    };

    match &cli.command {
        Command::Audit { cmd } => audit::run(cmd, fmt),
        Command::Compliance { cmd } => {
            compliance::run(cmd, fmt)?;
            Ok(0)
        }
        Command::Evidence(args) => {
            evidence::run(args, fmt)?;
            Ok(0)
        }
        Command::RotateKeys(args) => rotate_keys::run(args),
        Command::TenantBootstrap(args) => tenant_bootstrap::run(args),
        Command::HashPassword(args) => hash_password::run(args),
        Command::AuditTail(args) => audit_tail::run(args),
        Command::Secrets { cmd } => secrets::run(cmd, fmt),
        Command::Ueba { cmd } => ueba::run(cmd, fmt),
        Command::Version => {
            version::run(fmt);
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    match run(cli) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            // Errors are user-facing; render them through stderr.
            print_err(&err);
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::print_stderr, clippy::disallowed_macros)]
fn print_err(err: &anyhow::Error) {
    // Operator-facing error rendering. We intentionally bypass the
    // `tracing` subscriber here because (a) errors must always reach
    // the user even when log filtering hides INFO, and (b) `tracing`
    // may not be initialised when CLI parsing itself fails.
    eprintln!("error: {err:#}");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn cli_parses_audit_verify_args() {
        let cli = Cli::try_parse_from([
            "sx",
            "audit",
            "verify",
            "--tenant",
            "00000000-0000-7000-8000-000000000001",
            "--from",
            "/tmp/dump.ndjson",
        ])
        .unwrap();
        match cli.command {
            Command::Audit {
                cmd: audit::AuditCommand::Verify(a),
            } => {
                assert_eq!(
                    a.tenant.as_deref(),
                    Some("00000000-0000-7000-8000-000000000001")
                );
                assert_eq!(
                    a.from.as_ref().map(|p| p.to_string_lossy().into_owned()),
                    Some("/tmp/dump.ndjson".to_owned())
                );
                assert!(a.to.is_none());
                assert!(a.signing_key_env.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cli_parses_audit_verify_hmac_args() {
        let cli = Cli::try_parse_from([
            "sx",
            "audit",
            "verify",
            "--signing-key-env",
            "SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER",
            "--source",
            "/tmp/dump.json",
        ])
        .unwrap();
        match cli.command {
            Command::Audit {
                cmd: audit::AuditCommand::Verify(a),
            } => {
                assert_eq!(
                    a.signing_key_env.as_deref(),
                    Some("SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER"),
                );
                assert_eq!(
                    a.source.as_ref().map(|p| p.to_string_lossy().into_owned()),
                    Some("/tmp/dump.json".to_owned())
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cli_parses_compliance_list_args() {
        let cli =
            Cli::try_parse_from(["sx", "compliance", "list", "--framework", "iso27001"]).unwrap();
        match cli.command {
            Command::Compliance {
                cmd: compliance::ComplianceCommand::List(a),
            } => {
                assert_eq!(a.framework, "iso27001");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cli_parses_compliance_map_args() {
        let cli = Cli::try_parse_from([
            "sx",
            "compliance",
            "map",
            "--category",
            "authentication",
            "--finding-id",
            "F-1",
        ])
        .unwrap();
        match cli.command {
            Command::Compliance {
                cmd: compliance::ComplianceCommand::Map(a),
            } => {
                assert_eq!(a.category, "authentication");
                assert_eq!(a.finding_id, "F-1");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cli_parses_compliance_report_args() {
        let cli = Cli::try_parse_from([
            "sx",
            "compliance",
            "report",
            "--framework",
            "pci-dss",
            "--out",
            "/tmp/report.pdf",
            "--source",
            "/tmp/mapping.md",
        ])
        .unwrap();
        match cli.command {
            Command::Compliance {
                cmd: compliance::ComplianceCommand::Report(a),
            } => {
                assert_eq!(a.framework, compliance::ComplianceFramework::PciDss);
                assert_eq!(a.out.to_string_lossy(), "/tmp/report.pdf");
                assert_eq!(
                    a.source.as_ref().map(|p| p.to_string_lossy().into_owned()),
                    Some("/tmp/mapping.md".to_owned())
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cli_json_flag_parsed() {
        let cli = Cli::try_parse_from(["sx", "--json", "version"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn cli_verbose_flag_parsed() {
        let cli = Cli::try_parse_from(["sx", "-v", "version"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn cli_version_subcommand_runs() {
        // Direct call: side-effecting print, but must not panic.
        version::run(OutputFormat::Human);
    }
}
