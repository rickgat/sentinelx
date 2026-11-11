//! Print helpers used by the command handlers.
//!
//! These helpers are deliberately tiny: they centralise the
//! `print_stdout` / disallowed-macros allows so the rest of the crate
//! can stay under the workspace clippy deny.
//!
//! All user-facing output funnels through here so the global `--json`
//! flag has a single switch-point. The workspace clippy config bans
//! `println!` everywhere by default; this file is the **only** place
//! where it is allowed, because the whole point of these helpers is to
//! produce stdout output for the operator. Diagnostic logging still
//! flows through `tracing` everywhere else in the crate.

#![allow(clippy::print_stdout, clippy::disallowed_macros)]

use serde::Serialize;

use sx_compliance::prelude::{Control, FindingCategory, Framework};

/// Output format for the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable plain text / Markdown.
    Human,
    /// Machine-readable JSON.
    Json,
}

/// Render a one-line success message.
pub fn print_line(line: &str) {
    println!("{line}");
}

/// Render a list of controls. For [`OutputFormat::Human`] this emits a
/// Markdown table; for [`OutputFormat::Json`] it emits a single
/// `serde_json::to_string_pretty` blob of the list.
pub fn print_controls(controls: &[Control], fmt: OutputFormat) -> anyhow::Result<()> {
    match fmt {
        OutputFormat::Human => {
            println!("| Framework | ID | Title | Family |");
            println!("| --------- | -- | ----- | ------ |");
            for c in controls {
                println!(
                    "| {} | {} | {} | {} |",
                    c.framework.code(),
                    escape_pipe(&c.id),
                    escape_pipe(&c.title),
                    escape_pipe(&c.family),
                );
            }
        }
        OutputFormat::Json => {
            let s = serde_json::to_string_pretty(controls)?;
            println!("{s}");
        }
    }
    Ok(())
}

/// Render a finding-mapping result: which controls are implicated by
/// the given category.
pub fn print_mapping(
    finding_id: &str,
    category: FindingCategory,
    controls: &[Control],
    fmt: OutputFormat,
) -> anyhow::Result<()> {
    match fmt {
        OutputFormat::Human => {
            println!("## Finding {finding_id} — category `{category}`");
            println!();
            print_controls(controls, OutputFormat::Human)?;
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct View<'a> {
                finding_id: &'a str,
                category: &'a str,
                controls: &'a [Control],
            }
            let view = View {
                finding_id,
                category: category.code(),
                controls,
            };
            let s = serde_json::to_string_pretty(&view)?;
            println!("{s}");
        }
    }
    Ok(())
}

/// One row of the per-tenant HMAC verify summary.
#[derive(Debug, Clone, Serialize)]
pub struct TenantSummary {
    /// Tenant id (UUID string).
    pub tenant: String,
    /// Number of entries observed for this tenant.
    pub entries: u64,
    /// First sequence number observed.
    pub first_seq: u64,
    /// Last sequence number observed.
    pub last_seq: u64,
    /// Either `"ok"` or `"fail"`.
    pub status: String,
    /// Optional explanation when `status` is `"fail"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Render the per-tenant HMAC verify summary table + final OK/FAIL.
pub fn print_hmac_verify_report(
    summaries: &[TenantSummary],
    overall_ok: bool,
    fmt: OutputFormat,
) -> anyhow::Result<()> {
    match fmt {
        OutputFormat::Human => {
            println!("| Tenant | Entries | First seq | Last seq | Status |");
            println!("| ------ | ------- | --------- | -------- | ------ |");
            for s in summaries {
                println!(
                    "| {} | {} | {} | {} | {} |",
                    escape_pipe(&s.tenant),
                    s.entries,
                    s.first_seq,
                    s.last_seq,
                    s.status,
                );
            }
            if overall_ok {
                println!("OK");
            } else {
                println!("FAIL");
            }
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct View<'a> {
                status: &'a str,
                tenants: &'a [TenantSummary],
            }
            let view = View {
                status: if overall_ok { "ok" } else { "fail" },
                tenants: summaries,
            };
            let s = serde_json::to_string_pretty(&view)?;
            println!("{s}");
        }
    }
    Ok(())
}

/// Render an HMAC verify failure on a specific tenant + seq.
pub fn print_hmac_verify_failure(tenant: &str, at_seq: u64, message: &str, fmt: OutputFormat) {
    match fmt {
        OutputFormat::Human => {
            println!("hmac chain divergence");
            println!("  tenant: {tenant}");
            println!("  seq   : {at_seq}");
            println!("  cause : {message}");
        }
        OutputFormat::Json => {
            println!(
                "{{\"status\":\"hmac_divergence\",\"tenant\":\"{tenant}\",\"at_seq\":{at_seq},\"cause\":\"{}\"}}",
                escape_json(message),
            );
        }
    }
}

/// Render an audit-verify success report.
pub fn print_verify_report(
    tenant: &str,
    entries_checked: u64,
    first_seq_ts: Option<&str>,
    last_seq_ts: Option<&str>,
    fmt: OutputFormat,
) -> anyhow::Result<()> {
    match fmt {
        OutputFormat::Human => {
            println!("✓ chain verified");
            println!("  entries: {entries_checked}");
            println!("  tenant : {tenant}");
            if let Some(first) = first_seq_ts {
                println!("  first  : {first}");
            }
            if let Some(last) = last_seq_ts {
                println!("  last   : {last}");
            }
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct View<'a> {
                status: &'a str,
                tenant: &'a str,
                entries: u64,
                first: Option<&'a str>,
                last: Option<&'a str>,
            }
            let view = View {
                status: "verified",
                tenant,
                entries: entries_checked,
                first: first_seq_ts,
                last: last_seq_ts,
            };
            let s = serde_json::to_string_pretty(&view)?;
            println!("{s}");
        }
    }
    Ok(())
}

/// Render an audit-verify divergence report.
pub fn print_verify_failure(tenant: &str, at_seq: u64, message: &str, fmt: OutputFormat) {
    match fmt {
        OutputFormat::Human => {
            println!("✗ chain divergence");
            println!("  tenant: {tenant}");
            println!("  seq   : {at_seq}");
            println!("  cause : {message}");
        }
        OutputFormat::Json => {
            // Hand-format to avoid a fallible serde call on this path.
            println!(
                "{{\"status\":\"divergence\",\"tenant\":\"{tenant}\",\"at_seq\":{at_seq},\"cause\":\"{}\"}}",
                escape_json(message),
            );
        }
    }
}

/// Render a single framework as a Markdown header banner.
pub fn print_framework_header(framework: Framework) {
    println!("## {} ({})", framework.label(), framework.code());
    println!();
}

fn escape_pipe(s: &str) -> String {
    s.replace('|', "\\|")
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}
