//! `sx ueba freeze / unfreeze` — UEBA frozen-baseline operator hooks
//! (HIGH-010).
//!
//! Usage:
//!
//! ```text
//! sx ueba freeze   --user <user_id> [--api-url URL] [--token TOK] [--reason "...""]
//! sx ueba unfreeze --user <user_id> [--api-url URL] [--token TOK] [--reason "..."]
//! sx ueba snapshot --user <user_id> [--api-url URL] [--token TOK]
//! ```
//!
//! The command calls the same admin endpoints the dashboard does:
//!
//! * `POST /v1/admin/ueba/baseline/{user_id}/freeze`
//! * `POST /v1/admin/ueba/baseline/{user_id}/unfreeze`
//! * `GET  /v1/admin/ueba/baseline/{user_id}/snapshot`
//!
//! The token is taken either from `--token`, the `SX_ADMIN_TOKEN`
//! environment variable, or — if neither is set — the request is sent
//! unauthenticated (useful in dev / smoke tests where the auth middleware
//! is disabled). In production the API gates `/v1/admin/*` behind the
//! `admin:users` permission so unauthenticated requests are rejected.

use anyhow::{anyhow, Context};
use clap::{Args, Subcommand};
use reqwest::Client;
use serde_json::{json, Value};

use crate::output::OutputFormat;

/// Top-level `ueba` sub-command dispatcher.
#[derive(Debug, Subcommand)]
pub enum UebaCommand {
    /// Engage Frozen mode — capture a snapshot, block live writes.
    Freeze(FreezeArgs),
    /// Release Frozen mode — run drift detection, return to Active.
    Unfreeze(FreezeArgs),
    /// Report the current state + (if Frozen) the captured snapshot.
    Snapshot(SnapshotArgs),
}

/// Shared arguments for `freeze` and `unfreeze`.
#[derive(Debug, Args)]
pub struct FreezeArgs {
    /// User id (uuid) whose baseline to freeze / unfreeze.
    #[arg(long)]
    pub user: String,

    /// Base URL of the `SentinelX` API. Defaults to `http://127.0.0.1:8080`.
    #[arg(long = "api-url", default_value = "http://127.0.0.1:8080")]
    pub api_url: String,

    /// Bearer token for admin auth. Falls back to `SX_ADMIN_TOKEN`.
    #[arg(long)]
    pub token: Option<String>,

    /// Free-text operator reason (incident id, ticket reference).
    #[arg(long)]
    pub reason: Option<String>,
}

/// Arguments for `snapshot` — no body, no reason.
#[derive(Debug, Args)]
pub struct SnapshotArgs {
    /// User id (uuid).
    #[arg(long)]
    pub user: String,

    /// Base URL of the `SentinelX` API.
    #[arg(long = "api-url", default_value = "http://127.0.0.1:8080")]
    pub api_url: String,

    /// Bearer token. Falls back to `SX_ADMIN_TOKEN`.
    #[arg(long)]
    pub token: Option<String>,
}

/// Top-level dispatcher.
pub fn run(cmd: &UebaCommand, fmt: OutputFormat) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(async move {
        match cmd {
            UebaCommand::Freeze(a) => freeze_run(a, fmt).await,
            UebaCommand::Unfreeze(a) => unfreeze_run(a, fmt).await,
            UebaCommand::Snapshot(a) => snapshot_run(a, fmt).await,
        }
    })
}

async fn freeze_run(args: &FreezeArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let url = build_url(&args.api_url, &args.user, "freeze")?;
    let body = json!({ "reason": args.reason });
    post_and_render(&url, args.token.as_deref(), body, fmt).await
}

async fn unfreeze_run(args: &FreezeArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let url = build_url(&args.api_url, &args.user, "unfreeze")?;
    let body = json!({ "reason": args.reason });
    post_and_render(&url, args.token.as_deref(), body, fmt).await
}

async fn snapshot_run(args: &SnapshotArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let url = build_url(&args.api_url, &args.user, "snapshot")?;
    let token = resolve_token(args.token.as_deref());
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building http client")?;
    let mut req = client.get(&url);
    if let Some(t) = token.as_deref() {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.context("sending request")?;
    render(resp, fmt).await
}

async fn post_and_render(
    url: &str,
    token: Option<&str>,
    body: Value,
    fmt: OutputFormat,
) -> anyhow::Result<i32> {
    let token = resolve_token(token);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building http client")?;
    let mut req = client.post(url).json(&body);
    if let Some(t) = token.as_deref() {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.context("sending request")?;
    render(resp, fmt).await
}

async fn render(resp: reqwest::Response, fmt: OutputFormat) -> anyhow::Result<i32> {
    let status = resp.status();
    let text = resp.text().await.context("reading response body")?;
    match fmt {
        OutputFormat::Json => {
            // Pass-through: emit whatever the server returned.
            println_json(&text);
        }
        OutputFormat::Human => {
            print_human(status, &text);
        }
    }
    if status.is_success() {
        Ok(0)
    } else {
        Err(anyhow!("server returned {status}"))
    }
}

fn build_url(base: &str, user: &str, action: &str) -> anyhow::Result<String> {
    if user.trim().is_empty() {
        return Err(anyhow!("--user is empty"));
    }
    let base = base.trim_end_matches('/');
    Ok(format!("{base}/v1/admin/ueba/baseline/{user}/{action}",))
}

fn resolve_token(arg: Option<&str>) -> Option<String> {
    if let Some(t) = arg.map(str::to_owned) {
        return Some(t);
    }
    // SAFETY: the disallowed-methods lint blocks `std::env::var` workspace-wide
    // because production code should consume `sx_config` schema rather than
    // raw env. The CLI is a thin operator shim — the auth token is a
    // last-mile concern that has no schema home — so this read is allowed
    // here explicitly.
    #[allow(clippy::disallowed_methods)]
    {
        std::env::var("SX_ADMIN_TOKEN").ok()
    }
}

// --- Rendering helpers -------------------------------------------------
//
// `print_stdout` is forbidden workspace-wide for library crates, but the
// CLI's *primary purpose* is to print operator-facing text — the lint is
// silenced locally for that reason.

#[allow(clippy::print_stdout, clippy::disallowed_macros)]
fn println_json(text: &str) {
    println!("{text}");
}

#[allow(clippy::print_stdout, clippy::disallowed_macros)]
fn print_human(status: reqwest::StatusCode, text: &str) {
    println!("HTTP {}", status.as_u16());
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        if let Some(data) = v.get("data") {
            println!(
                "{}",
                serde_json::to_string_pretty(data).unwrap_or_else(|_| text.into())
            );
            return;
        }
    }
    println!("{text}");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn build_url_formats_correctly() {
        let u = build_url("http://127.0.0.1:8080", "alice", "freeze").unwrap();
        assert_eq!(
            u,
            "http://127.0.0.1:8080/v1/admin/ueba/baseline/alice/freeze"
        );
    }

    #[test]
    fn build_url_trims_trailing_slash() {
        let u = build_url("http://127.0.0.1:8080/", "alice", "unfreeze").unwrap();
        assert_eq!(
            u,
            "http://127.0.0.1:8080/v1/admin/ueba/baseline/alice/unfreeze"
        );
    }

    #[test]
    fn build_url_rejects_empty_user() {
        let e = build_url("http://x", "", "freeze").unwrap_err();
        assert!(e.to_string().contains("--user is empty"));
    }

    #[test]
    fn resolve_token_prefers_arg() {
        let t = resolve_token(Some("from-arg"));
        assert_eq!(t.as_deref(), Some("from-arg"));
    }
}
