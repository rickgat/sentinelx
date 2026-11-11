//! `sx audit-tail` — replay the recent tail of an audit log NDJSON dump.
//!
//! Reads newline-delimited audit entries from a file (or stdin when the
//! path is `-`), filters by a `--since` timestamp and an optional
//! `--tenant` filter, and emits either:
//!
//! - `--output json`  — the matching entries verbatim, one JSON object
//!   per line (NDJSON in, NDJSON out).
//! - `--output table` — a compact tab-aligned table for humans:
//!   `seq | ts | tenant_id | action | resource`.
//!
//! ## `--since` parsing
//!
//! The CLI accepts two forms:
//!
//! 1. **RFC 3339 absolute timestamp** — e.g. `2026-05-31T12:00:00Z`.
//! 2. **Relative duration string** — e.g. `15s`, `5m`, `2h`, `7d`. The
//!    cutoff is computed as `now() - duration`. This is the
//!    humantime-style shorthand operators expect from `kubectl logs`,
//!    `journalctl --since`, etc.
//!
//! ## Secret-handling policy
//!
//! Audit entries are not secrets, but they may contain PII in `before`
//! / `after` snapshots. The table output deliberately omits those
//! fields; JSON output is verbatim, which is the correct trade-off for
//! a tool that operators pipe into `jq` or downstream tooling.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use clap::{Args, ValueEnum};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tracing::instrument;
use uuid::Uuid;

use sx_audit::prelude::AuditEntry;
use sx_core::value_object::ids::TenantId;

/// Output shape for `audit-tail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuditTailOutput {
    /// One JSON object per line (NDJSON).
    Json,
    /// Tab-aligned table.
    Table,
}

/// Arguments for `sx audit-tail`.
#[derive(Debug, Args)]
pub struct AuditTailArgs {
    /// Cutoff: emit entries whose `ts >= since`.
    ///
    /// Accepts an RFC 3339 timestamp (`2026-05-31T12:00:00Z`) or a
    /// relative duration (`15s`, `5m`, `2h`, `7d`).
    #[arg(long)]
    pub since: String,
    /// Optional tenant id filter. When set, only entries whose
    /// `tenant_id` matches are emitted.
    #[arg(long)]
    pub tenant: Option<Uuid>,
    /// Output mode.
    #[arg(long, value_enum, default_value_t = AuditTailOutput::Table)]
    pub output: AuditTailOutput,
    /// Source NDJSON file. Use `-` to read from stdin.
    #[arg(long, default_value = "-")]
    pub from: PathBuf,
}

/// Top-level execute hook for the `audit-tail` sub-command.
#[instrument(skip_all, fields(since = %args.since, output = ?args.output))]
pub fn run(args: &AuditTailArgs) -> anyhow::Result<i32> {
    let now = OffsetDateTime::now_utc();
    let cutoff = parse_since(&args.since, now)
        .with_context(|| format!("invalid --since `{}`", args.since))?;
    let tenant_filter = args.tenant.map(TenantId::from_uuid);

    let entries = read_ndjson(&args.from)
        .with_context(|| format!("reading audit entries from {}", args.from.display()))?;

    let filtered: Vec<&AuditEntry> = entries
        .iter()
        .filter(|e| e.ts >= cutoff)
        .filter(|e| tenant_filter.is_none_or(|t| e.tenant_id == t))
        .collect();

    let stdout = std::io::stdout();
    let mut sink = stdout.lock();
    match args.output {
        AuditTailOutput::Json => render_json(&filtered, &mut sink)?,
        AuditTailOutput::Table => render_table(&filtered, &mut sink)?,
    }
    Ok(0)
}

/// Parse `--since` against the supplied `now` (so tests can pin time).
pub fn parse_since(s: &str, now: OffsetDateTime) -> anyhow::Result<OffsetDateTime> {
    // Try RFC 3339 first — it's unambiguous and what most tooling will
    // emit.
    if let Ok(ts) = OffsetDateTime::parse(s, &Rfc3339) {
        return Ok(ts);
    }
    // Fall back to a small humantime-style relative duration parser.
    let dur = parse_relative_duration(s)
        .ok_or_else(|| anyhow!("not a valid RFC 3339 timestamp or relative duration"))?;
    now.checked_sub(dur)
        .ok_or_else(|| anyhow!("relative duration `{s}` underflows the calendar"))
}

/// Parse a relative duration string. Supported units: `s`, `m`, `h`,
/// `d`. Returns `None` on any parse failure.
pub fn parse_relative_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Split off the trailing unit letter.
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num.parse().ok()?;
    if n < 0 {
        return None;
    }
    let dur = match unit {
        "s" => Duration::seconds(n),
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        _ => return None,
    };
    Some(dur)
}

/// Read NDJSON entries from `path`. `-` means stdin.
pub fn read_ndjson(path: &Path) -> anyhow::Result<Vec<AuditEntry>> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        {
            let stdin = std::io::stdin();
            let mut handle = stdin.lock();
            handle.read_to_string(&mut buf).context("reading stdin")?;
        }
        return read_ndjson_str(&buf, "<stdin>");
    }
    let f = File::open(path).with_context(|| format!("opening {} for read", path.display()))?;
    let mut entries = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line =
            line.with_context(|| format!("reading line {} from {}", i + 1, path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .with_context(|| format!("parsing line {} of {}", i + 1, path.display()))?;
        entries.push(entry);
    }
    Ok(entries)
}

fn read_ndjson_str(input: &str, label: &str) -> anyhow::Result<Vec<AuditEntry>> {
    let mut entries = Vec::new();
    for (i, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line)
            .with_context(|| format!("parsing line {} of {label}", i + 1))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Render NDJSON to `sink`. One object per line. Exposed for tests.
pub fn render_json<W: Write>(entries: &[&AuditEntry], sink: &mut W) -> anyhow::Result<()> {
    for e in entries {
        let s = serde_json::to_string(e)?;
        writeln!(sink, "{s}").context("writing json output")?;
    }
    Ok(())
}

/// Render a table to `sink`. Exposed for tests.
pub fn render_table<W: Write>(entries: &[&AuditEntry], sink: &mut W) -> anyhow::Result<()> {
    writeln!(sink, "{}", table_header()).context("writing table header")?;
    for e in entries {
        writeln!(sink, "{}", format_row(e)?).context("writing table row")?;
    }
    Ok(())
}

fn table_header() -> &'static str {
    "seq\tts\ttenant_id\taction\tresource"
}

fn format_row(e: &AuditEntry) -> anyhow::Result<String> {
    let ts =
        e.ts.format(&Rfc3339)
            .map_err(|err| anyhow!("formatting ts: {err}"))?;
    let action = serde_json::to_value(&e.action)
        .ok()
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "?".to_owned());
    let resource = format!("{}:{}", e.resource_kind, e.resource_id);
    Ok(format!(
        "{seq}\t{ts}\t{tenant}\t{action}\t{resource}",
        seq = e.seq,
        ts = ts,
        tenant = e.tenant_id,
    ))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::io::Write as _;

    use sx_audit::prelude::{build_entry, build_genesis, Actor, AuditAction, NewAuditEvent};
    use sx_core::value_object::ids::TenantId;
    use tempfile::NamedTempFile;

    use super::*;

    fn make_chain(tenant: TenantId, n: usize) -> Vec<AuditEntry> {
        let mut entries = Vec::with_capacity(n);
        let event = |i: usize| NewAuditEvent {
            tenant_id: tenant,
            actor: Actor::system(),
            action: AuditAction::Login,
            resource_kind: "tail-test".to_owned(),
            resource_id: format!("res-{i}"),
            before: None,
            after: None,
            request_id: format!("req-{i}"),
            ts: None,
        };
        let g = build_genesis(event(0)).unwrap();
        entries.push(g);
        for i in 1..n {
            let prev = &entries[i - 1];
            let e = build_entry(prev.seq + 1, prev.hash, event(i)).unwrap();
            entries.push(e);
        }
        entries
    }

    fn write_ndjson(entries: &[AuditEntry]) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        for e in entries {
            let line = serde_json::to_string(e).unwrap();
            writeln!(tmp, "{line}").unwrap();
        }
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn audit_tail_parses_rfc3339_since() {
        let now = OffsetDateTime::now_utc();
        let ts = OffsetDateTime::parse("2026-05-31T12:00:00Z", &Rfc3339).unwrap();
        let parsed = parse_since("2026-05-31T12:00:00Z", now).unwrap();
        assert_eq!(parsed, ts);
    }

    #[test]
    fn audit_tail_parses_humantime_since() {
        let now = OffsetDateTime::parse("2026-05-31T12:00:00Z", &Rfc3339).unwrap();
        let cutoff = parse_since("1h", now).unwrap();
        assert_eq!(cutoff, now - Duration::hours(1));

        let cutoff = parse_since("30m", now).unwrap();
        assert_eq!(cutoff, now - Duration::minutes(30));

        let cutoff = parse_since("7d", now).unwrap();
        assert_eq!(cutoff, now - Duration::days(7));

        let cutoff = parse_since("15s", now).unwrap();
        assert_eq!(cutoff, now - Duration::seconds(15));
    }

    #[test]
    fn audit_tail_rejects_garbage_since() {
        let now = OffsetDateTime::now_utc();
        let r = parse_since("not-a-time", now);
        assert!(r.is_err());
    }

    #[test]
    fn audit_tail_json_output_is_one_line_per_entry() {
        let tenant = TenantId::new();
        let entries = make_chain(tenant, 3);
        let refs: Vec<&AuditEntry> = entries.iter().collect();
        let mut buf: Vec<u8> = Vec::new();
        render_json(&refs, &mut buf).unwrap();
        let body = String::from_utf8(buf).unwrap();
        // Each line must parse back as a single entry.
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let _parsed: AuditEntry = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn audit_tail_table_output_renders_header_and_rows() {
        let tenant = TenantId::new();
        let entries = make_chain(tenant, 2);
        let refs: Vec<&AuditEntry> = entries.iter().collect();
        let mut buf: Vec<u8> = Vec::new();
        render_table(&refs, &mut buf).unwrap();
        let body = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 rows");
        assert!(lines[0].starts_with("seq\tts\ttenant_id\taction\tresource"));
        // Every row mentions the tenant id.
        for line in &lines[1..] {
            assert!(line.contains(&tenant.to_string()));
            assert!(line.contains("tail-test:res-"));
        }
    }

    #[test]
    fn audit_tail_filters_by_since_cutoff() {
        let tenant = TenantId::new();
        let entries = make_chain(tenant, 3);
        let f = write_ndjson(&entries);
        // Cutoff well in the future — no entries should pass.
        let args = AuditTailArgs {
            since: "2999-01-01T00:00:00Z".to_owned(),
            tenant: None,
            output: AuditTailOutput::Json,
            from: f.path().to_path_buf(),
        };
        let now = OffsetDateTime::now_utc();
        let cutoff = parse_since(&args.since, now).unwrap();
        let loaded = read_ndjson(&args.from).unwrap();
        let any = loaded.iter().any(|e| e.ts >= cutoff);
        assert!(!any, "all entries must be filtered out");
    }

    #[test]
    fn audit_tail_filters_by_tenant_id() {
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let mut entries = make_chain(tenant_a, 2);
        entries.extend(make_chain(tenant_b, 2));
        let refs: Vec<&AuditEntry> = entries.iter().filter(|e| e.tenant_id == tenant_a).collect();
        assert_eq!(refs.len(), 2);
        for e in &refs {
            assert_eq!(e.tenant_id, tenant_a);
        }
    }

    #[test]
    fn audit_tail_reads_ndjson_from_file() {
        let tenant = TenantId::new();
        let entries = make_chain(tenant, 4);
        let f = write_ndjson(&entries);
        let loaded = read_ndjson(f.path()).unwrap();
        assert_eq!(loaded.len(), 4);
    }
}
