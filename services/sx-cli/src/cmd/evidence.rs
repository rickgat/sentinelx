//! `sx evidence ...` — collect per-control evidence artifacts.
//!
//! Two frameworks are supported in this MVP:
//!
//! - `sx evidence soc2 collect --out <dir>` writes one JSON file per
//!   SOC 2 control into `<dir>`.
//! - `sx evidence iso27001 collect --out <dir>` does the same for the
//!   ISO/IEC 27001:2022 Annex A starter set.
//!
//! Each sub-framework also exposes a `list-controls` command that
//! enumerates the catalog without writing anything.
//!
//! Artifact file naming: `<framework>__<control-id>.json` with the
//! control id slugged (`.` and `/` collapsed to `_`) so the filenames
//! are filesystem-portable.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use tracing::{info, instrument};

use sx_compliance::evidence::manifest::EvidenceManifest;
use sx_compliance::evidence::s3_ship::{ship_directory, EvidenceSink, MockSink, SdkS3Sink};
use sx_compliance::evidence::{iso27001, soc2, EvidenceArtifact, EvidenceCollector};

use crate::output::{print_line, OutputFormat};

/// `sx evidence` arguments.
#[derive(Debug, Args)]
pub struct EvidenceArgs {
    /// Which framework family to operate on.
    #[command(subcommand)]
    pub cmd: EvidenceCommand,
}

/// Top-level evidence dispatch.
#[derive(Debug, Subcommand)]
pub enum EvidenceCommand {
    /// SOC 2 Trust Services Criteria evidence collectors.
    Soc2 {
        #[command(subcommand)]
        cmd: FrameworkCommand,
    },
    /// ISO/IEC 27001:2022 Annex A evidence collectors.
    Iso27001 {
        #[command(subcommand)]
        cmd: FrameworkCommand,
    },
    /// Ship a directory of evidence artifacts to an S3-like bucket.
    ///
    /// By default uses an in-memory mock sink (safe for CI / dry-runs).
    /// Pass `--real` to upload via the production `aws-sdk-s3` sink;
    /// credentials and region come from the SDK's default provider
    /// chain (env, shared profile, IMDS, etc.).
    ///
    /// Example:
    /// ```text
    /// # Dry-run (no AWS call):
    /// sx evidence ship --framework soc2 --from ./evidence --bucket s3://my-bucket/evidence
    ///
    /// # Real upload:
    /// AWS_REGION=us-east-1 \
    ///   sx evidence ship --framework soc2 --from ./evidence \
    ///     --bucket s3://my-bucket/evidence --real
    /// ```
    Ship(ShipArgs),
}

/// Arguments for the `ship` subcommand.
#[derive(Debug, Args)]
pub struct ShipArgs {
    /// Framework label to embed in keys + tags (`soc2`, `iso27001`, or `all`).
    #[arg(long)]
    pub framework: String,
    /// Source directory containing `*.json` artifacts to ship.
    #[arg(long)]
    pub from: PathBuf,
    /// Destination bucket prefix (e.g. `s3://my-bucket/evidence`).
    #[arg(long)]
    pub bucket: String,
    /// Use the production `aws-sdk-s3` sink instead of the in-memory mock.
    ///
    /// When set, AWS credentials and region are obtained from the SDK's
    /// default provider chain. No credentials are ever logged.
    #[arg(long, default_value_t = false)]
    pub real: bool,
}

/// Per-framework sub-sub-commands (shared by both SOC 2 and ISO).
#[derive(Debug, Subcommand)]
pub enum FrameworkCommand {
    /// Run every collector and write one JSON file per control to `--out`.
    Collect(CollectArgs),
    /// Enumerate the control identifiers exposed by this framework.
    ListControls,
}

/// Arguments for the `collect` sub-sub-command.
#[derive(Debug, Args)]
pub struct CollectArgs {
    /// Destination directory. Created (with parents) if missing.
    #[arg(long)]
    pub out: PathBuf,
}

/// One row of the operator-facing `collect` summary.
#[derive(Debug, Clone, Serialize)]
struct CollectRow {
    control_id: String,
    framework: String,
    path: String,
    bytes: u64,
}

/// Entry point for `sx evidence`.
#[instrument(skip_all)]
pub fn run(args: &EvidenceArgs, fmt: OutputFormat) -> Result<()> {
    match &args.cmd {
        EvidenceCommand::Soc2 { cmd } => run_framework(cmd, soc2::all_collectors(), "soc2", fmt),
        EvidenceCommand::Iso27001 { cmd } => {
            run_framework(cmd, iso27001::all_collectors(), "iso27001", fmt)
        }
        EvidenceCommand::Ship(args) => run_ship(args, fmt),
    }
}

fn run_ship(args: &ShipArgs, fmt: OutputFormat) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for evidence ship")?;
    let manifest = rt.block_on(async { run_ship_async(args).await })?;
    print_ship_manifest(&manifest, fmt)
}

async fn run_ship_async(args: &ShipArgs) -> Result<EvidenceManifest> {
    if args.real {
        let sink = SdkS3Sink::from_env()
            .await
            .context("failed to construct AWS S3 sink from the default credential chain")?;
        ship_with_sink(&sink, args, "aws-sdk").await
    } else {
        let sink = MockSink::new();
        ship_with_sink(&sink, args, "mock").await
    }
}

async fn ship_with_sink<S: EvidenceSink>(
    sink: &S,
    args: &ShipArgs,
    sink_label: &'static str,
) -> Result<EvidenceManifest> {
    let m = ship_directory(sink, &args.from, &args.bucket, &args.framework)
        .await
        .with_context(|| {
            format!(
                "failed to ship evidence from {} to {}",
                args.from.display(),
                args.bucket
            )
        })?;
    info!(
        target = "sx_cli::evidence",
        framework = args.framework.as_str(),
        artifacts = m.artifacts.len(),
        sink = sink_label,
        "evidence shipment complete"
    );
    Ok(m)
}

fn print_ship_manifest(manifest: &EvidenceManifest, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Human => {
            print_line(&format!(
                "## evidence shipment {} ({})",
                manifest.run_id, manifest.framework
            ));
            print_line("");
            print_line("| Control | Key | SHA-256 |");
            print_line("| ------- | --- | ------- |");
            for e in &manifest.artifacts {
                print_line(&format!(
                    "| {} | {} | {} |",
                    e.control_id, e.s3_key, e.sha256
                ));
            }
        }
        OutputFormat::Json => {
            let s = serde_json::to_string_pretty(manifest)
                .context("failed to serialize shipment manifest")?;
            print_line(&s);
        }
    }
    Ok(())
}

fn run_framework(
    cmd: &FrameworkCommand,
    collectors: Vec<Box<dyn EvidenceCollector>>,
    framework_label: &str,
    fmt: OutputFormat,
) -> Result<()> {
    match cmd {
        FrameworkCommand::Collect(args) => run_collect(args, &collectors, framework_label, fmt),
        FrameworkCommand::ListControls => run_list_controls(&collectors, framework_label, fmt),
    }
}

fn run_collect(
    args: &CollectArgs,
    collectors: &[Box<dyn EvidenceCollector>],
    framework_label: &str,
    fmt: OutputFormat,
) -> Result<()> {
    ensure_out_dir(&args.out)?;

    let mut rows: Vec<CollectRow> = Vec::with_capacity(collectors.len());
    for c in collectors {
        let artifact = c
            .collect()
            .with_context(|| format!("collector {} failed", c.id()))?;
        let path = write_artifact(&args.out, framework_label, &artifact)?;
        let meta = fs::metadata(&path).with_context(|| {
            format!("failed to stat artifact after writing: {}", path.display())
        })?;
        rows.push(CollectRow {
            control_id: artifact.control_id.clone(),
            framework: artifact.framework.clone(),
            path: path.display().to_string(),
            bytes: meta.len(),
        });
        info!(
            target = "sx_cli::evidence",
            control = artifact.control_id.as_str(),
            framework = framework_label,
            "evidence artifact written"
        );
    }

    print_collect_summary(&rows, framework_label, &args.out, fmt)?;
    Ok(())
}

fn run_list_controls(
    collectors: &[Box<dyn EvidenceCollector>],
    framework_label: &str,
    fmt: OutputFormat,
) -> Result<()> {
    let ids: Vec<String> = collectors.iter().map(|c| c.id().to_owned()).collect();

    match fmt {
        OutputFormat::Human => {
            print_line(&format!("## {framework_label} controls"));
            print_line("");
            print_line("| ID |");
            print_line("| -- |");
            for id in &ids {
                print_line(&format!("| {id} |"));
            }
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct View<'a> {
                framework: &'a str,
                controls: &'a [String],
            }
            let v = View {
                framework: framework_label,
                controls: &ids,
            };
            let s = serde_json::to_string_pretty(&v)
                .context("failed to serialize list-controls JSON view")?;
            print_line(&s);
        }
    }
    Ok(())
}

fn print_collect_summary(
    rows: &[CollectRow],
    framework_label: &str,
    out_dir: &Path,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Human => {
            print_line(&format!(
                "## {} evidence collected in {}",
                framework_label,
                out_dir.display()
            ));
            print_line("");
            print_line("| Control | Framework | Path | Bytes |");
            print_line("| ------- | --------- | ---- | ----- |");
            for r in rows {
                print_line(&format!(
                    "| {} | {} | {} | {} |",
                    r.control_id, r.framework, r.path, r.bytes
                ));
            }
        }
        OutputFormat::Json => {
            #[derive(Serialize)]
            struct View<'a> {
                framework: &'a str,
                out_dir: String,
                artifacts: &'a [CollectRow],
            }
            let v = View {
                framework: framework_label,
                out_dir: out_dir.display().to_string(),
                artifacts: rows,
            };
            let s = serde_json::to_string_pretty(&v)
                .context("failed to serialize collect summary JSON")?;
            print_line(&s);
        }
    }
    Ok(())
}

/// Slug a control id so it is filesystem-portable: `.` and `/` become `_`.
fn slug_control_id(id: &str) -> String {
    let mut s = String::with_capacity(id.len());
    for ch in id.chars() {
        if ch == '.' || ch == '/' || ch == '\\' {
            s.push('_');
        } else {
            s.push(ch);
        }
    }
    s
}

fn ensure_out_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create --out directory: {}", dir.display()))?;
    Ok(())
}

fn write_artifact(
    out_dir: &Path,
    framework_label: &str,
    artifact: &EvidenceArtifact,
) -> Result<PathBuf> {
    let file_name = format!(
        "{}__{}.json",
        framework_label,
        slug_control_id(&artifact.control_id)
    );
    let path = out_dir.join(file_name);
    let bytes = serde_json::to_vec_pretty(artifact)
        .with_context(|| format!("failed to serialize artifact for {}", artifact.control_id))?;
    fs::write(&path, &bytes)
        .with_context(|| format!("failed to write artifact at {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn tmpdir(label: &str) -> PathBuf {
        let nano = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("sx-cli-evi-{label}-{nano}"));
        // Intentionally do NOT pre-create — exercise the auto-mkdir path.
        p
    }

    #[test]
    fn slug_collapses_dots_and_slashes() {
        assert_eq!(slug_control_id("CC1.1"), "CC1_1");
        assert_eq!(slug_control_id("A.12.6"), "A_12_6");
        assert_eq!(slug_control_id("a/b\\c"), "a_b_c");
    }

    #[test]
    fn list_controls_enumerates_soc2_five() {
        let collectors = soc2::all_collectors();
        let ids: Vec<&str> = collectors.iter().map(|c| c.id()).collect();
        assert_eq!(ids.len(), 5);
        assert_eq!(ids.first().copied(), Some("CC1.1"));
    }

    #[test]
    fn list_controls_enumerates_iso_five() {
        let collectors = iso27001::all_collectors();
        let ids: Vec<&str> = collectors.iter().map(|c| c.id()).collect();
        assert_eq!(ids.len(), 5);
        assert_eq!(ids.last().copied(), Some("A.18.1"));
    }

    #[test]
    fn list_controls_total_is_ten_across_frameworks() {
        let total = soc2::all_collectors().len() + iso27001::all_collectors().len();
        assert_eq!(total, 10);
    }

    #[test]
    fn collect_creates_out_dir_and_writes_one_file_per_soc2_control() {
        let out = tmpdir("soc2-out");
        assert!(!out.exists());
        let args = EvidenceArgs {
            cmd: EvidenceCommand::Soc2 {
                cmd: FrameworkCommand::Collect(CollectArgs { out: out.clone() }),
            },
        };
        run(&args, OutputFormat::Json).unwrap();
        assert!(out.exists());

        let mut count = 0_usize;
        for entry in fs::read_dir(&out).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("json") {
                count += 1;
                let bytes = fs::read(&p).unwrap();
                let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(v.get("framework").and_then(|x| x.as_str()), Some("soc2"));
                assert!(v.get("control_id").is_some());
                assert!(v.get("evidence").is_some());
            }
        }
        assert_eq!(count, 5);
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn collect_writes_one_file_per_iso_control() {
        let out = tmpdir("iso-out");
        let args = EvidenceArgs {
            cmd: EvidenceCommand::Iso27001 {
                cmd: FrameworkCommand::Collect(CollectArgs { out: out.clone() }),
            },
        };
        run(&args, OutputFormat::Json).unwrap();

        let files: Vec<_> = fs::read_dir(&out)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        assert_eq!(files.len(), 5);
        for f in files {
            let bytes = fs::read(f.path()).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                v.get("framework").and_then(|x| x.as_str()),
                Some("iso27001")
            );
        }
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn list_controls_human_output_runs() {
        let collectors = soc2::all_collectors();
        run_list_controls(&collectors, "soc2", OutputFormat::Human).unwrap();
    }

    #[test]
    fn list_controls_json_output_runs() {
        let collectors = iso27001::all_collectors();
        run_list_controls(&collectors, "iso27001", OutputFormat::Json).unwrap();
    }

    #[test]
    fn ship_subcommand_runs_against_collected_directory() {
        // First, collect a small SOC 2 set into a temp dir.
        let out = tmpdir("ship-src");
        run(
            &EvidenceArgs {
                cmd: EvidenceCommand::Soc2 {
                    cmd: FrameworkCommand::Collect(CollectArgs { out: out.clone() }),
                },
            },
            OutputFormat::Json,
        )
        .unwrap();

        // Then, ship the directory with the mock sink. Smoke-test: this
        // must succeed and emit JSON without panicking.
        run(
            &EvidenceArgs {
                cmd: EvidenceCommand::Ship(ShipArgs {
                    framework: "soc2".to_owned(),
                    from: out.clone(),
                    bucket: "s3://my-bucket/evidence".to_owned(),
                    real: false,
                }),
            },
            OutputFormat::Json,
        )
        .unwrap();

        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn ship_args_real_flag_defaults_to_false() {
        use clap::Parser;

        #[derive(Debug, Parser)]
        #[command(no_binary_name = true)]
        struct Wrap {
            #[command(flatten)]
            args: ShipArgs,
        }

        let parsed = Wrap::try_parse_from([
            "--framework",
            "soc2",
            "--from",
            "/tmp/x",
            "--bucket",
            "s3://b/p",
        ])
        .unwrap();
        assert!(
            !parsed.args.real,
            "--real must default to false (safety: don't accidentally hit AWS)"
        );

        let parsed_real = Wrap::try_parse_from([
            "--framework",
            "soc2",
            "--from",
            "/tmp/x",
            "--bucket",
            "s3://b/p",
            "--real",
        ])
        .unwrap();
        assert!(parsed_real.args.real, "--real must opt in to real SDK");
    }

    #[test]
    fn ensure_out_dir_creates_nested_path() {
        let out = tmpdir("nested").join("a").join("b").join("c");
        ensure_out_dir(&out).unwrap();
        assert!(out.exists());
        // walk back up to remove the root tmp dir.
        let root = out
            .ancestors()
            .find(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with("sx-cli-evi-nested-"))
            })
            .unwrap()
            .to_path_buf();
        fs::remove_dir_all(&root).unwrap();
    }
}
