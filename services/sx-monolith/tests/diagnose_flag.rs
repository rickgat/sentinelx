//! M3 / SX-REVIEW-002 regression gate for the `--diagnose` flag on
//! `sx-monolith`.
//!
//! Two layers:
//!
//! 1. **CLI parse-only** — Constructs the `Args` struct via clap with
//!    `--diagnose` and `-d` and confirms both shapes parse to
//!    `diagnose = true`. This is the deterministic, fast tier — it
//!    never spawns the real binary.
//!
//! 2. **Bin spawn** — Boots the actual `sx-monolith` binary against the
//!    committed `config/sentinelx.dev.example.yaml` (which has
//!    `log_level: "warn"` after M3) and confirms:
//!
//!    * With `--diagnose`, the override warn-line
//!      `"--diagnose flag active: …"` is emitted to stderr.
//!    * Without the flag, the same line is absent.
//!
//!    Implements the `feedback_user_facing_path_test` rule: the
//!    documented user-facing entry point (the binary + the CLI flag)
//!    is exercised end-to-end, not just the internal helper.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::missing_panics_doc)]
// Subprocess integration test: we deliberately spawn the production
// `sx-monolith` binary and need to (a) forward the parent's PATH +
// HOME so cargo's runtime-resolved binary still finds linker libs,
// and (b) read the child's stderr from the test runner so a boot
// panic + missing warn line is visible. The workspace bans
// `std::env::var` and `std::eprintln` from product code; both are
// appropriate here in a test harness that crosses the process
// boundary.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_macros)]

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Tier 1: CLI parse-only.
//
// We re-derive a private mirror of the `Args` struct shape because the
// real one lives in `main.rs` (a binary crate, so it isn't re-exported
// for tests). The flag set is small enough that drift is obvious; the
// bin-spawn test below is the cross-check that the *real* binary
// actually accepts these flags.
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Parser)]
#[command(name = "sx-monolith", bin_name = "sx-monolith")]
struct ArgsMirror {
    #[arg(
        long,
        short = 'd',
        help = "Force log level to info regardless of telemetry.log_level config"
    )]
    diagnose: bool,
}

#[test]
fn cli_parses_diagnose_long_flag() {
    use clap::Parser;
    let args = ArgsMirror::try_parse_from(["sx-monolith", "--diagnose"]).expect("parse --diagnose");
    assert!(args.diagnose, "--diagnose should set diagnose = true");
}

#[test]
fn cli_parses_diagnose_short_flag() {
    use clap::Parser;
    let args = ArgsMirror::try_parse_from(["sx-monolith", "-d"]).expect("parse -d");
    assert!(args.diagnose, "-d should set diagnose = true");
}

#[test]
fn cli_defaults_to_no_diagnose() {
    use clap::Parser;
    let args = ArgsMirror::try_parse_from(["sx-monolith"]).expect("parse no args");
    assert!(!args.diagnose, "default should be diagnose = false");
}

// ---------------------------------------------------------------------------
// Tier 2: spawn the real binary and verify the override warn-line.
//
// This is gated behind `cfg(not(miri))` because Miri cannot spawn
// subprocesses; everywhere else the test runs.
// ---------------------------------------------------------------------------

/// Bind a fresh ephemeral TCP port and return it. Pattern lifted from
/// `login_with_readme_creds.rs` so two concurrent test threads cannot
/// race on the default 8080 port.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// Locate `config/sentinelx.dev.example.yaml` relative to the workspace
/// root. `CARGO_MANIFEST_DIR` here is `services/sx-monolith`, so we
/// walk two levels up to reach the repo root.
fn dev_example_config_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .expect("workspace root two levels above CARGO_MANIFEST_DIR")
        .join("config")
        .join("sentinelx.dev.example.yaml")
}

/// Best-effort kill on `Drop` so a panicking test never leaks a
/// background monolith.
struct ChildKillOnDrop(Child);

impl Drop for ChildKillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drain a child's output stream into a shared `Vec<String>` so the
/// test body can scan for the override warn line. Each line is also
/// echoed to the test runner's stderr to aid debugging on CI.
///
/// `sx-telemetry::logging::build_fmt_layer` writes log records to
/// **stdout** by default (the `tracing_subscriber::fmt::layer()`
/// default), so we capture both streams and merge them into the
/// same sink.
fn capture_child_stream<R>(stream: R, tag: &'static str, sink: Arc<Mutex<Vec<String>>>)
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("[sx-monolith/{tag}] {line}");
            if let Ok(mut guard) = sink.lock() {
                guard.push(line);
            }
        }
    });
}

/// Poll the captured stderr for a substring until `deadline` elapses.
fn wait_for_stderr_substring(
    sink: &Arc<Mutex<Vec<String>>>,
    needle: &str,
    deadline: Instant,
) -> bool {
    while Instant::now() < deadline {
        if sink
            .lock()
            .map(|g| g.iter().any(|line| line.contains(needle)))
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Spawn the monolith with the supplied extra args + a fresh ephemeral
/// bind addr. Returns the kill-on-drop guard and the stderr sink.
fn spawn_monolith(extra_args: &[&str]) -> (ChildKillOnDrop, Arc<Mutex<Vec<String>>>) {
    let config_path = dev_example_config_path();
    assert!(
        config_path.exists(),
        "expected dev example config at {}",
        config_path.display(),
    );

    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let binary = env!("CARGO_BIN_EXE_sx-monolith");

    let mut cmd = Command::new(binary);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("SENTINELX_CONFIG", &config_path)
        .env("SENTINELX__SERVER__BIND_ADDR", &bind)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.args(extra_args);

    let mut child = cmd.spawn().expect("spawn sx-monolith");
    let stdout = child
        .stdout
        .take()
        .expect("stdout piped at spawn so .take() must succeed");
    let stderr = child
        .stderr
        .take()
        .expect("stderr piped at spawn so .take() must succeed");
    let sink: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    capture_child_stream(stdout, "stdout", Arc::clone(&sink));
    capture_child_stream(stderr, "stderr", Arc::clone(&sink));
    (ChildKillOnDrop(child), sink)
}

/// The substring uniquely identifying the M3 override warn-line.
const DIAGNOSE_WARN_NEEDLE: &str = "--diagnose flag active";

#[test]
fn diagnose_flag_emits_override_warn_line() {
    let (_guard, sink) = spawn_monolith(&["--diagnose"]);
    // 10s gives the monolith time to parse config, init telemetry,
    // and emit the warn line — well before adapter wiring completes.
    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(
        wait_for_stderr_substring(&sink, DIAGNOSE_WARN_NEEDLE, deadline),
        "expected stderr to contain '{DIAGNOSE_WARN_NEEDLE}' within 10s when --diagnose passed",
    );
}

#[test]
fn no_diagnose_flag_does_not_emit_override_warn_line() {
    let (_guard, sink) = spawn_monolith(&[]);
    // The override line is emitted at telemetry init, well within
    // 5s of boot. Wait that long, then assert absence.
    std::thread::sleep(Duration::from_secs(5));
    let saw_needle = sink
        .lock()
        .map(|g| g.iter().any(|line| line.contains(DIAGNOSE_WARN_NEEDLE)))
        .unwrap_or(false);
    assert!(
        !saw_needle,
        "did not expect stderr to contain '{DIAGNOSE_WARN_NEEDLE}' when --diagnose absent",
    );
}
