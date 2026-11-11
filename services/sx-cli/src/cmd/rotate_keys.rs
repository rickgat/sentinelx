//! `sx rotate-keys` — emit a fresh 32-byte secret to an env file.
//!
//! This sub-command generates a cryptographically random secret using
//! [`rand::rngs::OsRng`] and writes it as a single line of the form
//!
//! ```text
//! <ENV_NAME>=<base64 of the raw bytes>
//! ```
//!
//! to the operator-supplied output file. The file mode is set to
//! `0o600` on Unix (best-effort on macOS) so that only the operator who
//! ran the command can read it back.
//!
//! ## Secret-handling policy
//!
//! The CLI NEVER prints or logs the secret value itself. Only the file
//! path and rollout instructions are written to stderr. The secret
//! itself only lives in the destination file (and, briefly, in the
//! `SecretBytes` newtype during generation, which is zeroized on drop).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use clap::{Args, ValueEnum};
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::instrument;
use zeroize_inline::ZeroizingVec;

/// What kind of secret is being rotated. Only used to pick the env var
/// name that the file should bind to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyKind {
    /// Signing key for short-lived JWT access tokens.
    JwtSigning,
    /// Per-deployment pepper for IAM attempt-email anonymisation.
    IamPepper,
    /// HMAC key for the audit-log anchor chain.
    AuditHmac,
}

impl KeyKind {
    /// Canonical env-var name that the secret will be bound to in the
    /// written file. This must match the `sx-config` schema names.
    #[must_use]
    pub const fn env_var_name(self) -> &'static str {
        match self {
            Self::JwtSigning => "SENTINELX__IAM__JWT_SIGNING_KEY",
            Self::IamPepper => "SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER",
            Self::AuditHmac => "SENTINELX__AUDIT__HMAC_KEY",
        }
    }

    /// Friendly label used in operator-facing rollout instructions.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::JwtSigning => "JWT signing key",
            Self::IamPepper => "IAM attempt-email pepper",
            Self::AuditHmac => "audit-log HMAC key",
        }
    }
}

/// Length (in raw bytes) of every generated secret. 32 bytes == 256 bits.
pub const SECRET_LEN: usize = 32;

/// Arguments for `sx rotate-keys`.
#[derive(Debug, Args)]
pub struct RotateKeysArgs {
    /// Which secret to rotate.
    #[arg(long, value_enum)]
    pub kind: KeyKind,
    /// Destination env file. Will be created (or truncated) and chmod'd
    /// to `0o600` on Unix.
    #[arg(long = "out-env-file")]
    pub out_env_file: PathBuf,
}

/// Top-level execute hook for the `rotate-keys` sub-command.
#[instrument(skip_all, fields(kind = ?args.kind))]
pub fn run(args: &RotateKeysArgs) -> anyhow::Result<i32> {
    rotate_to_file(args.kind, &args.out_env_file)?;
    print_rollout_instructions(args.kind, &args.out_env_file);
    Ok(0)
}

/// Internal: generate the secret and write it to `out`. Exposed for
/// tests; the public CLI surface goes through [`run`].
pub fn rotate_to_file(kind: KeyKind, out: &Path) -> anyhow::Result<()> {
    // Generate the secret. We wrap it in a zeroizing buffer so that
    // when we drop it the memory is wiped — defence in depth against
    // accidental reuse via `Drop` order or panics later in the call.
    let mut buf = ZeroizingVec::with_zeros(SECRET_LEN);
    OsRng.fill_bytes(buf.as_mut_slice());
    let encoded = B64.encode(buf.as_slice());

    let env_var = kind.env_var_name();
    let line = format!("{env_var}={encoded}\n");

    write_secret_file(out, line.as_bytes())
        .with_context(|| format!("writing secret to {}", out.display()))?;

    // Drop `buf` and `line` ASAP. `encoded` and `line` are not in
    // zeroizing buffers because base64 of random bytes is still
    // sensitive but the underlying bytes go through `Vec<u8>` paths
    // we cannot generically wipe; the host filesystem is the source
    // of truth for the secret going forward.
    drop(encoded);
    drop(line);
    Ok(())
}

/// Write `payload` to `path`, creating the file with mode `0o600` on
/// Unix and best-effort chmod on macOS. Truncates any existing file.
fn write_secret_file(path: &Path, payload: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "creating parent directory {} for secret file",
                    parent.display()
                )
            })?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    apply_unix_mode(&mut opts);
    let mut f = opts
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    f.write_all(payload)
        .with_context(|| format!("writing payload to {}", path.display()))?;
    f.flush()
        .with_context(|| format!("flushing {}", path.display()))?;

    // Belt-and-suspenders chmod for the case where the file already
    // existed and the open flags didn't replace its mode.
    set_unix_mode_0600(path);
    Ok(())
}

#[cfg(unix)]
fn apply_unix_mode(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}

#[cfg(not(unix))]
fn apply_unix_mode(_opts: &mut OpenOptions) {}

#[cfg(unix)]
fn set_unix_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_unix_mode_0600(_path: &Path) {}

/// Validate that the supplied kind string is a known [`KeyKind`].
///
/// Exposed for tests. Clap's `ValueEnum` already enforces this on the
/// command line; this helper exists so unit tests can assert the
/// rejection path without spinning the full clap parser.
#[cfg(test)]
pub fn parse_kind(s: &str) -> anyhow::Result<KeyKind> {
    match s {
        "jwt-signing" => Ok(KeyKind::JwtSigning),
        "iam-pepper" => Ok(KeyKind::IamPepper),
        "audit-hmac" => Ok(KeyKind::AuditHmac),
        other => Err(anyhow::anyhow!("unknown key kind: {other}")),
    }
}

#[allow(clippy::print_stderr, clippy::disallowed_macros)]
fn print_rollout_instructions(kind: KeyKind, out: &Path) {
    // IMPORTANT: never print the secret itself, just the file path.
    eprintln!(
        "wrote fresh {} ({} bytes) to {}",
        kind.label(),
        SECRET_LEN,
        out.display()
    );
    eprintln!("rollout:");
    eprintln!("  1. distribute the file to every service replica out-of-band (scp, KMS, vault)");
    eprintln!(
        "  2. update {} via `source {}`",
        kind.env_var_name(),
        out.display()
    );
    eprintln!("  3. restart each replica in rolling fashion, draining connections first");
    eprintln!("  4. confirm /healthz on each replica before continuing");
    eprintln!("  5. revoke the previous key after the rollout window closes");
    eprintln!("note: the secret value was NOT printed; read it back from the file above.");
}

/// Local zeroizing buffer; avoids a workspace dep on `zeroize` for the
/// CLI while still wiping the secret bytes on drop. Defined as a tiny
/// inline module so it can be unit-tested without exposing it as
/// part of the public CLI surface.
mod zeroize_inline {
    /// Vec-backed buffer that overwrites its contents with zero on drop.
    pub struct ZeroizingVec(Vec<u8>);

    impl ZeroizingVec {
        /// Allocate `n` zero bytes.
        pub fn with_zeros(n: usize) -> Self {
            Self(vec![0u8; n])
        }
        /// Borrow the buffer mutably for filling.
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }
        /// Borrow the buffer for read-only access.
        pub fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    impl Drop for ZeroizingVec {
        fn drop(&mut self) {
            for b in &mut self.0 {
                // Volatile-ish wipe: a plain assignment is sufficient
                // here because we are not optimising against an active
                // attacker reading process memory, only against
                // accidental disclosure via reuse of the allocation.
                *b = 0;
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::fs;

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn rotate_keys_emits_32_byte_base64_secret() {
        let tmp = NamedTempFile::new().unwrap();
        rotate_to_file(KeyKind::JwtSigning, tmp.path()).unwrap();
        let body = fs::read_to_string(tmp.path()).unwrap();
        // Shape: KEY=<base64>\n
        let trimmed = body.trim_end_matches('\n');
        let (key, value) = trimmed.split_once('=').expect("missing '=' in env file");
        assert_eq!(key, KeyKind::JwtSigning.env_var_name());
        let raw = B64.decode(value).expect("value not valid base64");
        assert_eq!(raw.len(), SECRET_LEN, "secret must be 32 bytes");
    }

    #[test]
    fn rotate_keys_file_shape_for_iam_pepper() {
        let tmp = NamedTempFile::new().unwrap();
        rotate_to_file(KeyKind::IamPepper, tmp.path()).unwrap();
        let body = fs::read_to_string(tmp.path()).unwrap();
        assert!(body.starts_with("SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER="));
        assert!(body.ends_with('\n'));
    }

    #[test]
    fn rotate_keys_file_shape_for_audit_hmac() {
        let tmp = NamedTempFile::new().unwrap();
        rotate_to_file(KeyKind::AuditHmac, tmp.path()).unwrap();
        let body = fs::read_to_string(tmp.path()).unwrap();
        assert!(body.starts_with("SENTINELX__AUDIT__HMAC_KEY="));
    }

    #[test]
    fn rotate_keys_rejects_unknown_kind() {
        let r = parse_kind("not-a-real-kind");
        assert!(r.is_err(), "unknown kinds must surface as an error");
    }

    #[test]
    fn rotate_keys_consecutive_calls_emit_different_secrets() {
        let a = NamedTempFile::new().unwrap();
        let b = NamedTempFile::new().unwrap();
        rotate_to_file(KeyKind::JwtSigning, a.path()).unwrap();
        rotate_to_file(KeyKind::JwtSigning, b.path()).unwrap();
        let va = fs::read_to_string(a.path()).unwrap();
        let vb = fs::read_to_string(b.path()).unwrap();
        assert_ne!(va, vb, "two rotations must produce distinct secrets");
    }

    #[cfg(unix)]
    #[test]
    fn rotate_keys_chmods_file_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = NamedTempFile::new().unwrap();
        rotate_to_file(KeyKind::IamPepper, tmp.path()).unwrap();
        let mode = fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be operator-only readable");
    }
}
