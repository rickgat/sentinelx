//! `sx tenant-bootstrap` — emit a Day-1 tenant env file.
//!
//! Produces:
//!
//! - A fresh time-ordered Tenant id ([`uuid::Uuid::now_v7`]).
//! - An Argon2id PHC hash of the placeholder password
//!   `"ChangeMeAfterFirstLogin!"`. The operator MUST rotate this after
//!   the first login; the CLI prints a reminder to stderr.
//! - An env file binding the new tenant identifiers so the operator can
//!   `source` it during the per-deployment bootstrap.
//!
//! ## Secret-handling policy
//!
//! The placeholder password is a known constant, so it does not require
//! zeroization. The PHC hash that is emitted is safe to write to disk by
//! design — it is intentionally a verifier that cannot be reversed into
//! the password.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use argon2::password_hash::{PasswordHasher as Argon2Hasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::Args;
use rand::rngs::OsRng;
use regex::Regex;
use tracing::instrument;
use uuid::Uuid;

/// Arguments for `sx tenant-bootstrap`.
#[derive(Debug, Args)]
pub struct TenantBootstrapArgs {
    /// URL-safe slug. Must match `^[a-z0-9](-?[a-z0-9])*$` and be at
    /// most 63 characters (DNS label compatible).
    #[arg(long)]
    pub slug: String,
    /// Human-readable display name.
    #[arg(long)]
    pub name: String,
    /// Admin contact email. Validated with a basic regex.
    #[arg(long = "admin-email")]
    pub admin_email: String,
    /// Destination env file. Will be created (or truncated) and chmod'd
    /// to `0o600` on Unix.
    #[arg(long = "out-env-file")]
    pub out_env_file: PathBuf,
}

/// The placeholder password the operator MUST change after the first
/// login. The hash of this string is what we emit to the env file.
pub const PLACEHOLDER_PASSWORD: &str = "ChangeMeAfterFirstLogin!";

/// Top-level execute hook for the `tenant-bootstrap` sub-command.
#[instrument(skip_all, fields(slug = %args.slug))]
pub fn run(args: &TenantBootstrapArgs) -> anyhow::Result<i32> {
    validate_slug(&args.slug)?;
    validate_email(&args.admin_email)?;

    let tenant_id = Uuid::now_v7();
    let phc = argon2id_phc_for(PLACEHOLDER_PASSWORD)?;

    let body = render_env_block(tenant_id, &args.slug, &args.name, &args.admin_email, &phc);
    write_env_file(&args.out_env_file, body.as_bytes())
        .with_context(|| format!("writing env file to {}", args.out_env_file.display()))?;

    print_rollout_instructions(tenant_id, &args.out_env_file);
    Ok(0)
}

/// Render the env block. Pure function so we can unit-test the shape.
#[must_use]
pub fn render_env_block(
    tenant_id: Uuid,
    slug: &str,
    name: &str,
    admin_email: &str,
    phc: &str,
) -> String {
    let mut buf = String::new();
    // The write! to a String cannot fail; the `let _ =` suppresses the
    // Result without unwrap and keeps the clippy `format_push_string`
    // hint quiet.
    let _ = writeln!(buf, "SENTINELX_TENANT_ID={tenant_id}");
    let _ = writeln!(buf, "SENTINELX_TENANT_SLUG={slug}");
    let _ = writeln!(buf, "SENTINELX_TENANT_NAME={}", escape_env_value(name));
    let _ = writeln!(buf, "SENTINELX_TENANT_ADMIN_EMAIL={admin_email}");
    let _ = writeln!(buf, "SENTINELX_TENANT_ADMIN_PHC={phc}");
    buf
}

/// Validate the slug — lowercase alphanumeric plus single dashes, no
/// leading/trailing dash, at most 63 chars.
pub fn validate_slug(slug: &str) -> anyhow::Result<()> {
    if slug.is_empty() {
        return Err(anyhow!("slug must not be empty"));
    }
    if slug.len() > 63 {
        return Err(anyhow!(
            "slug too long ({} chars); must be <= 63 to fit in a DNS label",
            slug.len()
        ));
    }
    // Pure-ASCII walk avoids a regex allocation on the hot path and
    // makes the rule explicit. Equivalent to: ^[a-z0-9](-?[a-z0-9])*$
    let bytes = slug.as_bytes();
    let mut prev_dash = false;
    for (i, b) in bytes.iter().enumerate() {
        let c = *b;
        let alnum = c.is_ascii_digit() || c.is_ascii_lowercase();
        let dash = c == b'-';
        if !alnum && !dash {
            return Err(anyhow!(
                "slug contains invalid character at position {i}: \
                 only lowercase alphanumeric and `-` are allowed"
            ));
        }
        if dash && (i == 0 || i + 1 == bytes.len() || prev_dash) {
            return Err(anyhow!(
                "slug must not start or end with `-` and must not contain `--`"
            ));
        }
        prev_dash = dash;
    }
    Ok(())
}

/// Validate the email with a deliberately permissive regex. Real RFC
/// 5321 / 5322 validation is out of scope for a Day-1 bootstrap helper;
/// we just guard against typos that would later trip the IAM service.
pub fn validate_email(email: &str) -> anyhow::Result<()> {
    if email.is_empty() {
        return Err(anyhow!("admin email must not be empty"));
    }
    if email.len() > 254 {
        return Err(anyhow!("admin email too long ({} chars)", email.len()));
    }
    // Compile once per call — the CLI runs each command in a fresh
    // process so caching has no value, and the regex is tiny.
    let re = Regex::new(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
        .map_err(|e| anyhow!("internal regex error: {e}"))?;
    if !re.is_match(email) {
        return Err(anyhow!("admin email is not in `local@domain.tld` form"));
    }
    Ok(())
}

/// Build a PHC string for `password` using Argon2id with cheap dev params.
///
/// Day-1 tenant bootstrap is a one-shot operation so we do not load the
/// production OWASP-strength params; instead we use the cheapest
/// parameters that the `argon2` crate accepts, because the operator is
/// expected to rotate this PHC after the first login anyway.
pub fn argon2id_phc_for(password: &str) -> anyhow::Result<String> {
    // Minimum acceptable params for the argon2 crate: m=8 KiB, t=1, p=1.
    let params = Params::new(8, 1, 1, None).map_err(|e| anyhow!("invalid argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    let phc = argon
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))?;
    Ok(phc.to_string())
}

fn write_env_file(path: &Path, payload: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "creating parent directory {} for env file",
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

/// Defensive escape for env values: strip embedded newlines so a hostile
/// name field cannot inject extra lines into the env file. We do not
/// quote because POSIX env files tolerate plain values; a name that
/// contains `=` characters is still rendered verbatim because it is
/// only used by the operator's downstream `source` step.
fn escape_env_value(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

#[allow(clippy::print_stderr, clippy::disallowed_macros)]
fn print_rollout_instructions(tenant_id: Uuid, out: &Path) {
    eprintln!(
        "bootstrapped tenant {tenant_id} env file at {}",
        out.display()
    );
    eprintln!("rollout:");
    eprintln!(
        "  1. `source {}` in the operator shell or feed it to your secret store",
        out.display()
    );
    eprintln!("  2. run `sx-monolith` (or your deploy) so the tenant row is created");
    eprintln!("  3. log in with the placeholder password and rotate it immediately");
    eprintln!("note: the placeholder password is *not* printed; refer to the runbook.");
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

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn tenant_bootstrap_emits_uuid_v7() {
        // Uuid v7 has version nibble == 7 in the third group.
        let id = Uuid::now_v7();
        let s = id.to_string();
        // Format: xxxxxxxx-xxxx-Vxxx-xxxx-xxxxxxxxxxxx — V == '7' for v7.
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(
            parts[2].starts_with('7'),
            "expected v7 version nibble, got {s}"
        );
    }

    #[test]
    fn tenant_bootstrap_phc_starts_with_argon2id() {
        let phc = argon2id_phc_for(PLACEHOLDER_PASSWORD).unwrap();
        assert!(phc.starts_with("$argon2id$"), "phc was: {phc}");
    }

    #[test]
    fn tenant_bootstrap_writes_expected_env_shape() {
        let tmp = NamedTempFile::new().unwrap();
        let args = TenantBootstrapArgs {
            slug: "acme-corp".to_owned(),
            name: "ACME Corp".to_owned(),
            admin_email: "ops@acme.example".to_owned(),
            out_env_file: tmp.path().to_path_buf(),
        };
        let rc = run(&args).unwrap();
        assert_eq!(rc, 0);
        let body = fs::read_to_string(tmp.path()).unwrap();
        assert!(body.contains("SENTINELX_TENANT_ID="));
        assert!(body.contains("SENTINELX_TENANT_SLUG=acme-corp\n"));
        assert!(body.contains("SENTINELX_TENANT_NAME=ACME Corp\n"));
        assert!(body.contains("SENTINELX_TENANT_ADMIN_EMAIL=ops@acme.example\n"));
        assert!(body.contains("SENTINELX_TENANT_ADMIN_PHC=$argon2id$"));
    }

    #[test]
    fn tenant_bootstrap_rejects_empty_slug() {
        let r = validate_slug("");
        assert!(r.is_err());
    }

    #[test]
    fn tenant_bootstrap_rejects_uppercase_slug() {
        let r = validate_slug("Acme");
        assert!(r.is_err(), "uppercase must be rejected");
    }

    #[test]
    fn tenant_bootstrap_rejects_dash_edges() {
        assert!(validate_slug("-acme").is_err());
        assert!(validate_slug("acme-").is_err());
        assert!(validate_slug("ac--me").is_err());
    }

    #[test]
    fn tenant_bootstrap_accepts_well_formed_slug() {
        assert!(validate_slug("a").is_ok());
        assert!(validate_slug("a1").is_ok());
        assert!(validate_slug("acme-corp-2").is_ok());
    }

    #[test]
    fn tenant_bootstrap_rejects_malformed_email() {
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("missing@tld").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("").is_err());
    }

    #[test]
    fn tenant_bootstrap_accepts_well_formed_email() {
        assert!(validate_email("ops@example.com").is_ok());
        assert!(validate_email("a.b+c@sub.example.co").is_ok());
    }

    #[test]
    fn tenant_bootstrap_strips_newlines_from_name() {
        let out = render_env_block(
            Uuid::now_v7(),
            "acme",
            "hostile\nname",
            "ops@example.com",
            "$argon2id$dummy",
        );
        assert!(!out.contains("hostile\nname"));
        assert!(out.contains("hostile name"));
    }
}
