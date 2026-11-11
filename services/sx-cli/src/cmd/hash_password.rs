//! `sx hash-password` — emit an Argon2id PHC string for a password.
//!
//! This is the in-tree replacement for the out-of-repo `/tmp/phc-gen`
//! helper that `scripts/local-dev-pg.sh` previously depended on. Because
//! the dependency lived outside the repository, persistent-Postgres dev
//! boots failed on a clean checkout with `no PHC generator found`.
//!
//! The command reads a password (from `--password`, or stdin when the
//! flag is omitted) and prints **only** the resulting Argon2id PHC string
//! to stdout, so a shell can capture it with `$(...)`. All diagnostics go
//! to stderr.
//!
//! ## Secret handling
//!
//! Prefer piping the password on stdin (`printf '%s' "$pw" | sx
//! hash-password`) over `--password`, which exposes the plaintext in the
//! process argument list. The emitted PHC is a one-way verifier and is
//! safe to place in an env var or config field.
//!
//! The Argon2id parameters come from [`tenant_bootstrap::argon2id_phc_for`]
//! so the output is byte-compatible with the rest of the CLI. Argon2 PHC
//! strings are self-describing (the cost parameters are encoded in the
//! string itself), so a hash produced here verifies correctly regardless
//! of the cost parameters the verifier is configured with.

use std::io::{Read, Write as _};

use anyhow::{anyhow, Context};
use clap::Args;

use crate::cmd::tenant_bootstrap::argon2id_phc_for;

/// Arguments for `sx hash-password`.
#[derive(Debug, Args)]
pub struct HashPasswordArgs {
    /// Password to hash. When omitted, the password is read from stdin
    /// (everything up to the first newline, trailing `\r`/`\n` trimmed).
    /// Prefer stdin: `--password` leaks the plaintext into the process
    /// argument list.
    #[arg(long)]
    pub password: Option<String>,
}

/// Top-level execute hook for the `hash-password` sub-command.
pub fn run(args: &HashPasswordArgs) -> anyhow::Result<i32> {
    let password = match &args.password {
        Some(pw) => pw.clone(),
        None => read_password_from_stdin()?,
    };
    if password.is_empty() {
        return Err(anyhow!(
            "empty password: pass --password <PW> or pipe a non-empty password on stdin"
        ));
    }
    let phc = argon2id_phc_for(&password)?;
    // ONLY the PHC on stdout, no trailing decoration, so callers can
    // capture it verbatim with command substitution. We write to the
    // stdout handle directly (rather than `println!`) so a broken pipe
    // surfaces as an error and the platform's "no raw stdout" lint stays
    // satisfied — diagnostics still go to stderr.
    writeln!(std::io::stdout(), "{phc}").context("writing PHC to stdout")?;
    Ok(0)
}

/// Read a password from stdin, trimming a single trailing newline
/// (and an optional preceding `\r`). Does not trim interior or leading
/// whitespace — a password may legitimately contain spaces.
fn read_password_from_stdin() -> anyhow::Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading password from stdin")?;
    // Strip at most one trailing line terminator; keep everything else.
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hashes_explicit_password_to_argon2id_phc() {
        let args = HashPasswordArgs {
            password: Some("SentinelXDemo123!".to_string()),
        };
        // run() prints to stdout; here we assert the underlying producer
        // directly so the test does not capture process stdout.
        let phc = argon2id_phc_for(args.password.as_deref().unwrap()).unwrap();
        assert!(phc.starts_with("$argon2id$"), "got: {phc}");
        // Exercise the run() path for its exit code / empty-guard logic.
        assert_eq!(run(&args).unwrap(), 0);
    }

    #[test]
    fn empty_password_is_rejected() {
        let args = HashPasswordArgs {
            password: Some(String::new()),
        };
        assert!(run(&args).is_err());
    }
}
