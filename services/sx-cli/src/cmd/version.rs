//! `sx version` — print the CLI package version.

use crate::output::{print_line, OutputFormat};

/// Return the package version compiled into this binary.
#[must_use]
pub fn package_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Execute the `version` sub-command.
pub fn run(fmt: OutputFormat) {
    match fmt {
        OutputFormat::Human => print_line(package_version()),
        OutputFormat::Json => {
            print_line(&format!(
                "{{\"version\":\"{}\"}}",
                package_version().replace('"', "\\\"")
            ));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn version_command_prints_pkg_version() {
        // The function itself is a side-effecting println; verify the
        // underlying constant is non-empty and matches the cargo value.
        let v = package_version();
        assert!(!v.is_empty());
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn version_run_human_succeeds() {
        // Side-effecting; just assert it doesn't panic.
        run(OutputFormat::Human);
    }
}
