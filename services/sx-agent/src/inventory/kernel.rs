//! Kernel version reader.
//!
//! On Linux the value is at `/proc/sys/kernel/osrelease`. On other platforms
//! we degrade gracefully: the caller observes [`Option::None`] and reports a
//! partial inventory.

use std::path::Path;

/// Reads the kernel version from the given path, trimming whitespace.
///
/// Returns `None` if the file does not exist (e.g. when running on macOS in
/// CI), surfacing a [`std::io::Error`] only for unexpected failures such as
/// permission denials on an existing file.
pub fn read_kernel<P: AsRef<Path>>(path: P) -> std::io::Result<Option<String>> {
    let p = path.as_ref();
    if !p.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(p)?;
    let trimmed = raw.trim().to_owned();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_kernel_returns_trimmed_value() {
        let Some((path, mut file)) = tempfile_or_skip() else {
            return;
        };
        writeln!(file, "  6.8.0-50-generic  ").unwrap();
        drop(file);
        let kernel = read_kernel(&path).unwrap();
        assert_eq!(kernel.as_deref(), Some("6.8.0-50-generic"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_kernel_returns_none_for_missing_file() {
        let kernel = read_kernel("/nonexistent/path/for/sx-agent/test").unwrap();
        assert!(kernel.is_none());
    }

    // Tiny ad-hoc temp file helper; std::env::temp_dir avoids extra deps.
    fn tempfile_or_skip() -> Option<(std::path::PathBuf, std::fs::File)> {
        let id = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("sx-agent-kernel-{id}"));
        let file = std::fs::File::create(&path).ok()?;
        Some((path, file))
    }
}
