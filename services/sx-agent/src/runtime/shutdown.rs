//! Process shutdown signal handling.
//!
//! The agent treats SIGINT (Ctrl-C from a terminal / `kubectl logs -f`
//! interrupt) and SIGTERM (`kubectl delete pod`, systemd stop) as the same
//! "drain and exit" event. Whichever arrives first wakes the runtime loop;
//! it finishes the current tick, then returns `Ok(())` so the binary exits 0.

use crate::error::AgentError;

/// Resolves when SIGINT or SIGTERM is received.
///
/// On non-Unix targets only Ctrl-C is observed — SIGTERM is delivered by
/// Unix kernels.
pub async fn shutdown_signal() -> Result<(), AgentError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res?;
                tracing::info!(signal = "SIGINT", "shutdown signal received");
            }
            _ = term.recv() => {
                tracing::info!(signal = "SIGTERM", "shutdown signal received");
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!(signal = "CTRL_C", "shutdown signal received");
        Ok(())
    }
}
