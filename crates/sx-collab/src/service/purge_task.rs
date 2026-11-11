//! Background TTL-purge loop for [`crate::service::sink::CallbackSink`].

use std::sync::Arc;
use std::time::Duration as StdDuration;

use time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::service::sink::CallbackSink;
use crate::service::TRACING_TARGET;

/// Spawn a periodic task that calls `sink.purge_expired(ttl)` every
/// `interval`.  The task stops when `shutdown` is notified.
#[must_use]
pub fn spawn_purge_task(
    sink: Arc<dyn CallbackSink>,
    ttl: Duration,
    interval: StdDuration,
    shutdown: Arc<Notify>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate-fire tick — we want the first purge at +interval.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match sink.purge_expired(ttl).await {
                        Ok(n) if n > 0 => debug!(
                            target: TRACING_TARGET,
                            removed = n,
                            "collaborator purge removed expired callbacks",
                        ),
                        Ok(_) => {}
                        Err(e) => warn!(
                            target: TRACING_TARGET,
                            error = %e,
                            "collaborator purge failed",
                        ),
                    }
                }
                () = shutdown.notified() => {
                    debug!(target: TRACING_TARGET, "purge task shutting down");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::spawn_purge_task;
    use crate::model::callback::Callback;
    use crate::model::token::Token;
    use crate::service::sink::{CallbackSink, InMemoryCallbackSink};
    use std::sync::Arc;
    use std::time::Duration as StdDuration;
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Notify;

    // `start_paused = true` switches tokio to a virtual clock for this
    // test. We then drive it forward with `tokio::time::advance(...)` so
    // the purge loop's `interval` ticks deterministically — no wall-clock
    // sleeps, no CI-load flakiness.
    #[tokio::test(start_paused = true)]
    async fn purge_task_runs_and_stops() {
        let sink = Arc::new(InMemoryCallbackSink::new());
        let stale = OffsetDateTime::now_utc() - Duration::hours(100);
        let tk = Token::new();
        sink.append(Callback::Dns {
            token: tk.clone(),
            query_type: "A".into(),
            source_ip: None,
            received_at: stale,
        })
        .await
        .unwrap();

        let shutdown = Arc::new(Notify::new());
        let handle = spawn_purge_task(
            sink.clone() as Arc<dyn CallbackSink>,
            Duration::hours(72),
            StdDuration::from_millis(50),
            shutdown.clone(),
        );

        // Hand control to the spawned task so it registers its interval
        // timer with the paused clock before we advance.
        tokio::task::yield_now().await;
        // Advance the virtual clock well past one full interval so the
        // ticker is guaranteed to fire at least once after the skipped
        // immediate tick.
        tokio::time::advance(StdDuration::from_millis(200)).await;
        // Yield several times so the spawned task can drain the tick(s),
        // run `purge_expired`, and re-arm the select! before we signal
        // shutdown. Three yields are enough in practice — `purge_expired`
        // is fully synchronous after the lock.
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }

        shutdown.notify_waiters();
        // The task should join promptly under a real second. `timeout`
        // still uses the (paused) virtual clock, but `handle` resolves as
        // soon as the spawned task notices the notify and breaks.
        tokio::time::timeout(StdDuration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(sink.find_by_token(&tk).await.unwrap().is_empty());
    }
}
