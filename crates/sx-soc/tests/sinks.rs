//! Tests for the sink implementations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening
)]

use std::sync::{Arc, Mutex};

use sx_soc::{Alert, AlertSink, BufferAlertSink, LogAlertSink, Severity};
use tracing::subscriber::with_default;
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

fn mk_alert(kind: &str) -> Alert {
    Alert::new(Severity::High, kind, "title", "desc", Some("t-1".into()))
}

#[derive(Default, Clone)]
struct CapturingLayer {
    events: Arc<Mutex<Vec<String>>>,
}

impl<S> tracing_subscriber::Layer<S> for CapturingLayer
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct V<'a>(&'a mut String);
        impl tracing::field::Visit for V<'_> {
            fn record_debug(&mut self, _f: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{value:?} ");
            }
            fn record_str(&mut self, _f: &tracing::field::Field, value: &str) {
                use std::fmt::Write;
                let _ = write!(self.0, "{value} ");
            }
        }
        let mut buf = String::new();
        event.record(&mut V(&mut buf));
        self.events.lock().unwrap().push(buf);
    }
}

#[test]
fn log_alert_sink_emits_a_tracing_event() {
    let layer = CapturingLayer::default();
    let events = layer.events.clone();
    let subscriber = Registry::default().with(layer);

    with_default(subscriber, || {
        let sink = LogAlertSink::new();
        let alert = mk_alert("auth.bruteforce");
        futures_block_on(async {
            sink.forward(&alert).await;
        });
    });

    let captured = events.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert!(
        captured[0].contains("auth.bruteforce"),
        "captured event missing kind: {captured:?}"
    );
}

#[tokio::test]
async fn buffer_alert_sink_appends_and_returns_snapshot() {
    let sink = BufferAlertSink::new(4);
    assert!(sink.is_empty().await);
    sink.forward(&mk_alert("a")).await;
    sink.forward(&mk_alert("b")).await;
    assert_eq!(sink.len().await, 2);
    let snap = sink.snapshot().await;
    assert_eq!(snap[0].kind, "a");
    assert_eq!(snap[1].kind, "b");
}

#[tokio::test]
async fn buffer_alert_sink_evicts_oldest_when_full() {
    let sink = BufferAlertSink::new(2);
    sink.forward(&mk_alert("a")).await;
    sink.forward(&mk_alert("b")).await;
    sink.forward(&mk_alert("c")).await;
    let snap = sink.snapshot().await;
    assert_eq!(snap.len(), 2);
    assert_eq!(snap[0].kind, "b");
    assert_eq!(snap[1].kind, "c");
}

#[tokio::test]
async fn buffer_alert_sink_capacity_zero_clamps_to_one() {
    let sink = BufferAlertSink::new(0);
    sink.forward(&mk_alert("a")).await;
    sink.forward(&mk_alert("b")).await;
    let snap = sink.snapshot().await;
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].kind, "b");
}

// Tiny helper to drive an async block inside a sync `with_default`.
fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(fut)
}
