//! Mobile push notification channel (APNs + FCM).
//!
//! Two outbound clients (`apns`, `fcm`), a per-tenant credential trait
//! ([`TenantPushCredentials`]), a device registry
//! ([`registry::DeviceRegistry`]), and a fan-out
//! [`dispatcher::PushDispatcher`] that enforces:
//!
//! * **Rate limit:** 5 notifications / minute / device.
//! * **Dedupe:** identical pushes for the same device within a 60s
//!   window are suppressed.
//! * **Severity gate:** only findings of severity `Critical` (or higher)
//!   fan out to the registered devices of the affected tenant's
//!   escalation contacts.
//!
//! All raw device tokens and JWT bearer values are wrapped in
//! [`secrecy::SecretString`] and never appear in `tracing` events or
//! error messages. The `Display` impl for [`PushError`] is
//! deliberately category-only.
//!
//! See [`crate::push::dispatcher::PushDispatcher::dispatch_finding`] for
//! the entry point invoked by upstream finding pipelines.

pub mod apns;
pub mod credentials;
pub mod dispatcher;
pub mod error;
pub mod fcm;
pub mod http;
pub mod registry;

pub use credentials::{
    ApnsCredentials, FcmCredentials, InMemoryTenantPushCredentials, TenantPushCredentials,
};
pub use dispatcher::{
    FindingSeverity, InMemoryAuditSink, MonotonicClock, PushAuditEvent, PushAuditSink,
    PushDispatcher, PushDispatcherConfig, PushFinding, SystemClock,
};
pub use error::PushError;
pub use registry::{
    DeviceId, DeviceRecord, DeviceRegistry, InMemoryDeviceRegistry, MobilePlatform,
    NewDeviceRegistration, RegistryEvent,
};
