//! Parser SDK — built-in OCSF parsers and the `LogParser` trait.

pub mod cloudtrail;
pub mod rfc5424;
pub mod suricata_eve;

use crate::error::ParseError;
use crate::schema::OcsfEvent;

/// Trait implemented by every log parser.
///
/// Parsers are stateless — the registry holds one shared instance per
/// source type behind a trait object. They take raw bytes and produce
/// an [`OcsfEvent`]; `tenant_id` is stamped by the ingestion service
/// after the parser returns.
pub trait LogParser: Send + Sync + std::fmt::Debug {
    /// Source-type token this parser handles (e.g. `"cloudtrail"`).
    fn source_type(&self) -> &'static str;

    /// Parse `payload` into a canonical OCSF event.
    fn parse(&self, payload: &str) -> Result<OcsfEvent, ParseError>;
}

pub use cloudtrail::CloudTrailParser;
pub use rfc5424::Rfc5424Parser;
pub use suricata_eve::SuricataEveParser;
