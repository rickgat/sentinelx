//! Parser registry — looks up a parser by its source-type token.

use std::collections::HashMap;
use std::sync::Arc;

use crate::parser::{CloudTrailParser, LogParser, Rfc5424Parser, SuricataEveParser};

/// Registry of source-type token → parser.
///
/// The registry is cheaply cloneable (parsers are `Arc<dyn LogParser>`).
/// MVP populates three built-in parsers; custom parsers can be added at
/// boot via [`Self::register`].
#[derive(Debug, Clone)]
pub struct LogParserRegistry {
    parsers: HashMap<String, Arc<dyn LogParser>>,
}

impl LogParserRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            parsers: HashMap::new(),
        }
    }

    /// Construct a registry pre-loaded with the three built-in parsers
    /// (CloudTrail, RFC 5424 syslog, Suricata EVE).
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut registry = Self::empty();
        registry.register(Arc::new(CloudTrailParser::new()));
        registry.register(Arc::new(Rfc5424Parser::new()));
        registry.register(Arc::new(SuricataEveParser::new()));
        registry
    }

    /// Register a parser. Overwrites any prior entry for the same source-type.
    pub fn register(&mut self, parser: Arc<dyn LogParser>) {
        self.parsers.insert(parser.source_type().to_owned(), parser);
    }

    /// Resolve a parser by source-type token.
    #[must_use]
    pub fn get(&self, source_type: &str) -> Option<Arc<dyn LogParser>> {
        self.parsers.get(source_type).cloned()
    }

    /// All registered source-type tokens, lexicographically sorted.
    #[must_use]
    pub fn source_types(&self) -> Vec<String> {
        let mut out: Vec<String> = self.parsers.keys().cloned().collect();
        out.sort();
        out
    }
}

impl Default for LogParserRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_contains_three_parsers() {
        let r = LogParserRegistry::with_builtins();
        let types = r.source_types();
        assert!(types.contains(&"cloudtrail".to_owned()));
        assert!(types.contains(&"syslog_rfc5424".to_owned()));
        assert!(types.contains(&"suricata_eve".to_owned()));
        assert_eq!(types.len(), 3);
    }

    #[test]
    fn empty_registry_has_no_parsers() {
        let r = LogParserRegistry::empty();
        assert!(r.source_types().is_empty());
        assert!(r.get("cloudtrail").is_none());
    }

    #[test]
    fn get_returns_registered_parser() {
        let r = LogParserRegistry::with_builtins();
        let p = r.get("cloudtrail").expect("cloudtrail registered");
        assert_eq!(p.source_type(), "cloudtrail");
    }

    #[test]
    fn register_overrides_existing_entry() {
        let mut r = LogParserRegistry::with_builtins();
        r.register(Arc::new(CloudTrailParser::new()));
        assert_eq!(r.source_types().len(), 3);
    }

    #[test]
    fn default_yields_builtins() {
        let r = LogParserRegistry::default();
        assert!(!r.source_types().is_empty());
    }
}
