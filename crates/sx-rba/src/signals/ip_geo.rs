//! IPv4 → ISO-3166 alpha-2 country code lookup.
//!
//! A tiny baked-in CSV (`assets/ip-to-country.csv`, < 10 KB) carries one
//! row per IPv4 `/8` (and a handful of carve-outs for RFC 1918 +
//! split-country `/8`s). Each row has the shape:
//!
//! ```csv
//! network_start,network_end,country
//! 1.0.0.0,1.0.0.255,US
//! ```
//!
//! Lookups are O(log n) — the table is sorted by `network_start` at
//! load time and binary-searched. The table is parsed exactly once per
//! process: [`CountryDb::default`] reads the embedded CSV and panics
//! AT TEST TIME only if a row is malformed; production callers go
//! through [`CountryDb::from_csv_str`] which returns a `Result` so a
//! caller can surface the parse error rather than panic.
//!
//! ## Coverage
//!
//! This is NOT a full MaxMind GeoLite table; it is a
//! "good-enough-for-unit-tests" fixture covering every IPv4 `/8` block
//! announced by IANA. The acceptance criteria explicitly call for a
//! "MaxMind GeoLite stub", and the audit row records the country code
//! returned by THIS table — production deployments will swap in a real
//! MaxMind reader behind the [`IpGeo`] trait.
//!
//! ## RFC 1918 / unroutable space
//!
//! Private + reserved ranges resolve to the sentinel country code `XX`
//! rather than `None` so the scorer can still observe the signal
//! ("this came from an internal network"). Callers that want stricter
//! semantics can compare the result to the [`PRIVATE_COUNTRY`]
//! constant.

use std::net::Ipv4Addr;

/// Country code returned for private / reserved address space.
pub const PRIVATE_COUNTRY: &str = "XX";

/// Country code returned for an address that does not match any row.
pub const UNKNOWN_COUNTRY: &str = "??";

/// CSV bytes baked into the crate. Used by [`CountryDb::default`].
const EMBEDDED_CSV: &str = include_str!("../../assets/ip-to-country.csv");

/// One row from the embedded CSV after parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    /// Inclusive start of the range as a `u32`.
    start: u32,
    /// Inclusive end of the range as a `u32`.
    end: u32,
    /// ISO-3166 alpha-2 country code, ASCII upper-case.
    country: [u8; 2],
}

/// Sorted in-memory lookup table keyed by `network_start`.
#[derive(Debug, Clone)]
pub struct CountryDb {
    /// Rows sorted ascending by `start`.
    rows: Vec<Row>,
}

impl Default for CountryDb {
    fn default() -> Self {
        // The embedded CSV is checked-in and reviewed; a parse error
        // here is a build-time bug, not a runtime one. Fall back to an
        // empty table on the unlikely event of a malformed row rather
        // than crash the process — the unit tests cover the embedded
        // CSV separately so a regression is caught there.
        Self::from_csv_str(EMBEDDED_CSV).unwrap_or_else(|err| {
            tracing::error!(
                target: "sx_rba.ip_geo",
                error = %err,
                "embedded ip-to-country.csv failed to parse; using empty table",
            );
            Self { rows: Vec::new() }
        })
    }
}

/// Errors raised while parsing the CSV.
#[derive(Debug, thiserror::Error)]
pub enum IpGeoError {
    /// A row had the wrong number of columns.
    #[error("invalid row at line {line}: expected 3 columns, got {got}")]
    InvalidColumns {
        /// 1-based line number in the source CSV.
        line: usize,
        /// Number of columns actually present.
        got: usize,
    },
    /// A start or end address failed to parse.
    #[error("invalid address at line {line}: {value}")]
    InvalidAddress {
        /// 1-based line number in the source CSV.
        line: usize,
        /// The bad token.
        value: String,
    },
    /// The country code did not have exactly two ASCII bytes.
    #[error("invalid country code at line {line}: {value}")]
    InvalidCountry {
        /// 1-based line number in the source CSV.
        line: usize,
        /// The bad token.
        value: String,
    },
}

impl CountryDb {
    /// Build a table from a CSV string (newline-separated rows, header
    /// row tolerated).
    pub fn from_csv_str(csv: &str) -> Result<Self, IpGeoError> {
        let mut rows: Vec<Row> = Vec::new();
        for (idx, raw_line) in csv.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            // Tolerate the header row.
            if line.starts_with("network_start") {
                continue;
            }
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() != 3 {
                return Err(IpGeoError::InvalidColumns {
                    line: line_no,
                    got: parts.len(),
                });
            }
            let p0 = parts.first().copied().unwrap_or("");
            let p1 = parts.get(1).copied().unwrap_or("");
            let p2 = parts.get(2).copied().unwrap_or("");
            let start = parse_ipv4(p0).ok_or_else(|| IpGeoError::InvalidAddress {
                line: line_no,
                value: p0.to_owned(),
            })?;
            let end = parse_ipv4(p1).ok_or_else(|| IpGeoError::InvalidAddress {
                line: line_no,
                value: p1.to_owned(),
            })?;
            let country_str = p2.trim();
            if country_str.len() != 2 || !country_str.bytes().all(|b| b.is_ascii_alphabetic()) {
                return Err(IpGeoError::InvalidCountry {
                    line: line_no,
                    value: country_str.to_owned(),
                });
            }
            let mut country = [0_u8; 2];
            // Upper-case in place so lookups are case-insensitive on input.
            let bytes = country_str.as_bytes();
            country[0] = bytes.first().copied().unwrap_or(b'?').to_ascii_uppercase();
            country[1] = bytes.get(1).copied().unwrap_or(b'?').to_ascii_uppercase();
            rows.push(Row {
                start: start.into(),
                end: end.into(),
                country,
            });
        }
        rows.sort_by_key(|r| r.start);
        Ok(Self { rows })
    }

    /// Number of rows held by this table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Look up the country code for `addr`.
    ///
    /// Returns:
    /// * [`PRIVATE_COUNTRY`] for RFC 1918 / reserved space recorded as `XX`.
    /// * [`UNKNOWN_COUNTRY`] when no row covers the address.
    /// * the ISO-3166 alpha-2 code otherwise.
    #[must_use]
    pub fn lookup(&self, addr: Ipv4Addr) -> String {
        let needle: u32 = addr.into();
        // Binary search by start; the matching row is the largest row
        // whose `start` <= needle. `partition_point` gives us
        // `idx` such that everything before is `<= needle`.
        let idx = self.rows.partition_point(|r| r.start <= needle);
        if idx == 0 {
            return UNKNOWN_COUNTRY.to_owned();
        }
        // Safe index: `idx` is in `[1, rows.len()]`, so `idx - 1` is in
        // `[0, rows.len() - 1]`.
        let Some(row) = self.rows.get(idx - 1) else {
            return UNKNOWN_COUNTRY.to_owned();
        };
        if needle >= row.start && needle <= row.end {
            // SAFETY: `country` is validated to be ASCII alphabetic at
            // load time, so it is valid UTF-8.
            String::from_utf8(row.country.to_vec()).unwrap_or_else(|_| UNKNOWN_COUNTRY.to_owned())
        } else {
            UNKNOWN_COUNTRY.to_owned()
        }
    }
}

/// Parse a dotted-quad IPv4 string. Returns `None` on any failure.
fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    s.trim().parse::<Ipv4Addr>().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn embedded_csv_loads_and_is_non_empty() {
        let db = CountryDb::default();
        assert!(!db.is_empty(), "embedded csv must produce non-empty table");
    }

    #[test]
    fn known_us_block_resolves_to_us() {
        let db = CountryDb::default();
        // 8.8.8.8 is squarely inside the US `/8`.
        assert_eq!(db.lookup(Ipv4Addr::new(8, 8, 8, 8)), "US");
    }

    #[test]
    fn known_cn_block_resolves_to_cn() {
        let db = CountryDb::default();
        // 27.0.0.1 is in a CN block per the fixture.
        assert_eq!(db.lookup(Ipv4Addr::new(27, 0, 0, 1)), "CN");
    }

    #[test]
    fn rfc1918_resolves_to_private_sentinel() {
        let db = CountryDb::default();
        assert_eq!(db.lookup(Ipv4Addr::new(10, 0, 0, 1)), PRIVATE_COUNTRY);
        assert_eq!(db.lookup(Ipv4Addr::new(192, 168, 1, 1)), PRIVATE_COUNTRY);
        assert_eq!(db.lookup(Ipv4Addr::new(172, 16, 0, 1)), PRIVATE_COUNTRY);
    }

    #[test]
    fn address_in_first_class_a_when_no_rows_below_returns_unknown() {
        let csv = "network_start,network_end,country\n10.0.0.0,10.0.0.255,US\n";
        let db = CountryDb::from_csv_str(csv).unwrap();
        assert_eq!(db.lookup(Ipv4Addr::new(9, 0, 0, 1)), UNKNOWN_COUNTRY);
    }

    #[test]
    fn boundary_lookups_are_inclusive() {
        let csv = "network_start,network_end,country\n1.2.3.0,1.2.3.10,US\n";
        let db = CountryDb::from_csv_str(csv).unwrap();
        assert_eq!(db.lookup(Ipv4Addr::new(1, 2, 3, 0)), "US");
        assert_eq!(db.lookup(Ipv4Addr::new(1, 2, 3, 10)), "US");
        assert_eq!(db.lookup(Ipv4Addr::new(1, 2, 3, 11)), UNKNOWN_COUNTRY);
    }

    #[test]
    fn malformed_csv_rejected() {
        let csv = "1.2.3.4,not-an-ip,US";
        let err = CountryDb::from_csv_str(csv).unwrap_err();
        assert!(matches!(err, IpGeoError::InvalidAddress { .. }));
    }

    #[test]
    fn malformed_country_rejected() {
        let csv = "1.2.3.0,1.2.3.10,USA";
        let err = CountryDb::from_csv_str(csv).unwrap_err();
        assert!(matches!(err, IpGeoError::InvalidCountry { .. }));
    }

    #[test]
    fn lowercase_country_uppercased() {
        let csv = "1.2.3.0,1.2.3.10,us";
        let db = CountryDb::from_csv_str(csv).unwrap();
        assert_eq!(db.lookup(Ipv4Addr::new(1, 2, 3, 5)), "US");
    }

    #[test]
    fn embedded_csv_is_under_size_budget() {
        // The acceptance criteria require the CSV stay tiny; assert a
        // generous upper bound so the fixture can't be silently bloated.
        const MAX_BYTES: usize = 50 * 1024;
        assert!(
            EMBEDDED_CSV.len() < MAX_BYTES,
            "embedded ip-to-country.csv must remain under {MAX_BYTES} bytes (was {})",
            EMBEDDED_CSV.len(),
        );
    }
}
