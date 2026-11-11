//! IPv4 → (latitude, longitude) centroid lookup.
//!
//! This is the smallest possible substitute for a MaxMind GeoLite2-City
//! database: the existing [`super::ip_geo::CountryDb`] already maps an
//! IP to an ISO-3166 alpha-2 country code, and this module pairs that
//! with a small in-process table of country centroids — the geometric
//! "centre" of the country's landmass, in WGS-84 decimal degrees.
//!
//! ## Why this design
//!
//! P2-007 (impossible-travel) needs *lat/lon*, not just country codes,
//! to feed the great-circle / haversine speed check. The acceptance
//! criteria specifically allow either extending the existing CSV with
//! lat/lon or using a stub: this module is the stub. The accuracy is
//! intentionally coarse (country-level, ±~1000 km for very large
//! countries) but that is more than sufficient for the 800 km/h
//! threshold the rule enforces — a country swap between two consecutive
//! logins is already at least several hundred kilometres of travel.
//!
//! Production deployments swap [`IpGeoCentroid`] for a real city-level
//! reader behind the same `Option<(lat, lon)>` return contract.
//!
//! ## Coverage
//!
//! The centroid table covers ~60 countries that the embedded CSV can
//! actually return. Unknown / private / placeholder country codes
//! (`??`, `XX`) resolve to `None` rather than silently picking `(0, 0)`,
//! because (0, 0) is a real point in the Gulf of Guinea and would
//! poison downstream haversine math with false near-equator distances.

use std::net::Ipv4Addr;

use super::ip_geo::{CountryDb, PRIVATE_COUNTRY, UNKNOWN_COUNTRY};

/// IPv4 → (lat, lon) lookup backed by [`CountryDb`] and a country-centroid table.
///
/// Construct once per process via [`IpGeoCentroid::default`] (uses the
/// embedded CSV) or via [`IpGeoCentroid::with_db`] for tests that want
/// to inject a custom [`CountryDb`].
#[derive(Debug, Clone, Default)]
pub struct IpGeoCentroid {
    db: CountryDb,
}

impl IpGeoCentroid {
    /// Build a centroid lookup that reuses an already-constructed
    /// [`CountryDb`]. Useful in tests that want to inject a tiny CSV.
    #[must_use]
    pub fn with_db(db: CountryDb) -> Self {
        Self { db }
    }

    /// Resolve `addr` to a `(lat, lon)` centroid in WGS-84 decimal
    /// degrees.
    ///
    /// Returns `None` for:
    /// * RFC 1918 / reserved space (the [`PRIVATE_COUNTRY`] sentinel).
    /// * Addresses not covered by the embedded CSV (the
    ///   [`UNKNOWN_COUNTRY`] sentinel).
    /// * Country codes not present in the centroid table.
    #[must_use]
    pub fn lookup_latlon(&self, addr: Ipv4Addr) -> Option<(f64, f64)> {
        let cc = self.db.lookup(addr);
        country_centroid(&cc)
    }

    /// Same as [`Self::lookup_latlon`] but returns the country code too,
    /// so the audit row can carry both the lat/lon and the underlying
    /// ISO-3166 code that produced it.
    #[must_use]
    pub fn lookup(&self, addr: Ipv4Addr) -> Option<GeoPoint> {
        let cc = self.db.lookup(addr);
        let (lat, lon) = country_centroid(&cc)?;
        Some(GeoPoint {
            country: cc,
            lat,
            lon,
        })
    }
}

/// One geolocated point: the ISO-3166 alpha-2 country code and the
/// (lat, lon) centroid.
#[derive(Debug, Clone, PartialEq)]
pub struct GeoPoint {
    /// ISO-3166 alpha-2 country code (always uppercase).
    pub country: String,
    /// Latitude in decimal degrees, WGS-84.
    pub lat: f64,
    /// Longitude in decimal degrees, WGS-84.
    pub lon: f64,
}

/// Country-code → (lat, lon) centroid.
///
/// Returns `None` for sentinels (`XX` private, `??` unknown) and for any
/// code not in the small table below; callers must treat the result as
/// "no geolocation evidence" rather than a default.
#[must_use]
pub fn country_centroid(country: &str) -> Option<(f64, f64)> {
    // Sentinel codes are NOT countries.
    if country == PRIVATE_COUNTRY || country == UNKNOWN_COUNTRY {
        return None;
    }
    // Normalise to uppercase for the lookup. The `CountryDb` already
    // upper-cases at load time, but external callers might pass mixed
    // case — keep the contract defensive.
    let key = country.to_ascii_uppercase();
    CENTROIDS
        .iter()
        .find(|(cc, _, _)| *cc == key.as_str())
        .map(|(_, lat, lon)| (*lat, *lon))
}

/// (ISO-3166 alpha-2, lat, lon) triples for the countries the embedded
/// CSV can return.
///
/// Centroids are approximate "country centre" coordinates rounded to
/// 4 decimal places. They are NOT capital-city coordinates because the
/// impossible-travel rule only cares about gross continent-scale jumps;
/// using e.g. Beijing for `CN` would understate the distance to Tibetan
/// IPs by ~2000 km.
#[allow(clippy::approx_constant)]
const CENTROIDS: &[(&str, f64, f64)] = &[
    ("AE", 23.4241, 53.8478),
    ("AR", -38.4161, -63.6167),
    ("AT", 47.5162, 14.5501),
    ("AU", -25.2744, 133.7751),
    ("BE", 50.5039, 4.4699),
    ("BG", 42.7339, 25.4858),
    ("BR", -14.2350, -51.9253),
    ("CA", 56.1304, -106.3468),
    ("CH", 46.8182, 8.2275),
    ("CL", -35.6751, -71.5430),
    ("CN", 35.8617, 104.1954),
    ("CZ", 49.8175, 15.4730),
    ("DE", 51.1657, 10.4515),
    ("DK", 56.2639, 9.5018),
    ("EG", 26.8206, 30.8025),
    ("ES", 40.4637, -3.7492),
    ("FI", 61.9241, 25.7482),
    ("FR", 46.2276, 2.2137),
    ("GB", 55.3781, -3.4360),
    ("GR", 39.0742, 21.8243),
    ("HK", 22.3193, 114.1694),
    ("HU", 47.1625, 19.5033),
    ("ID", -0.7893, 113.9213),
    ("IE", 53.1424, -7.6921),
    ("IL", 31.0461, 34.8516),
    ("IN", 20.5937, 78.9629),
    ("IR", 32.4279, 53.6880),
    ("IT", 41.8719, 12.5674),
    ("JP", 36.2048, 138.2529),
    ("KR", 35.9078, 127.7669),
    ("MX", 23.6345, -102.5528),
    ("MY", 4.2105, 101.9758),
    ("NG", 9.0820, 8.6753),
    ("NL", 52.1326, 5.2913),
    ("NO", 60.4720, 8.4689),
    ("NZ", -40.9006, 174.8860),
    ("PH", 12.8797, 121.7740),
    ("PK", 30.3753, 69.3451),
    ("PL", 51.9194, 19.1451),
    ("PT", 39.3999, -8.2245),
    ("RO", 45.9432, 24.9668),
    ("RU", 61.5240, 105.3188),
    ("SA", 23.8859, 45.0792),
    ("SE", 60.1282, 18.6435),
    ("SG", 1.3521, 103.8198),
    ("TH", 15.8700, 100.9925),
    ("TR", 38.9637, 35.2433),
    ("TW", 23.6978, 120.9605),
    ("UA", 48.3794, 31.1656),
    ("US", 37.0902, -95.7129),
    ("VE", 6.4238, -66.5897),
    ("VN", 14.0583, 108.2772),
    ("ZA", -30.5595, 22.9375),
];

#[cfg(test)]
#[allow(clippy::float_cmp, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn known_country_centroid_resolves() {
        let (lat, lon) = country_centroid("US").expect("US present");
        assert!((lat - 37.0902).abs() < 1e-3);
        assert!((lon - (-95.7129)).abs() < 1e-3);
    }

    #[test]
    fn lowercase_country_is_accepted() {
        assert!(country_centroid("us").is_some());
        assert!(country_centroid("De").is_some());
    }

    #[test]
    fn private_sentinel_is_none() {
        assert!(country_centroid(PRIVATE_COUNTRY).is_none());
    }

    #[test]
    fn unknown_sentinel_is_none() {
        assert!(country_centroid(UNKNOWN_COUNTRY).is_none());
    }

    #[test]
    fn unknown_country_code_is_none() {
        assert!(country_centroid("ZZ").is_none());
    }

    #[test]
    fn ipv4_lookup_returns_known_latlon_for_us_ip() {
        // 8.8.8.8 lives inside the embedded US `/8` block; we expect
        // the US centroid back rather than `None`.
        let geo = IpGeoCentroid::default();
        let (lat, lon) = geo
            .lookup_latlon(Ipv4Addr::new(8, 8, 8, 8))
            .expect("US centroid");
        assert!((lat - 37.0902).abs() < 1e-3);
        assert!((lon - (-95.7129)).abs() < 1e-3);
    }

    #[test]
    fn ipv4_lookup_returns_none_for_rfc1918() {
        let geo = IpGeoCentroid::default();
        assert!(geo.lookup_latlon(Ipv4Addr::new(10, 0, 0, 1)).is_none());
        assert!(geo.lookup_latlon(Ipv4Addr::new(192, 168, 1, 1)).is_none());
    }

    #[test]
    fn ipv4_lookup_with_geopoint_carries_country() {
        let geo = IpGeoCentroid::default();
        let p = geo.lookup(Ipv4Addr::new(8, 8, 8, 8)).expect("present");
        assert_eq!(p.country, "US");
    }

    #[test]
    fn ip_lookup_for_china_block_uses_cn_centroid() {
        // 114.4.0.1 sits in the embedded CN block per the CSV.
        // Confirm both the country resolution and the centroid mapping.
        let geo = IpGeoCentroid::default();
        let p = geo
            .lookup(Ipv4Addr::new(114, 4, 0, 1))
            .expect("must resolve");
        assert_eq!(p.country, "CN");
        let (lat, lon) = country_centroid("CN").unwrap();
        assert!((p.lat - lat).abs() < 1e-6);
        assert!((p.lon - lon).abs() < 1e-6);
    }

    #[test]
    fn centroid_table_has_no_duplicate_country_codes() {
        let mut codes: Vec<&str> = CENTROIDS.iter().map(|(cc, _, _)| *cc).collect();
        codes.sort_unstable();
        let len_before = codes.len();
        codes.dedup();
        assert_eq!(
            codes.len(),
            len_before,
            "centroid table must not have duplicate country codes"
        );
    }

    #[test]
    fn centroid_table_codes_are_uppercase_two_letter() {
        for (cc, _, _) in CENTROIDS {
            assert_eq!(cc.len(), 2, "country code {cc} must be exactly 2 chars");
            assert!(
                cc.chars().all(|c| c.is_ascii_uppercase()),
                "country code {cc} must be uppercase ASCII"
            );
        }
    }

    #[test]
    fn centroid_lat_lon_in_valid_ranges() {
        for (cc, lat, lon) in CENTROIDS {
            assert!(
                (-90.0..=90.0).contains(lat),
                "{cc}: lat {lat} out of WGS-84 range"
            );
            assert!(
                (-180.0..=180.0).contains(lon),
                "{cc}: lon {lon} out of WGS-84 range"
            );
        }
    }
}
