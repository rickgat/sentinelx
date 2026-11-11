//! Property-based round-trip tests for the [`Framework`] enum.
//!
//! The serde representation is part of the on-disk format and must
//! survive arbitrary serialisation cycles unchanged.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use sx_compliance::prelude::Framework;

fn framework_strategy() -> impl Strategy<Value = Framework> {
    prop_oneof![
        Just(Framework::Iso27001),
        Just(Framework::Soc2),
        Just(Framework::PciDss),
        Just(Framework::Hipaa),
        Just(Framework::Nist80053),
        Just(Framework::CisAws),
    ]
}

proptest! {
    /// Any [`Framework`] value, serialised to JSON and deserialised back,
    /// MUST produce the original value bit-for-bit.
    #[test]
    fn framework_round_trip_serde(fw in framework_strategy()) {
        let s = serde_json::to_string(&fw).unwrap();
        let back: Framework = serde_json::from_str(&s).unwrap();
        prop_assert_eq!(fw, back);
    }
}
