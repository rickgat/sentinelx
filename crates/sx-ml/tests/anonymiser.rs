//! Tests for the `Anonymiser`.

// Integration tests use `panic!` to assert on unexpected enum variants.
#![allow(clippy::panic)]

use proptest::prelude::*;
use secrecy::SecretString;
use std::collections::HashSet;
use sx_ml::prelude::*;

fn make_anonymiser() -> Anonymiser {
    let pepper = SecretString::from("tenant-A-pepper".to_string());
    let drop: HashSet<String> = ["email".to_string(), "src_ip".to_string()]
        .into_iter()
        .collect();
    let hash: HashSet<String> = ["user_id".to_string(), "host".to_string()]
        .into_iter()
        .collect();
    Anonymiser::new(pepper, drop, hash)
}

#[test]
fn anonymiser_hashes_categorical_field() {
    let anon = make_anonymiser();
    let mut row = FeatureVector::new();
    row.insert(
        "user_id".to_string(),
        FeatureValue::Category("alice@example.com".to_string()),
    );
    let out = anon.anonymise(row);
    match out.get("user_id") {
        Some(FeatureValue::Category(c)) => {
            assert_eq!(c.len(), 16, "digest should be 16 hex chars");
            assert!(c.chars().all(|c| c.is_ascii_hexdigit()));
            assert_ne!(c, "alice@example.com");
        }
        other => panic!("expected hashed category, got {other:?}"),
    }
}

#[test]
fn anonymiser_drops_pii_fields() {
    let anon = make_anonymiser();
    let mut row = FeatureVector::new();
    row.insert(
        "email".to_string(),
        FeatureValue::Category("bob@example.com".to_string()),
    );
    row.insert(
        "src_ip".to_string(),
        FeatureValue::Category("10.0.0.1".to_string()),
    );
    row.insert("severity".to_string(), FeatureValue::Number(7.5));
    let out = anon.anonymise(row);
    assert!(!out.contains_key("email"));
    assert!(!out.contains_key("src_ip"));
    assert!(out.contains_key("severity"));
}

#[test]
fn anonymiser_keeps_safe_fields_unchanged() {
    let anon = make_anonymiser();
    let mut row = FeatureVector::new();
    row.insert("severity".to_string(), FeatureValue::Number(7.5));
    row.insert("is_internal".to_string(), FeatureValue::Bool(true));
    let out = anon.anonymise(row.clone());
    assert_eq!(out.get("severity"), Some(&FeatureValue::Number(7.5)));
    assert_eq!(out.get("is_internal"), Some(&FeatureValue::Bool(true)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn anonymiser_hashes_categorical_field_proptest(s in "[a-zA-Z0-9@._-]{1,64}") {
        let anon = make_anonymiser();
        let mut row = FeatureVector::new();
        row.insert("user_id".to_string(), FeatureValue::Category(s));
        let out = anon.anonymise(row);
        match out.get("user_id") {
            Some(FeatureValue::Category(c)) => {
                prop_assert_eq!(c.len(), 16);
                prop_assert!(c.chars().all(|c| c.is_ascii_hexdigit()));
            }
            _ => prop_assert!(false, "expected hashed category"),
        }
    }
}
