//! Filter parser + evaluator tests.

#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use super::{parse, Filter, FilterOp};

fn must_parse(input: &str) -> Filter {
    parse(input).unwrap_or_else(|e| panic!("parse {input:?}: {e}"))
}

#[test]
fn parse_simple_eq() {
    let f = must_parse(r#"userName eq "alice""#);
    assert_eq!(
        f,
        Filter::Cmp {
            attr: "userName".into(),
            op: FilterOp::Eq,
            value: "alice".into(),
        }
    );
}

#[test]
fn parse_dotted_attr() {
    let f = must_parse(r#"name.givenName co "bo""#);
    assert_eq!(
        f,
        Filter::Cmp {
            attr: "name.givenName".into(),
            op: FilterOp::Co,
            value: "bo".into(),
        }
    );
}

#[test]
fn parse_starts_with() {
    let f = must_parse(r#"userName sw "ali""#);
    assert!(matches!(
        f,
        Filter::Cmp {
            op: FilterOp::Sw,
            ..
        }
    ));
}

#[test]
fn parse_ends_with() {
    let f = must_parse(r#"userName ew "ice""#);
    assert!(matches!(
        f,
        Filter::Cmp {
            op: FilterOp::Ew,
            ..
        }
    ));
}

#[test]
fn parse_and_or_precedence() {
    // `a and b or c` parses as `(a and b) or c` per RFC.
    let f = must_parse(r#"userName eq "a" and active eq "true" or displayName co "x""#);
    match f {
        Filter::Or(lhs, rhs) => {
            assert!(matches!(*lhs, Filter::And(_, _)));
            assert!(matches!(*rhs, Filter::Cmp { .. }));
        }
        other => panic!("expected Or, got {other:?}"),
    }
}

#[test]
fn parse_parens_override_precedence() {
    let f = must_parse(r#"userName eq "a" and (active eq "true" or displayName co "x")"#);
    match f {
        Filter::And(_, rhs) => assert!(matches!(*rhs, Filter::Or(_, _))),
        other => panic!("expected And, got {other:?}"),
    }
}

#[test]
fn parse_escapes_in_string() {
    let f = must_parse(r#"displayName eq "he said \"hi\"""#);
    if let Filter::Cmp { value, .. } = f {
        assert_eq!(value, r#"he said "hi""#);
    } else {
        panic!("expected Cmp");
    }
}

#[test]
fn parse_keywords_are_case_insensitive() {
    let f = must_parse(r#"userName EQ "alice" AND active eq "true""#);
    assert!(matches!(f, Filter::And(_, _)));
}

#[test]
fn parse_rejects_unknown_op() {
    assert!(parse(r#"userName foo "x""#).is_err());
}

#[test]
fn parse_rejects_unterminated_string() {
    assert!(parse(r#"userName eq "alice"#).is_err());
}

#[test]
fn parse_rejects_trailing_tokens() {
    assert!(parse(r#"userName eq "alice" )"#).is_err());
}

#[test]
fn parse_rejects_empty_input() {
    assert!(parse("").is_err());
    assert!(parse("   ").is_err());
}

// --- Evaluation -----------------------------------------------------------

#[test]
fn matches_eq_on_top_level() {
    let f = must_parse(r#"userName eq "alice""#);
    let obj = serde_json::json!({ "userName": "alice" });
    assert!(f.matches(&obj));
    let other = serde_json::json!({ "userName": "bob" });
    assert!(!f.matches(&other));
}

#[test]
fn matches_eq_is_case_insensitive() {
    let f = must_parse(r#"userName eq "ALICE""#);
    let obj = serde_json::json!({ "userName": "alice" });
    assert!(f.matches(&obj));
}

#[test]
fn matches_co_substring() {
    let f = must_parse(r#"displayName co "build""#);
    let obj = serde_json::json!({ "displayName": "Bob the Builder" });
    assert!(f.matches(&obj));
}

#[test]
fn matches_sw_prefix() {
    let f = must_parse(r#"userName sw "ali""#);
    let obj = serde_json::json!({ "userName": "alice" });
    assert!(f.matches(&obj));
    let other = serde_json::json!({ "userName": "malice" });
    assert!(!f.matches(&other));
}

#[test]
fn matches_ew_suffix() {
    let f = must_parse(r#"userName ew "ice""#);
    let obj = serde_json::json!({ "userName": "alice" });
    assert!(f.matches(&obj));
    let other = serde_json::json!({ "userName": "alicia" });
    assert!(!f.matches(&other));
}

#[test]
fn matches_dotted_path() {
    let f = must_parse(r#"name.givenName eq "Bob""#);
    let obj = serde_json::json!({ "name": { "givenName": "Bob" } });
    assert!(f.matches(&obj));
}

#[test]
fn matches_missing_attr_is_false() {
    let f = must_parse(r#"userName eq "alice""#);
    let obj = serde_json::json!({ "displayName": "alice" });
    assert!(!f.matches(&obj));
}

#[test]
fn matches_and_short_circuits() {
    let f = must_parse(r#"userName eq "alice" and displayName co "ice""#);
    let pass = serde_json::json!({ "userName": "alice", "displayName": "alice" });
    let fail = serde_json::json!({ "userName": "alice", "displayName": "bob" });
    assert!(f.matches(&pass));
    assert!(!f.matches(&fail));
}

#[test]
fn matches_or_short_circuits() {
    let f = must_parse(r#"userName eq "alice" or userName eq "bob""#);
    let a = serde_json::json!({ "userName": "alice" });
    let b = serde_json::json!({ "userName": "bob" });
    let c = serde_json::json!({ "userName": "carol" });
    assert!(f.matches(&a));
    assert!(f.matches(&b));
    assert!(!f.matches(&c));
}
