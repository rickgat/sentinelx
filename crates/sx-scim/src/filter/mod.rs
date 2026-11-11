//! SCIM filter parser (RFC 7644 §3.4.2.2).
//!
//! Supports a useful subset of the spec:
//!
//! - Comparison operators: `eq`, `co`, `sw`, `ew` (case-insensitive).
//! - Logical operators: `and`, `or` (left-associative; `and` binds tighter
//!   than `or` per spec).
//! - Parenthesised groups.
//! - Quoted string literals: `"foo"`, escape with `\"` and `\\`.
//! - Dotted attribute paths: `userName`, `name.givenName`, `emails.value`.
//!
//! Out of scope for the MVP: `ne`, `gt`, `ge`, `lt`, `le`, `pr`,
//! `not`, complex value filters (`emails[type eq "work"]`).

mod parser;

pub use parser::{parse, Filter, FilterOp};

#[cfg(test)]
mod tests;
