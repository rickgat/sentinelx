//! Agent runtime: the collect/report loop and process-level signal plumbing.
//!
//! `loop` is a Rust reserved word, so the loop module file is named
//! `main_loop.rs` and is reached via `runtime::main_loop`.

pub mod main_loop;
pub mod shutdown;
