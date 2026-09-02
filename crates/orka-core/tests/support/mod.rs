//! Shared test support for `orka-core` integration tests.
//!
//! Each test binary that needs the conformance suite adds `mod support;`
//! and calls into [`conformance`].

#[allow(dead_code)]
pub mod conformance;
