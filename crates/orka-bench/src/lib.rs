//! Test-only fake servers for `orka-core`'s integration tests.
//!
//! This crate exists so a test can exercise an HTTP or OAuth client
//! against a real loopback socket instead of a live cloud account.
//! Nothing in this crate ships in the built application.

pub mod fake_adls;
pub mod fake_aws;
pub mod fake_drive;
pub mod fake_dropbox;
pub mod fake_http;
pub mod fake_oauth;
pub mod tls;
