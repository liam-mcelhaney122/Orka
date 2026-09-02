//! Shared support for the opt-in mount and daemon benches.
//!
//! `bench_mounts.rs` adds `mod bench_support;` to reach [`nfs_fs`]. The
//! example binary `crates/orka-core/examples/nfs_bench_server.rs`
//! reaches the same file directly with `#[path]`, so the file system
//! implementation exists exactly once.

#[allow(dead_code)]
pub mod nfs_fs;
