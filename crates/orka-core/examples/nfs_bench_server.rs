//! Long-running NFS bench daemon for `just bench-up`.
//!
//! Serves one directory over NFSv3 on a fixed loopback port, so a
//! manual bench run (or a future fix to `orka_core::vfs::mount`'s
//! `nfs_argv`) has a stable server to mount against outside `cargo
//! test`. `crates/orka-core/tests/bench_mounts.rs` does not need this
//! binary: its own tests start and stop a private instance of the
//! same file system per test.
//!
//! Usage: `nfs_bench_server <port> <export-directory>`. Runs until
//! killed; `just bench-down` sends the daemon a plain `kill` using the
//! PID `just bench-up` recorded.
//!
//! `#[path]` reaches into the test tree to reuse [`DiskFs`] rather
//! than duplicating it: an example binary can use a crate's
//! dev-dependencies (here, `nfsserve` and `tokio`) exactly like a
//! test can, so the same file compiles in both places.
#[path = "../tests/bench_support/nfs_fs.rs"]
mod nfs_fs;

use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args
        .next()
        .expect("usage: nfs_bench_server <port> <export-directory>")
        .parse()
        .expect("port must be a number between 0 and 65535");
    let export: PathBuf = args
        .next()
        .expect("usage: nfs_bench_server <port> <export-directory>")
        .into();
    std::fs::create_dir_all(&export).unwrap_or_else(|e| {
        panic!(
            "cannot create the export directory {}: {e}",
            export.display()
        )
    });

    let fs = nfs_fs::DiskFs::new(export.clone());
    let listener = NFSTcpListener::bind(&format!("127.0.0.1:{port}"), fs)
        .await
        .unwrap_or_else(|e| panic!("cannot bind the NFS bench server to 127.0.0.1:{port}: {e}"));
    eprintln!(
        "nfs_bench_server: serving {} on 127.0.0.1:{}",
        export.display(),
        listener.get_listen_port()
    );
    listener
        .handle_forever()
        .await
        .unwrap_or_else(|e| panic!("NFS bench server stopped unexpectedly: {e}"));
}
