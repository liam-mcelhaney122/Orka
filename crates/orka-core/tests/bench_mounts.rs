//! Opt-in bench for the mounted connectors (SMB and NFS) and for
//! implicit-TLS FTPS.
//!
//! Every test in this file is `#[ignore]` and returns immediately
//! unless `ORKA_BENCH=1` is set, because each one drives a real
//! system mount helper (`mount_nfs`, `mount_smbfs`) or a real daemon
//! (`smbd`, an implicit-TLS FTP server), not a fake in-process server:
//!
//!   cargo test -p orka-core --test bench_mounts               # compiles; lists as ignored
//!   ORKA_BENCH=1 cargo test -p orka-core --test bench_mounts -- --include-ignored
//!
//! `just bench-up` starts the daemons this file assumes are already
//! running (`smbd` on port 4450; an implicit-TLS FTP server on port
//! 990 is a manual setup, see docs/TESTING.md); the NFS
//! tests start their own throw-away server instead, since
//! [`nfsserve`] is cheap to run in-process. See `docs/TESTING.md` for
//! the full picture.
//!
//! Every mount test takes [`MOUNT_LOCK`] first, so only one system
//! mount is ever in flight: `mount_nfs`/`mount_smbfs`/`umount` share
//! kernel mount-table state that is not safe to touch from two tests
//! at once.
//!
//! ## NFS on a high port
//!
//! A `nfsserve`-based test server binds one arbitrary high port and
//! never registers with the portmapper on port 111. `mount_nfs` can
//! still reach it when both `port=` and `mountport=` name that port;
//! [`orka_core::vfs::mount`] passes `ConnectionConfig::port` through
//! as exactly those options. `nfs_via_orka_mounts_and_meets_conformance`
//! below mounts through `MountFactory` that way and runs the shared
//! conformance suite.
//! `nfs_server_meets_conformance_with_the_documented_mount_options`
//! proves the test server itself is correct by mounting it by hand
//! with those options, bypassing `MountFactory` entirely.

mod bench_support;
mod support;

use bench_support::nfs_fs::DiskFs;
use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::ftp::FtpFactory;
use orka_core::vfs::mount::MountFactory;
use orka_core::vfs::{LocalBackend, Scheme};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Serializes every test in this file: `mount_nfs`, `mount_smbfs`, and
/// `umount` all touch shared kernel mount-table state.
static MOUNT_LOCK: Mutex<()> = Mutex::new(());

/// True only when the operator opted into this bench tier. Every test
/// checks this first and returns immediately when it is false, so
/// `cargo test --test bench_mounts` (no variable set) still compiles
/// and lists every test, just as ignored, without touching the
/// network or the file system.
fn bench_enabled() -> bool {
    std::env::var("ORKA_BENCH").as_deref() == Ok("1")
}

/// Skips a test with a clear reason instead of failing it, for a
/// precondition this file cannot itself satisfy (a daemon `just
/// bench-up` was supposed to start, or a package `just bench` needs
/// but this machine lacks). A `#[ignore]`d test that returns early
/// still reports as passed, which is what we want here: the daemon
/// tier documents what is missing rather than red-lining CI runs
/// that have not set it up.
macro_rules! skip_unless {
    ($cond:expr, $($reason:tt)+) => {
        if !$cond {
            eprintln!($($reason)+);
            return;
        }
    };
}

/// A [`SecretProvider`] that always returns the same secret, or none.
struct StaticSecret(Option<&'static str>);

impl SecretProvider for StaticSecret {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        self.0.map(str::to_string)
    }
}

fn no_secret() -> Arc<dyn SecretProvider> {
    Arc::new(StaticSecret(None))
}

fn secret(value: &'static str) -> Arc<dyn SecretProvider> {
    Arc::new(StaticSecret(Some(value)))
}

/// Like `Result::expect_err`, but for a success type
/// (`Arc<dyn FsBackend>`) that has no `Debug` impl, so
/// `Result::expect_err` cannot be called on it directly.
fn expect_connect_err(
    result: Result<Arc<dyn orka_core::vfs::FsBackend>, String>,
    message: &str,
) -> String {
    match result {
        Ok(_) => panic!("{message}"),
        Err(e) => e,
    }
}

/// Mirrors the private `mount_dir` helper in
/// `orka_core::vfs::mount::mount_dir`. That function is not `pub`, so
/// a bench test cannot call it directly; this copy exists only to
/// find (and clean up after) the same directory `MountFactory` uses.
fn expected_mount_dir(connection_id: &str) -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set to run this bench");
    Path::new(&home)
        .join("Library/Application Support/Orka/mounts")
        .join(connection_id.replace('/', "_"))
}

// ---------------------------------------------------------------
// NFS
// ---------------------------------------------------------------

/// Starts a [`DiskFs`] over `root` on a background thread with its own
/// current-thread Tokio runtime, and returns the port it bound. The
/// thread is never joined: it lives for the rest of this test
/// process, which is fine for a bench that starts a fresh server per
/// test on a fresh ephemeral port.
fn spawn_nfs_server(root: PathBuf) -> u16 {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a Tokio runtime for the NFS bench server");
        rt.block_on(async move {
            use nfsserve::tcp::{NFSTcp, NFSTcpListener};
            let fs = DiskFs::new(root);
            let listener = NFSTcpListener::bind("127.0.0.1:0", fs)
                .await
                .expect("bind the NFS bench server to an ephemeral port");
            let port = listener.get_listen_port();
            tx.send(port)
                .expect("send the bound NFS port to the test thread");
            let _ = listener.handle_forever().await;
        });
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the NFS bench server did not report its port in time")
}

/// Locates `mount_nfs` the same way `orka_core::vfs::mount` does:
/// `/sbin` and `/usr/sbin` first, since a GUI app's `PATH` often lacks
/// them.
fn mount_nfs_binary() -> PathBuf {
    for dir in ["/sbin", "/usr/sbin"] {
        let candidate = Path::new(dir).join("mount_nfs");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("mount_nfs")
}

/// Mounts the bench server through `MountFactory`, with the port
/// carried in `ConnectionConfig::port`, and runs the shared suite on
/// the mounted tree.
#[test]
#[ignore = "starts a real nfsserve daemon and mounts it with mount_nfs; run with ORKA_BENCH=1"]
fn nfs_via_orka_mounts_and_meets_conformance() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    let _guard = MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let export = tempfile::tempdir().expect("create the NFS export directory");
    let port = spawn_nfs_server(export.path().to_path_buf());

    let connection_id = "bench-nfs";
    let config = ConnectionConfig {
        id: connection_id.to_string(),
        display_name: "Bench NFS".to_string(),
        scheme: Scheme::Nfs,
        host: "127.0.0.1:/".to_string(),
        port: port as u32,
        username: String::new(),
        initial_path: "/".to_string(),
        auth: AuthMethod::None,
    };

    let backend = MountFactory
        .connect(&config, no_secret())
        .unwrap_or_else(|e| panic!("mount through MountFactory failed: {e}"));
    let mount_dir = expected_mount_dir(connection_id);
    // The mount backend takes paths relative to the mount root.
    backend
        .mkdir("/suite")
        .unwrap_or_else(|e| panic!("create the suite root on the mount: {e}"));
    support::conformance::exercise_backend(&*backend, "/suite");
    backend
        .delete("/suite", false)
        .unwrap_or_else(|e| panic!("remove the suite root: {e}"));
    drop(backend);
    assert!(
        !mount_dir.exists()
            || std::fs::read_dir(&mount_dir)
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
        "the mount point must be unmounted and empty after drop"
    );
    let _ = std::fs::remove_dir_all(mount_dir);
}

/// Proves the bench's own NFS server is correct, independent of the
/// gap above: mounted by hand with the option set the `nfsserve`
/// README documents for macOS, it passes the full conformance suite.
#[test]
#[ignore = "starts a real nfsserve daemon and mounts it with mount_nfs; run with ORKA_BENCH=1"]
fn nfs_server_meets_conformance_with_the_documented_mount_options() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    let _guard = MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let export = tempfile::tempdir().expect("create the NFS export directory");
    let port = spawn_nfs_server(export.path().to_path_buf());
    let mount_point = tempfile::tempdir().expect("create a mount point");

    // From the nfsserve README's macOS instructions, with the port
    // this test's server actually bound substituted for the fixed
    // example port.
    let opts = format!("nolocks,vers=3,tcp,rsize=131072,actimeo=120,port={port},mountport={port}");
    let status = Command::new(mount_nfs_binary())
        .arg("-o")
        .arg(&opts)
        .arg("127.0.0.1:/")
        .arg(mount_point.path())
        .status()
        .expect("run mount_nfs");
    assert!(
        status.success(),
        "mount_nfs failed with the documented option set ({opts}); an unprivileged mount here \
         is the load-bearing assumption of the whole NFS bench, see docs/TESTING.md"
    );

    struct Unmount<'a>(&'a Path);
    impl Drop for Unmount<'_> {
        fn drop(&mut self) {
            let _ = Command::new("/sbin/umount").arg("-f").arg(self.0).status();
        }
    }
    let _unmount = Unmount(mount_point.path());

    support::conformance::exercise_backend(&LocalBackend, &mount_point.path().to_string_lossy());
}

// ---------------------------------------------------------------
// SMB
// ---------------------------------------------------------------

const SMB_PORT: u16 = 4450;
/// The Samba user `just bench-up` registers. Samba with `security =
/// user` maps every login to a Unix account, so the recipe uses the
/// current account and the same name is read here. `ORKA_BENCH_SMB_USER`
/// overrides it.
fn smb_user() -> String {
    std::env::var("ORKA_BENCH_SMB_USER")
        .or_else(|_| std::env::var("USER"))
        .expect("USER or ORKA_BENCH_SMB_USER must be set")
}
const SMB_PASSWORD: &str = "orka-bench";

fn smb_daemon_reachable() -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{SMB_PORT}").parse().unwrap(),
        Duration::from_millis(300),
    )
    .is_ok()
}

fn smb_config(id: &str, share: &str, username: &str, auth: AuthMethod) -> ConnectionConfig {
    ConnectionConfig {
        id: id.to_string(),
        display_name: "Bench SMB".to_string(),
        scheme: Scheme::Smb,
        host: format!("127.0.0.1:{SMB_PORT}/{share}"),
        port: SMB_PORT as u32,
        username: username.to_string(),
        initial_path: "/".to_string(),
        auth,
    }
}

/// A Homebrew `smbd` (`/opt/homebrew/sbin/smbd`), started by `just
/// bench-up` from `bench/smb.conf`, must already be listening on
/// [`SMB_PORT`]; these tests do not start it themselves; that keeps
/// one daemon shared across every SMB test in this binary instead of
/// restarting it per test.
#[test]
#[ignore = "needs `just bench-up`'s smbd on port 4450; run with ORKA_BENCH=1"]
fn smb_password_login_meets_conformance() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    skip_unless!(
        smb_daemon_reachable(),
        "skipping: nothing is listening on 127.0.0.1:{SMB_PORT}; run `just bench-up` first \
         (needs Homebrew samba's smbd, not macOS's own /usr/sbin/smbd)"
    );
    let _guard = MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let id = "bench-smb-password";
    let config = smb_config(id, "secure", &smb_user(), AuthMethod::Password);
    let backend = MountFactory
        .connect(&config, secret(SMB_PASSWORD))
        .expect("password login to the secure share must connect");
    support::conformance::exercise_backend(&*backend, "/");
    drop(backend);
    let _ = std::fs::remove_dir_all(expected_mount_dir(id));
}

/// The `WORKGROUP;user` username form must work exactly like the bare
/// username, since `mount_smbfs` accepts both.
#[test]
#[ignore = "needs `just bench-up`'s smbd on port 4450; run with ORKA_BENCH=1"]
fn smb_workgroup_qualified_username_connects() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    skip_unless!(
        smb_daemon_reachable(),
        "skipping: nothing is listening on 127.0.0.1:{SMB_PORT}; run `just bench-up` first"
    );
    let _guard = MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let id = "bench-smb-workgroup";
    let user = format!("WORKGROUP;{}", smb_user());
    let config = smb_config(id, "secure", &user, AuthMethod::Password);
    let backend = MountFactory
        .connect(&config, secret(SMB_PASSWORD))
        .expect("a WORKGROUP;user login must connect");
    let _ = backend.list_dir("/", &orka_core::ListOptions::default());
    drop(backend);
    let _ = std::fs::remove_dir_all(expected_mount_dir(id));
}

#[test]
#[ignore = "needs `just bench-up`'s smbd on port 4450; run with ORKA_BENCH=1"]
fn smb_guest_share_connects_with_no_auth() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    skip_unless!(
        smb_daemon_reachable(),
        "skipping: nothing is listening on 127.0.0.1:{SMB_PORT}; run `just bench-up` first"
    );
    let _guard = MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let id = "bench-smb-guest";
    let config = smb_config(id, "guest", "", AuthMethod::None);
    let backend = MountFactory
        .connect(&config, no_secret())
        .expect("guest access to the guest-ok share must connect");
    let _ = backend.list_dir("/", &orka_core::ListOptions::default());
    drop(backend);
    let _ = std::fs::remove_dir_all(expected_mount_dir(id));
}

/// A wrong password must fail promptly with the daemon's own
/// refusal, never hang until `MOUNT_TIMEOUT`. The connect runs on its
/// own thread so this test can bound the wait itself, independent of
/// Orka's internal timeout.
#[test]
#[ignore = "needs `just bench-up`'s smbd on port 4450; run with ORKA_BENCH=1"]
fn smb_wrong_password_fails_promptly() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    skip_unless!(
        smb_daemon_reachable(),
        "skipping: nothing is listening on 127.0.0.1:{SMB_PORT}; run `just bench-up` first"
    );
    let _guard = MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let id = "bench-smb-wrong-password";
    let config = smb_config(id, "secure", &smb_user(), AuthMethod::Password);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = MountFactory.connect(&config, secret("not-the-real-password"));
        let _ = tx.send(result);
    });
    let result = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("a wrong password must be refused well inside Orka's 20s MOUNT_TIMEOUT");
    let err = expect_connect_err(result, "a wrong password must not connect");
    assert_ne!(
        err, "mount command timed out",
        "a wrong password must be refused by smbd, not silently hang until our own timeout"
    );

    let _ = std::fs::remove_dir_all(expected_mount_dir(id));
}

/// Dropping a mounted backend must unmount the share and remove the
/// mount directory, exactly as `MountBackend::drop` promises.
#[test]
#[ignore = "needs `just bench-up`'s smbd on port 4450; run with ORKA_BENCH=1"]
fn smb_unmount_on_drop_removes_the_mount_point() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    skip_unless!(
        smb_daemon_reachable(),
        "skipping: nothing is listening on 127.0.0.1:{SMB_PORT}; run `just bench-up` first"
    );
    let _guard = MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let id = "bench-smb-unmount";
    let config = smb_config(id, "secure", &smb_user(), AuthMethod::Password);
    let backend = MountFactory
        .connect(&config, secret(SMB_PASSWORD))
        .expect("password login must connect");
    let dir = expected_mount_dir(id);
    assert!(
        dir.exists(),
        "the mount directory must exist while connected"
    );

    drop(backend);

    // `umount` is not necessarily instantaneous; give the drop's
    // synchronous `umount -f` a brief moment before failing.
    let deadline = Instant::now() + Duration::from_secs(5);
    while dir.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !dir.exists(),
        "the mount directory must be gone after the backend drops: {}",
        dir.display()
    );
}

// ---------------------------------------------------------------
// Implicit-TLS FTPS
// ---------------------------------------------------------------

/// `is_implicit_tls_port` in `orka_core::vfs::ftp` keys on exactly
/// port 990, and `ConnectionConfig::port` also drives the real TCP
/// dial for FTP/FTPS (see `connect_session`), so there is no way to
/// point Orka's implicit-TLS path at a remapped port: the daemon
/// itself must listen on 990, which needs root. Homebrew's vsftpd is
/// built without SSL, so no recipe starts one; docs/TESTING.md
/// describes the manual setup and `ORKA_BENCH_FTPS_CA` names its CA.
const FTPS_IMPLICIT_PORT: u16 = 990;

fn ftps_daemon_reachable() -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{FTPS_IMPLICIT_PORT}").parse().unwrap(),
        Duration::from_millis(300),
    )
    .is_ok()
}

#[test]
#[ignore = "needs an implicit-TLS FTP server on port 990 and ORKA_BENCH_FTPS_CA; run with ORKA_BENCH=1"]
fn ftps_implicit_bench_connects_and_meets_conformance() {
    if !bench_enabled() {
        eprintln!("skipping: set ORKA_BENCH=1 to run the mount bench tier");
        return;
    }
    skip_unless!(
        ftps_daemon_reachable(),
        "skipping: nothing is listening on 127.0.0.1:{FTPS_IMPLICIT_PORT}; start an implicit-TLS \
         FTP server by hand first (see docs/TESTING.md)"
    );
    let Ok(ca_file) = std::env::var("ORKA_BENCH_FTPS_CA") else {
        eprintln!("skipping: ORKA_BENCH_FTPS_CA is not set to the server's CA PEM file");
        return;
    };
    let ca_file = PathBuf::from(ca_file);
    assert!(
        ca_file.exists(),
        "ORKA_BENCH_FTPS_CA points at a missing file: {ca_file:?}"
    );
    // SAFETY: this test does not run concurrently with anything else
    // in this process that reads `ORKA_EXTRA_CA_FILE` through a live
    // connection; the mount tests above never touch FTPS.
    unsafe {
        std::env::set_var("ORKA_EXTRA_CA_FILE", &ca_file);
    }

    let config = ConnectionConfig {
        id: "bench-ftps-implicit".to_string(),
        display_name: "Bench FTPS".to_string(),
        scheme: Scheme::Ftps,
        host: "127.0.0.1".to_string(),
        port: FTPS_IMPLICIT_PORT as u32,
        username: String::new(),
        initial_path: "/".to_string(),
        auth: AuthMethod::None,
    };
    let backend = FtpFactory::tls()
        .connect(&config, no_secret())
        .expect("implicit-TLS FTPS anonymous login must connect");
    support::conformance::exercise_backend(&*backend, "/");
}

/// The repository root, found from this test binary's own path
/// (`target/.../deps/bench_mounts-<hash>`) by walking up to the
/// nearest ancestor containing `Cargo.lock`. Avoids depending on the
/// process's current directory, which `cargo test` does not
/// guarantee is the repository root.
fn repo_root() -> PathBuf {
    let mut dir = std::env::current_exe().expect("read this test binary's own path");
    loop {
        dir = dir
            .parent()
            .expect("a test binary path must have a repository root above it")
            .to_path_buf();
        if dir.join("Cargo.lock").exists() {
            return dir;
        }
    }
}
