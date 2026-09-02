//! In-process benches for the FTP and FTPS (explicit TLS) connectors,
//! against real [`libunftp`] servers instead of a live host.
//!
//! `ORKA_EXTRA_CA_FILE` is process-global, so this binary starts every
//! fake server once, in [`servers`], and points that variable at the
//! one certificate authority every trusted FTPS test expects. Each
//! test still works against its own fresh subdirectory (see
//! [`fresh_root`]), so concurrent tests never touch the same files.

mod support;

use libunftp::auth::AnonymousAuthenticator;
use libunftp::ServerBuilder;
use orka_bench::tls::ServerTls;
use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::ftp::FtpFactory;
use orka_core::vfs::Scheme;
use orka_core::ListOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};
use unftp_core::auth::{AuthenticationError, Authenticator, Credentials, Principal};

/// The one user every password-protected fake server accepts.
const PASSWORD_USER: &str = "orka";
/// The correct password for [`PASSWORD_USER`]. A wrong-password test
/// must never let this string reach an error message.
const PASSWORD_SECRET: &str = "s3cret-swordfish";
/// Content of the file seeded ahead of time on the anonymous server.
const ANONYMOUS_FILE_CONTENT: &[u8] = b"anyone can read this";

/// Authenticates exactly one username/password pair; every other
/// login is a bad password. Debug is required by [`Authenticator`].
#[derive(Debug)]
struct FixedPasswordAuthenticator {
    username: &'static str,
    password: &'static str,
}

#[async_trait::async_trait]
impl Authenticator for FixedPasswordAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        creds: &Credentials,
    ) -> Result<Principal, AuthenticationError> {
        if username == self.username && creds.password.as_deref() == Some(self.password) {
            Ok(Principal {
                username: username.to_string(),
            })
        } else {
            Err(AuthenticationError::BadPassword)
        }
    }
}

/// Hands out one fixed secret for any connection id.
struct FixedSecret(String);

impl SecretProvider for FixedSecret {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        Some(self.0.clone())
    }
}

/// Hands out no secret at all, for anonymous auth.
struct NoSecret;

impl SecretProvider for NoSecret {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        None
    }
}

/// Picks a free loopback port by binding then dropping a listener.
/// `libunftp`'s listen address string has no port-0 support, so the
/// port must be chosen before the server binds its own listener.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().expect("read the bound port").port()
}

/// Blocks until `port` answers with an FTP greeting, or panics after 5
/// seconds. The server is spawned on a background runtime and needs a
/// moment to bind; without this a test's first connect can race it.
///
/// The probe reads at least one byte of the "220" greeting rather than
/// connecting and immediately dropping the socket: libunftp treats a
/// client that disconnects before the greeting is fully written as a
/// control-channel error, and on an FTPS-configured instance that
/// error can take the whole accept loop down with it, which then
/// looks like the server never started at all. Waiting for a real
/// byte of output avoids tripping that path.
fn wait_for_port(port: u16) {
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("valid loopback address");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = [0u8; 8];
            if matches!(stream.read(&mut buf), Ok(n) if n > 0) {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!("fake ftp server on port {port} did not start listening in time");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Writes `pem` to a fresh temp file and returns the handle. The
/// caller must keep the handle alive for as long as the server needs
/// to read it back.
fn write_pem_temp(pem: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create a temp file for a PEM block");
    file.write_all(pem.as_bytes()).expect("write the PEM block");
    file.flush().expect("flush the PEM temp file");
    file
}

/// Starts one `libunftp` server on its own port and returns that port
/// once the server is accepting connections. `ftps` enables explicit
/// FTPS on the instance when given a certificate and key file path.
fn spawn_server(
    runtime: &tokio::runtime::Runtime,
    root: PathBuf,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    ftps: Option<(PathBuf, PathBuf)>,
    passive_ports: RangeInclusive<u16>,
) -> u16 {
    let port = free_port();
    let mut builder = ServerBuilder::with_authenticator(
        Box::new(move || {
            unftp_sbe_fs::Filesystem::new(root.clone()).expect("open the fake ftp root")
        }),
        authenticator,
    )
    .passive_ports(passive_ports);
    if let Some((cert, key)) = ftps {
        builder = builder.ftps(cert, key);
    }
    let server = builder.build().expect("build the fake ftp server");
    runtime.spawn(async move {
        // The listen future only returns on shutdown or a bind
        // error; this binary never shuts a server down, so a
        // returned error would only ever surface as a hung test
        // (wait_for_port times out), never a silent miss.
        let _ = server.listen(format!("127.0.0.1:{port}")).await;
    });
    wait_for_port(port);
    port
}

/// Every fake FTP/FTPS server this binary starts, plus the TLS
/// material and background runtime that keep them alive.
struct Servers {
    password_port: u16,
    password_root: TempDir,
    anonymous_port: u16,
    _anonymous_root: TempDir,
    ftps_port: u16,
    ftps_root: TempDir,
    /// A second FTPS instance signed by a CA that `ORKA_EXTRA_CA_FILE`
    /// never trusts, for the certificate-rejection test.
    untrusted_ftps_port: u16,
    _untrusted_root: TempDir,
    _trusted_tls: ServerTls,
    _untrusted_tls: ServerTls,
    _cert_files: [NamedTempFile; 4],
    _runtime: tokio::runtime::Runtime,
}

/// Starts every fake server exactly once for the whole binary and
/// returns the shared handle. `ORKA_EXTRA_CA_FILE` is set here, before
/// any test connects, so every later FTPS connect in this process
/// resolves the same trust root.
fn servers() -> &'static Servers {
    static SERVERS: OnceLock<Servers> = OnceLock::new();
    SERVERS.get_or_init(|| {
        let runtime = tokio::runtime::Runtime::new().expect("build the fake-server runtime");

        let trusted_tls = ServerTls::generate().expect("generate the trusted test CA");
        let untrusted_tls = ServerTls::generate().expect("generate the untrusted test CA");
        // SAFETY: `OnceLock::get_or_init` runs this closure at most
        // once, and no test connects a backend before calling
        // `servers()` first, so no reader ever observes a partially
        // set environment.
        unsafe {
            std::env::set_var("ORKA_EXTRA_CA_FILE", trusted_tls.ca_file_path());
        }

        let password_root = tempfile::tempdir().expect("create the password ftp root");
        let anonymous_root = tempfile::tempdir().expect("create the anonymous ftp root");
        let ftps_root = tempfile::tempdir().expect("create the ftps root");
        let untrusted_root = tempfile::tempdir().expect("create the untrusted ftps root");

        std::fs::write(
            anonymous_root.path().join("hello.txt"),
            ANONYMOUS_FILE_CONTENT,
        )
        .expect("seed the anonymous file");

        let trusted_cert = write_pem_temp(&trusted_tls.cert_pem);
        let trusted_key = write_pem_temp(&trusted_tls.key_pem);
        let untrusted_cert = write_pem_temp(&untrusted_tls.cert_pem);
        let untrusted_key = write_pem_temp(&untrusted_tls.key_pem);

        let password_auth = || -> Arc<dyn Authenticator + Send + Sync> {
            Arc::new(FixedPasswordAuthenticator {
                username: PASSWORD_USER,
                password: PASSWORD_SECRET,
            })
        };

        let password_port = spawn_server(
            &runtime,
            password_root.path().to_path_buf(),
            password_auth(),
            None,
            39000..=39049,
        );
        let anonymous_port = spawn_server(
            &runtime,
            anonymous_root.path().to_path_buf(),
            Arc::new(AnonymousAuthenticator),
            None,
            39050..=39099,
        );
        let ftps_port = spawn_server(
            &runtime,
            ftps_root.path().to_path_buf(),
            password_auth(),
            Some((
                trusted_cert.path().to_path_buf(),
                trusted_key.path().to_path_buf(),
            )),
            39100..=39149,
        );
        let untrusted_ftps_port = spawn_server(
            &runtime,
            untrusted_root.path().to_path_buf(),
            password_auth(),
            Some((
                untrusted_cert.path().to_path_buf(),
                untrusted_key.path().to_path_buf(),
            )),
            39150..=39199,
        );

        Servers {
            password_port,
            password_root,
            anonymous_port,
            _anonymous_root: anonymous_root,
            ftps_port,
            ftps_root,
            untrusted_ftps_port,
            _untrusted_root: untrusted_root,
            _trusted_tls: trusted_tls,
            _untrusted_tls: untrusted_tls,
            _cert_files: [trusted_cert, trusted_key, untrusted_cert, untrusted_key],
            _runtime: runtime,
        }
    })
}

/// A fresh, empty subdirectory under `root` (FTP path form), unique to
/// one test so concurrent tests on the same server never collide.
fn fresh_root(root: &Path, label: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("{label}-{n}");
    std::fs::create_dir(root.join(&name)).expect("create a fresh test subdirectory");
    format!("/{name}")
}

/// Every fake server binds `127.0.0.1` specifically (see
/// [`spawn_server`]), not the wildcard address. `"localhost"` would
/// also work for the FTPS backend's SNI and certificate-name check
/// (the leaf certificate carries `localhost` as a DNS SAN), but this
/// host string also has to survive `ToSocketAddrs` resolution in
/// `ftp.rs`, which dials only the first address it gets back; on a
/// machine where `localhost` resolves to `::1` before `127.0.0.1`,
/// that first address is a loopback family the fake server never
/// bound, and the dial fails before TLS even starts. Using the literal
/// IP for every scheme sidesteps that ambiguity; the leaf certificate
/// also carries `127.0.0.1` as an IP SAN, so certificate verification
/// still exercises the real check.
fn config(scheme: Scheme, port: u16, auth: AuthMethod) -> ConnectionConfig {
    ConnectionConfig {
        id: "ftp-bench".to_string(),
        display_name: "FTP bench".to_string(),
        scheme,
        host: "127.0.0.1".to_string(),
        port: port as u32,
        username: PASSWORD_USER.to_string(),
        initial_path: "/".to_string(),
        auth,
    }
}

fn password_secret() -> Arc<dyn SecretProvider> {
    Arc::new(FixedSecret(PASSWORD_SECRET.to_string()))
}

#[test]
fn password_login_over_plain_ftp_passes_conformance() {
    let servers = servers();
    let root = fresh_root(servers.password_root.path(), "conformance");
    let cfg = config(Scheme::Ftp, servers.password_port, AuthMethod::Password);
    let backend = FtpFactory::default()
        .connect(&cfg, password_secret())
        .expect("connect with the right password");
    support::conformance::exercise_backend(&*backend, &root);
}

#[test]
fn anonymous_login_lists_and_reads_a_seeded_file() {
    let servers = servers();
    let cfg = config(Scheme::Ftp, servers.anonymous_port, AuthMethod::None);
    let backend = FtpFactory::default()
        .connect(&cfg, Arc::new(NoSecret))
        .expect("anonymous connect must succeed");

    let entries = backend
        .list_dir("/", &ListOptions::default())
        .expect("list the anonymous root");
    assert!(
        entries.iter().any(|e| e.name == "hello.txt"),
        "anonymous listing is missing the seeded file: {entries:?}"
    );

    let mut reader = backend
        .open_read("/hello.txt")
        .expect("open the seeded file");
    let mut content = Vec::new();
    reader
        .read_to_end(&mut content)
        .expect("read the seeded file");
    assert_eq!(content, ANONYMOUS_FILE_CONTENT);
}

#[test]
fn wrong_password_fails_without_leaking_it() {
    let servers = servers();
    let cfg = config(Scheme::Ftp, servers.password_port, AuthMethod::Password);
    let wrong_secret: Arc<dyn SecretProvider> =
        Arc::new(FixedSecret("definitely-not-the-password".to_string()));

    let err = FtpFactory::default()
        .connect(&cfg, wrong_secret)
        .err()
        .expect("a wrong password must fail to connect");
    assert!(
        err.contains("login"),
        "error must name the login step, got: {err}"
    );
    assert!(
        !err.contains("definitely-not-the-password"),
        "error must never contain the attempted password, got: {err}"
    );
}

#[test]
fn explicit_ftps_login_passes_conformance() {
    let servers = servers();
    let root = fresh_root(servers.ftps_root.path(), "conformance");
    let cfg = config(Scheme::Ftps, servers.ftps_port, AuthMethod::Password);
    let backend = FtpFactory::tls()
        .connect(&cfg, password_secret())
        .expect("ftps connect must succeed against the trusted certificate");
    support::conformance::exercise_backend(&*backend, &root);
}

/// A 3 MiB upload and download round-trip is already covered inside
/// [`support::conformance::exercise_backend`] above; this test asserts
/// it once more, explicitly and on its own, against the plain data
/// channel.
#[test]
fn a_three_mebibyte_file_round_trips_over_the_data_channel() {
    let servers = servers();
    let root = fresh_root(servers.password_root.path(), "data-channel");
    let cfg = config(Scheme::Ftp, servers.password_port, AuthMethod::Password);
    let backend = FtpFactory::default()
        .connect(&cfg, password_secret())
        .expect("connect for the data-channel round trip");

    let size = 3 * 1024 * 1024;
    let mut data = vec![0u8; size];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let path = support::conformance::join(&root, "large.bin");

    let mut writer = backend
        .create_write(&path, Some(size as u64))
        .expect("open the large file for writing");
    writer.write_all(&data).expect("write the large file");
    writer.finish().expect("finish the large file");

    let mut reader = backend
        .open_read(&path)
        .expect("open the large file for reading");
    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .expect("read the large file");
    assert_eq!(actual.len(), data.len(), "round-trip size");
    assert_eq!(actual, data, "round-trip content");

    backend
        .delete(&path, false)
        .expect("clean up the large file");
}

#[test]
fn ftps_rejects_a_certificate_outside_the_trust_file() {
    let servers = servers();
    let cfg = config(
        Scheme::Ftps,
        servers.untrusted_ftps_port,
        AuthMethod::Password,
    );

    let err = FtpFactory::tls()
        .connect(&cfg, password_secret())
        .err()
        .expect("a certificate signed by an untrusted CA must fail verification");
    assert!(
        !err.contains("login"),
        "verification must fail before login is attempted, got: {err}"
    );
}

#[test]
fn ftps_scheme_against_a_plain_server_fails_before_login() {
    let servers = servers();
    let cfg = config(Scheme::Ftps, servers.password_port, AuthMethod::Password);

    let err = FtpFactory::tls()
        .connect(&cfg, password_secret())
        .err()
        .expect("a server with no ftps configured must refuse AUTH TLS");
    assert!(
        !err.contains("login"),
        "the TLS negotiation must fail before login is attempted, got: {err}"
    );
}
