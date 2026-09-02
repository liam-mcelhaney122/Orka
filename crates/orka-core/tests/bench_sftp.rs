//! In-process benches for the SFTP connector, against a real
//! [`russh`] server with an [`russh_sftp`] filesystem-backed subsystem
//! instead of a live host.
//!
//! Each fake server instance advertises exactly one SSH auth method
//! (see [`AuthPolicy`]), matching how a real server is configured to
//! accept one login style. This binary starts one instance per policy
//! once, in [`servers`], and every test connects to the instance that
//! matches what it means to prove.

mod support;

use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::sftp::SftpFactory;
use orka_core::vfs::Scheme;
use orka_core::ListOptions;

use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{
    Auth, Handler as SshHandler, Msg, Response, Server as SshServerTrait, Session,
};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;

/// The one user every fake server accepts.
const SFTP_USER: &str = "orka";
/// The correct password, for the servers that check one. A
/// wrong-password test must never let this string reach an error
/// message.
const SFTP_PASSWORD: &str = "s3cret-halibut";
/// The passphrase protecting [`Servers::client_key_encrypted_path`].
const CLIENT_KEY_PASSPHRASE: &str = "s3cret-passphrase";

/// Which SSH auth method one fake server instance advertises and
/// accepts. Each variant matches one login style the SFTP backend
/// supports, so every test connects to the instance shaped for it.
#[derive(Clone)]
enum AuthPolicy {
    PasswordOnly,
    KeyboardInteractiveOnly,
    /// Accepts only a signature from this exact public key (OpenSSH
    /// single-line encoding).
    PublicKeyOnly(String),
    NoneAccepted,
}

fn methods_for(policy: &AuthPolicy) -> MethodSet {
    let kind = match policy {
        AuthPolicy::PasswordOnly => MethodKind::Password,
        AuthPolicy::KeyboardInteractiveOnly => MethodKind::KeyboardInteractive,
        AuthPolicy::PublicKeyOnly(_) => MethodKind::PublicKey,
        AuthPolicy::NoneAccepted => MethodKind::None,
    };
    [kind].as_slice().into()
}

/// One fake SSH server. `new_client` hands each connection a fresh
/// [`SshSession`] carrying the same root and policy.
#[derive(Clone)]
struct SshServer {
    root: PathBuf,
    policy: AuthPolicy,
}

impl SshServerTrait for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        SshSession {
            root: self.root.clone(),
            policy: self.policy.clone(),
            channels: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }
}

/// Per-connection SSH handler. Authenticates against `policy`, then
/// hands the `sftp` subsystem channel to [`SftpFsHandler`], a real
/// filesystem rooted at `root`.
struct SshSession {
    root: PathBuf,
    policy: AuthPolicy,
    channels: Arc<AsyncMutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl SshSession {
    async fn take_channel(&mut self, id: ChannelId) -> Channel<Msg> {
        self.channels
            .lock()
            .await
            .remove(&id)
            .expect("channel_open_session ran before the subsystem request")
    }
}

impl SshHandler for SshSession {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(
            if user == SFTP_USER && matches!(self.policy, AuthPolicy::NoneAccepted) {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(
            if user == SFTP_USER
                && password == SFTP_PASSWORD
                && matches!(self.policy, AuthPolicy::PasswordOnly)
            {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    /// Answers one "Password:" prompt. `None` on the first call means
    /// the client is only probing; this issues the single prompt.
    /// `Some` means the client answered it; this checks the answer.
    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        if !matches!(self.policy, AuthPolicy::KeyboardInteractiveOnly) {
            return Ok(Auth::reject());
        }
        let Some(mut response) = response else {
            return Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![("Password: ".into(), false)].into(),
            });
        };
        let answer = response
            .next()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        Ok(if user == SFTP_USER && answer == SFTP_PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let AuthPolicy::PublicKeyOnly(expected) = &self.policy else {
            return Ok(Auth::reject());
        };
        let offered = public_key.to_openssh().unwrap_or_default();
        Ok(if user == SFTP_USER && &offered == expected {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            let channel = self.take_channel(channel_id).await;
            let sftp = SftpFsHandler::new(self.root.clone());
            session.channel_success(channel_id)?;
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
}

/// Maps an [`std::io::Error`] onto the closest SFTP status code.
fn map_io_error(error: std::io::Error) -> StatusCode {
    match error.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

/// A real, filesystem-backed SFTP subsystem rooted at `root`. Every
/// path the client sends is relative to the SFTP root ("/"); this
/// joins it onto `root` before touching the real filesystem.
/// Implements exactly the handful of operations the SFTP backend
/// (`crates/orka-core/src/vfs/sftp.rs`) actually issues: `realpath`,
/// `lstat`/`stat`, `opendir`/`readdir`, `open`/`read`/`write`/`close`,
/// `mkdir`, `rmdir`, `remove`, and `rename`. Every other request (for
/// example `symlink`, `setstat`, or the `posix-rename@openssh.com`
/// extension) falls back to the trait's default `Err(unimplemented())`
/// response; the SFTP backend under test never needs them, and for
/// rename specifically the client library falls back to a plain
/// rename on its own when the extension is not available.
struct SftpFsHandler {
    root: PathBuf,
    open_files: HashMap<String, std::fs::File>,
    open_dirs: HashMap<String, VecDeque<(String, std::fs::Metadata)>>,
    next_handle: u64,
}

impl SftpFsHandler {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            open_files: HashMap::new(),
            open_dirs: HashMap::new(),
            next_handle: 0,
        }
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let trimmed = path.trim_start_matches('/');
        if trimmed.is_empty() {
            self.root.clone()
        } else {
            self.root.join(trimmed)
        }
    }

    fn new_handle(&mut self) -> String {
        self.next_handle += 1;
        self.next_handle.to_string()
    }
}

impl russh_sftp::server::Handler for SftpFsHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let canonical = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        Ok(Name {
            id,
            files: vec![File::dummy(canonical)],
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let dir = self.resolve(&path);
        let read_dir = std::fs::read_dir(&dir).map_err(map_io_error)?;
        let mut entries = VecDeque::new();
        for entry in read_dir {
            let entry = entry.map_err(|_| StatusCode::Failure)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = entry.metadata().map_err(|_| StatusCode::Failure)?;
            entries.push_back((name, meta));
        }
        let handle = self.new_handle();
        self.open_dirs.insert(handle.clone(), entries);
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let entries = self.open_dirs.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if entries.is_empty() {
            return Err(StatusCode::Eof);
        }
        let files = entries
            .drain(..)
            .map(|(name, meta)| File::new(name, FileAttributes::from(&meta)))
            .collect();
        Ok(Name { id, files })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.open_files.remove(&handle);
        self.open_dirs.remove(&handle);
        Ok(ok_status(id))
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.resolve(&filename);
        let options: std::fs::OpenOptions = pflags.into();
        let file = options.open(&path).map_err(map_io_error)?;
        let handle = self.new_handle();
        self.open_files.insert(handle.clone(), file);
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self
            .open_files
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset)).map_err(map_io_error)?;
        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf).map_err(map_io_error)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self
            .open_files
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset)).map_err(map_io_error)?;
        file.write_all(&data).map_err(map_io_error)?;
        Ok(ok_status(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::symlink_metadata(self.resolve(&path)).map_err(map_io_error)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&meta),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::metadata(self.resolve(&path)).map_err(map_io_error)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&meta),
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        std::fs::create_dir(self.resolve(&path)).map_err(map_io_error)?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(self.resolve(&path)).map_err(map_io_error)?;
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(self.resolve(&filename)).map_err(map_io_error)?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        std::fs::rename(self.resolve(&oldpath), self.resolve(&newpath)).map_err(map_io_error)?;
        Ok(ok_status(id))
    }
}

/// Starts one fake SFTP server and returns the port it is already
/// listening on. Binding happens synchronously, on the calling
/// thread, before this returns: `tokio::net::TcpListener::bind`
/// performs the actual `bind`+`listen` syscalls as part of resolving,
/// not lazily when first polled, so there is no window where a test
/// could dial the port before the kernel is ready to accept on it and
/// no probe-based readiness check is needed.
fn spawn_sftp_server(runtime: &tokio::runtime::Runtime, root: PathBuf, policy: AuthPolicy) -> u16 {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate an ed25519 host key");
    let listener = runtime.block_on(async {
        tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral sftp port")
    });
    let port = listener
        .local_addr()
        .expect("read the bound sftp port")
        .port();
    let config = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        methods: methods_for(&policy),
        ..Default::default()
    });
    let mut server = SshServer { root, policy };
    runtime.spawn(async move {
        // This binary never shuts a server down; a returned error
        // would only ever show up as a later connect failing, never a
        // silent miss, since the listener above is already known-bound.
        let _ = server.run_on_socket(config, &listener).await;
    });
    port
}

/// Writes `contents` to a fresh file under `dir` with owner-only
/// permissions, the way `ssh-keygen` writes a private key. `ssh-add`
/// and OpenSSH's own client refuse a key file that is readable by
/// anyone else.
fn write_private_key_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write a private key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict the private key file's permissions");
    }
    path
}

/// The running `ssh-agent` this binary starts for the agent test, if
/// starting one and loading the client key into it both succeeded.
struct SshAgent {
    auth_sock: String,
}

/// Kills the agent registered in [`AGENT_PID`], if any. Registered
/// with `libc::atexit` so the agent does not outlive this test binary;
/// best effort, since a `static` in this binary is never dropped on a
/// normal process exit.
static AGENT_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn kill_registered_agent() {
    let pid = AGENT_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: `pid` names a real `ssh-agent` process this binary
        // started; sending it a signal touches no memory.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

/// Starts `ssh-agent`, loads `key_path` into it with `ssh-add`, and
/// returns the agent's `SSH_AUTH_SOCK`. `None` if `ssh-agent` or
/// `ssh-add` is unavailable or refuses to run, which this binary
/// treats as an environment limitation rather than a test failure
/// (see [`sftp_agent_login_lists`]).
fn start_ssh_agent_and_add_key(key_path: &Path) -> Option<SshAgent> {
    let output = Command::new("/usr/bin/ssh-agent").arg("-s").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let auth_sock = stdout.lines().find_map(|line| {
        line.strip_prefix("SSH_AUTH_SOCK=")
            .and_then(|rest| rest.split(';').next())
            .map(str::to_string)
    })?;
    let pid: i32 = stdout.lines().find_map(|line| {
        line.strip_prefix("SSH_AGENT_PID=")
            .and_then(|rest| rest.split(';').next())
            .and_then(|s| s.parse().ok())
    })?;
    AGENT_PID.store(pid, Ordering::SeqCst);
    // SAFETY: registered once, here, the only place this binary
    // starts an agent.
    unsafe {
        libc::atexit(kill_registered_agent);
    }

    let add_status = Command::new("ssh-add")
        .arg(key_path)
        .env("SSH_AUTH_SOCK", &auth_sock)
        .status()
        .ok()?;
    if !add_status.success() {
        return None;
    }
    Some(SshAgent { auth_sock })
}

/// Every fake SFTP server this binary starts, plus the client key
/// material and background runtime that keep them usable.
struct Servers {
    password_port: u16,
    password_root: TempDir,
    keyboard_interactive_port: u16,
    keyboard_interactive_root: TempDir,
    /// Accepts only [`Servers::client_key_public_openssh`]; used by
    /// the public-key, encrypted-key, and agent tests, since all three
    /// ultimately authenticate as the same keypair.
    public_key_port: u16,
    public_key_root: TempDir,
    none_port: u16,
    none_root: TempDir,
    _client_key_dir: TempDir,
    client_key_path: PathBuf,
    /// `Some` only if this `ssh-key` build could encrypt an OpenSSH
    /// key export; see [`servers`].
    client_key_encrypted_path: Option<PathBuf>,
    /// `Some` only if `ssh-agent`/`ssh-add` are usable in this
    /// environment; see [`start_ssh_agent_and_add_key`].
    ssh_agent: Option<SshAgent>,
    _runtime: tokio::runtime::Runtime,
}

/// Starts every fake server exactly once for the whole binary and
/// returns the shared handle.
fn servers() -> &'static Servers {
    static SERVERS: OnceLock<Servers> = OnceLock::new();
    SERVERS.get_or_init(|| {
        let runtime = tokio::runtime::Runtime::new().expect("build the fake-server runtime");

        let client_key_dir = tempfile::tempdir().expect("create the client key directory");
        let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("generate the client ed25519 key");
        let client_key_openssh = client_key
            .to_openssh(LineEnding::LF)
            .expect("encode the client key as OpenSSH PEM");
        let client_key_path =
            write_private_key_file(client_key_dir.path(), "client_key", &client_key_openssh);
        let client_key_public_openssh = client_key
            .public_key()
            .to_openssh()
            .expect("encode the client public key");

        let client_key_encrypted_path = client_key
            .encrypt(&mut rand::rng(), CLIENT_KEY_PASSPHRASE)
            .ok()
            .and_then(|encrypted| encrypted.to_openssh(LineEnding::LF).ok())
            .map(|pem| write_private_key_file(client_key_dir.path(), "client_key_encrypted", &pem));

        let password_root = tempfile::tempdir().expect("create the password sftp root");
        let keyboard_interactive_root =
            tempfile::tempdir().expect("create the keyboard-interactive sftp root");
        let public_key_root = tempfile::tempdir().expect("create the public-key sftp root");
        let none_root = tempfile::tempdir().expect("create the none-auth sftp root");

        let password_port = spawn_sftp_server(
            &runtime,
            password_root.path().to_path_buf(),
            AuthPolicy::PasswordOnly,
        );
        let keyboard_interactive_port = spawn_sftp_server(
            &runtime,
            keyboard_interactive_root.path().to_path_buf(),
            AuthPolicy::KeyboardInteractiveOnly,
        );
        let public_key_port = spawn_sftp_server(
            &runtime,
            public_key_root.path().to_path_buf(),
            AuthPolicy::PublicKeyOnly(client_key_public_openssh),
        );
        let none_port = spawn_sftp_server(
            &runtime,
            none_root.path().to_path_buf(),
            AuthPolicy::NoneAccepted,
        );

        let ssh_agent = start_ssh_agent_and_add_key(&client_key_path);
        if let Some(agent) = &ssh_agent {
            // SAFETY: `OnceLock::get_or_init` runs this closure at
            // most once, and no test reads `SSH_AUTH_SOCK` before
            // calling `servers()` first, so no reader ever observes a
            // partially set environment.
            unsafe {
                std::env::set_var("SSH_AUTH_SOCK", &agent.auth_sock);
            }
        }

        Servers {
            password_port,
            password_root,
            keyboard_interactive_port,
            keyboard_interactive_root,
            public_key_port,
            public_key_root,
            none_port,
            none_root,
            _client_key_dir: client_key_dir,
            client_key_path,
            client_key_encrypted_path,
            ssh_agent,
            _runtime: runtime,
        }
    })
}

/// A fresh, empty subdirectory under `root` (SFTP path form), unique
/// to one test so concurrent tests on the same server never collide.
fn fresh_root(root: &Path, label: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("{label}-{n}");
    std::fs::create_dir(root.join(&name)).expect("create a fresh test subdirectory");
    format!("/{name}")
}

fn config(port: u16, auth: AuthMethod) -> ConnectionConfig {
    ConnectionConfig {
        id: "sftp-bench".to_string(),
        display_name: "SFTP bench".to_string(),
        scheme: Scheme::Sftp,
        host: "127.0.0.1".to_string(),
        port: port as u32,
        username: SFTP_USER.to_string(),
        initial_path: "/".to_string(),
        auth,
    }
}

/// Hands out one fixed secret for any connection id.
struct FixedSecret(String);

impl SecretProvider for FixedSecret {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        Some(self.0.clone())
    }
}

/// Hands out no secret at all.
struct NoSecret;

impl SecretProvider for NoSecret {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        None
    }
}

fn password_secret() -> Arc<dyn SecretProvider> {
    Arc::new(FixedSecret(SFTP_PASSWORD.to_string()))
}

#[test]
fn password_login_passes_conformance() {
    let servers = servers();
    let root = fresh_root(servers.password_root.path(), "conformance");
    let cfg = config(servers.password_port, AuthMethod::Password);
    let backend = SftpFactory::default()
        .connect(&cfg, password_secret())
        .expect("connect with the right password");
    support::conformance::exercise_backend(&*backend, &root);
}

#[test]
fn keyboard_interactive_only_server_authenticates_via_the_fallback() {
    let servers = servers();
    let root = fresh_root(servers.keyboard_interactive_root.path(), "kbdint");
    let cfg = config(servers.keyboard_interactive_port, AuthMethod::Password);
    let backend = SftpFactory::default()
        .connect(&cfg, password_secret())
        .expect("the keyboard-interactive fallback must authenticate a plain password login");
    let entries = backend
        .list_dir(&root, &ListOptions::default())
        .expect("list the fresh root after keyboard-interactive auth");
    assert!(
        entries.is_empty(),
        "a fresh root must start empty: {entries:?}"
    );
}

#[test]
fn wrong_password_fails_cleanly_without_leaking_it() {
    let servers = servers();
    let cfg = config(servers.password_port, AuthMethod::Password);
    let wrong_secret: Arc<dyn SecretProvider> =
        Arc::new(FixedSecret("definitely-not-the-password".to_string()));

    let err = SftpFactory::default()
        .connect(&cfg, wrong_secret)
        .err()
        .expect("a wrong password must fail to connect");
    assert!(
        err.to_lowercase().contains("auth"),
        "error must name the auth step, got: {err}"
    );
    assert!(
        !err.contains("definitely-not-the-password"),
        "error must never contain the attempted password, got: {err}"
    );
}

#[test]
fn public_key_login_lists_and_a_wrong_key_fails() {
    let servers = servers();
    let root = fresh_root(servers.public_key_root.path(), "pubkey");
    let cfg = config(
        servers.public_key_port,
        AuthMethod::SshKey {
            key_path: servers.client_key_path.to_string_lossy().into_owned(),
        },
    );
    let backend = SftpFactory::default()
        .connect(&cfg, Arc::new(NoSecret))
        .expect("the registered key must authenticate");
    let entries = backend
        .list_dir(&root, &ListOptions::default())
        .expect("list the fresh root after key auth");
    assert!(
        entries.is_empty(),
        "a fresh root must start empty: {entries:?}"
    );

    // A different, freshly generated key that the server never saw.
    let wrong_key_dir = tempfile::tempdir().expect("create a directory for the wrong key");
    let wrong_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("generate a throwaway key");
    let wrong_key_openssh = wrong_key
        .to_openssh(LineEnding::LF)
        .expect("encode the throwaway key as OpenSSH PEM");
    let wrong_key_path =
        write_private_key_file(wrong_key_dir.path(), "wrong_key", &wrong_key_openssh);
    let mut wrong_cfg = cfg;
    wrong_cfg.auth = AuthMethod::SshKey {
        key_path: wrong_key_path.to_string_lossy().into_owned(),
    };
    let err = SftpFactory::default()
        .connect(&wrong_cfg, Arc::new(NoSecret))
        .err()
        .expect("a key the server never registered must fail");
    assert!(
        err.to_lowercase().contains("auth"),
        "error must mention authentication, got: {err}"
    );
}

#[test]
fn encrypted_key_authenticates_using_the_stored_passphrase() {
    let servers = servers();
    let Some(encrypted_path) = &servers.client_key_encrypted_path else {
        eprintln!(
            "skipping encrypted_key_authenticates_using_the_stored_passphrase: \
             this ssh-key build could not produce an encrypted OpenSSH key export"
        );
        return;
    };
    let root = fresh_root(servers.public_key_root.path(), "pubkey-encrypted");
    let cfg = config(
        servers.public_key_port,
        AuthMethod::SshKey {
            key_path: encrypted_path.to_string_lossy().into_owned(),
        },
    );
    let secrets: Arc<dyn SecretProvider> = Arc::new(FixedSecret(CLIENT_KEY_PASSPHRASE.to_string()));
    let backend = SftpFactory::default().connect(&cfg, secrets).expect(
        "the encrypted key with the right passphrase from the secret provider must authenticate",
    );
    let entries = backend
        .list_dir(&root, &ListOptions::default())
        .expect("list the fresh root after encrypted-key auth");
    assert!(
        entries.is_empty(),
        "a fresh root must start empty: {entries:?}"
    );
}

#[test]
fn none_accepted_server_authenticates_before_any_credential_is_sent() {
    let servers = servers();
    let root = fresh_root(servers.none_root.path(), "none");
    // `AuthMethod::Password` still needs a secret to build a config
    // that passes `prepare_auth`, but the wire-level "none" probe
    // libssh2 always tries first succeeds before that secret is ever
    // sent; see `userauth_password_with_fallback` in `sftp.rs`.
    let cfg = config(servers.none_port, AuthMethod::Password);
    let secrets: Arc<dyn SecretProvider> = Arc::new(FixedSecret("never-sent".to_string()));
    let backend = SftpFactory::default()
        .connect(&cfg, secrets)
        .expect("a server that accepts \"none\" must authenticate before any password is sent");
    let entries = backend
        .list_dir(&root, &ListOptions::default())
        .expect("list the fresh root after none-auth");
    assert!(
        entries.is_empty(),
        "a fresh root must start empty: {entries:?}"
    );
}

#[test]
fn sftp_agent_login_lists() {
    let servers = servers();
    if servers.ssh_agent.is_none() {
        eprintln!(
            "skipping sftp_agent_login_lists: ssh-agent/ssh-add are unavailable or refused to run \
             in this environment"
        );
        return;
    }
    let root = fresh_root(servers.public_key_root.path(), "agent");
    let cfg = config(servers.public_key_port, AuthMethod::SshAgent);
    let backend = SftpFactory::default()
        .connect(&cfg, Arc::new(NoSecret))
        .expect("agent auth with the loaded key must authenticate");
    let entries = backend
        .list_dir(&root, &ListOptions::default())
        .expect("list the fresh root after agent auth");
    assert!(
        entries.is_empty(),
        "a fresh root must start empty: {entries:?}"
    );
}
