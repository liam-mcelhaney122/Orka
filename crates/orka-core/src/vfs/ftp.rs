//! FTP backend over the `suppaftp` crate.
//!
//! [`FtpFactory`] dials and authenticates one control connection per
//! connection. [`FtpBackend`] serializes metadata calls (listing,
//! stat, delete, rename, mkdir) through one mutex because an FTP
//! control connection is stateful and one data-transfer command
//! occupies it until the transfer finishes. Each read or write
//! transfer therefore opens its own control connection on a pump
//! thread, exactly like the SFTP backend: the pump owns the
//! `suppaftp` handles, and chunks cross a bounded channel to a plain
//! `Read`/`Write` side the caller uses.
//!
//! This backend speaks both plain FTP and FTPS. Plain FTP sends the
//! login and every byte of data in cleartext; prefer `sftp://` when a
//! server supports it. FTPS wraps the same control and data
//! connections in TLS: port 990 dials straight into TLS (implicit
//! mode, deprecated by the FTP spec but still expected by many
//! servers); any other port connects in cleartext first and then
//! sends `AUTH TLS` (explicit mode). Both FTPS modes require `PROT P`
//! so file data, not only the login, travels encrypted. Error strings
//! must never include secret material.
//!
//! FTP has no generic "stat" command with reliable semantics across
//! servers, so [`FtpBackend::stat`] lists the parent directory and
//! matches the entry by name. This mirrors how graphical FTP clients
//! resolve single-path metadata.
//!
//! TLS verification trusts only the Mozilla root set baked in by
//! `webpki-roots`. A private or self-signed certificate authority is
//! not supported yet.

use super::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, UNIX_EPOCH};
use suppaftp::list::File as FtpFile;
use suppaftp::rustls::{ClientConfig, RootCertStore};
use suppaftp::{RustlsConnector, RustlsFtpStream, Status};

/// The control (and, once secured, data) connection type.
///
/// This is the same type whether or not the session ends up secured.
/// `suppaftp` tells the two apart only at the byte-stream level
/// (`DataStream`'s `Tcp`/`Ssl` variants), not at the Rust type level.
/// A plain FTP session and a negotiated FTPS session therefore share
/// this alias. Every operation below (list, read, write, rename,
/// delete, mkdir, transfer pumps) works unchanged on both.
type FtpStream = RustlsFtpStream;

/// The conventional implicit-TLS FTPS port. A connect to any other
/// port uses explicit `AUTH TLS` instead.
const IMPLICIT_TLS_PORT: u16 = 990;

/// TCP dial timeout. Covers connect only.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Read/write timeout applied to the control connection once it is up.
/// Best effort: it bounds the control channel, but a data connection
/// opened later for a transfer is a separate socket with its own
/// default (unbounded) timeout.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Bytes per chunk on a transfer channel.
const CHUNK_SIZE: usize = 128 * 1024;

/// Chunks a transfer channel buffers. With [`CHUNK_SIZE`] this bounds
/// in-flight memory near 512 KiB per transfer.
const CHANNEL_DEPTH: usize = 4;

/// Auth material resolved before the network dial. Resolving first
/// gives a missing secret or a bad config an immediate error instead
/// of a pointless TCP connect.
enum PreparedAuth {
    Password(String),
    Anonymous,
}

/// The user/password pair anonymous FTP expects. `anonymous@` is the
/// conventional email-like placeholder (RFC 1635); most servers that
/// allow anonymous access accept it, and many also accept an empty
/// password.
fn anonymous_credentials() -> (&'static str, &'static str) {
    ("anonymous", "anonymous@")
}

fn prepare_auth(
    config: &ConnectionConfig,
    secrets: &dyn SecretProvider,
) -> Result<PreparedAuth, String> {
    match &config.auth {
        AuthMethod::Password => {
            let password = secrets
                .get_secret(&config.id)
                .ok_or_else(|| "no password stored for this connection".to_string())?;
            Ok(PreparedAuth::Password(password))
        }
        AuthMethod::None => Ok(PreparedAuth::Anonymous),
        AuthMethod::SshKey { .. }
        | AuthMethod::SshAgent
        | AuthMethod::S3Profile { .. }
        | AuthMethod::S3Keys
        | AuthMethod::OAuthToken
        | AuthMethod::SharedKey
        | AuthMethod::SasToken
        | AuthMethod::ServicePrincipal { .. }
        | AuthMethod::OAuthApp { .. }
        | AuthMethod::ServiceAccount
        | AuthMethod::Kerberos => Err("wrong auth method for ftp".to_string()),
    }
}

/// Dials and authenticates one control connection for one config. The
/// factory uses it for the primary connection; every transfer pump
/// uses it again for its own connection. `tls` selects FTPS: implicit
/// mode on [`IMPLICIT_TLS_PORT`], explicit `AUTH TLS` otherwise.
fn connect_session(
    config: &ConnectionConfig,
    secrets: &dyn SecretProvider,
    tls: bool,
) -> Result<FtpStream, String> {
    let auth = prepare_auth(config, secrets)?;
    let port = u16::try_from(config.port).map_err(|_| format!("invalid port {}", config.port))?;
    let addr = (config.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {}: {e}", config.host))?
        .next()
        .ok_or_else(|| format!("cannot resolve {}", config.host))?;
    let mut stream = if tls {
        connect_tls(&config.host, addr, port)?
    } else {
        FtpStream::connect_timeout(addr, CONNECT_TIMEOUT)
            .map_err(|e| format!("cannot connect to {}:{port}: {e}", config.host))?
    };
    // Best effort: an unsupported timeout on the underlying socket
    // must not fail the connect.
    let _ = stream.get_ref().set_read_timeout(Some(SESSION_TIMEOUT));
    let _ = stream.get_ref().set_write_timeout(Some(SESSION_TIMEOUT));
    let (user, password) = match &auth {
        PreparedAuth::Password(password) => (config.username.as_str(), password.as_str()),
        PreparedAuth::Anonymous => anonymous_credentials(),
    };
    // Error strings must never include secret material.
    stream
        .login(user, password)
        .map_err(|_| "login failed".to_string())?;
    Ok(stream)
}

/// True when `port` is the conventional implicit-TLS FTPS port.
fn is_implicit_tls_port(port: u16) -> bool {
    port == IMPLICIT_TLS_PORT
}

/// A TLS connector trusting the Mozilla root set baked in by
/// `webpki-roots`. Built fresh per connect: an FTP control connection
/// is short-lived compared to the cost of building a `ClientConfig`,
/// and a fresh connector keeps this function free of shared mutable
/// state.
fn tls_connector() -> RustlsConnector {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    RustlsConnector::from(Arc::new(config))
}

/// Dials `addr` over FTPS. `host` is the TLS server name and must be
/// the name from the connection config, not a resolved IP: it is used
/// for both SNI and certificate verification.
///
/// Both modes dial (and, for explicit mode, apply the session
/// timeouts) before any TLS byte crosses the wire, so a stalled dial
/// or a stalled handshake cannot hang past [`CONNECT_TIMEOUT`].
fn connect_tls(host: &str, addr: SocketAddr, port: u16) -> Result<FtpStream, String> {
    let connector = tls_connector();
    if is_implicit_tls_port(port) {
        let mut stream = connect_secure_implicit_bounded(addr, connector, host, CONNECT_TIMEOUT)
            .map_err(|e| format!("cannot connect to {host}:{port}: {e}"))?;
        // Best effort: an unsupported timeout on the underlying socket
        // must not fail the connect.
        let _ = stream.get_ref().set_read_timeout(Some(SESSION_TIMEOUT));
        let _ = stream.get_ref().set_write_timeout(Some(SESSION_TIMEOUT));
        // Implicit mode skips the `AUTH TLS` exchange that normally
        // negotiates PBSZ/PROT, so the data channel is protected by
        // hand here.
        secure_data_channel(&mut stream)?;
        Ok(stream)
    } else {
        let socket = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| format!("cannot connect to {host}:{port}: {e}"))?;
        // Best effort: an unsupported timeout on the underlying socket
        // must not fail the connect. Setting it now, before the
        // control-channel greeting and the TLS handshake, bounds both.
        let _ = socket.set_read_timeout(Some(SESSION_TIMEOUT));
        let _ = socket.set_write_timeout(Some(SESSION_TIMEOUT));
        let plain = FtpStream::connect_with_stream(socket)
            .map_err(|e| format!("cannot connect to {host}:{port}: {e}"))?;
        // `into_secure` negotiates PBSZ 0 and PROT P itself.
        plain
            .into_secure(connector, host)
            .map_err(|e| format!("cannot negotiate TLS with {host}:{port}: {e}"))
    }
}

/// Dials `addr` and negotiates implicit FTPS, bounded to `timeout`.
///
/// `suppaftp` (6.3.0) has no stream-based constructor for implicit
/// mode: [`FtpStream::connect_secure_implicit`] always dials its own
/// `TcpStream::connect` internally, with no timeout and no stream
/// handed in, so this cannot set a timeout on the socket up front the
/// way [`connect_tls`] does for explicit mode. Instead this runs the
/// whole dial and handshake on a helper thread and stops waiting for
/// it once `timeout` elapses. A helper thread that misses the
/// deadline is abandoned; std has no way to cancel a blocking socket
/// call from outside it, so the thread finishes (or fails) on its own
/// once the connect or handshake resolves.
fn connect_secure_implicit_bounded(
    addr: SocketAddr,
    connector: RustlsConnector,
    host: &str,
    timeout: Duration,
) -> Result<FtpStream, String> {
    let host = host.to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result =
            FtpStream::connect_secure_implicit(addr, connector, &host).map_err(|e| e.to_string());
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(format!("timed out after {}s", timeout.as_secs())),
    }
}

/// Sends `PBSZ 0` then `PROT P` so the data channel (listings,
/// transfers), not only the login, is encrypted. `into_secure` does
/// this on its own for explicit TLS; implicit TLS has no equivalent
/// step in `suppaftp`, so implicit mode calls this directly.
fn secure_data_channel(stream: &mut FtpStream) -> Result<(), String> {
    stream
        .custom_command("PBSZ 0", &[Status::CommandOk])
        .map_err(|e| format!("cannot set protection buffer size: {e}"))?;
    stream
        .custom_command("PROT P", &[Status::CommandOk])
        .map_err(|e| format!("cannot require an encrypted data channel: {e}"))?;
    Ok(())
}

/// Creates FTP backends for [`super::Scheme::Ftp`] and
/// [`super::Scheme::Ftps`]. Plain FTP (`tls: false`) sends the login
/// and all data in cleartext. FTPS (`tls: true`) wraps the control
/// connection, and per [`secure_data_channel`] the data connection
/// too, in TLS: see [`connect_tls`] for implicit-vs-explicit mode
/// selection.
#[derive(Debug, Clone, Copy, Default)]
pub struct FtpFactory {
    tls: bool,
}

impl FtpFactory {
    /// An FTPS factory. Port 990 means implicit TLS; any other port
    /// means explicit `AUTH TLS` on the plain control connection.
    pub fn tls() -> Self {
        Self { tls: true }
    }
}

impl BackendFactory for FtpFactory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        let stream = connect_session(config, secrets.as_ref(), self.tls)?;
        Ok(Arc::new(FtpBackend {
            inner: Mutex::new(stream),
            config: config.clone(),
            secrets,
            tls: self.tls,
        }))
    }
}

/// Joins a directory path with a child name without a double slash.
fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// The directory that contains `path`, for stat's parent-listing walk.
fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

/// True for a server-reported name that is safe to join onto a path
/// with [`join_path`]. A server-reported name is untrusted: `.`/`..`
/// and any name containing `/` must be rejected, or a crafted LIST
/// entry could build a path outside the directory being listed or
/// deleted (`delete_tree` recurses on whatever path it builds).
fn is_safe_child_name(name: &str) -> bool {
    name != "." && name != ".." && !name.contains('/')
}

/// The final path segment, for matching an entry by name in a parent
/// listing. `None` for a path with no segment (the root).
fn last_segment(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn is_root(path: &str) -> bool {
    path.is_empty() || path == "/"
}

/// A synthetic entry for the root, which has no parent directory to
/// list. FTP has no metadata for the root itself, so size and
/// modification time are unavailable.
fn root_entry() -> Entry {
    Entry {
        name: "/".to_string(),
        path: "/".to_string(),
        is_dir: true,
        size: 0,
        modified_ms: 0,
        is_hidden: false,
        is_symlink: false,
    }
}

/// Builds an [`Entry`] from a parsed LIST line. `path` is the full
/// backend-local path the caller has already computed.
fn entry_from_file(path: &str, name: String, file: &FtpFile) -> Entry {
    let is_dir = file.is_directory();
    let modified_ms = file
        .modified()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Entry {
        is_hidden: name.starts_with('.'),
        name,
        path: path.to_string(),
        is_dir,
        size: if is_dir { 0 } else { file.size() as u64 },
        modified_ms,
        is_symlink: file.is_symlink(),
    }
}

/// A chunk from a read pump. `Err` carries the pump's failure once,
/// after which the channel closes.
type ChunkResult = Result<Vec<u8>, String>;

/// `Read` over a chunk channel. The pump thread owns the `suppaftp`
/// handles; this side only drains bytes, so it is plain `Send`
/// plumbing.
struct ChannelReader {
    rx: Receiver<ChunkResult>,
    /// Current chunk, partially consumed up to `pos`.
    buffer: Vec<u8>,
    pos: usize,
    done: bool,
}

impl ChannelReader {
    fn new(rx: Receiver<ChunkResult>) -> Self {
        Self {
            rx,
            buffer: Vec::new(),
            pos: 0,
            done: false,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.buffer.len() {
            if self.done {
                return Ok(0);
            }
            match self.rx.recv() {
                Ok(Ok(chunk)) => {
                    self.buffer = chunk;
                    self.pos = 0;
                }
                Ok(Err(message)) => {
                    self.done = true;
                    return Err(io::Error::other(message));
                }
                // A closed channel with no error is end of file.
                Err(_) => {
                    self.done = true;
                    return Ok(0);
                }
            }
        }
        let n = buf.len().min(self.buffer.len() - self.pos);
        buf[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Reads `path` on its own control connection and feeds chunks to
/// `tx`. A send failure means the reader dropped; the pump still
/// finalizes the data transfer on the control channel and then stops.
fn read_pump(
    config: &ConnectionConfig,
    secrets: &dyn SecretProvider,
    tls: bool,
    path: &str,
    tx: &SyncSender<ChunkResult>,
) -> Result<(), String> {
    let mut stream = connect_session(config, secrets, tls)?;
    let mut data = stream
        .retr_as_stream(path)
        .map_err(|e| format!("cannot open {path}: {e}"))?;
    loop {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let n = data
            .read(&mut chunk)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        chunk.truncate(n);
        if tx.send(Ok(chunk)).is_err() {
            let _ = stream.finalize_retr_stream(data);
            return Ok(());
        }
    }
    stream
        .finalize_retr_stream(data)
        .map_err(|e| format!("cannot finish reading {path}: {e}"))
}

/// `Write` over a chunk channel to a pump thread that owns the
/// `suppaftp` handles. A pump failure poisons the writer, so the next
/// `write` or `flush` reports the stored error.
struct ChannelWriter {
    /// `None` after `finish`, which closes the channel.
    tx: Option<SyncSender<Vec<u8>>>,
    /// The pump's final result, sent exactly once before it exits.
    done_rx: Receiver<Result<(), String>>,
    handle: Option<JoinHandle<()>>,
    poisoned: Option<String>,
}

impl ChannelWriter {
    fn new(
        tx: SyncSender<Vec<u8>>,
        done_rx: Receiver<Result<(), String>>,
        handle: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            tx: Some(tx),
            done_rx,
            handle,
            poisoned: None,
        }
    }

    /// Sends one chunk. A send failure means the pump exited early;
    /// the pump's final result then explains why.
    fn send(&mut self, chunk: Vec<u8>) -> io::Result<()> {
        if let Some(message) = &self.poisoned {
            return Err(io::Error::other(message.clone()));
        }
        let Some(tx) = &self.tx else {
            return Err(io::Error::other("writer is closed"));
        };
        if tx.send(chunk).is_err() {
            let message = match self.done_rx.recv() {
                Ok(Err(message)) => message,
                _ => "write pump exited early".to_string(),
            };
            self.poisoned = Some(message.clone());
            return Err(io::Error::other(message));
        }
        Ok(())
    }

    /// Closes the channel, waits for the pump's final result, and
    /// joins the thread. Idempotent; later calls repeat the outcome.
    fn finish(&mut self) -> Result<(), String> {
        // Dropping the sender is the close signal for the pump.
        self.tx.take();
        let result = match &self.poisoned {
            Some(message) => Err(message.clone()),
            None => match self.done_rx.recv() {
                Ok(result) => result,
                Err(_) => Err("write pump exited without a result".to_string()),
            },
        };
        if let Err(message) = &result {
            self.poisoned = Some(message.clone());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        result
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.send(buf.to_vec())?;
        Ok(buf.len())
    }

    /// A barrier only: an empty chunk crosses the channel and surfaces
    /// a pump failure.
    fn flush(&mut self) -> io::Result<()> {
        self.send(Vec::new())
    }
}

impl WriteFinish for ChannelWriter {
    /// Closes the pump and returns its final result, so a close-time
    /// failure (quota, dropped connection) reaches the caller.
    fn finish(mut self: Box<Self>) -> Result<(), String> {
        ChannelWriter::finish(&mut self)
    }
}

impl Drop for ChannelWriter {
    /// Best-effort backstop for an abandoned writer. A failure here
    /// has no caller left to reach; callers that need certainty must
    /// use [`WriteFinish::finish`].
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// Writes chunks from `rx` to `path` on its own control connection.
/// Returns after the writer closes the channel and the transfer
/// finalizes.
fn write_pump(
    config: &ConnectionConfig,
    secrets: &dyn SecretProvider,
    tls: bool,
    path: &str,
    rx: &Receiver<Vec<u8>>,
) -> Result<(), String> {
    let mut stream = connect_session(config, secrets, tls)?;
    let mut data = stream
        .put_with_stream(path)
        .map_err(|e| format!("cannot create {path}: {e}"))?;
    while let Ok(chunk) = rx.recv() {
        // An empty chunk is a flush barrier; nothing to write.
        if chunk.is_empty() {
            continue;
        }
        data.write_all(&chunk)
            .map_err(|e| format!("cannot write {path}: {e}"))?;
    }
    stream
        .finalize_put_stream(data)
        .map_err(|e| format!("cannot close {path}: {e}"))
}

/// One live FTP connection. The mutex holds the primary control
/// connection for metadata calls; an FTP control connection does not
/// support concurrent commands. Transfers never take this mutex: each
/// one dials its own connection from the stored config and secrets,
/// so a long transfer cannot block listings.
pub struct FtpBackend {
    inner: Mutex<FtpStream>,
    config: ConnectionConfig,
    secrets: Arc<dyn SecretProvider>,
    tls: bool,
}

impl FtpBackend {
    /// Deletes a directory tree with a manual walk: FTP has no
    /// server-side recursive delete. Takes `&mut FtpStream` so the
    /// caller's lock guard covers the whole recursion; the mutex is
    /// not reentrant.
    fn delete_tree(stream: &mut FtpStream, path: &str) -> Result<(), String> {
        let lines = stream
            .list(Some(path))
            .map_err(|e| format!("cannot list {path}: {e}"))?;
        for line in &lines {
            let Ok(file) = FtpFile::try_from(line.as_str()) else {
                continue;
            };
            let name = file.name();
            if !is_safe_child_name(name) {
                continue;
            }
            let child = join_path(path, name);
            if file.is_directory() && !file.is_symlink() {
                Self::delete_tree(stream, &child)?;
            } else {
                stream
                    .rm(&child)
                    .map_err(|e| format!("cannot delete {child}: {e}"))?;
            }
        }
        stream
            .rmdir(path)
            .map_err(|e| format!("cannot delete {path}: {e}"))
    }
}

impl FsBackend for FtpBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            is_local: false,
            can_trash: false,
            can_watch: false,
            can_rename: true,
            server_side_copy: false,
            preserves_permissions: false,
        }
    }

    fn list_dir(&self, path: &str, opts: &ListOptions) -> Result<Vec<Entry>, String> {
        let mut guard = self.inner.lock().unwrap();
        let lines = guard
            .list(Some(path))
            .map_err(|e| format!("cannot list {path}: {e}"))?;
        let mut entries = Vec::new();
        for line in &lines {
            // Some servers emit a non-entry summary line (e.g. "total
            // 12") ahead of POSIX-style listings; it fails to parse
            // and is skipped rather than treated as an error.
            let Ok(file) = FtpFile::try_from(line.as_str()) else {
                continue;
            };
            let name = file.name().to_string();
            if !is_safe_child_name(&name) {
                continue;
            }
            if name.starts_with('.') && !opts.include_hidden {
                continue;
            }
            let item_path = join_path(path, &name);
            let entry = entry_from_file(&item_path, name, &file);
            if opts.dirs_only && !entry.is_dir {
                continue;
            }
            entries.push(entry);
        }
        crate::sort_entries(&mut entries);
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        if is_root(path) {
            return Ok(root_entry());
        }
        let name = last_segment(path).ok_or_else(|| format!("cannot stat {path}: invalid path"))?;
        let parent = parent_of(path);
        let mut guard = self.inner.lock().unwrap();
        let lines = guard
            .list(Some(parent))
            .map_err(|e| format!("cannot stat {path}: {e}"))?;
        for line in &lines {
            let Ok(file) = FtpFile::try_from(line.as_str()) else {
                continue;
            };
            if file.name() == name {
                return Ok(entry_from_file(path, name.to_string(), &file));
            }
        }
        Err(format!("cannot stat {path}: not found"))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        let (tx, rx) = mpsc::sync_channel::<ChunkResult>(CHANNEL_DEPTH);
        let config = self.config.clone();
        let secrets = self.secrets.clone();
        let tls = self.tls;
        let path = path.to_string();
        std::thread::spawn(move || {
            if let Err(message) = read_pump(&config, secrets.as_ref(), tls, &path, &tx) {
                // A send failure means the reader is gone; drop the
                // error with it.
                let _ = tx.send(Err(message));
            }
        });
        // A connect or open failure surfaces on the first read call.
        Ok(Box::new(ChannelReader::new(rx)))
    }

    fn create_write(
        &self,
        path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_DEPTH);
        let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let config = self.config.clone();
        let secrets = self.secrets.clone();
        let tls = self.tls;
        let path = path.to_string();
        let handle = std::thread::spawn(move || {
            let result = write_pump(&config, secrets.as_ref(), tls, &path, &rx);
            // An error must also drain no further: returning drops rx,
            // so the writer's next send fails and reads this result.
            let _ = done_tx.send(result);
        });
        Ok(Box::new(ChannelWriter::new(tx, done_rx, Some(handle))))
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let entry = self.stat(path)?;
        let mut guard = self.inner.lock().unwrap();
        if entry.is_dir && !entry.is_symlink {
            if recursive {
                Self::delete_tree(&mut guard, path)
            } else {
                guard
                    .rmdir(path)
                    .map_err(|e| format!("cannot delete {path}: {e}"))
            }
        } else {
            guard
                .rm(path)
                .map_err(|e| format!("cannot delete {path}: {e}"))
        }
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let mut guard = self.inner.lock().unwrap();
        guard
            .rename(from, to)
            .map_err(|e| format!("cannot rename {from}: {e}"))
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let mut guard = self.inner.lock().unwrap();
        guard
            .mkdir(path)
            .map_err(|e| format!("cannot create {path}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::Scheme;
    use std::time::Instant;

    struct NoSecrets;
    impl SecretProvider for NoSecrets {
        fn get_secret(&self, _connection_id: &str) -> Option<String> {
            None
        }
    }

    fn config(auth: AuthMethod) -> ConnectionConfig {
        ConnectionConfig {
            id: "test".to_string(),
            display_name: "Test".to_string(),
            scheme: Scheme::Ftp,
            host: "127.0.0.1".to_string(),
            port: 21,
            username: "user".to_string(),
            initial_path: "/".to_string(),
            auth,
        }
    }

    #[test]
    fn anonymous_credentials_are_the_ftp_convention() {
        assert_eq!(anonymous_credentials(), ("anonymous", "anonymous@"));
    }

    #[test]
    fn is_safe_child_name_rejects_traversal_and_slashes() {
        assert!(is_safe_child_name("file.txt"));
        assert!(is_safe_child_name(".hidden"));
        assert!(!is_safe_child_name("."));
        assert!(!is_safe_child_name(".."));
        // A crafted LIST name must never carry its own path separator:
        // join_path would build a path outside the directory being
        // listed or deleted.
        assert!(!is_safe_child_name("../../../etc/passwd"));
        assert!(!is_safe_child_name("../sibling"));
        assert!(!is_safe_child_name("a/b"));
    }

    #[test]
    fn join_path_avoids_double_slash_at_root() {
        assert_eq!(join_path("/", "file.txt"), "/file.txt");
        assert_eq!(join_path("/a/b", "c"), "/a/b/c");
    }

    #[test]
    fn parent_of_finds_the_containing_directory() {
        assert_eq!(parent_of("/a/b/c"), "/a/b");
        assert_eq!(parent_of("/a"), "/");
        assert_eq!(parent_of("/"), "/");
    }

    #[test]
    fn last_segment_extracts_the_final_component() {
        assert_eq!(last_segment("/a/b/c"), Some("c"));
        assert_eq!(last_segment("/a"), Some("a"));
        assert_eq!(last_segment("/"), None);
        assert_eq!(last_segment(""), None);
    }

    #[test]
    fn root_is_recognized_with_or_without_the_slash() {
        assert!(is_root("/"));
        assert!(is_root(""));
        assert!(!is_root("/a"));
    }

    #[test]
    fn entry_from_file_flags_dotfiles_as_hidden() {
        let file = FtpFile::try_from("-rw-r--r-- 1 user group 100 Jan 1 2024 .hidden").unwrap();
        let entry = entry_from_file("/.hidden", ".hidden".to_string(), &file);
        assert!(entry.is_hidden);
        assert!(!entry.is_dir);
        assert_eq!(entry.size, 100);
    }

    #[test]
    fn entry_from_file_reports_directories_with_zero_size() {
        let file = FtpFile::try_from("drwxr-xr-x 2 user group 4096 Jan 1 2024 sub").unwrap();
        let entry = entry_from_file("/sub", "sub".to_string(), &file);
        assert!(entry.is_dir);
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn wrong_auth_method_is_rejected_before_any_dial() {
        // The host is unroutable; a fast error proves no dial happened.
        let mut cfg = config(AuthMethod::SshAgent);
        cfg.host = "host.invalid".to_string();
        let start = Instant::now();
        let err = FtpFactory::default()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("wrong auth method"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn missing_password_fails_before_any_dial() {
        let mut cfg = config(AuthMethod::Password);
        cfg.host = "host.invalid".to_string();
        let start = Instant::now();
        let err = FtpFactory::default()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("no password stored"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn is_implicit_tls_port_selects_990_only() {
        assert!(is_implicit_tls_port(990));
        assert!(!is_implicit_tls_port(21));
        assert!(!is_implicit_tls_port(2121));
        assert!(!is_implicit_tls_port(0));
    }

    #[test]
    fn tls_factory_rejects_wrong_auth_method_before_any_dial() {
        // Same auth kinds as plain FTP; the check runs before TLS mode
        // selection or any dial, so an unroutable host still proves no
        // network access happened.
        let mut cfg = config(AuthMethod::SshAgent);
        cfg.scheme = Scheme::Ftps;
        cfg.host = "host.invalid".to_string();
        let start = Instant::now();
        let err = FtpFactory::tls()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("wrong auth method"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn tls_factory_rejects_missing_password_before_any_dial() {
        let mut cfg = config(AuthMethod::Password);
        cfg.scheme = Scheme::Ftps;
        cfg.host = "host.invalid".to_string();
        let start = Instant::now();
        let err = FtpFactory::tls()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("no password stored"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn closed_port_fails_cleanly_and_quickly() {
        // Bind then drop a listener to get a port that refuses connects.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut cfg = config(AuthMethod::None);
        cfg.port = port as u32;
        let start = Instant::now();
        let err = FtpFactory::default()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("cannot connect"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(20));
    }

    #[test]
    fn tls_closed_port_fails_cleanly_on_the_explicit_path() {
        // An ephemeral port is never 990, so this exercises
        // connect_tls's explicit branch (plain connect, then
        // into_secure) rather than connect_secure_implicit.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        assert!(!is_implicit_tls_port(port));
        let mut cfg = config(AuthMethod::None);
        cfg.scheme = Scheme::Ftps;
        cfg.port = port as u32;
        let start = Instant::now();
        let err = FtpFactory::tls()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("cannot connect"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(20));
    }

    #[test]
    fn implicit_bounded_connect_fails_cleanly_on_a_closed_port() {
        // Exercises connect_secure_implicit_bounded directly: a closed
        // port refuses the dial immediately, well inside the timeout,
        // and the helper thread's error reaches the caller.
        let addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let start = Instant::now();
        let err = connect_secure_implicit_bounded(
            addr,
            tls_connector(),
            "localhost",
            Duration::from_secs(5),
        )
        .err()
        .expect("must fail");
        assert!(!err.is_empty());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn channel_reader_streams_chunks_in_order() {
        let (tx, rx) = mpsc::sync_channel::<ChunkResult>(CHANNEL_DEPTH);
        let pump = std::thread::spawn(move || {
            tx.send(Ok(b"hello ".to_vec())).unwrap();
            tx.send(Ok(b"streaming ".to_vec())).unwrap();
            tx.send(Ok(b"world".to_vec())).unwrap();
            // Dropping the sender signals end of file.
        });
        let mut reader = ChannelReader::new(rx);
        let mut out = String::new();
        reader.read_to_string(&mut out).unwrap();
        assert_eq!(out, "hello streaming world");
        // End of file must stay stable across repeated reads.
        assert_eq!(reader.read(&mut [0u8; 8]).unwrap(), 0);
        pump.join().unwrap();
    }

    #[test]
    fn channel_reader_surfaces_pump_error_after_good_bytes() {
        let (tx, rx) = mpsc::sync_channel::<ChunkResult>(CHANNEL_DEPTH);
        tx.send(Ok(b"partial".to_vec())).unwrap();
        tx.send(Err("connection lost".to_string())).unwrap();
        drop(tx);
        let mut reader = ChannelReader::new(rx);
        let mut buf = [0u8; 16];
        assert_eq!(reader.read(&mut buf).unwrap(), 7);
        let err = reader.read(&mut buf).unwrap_err();
        assert!(err.to_string().contains("connection lost"), "got: {err}");
    }

    /// Fake write pump with the production channel shapes. Collects
    /// bytes and reports `result` when the writer closes the channel.
    fn fake_write_pump(
        result: Result<(), String>,
        fail_immediately: bool,
    ) -> (ChannelWriter, Arc<Mutex<Vec<u8>>>) {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_DEPTH);
        let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let written = Arc::new(Mutex::new(Vec::new()));
        let sink = written.clone();
        let handle = std::thread::spawn(move || {
            if !fail_immediately {
                while let Ok(chunk) = rx.recv() {
                    sink.lock().unwrap().extend_from_slice(&chunk);
                }
            }
            // Returning drops rx, so a failed pump rejects later sends.
            let _ = done_tx.send(result);
        });
        (ChannelWriter::new(tx, done_rx, Some(handle)), written)
    }

    #[test]
    fn channel_writer_delivers_bytes_and_finishes_clean() {
        let (mut writer, written) = fake_write_pump(Ok(()), false);
        writer.write_all(b"first ").unwrap();
        writer.flush().unwrap();
        writer.write_all(b"second").unwrap();
        assert_eq!(writer.finish(), Ok(()));
        assert_eq!(written.lock().unwrap().as_slice(), b"first second");
    }

    #[test]
    fn channel_writer_poisons_after_pump_failure() {
        let (mut writer, _) = fake_write_pump(Err("disk full".to_string()), true);
        let err = loop {
            match writer.write_all(b"data") {
                Ok(()) => continue,
                Err(err) => break err,
            }
        };
        assert!(err.to_string().contains("disk full"), "got: {err}");
        let err = writer.flush().unwrap_err();
        assert!(err.to_string().contains("disk full"), "got: {err}");
        assert_eq!(writer.finish(), Err("disk full".to_string()));
    }

    #[test]
    fn channel_writer_drop_joins_pump() {
        let (mut writer, written) = fake_write_pump(Ok(()), false);
        writer.write_all(b"bytes").unwrap();
        drop(writer);
        assert_eq!(written.lock().unwrap().as_slice(), b"bytes");
    }
}
