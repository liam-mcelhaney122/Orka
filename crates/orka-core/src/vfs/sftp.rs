//! SFTP backend over the `ssh2` crate.
//!
//! [`SftpFactory`] dials and authenticates one session per connection.
//! [`SftpBackend`] serializes metadata calls through one mutex because
//! an ssh2 session is `Send` but not safe for concurrent use. Each
//! read or write transfer opens its own session on a pump thread, so
//! transfers stream without holding the metadata lock. An ssh2 file
//! handle borrows its `Sftp`, so the handle stays inside the pump
//! thread and chunks cross a bounded channel. Rsync mode serves the
//! same wire protocols and adds same-backend copies through a remote
//! `cp` over `ssh`.

use super::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};
use ssh2::{OpenFlags, OpenType, RenameFlags, Session, Sftp};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// TCP dial timeout. Covers connect only; the session timeout below
/// covers the handshake and every later call.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-call timeout in milliseconds. A stalled server errors the call
/// instead of hanging the ops worker.
const SESSION_TIMEOUT_MS: u32 = 30_000;

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
    Key {
        key_path: PathBuf,
        passphrase: Option<String>,
    },
    Agent,
}

/// Expands a leading `~` or `~/` to the value of `HOME`.
fn expand_key_path(key_path: &str) -> Result<PathBuf, String> {
    if key_path == "~" || key_path.starts_with("~/") {
        let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
        let rest = key_path.strip_prefix('~').unwrap();
        return Ok(PathBuf::from(format!("{home}{rest}")));
    }
    Ok(PathBuf::from(key_path))
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
        AuthMethod::SshKey { key_path } => Ok(PreparedAuth::Key {
            key_path: expand_key_path(key_path)?,
            // A missing secret means an unencrypted key.
            passphrase: secrets.get_secret(&config.id),
        }),
        AuthMethod::SshAgent => Ok(PreparedAuth::Agent),
        AuthMethod::S3Profile { .. }
        | AuthMethod::S3Keys
        | AuthMethod::OAuthToken
        | AuthMethod::SharedKey
        | AuthMethod::SasToken
        | AuthMethod::ServicePrincipal { .. }
        | AuthMethod::OAuthApp { .. }
        | AuthMethod::ServiceAccount
        | AuthMethod::Kerberos
        | AuthMethod::None => Err("wrong auth method for sftp".to_string()),
    }
}

/// Dials, authenticates, and opens the SFTP subsystem for one config.
/// The factory uses it for the primary session; every transfer pump
/// uses it again for its own session.
fn connect_session(
    config: &ConnectionConfig,
    secrets: &dyn SecretProvider,
) -> Result<(Session, Sftp), String> {
    let auth = prepare_auth(config, secrets)?;
    let port = u16::try_from(config.port).map_err(|_| format!("invalid port {}", config.port))?;
    let addr = (config.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {}: {e}", config.host))?
        .next()
        .ok_or_else(|| format!("cannot resolve {}", config.host))?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("cannot connect to {}:{port}: {e}", config.host))?;
    let mut session = Session::new().map_err(|e| format!("ssh session failed: {e}"))?;
    // Bound the handshake and every later call.
    session.set_timeout(SESSION_TIMEOUT_MS);
    session.set_tcp_stream(stream);
    session
        .handshake()
        .map_err(|e| format!("ssh handshake failed: {e}"))?;
    let user = config.username.as_str();
    // Error strings must never include secret material.
    match auth {
        PreparedAuth::Password(password) => session
            .userauth_password(user, &password)
            .map_err(|e| format!("password auth failed: {e}"))?,
        PreparedAuth::Key {
            key_path,
            passphrase,
        } => session
            .userauth_pubkey_file(user, None, &key_path, passphrase.as_deref())
            .map_err(|e| format!("key auth failed: {e}"))?,
        PreparedAuth::Agent => session
            .userauth_agent(user)
            .map_err(|e| format!("agent auth failed: {e}"))?,
    }
    if !session.authenticated() {
        return Err("authentication failed".to_string());
    }
    let sftp = session
        .sftp()
        .map_err(|e| format!("sftp subsystem failed: {e}"))?;
    Ok((session, sftp))
}

/// Which transport role one backend plays. Both modes speak SFTP over
/// SSH for listings, transfers, and metadata. The difference is the
/// copy path: `Rsync` may shell out to a remote `cp` over `ssh`,
/// while `Sftp` always streams copies through this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpMode {
    Sftp,
    Rsync,
}

/// Deadline for one remote copy. A hung `ssh` must not stall the ops
/// worker forever.
const REMOTE_COPY_TIMEOUT: Duration = Duration::from_secs(30);

/// Sleep between child polls in the deadline wait.
const COPY_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Builds the exact argv for a same-host remote copy. Pure, so tests
/// can assert the full command line. The `--` separators keep
/// operand-looking paths out of the option parsing, and no secret
/// appears here: key and agent auth never need one.
fn remote_copy_argv(config: &ConnectionConfig, from: &str, to: &str) -> Vec<String> {
    vec![
        "ssh".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-p".into(),
        config.port.to_string(),
        format!("{}@{}", config.username, config.host),
        "--".into(),
        "cp".into(),
        "-a".into(),
        "--".into(),
        from.into(),
        to.into(),
    ]
}

/// Kills the child process. SIGKILL cannot be caught or ignored, so a
/// wedged `ssh` always dies. A kill of an already-exited pid fails
/// harmlessly, so the result is ignored.
/// Safety: `kill` sends one signal to the child's pid and touches no
/// other memory.
fn kill_child(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(child.id() as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = child.kill();
}

/// Reads one pipe to the end. Lossy UTF-8 keeps odd remote output
/// from turning into an error.
fn drain_to_string(mut pipe: impl Read) -> String {
    let mut bytes = Vec::new();
    let _ = pipe.read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Runs `cmd` with captured output under a hard deadline. On a
/// deadline miss the child gets SIGKILL and the helper reports a
/// timeout error. Output drains on separate threads, so a child that
/// fills its pipes cannot deadlock the wait.
fn run_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<(ExitStatus, String, String), String> {
    let deadline = Instant::now() + timeout;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot spawn {}: {e}", cmd.get_program().to_string_lossy()))?;
    let stdout_pipe = child.stdout.take().expect("stdout is piped");
    let stderr_pipe = child.stderr.take().expect("stderr is piped");
    let stdout_reader = std::thread::spawn(move || drain_to_string(stdout_pipe));
    let stderr_reader = std::thread::spawn(move || drain_to_string(stderr_pipe));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_child(&mut child);
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(format!("timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(COPY_POLL_INTERVAL);
            }
            Err(e) => return Err(format!("cannot wait for child: {e}")),
        }
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok((status, stdout, stderr))
}

/// Copies `from` to `to` on the connection's host with one remote
/// `cp`. The ops engine pre-checks the destination, so a plain
/// `cp -a` that refuses an existing destination maps to an error.
fn remote_copy(config: &ConnectionConfig, from: &str, to: &str) -> Result<(), String> {
    let argv = remote_copy_argv(config, from, to);
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    let (status, _stdout, stderr) = run_with_timeout(cmd, REMOTE_COPY_TIMEOUT)
        .map_err(|e| format!("remote copy failed: {e}"))?;
    if status.success() {
        return Ok(());
    }
    let detail = stderr.trim();
    if detail.is_empty() {
        Err(format!("remote copy failed: cp exited with {status}"))
    } else {
        Err(format!("remote copy failed: {detail}"))
    }
}

/// Decides whether a same-backend copy may shell out to a remote
/// `cp`. Only rsync mode with key or agent auth qualifies. The gate
/// is pure so tests cover it without a live session.
fn native_copy_supported(mode: SftpMode, auth: &AuthMethod) -> bool {
    matches!(
        (mode, auth),
        (SftpMode::Rsync, AuthMethod::SshKey { .. }) | (SftpMode::Rsync, AuthMethod::SshAgent)
    )
}

/// The copy path behind [`FsBackend::copy_native`] for one mode and
/// config. Free-standing so tests exercise it without a live session.
fn copy_native_impl(
    mode: SftpMode,
    config: &ConnectionConfig,
    from: &str,
    to: &str,
) -> Option<Result<(), String>> {
    if !native_copy_supported(mode, &config.auth) {
        return None;
    }
    Some(remote_copy(config, from, to))
}

/// Creates SFTP backends. The default value serves
/// [`super::Scheme::Sftp`]; [`SftpFactory::rsync`] serves
/// [`super::Scheme::Rsync`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SftpFactory {
    mode: SftpMode,
}

impl Default for SftpFactory {
    fn default() -> Self {
        Self {
            mode: SftpMode::Sftp,
        }
    }
}

impl SftpFactory {
    /// The factory's transport mode.
    pub fn mode(&self) -> SftpMode {
        self.mode
    }

    /// Returns a factory whose backends copy same-backend files with
    /// a remote `cp` over `ssh`.
    pub fn rsync() -> Self {
        Self {
            mode: SftpMode::Rsync,
        }
    }
}

impl BackendFactory for SftpFactory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        let (session, sftp) = connect_session(config, secrets.as_ref())?;
        Ok(Arc::new(SftpBackend {
            inner: Mutex::new((session, sftp)),
            config: config.clone(),
            secrets,
            mode: self.mode,
        }))
    }
}

/// A chunk from a read pump. `Err` carries the pump's failure once,
/// after which the channel closes.
type ChunkResult = Result<Vec<u8>, String>;

/// `Read` over a chunk channel. The pump thread owns the ssh2 handles;
/// this side only drains bytes, so it is plain `Send` plumbing.
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

/// Reads `path` on its own session and feeds chunks to `tx`. A send
/// failure means the reader dropped; the pump stops quietly.
fn read_pump(
    config: &ConnectionConfig,
    secrets: &dyn SecretProvider,
    path: &str,
    tx: &SyncSender<ChunkResult>,
) -> Result<(), String> {
    let (_session, sftp) = connect_session(config, secrets)?;
    let mut file = sftp
        .open(Path::new(path))
        .map_err(|e| format!("cannot open {path}: {e}"))?;
    loop {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let n = file
            .read(&mut chunk)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        chunk.truncate(n);
        if tx.send(Ok(chunk)).is_err() {
            return Ok(());
        }
    }
}

/// `Write` over a chunk channel to a pump thread that owns the ssh2
/// handles. A pump failure poisons the writer, so the next `write` or
/// `flush` reports the stored error.
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
    /// a pump failure. Durability comes from the close in the pump.
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

/// Writes chunks from `rx` to `path` on its own session. Returns after
/// the writer closes the channel and the remote file closes.
fn write_pump(
    config: &ConnectionConfig,
    secrets: &dyn SecretProvider,
    path: &str,
    rx: &Receiver<Vec<u8>>,
) -> Result<(), String> {
    let (_session, sftp) = connect_session(config, secrets)?;
    let flags = OpenFlags::WRITE | OpenFlags::TRUNCATE;
    let mut file = sftp
        .open_mode(Path::new(path), flags, 0o644, OpenType::File)
        .map_err(|e| format!("cannot create {path}: {e}"))?;
    while let Ok(chunk) = rx.recv() {
        // An empty chunk is a flush barrier; nothing to write.
        if chunk.is_empty() {
            continue;
        }
        file.write_all(&chunk)
            .map_err(|e| format!("cannot write {path}: {e}"))?;
    }
    // Many servers lack the fsync extension; the close below is the
    // durability point for sftp, so a fsync error is not fatal.
    let _ = file.fsync();
    file.close()
        .map_err(|e| format!("cannot close {path}: {e}"))
}

/// One live SFTP connection. The mutex holds the primary session for
/// metadata calls; ssh2 sessions do not support concurrent calls.
/// Transfers never take this mutex: each one dials its own session
/// from the stored config and secrets, so a long transfer cannot
/// block listings.
pub struct SftpBackend {
    inner: Mutex<(Session, Sftp)>,
    config: ConnectionConfig,
    secrets: Arc<dyn SecretProvider>,
    /// Chooses the copy path; every other call behaves the same.
    mode: SftpMode,
}

impl SftpBackend {
    /// Builds an [`Entry`] from a stat. Callers pass the lstat data;
    /// symlink resolution happens in `list_dir` before this point.
    fn entry_from_stat(path: &str, name: String, stat: &ssh2::FileStat, is_symlink: bool) -> Entry {
        let is_dir = stat.is_dir();
        Entry {
            is_hidden: name.starts_with('.'),
            name,
            path: path.to_string(),
            is_dir,
            size: if is_dir { 0 } else { stat.size.unwrap_or(0) },
            modified_ms: stat.mtime.unwrap_or(0) as i64 * 1000,
            is_symlink,
        }
    }

    /// Deletes a directory tree. Takes `&Sftp` so the caller's lock
    /// guard covers the whole recursion; the mutex is not reentrant.
    fn delete_tree(sftp: &Sftp, path: &Path) -> Result<(), String> {
        let items = sftp
            .readdir(path)
            .map_err(|e| format!("cannot list {}: {e}", path.display()))?;
        for (item_path, stat) in items {
            // Delete a symlink itself, never its target's tree.
            if stat.is_dir() && !stat.file_type().is_symlink() {
                Self::delete_tree(sftp, &item_path)?;
            } else {
                sftp.unlink(&item_path)
                    .map_err(|e| format!("cannot delete {}: {e}", item_path.display()))?;
            }
        }
        sftp.rmdir(path)
            .map_err(|e| format!("cannot delete {}: {e}", path.display()))
    }
}

impl FsBackend for SftpBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            is_local: false,
            can_trash: false,
            can_watch: false,
            can_rename: true,
            server_side_copy: self.mode == SftpMode::Rsync,
            preserves_permissions: true,
        }
    }

    fn list_dir(&self, path: &str, opts: &ListOptions) -> Result<Vec<Entry>, String> {
        let guard = self.inner.lock().unwrap();
        let sftp = &guard.1;
        let items = sftp
            .readdir(Path::new(path))
            .map_err(|e| format!("cannot list {path}: {e}"))?;
        let mut entries = Vec::new();
        for (item_path, stat) in items {
            let name = match item_path.file_name() {
                Some(n) => n.to_string_lossy().into_owned(),
                None => continue,
            };
            if name == "." || name == ".." {
                continue;
            }
            if name.starts_with('.') && !opts.include_hidden {
                continue;
            }
            // readdir stats are lstat-like. Follow a symlink with one
            // extra stat so it reports the target's kind and size. A
            // broken link keeps the lstat data and lists as a file.
            let is_symlink = stat.file_type().is_symlink();
            let effective = if is_symlink {
                sftp.stat(&item_path).unwrap_or(stat)
            } else {
                stat
            };
            let item_path = item_path.to_string_lossy().into_owned();
            let entry = Self::entry_from_stat(&item_path, name, &effective, is_symlink);
            if opts.dirs_only && !entry.is_dir {
                continue;
            }
            entries.push(entry);
        }
        crate::sort_entries(&mut entries);
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let guard = self.inner.lock().unwrap();
        let stat = guard
            .1
            .stat(Path::new(path))
            .map_err(|e| format!("cannot stat {path}: {e}"))?;
        let name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        Ok(Self::entry_from_stat(path, name, &stat, false))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        let (tx, rx) = mpsc::sync_channel::<ChunkResult>(CHANNEL_DEPTH);
        let config = self.config.clone();
        let secrets = self.secrets.clone();
        let path = path.to_string();
        std::thread::spawn(move || {
            if let Err(message) = read_pump(&config, secrets.as_ref(), &path, &tx) {
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
        let path = path.to_string();
        let handle = std::thread::spawn(move || {
            let result = write_pump(&config, secrets.as_ref(), &path, &rx);
            // An error must also drain no further: returning drops rx,
            // so the writer's next send fails and reads this result.
            let _ = done_tx.send(result);
        });
        Ok(Box::new(ChannelWriter::new(tx, done_rx, Some(handle))))
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let guard = self.inner.lock().unwrap();
        let sftp = &guard.1;
        let p = Path::new(path);
        // lstat so a symlink to a directory deletes as a link.
        let stat = sftp
            .lstat(p)
            .map_err(|e| format!("cannot stat {path}: {e}"))?;
        if stat.is_dir() && !stat.file_type().is_symlink() {
            if recursive {
                Self::delete_tree(sftp, p)
            } else {
                sftp.rmdir(p)
                    .map_err(|e| format!("cannot delete {path}: {e}"))
            }
        } else {
            sftp.unlink(p)
                .map_err(|e| format!("cannot delete {path}: {e}"))
        }
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let guard = self.inner.lock().unwrap();
        let sftp = &guard.1;
        let flags = RenameFlags::OVERWRITE | RenameFlags::ATOMIC;
        // Some servers reject the flags; retry plain before failing.
        sftp.rename(Path::new(from), Path::new(to), Some(flags))
            .or_else(|_| sftp.rename(Path::new(from), Path::new(to), None))
            .map_err(|e| format!("cannot rename {from}: {e}"))
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let guard = self.inner.lock().unwrap();
        guard
            .1
            .mkdir(Path::new(path), 0o755)
            .map_err(|e| format!("cannot create {path}: {e}"))
    }

    /// Copies with a remote `cp` when the transport allows it. Only
    /// rsync mode with key or agent auth qualifies. Password auth
    /// streams instead: `ssh` with a password cannot run
    /// non-interactively, and the secret must never reach a command
    /// line.
    fn copy_native(&self, from: &str, to: &str) -> Option<Result<(), String>> {
        copy_native_impl(self.mode, &self.config, from, to)
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
            scheme: Scheme::Sftp,
            host: "127.0.0.1".to_string(),
            port: 22,
            username: "user".to_string(),
            initial_path: "/".to_string(),
            auth,
        }
    }

    #[test]
    fn key_path_tilde_expands_to_home() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(
            expand_key_path("~/.ssh/id_ed25519").unwrap(),
            PathBuf::from(format!("{home}/.ssh/id_ed25519"))
        );
        assert_eq!(expand_key_path("~").unwrap(), PathBuf::from(home));
        // A mid-path tilde is a literal character.
        assert_eq!(expand_key_path("/a/~b").unwrap(), PathBuf::from("/a/~b"));
        assert_eq!(
            expand_key_path("/etc/key").unwrap(),
            PathBuf::from("/etc/key")
        );
    }

    #[test]
    fn missing_password_fails_before_any_dial() {
        // The host is unroutable; a fast error proves no dial happened.
        let mut cfg = config(AuthMethod::Password);
        cfg.host = "host.invalid".to_string();
        let start = Instant::now();
        let err = SftpFactory::default()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("no password stored"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn s3_auth_is_rejected() {
        let err = SftpFactory::default()
            .connect(&config(AuthMethod::S3Keys), Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("wrong auth method"), "got: {err}");
    }

    #[test]
    fn closed_port_fails_cleanly_and_quickly() {
        // Bind then drop a listener to get a port that refuses connects.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut cfg = config(AuthMethod::SshAgent);
        cfg.port = port as u32;
        let start = Instant::now();
        let err = SftpFactory::default()
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        // On a busy machine, another process can claim the freed port
        // before the connect. The connect then reaches a non-SSH peer
        // and fails at the handshake instead of the TCP connect. Both
        // shapes satisfy the property under test: a clean, fast error.
        assert!(
            err.contains("cannot connect") || err.contains("handshake"),
            "got: {err}"
        );
        assert!(start.elapsed() < Duration::from_secs(20));
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
    fn channel_reader_splits_chunks_across_small_reads() {
        let (tx, rx) = mpsc::sync_channel::<ChunkResult>(CHANNEL_DEPTH);
        tx.send(Ok(b"abcdef".to_vec())).unwrap();
        drop(tx);
        let mut reader = ChannelReader::new(rx);
        let mut buf = [0u8; 4];
        assert_eq!(reader.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"abcd");
        assert_eq!(reader.read(&mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"ef");
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
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
        // The pump takes nothing, so a write fails once its receiver
        // is gone and reports the pump's stored reason.
        let err = loop {
            match writer.write_all(b"data") {
                Ok(()) => continue,
                Err(err) => break err,
            }
        };
        assert!(err.to_string().contains("disk full"), "got: {err}");
        // The poisoned state must repeat on every later call.
        let err = writer.flush().unwrap_err();
        assert!(err.to_string().contains("disk full"), "got: {err}");
        assert_eq!(writer.finish(), Err("disk full".to_string()));
    }

    #[test]
    fn channel_writer_drop_joins_pump() {
        let (mut writer, written) = fake_write_pump(Ok(()), false);
        writer.write_all(b"bytes").unwrap();
        drop(writer);
        // Drop runs finish, so the pump saw the close and exited.
        assert_eq!(written.lock().unwrap().as_slice(), b"bytes");
    }

    #[test]
    fn factory_defaults_to_sftp_and_rsync_switches_mode() {
        assert_eq!(SftpFactory::default().mode(), SftpMode::Sftp);
        assert_eq!(SftpFactory::rsync().mode(), SftpMode::Rsync);
        assert_eq!(SftpFactory::default().mode(), SftpMode::Sftp);
    }

    #[test]
    fn native_copy_gate_accepts_only_rsync_with_key_or_agent_auth() {
        let key = AuthMethod::SshKey {
            key_path: "/keys/id_ed25519".to_string(),
        };
        assert!(!native_copy_supported(
            SftpMode::Sftp,
            &AuthMethod::Password
        ));
        assert!(!native_copy_supported(SftpMode::Sftp, &key));
        assert!(!native_copy_supported(
            SftpMode::Sftp,
            &AuthMethod::SshAgent
        ));
        assert!(!native_copy_supported(
            SftpMode::Rsync,
            &AuthMethod::Password
        ));
        assert!(!native_copy_supported(
            SftpMode::Rsync,
            &AuthMethod::OAuthToken
        ));
        assert!(!native_copy_supported(
            SftpMode::Rsync,
            &AuthMethod::SharedKey
        ));
        assert!(native_copy_supported(SftpMode::Rsync, &key));
        assert!(native_copy_supported(
            SftpMode::Rsync,
            &AuthMethod::SshAgent
        ));
    }

    #[test]
    fn copy_native_returns_none_for_sftp_mode_and_rsync_password() {
        // These gates close before any process spawns, so no dial or
        // spawn happens.
        let no_path = ("/src/a", "/dst/b");
        assert!(copy_native_impl(
            SftpMode::Sftp,
            &config(AuthMethod::Password),
            no_path.0,
            no_path.1
        )
        .is_none());
        assert!(copy_native_impl(
            SftpMode::Rsync,
            &config(AuthMethod::Password),
            no_path.0,
            no_path.1
        )
        .is_none());
    }

    #[test]
    fn copy_native_runs_ssh_for_rsync_key_auth_and_maps_failure() {
        // ssh dials a port that refuses connects and fails fast. The
        // gate opens, so the caller gets Some and the failure carries
        // the mapped message.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut cfg = config(AuthMethod::SshKey {
            key_path: "/nonexistent/key".to_string(),
        });
        cfg.port = port as u32;
        let result = copy_native_impl(SftpMode::Rsync, &cfg, "/src/a", "/dst/b")
            .expect("rsync mode with key auth must open the gate");
        let err = result.err().expect("a refused dial must fail");
        assert!(err.contains("remote copy failed"), "got: {err}");
    }

    #[test]
    fn remote_copy_argv_is_exact_and_operand_safe() {
        let mut cfg = config(AuthMethod::SshKey {
            key_path: "~/.ssh/id_ed25519".to_string(),
        });
        cfg.host = "example.com".to_string();
        cfg.port = 2222;
        cfg.username = "liam".to_string();
        let expected: Vec<String> = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-p",
            "2222",
            "liam@example.com",
            "--",
            "cp",
            "-a",
            "--",
            "/srv/-weird name",
            "/srv/dst",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            remote_copy_argv(&cfg, "/srv/-weird name", "/srv/dst"),
            expected
        );
    }

    #[test]
    fn run_with_timeout_captures_output_of_a_fast_command() {
        let mut cmd = Command::new("/bin/echo");
        cmd.arg("hello");
        let (status, stdout, stderr) = run_with_timeout(cmd, Duration::from_secs(10)).unwrap();
        assert!(status.success());
        assert_eq!(stdout.trim(), "hello");
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_with_timeout_kills_a_long_sleep() {
        let start = Instant::now();
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("30");
        let err = run_with_timeout(cmd, Duration::from_millis(200))
            .err()
            .expect("a 30s sleep must hit a 200ms deadline");
        assert!(err.contains("timed out"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
