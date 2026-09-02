//! Dropbox backend over the Dropbox REST API.
//!
//! Every call is one independent authenticated HTTP request, so the
//! backend holds only an [`oauth::TokenSource`] and a pooled agent; no
//! session mutex exists. Transfers run on pump threads that own the
//! HTTP response or the upload session, and chunks cross bounded
//! channels with the same reader and writer structure the SFTP
//! backend uses.

use super::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use super::endpoints;
use super::http;
use super::oauth;
use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

// Paths appended to `api_base` (the RPC endpoints, JSON in and out)
// or `content_base` (raw bytes in or out). Both bases are resolved
// once when the backend is built, from `ORKA_ENDPOINT_DROPBOX_API`
// and `ORKA_ENDPOINT_DROPBOX_CONTENT`; see [`DropboxFactory::connect`].
const LIST_PATH: &str = "/2/files/list_folder";
const LIST_CONTINUE_PATH: &str = "/2/files/list_folder/continue";
const METADATA_PATH: &str = "/2/files/get_metadata";
const DELETE_PATH: &str = "/2/files/delete_v2";
const MOVE_PATH: &str = "/2/files/move_v2";
const CREATE_FOLDER_PATH: &str = "/2/files/create_folder_v2";
const DOWNLOAD_PATH: &str = "/2/files/download";
const UPLOAD_START_PATH: &str = "/2/files/upload_session/start";
const UPLOAD_APPEND_PATH: &str = "/2/files/upload_session/append_v2";
const UPLOAD_FINISH_PATH: &str = "/2/files/upload_session/finish";

/// Bytes read from a download response before one channel send. Small
/// chunks keep the reader responsive and bound in-flight memory.
const READ_CHUNK_SIZE: usize = 64 * 1024;

/// Chunks a transfer channel buffers. Bounds in-flight memory per
/// transfer together with [`READ_CHUNK_SIZE`].
const CHANNEL_DEPTH: usize = 4;

/// Canonicalizes a backend path to one leading slash and no trailing
/// slash, with root as "/". Rejecting ".." here keeps every later call
/// from escaping the intended tree.
fn normalize_path(path: &str) -> Result<String, String> {
    if path.split('/').any(|segment| segment == "..") {
        return Err(format!("path must not contain '..' segments: {path}"));
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok("/".to_string());
    }
    let mut out = String::with_capacity(trimmed.len() + 1);
    for segment in trimmed.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(segment);
    }
    Ok(out)
}

/// Converts a normalized path to the form Dropbox expects. The root
/// listing uses the empty string, not "/".
fn dropbox_path(normalized: &str) -> &str {
    if normalized == "/" {
        ""
    } else {
        normalized
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

/// The directory that contains `path`, for building entry paths.
fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

/// Builds the Dropbox-API-Arg header value. The API requires compact
/// JSON; spaces corrupt the header parse on the server.
fn api_arg(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

/// Flattens a request failure into one message. A 401 gets an extra
/// hint because Dropbox tokens expire and the raw body says little.
fn request_error(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(401, response) => {
            let body = http::read_body_string(response);
            format!("HTTP 401: {body} (the access token may be expired)")
        }
        other => http::error_string(other),
    }
}

/// Runs one Dropbox call against a token source, retrying once with a
/// forced refresh when the first attempt fails with HTTP 401. Shares
/// its retry policy with [`oauth::call_with_auth_retry`], with
/// [`request_error`] as the error hook so a failure that survives the
/// retry keeps Dropbox's expired-token hint instead of the generic
/// message the shared helper uses by default.
fn call_with_auth_retry<T>(
    tokens: &oauth::TokenSource,
    call: impl FnMut(&str) -> Result<T, ureq::Error>,
) -> Result<T, String> {
    oauth::call_with_auth_retry_and(tokens, request_error, call)
}

/// A chunk from a read pump. `Err` carries the pump's failure once,
/// after which the channel closes.
type ChunkResult = Result<Vec<u8>, String>;

/// `Read` over a chunk channel. The pump thread owns the HTTP
/// response; this side only drains bytes, so it is plain plumbing.
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

/// `Write` over a chunk channel to a pump thread that owns the upload
/// session. A pump failure poisons the writer, so the next `write` or
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

/// Downloads `path` and feeds chunks to `tx`. A send failure means the
/// reader dropped; the pump stops quietly. `content_base` is the
/// content-API origin resolved once when the backend was built.
fn read_pump(
    tokens: oauth::TokenSource,
    agent: ureq::Agent,
    content_base: String,
    path: String,
    tx: &SyncSender<ChunkResult>,
) -> Result<(), String> {
    let arg = api_arg(&json!({"path": dropbox_path(&path)}));
    let url = format!("{content_base}{DOWNLOAD_PATH}");
    let response = call_with_auth_retry(&tokens, |token| {
        agent
            .post(&url)
            .set("Authorization", &auth_header(token))
            .set("Dropbox-API-Arg", &arg)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&[])
    })?;
    let mut reader = http::response_reader(response);
    let mut chunk = vec![0u8; READ_CHUNK_SIZE];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| format!("download of {path} failed: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        if tx.send(Ok(chunk[..n].to_vec())).is_err() {
            return Ok(());
        }
    }
}

fn start_upload_session(
    tokens: &oauth::TokenSource,
    agent: &ureq::Agent,
    content_base: &str,
) -> Result<String, String> {
    let url = format!("{content_base}{UPLOAD_START_PATH}");
    let response = call_with_auth_retry(tokens, |token| {
        agent
            .post(&url)
            .set("Authorization", &auth_header(token))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&[])
    })?;
    let value: Value = response
        .into_json()
        .map_err(|e| format!("upload session start returned bad JSON: {e}"))?;
    value
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "upload session start response has no session_id".to_string())
}

fn finish_upload_session(
    tokens: &oauth::TokenSource,
    agent: &ureq::Agent,
    content_base: &str,
    path: &str,
    session_id: &str,
    offset: u64,
) -> Result<(), String> {
    let arg = api_arg(&json!({
        "commit": {
            "path": dropbox_path(path),
            "mode": "overwrite",
            "autorename": false,
            "mute": true,
        },
        "cursor": {"session_id": session_id, "offset": offset},
    }));
    let url = format!("{content_base}{UPLOAD_FINISH_PATH}");
    let response = call_with_auth_retry(tokens, |token| {
        agent
            .post(&url)
            .set("Authorization", &auth_header(token))
            .set("Dropbox-API-Arg", &arg)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&[])
    })?;
    // Drain the small ack so the connection returns to the pool.
    drop(http::read_body_string(response));
    Ok(())
}

/// One append call: the byte offset, the chunk, and whether it ends
/// the session. Shared by the write pump and its tests.
type AppendChunk<'a> = dyn FnMut(u64, &[u8], bool) -> Result<(), String> + 'a;

/// Receives write chunks and hands each to `append` with its byte
/// offset. The final call is an empty body with `close: true`, which
/// ends the upload session. Returns the accumulated offset for the
/// finish call. Split from [`write_pump`] so offset accounting is
/// testable without a network.
fn pump_uploads(rx: Receiver<Vec<u8>>, append: &mut AppendChunk<'_>) -> Result<u64, String> {
    let mut offset: u64 = 0;
    while let Ok(chunk) = rx.recv() {
        // An empty chunk is a flush barrier; nothing to upload.
        if chunk.is_empty() {
            continue;
        }
        append(offset, &chunk, false)?;
        offset += chunk.len() as u64;
    }
    append(offset, &[], true)?;
    Ok(offset)
}

/// Drains write chunks into one Dropbox upload session and commits
/// the file at `path`. Returns after the writer closes the channel
/// and the session commits.
fn write_pump(
    tokens: oauth::TokenSource,
    agent: ureq::Agent,
    content_base: String,
    path: String,
    rx: Receiver<Vec<u8>>,
) -> Result<(), String> {
    let session_id = start_upload_session(&tokens, &agent, &content_base)?;
    let sid = session_id.clone();
    let append_url = format!("{content_base}{UPLOAD_APPEND_PATH}");
    let mut append = |offset: u64, chunk: &[u8], close: bool| -> Result<(), String> {
        let arg = api_arg(&json!({
            "cursor": {"session_id": sid, "offset": offset},
            "close": close,
        }));
        let response = call_with_auth_retry(&tokens, |token| {
            agent
                .post(&append_url)
                .set("Authorization", &auth_header(token))
                .set("Dropbox-API-Arg", &arg)
                .set("Content-Type", "application/octet-stream")
                .send_bytes(chunk)
        })?;
        drop(http::read_body_string(response));
        Ok(())
    };
    let offset = pump_uploads(rx, &mut append)?;
    finish_upload_session(&tokens, &agent, &content_base, &path, &session_id, offset)?;
    Ok(())
}

/// Builds one [`Entry`] from a list or metadata JSON item. Deleted
/// items yield `None`; the list skips them and stat reports not-found.
fn entry_from_json(item: &Value, parent: &str) -> Option<Entry> {
    let tag = item.get(".tag")?.as_str()?;
    if tag == "deleted" {
        return None;
    }
    let name = item.get("name")?.as_str()?.to_string();
    let is_dir = tag == "folder";
    let size = if is_dir {
        0
    } else {
        item.get("size").and_then(Value::as_u64).unwrap_or(0)
    };
    let modified_ms = item
        .get("server_modified")
        .and_then(Value::as_str)
        .and_then(http::parse_rfc3339_to_ms)
        .unwrap_or(0);
    Some(Entry {
        is_hidden: name.starts_with('.'),
        path: join_path(parent, &name),
        name,
        is_dir,
        size,
        modified_ms,
        is_symlink: false,
    })
}

fn parse_entries(response: &Value, parent: &str) -> Vec<Entry> {
    let empty = Vec::new();
    let items = response
        .get("entries")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    items
        .iter()
        .filter_map(|item| entry_from_json(item, parent))
        .collect()
}

/// A synthetic root, because get_metadata rejects "/" and the UI still
/// needs a stat target for the tree root.
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

/// One live Dropbox connection. Holds the token source resolved at
/// connect; REST calls share no other state, so no lock is needed.
struct DropboxBackend {
    tokens: oauth::TokenSource,
    agent: ureq::Agent,
    /// `ORKA_ENDPOINT_DROPBOX_API` or its production default, resolved
    /// once when this backend was built.
    api_base: String,
    /// `ORKA_ENDPOINT_DROPBOX_CONTENT` or its production default,
    /// resolved the same way as `api_base`.
    content_base: String,
}

impl DropboxBackend {
    /// POSTs a JSON body to `{api_base}{path}` and parses the JSON
    /// response. All metadata and RPC endpoints share this shape.
    fn post_json(&self, path: &str, body: Value) -> Result<Value, String> {
        let url = format!("{}{path}", self.api_base);
        let response = call_with_auth_retry(&self.tokens, |token| {
            self.agent
                .post(&url)
                .set("Authorization", &auth_header(token))
                .send_json(body.clone())
        })?;
        response
            .into_json()
            .map_err(|e| format!("response was not valid JSON: {e}"))
    }
}

/// Creates Dropbox backends. Registered once for [`super::Scheme::Dropbox`].
pub struct DropboxFactory;

impl BackendFactory for DropboxFactory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        // Auth is resolved and validated before any network work so a
        // bad config or a missing secret fails immediately.
        let tokens = match &config.auth {
            AuthMethod::OAuthToken => {
                let token = secrets
                    .get_secret(&config.id)
                    .ok_or_else(|| "no access token stored for this connection".to_string())?;
                oauth::TokenSource::Fixed(token)
            }
            AuthMethod::OAuthApp { client_id, .. } => {
                let raw = secrets
                    .get_secret(&config.id)
                    .ok_or_else(|| "no token stored for this connection".to_string())?;
                // Fail on a malformed secret now rather than on the
                // first request.
                oauth::TokenSet::from_json(&raw)?;
                oauth::TokenSource::OAuthApp {
                    provider: oauth::Provider::Dropbox,
                    client_id: client_id.clone(),
                    connection_id: config.id.clone(),
                    secrets,
                    cache: Arc::new(Mutex::new(None)),
                }
            }
            _ => return Err("wrong auth method for dropbox".to_string()),
        };
        Ok(Arc::new(DropboxBackend {
            tokens,
            agent: http::agent()?,
            api_base: endpoints::dropbox_api_base(),
            content_base: endpoints::dropbox_content_base(),
        }))
    }
}

impl FsBackend for DropboxBackend {
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
        let dir = normalize_path(path)?;
        let mut body = json!({"path": dropbox_path(&dir), "recursive": false});
        let mut list_path = LIST_PATH;
        let mut entries = Vec::new();
        loop {
            let response = self.post_json(list_path, body)?;
            entries.extend(parse_entries(&response, &dir));
            if !response
                .get("has_more")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                break;
            }
            let cursor = response
                .get("cursor")
                .and_then(Value::as_str)
                .ok_or_else(|| "list response has more entries but no cursor".to_string())?;
            body = json!({"cursor": cursor});
            list_path = LIST_CONTINUE_PATH;
        }
        entries.retain(|entry| {
            (opts.include_hidden || !entry.is_hidden) && (!opts.dirs_only || entry.is_dir)
        });
        crate::sort_entries(&mut entries);
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let p = normalize_path(path)?;
        if p == "/" {
            return Ok(root_entry());
        }
        let value = match self.post_json(METADATA_PATH, json!({"path": dropbox_path(&p)})) {
            Ok(value) => value,
            Err(message) => {
                // The API reports a missing item as path/not_found in
                // the error body; callers match on "not found".
                if message.contains("not_found") {
                    return Err(format!("not found: {p}"));
                }
                return Err(message);
            }
        };
        let tag = value.get(".tag").and_then(Value::as_str).unwrap_or("");
        if tag == "deleted" {
            return Err(format!("not found: {p}"));
        }
        entry_from_json(&value, parent_of(&p))
            .ok_or_else(|| format!("cannot read metadata for {p}"))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn Read + Send>, String> {
        let path = normalize_path(path)?;
        let (tx, rx) = mpsc::sync_channel::<ChunkResult>(CHANNEL_DEPTH);
        let tokens = self.tokens.clone();
        let agent = self.agent.clone();
        let content_base = self.content_base.clone();
        std::thread::spawn(move || {
            if let Err(message) = read_pump(tokens, agent, content_base, path, &tx) {
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
        let path = normalize_path(path)?;
        if path == "/" {
            return Err("cannot write to the root".to_string());
        }
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_DEPTH);
        let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let tokens = self.tokens.clone();
        let agent = self.agent.clone();
        let content_base = self.content_base.clone();
        let handle = std::thread::spawn(move || {
            let result = write_pump(tokens, agent, content_base, path, rx);
            // Returning drops rx, so a failed pump rejects later sends.
            let _ = done_tx.send(result);
        });
        Ok(Box::new(ChannelWriter::new(tx, done_rx, Some(handle))))
    }

    fn delete(&self, path: &str, _recursive: bool) -> Result<(), String> {
        let p = normalize_path(path)?;
        if p == "/" {
            return Err("cannot delete the root".to_string());
        }
        // delete_v2 removes files and non-empty folders alike, so the
        // recursive flag needs no server-side handling.
        self.post_json(DELETE_PATH, json!({"path": dropbox_path(&p)}))
            .map(|_| ())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let from = normalize_path(from)?;
        let to = normalize_path(to)?;
        if from == "/" || to == "/" {
            return Err("cannot rename the root".to_string());
        }
        self.post_json(
            MOVE_PATH,
            json!({"from_path": dropbox_path(&from), "to_path": dropbox_path(&to), "autorename": false}),
        )
        .map(|_| ())
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let p = normalize_path(path)?;
        if p == "/" {
            return Ok(());
        }
        match self.post_json(CREATE_FOLDER_PATH, json!({"path": dropbox_path(&p)})) {
            Ok(_) => Ok(()),
            Err(message) => {
                // The API reports an existing folder as path/conflict;
                // mkdir stays idempotent, so that case is success.
                if message.contains("path/conflict") {
                    Ok(())
                } else {
                    Err(message)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::Scheme;
    use std::time::{Duration, Instant};

    struct NoSecrets;
    impl SecretProvider for NoSecrets {
        fn get_secret(&self, _connection_id: &str) -> Option<String> {
            None
        }
    }

    struct FixedSecrets;
    impl SecretProvider for FixedSecrets {
        fn get_secret(&self, _connection_id: &str) -> Option<String> {
            Some("token-value".to_string())
        }
    }

    fn config(auth: AuthMethod) -> ConnectionConfig {
        ConnectionConfig {
            id: "test".to_string(),
            display_name: "Test".to_string(),
            scheme: Scheme::Dropbox,
            host: "dropbox.com".to_string(),
            port: 443,
            username: String::new(),
            initial_path: "/".to_string(),
            auth,
        }
    }

    /// Serves one HTTP response on a local port, for status-error
    /// mapping tests without external network. The request is drained
    /// and the socket lingers so the client reads a clean close.
    fn serve_once(status_line: &str, body: &str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let status_line = status_line.to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1];
            // Drain the request headers and body one byte at a time
            // until the blank line, so the close never sends a reset.
            let mut seen = String::new();
            while !seen.contains("\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => seen.push(buf[0] as char),
                    Err(_) => break,
                }
            }
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            std::thread::sleep(Duration::from_millis(200));
        });
        port
    }

    fn post_error(port: u16) -> ureq::Error {
        http::agent()
            .unwrap()
            .post(&format!("http://127.0.0.1:{port}/x"))
            .send_string("{}")
            .expect_err("must fail")
    }

    #[test]
    fn normalize_path_repairs_slashes_and_rejects_dot_dot() {
        assert_eq!(normalize_path("/").unwrap(), "/");
        assert_eq!(normalize_path("").unwrap(), "/");
        assert_eq!(normalize_path("a/b").unwrap(), "/a/b");
        assert_eq!(normalize_path("/a//b/").unwrap(), "/a/b");
        assert_eq!(normalize_path("/Dir/file.txt").unwrap(), "/Dir/file.txt");
        assert_eq!(normalize_path("a..b").unwrap(), "/a..b");
        assert!(normalize_path("/a/../b").is_err());
        assert!(normalize_path("..").is_err());
        assert!(normalize_path("a/..").is_err());
    }

    #[test]
    fn join_and_parent_build_backend_paths() {
        assert_eq!(join_path("/", "x"), "/x");
        assert_eq!(join_path("/a", "x"), "/a/x");
        assert_eq!(parent_of("/a"), "/");
        assert_eq!(parent_of("/a/b"), "/a");
        assert_eq!(dropbox_path("/"), "");
        assert_eq!(dropbox_path("/a/b"), "/a/b");
    }

    #[test]
    fn api_arg_is_compact_json() {
        assert_eq!(
            api_arg(&json!({"path": "/a b/c.txt"})),
            r#"{"path":"/a b/c.txt"}"#
        );
        assert_eq!(
            api_arg(&json!({"cursor": {"session_id": "sid", "offset": 5}, "close": true})),
            r#"{"close":true,"cursor":{"offset":5,"session_id":"sid"}}"#
        );
        assert_eq!(
            api_arg(&json!({"commit": {"path": "/x", "mode": "overwrite"}})),
            r#"{"commit":{"mode":"overwrite","path":"/x"}}"#
        );
    }

    #[test]
    fn list_payload_parses_to_entries() {
        let payload = json!({
            "entries": [
                {".tag": "folder", "name": "Archive", "path_lower": "/notes/archive", "id": "id:1"},
                {".tag": "file", "name": "todo.md", "path_lower": "/notes/todo.md",
                 "size": 12, "server_modified": "2023-05-31T15:14:23Z", "id": "id:2"},
                {".tag": "file", "name": ".env", "path_lower": "/notes/.env",
                 "size": 4, "server_modified": "2023-05-31T15:14:23Z", "id": "id:3"},
                {".tag": "deleted", "name": "gone.txt", "path_lower": "/notes/gone.txt", "id": "id:4"}
            ],
            "has_more": false,
            "cursor": "c"
        });
        let entries = parse_entries(&payload, "/Notes");
        assert_eq!(entries.len(), 3);
        let folder = &entries[0];
        assert_eq!(folder.name, "Archive");
        assert_eq!(folder.path, "/Notes/Archive");
        assert!(folder.is_dir);
        assert_eq!(folder.size, 0);
        assert_eq!(folder.modified_ms, 0);
        let file = &entries[1];
        assert_eq!(file.name, "todo.md");
        assert_eq!(file.path, "/Notes/todo.md");
        assert!(!file.is_dir);
        assert_eq!(file.size, 12);
        assert_eq!(file.modified_ms, 1_685_546_063_000);
        assert!(!file.is_hidden);
        let hidden = &entries[2];
        assert!(hidden.is_hidden);
    }

    #[test]
    fn conflict_status_maps_body_into_error() {
        let port = serve_once(
            "HTTP/1.1 409 Conflict",
            r#"{"error_summary": "path/conflict/"}"#,
        );
        let message = http::error_string(post_error(port));
        assert!(message.contains("409"), "got: {message}");
        assert!(message.contains("path/conflict"), "got: {message}");
    }

    #[test]
    fn auth_error_hints_at_expired_token() {
        let port = serve_once(
            "HTTP/1.1 401 Unauthorized",
            r#"{"error_summary": "invalid_access_token/"}"#,
        );
        let message = request_error(post_error(port));
        assert!(message.contains("401"), "got: {message}");
        assert!(message.contains("expired"), "got: {message}");
    }

    #[test]
    fn missing_token_fails_before_any_network_call() {
        let start = Instant::now();
        let err = DropboxFactory
            .connect(&config(AuthMethod::OAuthToken), Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("no access token"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn non_oauth_auth_is_rejected() {
        let err = DropboxFactory
            .connect(&config(AuthMethod::Password), Arc::new(FixedSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("wrong auth method"), "got: {err}");
    }

    #[test]
    fn connect_stores_the_token_without_dialing() {
        let backend = DropboxFactory
            .connect(&config(AuthMethod::OAuthToken), Arc::new(FixedSecrets))
            .expect("must connect");
        let capabilities = backend.capabilities();
        assert!(!capabilities.is_local);
        assert!(!capabilities.can_trash);
        assert!(!capabilities.can_watch);
        assert!(capabilities.can_rename);
        assert!(!capabilities.server_side_copy);
        assert!(!capabilities.preserves_permissions);
    }

    #[test]
    fn api_base_override_is_used_for_metadata_requests() {
        use crate::vfs::endpoints::test_support::with_var;
        let body =
            r#"{".tag":"file","name":"a.txt","size":3,"server_modified":"2023-05-31T15:14:23Z"}"#;
        let port = serve_once("HTTP/1.1 200 OK", body);
        with_var(
            "ORKA_ENDPOINT_DROPBOX_API",
            &format!("http://127.0.0.1:{port}"),
            || {
                let backend = DropboxFactory
                    .connect(&config(AuthMethod::OAuthToken), Arc::new(FixedSecrets))
                    .expect("must connect");
                let entry = backend
                    .stat("/a.txt")
                    .expect("must reach the overridden API base");
                assert_eq!(entry.name, "a.txt");
                assert_eq!(entry.size, 3);
            },
        );
    }

    fn oauth_app_auth() -> AuthMethod {
        AuthMethod::OAuthApp {
            client_id: "client".to_string(),
            tenant_id: String::new(),
        }
    }

    #[test]
    fn oauth_app_without_a_stored_secret_fails_before_any_network_call() {
        let err = DropboxFactory
            .connect(&config(oauth_app_auth()), Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("no token stored"), "got: {err}");
    }

    #[test]
    fn oauth_app_with_a_malformed_secret_fails_before_any_network_call() {
        struct BadSecret;
        impl SecretProvider for BadSecret {
            fn get_secret(&self, _connection_id: &str) -> Option<String> {
                Some("not a token set".to_string())
            }
        }
        let err = DropboxFactory
            .connect(&config(oauth_app_auth()), Arc::new(BadSecret))
            .err()
            .expect("must fail");
        assert!(err.contains("cannot decode token set"), "got: {err}");
    }

    #[test]
    fn oauth_app_with_a_valid_secret_connects() {
        let set = oauth::TokenSet {
            access_token: "a".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at_ms: u64::MAX,
            client_secret: None,
        };
        struct GoodSecret(String);
        impl SecretProvider for GoodSecret {
            fn get_secret(&self, _connection_id: &str) -> Option<String> {
                Some(self.0.clone())
            }
        }
        let backend = DropboxFactory
            .connect(
                &config(oauth_app_auth()),
                Arc::new(GoodSecret(set.to_json().unwrap())),
            )
            .expect("must connect");
        assert!(!backend.capabilities().is_local);
    }

    #[test]
    fn upload_offsets_accumulate_and_close_appends_empty() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let handle = std::thread::spawn(move || {
            let mut log: Vec<(u64, usize, bool)> = Vec::new();
            let mut append = |offset: u64, chunk: &[u8], close: bool| -> Result<(), String> {
                log.push((offset, chunk.len(), close));
                Ok(())
            };
            let result = pump_uploads(rx, &mut append);
            (result, log)
        });
        tx.send(b"abc".to_vec()).unwrap();
        tx.send(Vec::new()).unwrap();
        tx.send(b"de".to_vec()).unwrap();
        drop(tx);
        let (result, log) = handle.join().unwrap();
        assert_eq!(result, Ok(5));
        assert_eq!(log, vec![(0, 3, false), (3, 2, false), (5, 0, true)]);
    }

    #[test]
    fn upload_pump_stops_on_append_failure() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let handle = std::thread::spawn(move || {
            let mut calls = 0;
            let mut append = |_offset: u64, _chunk: &[u8], _close: bool| -> Result<(), String> {
                calls += 1;
                Err("append failed".to_string())
            };
            let result = pump_uploads(rx, &mut append);
            (result, calls)
        });
        tx.send(b"abc".to_vec()).unwrap();
        drop(tx);
        let (result, calls) = handle.join().unwrap();
        assert_eq!(result, Err("append failed".to_string()));
        assert_eq!(calls, 1);
    }

    /// Fake write pump with the production channel shapes. Collects
    /// bytes and reports `result` when the writer closes the channel.
    fn fake_write_pump(
        result: Result<(), String>,
        fail_immediately: bool,
    ) -> (ChannelWriter, Arc<std::sync::Mutex<Vec<u8>>>) {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_DEPTH);
        let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let written = Arc::new(std::sync::Mutex::new(Vec::new()));
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
}
