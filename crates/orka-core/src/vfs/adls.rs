//! Azure Data Lake Storage Gen2 backend over the `dfs` REST API.
//!
//! [`AdlsFactory`] validates the connection and resolves the
//! credential before any network call, so a bad config fails fast.
//! [`AdlsBackend`] signs SharedKey requests with HMAC-SHA256 in the
//! Blob SharedKey canonical form, and sends OAuth requests with a
//! Bearer token. Paths are backend-local strings inside
//! the connection's filesystem (container); the URI form
//! `adls://<connection>/a/b` is built by [`join_uri`].

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Read;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use super::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use super::http::{
    agent, error_string, is_ok, parse_rfc1123_to_ms, read_body_string, response_reader, url_encode,
};
use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};

/// `x-ms-version` sent on every request. A pinned version keeps the
/// REST behavior stable across Azure service updates.
const MS_VERSION: &str = "2023-11-03";

/// Chunks a transfer channel buffers. This bounds in-flight memory
/// per upload transfer.
const CHANNEL_DEPTH: usize = 4;

/// The HTTP verbs the ADLS REST surface needs. An enum keeps an
/// unsupported method string out of the request path entirely.
enum Method {
    Get,
    Put,
    Patch,
    Delete,
}

impl Method {
    /// The verb as it appears first in the string-to-sign.
    fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// Creates ADLS Gen2 backends. Registered once for the `adls` scheme.
pub struct AdlsFactory;

impl BackendFactory for AdlsFactory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        let core = build_core(config, secrets.as_ref())?;
        Ok(Arc::new(AdlsBackend {
            core: Arc::new(core),
        }))
    }
}

/// Validates the config and resolves the account key. Everything that
/// can fail without the network fails here, before any request.
fn build_core(config: &ConnectionConfig, secrets: &dyn SecretProvider) -> Result<AdlsCore, String> {
    if config.host.is_empty() {
        return Err("adls host is empty; use the account endpoint, for example myaccount.dfs.core.windows.net".to_string());
    }
    if config.host.contains("://") {
        return Err("adls host must not contain a scheme; use the account endpoint, for example myaccount.dfs.core.windows.net".to_string());
    }
    if config.username.is_empty() {
        return Err(
            "adls username is empty; it must be the filesystem (container) name".to_string(),
        );
    }
    let credential = match &config.auth {
        AuthMethod::SharedKey => {
            let key = secrets
                .get_secret(&config.id)
                .ok_or_else(|| "no account key stored for this connection".to_string())?;
            // Decode before any network call, so a bad key fails fast.
            let key_bytes = BASE64
                .decode(key.trim())
                .map_err(|_| "account key is not valid base64".to_string())?;
            AdlsCredential::SharedKey(key_bytes)
        }
        AuthMethod::OAuthToken => {
            // The secret is the raw bearer access token. It is not
            // base64, so it must not go through the key decoder.
            let token = secrets
                .get_secret(&config.id)
                .ok_or_else(|| "no access token stored for this connection".to_string())?;
            AdlsCredential::Bearer(token.trim().to_string())
        }
        _ => return Err("wrong auth method for adls; use SharedKey or an OAuth token".to_string()),
    };
    let account = config
        .host
        .split('.')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "adls host must start with the account name".to_string())?;
    Ok(AdlsCore {
        agent: agent(),
        host: config.host.clone(),
        account: account.to_string(),
        filesystem: config.username.clone(),
        credential,
    })
}

/// The secret that authorizes requests. SharedKey holds the decoded
/// account key for HMAC signing. Bearer holds an OAuth access token
/// sent as-is in the Authorization header.
enum AdlsCredential {
    SharedKey(Vec<u8>),
    Bearer(String),
}

/// Shared signing and HTTP state for one connection. The credential
/// never leaves this struct and never appears in an error string.
struct AdlsCore {
    agent: ureq::Agent,
    host: String,
    account: String,
    filesystem: String,
    credential: AdlsCredential,
}

impl AdlsCore {
    fn base_url(&self) -> String {
        format!("https://{}/{}/", self.host, url_encode(&self.filesystem))
    }

    /// Percent-encodes a backend-local path for the URL, keeping the
    /// `/` separators. The canonicalized resource uses the raw path.
    fn encoded_path(path: &str) -> String {
        path.split('/')
            .map(url_encode)
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Builds the full request URL and the query pairs sorted by
    /// name. The sorted pairs also feed the canonicalized resource,
    /// so the signature always matches what goes on the wire.
    fn request_url(
        &self,
        path: &str,
        params: &[(String, String)],
    ) -> (String, Vec<(String, String)>) {
        let mut sorted: Vec<(String, String)> = params.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let query = sorted
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let suffix = Self::encoded_path(path).trim_start_matches('/').to_string();
        let url = if query.is_empty() {
            format!("{}{}", self.base_url(), suffix)
        } else {
            format!("{}{}?{}", self.base_url(), suffix, query)
        };
        (url, sorted)
    }

    /// Sends one signed request. `ms_headers` lists extra `x-ms-*`
    /// headers; `x-ms-date` and `x-ms-version` are always added. A
    /// body gets an explicit content type that matches the signature.
    /// Only headers sent here are signed.
    fn request(
        &self,
        method: Method,
        path: &str,
        params: &[(String, String)],
        ms_headers: &[(&str, String)],
        body: Option<&[u8]>,
    ) -> Result<ureq::Response, Box<ureq::Error>> {
        let (url, sorted_params) = self.request_url(path, params);
        let date = now_rfc1123();
        let content_type = body.map(|_| "application/octet-stream".to_string());
        let mut all_ms: Vec<(String, String)> = vec![
            ("x-ms-date".to_string(), date),
            ("x-ms-version".to_string(), MS_VERSION.to_string()),
        ];
        for (name, value) in ms_headers {
            all_ms.push((name.to_string(), value.clone()));
        }
        let auth = match &self.credential {
            AdlsCredential::SharedKey(key) => {
                let resource =
                    canonicalized_resource(&self.account, &self.filesystem, path, &sorted_params);
                let sts = string_to_sign(
                    method.as_str(),
                    body.map_or(0, |b| b.len() as u64),
                    content_type.as_deref(),
                    None,
                    &all_ms,
                    &resource,
                );
                format!("SharedKey {}:{}", self.account, signature_b64(key, &sts))
            }
            // Bearer requests need no signature. Azure still requires
            // `x-ms-version`, which `all_ms` already carries.
            AdlsCredential::Bearer(token) => format!("Bearer {token}"),
        };
        let mut req = match method {
            Method::Get => self.agent.get(&url),
            Method::Put => self.agent.put(&url),
            Method::Patch => self.agent.patch(&url),
            Method::Delete => self.agent.delete(&url),
        };
        for (name, value) in &all_ms {
            req = req.set(name, value);
        }
        if let Some(ct) = &content_type {
            req = req.set("Content-Type", ct);
        }
        req = req.set("Authorization", &auth);
        match body {
            Some(bytes) => req.send_bytes(bytes).map_err(Box::new),
            None => req.call().map_err(Box::new),
        }
    }

    /// GET with `resource=filesystem`, paged by `x-ms-continuation`.
    /// `directory` is the backend-local path without the leading
    /// slash; it is omitted at the root.
    fn fetch_page(
        &self,
        directory: &str,
        continuation: Option<&str>,
    ) -> Result<(String, Option<String>), String> {
        let mut params: Vec<(String, String)> = vec![
            ("resource".to_string(), "filesystem".to_string()),
            ("recursive".to_string(), "false".to_string()),
        ];
        if !directory.is_empty() {
            params.push(("directory".to_string(), directory.to_string()));
        }
        if let Some(token) = continuation {
            params.push(("continuation".to_string(), token.to_string()));
        }
        let display = if directory.is_empty() {
            "/".to_string()
        } else {
            format!("/{directory}")
        };
        let response = self
            .request(Method::Get, "", &params, &[], None)
            .map_err(|e| request_error("cannot list", &display, *e))?;
        let token = response.header("x-ms-continuation").map(|t| t.to_string());
        let mut body = String::new();
        response
            .into_reader()
            .read_to_string(&mut body)
            .map_err(|e| format!("cannot read listing: {e}"))?;
        Ok((body, token))
    }

    /// PATCH append of one chunk. The server tracks the position;
    /// the caller only counts bytes for the final flush.
    fn append(&self, path: &str, chunk: &[u8]) -> Result<(), String> {
        let params = vec![("action".to_string(), "append".to_string())];
        self.request(Method::Patch, path, &params, &[], Some(chunk))
            .map_err(|e| request_error("cannot append to", path, *e))
            .map(|_| ())
    }

    /// PATCH flush that closes the file at `position`. This is the
    /// durability point of an upload.
    fn flush(&self, path: &str, position: u64) -> Result<(), String> {
        let params = vec![
            ("action".to_string(), "flush".to_string()),
            ("position".to_string(), position.to_string()),
            ("close".to_string(), "true".to_string()),
        ];
        self.request(Method::Patch, path, &params, &[], Some(&[]))
            .map_err(|e| request_error("cannot flush", path, *e))
            .map(|_| ())
    }
}

/// Flattens a request failure for `path`. A 404 reads as "not found"
/// so callers can match it the way local ops errors are matched.
fn request_error(action: &str, path: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(404, _) => format!("{path}: not found"),
        other => format!("{action} {path}: {}", error_string(other)),
    }
}

/// Classifies a mkdir status. A 409 whose body reports
/// `PathAlreadyExists` is success because mkdir is idempotent.
fn mkdir_result(status: u16, body: &str) -> Result<(), String> {
    if is_ok(status) {
        return Ok(());
    }
    if status == 409 && body.contains("PathAlreadyExists") {
        return Ok(());
    }
    Err(format!("cannot create directory: HTTP {status}: {body}"))
}

/// Decides the rename pre-check from the destination getStatus call.
/// `Ok(true)` means the destination exists and the rename must fail;
/// `Ok(false)` means proceed.
fn rename_dest_exists(status: u16) -> Result<bool, String> {
    if is_ok(status) {
        Ok(true)
    } else if status == 404 {
        Ok(false)
    } else {
        Err(format!("cannot check rename destination: HTTP {status}"))
    }
}

/// `Write` over a chunk channel to a pump thread that owns the HTTP
/// appends. A pump failure poisons the writer, so the next `write`
/// or `flush` reports the stored error. The shape matches the sftp
/// writer so transfers behave the same across backends.
struct ChannelWriter {
    tx: Option<SyncSender<Vec<u8>>>,
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
    fn send(&mut self, chunk: Vec<u8>) -> std::io::Result<()> {
        if let Some(message) = &self.poisoned {
            return Err(std::io::Error::other(message.clone()));
        }
        let Some(tx) = &self.tx else {
            return Err(std::io::Error::other("writer is closed"));
        };
        if tx.send(chunk).is_err() {
            let message = match self.done_rx.recv() {
                Ok(Err(message)) => message,
                _ => "write pump exited early".to_string(),
            };
            self.poisoned = Some(message.clone());
            return Err(std::io::Error::other(message));
        }
        Ok(())
    }

    /// Closes the channel, waits for the pump's final result (the
    /// flush request), and joins the thread. Idempotent; later calls
    /// repeat the outcome.
    fn finish(&mut self) -> Result<(), String> {
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

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.send(buf.to_vec())?;
        Ok(buf.len())
    }

    /// A barrier only: an empty chunk is a no-op in the pump but
    /// surfaces a pump failure. Durability comes from the flush the
    /// pump sends after the channel closes.
    fn flush(&mut self) -> std::io::Result<()> {
        self.send(Vec::new())
    }
}

impl WriteFinish for ChannelWriter {
    /// Surfaces close-time failures (quota, flush rejection) that the
    /// per-chunk writes cannot see.
    fn finish(mut self: Box<Self>) -> Result<(), String> {
        ChannelWriter::finish(&mut self)
    }
}

impl Drop for ChannelWriter {
    /// Best-effort backstop for an abandoned writer: closing the
    /// channel makes the pump send the flush. Callers that need
    /// certainty must use [`WriteFinish::finish`].
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// Consumes chunks and appends each one at the running position. The
/// flush request runs after the writer closes the channel, so the
/// file reads as complete only when the write finishes.
fn write_pump(core: &AdlsCore, path: &str, rx: &Receiver<Vec<u8>>) -> Result<(), String> {
    let mut position: u64 = 0;
    while let Ok(chunk) = rx.recv() {
        if chunk.is_empty() {
            continue;
        }
        core.append(path, &chunk)?;
        position += chunk.len() as u64;
    }
    core.flush(path, position)
}

/// One live ADLS connection. Every call signs its own request, so
/// calls can run concurrently on the shared agent.
pub struct AdlsBackend {
    core: Arc<AdlsCore>,
}

impl AdlsBackend {
    /// Normalizes a backend-local path. The result is either empty
    /// (the filesystem root) or starts with `/`. `..` is rejected so
    /// a crafted name cannot escape the filesystem.
    fn normalize(path: &str) -> Result<String, String> {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        if trimmed.is_empty() {
            return Ok(String::new());
        }
        let mut parts = Vec::new();
        for part in trimmed.split('/') {
            match part {
                "" | "." => {}
                ".." => return Err(format!("path must not contain '..': {path}")),
                other => parts.push(other),
            }
        }
        if parts.is_empty() {
            return Ok(String::new());
        }
        Ok(format!("/{}", parts.join("/")))
    }

    /// Builds one entry from a listed path name and its fields. The
    /// listing reports names relative to the filesystem root without
    /// a leading slash; Orka paths always carry one.
    fn entry_from_listed(
        name: &str,
        is_dir: bool,
        size: u64,
        last_modified: Option<&str>,
    ) -> Entry {
        let display_name = name.rsplit('/').next().unwrap_or(name).to_string();
        Entry {
            is_hidden: display_name.starts_with('.'),
            name: display_name,
            path: format!("/{name}"),
            is_dir,
            size: if is_dir { 0 } else { size },
            modified_ms: last_modified.and_then(parse_rfc1123_to_ms).unwrap_or(0),
            is_symlink: false,
        }
    }

    /// Parses one listing page against the list options.
    fn parse_list_page(json: &str, opts: &ListOptions) -> Result<Vec<Entry>, String> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("cannot parse listing: {e}"))?;
        let paths = value
            .get("paths")
            .and_then(|p| p.as_array())
            .ok_or_else(|| "listing has no paths array".to_string())?;
        let mut entries = Vec::new();
        for item in paths {
            let Some(name) = item.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let is_dir = item
                .get("isDirectory")
                .and_then(|d| d.as_bool())
                .unwrap_or(false);
            let size = item
                .get("contentLength")
                .and_then(|s| s.as_u64())
                .unwrap_or(0);
            let modified = item.get("lastModified").and_then(|m| m.as_str());
            let entry = Self::entry_from_listed(name, is_dir, size, modified);
            if entry.name.starts_with('.') && !opts.include_hidden {
                continue;
            }
            if opts.dirs_only && !entry.is_dir {
                continue;
            }
            entries.push(entry);
        }
        Ok(entries)
    }
}

/// Drives the continuation loop against an injectable page fetcher.
/// Pure over the closure, so tests can page without a server.
fn list_all_pages<F>(mut fetch: F) -> Result<Vec<Entry>, String>
where
    F: FnMut(Option<&str>) -> Result<(Vec<Entry>, Option<String>), String>,
{
    let mut all = Vec::new();
    let mut continuation: Option<String> = None;
    loop {
        let (entries, next) = fetch(continuation.as_deref())?;
        all.extend(entries);
        match next {
            Some(token) if !token.is_empty() => continuation = Some(token),
            _ => return Ok(all),
        }
    }
}

impl FsBackend for AdlsBackend {
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
        let normalized = Self::normalize(path)?;
        let directory = normalized.trim_start_matches('/').to_string();
        let core = self.core.clone();
        let mut entries = list_all_pages(|continuation| {
            let (body, next) = core.fetch_page(&directory, continuation)?;
            let entries = Self::parse_list_page(&body, opts)?;
            Ok((entries, next))
        })?;
        crate::sort_entries(&mut entries);
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let normalized = Self::normalize(path)?;
        if normalized.is_empty() {
            return Err("cannot stat the filesystem root".to_string());
        }
        let params = vec![("action".to_string(), "getStatus".to_string())];
        let response = self
            .core
            .request(Method::Get, &normalized, &params, &[], None)
            .map_err(|e| request_error("cannot stat", &normalized, *e))?;
        let mut body = String::new();
        response
            .into_reader()
            .read_to_string(&mut body)
            .map_err(|e| format!("cannot read stat for {normalized}: {e}"))?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("cannot parse stat for {normalized}: {e}"))?;
        let is_dir = value
            .get("isDirectory")
            .and_then(|d| d.as_bool())
            .unwrap_or(false);
        let size = value
            .get("contentLength")
            .and_then(|s| s.as_u64())
            .unwrap_or(0);
        let modified = value.get("lastModified").and_then(|m| m.as_str());
        let name = normalized
            .rsplit('/')
            .next()
            .unwrap_or(&normalized)
            .to_string();
        Ok(Entry {
            is_hidden: name.starts_with('.'),
            name,
            path: normalized,
            is_dir,
            size: if is_dir { 0 } else { size },
            modified_ms: modified.and_then(parse_rfc1123_to_ms).unwrap_or(0),
            is_symlink: false,
        })
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        let normalized = Self::normalize(path)?;
        let response = self
            .core
            .request(Method::Get, &normalized, &[], &[], None)
            .map_err(|e| request_error("cannot open", &normalized, *e))?;
        Ok(response_reader(response))
    }

    fn create_write(
        &self,
        path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        let normalized = Self::normalize(path)?;
        if normalized.is_empty() {
            return Err("cannot write the filesystem root".to_string());
        }
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_DEPTH);
        let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let core = self.core.clone();
        let handle = std::thread::spawn(move || {
            let result = write_pump(&core, &normalized, &rx);
            // Returning drops rx, so a failed pump rejects later sends
            // and the writer reads this result as the reason.
            let _ = done_tx.send(result);
        });
        Ok(Box::new(ChannelWriter::new(tx, done_rx, Some(handle))))
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let normalized = Self::normalize(path)?;
        if normalized.is_empty() {
            return Err("cannot delete the filesystem root".to_string());
        }
        let params = vec![("recursive".to_string(), recursive.to_string())];
        self.core
            .request(Method::Delete, &normalized, &params, &[], None)
            .map_err(|e| request_error("cannot delete", &normalized, *e))
            .map(|_| ())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let src = Self::normalize(from)?;
        let dest = Self::normalize(to)?;
        if src.is_empty() || dest.is_empty() {
            return Err("cannot rename the filesystem root".to_string());
        }
        // Azure renames over an existing destination; Orka renames
        // never overwrite, so the pre-check keeps local semantics.
        let params = vec![("action".to_string(), "getStatus".to_string())];
        let status = match self.core.request(Method::Get, &dest, &params, &[], None) {
            Ok(response) => response.status(),
            Err(boxed) => match *boxed {
                ureq::Error::Status(status, _) => status,
                e => return Err(format!("cannot rename {from}: {}", error_string(e))),
            },
        };
        if rename_dest_exists(status)? {
            return Err(format!("an item with this name already exists: {to}"));
        }
        let source = format!("/{}/{}", self.core.filesystem, src.trim_start_matches('/'));
        let ms_headers = vec![("x-ms-rename-source", url_encode(&source))];
        let params = vec![("action".to_string(), "rename".to_string())];
        self.core
            .request(Method::Put, &dest, &params, &ms_headers, None)
            .map_err(|e| request_error("cannot rename", &dest, *e))
            .map(|_| ())
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let normalized = Self::normalize(path)?;
        if normalized.is_empty() {
            return Err("cannot create the filesystem root".to_string());
        }
        let params = vec![("resource".to_string(), "directory".to_string())];
        match self
            .core
            .request(Method::Put, &normalized, &params, &[], None)
        {
            Ok(_) => Ok(()),
            Err(boxed) => match *boxed {
                ureq::Error::Status(status, response) => {
                    let body = read_body_string(response);
                    mkdir_result(status, &body)
                }
                e => Err(format!("cannot create {normalized}: {}", error_string(e))),
            },
        }
    }
}

/// Lowercases and sorts the `x-ms-*` headers into the Blob SharedKey
/// canonicalized-headers form: one `name:value\n` line per header,
/// values trimmed. Only these headers go in the signature, so this
/// must list exactly what the request sends.
fn canonicalized_headers(headers: &[(String, String)]) -> String {
    let mut selected: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| name.to_ascii_lowercase().starts_with("x-ms-"))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    selected.sort_by(|a, b| a.0.cmp(&b.0));
    selected
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect()
}

/// Builds the canonicalized resource: `/{account}/{filesystem}{path}`
/// followed by one `\n{name}:{value}` per query parameter, sorted by
/// name, values as sent (decoded).
fn canonicalized_resource(
    account: &str,
    filesystem: &str,
    path: &str,
    params: &[(String, String)],
) -> String {
    let mut out = format!("/{account}/{filesystem}{path}");
    let mut sorted: Vec<(String, String)> = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in sorted {
        out.push('\n');
        out.push_str(&name);
        out.push(':');
        out.push_str(&value);
    }
    out
}

/// Builds the Blob SharedKey string-to-sign. Standard headers Orka
/// never sends stay empty lines; `date` is always empty because
/// `x-ms-date` is present, which also makes Azure ignore the auto
/// `Date` header ureq adds.
fn string_to_sign(
    method: &str,
    content_length: u64,
    content_type: Option<&str>,
    range: Option<&str>,
    ms_headers: &[(String, String)],
    canonical_resource: &str,
) -> String {
    let mut s = String::new();
    s.push_str(method);
    s.push('\n');
    // content-encoding, content-language.
    s.push_str("\n\n");
    // content-length: empty when 0 or absent.
    if content_length > 0 {
        s.push_str(&content_length.to_string());
    }
    s.push('\n');
    // content-md5.
    s.push('\n');
    s.push_str(content_type.unwrap_or(""));
    s.push('\n');
    // date: always empty; x-ms-date carries the time.
    s.push('\n');
    // if-modified-since, if-match, if-none-match, if-unmodified-since.
    s.push_str("\n\n\n\n");
    s.push_str(range.unwrap_or(""));
    s.push('\n');
    s.push_str(&canonicalized_headers(ms_headers));
    s.push('\n');
    s.push_str(canonical_resource);
    s
}

/// HMAC-SHA256 over `data` with `key`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Base64 of the request signature, the second half of the
/// Authorization header.
fn signature_b64(key: &[u8], string_to_sign: &str) -> String {
    BASE64.encode(hmac_sha256(key, string_to_sign.as_bytes()))
}

/// RFC 1123 date for the current UTC time, second precision. Azure
/// compares this against its own clock, so it must be GMT-formatted.
fn now_rfc1123() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    rfc1123_from_unix_ms(ms)
}

/// Formats milliseconds since the Unix epoch as
/// `Wed, 15 Nov 2023 12:45:26 GMT`. Pure so tests can pin exact
/// values; the inverse check runs through `parse_rfc1123_to_ms`.
pub fn rfc1123_from_unix_ms(ms: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, so the epoch maps to index 4.
    let weekday = WEEKDAYS[(days.rem_euclid(7) + 4) as usize % 7];
    format!(
        "{weekday}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        MONTHS[(month - 1) as usize],
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Days since 1970-01-01 to a civil date. Howard Hinnant's
/// `civil_from_days` algorithm; the inverse of `days_from_civil`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (year + if month <= 2 { 1 } else { 0 }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{join_uri, Scheme, VPath};
    use std::io::Write as _;

    struct StaticSecrets(&'static str);
    impl SecretProvider for StaticSecrets {
        fn get_secret(&self, _connection_id: &str) -> Option<String> {
            Some(self.0.to_string())
        }
    }

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
            scheme: Scheme::Adls,
            host: "myaccount.dfs.core.windows.net".to_string(),
            port: 443,
            username: "fs".to_string(),
            initial_path: "/".to_string(),
            auth,
        }
    }

    /// RFC 4231 test case 2: key "Jefe", message
    /// "what do ya want for nothing?".
    const RFC4231_KEY: &[u8] = b"Jefe";
    const RFC4231_MESSAGE: &str = "what do ya want for nothing?";
    const RFC4231_HEX: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hmac_matches_published_vector() {
        assert_eq!(
            hmac_sha256(RFC4231_KEY, RFC4231_MESSAGE.as_bytes()),
            hex_to_bytes(RFC4231_HEX)
        );
    }

    #[test]
    fn authorization_header_uses_published_vector() {
        // The header must be "SharedKey {account}:{base64(digest)}",
        // verifiable against the published HMAC result offline.
        let sig = signature_b64(RFC4231_KEY, RFC4231_MESSAGE);
        let header = format!("SharedKey myaccount:{sig}");
        let expected = format!(
            "SharedKey myaccount:{}",
            BASE64.encode(hex_to_bytes(RFC4231_HEX))
        );
        assert_eq!(header, expected);
        assert!(header.starts_with("SharedKey myaccount:"));
    }

    #[test]
    fn string_to_sign_matches_canonical_get_for_list() {
        let ms_headers = vec![
            (
                "x-ms-date".to_string(),
                "Wed, 15 Nov 2023 12:45:26 GMT".to_string(),
            ),
            ("x-ms-version".to_string(), MS_VERSION.to_string()),
        ];
        let resource = canonicalized_resource(
            "myaccount",
            "fs",
            "",
            &[
                ("resource".to_string(), "filesystem".to_string()),
                ("recursive".to_string(), "false".to_string()),
            ],
        );
        let sts = string_to_sign("GET", 0, None, None, &ms_headers, &resource);
        let expected = "GET\n\
            \n\n\n\n\n\n\n\n\n\n\n\
            x-ms-date:Wed, 15 Nov 2023 12:45:26 GMT\n\
            x-ms-version:2023-11-03\n\
            \n\
            /myaccount/fs\nrecursive:false\nresource:filesystem";
        assert_eq!(sts, expected);
    }

    #[test]
    fn string_to_sign_matches_patch_with_body_and_rename_source() {
        let ms_headers = vec![
            (
                "x-ms-date".to_string(),
                "Wed, 15 Nov 2023 12:45:26 GMT".to_string(),
            ),
            ("x-ms-version".to_string(), MS_VERSION.to_string()),
            ("x-ms-rename-source".to_string(), "/fs/src.txt".to_string()),
        ];
        let resource = canonicalized_resource(
            "myaccount",
            "fs",
            "/dir/file.txt",
            &[("action".to_string(), "append".to_string())],
        );
        let sts = string_to_sign(
            "PATCH",
            5,
            Some("application/octet-stream"),
            None,
            &ms_headers,
            &resource,
        );
        let expected = "PATCH\n\
            \n\n\
            5\n\
            \n\
            application/octet-stream\n\
            \n\
            \n\n\n\n\n\
            x-ms-date:Wed, 15 Nov 2023 12:45:26 GMT\n\
            x-ms-rename-source:/fs/src.txt\n\
            x-ms-version:2023-11-03\n\
            \n\
            /myaccount/fs/dir/file.txt\naction:append";
        assert_eq!(sts, expected);
    }

    #[test]
    fn canonicalized_resource_sorts_query_parameters() {
        let resource = canonicalized_resource(
            "myaccount",
            "fs",
            "/a b",
            &[
                ("resource".to_string(), "filesystem".to_string()),
                ("directory".to_string(), "a b".to_string()),
                ("recursive".to_string(), "false".to_string()),
            ],
        );
        assert_eq!(
            resource,
            "/myaccount/fs/a b\ndirectory:a b\nrecursive:false\nresource:filesystem"
        );
    }

    #[test]
    fn canonicalized_headers_sort_lowercase_and_trim() {
        let headers = vec![
            ("X-Ms-Version".to_string(), " 2023-11-03 ".to_string()),
            ("x-ms-date".to_string(), "Wed, 15 Nov 2023".to_string()),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ];
        assert_eq!(
            canonicalized_headers(&headers),
            "x-ms-date:Wed, 15 Nov 2023\nx-ms-version:2023-11-03\n"
        );
    }

    #[test]
    fn request_url_encodes_path_and_sorts_query() {
        let core = AdlsCore {
            agent: agent(),
            host: "myaccount.dfs.core.windows.net".to_string(),
            account: "myaccount".to_string(),
            filesystem: "fs".to_string(),
            credential: AdlsCredential::SharedKey(vec![1]),
        };
        let (url, sorted) = core.request_url(
            "/a b/c.txt",
            &[
                ("resource".to_string(), "filesystem".to_string()),
                ("directory".to_string(), "a b".to_string()),
            ],
        );
        assert_eq!(
            url,
            "https://myaccount.dfs.core.windows.net/fs/a%20b/c.txt?directory=a%20b&resource=filesystem"
        );
        assert_eq!(
            sorted,
            vec![
                ("directory".to_string(), "a b".to_string()),
                ("resource".to_string(), "filesystem".to_string()),
            ]
        );
        let (root_url, _) = core.request_url("", &[]);
        assert_eq!(root_url, "https://myaccount.dfs.core.windows.net/fs/");
    }

    #[test]
    fn list_json_parses_to_entries() {
        let json = r#"{
            "paths": [
                {"name": "dir", "isDirectory": true,
                 "lastModified": "Wed, 15 Nov 2023 12:45:26 GMT"},
                {"name": "dir/sub.txt", "contentLength": 123,
                 "lastModified": "Thu, 16 Nov 2023 08:00:00 GMT"},
                {"name": ".hidden", "contentLength": 1}
            ]
        }"#;
        let opts = ListOptions::default();
        let entries = AdlsBackend::parse_list_page(json, &opts).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/dir");
        assert_eq!(entries[0].name, "dir");
        assert!(entries[0].is_dir);
        assert_eq!(entries[0].size, 0);
        assert_eq!(
            entries[0].modified_ms,
            parse_rfc1123_to_ms("Wed, 15 Nov 2023 12:45:26 GMT").unwrap()
        );
        assert_eq!(entries[1].path, "/dir/sub.txt");
        assert_eq!(entries[1].name, "sub.txt");
        assert!(!entries[1].is_dir);
        assert_eq!(entries[1].size, 123);
        assert_eq!(
            entries[1].modified_ms,
            parse_rfc1123_to_ms("Thu, 16 Nov 2023 08:00:00 GMT").unwrap()
        );
        // Hidden entries stay out unless requested.
        let with_hidden = ListOptions {
            include_hidden: true,
            dirs_only: false,
        };
        let all = AdlsBackend::parse_list_page(json, &with_hidden).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all[2].is_hidden);
    }

    #[test]
    fn pagination_follows_continuation_tokens() {
        let page_one = r#"{"paths":[{"name":"a","contentLength":1}]}"#;
        let page_two = r#"{"paths":[{"name":"b","contentLength":2}]}"#;
        let mut calls: Vec<Option<String>> = Vec::new();
        let entries = list_all_pages(|continuation| {
            calls.push(continuation.map(|c| c.to_string()));
            match calls.len() {
                1 => Ok((
                    AdlsBackend::parse_list_page(page_one, &ListOptions::default()).unwrap(),
                    Some("token-1".to_string()),
                )),
                2 => Ok((
                    AdlsBackend::parse_list_page(page_two, &ListOptions::default()).unwrap(),
                    None,
                )),
                _ => panic!("fetched past the last page"),
            }
        })
        .unwrap();
        assert_eq!(calls, vec![None, Some("token-1".to_string())]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/a");
        assert_eq!(entries[1].path, "/b");
    }

    #[test]
    fn normalize_paths_reject_dotdot_and_handle_slashes() {
        assert_eq!(AdlsBackend::normalize("").unwrap(), "");
        assert_eq!(AdlsBackend::normalize("/").unwrap(), "");
        assert_eq!(AdlsBackend::normalize("/a/b").unwrap(), "/a/b");
        assert_eq!(AdlsBackend::normalize("a/b/").unwrap(), "/a/b");
        assert_eq!(AdlsBackend::normalize("/a//b/./").unwrap(), "/a/b");
        let err = AdlsBackend::normalize("/a/../b").unwrap_err();
        assert!(err.contains(".."), "got: {err}");
    }

    #[test]
    fn mkdir_treats_path_already_exists_as_success() {
        assert_eq!(mkdir_result(201, ""), Ok(()));
        assert_eq!(
            mkdir_result(409, "<Error><Code>PathAlreadyExists</Code></Error>"),
            Ok(())
        );
        let err =
            mkdir_result(409, "<Error><Code>InvalidFlushPosition</Code></Error>").unwrap_err();
        assert!(err.contains("409"), "got: {err}");
        assert!(mkdir_result(403, "forbidden").is_err());
    }

    #[test]
    fn rename_precheck_blocks_existing_destination_only() {
        assert_eq!(rename_dest_exists(200), Ok(true));
        assert_eq!(rename_dest_exists(201), Ok(true));
        assert_eq!(rename_dest_exists(404), Ok(false));
        assert!(rename_dest_exists(500).is_err());
    }

    #[test]
    fn request_error_maps_404_to_not_found() {
        let not_found =
            ureq::Error::Status(404, ureq::Response::new(404, "Not Found", "").unwrap());
        assert_eq!(
            request_error("cannot stat", "/missing", not_found),
            "/missing: not found"
        );
        let server_error = ureq::Error::Status(
            500,
            ureq::Response::new(500, "Server Error", "boom").unwrap(),
        );
        let message = request_error("cannot stat", "/x", server_error);
        assert!(message.contains("HTTP 500"), "got: {message}");
        assert!(message.contains("boom"), "got: {message}");
    }

    #[test]
    fn rfc1123_formatter_matches_known_values_and_round_trips() {
        assert_eq!(rfc1123_from_unix_ms(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            rfc1123_from_unix_ms(1_700_052_326_000),
            "Wed, 15 Nov 2023 12:45:26 GMT"
        );
        // Leap year: 2024-02-29.
        assert_eq!(
            rfc1123_from_unix_ms(1_709_164_800_000),
            "Thu, 29 Feb 2024 00:00:00 GMT"
        );
        // The current time must survive a round trip at second
        // precision, which is what the wire format carries.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let round_tripped = parse_rfc1123_to_ms(&rfc1123_from_unix_ms(now_ms)).unwrap();
        assert_eq!(round_tripped, now_ms - now_ms.rem_euclid(1000));
    }

    /// Fake pump with the production channel shapes. Collects bytes
    /// and reports `result` when the writer closes the channel.
    fn fake_writer(
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
    fn writer_streams_chunks_and_finishes_clean() {
        let (mut writer, written) = fake_writer(Ok(()), false);
        writer.write_all(b"first ").unwrap();
        writer.flush().unwrap();
        writer.write_all(b"second").unwrap();
        assert_eq!(writer.finish(), Ok(()));
        assert_eq!(written.lock().unwrap().as_slice(), b"first second");
    }

    #[test]
    fn writer_poisons_after_pump_failure() {
        let (mut writer, _) = fake_writer(Err("append failed".to_string()), true);
        // The pump takes nothing, so a write fails once its receiver
        // is gone and reports the pump's stored reason.
        let err = loop {
            match writer.write_all(b"data") {
                Ok(()) => continue,
                Err(err) => break err,
            }
        };
        assert!(err.to_string().contains("append failed"), "got: {err}");
        // The poisoned state must repeat on every later call.
        assert_eq!(writer.flush().unwrap_err().to_string(), "append failed");
        assert_eq!(writer.finish(), Err("append failed".to_string()));
    }

    #[test]
    fn writer_drop_joins_pump() {
        let (mut writer, written) = fake_writer(Ok(()), false);
        writer.write_all(b"bytes").unwrap();
        drop(writer);
        // Drop runs finish, so the pump saw the close and exited.
        assert_eq!(written.lock().unwrap().as_slice(), b"bytes");
    }

    #[test]
    fn factory_rejects_missing_key_before_network() {
        let err = build_core(&config(AuthMethod::SharedKey), &NoSecrets)
            .err()
            .expect("must fail");
        assert!(
            err.contains("no account key stored for this connection"),
            "got: {err}"
        );
    }

    #[test]
    fn factory_accepts_oauth_token() {
        let core = build_core(&config(AuthMethod::OAuthToken), &StaticSecrets("tok"))
            .expect("must succeed offline");
        // The token is stored as-is; it is not base64.
        match core.credential {
            AdlsCredential::Bearer(token) => assert_eq!(token, "tok"),
            AdlsCredential::SharedKey(_) => panic!("expected a Bearer credential"),
        }
    }

    #[test]
    fn factory_rejects_oauth_without_stored_token() {
        let err = build_core(&config(AuthMethod::OAuthToken), &NoSecrets)
            .err()
            .expect("must fail");
        assert!(
            err.contains("no access token stored for this connection"),
            "got: {err}"
        );
    }

    #[test]
    fn factory_rejects_other_auth_methods() {
        let err = build_core(&config(AuthMethod::Password), &StaticSecrets("pw"))
            .err()
            .expect("must fail");
        assert!(err.contains("wrong auth method"), "got: {err}");
    }

    #[test]
    fn factory_rejects_bad_host() {
        let mut cfg = config(AuthMethod::SharedKey);
        cfg.host = String::new();
        let err = build_core(&cfg, &StaticSecrets("a2V5"))
            .err()
            .expect("must fail");
        assert!(err.contains("host is empty"), "got: {err}");

        cfg.host = "https://myaccount.dfs.core.windows.net".to_string();
        let err = build_core(&cfg, &StaticSecrets("a2V5"))
            .err()
            .expect("must fail");
        assert!(err.contains("must not contain a scheme"), "got: {err}");
    }

    #[test]
    fn factory_rejects_invalid_base64_key_without_leaking_it() {
        let secret = "not base64 !!!";
        let err = build_core(&config(AuthMethod::SharedKey), &StaticSecrets(secret))
            .err()
            .expect("must fail");
        assert!(err.contains("not valid base64"), "got: {err}");
        assert!(!err.contains(secret), "error must not contain the key");
    }

    #[test]
    fn factory_derives_account_and_filesystem_from_config() {
        let core = build_core(&config(AuthMethod::SharedKey), &StaticSecrets("a2V5"))
            .expect("must succeed offline");
        assert_eq!(core.account, "myaccount");
        assert_eq!(core.filesystem, "fs");
        // "a2V5" is base64 for "key"; the decoded bytes sign requests.
        match core.credential {
            AdlsCredential::SharedKey(key) => assert_eq!(key, b"key"),
            AdlsCredential::Bearer(_) => panic!("expected a SharedKey credential"),
        }
    }

    #[test]
    fn uri_form_round_trips_through_vpath_parse() {
        let uri = join_uri(Scheme::Adls, "store", "/fs/dir");
        assert_eq!(uri, "adls://store/fs/dir");
        assert_eq!(VPath::parse(&uri).to_uri_string(), uri);
    }
}
