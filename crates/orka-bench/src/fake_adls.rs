//! A fake Azure Data Lake Storage Gen2 (`dfs`) REST endpoint for tests.
//!
//! [`FakeAdls`] answers the documented `dfs` request shapes: list
//! paths, get properties (`HEAD`), create, append, flush, read,
//! delete, and rename, each behind whichever credential
//! [`AdlsConfig`] configures (shared key, SAS, a pasted bearer token,
//! or a token minted by a [`crate::fake_oauth::FakeOAuth`]). One
//! instance can back every sign-in path a test binary exercises,
//! since every field in [`AdlsConfig`] is independent: a request is
//! accepted as soon as it carries any one valid credential.
//!
//! The fake is strict where the real service is strict, so a client
//! that drifts from the documented API fails here first: an append or
//! flush must carry a `position` equal to the file's current length,
//! an append needs a prior `PUT ?resource=file`, a create needs
//! `Content-Length: 0`, and properties come back in headers with an
//! empty body.
//!
//! This fake always serves HTTPS, on a throwaway certificate from
//! [`crate::tls::ServerTls`]. The ADLS backend has no field for a
//! port separate from its host, so a test must fold the port into the
//! host string (`"localhost:{port}"`); that string is not one of the
//! bare loopback literals `orka_core`'s `scheme_for_host` special-cases
//! for plain HTTP, so it resolves to HTTPS. A test trusts this fake's
//! certificate by pointing `ORKA_EXTRA_CA_FILE` at
//! [`FakeAdls::ca_file_path`] before it builds a backend.

use crate::fake_http::{Handler, Request, Response, Server};
use crate::fake_oauth::TokenStore;
use crate::tls::ServerTls;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Settings for one running [`FakeAdls`]. Every field is independent:
/// a request is accepted as soon as it carries any one credential this
/// config accepts, so one running instance can back every sign-in path
/// a test binary needs without rebinding a port (and re-pointing
/// `ORKA_EXTRA_CA_FILE`) per credential kind.
#[derive(Default)]
pub struct AdlsConfig {
    /// A display-only account name. Signature verification uses the
    /// account this fake's own host implies (see [`AdlsState::account`]),
    /// not this field, since that is what a real client actually signs
    /// with; this is kept only for a test that wants a realistic name
    /// to show up in a seeded error body.
    pub account_name: String,
    /// The base64 account key a `SharedKey` request must sign with.
    pub shared_key_base64: Option<String>,
    /// The exact SAS query string (no leading `?`) a SAS request must
    /// carry. Every key in it must appear, with the same value, on the
    /// request's query string.
    pub sas_token: Option<String>,
    /// A token store shared with a [`crate::fake_oauth::FakeOAuth`],
    /// for a service-principal or signed-in-app bearer token.
    pub token_store: Option<TokenStore>,
    /// A fixed bearer token, for the pasted-token (`OAuthToken`)
    /// sign-in method.
    pub static_bearer: Option<String>,
}

/// One entry in a fake filesystem's flat tree. Keyed by its path
/// relative to the filesystem root, without a leading slash (the root
/// itself is never a key).
#[derive(Clone)]
enum Node {
    Dir { modified_ms: i64 },
    File { content: Vec<u8>, modified_ms: i64 },
}

/// One filesystem (container)'s tree, plus any append data staged but
/// not yet flushed. A file node exists only after a
/// `PUT ?resource=file` (or a direct seed); an append to a path with
/// no node fails with 404, as it does on the real service.
#[derive(Default)]
struct FsTree {
    nodes: HashMap<String, Node>,
    pending: HashMap<String, Vec<u8>>,
}

impl FsTree {
    /// The offset the next append or flush must name: the committed
    /// bytes plus everything staged since the last flush.
    fn uncommitted_len(&self, path: &str) -> Option<usize> {
        match self.nodes.get(path) {
            Some(Node::File { content, .. }) => {
                Some(content.len() + self.pending.get(path).map_or(0, Vec::len))
            }
            _ => None,
        }
    }

    /// Inserts a directory node for every missing ancestor of `path`.
    /// The real service creates intermediate directories on any
    /// create, so a listing of the parent must show them.
    fn ensure_parents(&mut self, path: &str) {
        let mut prefix = String::new();
        for segment in path.split('/') {
            if !prefix.is_empty() {
                self.nodes.entry(prefix.clone()).or_insert(Node::Dir {
                    modified_ms: now_ms(),
                });
                prefix.push('/');
            }
            prefix.push_str(segment);
        }
    }
}

/// Shared state behind every request this fake serves.
struct AdlsState {
    config: AdlsConfig,
    filesystems: Mutex<HashMap<String, FsTree>>,
    /// Maximum entries returned per listing page. `usize::MAX` (the
    /// default) never pages; [`FakeAdls::set_page_size`] lowers it to
    /// force a continuation.
    page_size: Mutex<usize>,
    /// Count of `SharedKey` requests whose signature checked out.
    verified_signatures: AtomicU64,
    /// This server's own `host:port`, filled in once
    /// [`FakeAdls::start`] knows the OS-assigned port. Needed to derive
    /// the account name a real client would sign with (see
    /// [`AdlsState::account`]), which is not known until the listener
    /// binds — the same reason [`crate::fake_oauth::FakeOAuth`] fills
    /// in its own token URL this way.
    host: OnceLock<String>,
}

impl AdlsState {
    /// The account name `orka_core`'s `AdlsCore` derives from the
    /// connection host: everything before the first `.`. A test host
    /// is `"localhost:{port}"`, which has no `.`, so the whole string
    /// is the account; this mirrors that derivation exactly, since a
    /// mismatch here would fail every `SharedKey` signature check.
    fn account(&self) -> &str {
        let host = self.host.get().map(String::as_str).unwrap_or("");
        host.split('.').next().unwrap_or(host)
    }
}

/// A running fake ADLS endpoint, bound to a loopback port over HTTPS.
pub struct FakeAdls {
    server: Server,
    tls: ServerTls,
    state: Arc<AdlsState>,
}

impl FakeAdls {
    /// Starts the fake on an OS-assigned loopback port.
    pub fn start(config: AdlsConfig) -> FakeAdls {
        let tls = ServerTls::generate().expect("cannot generate test TLS material");
        let state = Arc::new(AdlsState {
            config,
            filesystems: Mutex::new(HashMap::new()),
            page_size: Mutex::new(usize::MAX),
            verified_signatures: AtomicU64::new(0),
            host: OnceLock::new(),
        });
        let handler_state = Arc::clone(&state);
        let handler: Handler = Arc::new(move |req: &Request| route(req, &handler_state));
        let server = Server::start_tls(&tls, handler);
        let _ = state.host.set(format!("localhost:{}", server.port()));
        FakeAdls { server, tls, state }
    }

    /// This server's base URL (`https://localhost:{port}`).
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// The value to use as a connection's `host`: this server's own
    /// `host:port`, in the form `AdlsCore` needs since it has no
    /// separate port field.
    pub fn host_with_port(&self) -> String {
        self.state
            .host
            .get()
            .cloned()
            .unwrap_or_else(|| format!("localhost:{}", self.server.port()))
    }

    /// Path to a PEM file holding this fake's CA certificate. Point
    /// `ORKA_EXTRA_CA_FILE` at this before building a backend that
    /// connects here, so the backend's TLS client trusts it.
    pub fn ca_file_path(&self) -> &std::path::Path {
        self.tls.ca_file_path()
    }

    /// Every request this fake has received, in arrival order. A test
    /// with more than one filesystem should filter this by request
    /// path, since the log is shared across every filesystem this
    /// instance serves.
    pub fn requests(&self) -> Vec<Request> {
        self.server.requests()
    }

    /// The number of `SharedKey` requests whose signature this fake
    /// recomputed and matched.
    pub fn verified_signature_count(&self) -> u64 {
        self.state.verified_signatures.load(Ordering::SeqCst)
    }

    /// Creates an empty filesystem (container). A no-op if it already
    /// exists.
    pub fn create_filesystem(&self, name: &str) {
        self.state
            .filesystems
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default();
    }

    /// Seeds a file directly, without going through append/flush.
    /// `path` may carry a leading slash; it is stripped to match this
    /// fake's internal key form.
    pub fn seed_file(&self, filesystem: &str, path: &str, bytes: &[u8]) {
        let mut filesystems = self.state.filesystems.lock().unwrap();
        let fs = filesystems.entry(filesystem.to_string()).or_default();
        let key = path.trim_start_matches('/').to_string();
        fs.ensure_parents(&key);
        fs.nodes.insert(
            key,
            Node::File {
                content: bytes.to_vec(),
                modified_ms: now_ms(),
            },
        );
    }

    /// Sets the maximum entries returned per listing page, forcing a
    /// continuation once a directory holds more than this.
    pub fn set_page_size(&self, n: usize) {
        *self.state.page_size.lock().unwrap() = n;
    }
}

// --- Request routing ---

/// Dispatches one request to its handler, after checking the
/// credential it carries. Each branch is one documented `dfs`
/// operation: Filesystem - List, Path - Get Properties (`HEAD`),
/// Path - Read (`GET` with no `action`), Path - Create (`PUT`),
/// Path - Update (`PATCH` append or flush), and Path - Delete.
fn route(req: &Request, state: &Arc<AdlsState>) -> Response {
    let (filesystem, path) = split_filesystem_and_path(&req.path);
    let is_listing = req.method == "GET" && req.query_param("resource") == Some("filesystem");
    let signing_path = if is_listing {
        String::new()
    } else {
        format!("/{path}")
    };

    if let Err(response) = authorize(req, state, &filesystem, &signing_path) {
        return response;
    }

    if is_listing {
        return handle_list(req, state, &filesystem);
    }
    match (req.method.as_str(), req.query_param("action")) {
        ("HEAD", None | Some("getStatus")) => handle_head(state, &filesystem, &path),
        // Path - Read takes no `action`. The old client sent
        // `GET ?action=getStatus` and parsed a JSON body; the real
        // service has no such operation.
        ("GET", Some(_)) => azure_error(
            400,
            "InvalidQueryParameterValue",
            "action is not a valid query parameter for a GET on a path",
        ),
        ("GET", None) => handle_read(req, state, &filesystem, &path),
        ("PATCH", Some("append")) => handle_append(req, state, &filesystem, &path),
        ("PATCH", Some("flush")) => handle_flush(req, state, &filesystem, &path),
        ("PUT", Some("rename")) => handle_rename(req, state, &filesystem, &path),
        ("PUT", None) => match req.query_param("resource") {
            Some("file") => handle_create_file(req, state, &filesystem, &path),
            Some("directory") => handle_mkdir(req, state, &filesystem, &path),
            _ => azure_error(
                400,
                "MissingRequiredQueryParameter",
                "a PUT on a path needs resource=file or resource=directory",
            ),
        },
        ("DELETE", None) => handle_delete(req, state, &filesystem, &path),
        _ => azure_error(
            400,
            "InvalidQueryParameterValue",
            "unrecognized request shape",
        ),
    }
}

/// Splits a raw (still percent-encoded) request-line path into the
/// filesystem name and the remaining backend-local path, both
/// decoded and without a leading slash. `AdlsCore::base_url` always
/// puts the filesystem first, so this is the inverse of that.
fn split_filesystem_and_path(raw_path: &str) -> (String, String) {
    let decoded = percent_decode(raw_path);
    let trimmed = decoded.trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((fs, rest)) => (fs.to_string(), rest.to_string()),
        None => (trimmed.to_string(), String::new()),
    }
}

/// Checks whichever credential the request carries against
/// `state.config`. `signing_path` is the backend-local path exactly as
/// `orka_core::vfs::adls` signs it: empty for a listing call, `/` plus
/// the path otherwise.
fn authorize(
    req: &Request,
    state: &AdlsState,
    filesystem: &str,
    signing_path: &str,
) -> Result<(), Response> {
    if let Some(header) = req.header("authorization") {
        if let Some(rest) = header.strip_prefix("SharedKey ") {
            return authorize_shared_key(rest, req, state, filesystem, signing_path);
        }
        if let Some(token) = header.strip_prefix("Bearer ") {
            return authorize_bearer(token, state);
        }
        return Err(unauthorized("unrecognized Authorization scheme"));
    }

    // No Authorization header: the only other credential ADLS ever
    // sends is a SAS query string, with no header at all.
    if let Some(sas) = &state.config.sas_token {
        if sas_matches(sas, &req.query) {
            return Ok(());
        }
    }
    Err(unauthorized("no valid credential presented"))
}

fn authorize_shared_key(
    rest: &str,
    req: &Request,
    state: &AdlsState,
    filesystem: &str,
    signing_path: &str,
) -> Result<(), Response> {
    // The account name itself can contain ':' (a test host is
    // "localhost:{port}"), so only the last ':' can safely separate
    // it from the signature: a base64 signature never contains one.
    let Some((_account_label, signature)) = rest.rsplit_once(':') else {
        return Err(unauthorized("malformed SharedKey header"));
    };
    let Some(key_b64) = &state.config.shared_key_base64 else {
        return Err(unauthorized("shared key auth is not configured"));
    };
    let Ok(key_bytes) = BASE64.decode(key_b64.trim()) else {
        return Err(unauthorized("configured shared key is not valid base64"));
    };
    let expected = expected_signature(req, state.account(), filesystem, signing_path, &key_bytes);
    if expected == signature {
        state.verified_signatures.fetch_add(1, Ordering::SeqCst);
        Ok(())
    } else {
        Err(forbidden("the signature did not match"))
    }
}

fn authorize_bearer(token: &str, state: &AdlsState) -> Result<(), Response> {
    let matches_static = state.config.static_bearer.as_deref() == Some(token);
    let matches_store = state
        .config
        .token_store
        .as_ref()
        .is_some_and(|store| store.is_valid_access_token(token));
    if matches_static || matches_store {
        Ok(())
    } else {
        Err(unauthorized("the bearer token is invalid or expired"))
    }
}

/// True when every `key=value` pair in `configured_sas` (a query
/// string with no leading `?`) also appears in `query`, and the
/// configured string carries both `sv` and `sig` — the two parameters
/// every real SAS token has, and the shape
/// `orka_core::vfs::adls::normalize_sas_token` requires before it ever
/// reaches this fake.
fn sas_matches(configured_sas: &str, query: &[(String, String)]) -> bool {
    let expected = parse_query_pairs(configured_sas);
    let has_sv = expected.iter().any(|(k, _)| k == "sv");
    let has_sig = expected.iter().any(|(k, _)| k == "sig");
    if !has_sv || !has_sig {
        return false;
    }
    expected
        .iter()
        .all(|(k, v)| query.iter().any(|(qk, qv)| qk == k && qv == v))
}

fn parse_query_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

// --- Route handlers ---

fn handle_list(req: &Request, state: &Arc<AdlsState>, filesystem: &str) -> Response {
    let directory = req.query_param("directory").unwrap_or("").to_string();
    let filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get(filesystem) else {
        return azure_error(
            404,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        );
    };

    let mut names: Vec<&String> = fs
        .nodes
        .keys()
        .filter(|key| parent_of(key) == directory)
        .collect();
    names.sort();

    let page_size = *state.page_size.lock().unwrap();
    let start: usize = req
        .query_param("continuation")
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
        .min(names.len());
    let end = start.saturating_add(page_size).min(names.len());

    // The real listing sends every value as a string: `isDirectory`
    // is `"true"` and is absent for a file, and `contentLength` is
    // `"0"` for a directory. A client that reads a JSON boolean or
    // number here sees nothing.
    let paths: Vec<serde_json::Value> = names[start..end]
        .iter()
        .map(|name| match &fs.nodes[*name] {
            Node::Dir { modified_ms } => serde_json::json!({
                "name": name,
                "isDirectory": "true",
                "contentLength": "0",
                "etag": etag_for(*modified_ms, 0),
                "lastModified": rfc1123(*modified_ms),
            }),
            Node::File {
                content,
                modified_ms,
            } => serde_json::json!({
                "name": name,
                "contentLength": content.len().to_string(),
                "etag": etag_for(*modified_ms, content.len()),
                "lastModified": rfc1123(*modified_ms),
            }),
        })
        .collect();

    let response = Response::json(200, &serde_json::json!({ "paths": paths }));
    if end < names.len() {
        response.header("x-ms-continuation", &end.to_string())
    } else {
        response
    }
}

/// The parent directory of a tree key: everything before its last
/// `/`, or the filesystem root (`""`) when there is none.
fn parent_of(key: &str) -> &str {
    key.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Path - Get Properties. The answer is all headers and no body:
/// `x-ms-resource-type` (`file` or `directory`), `Content-Length`,
/// `Last-Modified`, `ETag`, and an empty `x-ms-properties`.
///
/// `Content-Length` is set here by hand. The transport in
/// [`crate::fake_http`] appends its own `Content-Length: 0` after the
/// handler's headers, so the wire carries two; a client reads the
/// first, and a HEAD answer has no body for the second to describe.
fn handle_head(state: &Arc<AdlsState>, filesystem: &str, path: &str) -> Response {
    let filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get(filesystem) else {
        return head_error(404, "FilesystemNotFound");
    };
    let (resource_type, length, modified_ms) = match fs.nodes.get(path) {
        Some(Node::Dir { modified_ms }) => ("directory", 0, *modified_ms),
        Some(Node::File {
            content,
            modified_ms,
        }) => ("file", content.len(), *modified_ms),
        None => return head_error(404, "PathNotFound"),
    };
    Response::empty(200)
        .header("Content-Length", &length.to_string())
        .header("x-ms-resource-type", resource_type)
        .header("Last-Modified", &rfc1123(modified_ms))
        .header("ETag", &etag_for(modified_ms, length))
        .header("x-ms-properties", "")
}

/// Path - Read. A `Range: bytes=a-b` header narrows the answer to a
/// 206 with `Content-Range`; a range that starts past the end is a
/// 416, as on the real service.
fn handle_read(req: &Request, state: &Arc<AdlsState>, filesystem: &str, path: &str) -> Response {
    let filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get(filesystem) else {
        return azure_error(
            404,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        );
    };
    let content = match fs.nodes.get(path) {
        Some(Node::File { content, .. }) => content,
        Some(Node::Dir { .. }) => {
            return azure_error(400, "InvalidOperation", "cannot read a directory")
        }
        None => return azure_error(404, "PathNotFound", "The specified path does not exist."),
    };
    let Some(range) = req.header("range") else {
        return Response::bytes(200, "application/octet-stream", content.clone());
    };
    match parse_byte_range(range, content.len()) {
        Some((start, end)) => Response::bytes(
            206,
            "application/octet-stream",
            content[start..=end].to_vec(),
        )
        .header(
            "Content-Range",
            &format!("bytes {start}-{end}/{}", content.len()),
        ),
        None => azure_error(
            416,
            "InvalidRange",
            "The range specified is invalid for the current size of the resource.",
        )
        .header("Content-Range", &format!("bytes */{}", content.len())),
    }
}

/// Parses `bytes=start-end` or `bytes=start-` into an inclusive index
/// pair clamped to `len`. `None` when the header is malformed or the
/// start lies past the last byte.
fn parse_byte_range(header: &str, len: usize) -> Option<(usize, usize)> {
    let spec = header.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: usize = start.trim().parse().ok()?;
    if len == 0 || start >= len {
        return None;
    }
    let end: usize = match end.trim() {
        "" => len - 1,
        text => text.parse::<usize>().ok()?.min(len - 1),
    };
    if end < start {
        return None;
    }
    Some((start, end))
}

/// Path - Create for a file. Creates the file, or truncates an
/// existing one to zero bytes and drops any staged appends, the way a
/// create without `If-None-Match: *` overwrites on the real service.
fn handle_create_file(
    req: &Request,
    state: &Arc<AdlsState>,
    filesystem: &str,
    path: &str,
) -> Response {
    if let Err(response) = require_zero_content_length(req) {
        return response;
    }
    if path.is_empty() {
        return azure_error(
            400,
            "InvalidResourceName",
            "a file needs a name below the filesystem root",
        );
    }
    let mut filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get_mut(filesystem) else {
        return azure_error(
            404,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        );
    };
    if matches!(fs.nodes.get(path), Some(Node::Dir { .. })) {
        return azure_error(
            409,
            "PathAlreadyExists",
            "The specified path already exists.",
        );
    }
    fs.ensure_parents(path);
    fs.pending.remove(path);
    fs.nodes.insert(
        path.to_string(),
        Node::File {
            content: Vec::new(),
            modified_ms: now_ms(),
        },
    );
    Response::empty(201)
}

/// Path - Update with `action=append`. The `position` query parameter
/// is required and must equal the file's current uncommitted length;
/// the file must already exist.
fn handle_append(req: &Request, state: &Arc<AdlsState>, filesystem: &str, path: &str) -> Response {
    let position = match required_position(req) {
        Ok(position) => position,
        Err(response) => return response,
    };
    let mut filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get_mut(filesystem) else {
        return azure_error(
            404,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        );
    };
    let Some(expected) = fs.uncommitted_len(path) else {
        return match fs.nodes.get(path) {
            Some(Node::Dir { .. }) => {
                azure_error(400, "InvalidOperation", "cannot append to a directory")
            }
            _ => azure_error(404, "PathNotFound", "The specified path does not exist."),
        };
    };
    if position != expected {
        return azure_error(
            400,
            "InvalidFlushPosition",
            &format!("the position {position} does not equal the current length {expected}"),
        );
    }
    fs.pending
        .entry(path.to_string())
        .or_default()
        .extend_from_slice(&req.body);
    Response::empty(202)
}

/// Path - Update with `action=flush`. Commits the staged appends.
/// `position` must equal the committed length plus everything staged,
/// and the body must be empty; a flush at position 0 on a fresh file
/// commits an empty file.
fn handle_flush(req: &Request, state: &Arc<AdlsState>, filesystem: &str, path: &str) -> Response {
    let position = match required_position(req) {
        Ok(position) => position,
        Err(response) => return response,
    };
    if let Err(response) = require_zero_content_length(req) {
        return response;
    }
    let mut filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get_mut(filesystem) else {
        return azure_error(
            404,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        );
    };
    let Some(expected) = fs.uncommitted_len(path) else {
        return azure_error(404, "PathNotFound", "The specified path does not exist.");
    };
    if position != expected {
        return azure_error(
            400,
            "InvalidFlushPosition",
            &format!("the position {position} does not equal the uploaded length {expected}"),
        );
    }
    let staged = fs.pending.remove(path).unwrap_or_default();
    let modified_ms = now_ms();
    let length = match fs.nodes.get_mut(path) {
        Some(Node::File {
            content,
            modified_ms: node_modified,
        }) => {
            content.extend_from_slice(&staged);
            *node_modified = modified_ms;
            content.len()
        }
        _ => 0,
    };
    Response::empty(200)
        .header("ETag", &etag_for(modified_ms, length))
        .header("Last-Modified", &rfc1123(modified_ms))
}

/// Path - Create for a directory. Idempotent for an existing
/// directory but a conflict for an existing file.
fn handle_mkdir(req: &Request, state: &Arc<AdlsState>, filesystem: &str, path: &str) -> Response {
    if let Err(response) = require_zero_content_length(req) {
        return response;
    }
    let mut filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get_mut(filesystem) else {
        return azure_error(
            404,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        );
    };
    if matches!(fs.nodes.get(path), Some(Node::File { .. })) {
        return azure_error(
            409,
            "PathAlreadyExists",
            "The specified path already exists.",
        );
    }
    fs.ensure_parents(path);
    fs.nodes.entry(path.to_string()).or_insert(Node::Dir {
        modified_ms: now_ms(),
    });
    Response::empty(201)
}

/// The `position` query parameter an append or flush must carry.
fn required_position(req: &Request) -> Result<usize, Response> {
    let Some(raw) = req.query_param("position") else {
        return Err(azure_error(
            400,
            "MissingRequiredQueryParameter",
            "position is required for append and flush",
        ));
    };
    raw.parse().map_err(|_| {
        azure_error(
            400,
            "InvalidQueryParameterValue",
            "position must be a non-negative integer",
        )
    })
}

/// Path - Create and a flush both require `Content-Length: 0`. A
/// client that sends no body and no header at all is rejected too,
/// since Azure Storage answers a body-less PUT without a length with
/// 411.
fn require_zero_content_length(req: &Request) -> Result<(), Response> {
    match req.header("content-length") {
        Some("0") => Ok(()),
        Some(_) => Err(azure_error(
            400,
            "InvalidHeaderValue",
            "Content-Length must be 0",
        )),
        None => Err(azure_error(
            411,
            "MissingContentLengthHeader",
            "Content-Length is required",
        )),
    }
}

/// A deterministic entity tag from the time and size, so a repeated
/// read of an unchanged file sees the same value.
fn etag_for(modified_ms: i64, length: usize) -> String {
    format!("\"0x{modified_ms:X}{length:X}\"")
}

fn handle_delete(req: &Request, state: &Arc<AdlsState>, filesystem: &str, path: &str) -> Response {
    let recursive = req.query_param("recursive") == Some("true");
    let mut filesystems = state.filesystems.lock().unwrap();
    let Some(fs) = filesystems.get_mut(filesystem) else {
        return azure_error(
            404,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        );
    };
    if !fs.nodes.contains_key(path) {
        return azure_error(404, "PathNotFound", "The specified path does not exist.");
    }
    let child_prefix = format!("{path}/");
    let has_children = fs.nodes.keys().any(|key| key.starts_with(&child_prefix));
    if has_children && !recursive {
        return azure_error(409, "DirectoryNotEmpty", "The directory is not empty.");
    }
    fs.nodes
        .retain(|key, _| !(key == path || key.starts_with(&child_prefix)));
    Response::json(200, &serde_json::json!({}))
}

/// Renames the whole subtree rooted at the source path (decoded from
/// `x-ms-rename-source`) onto `dest_path`, matching real Azure's
/// atomic directory rename.
fn handle_rename(
    req: &Request,
    state: &Arc<AdlsState>,
    filesystem: &str,
    dest_path: &str,
) -> Response {
    let Some(raw_source) = req.header("x-ms-rename-source") else {
        return azure_error(
            400,
            "MissingRequiredHeader",
            "x-ms-rename-source is required",
        );
    };
    let decoded_source = percent_decode(raw_source);
    let expected_prefix = format!("/{filesystem}/");
    let Some(src_path) = decoded_source.strip_prefix(&expected_prefix) else {
        return azure_error(
            400,
            "InvalidHeaderValue",
            "x-ms-rename-source must reference this filesystem",
        );
    };

    let mut filesystems = state.filesystems.lock().unwrap();
    let fs = filesystems.entry(filesystem.to_string()).or_default();
    if fs.nodes.contains_key(dest_path) {
        return azure_error(
            409,
            "PathAlreadyExists",
            "The specified path already exists.",
        );
    }
    if !fs.nodes.contains_key(src_path) {
        return azure_error(404, "PathNotFound", "The specified path does not exist.");
    }

    let child_prefix = format!("{src_path}/");
    let moved: Vec<String> = fs
        .nodes
        .keys()
        .filter(|key| key.as_str() == src_path || key.starts_with(&child_prefix))
        .cloned()
        .collect();
    for key in moved {
        if let Some(node) = fs.nodes.remove(&key) {
            let suffix = key.strip_prefix(src_path).unwrap_or("");
            fs.nodes.insert(format!("{dest_path}{suffix}"), node);
        }
    }
    Response::empty(201)
}

// --- Blob SharedKey signature verification ---
//
// This mirrors `orka_core::vfs::adls`'s client-side signing exactly
// (`canonicalized_headers`, `canonicalized_resource`, `string_to_sign`,
// `hmac_sha256`, `signature_b64`), so this fake can recompute the same
// signature a real client sent. It is a deliberate copy rather than a
// shared dependency: `orka-bench` cannot depend on `orka-core` without
// a dependency cycle, since `orka-core`'s own tests depend on
// `orka-bench`.

fn expected_signature(
    req: &Request,
    account: &str,
    filesystem: &str,
    signing_path: &str,
    key: &[u8],
) -> String {
    let ms_headers: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(name, _)| name.starts_with("x-ms-"))
        .cloned()
        .collect();
    let resource = canonicalized_resource(account, filesystem, signing_path, &req.query);
    let content_type = req.header("content-type");
    let range = req.header("range");
    let sts = string_to_sign(
        &req.method,
        req.body.len() as u64,
        content_type,
        range,
        &ms_headers,
        &resource,
    );
    signature_b64(key, &sts)
}

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

/// The Blob SharedKey string-to-sign. `range` is the request's own
/// `Range` header when one is sent, since a ranged read signs it.
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
    s.push_str("\n\n");
    if content_length > 0 {
        s.push_str(&content_length.to_string());
    }
    s.push('\n');
    s.push('\n');
    s.push_str(content_type.unwrap_or(""));
    s.push('\n');
    s.push('\n');
    s.push_str("\n\n\n\n");
    s.push_str(range.unwrap_or(""));
    s.push('\n');
    s.push_str(&canonicalized_headers(ms_headers));
    s.push('\n');
    s.push_str(canonical_resource);
    s
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn signature_b64(key: &[u8], string_to_sign: &str) -> String {
    BASE64.encode(hmac_sha256(key, string_to_sign.as_bytes()))
}

// --- Small helpers ---

/// An error in the `dfs` shape: a JSON body and the same code in
/// `x-ms-error-code`.
fn azure_error(status: u16, code: &str, message: &str) -> Response {
    Response::json(
        status,
        &serde_json::json!({ "error": { "code": code, "message": message } }),
    )
    .header("x-ms-error-code", code)
}

/// An error on a HEAD answer, which never carries a body: only the
/// status and `x-ms-error-code` say what happened.
fn head_error(status: u16, code: &str) -> Response {
    Response::empty(status).header("x-ms-error-code", code)
}

fn unauthorized(message: &str) -> Response {
    azure_error(401, "AuthenticationFailed", message)
}

fn forbidden(message: &str) -> Response {
    azure_error(403, "AuthorizationPermissionMismatch", message)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Decodes `%XX` escapes only. Unlike form/query decoding, a URL path
/// (and the path this fake reconstructs from an `x-ms-rename-source`
/// header) must not turn a literal `+` into a space.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Formats milliseconds since the Unix epoch as
/// `Wed, 15 Nov 2023 12:45:26 GMT`, the form
/// `orka_core::vfs::http::parse_rfc1123_to_ms` reads. Duplicated from
/// `orka_core::vfs::adls::rfc1123_from_unix_ms` for the same reason as
/// the signing functions above: this crate cannot depend on
/// `orka-core`.
fn rfc1123(ms: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
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
/// `civil_from_days` algorithm.
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
