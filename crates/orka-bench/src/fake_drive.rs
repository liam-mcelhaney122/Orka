//! A fake Google Drive v3 REST API for tests.
//!
//! Serves the routes [`orka_core`'s Drive backend](../orka_core/vfs/gdrive)
//! calls: `files.list` with the `q` filters and pagination the backend
//! emits, `files.get` (metadata, and `alt=media` download), the
//! multipart and media upload endpoints, `files.create` for a folder,
//! `files.update` for a rename, and `files.delete`. State lives in one
//! in-memory tree, keyed by generated ids.
//!
//! A file never trashes; delete removes it (and, for a folder, every
//! descendant) outright, matching the real `files.delete` endpoint
//! the backend calls.
//!
//! An unauthenticated or wrongly authenticated request gets a `401`
//! in the Google error JSON shape. A request for an id this fake does
//! not hold gets a `404` in the same shape.

use crate::fake_http::{Handler, Request, Response, Server};
use crate::fake_oauth::TokenStore;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Google's folder MIME type.
pub const FOLDER_MIME: &str = "application/vnd.google-apps.folder";

/// The parent id every top-level item's `parents` array carries. Drive
/// accepts this alias for the root folder in a query; this fake never
/// stores a real item under it, so a query can match against it
/// directly.
const ROOT_ID: &str = "root";

/// One in-memory Drive item.
struct DriveFile {
    id: String,
    name: String,
    mime_type: String,
    parents: Vec<String>,
    bytes: Vec<u8>,
    modified_time: String,
}

/// Settings for one [`FakeDrive`] instance.
pub struct DriveConfig {
    /// Access tokens from a shared [`crate::fake_oauth::FakeOAuth`],
    /// for the OAuth-app and service-account sign-in paths. `None`
    /// when a test only exercises the pasted-token path.
    pub token_store: Option<TokenStore>,
    /// A fixed bearer token this fake also accepts, for the
    /// pasted-token sign-in path. `None` when a test only exercises
    /// OAuth-based sign-in.
    pub static_bearer: Option<String>,
    /// The largest number of items one `files.list` page returns,
    /// regardless of the `pageSize` the caller requested. Set low to
    /// force a listing across several pages in a test; the backend's
    /// own pagination loop keeps working either way.
    pub page_size: usize,
}

/// State shared across every connection this fake serves.
struct Inner {
    files: HashMap<String, DriveFile>,
    /// Insertion order, so a listing paginates deterministically
    /// instead of depending on `HashMap` iteration order.
    order: Vec<String>,
}

struct DriveState {
    inner: Mutex<Inner>,
    next_id: AtomicU64,
    page_size: AtomicUsize,
    token_store: Option<TokenStore>,
    static_bearer: Option<String>,
}

impl DriveState {
    fn next_id(&self) -> String {
        format!(
            "fake-drive-id-{}",
            self.next_id.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// Returns the id of the folder named `name` directly under
    /// `parent_id`, creating it first if no such folder exists yet.
    /// Walking the same path segment twice (a nested `seed_file` after
    /// a `seed_folder` for its parent, for example) must land on one
    /// folder, not a fresh duplicate every time.
    fn ensure_folder(&self, name: &str, parent_id: &str) -> String {
        let existing = {
            let inner = self.inner.lock().unwrap();
            inner
                .order
                .iter()
                .filter_map(|id| inner.files.get(id))
                .find(|f| {
                    f.mime_type == FOLDER_MIME
                        && f.name == name
                        && f.parents.iter().any(|p| p == parent_id)
                })
                .map(|f| f.id.clone())
        };
        existing.unwrap_or_else(|| self.create_item(name, FOLDER_MIME, parent_id, Vec::new()))
    }

    /// Creates one item and returns its new id.
    fn create_item(&self, name: &str, mime_type: &str, parent_id: &str, bytes: Vec<u8>) -> String {
        let id = self.next_id();
        let file = DriveFile {
            id: id.clone(),
            name: name.to_string(),
            mime_type: mime_type.to_string(),
            parents: vec![parent_id.to_string()],
            bytes,
            // A fixed timestamp is enough: the backend only needs a
            // parseable RFC 3339 value that yields a positive
            // milliseconds figure, never an exact one.
            modified_time: "2024-01-01T00:00:00Z".to_string(),
        };
        let mut inner = self.inner.lock().unwrap();
        inner.order.push(id.clone());
        inner.files.insert(id.clone(), file);
        id
    }
}

/// A fake Google Drive v3 API bound to a loopback port.
pub struct FakeDrive {
    server: Server,
    state: Arc<DriveState>,
}

impl FakeDrive {
    /// Starts the server on an OS-assigned loopback port.
    pub fn start(config: DriveConfig) -> FakeDrive {
        let state = Arc::new(DriveState {
            inner: Mutex::new(Inner {
                files: HashMap::new(),
                order: Vec::new(),
            }),
            next_id: AtomicU64::new(1),
            page_size: AtomicUsize::new(config.page_size.max(1)),
            token_store: config.token_store,
            static_bearer: config.static_bearer,
        });
        let handler_state = Arc::clone(&state);
        let handler: Handler = Arc::new(move |req: &Request| route(req, &handler_state));
        let server = Server::start(handler);
        FakeDrive { server, state }
    }

    /// This server's base URL. Set `ORKA_ENDPOINT_GOOGLE_API` to this
    /// so the backend builds `{base}/drive/v3` and
    /// `{base}/upload/drive/v3` against it.
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// Every request this fake has received, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.server.requests()
    }

    /// Sets the largest number of items one `files.list` page returns.
    pub fn set_page_size(&self, n: usize) {
        self.state.page_size.store(n.max(1), Ordering::SeqCst);
    }

    /// Creates every folder segment in `path` under the Drive root and
    /// returns the id of the leaf folder. A segment that already
    /// exists (from an earlier `seed_folder` or `seed_file` call under
    /// the same path) is reused rather than duplicated.
    pub fn seed_folder(&self, path: &str) -> String {
        let mut parent_id = ROOT_ID.to_string();
        for segment in split_path(path) {
            parent_id = self.state.ensure_folder(&segment, &parent_id);
        }
        parent_id
    }

    /// Creates the folders in `path`'s parent (if any, reusing ones
    /// that already exist) and one file at its leaf holding `bytes`.
    /// Returns the new file's id.
    pub fn seed_file(&self, path: &str, bytes: &[u8]) -> String {
        let mut segments = split_path(path);
        let name = segments
            .pop()
            .expect("seed_file path must include a file name");
        let mut parent_id = ROOT_ID.to_string();
        for segment in segments {
            parent_id = self.state.ensure_folder(&segment, &parent_id);
        }
        self.state.create_item(
            &name,
            "application/octet-stream",
            &parent_id,
            bytes.to_vec(),
        )
    }
}

/// Splits a `/`-separated path into its non-empty segments.
fn split_path(path: &str) -> Vec<String> {
    path.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Dispatches one request by method and path. Every route requires a
/// valid bearer token first.
fn route(req: &Request, state: &Arc<DriveState>) -> Response {
    if let Some(unauthorized) = check_auth(state, req) {
        return unauthorized;
    }
    match req.path.as_str() {
        "/drive/v3/files" => match req.method.as_str() {
            "GET" => handle_list(state, req),
            "POST" => handle_create_metadata(state, req),
            _ => Response::text(404, "not found"),
        },
        "/upload/drive/v3/files" => match req.method.as_str() {
            "POST" => handle_upload_create(state, req),
            _ => Response::text(404, "not found"),
        },
        path => {
            if let Some(id) = path.strip_prefix("/drive/v3/files/") {
                match req.method.as_str() {
                    "GET" if req.query_param("alt") == Some("media") => handle_download(state, id),
                    "GET" => handle_get_metadata(state, id),
                    "PATCH" => handle_patch_metadata(state, req, id),
                    "DELETE" => handle_delete(state, id),
                    _ => Response::text(404, "not found"),
                }
            } else if let Some(id) = path.strip_prefix("/upload/drive/v3/files/") {
                match req.method.as_str() {
                    "PATCH" => handle_upload_media(state, req, id),
                    _ => Response::text(404, "not found"),
                }
            } else {
                Response::text(404, "not found")
            }
        }
    }
}

/// Checks the `Authorization: Bearer` header against either the
/// configured static token or the shared OAuth token store.
fn check_auth(state: &Arc<DriveState>, req: &Request) -> Option<Response> {
    let authorized = match req.bearer_token() {
        Some(token) => {
            state.static_bearer.as_deref() == Some(token)
                || state
                    .token_store
                    .as_ref()
                    .is_some_and(|store| store.is_valid_access_token(token))
        }
        None => false,
    };
    if authorized {
        None
    } else {
        Some(google_error(401, "Invalid Credentials"))
    }
}

/// One `files.list` `q` filter, parsed out of the literal syntax the
/// backend emits: `'<id>' in parents`, `name = '<name>'`, and
/// `mimeType = '<mime>'`, joined with ` and `. `trashed = false` is
/// always true here (nothing is ever trashed) so it needs no parsing.
struct ParsedQuery {
    parent_id: String,
    name: Option<String>,
    mime_type: Option<String>,
}

fn parse_q(q: &str) -> ParsedQuery {
    let mut parent_id = String::new();
    let mut name = None;
    let mut mime_type = None;
    for clause in q.split(" and ") {
        let clause = clause.trim();
        if let Some(rest) = clause.strip_suffix(" in parents") {
            parent_id = unescape_literal(rest.trim());
        } else if let Some(rest) = clause.strip_prefix("name = ") {
            name = Some(unescape_literal(rest.trim()));
        } else if let Some(rest) = clause.strip_prefix("mimeType = ") {
            mime_type = Some(unescape_literal(rest.trim()));
        }
    }
    ParsedQuery {
        parent_id,
        name,
        mime_type,
    }
}

/// Reverses the backend's own query-literal escaping: strips the
/// surrounding quotes, then un-escapes a backslash-escaped character
/// back to itself.
fn unescape_literal(quoted: &str) -> String {
    let inner = quoted
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(quoted);
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn handle_list(state: &Arc<DriveState>, req: &Request) -> Response {
    let parsed = parse_q(req.query_param("q").unwrap_or(""));
    let requested_page_size: usize = req
        .query_param("pageSize")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let effective_page_size = requested_page_size
        .min(state.page_size.load(Ordering::SeqCst))
        .max(1);
    let offset: usize = req
        .query_param("pageToken")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let inner = state.inner.lock().unwrap();
    let matches: Vec<&DriveFile> = inner
        .order
        .iter()
        .filter_map(|id| inner.files.get(id))
        .filter(|f| f.parents.iter().any(|p| p == &parsed.parent_id))
        .filter(|f| parsed.name.as_deref().is_none_or(|n| f.name == n))
        .filter(|f| parsed.mime_type.as_deref().is_none_or(|m| f.mime_type == m))
        .collect();

    let start = offset.min(matches.len());
    let end = (start + effective_page_size).min(matches.len());
    let files_json: Vec<Value> = matches[start..end].iter().map(|f| file_json(f)).collect();

    let mut body = json!({"kind": "drive#fileList", "files": files_json});
    if end < matches.len() {
        body["nextPageToken"] = Value::String(end.to_string());
    }
    Response::json(200, &body)
}

fn handle_create_metadata(state: &Arc<DriveState>, req: &Request) -> Response {
    let body = match req.json() {
        Ok(v) => v,
        Err(e) => return google_error(400, e),
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("untitled");
    let mime_type = body.get("mimeType").and_then(|v| v.as_str()).unwrap_or("");
    let parent_id = first_parent(&body);
    let id = state.create_item(name, mime_type, &parent_id, Vec::new());
    respond_with_file(state, &id)
}

fn handle_upload_create(state: &Arc<DriveState>, req: &Request) -> Response {
    let content_type = req.header("content-type").unwrap_or("");
    let Some(boundary) = extract_boundary(content_type) else {
        return google_error(400, "missing multipart boundary");
    };
    let Some((metadata_bytes, file_bytes)) = parse_multipart_related(&req.body, &boundary) else {
        return google_error(400, "malformed multipart body");
    };
    let metadata: Value = match serde_json::from_slice(&metadata_bytes) {
        Ok(v) => v,
        Err(_) => return google_error(400, "malformed multipart metadata"),
    };
    let name = metadata
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("untitled");
    let parent_id = first_parent(&metadata);
    let id = state.create_item(name, "application/octet-stream", &parent_id, file_bytes);
    respond_with_file(state, &id)
}

fn handle_upload_media(state: &Arc<DriveState>, req: &Request, id: &str) -> Response {
    let mut inner = state.inner.lock().unwrap();
    let Some(file) = inner.files.get_mut(id) else {
        return google_error(404, format!("File not found: {id}."));
    };
    file.bytes = req.body.clone();
    Response::json(200, &file_json(file))
}

fn handle_get_metadata(state: &Arc<DriveState>, id: &str) -> Response {
    let inner = state.inner.lock().unwrap();
    match inner.files.get(id) {
        Some(f) => Response::json(200, &file_json(f)),
        None => google_error(404, format!("File not found: {id}.")),
    }
}

fn handle_download(state: &Arc<DriveState>, id: &str) -> Response {
    let inner = state.inner.lock().unwrap();
    match inner.files.get(id) {
        Some(f) if f.mime_type != FOLDER_MIME => {
            Response::bytes(200, "application/octet-stream", f.bytes.clone())
        }
        Some(_) => google_error(400, "folders have no media content"),
        None => google_error(404, format!("File not found: {id}.")),
    }
}

fn handle_patch_metadata(state: &Arc<DriveState>, req: &Request, id: &str) -> Response {
    let body = match req.json() {
        Ok(v) => v,
        Err(_) => return google_error(400, "malformed JSON body"),
    };
    let mut inner = state.inner.lock().unwrap();
    let Some(file) = inner.files.get_mut(id) else {
        return google_error(404, format!("File not found: {id}."));
    };
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        file.name = name.to_string();
    }
    Response::json(200, &file_json(file))
}

fn handle_delete(state: &Arc<DriveState>, id: &str) -> Response {
    let mut inner = state.inner.lock().unwrap();
    if !inner.files.contains_key(id) {
        return google_error(404, format!("File not found: {id}."));
    }
    delete_recursive(&mut inner, id);
    Response::empty(204)
}

/// Removes `id` and every descendant. Drive deletes a folder's
/// children server-side, so the backend never has to recurse itself;
/// this fake must do the same.
fn delete_recursive(inner: &mut Inner, id: &str) {
    let children: Vec<String> = inner
        .order
        .iter()
        .filter(|candidate| {
            inner
                .files
                .get(candidate.as_str())
                .is_some_and(|f| f.parents.iter().any(|p| p == id))
        })
        .cloned()
        .collect();
    for child in children {
        delete_recursive(inner, &child);
    }
    inner.files.remove(id);
    inner.order.retain(|x| x != id);
}

/// Looks up `id` and renders it as a `files.get`-shaped response.
/// Panics if `id` is missing: only called right after this fake
/// created that exact id, so a miss would be a bug in this file.
fn respond_with_file(state: &Arc<DriveState>, id: &str) -> Response {
    let inner = state.inner.lock().unwrap();
    let file = inner.files.get(id).expect("just-created id must exist");
    Response::json(200, &file_json(file))
}

/// The first entry of a `parents` array, or the Drive root when the
/// field is absent or empty.
fn first_parent(value: &Value) -> String {
    value
        .get("parents")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or(ROOT_ID)
        .to_string()
}

/// Renders one item the way `files.list` and `files.get` do. `size`
/// is a JSON string, and only present for a non-folder, matching the
/// real API.
fn file_json(f: &DriveFile) -> Value {
    let mut v = json!({
        "id": f.id,
        "name": f.name,
        "mimeType": f.mime_type,
        "modifiedTime": f.modified_time,
        "parents": f.parents,
    });
    if f.mime_type != FOLDER_MIME {
        v["size"] = Value::String(f.bytes.len().to_string());
    }
    v
}

/// A Drive-shaped error body: `{"error": {"code", "message", "errors"}}`.
fn google_error(status: u16, message: impl Into<String>) -> Response {
    let message = message.into();
    let reason = match status {
        401 => "authError",
        404 => "notFound",
        _ => "invalid",
    };
    Response::json(
        status,
        &json!({
            "error": {
                "code": status,
                "message": &message,
                "errors": [{"message": &message, "domain": "global", "reason": reason}],
            }
        }),
    )
}

/// Pulls the `boundary` parameter out of a `multipart/related`
/// `Content-Type` header value.
fn extract_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').find_map(|part| {
        part.trim()
            .strip_prefix("boundary=")
            .map(|b| b.trim_matches('"').to_string())
    })
}

/// Splits `haystack` on every occurrence of `needle`, keeping the
/// pieces between them (including an empty piece before a leading
/// match and after a trailing one).
fn split_on_all<'a>(haystack: &'a [u8], needle: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut rest = haystack;
    while let Some(idx) = find_bytes(rest, needle) {
        parts.push(&rest[..idx]);
        rest = &rest[idx + needle.len()..];
    }
    parts.push(rest);
    parts
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn strip_leading_crlf(b: &[u8]) -> &[u8] {
    b.strip_prefix(b"\r\n".as_slice()).unwrap_or(b)
}

fn strip_trailing_crlf(b: &[u8]) -> &[u8] {
    b.strip_suffix(b"\r\n".as_slice()).unwrap_or(b)
}

fn split_headers_body(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let idx = find_bytes(b, b"\r\n\r\n")?;
    Some((&b[..idx], &b[idx + 4..]))
}

/// Parses the exact `multipart/related` wire format the backend's own
/// `multipart_body` builds: one JSON part, then one raw-bytes part,
/// both between `--{boundary}` delimiters. Returns `None` for
/// anything else, since this fake only needs to understand the shape
/// its one caller produces.
fn parse_multipart_related(body: &[u8], boundary: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let delimiter = format!("--{boundary}");
    let parts = split_on_all(body, delimiter.as_bytes());
    if parts.len() < 3 {
        return None;
    }

    let (_, json_body) = split_headers_body(strip_leading_crlf(parts[1]))?;
    let (_, file_body) = split_headers_body(strip_leading_crlf(parts[2]))?;
    Some((
        strip_trailing_crlf(json_body).to_vec(),
        strip_trailing_crlf(file_body).to_vec(),
    ))
}
