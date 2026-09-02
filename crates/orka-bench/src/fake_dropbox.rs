//! A fake Dropbox REST API server for tests.
//!
//! [`FakeDropbox`] serves both the RPC routes (`list_folder`,
//! `get_metadata`, `delete_v2`, `move_v2`, `create_folder_v2`) and the
//! content routes (`download`, the `upload_session` trio) from one
//! [`Server`], matching how the real Dropbox API splits its two
//! origins but keeping one process and one request log for a test to
//! inspect. State lives in an in-memory tree keyed by lowercase path,
//! since Dropbox itself treats paths case-insensitively.
//!
//! A bearer token is checked against either a fixed string
//! ([`DropboxConfig::static_bearer`], for the pasted-token auth
//! method) or a [`crate::fake_oauth::TokenStore`] shared with a
//! [`crate::fake_oauth::FakeOAuth`] instance ([`DropboxConfig::token_store`],
//! for the refreshable OAuth-app auth method). A token that fails
//! either check gets Dropbox's own 401 error shape, so a client's
//! expired-token retry path runs against a realistic response.

use crate::fake_http::{Handler, Request, Response, Server};
use crate::fake_oauth::TokenStore;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Settings for one [`FakeDropbox`] instance.
pub struct DropboxConfig {
    /// Checks a bearer token against tokens a [`crate::fake_oauth::FakeOAuth`]
    /// has issued. Used for the OAuth-app auth method; `None` when the
    /// test drives the pasted-token auth method instead.
    pub token_store: Option<TokenStore>,
    /// Checks a bearer token against one fixed string. Used for the
    /// pasted-token auth method; `None` when the test drives the
    /// OAuth-app auth method instead.
    pub static_bearer: Option<String>,
    /// Maximum entries `list_folder` and `list_folder/continue` return
    /// in one page. Real Dropbox pages at up to 2,000; a test sets
    /// this low to exercise the continuation loop without seeding
    /// thousands of entries.
    pub page_size: usize,
}

impl Default for DropboxConfig {
    fn default() -> Self {
        Self {
            token_store: None,
            static_bearer: None,
            page_size: usize::MAX,
        }
    }
}

/// One file or folder in the fake's tree.
#[derive(Clone)]
struct Node {
    is_dir: bool,
    name: String,
    /// Case-preserved path, as Dropbox's `path_display` reports it.
    path_display: String,
    size: u64,
    server_modified: String,
    content_hash: Option<String>,
    content: Vec<u8>,
}

/// One in-progress chunked upload.
struct UploadSession {
    buffer: Vec<u8>,
}

/// Entries still owed to a `list_folder/continue` caller, keyed by the
/// cursor this fake handed back on the page that preceded them.
struct PendingListing {
    remaining: Vec<Value>,
}

struct DropboxState {
    token_store: Option<TokenStore>,
    static_bearer: Option<String>,
    page_size: Mutex<usize>,
    tree: Mutex<HashMap<String, Node>>,
    cursors: Mutex<HashMap<String, PendingListing>>,
    sessions: Mutex<HashMap<String, UploadSession>>,
}

/// A fake Dropbox API and content server bound to one loopback port.
pub struct FakeDropbox {
    server: Server,
    state: Arc<DropboxState>,
}

impl FakeDropbox {
    /// Starts the server on an OS-assigned loopback port. Point both
    /// `ORKA_ENDPOINT_DROPBOX_API` and `ORKA_ENDPOINT_DROPBOX_CONTENT`
    /// at [`FakeDropbox::base_url`]: the real API splits RPC and
    /// content calls across two origins, but this fake answers both
    /// from the same one.
    pub fn start(config: DropboxConfig) -> FakeDropbox {
        let state = Arc::new(DropboxState {
            token_store: config.token_store,
            static_bearer: config.static_bearer,
            page_size: Mutex::new(config.page_size),
            tree: Mutex::new(HashMap::new()),
            cursors: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        });
        let handler_state = Arc::clone(&state);
        let handler: Handler = Arc::new(move |req: &Request| route(req, &handler_state));
        let server = Server::start(handler);
        FakeDropbox { server, state }
    }

    /// This server's base URL.
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// Every request this fake has received, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.server.requests()
    }

    /// Changes the pagination page size after the server has started.
    pub fn set_page_size(&self, page_size: usize) {
        *self.state.page_size.lock().unwrap() = page_size;
    }

    /// Creates an empty folder at `path` (Dropbox path form, e.g.
    /// `/folder`). A conformance-suite root must be seeded this way
    /// before the suite runs, since the fake reports `path/not_found`
    /// for a folder it has never heard of, matching the real API.
    pub fn seed_folder(&self, path: &str) {
        let name = last_segment(path);
        self.state.tree.lock().unwrap().insert(
            path.to_lowercase(),
            Node {
                is_dir: true,
                name,
                path_display: path.to_string(),
                size: 0,
                server_modified: now_rfc3339(),
                content_hash: None,
                content: Vec::new(),
            },
        );
    }

    /// Creates a file at `path` (Dropbox path form) with `content`.
    pub fn seed_file(&self, path: &str, content: &[u8]) {
        let name = last_segment(path);
        self.state.tree.lock().unwrap().insert(
            path.to_lowercase(),
            Node {
                is_dir: false,
                name,
                path_display: path.to_string(),
                size: content.len() as u64,
                server_modified: now_rfc3339(),
                content_hash: Some(content_hash(content)),
                content: content.to_vec(),
            },
        );
    }
}

/// The last `/`-separated segment of a path, for a node's `name`.
fn last_segment(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// The Dropbox-form parent of a lowercase path: `/a/b` -> `/a`, and
/// `/a` -> `""` (root). Mirrors `dropbox::parent_of`, independently,
/// since this crate does not depend on `orka-core`.
fn parent_lower(path_lower: &str) -> String {
    match path_lower.rfind('/') {
        Some(0) | None => String::new(),
        Some(index) => path_lower[..index].to_string(),
    }
}

/// A short hex digest for a seeded or uploaded file's `content_hash`.
/// Real Dropbox hashes 4 MiB blocks and combines them; this fake only
/// needs a stable, present value; the backend never parses it.
fn content_hash(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(content);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The current time as an RFC 3339 UTC timestamp
/// (`"2023-05-31T15:14:23Z"`), the form Dropbox's `server_modified`
/// uses. Implemented locally (the inverse of the civil-date algorithm
/// `orka_core::vfs::http` uses to parse this same form), since this
/// crate does not depend on `orka-core`.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: the calendar date for a count
/// of days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// A random hex token, for session ids and cursor ids.
fn random_id() -> String {
    let mut buf = [0u8; 16];
    if getrandom::getrandom(&mut buf).is_err() {
        let fallback = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        buf = fallback.to_be_bytes()[..16].try_into().unwrap_or(buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// One error body in the shape Dropbox's API uses:
/// `{"error_summary": "...", "error": {".tag": "..."}}`. A backend
/// error mapping (like `dropbox::request_error`) matches on a
/// substring of `error_summary`, so the exact `.tag` value is not load
/// bearing.
fn dropbox_error(status: u16, error_summary: &str) -> Response {
    let tag = error_summary.split('/').next().unwrap_or("");
    Response::json(
        status,
        &json!({"error_summary": error_summary, "error": {".tag": tag}}),
    )
}

/// Checks the request's bearer token against whichever check(s)
/// `state` is configured with. `None` means the token is fine; `Some`
/// carries the 401 response to send instead.
///
/// Both a fixed string and a token store can be configured at once,
/// and either accepts the token: a test binary that shares one fake
/// across a pasted-token connection and an OAuth-app connection needs
/// both checks live on the same server, since the endpoint override
/// environment variables this fake's URL feeds are process-global and
/// so, in practice, only one fake serves the whole binary. A token
/// that matches neither check (or no check at all is configured, in
/// which case every token is accepted) is rejected.
fn check_auth(req: &Request, state: &DropboxState) -> Option<Response> {
    let token = req.bearer_token();
    let matches_static = match &state.static_bearer {
        Some(expected) => token == Some(expected.as_str()),
        None => false,
    };
    let matches_store = match &state.token_store {
        Some(store) => token
            .map(|t| store.is_valid_access_token(t))
            .unwrap_or(false),
        None => false,
    };
    let no_check_configured = state.static_bearer.is_none() && state.token_store.is_none();
    if matches_static || matches_store || no_check_configured {
        None
    } else {
        Some(dropbox_error(
            401,
            "invalid_access_token/the access token has expired",
        ))
    }
}

fn route(req: &Request, state: &Arc<DropboxState>) -> Response {
    if let Some(response) = check_auth(req, state) {
        return response;
    }
    match req.path.as_str() {
        "/2/files/list_folder" => handle_list_folder(req, state),
        "/2/files/list_folder/continue" => handle_list_continue(req, state),
        "/2/files/get_metadata" => handle_get_metadata(req, state),
        "/2/files/delete_v2" => handle_delete(req, state),
        "/2/files/move_v2" => handle_move(req, state),
        "/2/files/create_folder_v2" => handle_create_folder(req, state),
        "/2/files/download" => handle_download(req, state),
        "/2/files/upload_session/start" => handle_upload_start(req, state),
        "/2/files/upload_session/append_v2" => handle_upload_append(req, state),
        "/2/files/upload_session/finish" => handle_upload_finish(req, state),
        _ => Response::text(404, "not found"),
    }
}

/// One entry's Dropbox metadata JSON, as `list_folder` and
/// `get_metadata` return it.
fn entry_json(node: &Node) -> Value {
    let mut value = json!({
        ".tag": if node.is_dir { "folder" } else { "file" },
        "name": node.name,
        "path_lower": node.path_display.to_lowercase(),
        "path_display": node.path_display,
        "id": format!("id:{}", node.path_display.to_lowercase()),
    });
    if !node.is_dir {
        value["size"] = json!(node.size);
        value["server_modified"] = json!(node.server_modified);
        value["client_modified"] = json!(node.server_modified);
        if let Some(hash) = &node.content_hash {
            value["content_hash"] = json!(hash);
        }
    }
    value
}

/// The immediate children of `dir_lower`, sorted by path for a stable
/// page order, as their entry JSON.
fn children_of(state: &DropboxState, dir_lower: &str) -> Vec<Value> {
    let tree = state.tree.lock().unwrap();
    let mut children: Vec<&Node> = tree
        .iter()
        .filter(|(path_lower, _)| parent_lower(path_lower) == dir_lower)
        .map(|(_, node)| node)
        .collect();
    children.sort_by_key(|node| node.path_display.to_lowercase());
    children.iter().map(|node| entry_json(node)).collect()
}

/// True when `path_lower` names a folder that exists, or is the root
/// (`""`, which always exists and is never stored as a node).
fn folder_exists(state: &DropboxState, path_lower: &str) -> bool {
    if path_lower.is_empty() {
        return true;
    }
    state
        .tree
        .lock()
        .unwrap()
        .get(path_lower)
        .is_some_and(|node| node.is_dir)
}

fn parse_json_body(req: &Request) -> Result<Value, Response> {
    req.json()
        .map_err(|_| dropbox_error(400, "bad request body"))
}

fn handle_list_folder(req: &Request, state: &Arc<DropboxState>) -> Response {
    let body = match parse_json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let path = body.get("path").and_then(Value::as_str).unwrap_or("");
    let path_lower = path.to_lowercase();
    if !folder_exists(state, &path_lower) {
        return dropbox_error(409, "path/not_found/");
    }
    let mut entries = children_of(state, &path_lower);
    let page_size = *state.page_size.lock().unwrap();
    if entries.len() <= page_size {
        return Response::json(
            200,
            &json!({"entries": entries, "cursor": random_id(), "has_more": false}),
        );
    }
    let remaining: Vec<Value> = entries.split_off(page_size);
    let cursor = random_id();
    state
        .cursors
        .lock()
        .unwrap()
        .insert(cursor.clone(), PendingListing { remaining });
    Response::json(
        200,
        &json!({"entries": entries, "cursor": cursor, "has_more": true}),
    )
}

fn handle_list_continue(req: &Request, state: &Arc<DropboxState>) -> Response {
    let body = match parse_json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(cursor) = body.get("cursor").and_then(Value::as_str) else {
        return dropbox_error(400, "bad request body");
    };
    let mut pending = match state.cursors.lock().unwrap().remove(cursor) {
        Some(pending) => pending,
        None => return dropbox_error(409, "path/not_found/cursor is unknown or already spent"),
    };
    let page_size = *state.page_size.lock().unwrap();
    let page: Vec<Value> = if pending.remaining.len() <= page_size {
        std::mem::take(&mut pending.remaining)
    } else {
        let rest = pending.remaining.split_off(page_size);
        std::mem::replace(&mut pending.remaining, rest)
    };
    let has_more = !pending.remaining.is_empty();
    if has_more {
        state
            .cursors
            .lock()
            .unwrap()
            .insert(cursor.to_string(), pending);
    }
    Response::json(
        200,
        &json!({"entries": page, "cursor": cursor, "has_more": has_more}),
    )
}

fn handle_get_metadata(req: &Request, state: &Arc<DropboxState>) -> Response {
    let body = match parse_json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let path = body.get("path").and_then(Value::as_str).unwrap_or("");
    let path_lower = path.to_lowercase();
    match state.tree.lock().unwrap().get(&path_lower) {
        Some(node) => Response::json(200, &entry_json(node)),
        None => dropbox_error(409, "path/not_found/"),
    }
}

fn handle_delete(req: &Request, state: &Arc<DropboxState>) -> Response {
    let body = match parse_json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let path = body.get("path").and_then(Value::as_str).unwrap_or("");
    let path_lower = path.to_lowercase();
    let mut tree = state.tree.lock().unwrap();
    let Some(removed) = tree.remove(&path_lower) else {
        return dropbox_error(409, "path/not_found/");
    };
    if removed.is_dir {
        let prefix = format!("{path_lower}/");
        tree.retain(|key, _| !key.starts_with(&prefix));
    }
    Response::json(200, &json!({"metadata": entry_json(&removed)}))
}

fn handle_move(req: &Request, state: &Arc<DropboxState>) -> Response {
    let body = match parse_json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let from = body.get("from_path").and_then(Value::as_str).unwrap_or("");
    let to = body.get("to_path").and_then(Value::as_str).unwrap_or("");
    let from_lower = from.to_lowercase();
    let to_lower = to.to_lowercase();

    let mut tree = state.tree.lock().unwrap();
    let Some(mut node) = tree.remove(&from_lower) else {
        return dropbox_error(409, "path/not_found/");
    };
    if tree.contains_key(&to_lower) {
        tree.insert(from_lower, node);
        return dropbox_error(409, "to/conflict/");
    }
    let is_dir = node.is_dir;
    node.name = last_segment(to);
    node.path_display = to.to_string();
    let moved = entry_json(&node);
    tree.insert(to_lower.clone(), node);

    if is_dir {
        let old_prefix = format!("{from_lower}/");
        let descendants: Vec<String> = tree
            .keys()
            .filter(|key| key.starts_with(&old_prefix))
            .cloned()
            .collect();
        for old_key in descendants {
            let mut descendant = tree.remove(&old_key).expect("key just listed from the map");
            let suffix = &old_key[old_prefix.len()..];
            let new_key = format!("{to_lower}/{suffix}");
            let new_display = format!("{to}/{}", &descendant.path_display[from.len() + 1..]);
            descendant.path_display = new_display;
            tree.insert(new_key, descendant);
        }
    }
    Response::json(200, &json!({"metadata": moved}))
}

fn handle_create_folder(req: &Request, state: &Arc<DropboxState>) -> Response {
    let body = match parse_json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let path = body.get("path").and_then(Value::as_str).unwrap_or("");
    let path_lower = path.to_lowercase();
    let mut tree = state.tree.lock().unwrap();
    if tree.contains_key(&path_lower) {
        return dropbox_error(409, "path/conflict/folder");
    }
    let node = Node {
        is_dir: true,
        name: last_segment(path),
        path_display: path.to_string(),
        size: 0,
        server_modified: now_rfc3339(),
        content_hash: None,
        content: Vec::new(),
    };
    let entry = entry_json(&node);
    tree.insert(path_lower, node);
    Response::json(200, &json!({"metadata": entry}))
}

/// Parses the `Dropbox-API-Arg` header every content-route request
/// carries, the same header `dropbox::api_arg` builds on the client
/// side.
fn parse_api_arg(req: &Request) -> Result<Value, Response> {
    let raw = req
        .header("dropbox-api-arg")
        .ok_or_else(|| dropbox_error(400, "missing Dropbox-API-Arg header"))?;
    serde_json::from_str(raw).map_err(|_| dropbox_error(400, "malformed Dropbox-API-Arg header"))
}

fn handle_download(req: &Request, state: &Arc<DropboxState>) -> Response {
    let arg = match parse_api_arg(req) {
        Ok(arg) => arg,
        Err(response) => return response,
    };
    let path = arg.get("path").and_then(Value::as_str).unwrap_or("");
    let path_lower = path.to_lowercase();
    match state.tree.lock().unwrap().get(&path_lower) {
        Some(node) if !node.is_dir => {
            Response::bytes(200, "application/octet-stream", node.content.clone())
                .header("Dropbox-API-Result", &entry_json(node).to_string())
        }
        _ => dropbox_error(409, "path/not_found/"),
    }
}

fn handle_upload_start(_req: &Request, state: &Arc<DropboxState>) -> Response {
    let session_id = random_id();
    state
        .sessions
        .lock()
        .unwrap()
        .insert(session_id.clone(), UploadSession { buffer: Vec::new() });
    Response::json(200, &json!({"session_id": session_id}))
}

fn handle_upload_append(req: &Request, state: &Arc<DropboxState>) -> Response {
    let arg = match parse_api_arg(req) {
        Ok(arg) => arg,
        Err(response) => return response,
    };
    let Some(cursor) = arg.get("cursor") else {
        return dropbox_error(400, "bad request body");
    };
    let Some(session_id) = cursor.get("session_id").and_then(Value::as_str) else {
        return dropbox_error(400, "bad request body");
    };
    let offset = cursor.get("offset").and_then(Value::as_u64).unwrap_or(0);

    let mut sessions = state.sessions.lock().unwrap();
    let Some(session) = sessions.get_mut(session_id) else {
        return dropbox_error(409, "upload_session/not_found/");
    };
    if offset != session.buffer.len() as u64 {
        return dropbox_error(409, "upload_session/incorrect_offset/");
    }
    session.buffer.extend_from_slice(&req.body);
    Response::empty(200)
}

fn handle_upload_finish(req: &Request, state: &Arc<DropboxState>) -> Response {
    let arg = match parse_api_arg(req) {
        Ok(arg) => arg,
        Err(response) => return response,
    };
    let Some(cursor) = arg.get("cursor") else {
        return dropbox_error(400, "bad request body");
    };
    let Some(session_id) = cursor.get("session_id").and_then(Value::as_str) else {
        return dropbox_error(400, "bad request body");
    };
    let offset = cursor.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let Some(commit) = arg.get("commit") else {
        return dropbox_error(400, "bad request body");
    };
    let path = commit.get("path").and_then(Value::as_str).unwrap_or("");

    let session = match state.sessions.lock().unwrap().remove(session_id) {
        Some(session) => session,
        None => return dropbox_error(409, "upload_session/not_found/"),
    };
    if offset != session.buffer.len() as u64 {
        return dropbox_error(409, "upload_session/incorrect_offset/");
    }

    let path_lower = path.to_lowercase();
    let node = Node {
        is_dir: false,
        name: last_segment(path),
        path_display: path.to_string(),
        size: session.buffer.len() as u64,
        server_modified: now_rfc3339(),
        content_hash: Some(content_hash(&session.buffer)),
        content: session.buffer,
    };
    let entry = entry_json(&node);
    state.tree.lock().unwrap().insert(path_lower, node);
    Response::json(200, &entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_folder_lists_its_children() {
        let dropbox = FakeDropbox::start(DropboxConfig {
            static_bearer: Some("tok".to_string()),
            ..DropboxConfig::default()
        });
        dropbox.seed_folder("/root");
        dropbox.seed_file("/root/a.txt", b"hello");

        let response: Value = ureq::post(&format!("{}/2/files/list_folder", dropbox.base_url()))
            .set("Authorization", "Bearer tok")
            .send_json(json!({"path": "/root", "recursive": false}))
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(response["has_more"], false);
        let entries = response["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "a.txt");
    }

    #[test]
    fn a_bad_bearer_token_is_rejected() {
        let dropbox = FakeDropbox::start(DropboxConfig {
            static_bearer: Some("right".to_string()),
            ..DropboxConfig::default()
        });
        dropbox.seed_folder("/root");
        let err = ureq::post(&format!("{}/2/files/list_folder", dropbox.base_url()))
            .set("Authorization", "Bearer wrong")
            .send_json(json!({"path": "/root"}))
            .unwrap_err();
        assert!(matches!(err, ureq::Error::Status(401, _)));
    }

    #[test]
    fn listing_an_unknown_folder_reports_not_found() {
        let dropbox = FakeDropbox::start(DropboxConfig {
            static_bearer: Some("tok".to_string()),
            ..DropboxConfig::default()
        });
        let err = ureq::post(&format!("{}/2/files/list_folder", dropbox.base_url()))
            .set("Authorization", "Bearer tok")
            .send_json(json!({"path": "/nope"}))
            .unwrap_err();
        assert!(matches!(err, ureq::Error::Status(409, _)));
    }

    #[test]
    fn pagination_serves_every_entry_across_continue_calls() {
        let dropbox = FakeDropbox::start(DropboxConfig {
            static_bearer: Some("tok".to_string()),
            page_size: 3,
            ..DropboxConfig::default()
        });
        dropbox.seed_folder("/root");
        for i in 0..7 {
            dropbox.seed_file(&format!("/root/f{i}.txt"), b"x");
        }

        let mut seen = Vec::new();
        let first: Value = ureq::post(&format!("{}/2/files/list_folder", dropbox.base_url()))
            .set("Authorization", "Bearer tok")
            .send_json(json!({"path": "/root"}))
            .unwrap()
            .into_json()
            .unwrap();
        seen.extend(first["entries"].as_array().unwrap().clone());
        let mut cursor = first["cursor"].as_str().unwrap().to_string();
        let mut has_more = first["has_more"].as_bool().unwrap();
        let mut continues = 0;
        while has_more {
            let page: Value = ureq::post(&format!(
                "{}/2/files/list_folder/continue",
                dropbox.base_url()
            ))
            .set("Authorization", "Bearer tok")
            .send_json(json!({"cursor": cursor}))
            .unwrap()
            .into_json()
            .unwrap();
            continues += 1;
            seen.extend(page["entries"].as_array().unwrap().clone());
            cursor = page["cursor"].as_str().unwrap().to_string();
            has_more = page["has_more"].as_bool().unwrap();
        }
        assert_eq!(seen.len(), 7);
        assert_eq!(continues, 2);
    }

    #[test]
    fn chunked_upload_round_trips_through_the_session_endpoints() {
        let dropbox = FakeDropbox::start(DropboxConfig {
            static_bearer: Some("tok".to_string()),
            ..DropboxConfig::default()
        });
        let base = dropbox.base_url();

        let start: Value = ureq::post(&format!("{base}/2/files/upload_session/start"))
            .set("Authorization", "Bearer tok")
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&[])
            .unwrap()
            .into_json()
            .unwrap();
        let session_id = start["session_id"].as_str().unwrap().to_string();

        let first = b"first-chunk-".repeat(100);
        ureq::post(&format!("{base}/2/files/upload_session/append_v2"))
            .set("Authorization", "Bearer tok")
            .set(
                "Dropbox-API-Arg",
                &json!({"cursor": {"session_id": session_id, "offset": 0}, "close": false})
                    .to_string(),
            )
            .send_bytes(&first)
            .unwrap();

        ureq::post(&format!("{base}/2/files/upload_session/append_v2"))
            .set("Authorization", "Bearer tok")
            .set(
                "Dropbox-API-Arg",
                &json!({"cursor": {"session_id": session_id, "offset": first.len()}, "close": true})
                    .to_string(),
            )
            .send_bytes(&[])
            .unwrap();

        let finish: Value = ureq::post(&format!("{base}/2/files/upload_session/finish"))
            .set("Authorization", "Bearer tok")
            .set(
                "Dropbox-API-Arg",
                &json!({
                    "commit": {"path": "/big.bin", "mode": "overwrite", "autorename": false, "mute": true},
                    "cursor": {"session_id": session_id, "offset": first.len()},
                })
                .to_string(),
            )
            .send_bytes(&[])
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(finish["size"], first.len());

        let download = ureq::post(&format!("{base}/2/files/download"))
            .set("Authorization", "Bearer tok")
            .set("Dropbox-API-Arg", &json!({"path": "/big.bin"}).to_string())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&[])
            .unwrap();
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut download.into_reader(), &mut body).unwrap();
        assert_eq!(body, first);
    }

    #[test]
    fn moving_a_folder_carries_its_children() {
        let dropbox = FakeDropbox::start(DropboxConfig {
            static_bearer: Some("tok".to_string()),
            ..DropboxConfig::default()
        });
        dropbox.seed_folder("/src");
        dropbox.seed_file("/src/inner.txt", b"hi");
        let base = dropbox.base_url();

        ureq::post(&format!("{base}/2/files/move_v2"))
            .set("Authorization", "Bearer tok")
            .send_json(json!({"from_path": "/src", "to_path": "/dst", "autorename": false}))
            .unwrap();

        let listing: Value = ureq::post(&format!("{base}/2/files/list_folder"))
            .set("Authorization", "Bearer tok")
            .send_json(json!({"path": "/dst"}))
            .unwrap()
            .into_json()
            .unwrap();
        let entries = listing["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["path_display"], "/dst/inner.txt");
    }
}
