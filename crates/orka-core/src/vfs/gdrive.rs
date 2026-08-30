//! Google Drive backend over the Drive API v3 REST interface.
//!
//! Drive addresses files by id, but Orka addresses them by path, so
//! [`GdriveBackend`] keeps a cache that maps folder paths ("/a/b") to
//! folder ids. Cache misses walk one segment at a time through
//! `files.list`, and mutations drop the cached entries under the
//! changed path so stale ids cannot survive a delete or rename.
//!
//! Uploads buffer to a local temp file and issue one Drive request on
//! [`WriteFinish::finish`]. That keeps the close-time error contract
//! and makes an upload atomic from Drive's point of view: either one
//! overwrite PATCH or one multipart create lands.

use super::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use super::http;
use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const API_BASE: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD_BASE: &str = "https://www.googleapis.com/upload/drive/v3";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
/// Google Docs/Sheets/Slides types start with this prefix. They have
/// no downloadable bytes; only an export conversion can produce a file.
const WORKSPACE_MIME_PREFIX: &str = "application/vnd.google-apps.";
/// Drive accepts this alias for the root folder, so paths never need a
/// real root id before the first network call.
const ROOT_ALIAS: &str = "root";
const RESOLVE_PAGE_SIZE: u32 = 100;
const RESOLVE_FIELDS: &str = "nextPageToken,files(id,name)";
const LIST_PAGE_SIZE: u32 = 200;
const LIST_FIELDS: &str = "nextPageToken,files(id,name,mimeType,size,modifiedTime)";
const BOUNDARY: &str = "orka_drive_boundary_7ad9c1";

/// One item from `files.list` or `files.get`.
///
/// `size` is absent for Google Workspace documents and directories;
/// Drive also sends it as a JSON string, so both forms parse here.
#[derive(Debug, Clone, PartialEq)]
struct DriveItem {
    id: String,
    name: String,
    mime_type: String,
    size: Option<u64>,
    modified_time: Option<String>,
}

impl DriveItem {
    fn is_folder(&self) -> bool {
        self.mime_type == FOLDER_MIME
    }
}

/// Builds a [`DriveItem`] from one JSON object. Returns `None` when the
/// object lacks the id or name Drive always sends, so a malformed item
/// skips instead of failing a whole listing.
fn item_from_value(value: &serde_json::Value) -> Option<DriveItem> {
    let id = value.get("id")?.as_str()?.to_string();
    let name = value.get("name")?.as_str()?.to_string();
    let mime_type = value
        .get("mimeType")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    // Drive sends size as a string; accept a number defensively.
    let size = match value.get("size") {
        Some(serde_json::Value::String(s)) => s.parse::<u64>().ok(),
        Some(other) => other.as_u64(),
        None => None,
    };
    let modified_time = value
        .get("modifiedTime")
        .and_then(|m| m.as_str())
        .map(str::to_string);
    Some(DriveItem {
        id,
        name,
        mime_type,
        size,
        modified_time,
    })
}

/// Parses one `files.list` page. The second element is the page token
/// for the next request, or `None` after the last page.
fn parse_file_list(body: &str) -> Result<(Vec<DriveItem>, Option<String>), String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON from Drive: {e}"))?;
    let next = value
        .get("nextPageToken")
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let mut items = Vec::new();
    if let Some(files) = value.get("files").and_then(|f| f.as_array()) {
        for file in files {
            if let Some(item) = item_from_value(file) {
                items.push(item);
            }
        }
    }
    Ok((items, next))
}

/// Parses one `files.get` resource.
fn parse_file_resource(body: &str) -> Result<DriveItem, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON from Drive: {e}"))?;
    item_from_value(&value).ok_or_else(|| "file resource is missing id or name".to_string())
}

/// Returns the path without trailing slashes and with a leading slash,
/// or "/" for the root. Every cache key and error message uses this
/// form so lookups stay consistent regardless of caller input.
fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Splits a normalized path into its non-empty segments.
fn split_segments(normalized: &str) -> Vec<&str> {
    normalized.split('/').filter(|s| !s.is_empty()).collect()
}

/// The parent path and final name of a normalized path. `None` for the
/// root, which has no parent.
fn split_parent_name(normalized: &str) -> Option<(String, String)> {
    let segments = split_segments(normalized);
    let name = segments.last()?.to_string();
    let parent = if segments.len() == 1 {
        "/".to_string()
    } else {
        format!("/{}", segments[..segments.len() - 1].join("/"))
    };
    Some((parent, name))
}

fn join_child(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Escapes a value inside a Drive query string literal. Without this a
/// name containing a quote changes the query's meaning.
fn escape_query(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Query for folder resolution: one direct child folder by name.
fn folder_query(parent_id: &str, name: &str) -> String {
    format!(
        "'{}' in parents and name = '{}' and trashed = false and mimeType = '{FOLDER_MIME}'",
        escape_query(parent_id),
        escape_query(name)
    )
}

/// Query for listing a folder's children.
fn list_query(parent_id: &str) -> String {
    format!(
        "'{}' in parents and trashed = false",
        escape_query(parent_id)
    )
}

/// Query for finding one child of any kind by name.
fn find_query(parent_id: &str, name: &str) -> String {
    format!(
        "'{}' in parents and trashed = false and name = '{}'",
        escape_query(parent_id),
        escape_query(name)
    )
}

/// Builds the `files.list` URL. The query goes through percent
/// encoding because it contains spaces, quotes, and equals signs.
fn files_list_url(q: &str, fields: &str, page_size: u32, page_token: Option<&str>) -> String {
    let mut url = format!(
        "{API_BASE}/files?fields={fields}&pageSize={page_size}&q={}",
        http::url_encode(q)
    );
    if let Some(token) = page_token {
        url.push_str("&pageToken=");
        url.push_str(&http::url_encode(token));
    }
    url
}

/// Builds the exact multipart upload body for `uploadType=multipart`.
fn multipart_body(metadata_json: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata_json}\r\n--{BOUNDARY}\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// Builds an [`Entry`] from a Drive item found at `path`.
fn entry_from_file(path: &str, item: DriveItem) -> Entry {
    let is_dir = item.is_folder();
    Entry {
        is_hidden: item.name.starts_with('.'),
        name: item.name,
        path: path.to_string(),
        is_dir,
        // Workspace documents and directories have no size; report 0.
        size: if is_dir { 0 } else { item.size.unwrap_or(0) },
        modified_ms: item
            .modified_time
            .as_deref()
            .and_then(http::parse_rfc3339_to_ms)
            .unwrap_or(0),
        is_symlink: false,
    }
}

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

/// Bearer-token HTTP transport for one connection. Cloned into upload
/// hooks so a transfer never borrows the backend itself.
#[derive(Clone)]
struct Transport {
    agent: ureq::Agent,
    token: String,
}

impl Transport {
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Authenticated GET that returns the whole JSON body.
    fn get_json(&self, url: &str) -> Result<String, String> {
        let response = self
            .agent
            .get(url)
            .set("Authorization", &self.auth_header())
            .call()
            .map_err(http::error_string)?;
        Ok(http::read_body_string(response))
    }

    /// Lists files across pages until the token runs out.
    fn list_files(&self, q: &str, fields: &str, page_size: u32) -> Result<Vec<DriveItem>, String> {
        let mut items = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let url = files_list_url(q, fields, page_size, token.as_deref());
            let (page, next) = parse_file_list(&self.get_json(&url)?)?;
            items.extend(page);
            match next {
                Some(next) => token = Some(next),
                None => return Ok(items),
            }
        }
    }

    /// Folder lookup for one walk segment. The query filters on the
    /// folder mime type server-side, so any result is a folder.
    fn find_folder(&self, parent_id: &str, name: &str) -> Result<Vec<DriveItem>, String> {
        self.list_files(
            &folder_query(parent_id, name),
            RESOLVE_FIELDS,
            RESOLVE_PAGE_SIZE,
        )
    }

    /// Full metadata for one id.
    fn get_file(&self, id: &str) -> Result<DriveItem, String> {
        let url = format!("{API_BASE}/files/{id}?fields=id,name,mimeType,size,modifiedTime");
        parse_file_resource(&self.get_json(&url)?)
    }

    /// Opens a media download as a streaming reader. The response owns
    /// the connection until the reader drains or drops.
    fn download(&self, id: &str) -> Result<Box<dyn Read + Send>, String> {
        let url = format!("{API_BASE}/files/{id}?alt=media");
        let response = self
            .agent
            .get(&url)
            .set("Authorization", &self.auth_header())
            .call()
            .map_err(http::error_string)?;
        Ok(http::response_reader(response))
    }

    /// Overwrites an existing file's content in place.
    fn patch_media(&self, id: &str, bytes: &[u8]) -> Result<(), String> {
        let url = format!("{UPLOAD_BASE}/files/{id}?uploadType=media");
        self.agent
            .patch(&url)
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/octet-stream")
            .send(bytes)
            .map_err(http::error_string)?;
        Ok(())
    }

    /// Creates a new file with its content in one multipart request.
    fn post_multipart(&self, metadata_json: &str, bytes: &[u8]) -> Result<(), String> {
        let url = format!("{UPLOAD_BASE}/files?uploadType=multipart");
        let body = multipart_body(metadata_json, bytes);
        self.agent
            .post(&url)
            .set("Authorization", &self.auth_header())
            .set(
                "Content-Type",
                &format!("multipart/related; boundary={BOUNDARY}"),
            )
            .send(body.as_slice())
            .map_err(http::error_string)?;
        Ok(())
    }

    /// Creates one folder and returns its new id.
    fn create_folder(&self, name: &str, parent_id: &str) -> Result<String, String> {
        let response = self
            .agent
            .post(&format!("{API_BASE}/files"))
            .set("Authorization", &self.auth_header())
            .send_json(serde_json::json!({
                "name": name,
                "mimeType": FOLDER_MIME,
                "parents": [parent_id],
            }))
            .map_err(http::error_string)?;
        let body = http::read_body_string(response);
        let value: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("invalid JSON from Drive: {e}"))?;
        value
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_string)
            .ok_or_else(|| "folder create response is missing id".to_string())
    }

    /// Trashes one file or folder. Drive deletes a folder's children
    /// server-side, so no client-side recursion is needed.
    fn delete_file(&self, id: &str) -> Result<(), String> {
        self.agent
            .delete(&format!("{API_BASE}/files/{id}"))
            .set("Authorization", &self.auth_header())
            .call()
            .map_err(http::error_string)?;
        Ok(())
    }

    /// Renames one item in place.
    fn rename_file(&self, id: &str, name: &str) -> Result<(), String> {
        self.agent
            .patch(&format!("{API_BASE}/files/{id}"))
            .set("Authorization", &self.auth_header())
            .send_json(serde_json::json!({ "name": name }))
            .map_err(http::error_string)?;
        Ok(())
    }
}

type PathCache = Mutex<HashMap<String, String>>;

/// Fetch callback for one walk segment: given the parent folder id and
/// the segment name, return the matching children. Injectable so tests
/// exercise the walk and cache without any network.
type FolderFetch<'a> = dyn FnMut(&str, &str) -> Result<Vec<DriveItem>, String> + 'a;

fn resolve_folder_with(
    cache: &PathCache,
    segments: &[&str],
    fetch: &mut FolderFetch<'_>,
) -> Result<String, String> {
    let mut id = ROOT_ALIAS.to_string();
    let mut current = String::new();
    for segment in segments {
        current = join_child(&current, segment);
        if let Some(cached) = cache.lock().unwrap().get(&current) {
            id = cached.clone();
            continue;
        }
        let children = fetch(&id, segment)?;
        match children.into_iter().find(|item| item.name == *segment) {
            Some(item) => {
                id = item.id;
                cache.lock().unwrap().insert(current.clone(), id.clone());
            }
            None => return Err(format!("parent folder not found: {current}")),
        }
    }
    Ok(id)
}

/// Drops cached ids for `path` and everything below it. A delete or
/// rename invalidates server-side state, so any kept id would be stale.
fn invalidate_under(cache: &PathCache, path: &str) {
    let prefix = if path == "/" {
        "/".to_string()
    } else {
        format!("{path}/")
    };
    cache
        .lock()
        .unwrap()
        .retain(|key, _| *key != path && !key.starts_with(&prefix));
}

/// Uploads buffered bytes to `parent_path/name`. An existing item with
/// the same name is overwritten in place, matching local file writes.
/// A missing parent folder is an error, never an implicit create.
fn upload_bytes(
    transport: &Transport,
    cache: &PathCache,
    parent_path: &str,
    name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let parent_id = resolve_folder_cached(transport, cache, parent_path)?;
    let existing = find_item(transport, &parent_id, name)?;
    match existing {
        Some(item) => transport.patch_media(&item.id, bytes),
        None => {
            let metadata = serde_json::json!({ "name": name, "parents": [parent_id] }).to_string();
            transport.post_multipart(&metadata, bytes)
        }
    }
}

/// Resolves a folder path to a Drive id, using the shared cache.
fn resolve_folder_cached(
    transport: &Transport,
    cache: &PathCache,
    path: &str,
) -> Result<String, String> {
    let normalized = normalize_path(path);
    let segments = split_segments(&normalized);
    if segments.is_empty() {
        return Ok(ROOT_ALIAS.to_string());
    }
    let owned = transport.clone();
    let mut fetch = move |parent_id: &str, name: &str| -> Result<Vec<DriveItem>, String> {
        owned.find_folder(parent_id, name)
    };
    resolve_folder_with(cache, &segments, &mut fetch)
}

/// Finds one child of any kind by name in a folder.
fn find_item(
    transport: &Transport,
    parent_id: &str,
    name: &str,
) -> Result<Option<DriveItem>, String> {
    let q = find_query(parent_id, name);
    Ok(transport
        .list_files(&q, LIST_FIELDS, LIST_PAGE_SIZE)?
        .into_iter()
        .next())
}

/// The upload hook a finished temp-file writer calls.
type Uploader = Box<dyn FnOnce(Vec<u8>) -> Result<(), String> + Send>;

/// Buffers an upload in a temp file and uploads once on finish.
///
/// The temp file keeps memory bounded for large writes and gives the
/// single Drive request the full byte count. Failure semantics match
/// the sftp [`super::sftp::ChannelWriter`]: the first failure poisons
/// the writer, later calls repeat it, and drop finishes best-effort.
struct TempFileWriter {
    file: Option<std::fs::File>,
    temp_path: Option<PathBuf>,
    uploader: Option<Uploader>,
    poisoned: Option<String>,
    done: bool,
}

impl TempFileWriter {
    fn create(uploader: Uploader) -> io::Result<Self> {
        let temp_path = unique_temp_path();
        let file = std::fs::File::create(&temp_path)?;
        Ok(Self {
            file: Some(file),
            temp_path: Some(temp_path),
            uploader: Some(uploader),
            poisoned: None,
            done: false,
        })
    }

    /// Closes and removes the temp file, then runs the upload hook.
    /// Idempotent: a repeat is a no-op success because drop guards on
    /// `done`.
    fn finish_impl(&mut self) -> Result<(), String> {
        self.done = true;
        let bytes = match self.temp_path.take() {
            Some(path) => {
                let read = std::fs::read(&path);
                let _ = std::fs::remove_file(&path);
                match read {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let message = format!("cannot read upload buffer: {e}");
                        self.poisoned = Some(message.clone());
                        return Err(message);
                    }
                }
            }
            None => Vec::new(),
        };
        self.file.take();
        if let Some(message) = &self.poisoned {
            return Err(message.clone());
        }
        match self.uploader.take() {
            Some(upload) => upload(bytes),
            // Already finished earlier in this call chain.
            None => Ok(()),
        }
    }
}

impl Write for TempFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(message) = &self.poisoned {
            return Err(io::Error::other(message.clone()));
        }
        // An empty write is a flush barrier, not content.
        if buf.is_empty() {
            return Ok(0);
        }
        match self.file.as_mut() {
            Some(file) => file.write_all(buf).map(|()| buf.len()).inspect_err(|e| {
                let message = format!("cannot buffer upload: {e}");
                self.poisoned = Some(message);
            }),
            None => Err(io::Error::other("writer is closed")),
        }
    }

    /// A barrier only: bytes are already on disk, and the upload is
    /// the durability point at finish.
    fn flush(&mut self) -> io::Result<()> {
        if let Some(message) = &self.poisoned {
            return Err(io::Error::other(message.clone()));
        }
        Ok(())
    }
}

impl WriteFinish for TempFileWriter {
    fn finish(mut self: Box<Self>) -> Result<(), String> {
        self.finish_impl()
    }
}

impl Drop for TempFileWriter {
    /// Best-effort backstop for an abandoned writer; also guarantees
    /// the temp file never survives the writer.
    fn drop(&mut self) {
        if !self.done {
            let _ = self.finish_impl();
        }
        if let Some(path) = self.temp_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn unique_temp_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("orka-gdrive-{pid}-{unique}.tmp"))
}

/// One live Google Drive connection.
pub struct GdriveBackend {
    transport: Transport,
    /// Arc so an upload hook can own it after the writer outlives
    /// any single borrow of the backend.
    cache: Arc<PathCache>,
}

impl GdriveBackend {
    fn resolve_folder(&self, path: &str) -> Result<String, String> {
        resolve_folder_cached(&self.transport, &self.cache, path)
    }

    /// Resolves a non-root path to its item. The parent folder must
    /// exist; the item itself is matched by name server-side.
    fn stat_item(&self, path: &str) -> Result<DriveItem, String> {
        let normalized = normalize_path(path);
        let (parent, name) = split_parent_name(&normalized)
            .ok_or_else(|| "cannot stat the root folder".to_string())?;
        let parent_id = self.resolve_folder(&parent)?;
        let found = find_item(&self.transport, &parent_id, &name)?
            .ok_or_else(|| format!("{normalized}: not found"))?;
        self.transport.get_file(&found.id)
    }
}

impl FsBackend for GdriveBackend {
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
        let normalized = normalize_path(path);
        let parent_id = self.resolve_folder(&normalized)?;
        let q = list_query(&parent_id);
        let items = self.transport.list_files(&q, LIST_FIELDS, LIST_PAGE_SIZE)?;
        let mut entries = Vec::new();
        for item in items {
            if item.name.starts_with('.') && !opts.include_hidden {
                continue;
            }
            let child_path = join_child(&normalized, &item.name);
            let entry = entry_from_file(&child_path, item);
            if opts.dirs_only && !entry.is_dir {
                continue;
            }
            entries.push(entry);
        }
        crate::sort_entries(&mut entries);
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let normalized = normalize_path(path);
        if split_segments(&normalized).is_empty() {
            return Ok(root_entry());
        }
        let item = self.stat_item(&normalized)?;
        Ok(entry_from_file(&normalized, item))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn Read + Send>, String> {
        let normalized = normalize_path(path);
        let item = self.stat_item(&normalized)?;
        if item.is_folder() {
            return Err(format!("{normalized} is a folder"));
        }
        // Google Docs types have no downloadable bytes; the media
        // endpoint would return an opaque error, so fail with the
        // real reason instead.
        if item.mime_type.starts_with(WORKSPACE_MIME_PREFIX) {
            return Err(format!(
                "cannot download {}: Google Workspace export is not supported",
                item.name
            ));
        }
        self.transport.download(&item.id)
    }

    fn create_write(
        &self,
        path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        let normalized = normalize_path(path);
        let (parent, name) = split_parent_name(&normalized)
            .ok_or_else(|| "cannot upload to the root folder".to_string())?;
        let transport = self.transport.clone();
        let cache = Arc::clone(&self.cache);
        let uploader: Uploader =
            Box::new(move |bytes| upload_bytes(&transport, &cache, &parent, &name, &bytes));
        let writer = TempFileWriter::create(uploader)
            .map_err(|e| format!("cannot buffer upload for {normalized}: {e}"))?;
        Ok(Box::new(writer))
    }

    fn delete(&self, path: &str, _recursive: bool) -> Result<(), String> {
        let normalized = normalize_path(path);
        if split_segments(&normalized).is_empty() {
            return Err("cannot delete the root folder".to_string());
        }
        let (parent, name) = split_parent_name(&normalized)
            .ok_or_else(|| "cannot delete the root folder".to_string())?;
        let parent_id = self.resolve_folder(&parent)?;
        let item = find_item(&self.transport, &parent_id, &name)?
            .ok_or_else(|| format!("{normalized}: not found"))?;
        self.transport.delete_file(&item.id)?;
        invalidate_under(&self.cache, &normalized);
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let from_n = normalize_path(from);
        let to_n = normalize_path(to);
        if split_segments(&from_n).is_empty() {
            return Err("cannot rename the root folder".to_string());
        }
        let (from_parent, old_name) = split_parent_name(&from_n)
            .ok_or_else(|| "cannot rename the root folder".to_string())?;
        let (to_parent, new_name) = split_parent_name(&to_n)
            .ok_or_else(|| "cannot rename to the root folder".to_string())?;
        if from_parent != to_parent {
            // Drive renames within one parent; a move would need a
            // parents patch, which this backend does not offer.
            return Err("cross-folder rename is not supported on Google Drive".to_string());
        }
        let parent_id = self.resolve_folder(&from_parent)?;
        let item = find_item(&self.transport, &parent_id, &old_name)?
            .ok_or_else(|| format!("{from_n}: not found"))?;
        // Drive allows duplicate names; local semantics do not, so
        // pre-check the destination by name.
        if find_item(&self.transport, &parent_id, &new_name)?.is_some() {
            return Err(format!("an item with this name already exists: {to_n}"));
        }
        self.transport.rename_file(&item.id, &new_name)?;
        invalidate_under(&self.cache, &from_n);
        Ok(())
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let normalized = normalize_path(path);
        if split_segments(&normalized).is_empty() {
            // The root always exists.
            return Ok(());
        }
        let (parent, name) = split_parent_name(&normalized)
            .ok_or_else(|| "cannot create the root folder".to_string())?;
        let parent_id = self.resolve_folder(&parent)?;
        // Idempotent: an existing folder with this name is success.
        let existing = self.transport.find_folder(&parent_id, &name)?;
        if let Some(item) = existing.into_iter().next() {
            self.cache
                .lock()
                .unwrap()
                .insert(normalized.clone(), item.id);
            return Ok(());
        }
        let id = self.transport.create_folder(&name, &parent_id)?;
        self.cache.lock().unwrap().insert(normalized, id);
        Ok(())
    }
}

/// Creates Google Drive backends. Registered once for
/// [`super::Scheme::Gdrive`].
pub struct GdriveFactory;

impl BackendFactory for GdriveFactory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        if config.auth != AuthMethod::OAuthToken {
            return Err("wrong auth method for gdrive".to_string());
        }
        // Resolve the token before anything else so a missing secret
        // fails without a network call.
        let token = secrets
            .get_secret(&config.id)
            .ok_or_else(|| "no access token stored for this connection".to_string())?;
        Ok(Arc::new(GdriveBackend {
            transport: Transport {
                agent: http::agent(),
                token,
            },
            cache: Arc::new(Mutex::new(HashMap::new())),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::Scheme;
    use std::sync::Arc;

    struct NoSecrets;
    impl SecretProvider for NoSecrets {
        fn get_secret(&self, _connection_id: &str) -> Option<String> {
            None
        }
    }

    fn config() -> ConnectionConfig {
        ConnectionConfig {
            id: "test".to_string(),
            display_name: "Test".to_string(),
            scheme: Scheme::Gdrive,
            host: "drive.google.com".to_string(),
            port: 443,
            username: "user".to_string(),
            initial_path: "/".to_string(),
            auth: AuthMethod::OAuthToken,
        }
    }

    fn folder_item(id: &str, name: &str) -> DriveItem {
        DriveItem {
            id: id.to_string(),
            name: name.to_string(),
            mime_type: FOLDER_MIME.to_string(),
            size: None,
            modified_time: None,
        }
    }

    #[test]
    fn missing_token_fails_before_any_network_call() {
        let err = GdriveFactory
            .connect(&config(), Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(
            err.contains("no access token stored for this connection"),
            "got: {err}"
        );
    }

    #[test]
    fn wrong_auth_method_is_rejected() {
        let mut cfg = config();
        cfg.auth = AuthMethod::Password;
        let err = GdriveFactory
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("wrong auth method"), "got: {err}");
    }

    #[test]
    fn folder_query_text_matches_drive_syntax() {
        assert_eq!(
            folder_query("FOLDERID", "My Docs"),
            "'FOLDERID' in parents and name = 'My Docs' and trashed = false and \
             mimeType = 'application/vnd.google-apps.folder'"
        );
    }

    #[test]
    fn list_and_find_queries_match_drive_syntax() {
        assert_eq!(list_query("P"), "'P' in parents and trashed = false");
        assert_eq!(
            find_query("P", "a.txt"),
            "'P' in parents and trashed = false and name = 'a.txt'"
        );
    }

    #[test]
    fn list_url_encodes_the_query() {
        let q = folder_query("FOLDERID", "My Docs");
        let url = files_list_url(&q, RESOLVE_FIELDS, RESOLVE_PAGE_SIZE, None);
        assert!(
            url.starts_with("https://www.googleapis.com/drive/v3/files?"),
            "url: {url}"
        );
        assert!(url.contains(&http::url_encode(&q)), "url: {url}");
        assert!(url.contains("pageSize=100"), "url: {url}");
        assert!(!url.contains("pageToken"), "url: {url}");
        // Quotes and spaces must be percent-encoded, never raw.
        assert!(!url.contains("My Docs"), "url: {url}");
        let paged = files_list_url(&q, RESOLVE_FIELDS, RESOLVE_PAGE_SIZE, Some("tok/en"));
        assert!(
            paged.contains(&format!("pageToken={}", http::url_encode("tok/en"))),
            "url: {paged}"
        );
    }

    fn sample_list_json() -> &'static str {
        r#"{
            "kind": "drive#fileList",
            "nextPageToken": null,
            "files": [
                {"id": "d1", "name": "Reports",
                 "mimeType": "application/vnd.google-apps.folder",
                 "modifiedTime": "2023-05-31T15:14:23Z"},
                {"id": "f1", "name": "a.txt", "mimeType": "text/plain",
                 "size": "12", "modifiedTime": "2023-05-31T15:14:23Z"},
                {"id": "f2", "name": "Design Doc",
                 "mimeType": "application/vnd.google-apps.document",
                 "modifiedTime": "2023-05-31T15:14:23Z"},
                {"id": "f3", "name": ".hidden", "mimeType": "text/plain", "size": "3"}
            ]
        }"#
    }

    #[test]
    fn parses_recorded_list_sample_into_entries() {
        let (items, next) = parse_file_list(sample_list_json()).unwrap();
        assert_eq!(next, None);
        assert_eq!(items.len(), 4);
        let entries: Vec<Entry> = items
            .into_iter()
            .map(|item| {
                let child = join_child("/proj", &item.name);
                entry_from_file(&child, item)
            })
            .collect();

        let folder = &entries[0];
        assert!(folder.is_dir);
        assert_eq!(folder.name, "Reports");
        assert_eq!(folder.path, "/proj/Reports");
        assert_eq!(folder.size, 0);
        assert_eq!(folder.modified_ms, 1_685_546_063_000);
        assert!(!folder.is_hidden);

        let file = &entries[1];
        assert!(!file.is_dir);
        assert_eq!(file.size, 12);

        // A Google Docs file has no size field and must report 0.
        let doc = &entries[2];
        assert!(!doc.is_dir);
        assert_eq!(doc.size, 0);

        let hidden = &entries[3];
        assert!(hidden.is_hidden);
    }

    #[test]
    fn size_parses_drive_string_form() {
        let sized =
            item_from_value(&serde_json::json!({"id": "i", "name": "n", "size": "1234"})).unwrap();
        assert_eq!(sized.size, Some(1_234));
        let absent = item_from_value(&serde_json::json!({"id": "i", "name": "n"})).unwrap();
        assert_eq!(absent.size, None);
    }

    #[test]
    fn walk_resolves_deep_paths_in_order() {
        let cache = Mutex::new(HashMap::new());
        let mut calls: Vec<(String, String)> = Vec::new();
        let mut fetch = |parent_id: &str, name: &str| -> Result<Vec<DriveItem>, String> {
            calls.push((parent_id.to_string(), name.to_string()));
            match name {
                "a" => Ok(vec![folder_item("id-a", "a")]),
                "b" => Ok(vec![folder_item("id-ab", "b")]),
                _ => Ok(vec![]),
            }
        };
        let id = resolve_folder_with(&cache, &["a", "b"], &mut fetch).unwrap();
        assert_eq!(id, "id-ab");
        assert_eq!(
            calls,
            vec![
                ("root".to_string(), "a".to_string()),
                ("id-a".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn second_resolution_hits_the_cache() {
        let cache = Mutex::new(HashMap::new());
        let mut fetch = |parent_id: &str, name: &str| -> Result<Vec<DriveItem>, String> {
            assert_eq!(parent_id, "root");
            Ok(vec![folder_item("id-a", name)])
        };
        assert_eq!(
            resolve_folder_with(&cache, &["a"], &mut fetch).unwrap(),
            "id-a"
        );
        let mut no_fetch = |_parent: &str, _name: &str| -> Result<Vec<DriveItem>, String> {
            panic!("cached resolution must not fetch");
        };
        assert_eq!(
            resolve_folder_with(&cache, &["a"], &mut no_fetch).unwrap(),
            "id-a"
        );
    }

    #[test]
    fn missing_segment_reports_parent_folder_not_found() {
        let cache = Mutex::new(HashMap::new());
        let mut fetch =
            |_parent: &str, _name: &str| -> Result<Vec<DriveItem>, String> { Ok(vec![]) };
        let err = resolve_folder_with(&cache, &["missing"], &mut fetch).unwrap_err();
        assert!(err.contains("parent folder not found"), "got: {err}");
        assert!(err.contains("/missing"), "got: {err}");
    }

    #[test]
    fn invalidate_under_clears_only_the_affected_prefix() {
        let cache = Mutex::new(HashMap::from([
            ("/a".to_string(), "1".to_string()),
            ("/a/old".to_string(), "2".to_string()),
            ("/a/old/sub".to_string(), "3".to_string()),
            ("/a/older".to_string(), "4".to_string()),
            ("/b".to_string(), "5".to_string()),
        ]));
        invalidate_under(&cache, "/a/old");
        let keys: Vec<String> = cache.lock().unwrap().keys().cloned().collect();
        assert!(keys.contains(&"/a".to_string()));
        assert!(keys.contains(&"/a/older".to_string()));
        assert!(keys.contains(&"/b".to_string()));
        assert!(!keys.iter().any(|k| k == "/a/old" || k == "/a/old/sub"));
    }

    #[test]
    fn multipart_body_has_exact_wire_bytes() {
        let metadata = r#"{"name":"notes.txt","parents":["abc123"]}"#;
        let body = multipart_body(metadata, b"hello");
        let expected: Vec<u8> = format!(
            "--{BOUNDARY}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n\
             {metadata}\r\n--{BOUNDARY}\r\nContent-Type: application/octet-stream\r\n\r\n\
             hello\r\n--{BOUNDARY}--\r\n"
        )
        .into_bytes();
        assert_eq!(body, expected);
    }

    #[test]
    fn temp_writer_finish_uploads_buffered_bytes() {
        let uploaded = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = uploaded.clone();
        let uploader: Uploader = Box::new(move |bytes| {
            sink.lock().unwrap().extend_from_slice(&bytes);
            Ok(())
        });
        let mut writer = TempFileWriter::create(uploader).unwrap();
        let temp_path = writer.temp_path.clone().unwrap();
        writer.write_all(b"hello ").unwrap();
        writer.write_all(b"world").unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.finish_impl(), Ok(()));
        assert_eq!(uploaded.lock().unwrap().as_slice(), b"hello world");
        assert!(
            !temp_path.exists(),
            "temp file must be removed after finish"
        );
    }

    #[test]
    fn temp_writer_poison_repeats_on_later_calls() {
        let mut writer = TempFileWriter {
            file: None,
            temp_path: None,
            uploader: None,
            poisoned: Some("disk full".to_string()),
            done: false,
        };
        let err = writer.write_all(b"x").unwrap_err();
        assert!(err.to_string().contains("disk full"), "got: {err}");
        let err = writer.flush().unwrap_err();
        assert!(err.to_string().contains("disk full"), "got: {err}");
        assert_eq!(writer.finish_impl(), Err("disk full".to_string()));
    }

    #[test]
    fn temp_writer_drop_finishes_best_effort() {
        let uploaded = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = uploaded.clone();
        let uploader: Uploader = Box::new(move |bytes| {
            sink.lock().unwrap().extend_from_slice(&bytes);
            Ok(())
        });
        let mut writer = TempFileWriter::create(uploader).unwrap();
        let temp_path = writer.temp_path.clone().unwrap();
        writer.write_all(b"bytes").unwrap();
        drop(writer);
        assert_eq!(uploaded.lock().unwrap().as_slice(), b"bytes");
        assert!(!temp_path.exists());
    }

    #[test]
    fn temp_writer_upload_failure_surfaces_at_finish() {
        let uploader: Uploader = Box::new(|_bytes| Err("upload failed".to_string()));
        let mut writer = TempFileWriter::create(uploader).unwrap();
        let temp_path = writer.temp_path.clone().unwrap();
        writer.write_all(b"data").unwrap();
        assert_eq!(writer.finish_impl(), Err("upload failed".to_string()));
        assert!(
            !temp_path.exists(),
            "temp file must be removed even on failure"
        );
    }

    #[test]
    fn normalize_and_split_handle_root_and_trailing_slashes() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("a/b/"), "/a/b");
        assert_eq!(split_segments("/a/b"), vec!["a", "b"]);
        assert_eq!(split_segments("/"), Vec::<&str>::new());
        assert_eq!(
            split_parent_name("/a/b/c.txt"),
            Some(("/a/b".to_string(), "c.txt".to_string()))
        );
        assert_eq!(
            split_parent_name("/top.txt"),
            Some(("/".to_string(), "top.txt".to_string()))
        );
        assert_eq!(split_parent_name("/"), None);
        assert_eq!(join_child("/", "x"), "/x");
        assert_eq!(join_child("/a", "x"), "/a/x");
    }
}
