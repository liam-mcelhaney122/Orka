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
use super::oauth;
use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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
/// OAuth scope requested for both the interactive sign-in and a
/// service-account JWT.
const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive";
/// Token endpoint a service-account key uses when its own JSON omits
/// `token_uri`, which every key Google issues today includes anyway.
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// Lifetime Google grants a service-account JWT-bearer token.
const SERVICE_ACCOUNT_TOKEN_LIFETIME_SECS: u64 = 3600;

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

/// The fields this backend needs from a Google service-account JSON
/// key file. The file carries other fields (`project_id`, `client_id`,
/// a key id); they are not needed to sign a JWT-bearer request.
#[derive(Debug)]
struct ServiceAccountKey {
    client_email: String,
    private_key_pem: String,
    token_uri: String,
}

/// Parses a service-account key file's content, which is the raw
/// keychain secret for [`AuthMethod::ServiceAccount`].
fn parse_service_account_key(raw: &str) -> Result<ServiceAccountKey, String> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| "service-account key is not valid JSON".to_string())?;
    let client_email = value
        .get("client_email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "service-account key is missing client_email".to_string())?
        .to_string();
    let private_key_pem = value
        .get("private_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "service-account key is missing private_key".to_string())?
        .to_string();
    let token_uri = value
        .get("token_uri")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_TOKEN_URI)
        .to_string();
    Ok(ServiceAccountKey {
        client_email,
        private_key_pem,
        token_uri,
    })
}

/// Encodes the JWT header and a claims JSON object as one base64url
/// signing-input string ("header.claims"), the exact bytes an RS256
/// signature covers.
fn jwt_signing_input(claims_json: &str) -> String {
    const HEADER_JSON: &str = r#"{"alg":"RS256","typ":"JWT"}"#;
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER_JSON),
        URL_SAFE_NO_PAD.encode(claims_json)
    )
}

/// Builds the claims object for a service-account JWT-bearer exchange.
fn jwt_claims_json(client_email: &str, scope: &str, token_uri: &str, issued_at: u64) -> String {
    serde_json::json!({
        "iss": client_email,
        "scope": scope,
        "aud": token_uri,
        "iat": issued_at,
        "exp": issued_at + SERVICE_ACCOUNT_TOKEN_LIFETIME_SECS,
    })
    .to_string()
}

/// Signs `data` with the service-account private key using RSASSA-PKCS1-v1_5
/// with SHA-256 (RS256). The key material never appears in the error:
/// a parse failure reports only that the key is not a valid PEM key.
fn sign_rs256(private_key_pem: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|_| "service-account private key is not a valid PKCS8 PEM key".to_string())?;
    let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
    let signature = signing_key
        .try_sign(data)
        .map_err(|_| "cannot sign the service-account JWT".to_string())?;
    Ok(signature.to_vec())
}

/// Builds and signs one JWT-bearer assertion for `key`, valid from
/// `now_secs` for [`SERVICE_ACCOUNT_TOKEN_LIFETIME_SECS`].
fn build_signed_jwt(key: &ServiceAccountKey, now_secs: u64) -> Result<String, String> {
    let claims = jwt_claims_json(&key.client_email, DRIVE_SCOPE, &key.token_uri, now_secs);
    let signing_input = jwt_signing_input(&claims);
    let signature = sign_rs256(&key.private_key_pem, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// Exchanges a signed JWT for an access token. Returns the token and
/// its lifetime in seconds, as reported by the token endpoint.
fn exchange_jwt_for_token(
    agent: &ureq::Agent,
    token_uri: &str,
    jwt: &str,
) -> Result<(String, u64), String> {
    let form = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", jwt),
    ];
    let response = agent
        .post(token_uri)
        .send_form(&form)
        .map_err(http::error_string)?;
    let value: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("service-account token response was not valid JSON: {e}"))?;
    let access_token = value
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "service-account token response is missing access_token".to_string())?
        .to_string();
    let expires_in = value
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(SERVICE_ACCOUNT_TOKEN_LIFETIME_SECS);
    Ok((access_token, expires_in))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One cached service-account access token.
struct CachedToken {
    access_token: String,
    expires_at_ms: u64,
}

/// This backend's access-token sources: everything [`oauth::TokenSource`]
/// covers (a pasted token or an OAuth app), plus a Google service
/// account, which signs its own short-lived JWTs instead of holding a
/// refresh token.
enum GdriveTokenSource {
    Shared(oauth::TokenSource),
    ServiceAccount {
        key: ServiceAccountKey,
        cached: Mutex<Option<CachedToken>>,
    },
}

impl GdriveTokenSource {
    /// A token for the next request. A service account only reaches
    /// the network when its cached token is close to expiry.
    fn token(&self, agent: &ureq::Agent) -> Result<String, String> {
        match self {
            GdriveTokenSource::Shared(source) => source.token(),
            GdriveTokenSource::ServiceAccount { key, cached } => {
                if let Some(existing) = cached.lock().unwrap().as_ref() {
                    if !oauth::needs_refresh(existing.expires_at_ms, now_ms()) {
                        return Ok(existing.access_token.clone());
                    }
                }
                mint_service_account_token(agent, key, cached)
            }
        }
    }

    /// A token for a retry after an HTTP 401. A service account drops
    /// its cache first, so this always signs and exchanges a fresh
    /// JWT rather than possibly repeating a token the server just
    /// rejected.
    fn refresh(&self, agent: &ureq::Agent) -> Result<String, String> {
        match self {
            GdriveTokenSource::Shared(source) => source.refresh(),
            GdriveTokenSource::ServiceAccount { key, cached } => {
                *cached.lock().unwrap() = None;
                mint_service_account_token(agent, key, cached)
            }
        }
    }
}

fn mint_service_account_token(
    agent: &ureq::Agent,
    key: &ServiceAccountKey,
    cached: &Mutex<Option<CachedToken>>,
) -> Result<String, String> {
    let now_secs = now_ms() / 1000;
    let jwt = build_signed_jwt(key, now_secs)?;
    let (access_token, expires_in) = exchange_jwt_for_token(agent, &key.token_uri, &jwt)?;
    let expires_at_ms = now_ms().saturating_add(expires_in.saturating_mul(1000));
    *cached.lock().unwrap() = Some(CachedToken {
        access_token: access_token.clone(),
        expires_at_ms,
    });
    Ok(access_token)
}

/// Bearer-token HTTP transport for one connection. Cloned into upload
/// hooks so a transfer never borrows the backend itself; the token
/// source is behind an `Arc` so that clone stays cheap.
#[derive(Clone)]
struct Transport {
    agent: ureq::Agent,
    tokens: Arc<GdriveTokenSource>,
}

impl Transport {
    /// Runs one Drive call, retrying once with a forced refresh when
    /// the first attempt fails with HTTP 401. `call` must build a
    /// fresh request on every invocation; `ureq` consumes a request
    /// builder on send, so the same builder cannot be reused for the
    /// retry.
    fn with_auth_retry<T>(
        &self,
        mut call: impl FnMut(&str) -> Result<T, ureq::Error>,
    ) -> Result<T, String> {
        let header = format!("Bearer {}", self.tokens.token(&self.agent)?);
        match call(&header) {
            Ok(value) => Ok(value),
            Err(ureq::Error::Status(401, _)) => {
                let header = format!("Bearer {}", self.tokens.refresh(&self.agent)?);
                call(&header).map_err(http::error_string)
            }
            Err(e) => Err(http::error_string(e)),
        }
    }

    /// Authenticated GET that returns the whole JSON body.
    fn get_json(&self, url: &str) -> Result<String, String> {
        let response = self.with_auth_retry(|header| {
            self.agent.get(url).set("Authorization", header).call()
        })?;
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
    /// the connection until the reader drains or drops. The 401 retry
    /// covers only opening the stream, not bytes already in flight.
    fn download(&self, id: &str) -> Result<Box<dyn Read + Send>, String> {
        let url = format!("{API_BASE}/files/{id}?alt=media");
        let response = self.with_auth_retry(|header| {
            self.agent.get(&url).set("Authorization", header).call()
        })?;
        Ok(http::response_reader(response))
    }

    /// Overwrites an existing file's content in place.
    fn patch_media(&self, id: &str, bytes: &[u8]) -> Result<(), String> {
        let url = format!("{UPLOAD_BASE}/files/{id}?uploadType=media");
        self.with_auth_retry(|header| {
            self.agent
                .patch(&url)
                .set("Authorization", header)
                .set("Content-Type", "application/octet-stream")
                .send(bytes)
        })?;
        Ok(())
    }

    /// Creates a new file with its content in one multipart request.
    fn post_multipart(&self, metadata_json: &str, bytes: &[u8]) -> Result<(), String> {
        let url = format!("{UPLOAD_BASE}/files?uploadType=multipart");
        let body = multipart_body(metadata_json, bytes);
        self.with_auth_retry(|header| {
            self.agent
                .post(&url)
                .set("Authorization", header)
                .set(
                    "Content-Type",
                    &format!("multipart/related; boundary={BOUNDARY}"),
                )
                .send(body.as_slice())
        })?;
        Ok(())
    }

    /// Creates one folder and returns its new id.
    fn create_folder(&self, name: &str, parent_id: &str) -> Result<String, String> {
        let url = format!("{API_BASE}/files");
        let body = serde_json::json!({
            "name": name,
            "mimeType": FOLDER_MIME,
            "parents": [parent_id],
        });
        let response = self.with_auth_retry(|header| {
            self.agent
                .post(&url)
                .set("Authorization", header)
                .send_json(body.clone())
        })?;
        let text = http::read_body_string(response);
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("invalid JSON from Drive: {e}"))?;
        value
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_string)
            .ok_or_else(|| "folder create response is missing id".to_string())
    }

    /// Trashes one file or folder. Drive deletes a folder's children
    /// server-side, so no client-side recursion is needed.
    fn delete_file(&self, id: &str) -> Result<(), String> {
        let url = format!("{API_BASE}/files/{id}");
        self.with_auth_retry(|header| {
            self.agent.delete(&url).set("Authorization", header).call()
        })?;
        Ok(())
    }

    /// Renames one item in place.
    fn rename_file(&self, id: &str, name: &str) -> Result<(), String> {
        let url = format!("{API_BASE}/files/{id}");
        let body = serde_json::json!({ "name": name });
        self.with_auth_retry(|header| {
            self.agent
                .patch(&url)
                .set("Authorization", header)
                .send_json(body.clone())
        })?;
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
        // Every auth path resolves and validates its secret before any
        // network call, so a bad config or a missing secret fails fast.
        let tokens = match &config.auth {
            AuthMethod::OAuthToken => {
                let token = secrets
                    .get_secret(&config.id)
                    .ok_or_else(|| "no access token stored for this connection".to_string())?;
                GdriveTokenSource::Shared(oauth::TokenSource::Fixed(token))
            }
            AuthMethod::OAuthApp { client_id, .. } => {
                let raw = secrets
                    .get_secret(&config.id)
                    .ok_or_else(|| "no token stored for this connection".to_string())?;
                // Fail on a malformed secret now rather than on the
                // first request.
                oauth::TokenSet::from_json(&raw)?;
                GdriveTokenSource::Shared(oauth::TokenSource::OAuthApp {
                    provider: oauth::Provider::Google,
                    client_id: client_id.clone(),
                    connection_id: config.id.clone(),
                    secrets,
                })
            }
            AuthMethod::ServiceAccount => {
                let raw = secrets.get_secret(&config.id).ok_or_else(|| {
                    "no service-account key stored for this connection".to_string()
                })?;
                let key = parse_service_account_key(&raw)?;
                GdriveTokenSource::ServiceAccount {
                    key,
                    cached: Mutex::new(None),
                }
            }
            _ => return Err("wrong auth method for gdrive".to_string()),
        };
        Ok(Arc::new(GdriveBackend {
            transport: Transport {
                agent: http::agent(),
                tokens: Arc::new(tokens),
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
    fn oauth_app_without_a_stored_secret_fails_before_any_network_call() {
        let mut cfg = config();
        cfg.auth = AuthMethod::OAuthApp {
            client_id: "client".to_string(),
            tenant_id: String::new(),
        };
        let err = GdriveFactory
            .connect(&cfg, Arc::new(NoSecrets))
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
        let mut cfg = config();
        cfg.auth = AuthMethod::OAuthApp {
            client_id: "client".to_string(),
            tenant_id: String::new(),
        };
        let err = GdriveFactory
            .connect(&cfg, Arc::new(BadSecret))
            .err()
            .expect("must fail");
        assert!(err.contains("cannot decode token set"), "got: {err}");
    }

    #[test]
    fn oauth_app_with_a_valid_secret_connects() {
        let set = oauth::TokenSet {
            access_token: "a".to_string(),
            refresh_token: Some("r".to_string()),
            expires_at_ms: now_ms() + 3_600_000,
            client_secret: None,
        };
        struct GoodSecret(String);
        impl SecretProvider for GoodSecret {
            fn get_secret(&self, _connection_id: &str) -> Option<String> {
                Some(self.0.clone())
            }
        }
        let mut cfg = config();
        cfg.auth = AuthMethod::OAuthApp {
            client_id: "client".to_string(),
            tenant_id: String::new(),
        };
        let backend = GdriveFactory
            .connect(&cfg, Arc::new(GoodSecret(set.to_json().unwrap())))
            .expect("must connect");
        assert!(!backend.capabilities().is_local);
    }

    #[test]
    fn service_account_without_a_stored_secret_fails_before_any_network_call() {
        let mut cfg = config();
        cfg.auth = AuthMethod::ServiceAccount;
        let err = GdriveFactory
            .connect(&cfg, Arc::new(NoSecrets))
            .err()
            .expect("must fail");
        assert!(err.contains("no service-account key"), "got: {err}");
    }

    #[test]
    fn service_account_with_malformed_json_fails_before_any_network_call() {
        struct BadSecret;
        impl SecretProvider for BadSecret {
            fn get_secret(&self, _connection_id: &str) -> Option<String> {
                Some("not json".to_string())
            }
        }
        let mut cfg = config();
        cfg.auth = AuthMethod::ServiceAccount;
        let err = GdriveFactory
            .connect(&cfg, Arc::new(BadSecret))
            .err()
            .expect("must fail");
        assert!(err.contains("not valid JSON"), "got: {err}");
    }

    #[test]
    fn service_account_key_missing_a_required_field_is_rejected() {
        let err = parse_service_account_key(r#"{"client_email":"a@b.com"}"#).unwrap_err();
        assert!(err.contains("private_key"), "got: {err}");
    }

    #[test]
    fn service_account_key_parses_required_and_default_fields() {
        let key = parse_service_account_key(
            r#"{"client_email":"svc@proj.iam.gserviceaccount.com","private_key":"PEM"}"#,
        )
        .unwrap();
        assert_eq!(key.client_email, "svc@proj.iam.gserviceaccount.com");
        assert_eq!(key.private_key_pem, "PEM");
        assert_eq!(key.token_uri, DEFAULT_TOKEN_URI);
    }

    #[test]
    fn jwt_signing_input_base64url_encodes_header_and_claims() {
        let claims = r#"{"iss":"a@b.com"}"#;
        let input = jwt_signing_input(claims);
        let (header_part, claims_part) = input.split_once('.').expect("must have one dot");
        assert!(!header_part.contains('='), "no padding: {header_part}");
        assert_eq!(
            URL_SAFE_NO_PAD.decode(header_part).unwrap(),
            br#"{"alg":"RS256","typ":"JWT"}"#
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(claims_part).unwrap(), claims.as_bytes());
    }

    #[test]
    fn jwt_claims_carry_the_drive_scope_and_a_one_hour_lifetime() {
        let json = jwt_claims_json("svc@proj.iam.gserviceaccount.com", DRIVE_SCOPE, DEFAULT_TOKEN_URI, 1_000);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["iss"], "svc@proj.iam.gserviceaccount.com");
        assert_eq!(value["scope"], DRIVE_SCOPE);
        assert_eq!(value["aud"], DEFAULT_TOKEN_URI);
        assert_eq!(value["iat"], 1_000);
        assert_eq!(value["exp"], 1_000 + SERVICE_ACCOUNT_TOKEN_LIFETIME_SECS);
    }

    #[test]
    fn signing_with_a_malformed_key_reports_no_key_material() {
        let err = sign_rs256("not a pem key", b"data").unwrap_err();
        assert!(err.contains("not a valid PKCS8 PEM key"), "got: {err}");
        assert!(!err.contains("not a pem key"), "must not echo the input: {err}");
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

    /// A throwaway 2048-bit RSA test key in PKCS8 PEM form. Generated
    /// once with `openssl genpkey`; used only to exercise parsing and
    /// signing, never to protect anything.
    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPcdg4RbbpbW/2\n\
guS1dvoZoIiGcvTUzEMCFXrTy1X8m9N33DAL4tqrFwmsxqsjr6qRzgaATe75mzVr\n\
SwK2K5ApFhxQF+rayUWkUOH68N9uaXIg4hLANbHJkDKtuZSVLD5IBm5VZdJg1X2C\n\
WjzUZjRhtoyOrjIiORJaEMzITOczvFgg3TNbkrS9zLdOu7X8HNYusKVomZO0AD96\n\
1Sk8t3V+E1+UcF2VYqOs4luqg2x4oI2Yqz0QXc1yqXrUveSZiJ6rPsd3aov/SxFC\n\
Q2rSuabuTlVzbfE3GXw4cjix1C9oyY27SUaDIFlypGwP+CL7+/kwxDPTSy2LBPxZ\n\
0RYxcqK5AgMBAAECggEAEP9Gf0yIXAr+rAeglBUku+8mkJb1uZk8+lGRPVkBTs/j\n\
yAPkyeyItzu4LA3L3azZ6yrNkeYQ09HkUsoUIEy5z1auSN+/e2AXfTWwC8mAZ9cV\n\
pgfFZTYLvwoPek2PlO4e8kmDRoBaeFsLIXWhsKjpLNfHdN9lYIl67UydbYy45Z5T\n\
eGdu227UrkjhZthae1yS7jB/6KzICTVWPyBOfKuyIQLGYdvikKNT0PgZNddePQKX\n\
fAdWsr+epORZ/ur8ZIZB0Xm7YZxrNWCljvTZ9G/o5Zq1baReNVk4shjJv+dMQ6Ng\n\
hhcRfPs3t4YvkepNdchgXS56hKeRefUJIE4c1bUlaQKBgQDqi6iWjM3A5oL3TI4h\n\
bYBE4uaYAe0EhoQxFCk6ZfdjA31NHbMAWqMXoub1xYM0jGf6lSNEsV1X2I4qmq+w\n\
OLEuqcqyv6mnGXCqHEAss4RiXypzeBPWjKKOF36RbmeWnwlgNWHl4E6iJC8Ofh6s\n\
Thx3FG9XU9OHJpGvJZPGxOZVjQKBgQDia5Eutisu8222ApZFqaXbo30J55UsV7Kj\n\
CqST7yBuK195k2MGrT3oj0AEDAzCwyyPjTy4578mx+XD5vYG8+JQi7qMrioqlS4h\n\
BgEJuwk/wFmuVZ+7F/NdTfjxzNFQw5ocTnRywfLCqD2dUhFuOJJbcctOHS0Iyi14\n\
srLV0R/o3QKBgQC1NOsuTWCVnUIn3+ybZOdJ0WfInwxIh8jPxjzIEolb5RFEqCJo\n\
rp38n+4CifOBgMzAq8KQyttMCFJmFhaQdmxlmeaxzSQ8pooF00e9gYBRJCc/CNGC\n\
3Cqmzv4JTBwaIYrz2qplGLSHzp7Qep4mDz8svQv8kxYE/8ZkZArU8cDm7QKBgDfr\n\
jS3WPBAaewwq02ZdIeN/G1Co64TKHAp8hG0s7/uFpszmA90QSGv5hTv6peQsRAMo\n\
RMj+I422bR7XGghZj5mJCQfZs/xUX9I0I2l90ij2nq+Z4htZLPfsXAGMLl4eER/Q\n\
mJ4HHKfK2XzTWg641hzTm/ys5AR5uoVGzThVr+XZAoGBALQ0qrMelwnhyd5izMlN\n\
EbzOIkzGPhCRCQCSYvyRY5n3nE/ogPg+6OhFM/hHd9xium4Ixol0GyqPqKxb2Cr5\n\
6VPR9vJ456pKSB1Q4BleNeP8WnjHY4PBDpRV225UWmcGB9vUccnzinJjsI6dVAcO\n\
aS9y8P0DQbTj67ERLsLTfd2M\n\
-----END PRIVATE KEY-----\n";

    fn sample_service_account_json() -> String {
        serde_json::json!({
            "type": "service_account",
            "project_id": "proj",
            "private_key_id": "kid1",
            "private_key": TEST_PRIVATE_KEY_PEM,
            "client_email": "svc@proj.iam.gserviceaccount.com",
            "client_id": "123",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string()
    }

    #[test]
    fn sign_rs256_produces_a_signature_the_public_key_verifies() {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;

        let signature_bytes = sign_rs256(TEST_PRIVATE_KEY_PEM, b"data-to-sign").unwrap();
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY_PEM).unwrap();
        let verifying_key: VerifyingKey<sha2::Sha256> =
            VerifyingKey::new(private_key.to_public_key());
        let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
        verifying_key
            .verify(b"data-to-sign", &signature)
            .expect("signature must verify against the matching public key");
    }

    #[test]
    fn build_signed_jwt_has_three_dot_separated_parts() {
        let key = parse_service_account_key(&sample_service_account_json()).unwrap();
        let jwt = build_signed_jwt(&key, 1_700_000_000).unwrap();
        assert_eq!(jwt.matches('.').count(), 2, "jwt: {jwt}");
    }

    #[test]
    fn service_account_with_a_valid_secret_connects() {
        struct GoodSecret(String);
        impl SecretProvider for GoodSecret {
            fn get_secret(&self, _connection_id: &str) -> Option<String> {
                Some(self.0.clone())
            }
        }
        let mut cfg = config();
        cfg.auth = AuthMethod::ServiceAccount;
        let backend = GdriveFactory
            .connect(&cfg, Arc::new(GoodSecret(sample_service_account_json())))
            .expect("a well-formed key must connect");
        // A parsed key connects without reaching the network; the JWT
        // is only signed and exchanged on the first real request.
        let _ = backend.capabilities();
    }
}
