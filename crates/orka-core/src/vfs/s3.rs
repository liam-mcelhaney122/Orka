//! S3 backend over hand-rolled AWS Signature Version 4 (SigV4) signing
//! and `ureq`.
//!
//! [`S3Factory`] validates the connection and resolves the access key
//! and secret key before any network call, so a bad config fails fast.
//! [`S3Backend`] signs every request with SigV4 the way [`super::adls`]
//! signs Blob SharedKey requests: pure functions build the canonical
//! request and the string to sign, so the signing steps are testable
//! without a server.
//!
//! One S3 "connection" is one set of credentials against one endpoint
//! host; the bucket comes from the backend-local path, not from the
//! connection. `s3://media/bucket/key` resolves to connection `media`
//! and backend-local path `/bucket/key`, so [`split_bucket_key`] is the
//! seam that turns that path into a bucket name and an object key on
//! every call.
//!
//! S3 has no real directories. Listing emulates them the way every S3
//! GUI client does: `ListObjectsV2` with `delimiter=/` turns
//! `CommonPrefixes` into virtual folders. `mkdir` creates a zero-byte
//! object whose key ends in `/`, the common "folder marker" convention.
//!
//! Known v1 limitations (see the module's design brief):
//! - No multipart upload. `create_write` buffers the whole object in
//!   memory and issues one `PutObject` on `finish`, so very large
//!   uploads can exhaust memory. A future milestone can add multipart
//!   for files over some threshold.
//! - No region field in the UI. The region is derived from `host`
//!   (`s3.<region>.amazonaws.com` or bare `s3.amazonaws.com` maps to
//!   that region; a legacy `s3-<region>.amazonaws.com` host is also
//!   accepted; anything else, including third-party endpoints, uses
//!   `us-east-1`, which most S3-compatible services accept regardless
//!   of their real location).
//! - Requests use path-style addressing (`https://host/bucket/key`)
//!   rather than virtual-hosted-style (`https://bucket.host/key`).
//!   Path-style works against every S3-compatible provider and against
//!   most AWS regions; a small number of newer AWS regions require
//!   virtual-hosted-style, which is out of scope for this milestone.
//! - `rename` has no atomic primitive in the S3 API. A single object
//!   renames as `CopyObject` then `DeleteObject`; a "folder" renames by
//!   copying every object under the source prefix, then deleting each
//!   source key. A crash midway leaves both the source and a partial
//!   destination; `can_rename` is still reported `true` because the
//!   operation is a normal, everyday one, matching how the other
//!   backends treat rename as a capability the UI exposes with a
//!   best-effort implementation underneath (`sftp`'s remote `cp`,
//!   `adls`'s single REST rename) even though only ADLS's is atomic.
//! - `delete` maps directly onto `DeleteObject`, which S3 treats as
//!   idempotent: deleting an absent key returns success rather than an
//!   error. This backend does not add a not-found check in front of
//!   it, so deleting something that was never there is a silent no-op,
//!   matching real S3 behavior instead of emulating POSIX semantics.
//! - Recursive delete and folder rename list every key under the
//!   prefix and act on each one individually (no `DeleteObjects`
//!   batch call), so a very large folder is slower than it needs to be
//!   but is still correct.
//! - S3 object keys are opaque strings, not filesystem paths, so a key
//!   containing a literal `.` or `..` segment is a perfectly valid
//!   object name to S3. But the HTTP client normalizes `/a/../b` to
//!   `/b` in the URL it puts on the wire, after this backend has
//!   already signed `/a/../b` — a mismatch that SigV4 rejects, or
//!   worse, one that could silently act on the wrong key if it happened
//!   to match. [`S3Core::canonical_uri`] escapes a `.` or `..` segment
//!   as `%2E`/`%2E%2E` so the signed path and the wire path are always
//!   the same string.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use super::http::{agent, error_string, parse_rfc1123_to_ms, parse_rfc3339_to_ms, response_reader, url_encode};
use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};

/// AWS service name signed into every request's credential scope.
const SERVICE: &str = "s3";

/// Creates S3 backends. Registered once for the `s3` scheme.
pub struct S3Factory;

impl BackendFactory for S3Factory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        let core = build_core(config, secrets.as_ref())?;
        Ok(Arc::new(S3Backend {
            core: Arc::new(core),
        }))
    }
}

/// Validates the config and resolves the access key and secret key.
/// Everything that can fail without the network fails here, before
/// any request.
fn build_core(config: &ConnectionConfig, secrets: &dyn SecretProvider) -> Result<S3Core, String> {
    if config.host.is_empty() {
        return Err(
            "s3 host is empty; use the endpoint host, for example s3.amazonaws.com".to_string(),
        );
    }
    if config.host.contains("://") {
        return Err(
            "s3 host must not contain a scheme; use the endpoint host, for example s3.amazonaws.com"
                .to_string(),
        );
    }
    let (access_key, secret_key) = match &config.auth {
        AuthMethod::S3Keys => {
            if config.username.is_empty() {
                return Err("s3 username is empty; it must be the access key id".to_string());
            }
            let secret = secrets
                .get_secret(&config.id)
                .ok_or_else(|| "no secret access key stored for this connection".to_string())?;
            (config.username.clone(), secret)
        }
        AuthMethod::S3Profile { profile } => load_profile(profile)?,
        _ => return Err("wrong auth method for s3".to_string()),
    };
    let port = if config.port == 0 {
        443
    } else {
        u16::try_from(config.port).map_err(|_| format!("invalid port {}", config.port))?
    };
    Ok(S3Core {
        agent: agent(),
        host: config.host.clone(),
        port,
        region: region_from_host(&config.host),
        access_key,
        secret_key,
    })
}

/// Derives the AWS region from the endpoint host. Recognizes the
/// current `s3.<region>.amazonaws.com` form, the bare
/// `s3.amazonaws.com` (`us-east-1`), and the legacy
/// `s3-<region>.amazonaws.com` form. Anything else, including a
/// third-party endpoint, defaults to `us-east-1`, which most
/// S3-compatible services accept regardless of where they run. There
/// is no region field in the connection config to override this; see
/// the module doc comment.
fn region_from_host(host: &str) -> String {
    if host == "s3.amazonaws.com" {
        return "us-east-1".to_string();
    }
    if let Some(region) = host
        .strip_prefix("s3.")
        .and_then(|s| s.strip_suffix(".amazonaws.com"))
    {
        if !region.is_empty() {
            return region.to_string();
        }
    }
    if let Some(region) = host
        .strip_prefix("s3-")
        .and_then(|s| s.strip_suffix(".amazonaws.com"))
    {
        if !region.is_empty() {
            return region.to_string();
        }
    }
    "us-east-1".to_string()
}

/// Splits a backend-local path into its bucket and object key. The
/// first path segment is the bucket; the rest, including any internal
/// slashes, is the key or prefix as-is. The empty path and `/` are the
/// account root: no bucket, no key.
fn split_bucket_key(path: &str) -> (String, String) {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return (String::new(), String::new());
    }
    match trimmed.split_once('/') {
        Some((bucket, key)) => (bucket.to_string(), key.to_string()),
        None => (trimmed.to_string(), String::new()),
    }
}

/// Locates AWS access keys for a named profile. Checks
/// `~/.aws/credentials` first (section named exactly `profile`), then
/// falls back to `~/.aws/config` (section `[profile <name>]`, or
/// `[default]` for the default profile), matching the standard AWS
/// SDK file layout. No secret from the keychain is involved for this
/// auth method.
fn load_profile(profile: &str) -> Result<(String, String), String> {
    load_profile_from_dir(profile, &aws_dir()?)
}

/// [`load_profile`] with the `~/.aws` directory passed in, so tests can
/// point it at a fixture directory instead of mutating the process-wide
/// `HOME` environment variable — which would race with any other test
/// in this binary that reads `HOME`, since Rust runs unit tests on
/// parallel threads within one process.
fn load_profile_from_dir(profile: &str, dir: &Path) -> Result<(String, String), String> {
    if let Some(section) = read_ini_section(&dir.join("credentials"), profile) {
        if let Some(pair) = keys_from_section(&section) {
            return Ok(pair);
        }
    }
    let config_section = if profile == "default" {
        "default".to_string()
    } else {
        format!("profile {profile}")
    };
    if let Some(section) = read_ini_section(&dir.join("config"), &config_section) {
        if let Some(pair) = keys_from_section(&section) {
            return Ok(pair);
        }
    }
    Err(format!("no credentials found for AWS profile '{profile}'"))
}

fn keys_from_section(section: &HashMap<String, String>) -> Option<(String, String)> {
    let id = section.get("aws_access_key_id")?.clone();
    let secret = section.get("aws_secret_access_key")?.clone();
    Some((id, secret))
}

fn aws_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".aws"))
}

fn read_ini_section(path: &Path, section_name: &str) -> Option<HashMap<String, String>> {
    let contents = std::fs::read_to_string(path).ok()?;
    parse_ini_section(&contents, section_name)
}

/// Parses one named section out of an AWS-style INI file. Pure, so
/// tests cover it without touching the filesystem.
fn parse_ini_section(contents: &str, section_name: &str) -> Option<HashMap<String, String>> {
    let mut in_section = false;
    let mut map = HashMap::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_section = name.trim().eq_ignore_ascii_case(section_name);
            continue;
        }
        if in_section {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(
                    key.trim().to_ascii_lowercase(),
                    value.trim().to_string(),
                );
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// The HTTP verbs this backend needs.
#[derive(Clone, Copy)]
enum Method {
    Get,
    Head,
    Put,
    Delete,
}

impl Method {
    fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

/// Shared signing and HTTP state for one connection. The secret key
/// never leaves this struct and never appears in an error string.
struct S3Core {
    agent: ureq::Agent,
    host: String,
    port: u16,
    region: String,
    access_key: String,
    secret_key: String,
}

impl S3Core {
    fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn base_url(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }

    /// Percent-encodes one path segment. A segment that is exactly `.`
    /// or `..` is escaped to `%2E`/`%2E%2E` instead of being passed
    /// through literally: an HTTP client normalizes a syntactic dot
    /// segment out of the URL path before putting it on the wire, but
    /// it leaves an escaped `%2E` alone, so this is what keeps the
    /// signed path and the wire path identical for a key that contains
    /// a literal `.`/`..` component.
    fn encode_uri_segment(segment: &str) -> String {
        match segment {
            "." => "%2E".to_string(),
            ".." => "%2E%2E".to_string(),
            other => url_encode(other),
        }
    }

    /// The request path for path-style addressing: `/` at the account
    /// root, `/{bucket}` with no key, `/{bucket}/{key}` otherwise. Each
    /// path segment is percent-encoded on its own so `/` inside the key
    /// stays a separator, the same split-then-encode approach
    /// [`super::adls`] uses for its request paths.
    fn canonical_uri(bucket: &str, key: &str) -> String {
        if bucket.is_empty() {
            return "/".to_string();
        }
        let mut path = format!("/{}", Self::encode_uri_segment(bucket));
        if !key.is_empty() {
            let encoded_key = key
                .split('/')
                .map(Self::encode_uri_segment)
                .collect::<Vec<_>>()
                .join("/");
            path.push('/');
            path.push_str(&encoded_key);
        }
        path
    }

    /// Sends one SigV4-signed request. `extra_headers` are added to
    /// both the wire request and the signature; `host`,
    /// `x-amz-content-sha256`, and `x-amz-date` are always added and
    /// always signed.
    fn request(
        &self,
        method: Method,
        bucket: &str,
        key: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, String)],
        body: Option<&[u8]>,
    ) -> Result<ureq::Response, Box<ureq::Error>> {
        let uri = Self::canonical_uri(bucket, key);
        let query_string = canonical_query_string(query);
        let url = if query_string.is_empty() {
            format!("{}{}", self.base_url(), uri)
        } else {
            format!("{}{}?{}", self.base_url(), uri, query_string)
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let (amz_date, date_stamp) = amz_datetime(now_ms);
        let payload_hash = sha256_hex(body.unwrap_or(&[]));
        let mut headers: Vec<(String, String)> = vec![
            ("host".to_string(), self.host_header()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        for (name, value) in extra_headers {
            headers.push((name.to_string(), value.clone()));
        }
        let (canonical_headers_block, signed_headers) = canonical_headers(&headers);
        let creq = canonical_request(
            method.as_str(),
            &uri,
            &query_string,
            &canonical_headers_block,
            &signed_headers,
            &payload_hash,
        );
        let credential_scope = format!("{date_stamp}/{}/{SERVICE}/aws4_request", self.region);
        let sts = string_to_sign(&amz_date, &credential_scope, &creq);
        let key_bytes = signing_key(&self.secret_key, &date_stamp, &self.region, SERVICE);
        let signature = hex_encode(&hmac_sha256(&key_bytes, sts.as_bytes()));
        let auth = authorization_header(
            &self.access_key,
            &date_stamp,
            &self.region,
            SERVICE,
            &signed_headers,
            &signature,
        );
        let mut req = match method {
            Method::Get => self.agent.get(&url),
            Method::Head => self.agent.head(&url),
            Method::Put => self.agent.put(&url),
            Method::Delete => self.agent.delete(&url),
        };
        for (name, value) in &headers {
            // ureq sets Host from the URL; it is signed but never set
            // explicitly here.
            if name == "host" {
                continue;
            }
            req = req.set(name, value);
        }
        req = req.set("Authorization", &auth);
        match body {
            Some(bytes) => req.send_bytes(bytes).map_err(Box::new),
            None => req.call().map_err(Box::new),
        }
    }

    fn list_buckets(&self) -> Result<Vec<Entry>, String> {
        let response = self
            .request(Method::Get, "", "", &[], &[], None)
            .map_err(|e| request_error("cannot list", "buckets", *e))?;
        let body = read_body(response)?;
        Ok(parse_list_buckets(&body)
            .into_iter()
            .map(|b| Entry {
                is_hidden: b.name.starts_with('.'),
                path: format!("/{}", b.name),
                name: b.name,
                is_dir: true,
                size: 0,
                modified_ms: b.creation_ms,
                is_symlink: false,
            })
            .collect())
    }

    /// Lists direct children of `prefix` in `bucket` using
    /// `delimiter=/`, so `CommonPrefixes` become virtual folders. Skips
    /// the exact-prefix object itself, the folder-marker convention's
    /// zero-byte object, so it never shows up as a same-named file.
    fn list_objects(&self, bucket: &str, prefix: &str) -> Result<Vec<Entry>, String> {
        let mut entries = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("delimiter".to_string(), "/".to_string()),
            ];
            if !prefix.is_empty() {
                query.push(("prefix".to_string(), prefix.to_string()));
            }
            if let Some(token) = &continuation {
                query.push(("continuation-token".to_string(), token.clone()));
            }
            let response = self
                .request(Method::Get, bucket, "", &query, &[], None)
                .map_err(|e| request_error("cannot list", bucket, *e))?;
            let body = read_body(response)?;
            let page = parse_list_objects(&body);
            for common_prefix in &page.common_prefixes {
                let name = common_prefix
                    .strip_prefix(prefix)
                    .unwrap_or(common_prefix)
                    .trim_end_matches('/')
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                entries.push(Entry {
                    is_hidden: name.starts_with('.'),
                    name,
                    path: format!("/{bucket}/{}", common_prefix.trim_end_matches('/')),
                    is_dir: true,
                    size: 0,
                    modified_ms: 0,
                    is_symlink: false,
                });
            }
            for (key, size, modified_ms) in &page.contents {
                if key == prefix {
                    continue;
                }
                let name = key.strip_prefix(prefix).unwrap_or(key).to_string();
                if name.is_empty() {
                    continue;
                }
                entries.push(Entry {
                    is_hidden: name.starts_with('.'),
                    name,
                    path: format!("/{bucket}/{key}"),
                    is_dir: false,
                    size: *size,
                    modified_ms: *modified_ms,
                    is_symlink: false,
                });
            }
            match page.next_continuation_token {
                Some(token) if !token.is_empty() => continuation = Some(token),
                _ => return Ok(entries),
            }
        }
    }

    /// Lists every key under `prefix`, at any depth (no delimiter).
    /// Used by recursive delete and folder rename.
    fn list_all_keys(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, String> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut query = vec![("list-type".to_string(), "2".to_string())];
            if !prefix.is_empty() {
                query.push(("prefix".to_string(), prefix.to_string()));
            }
            if let Some(token) = &continuation {
                query.push(("continuation-token".to_string(), token.clone()));
            }
            let response = self
                .request(Method::Get, bucket, "", &query, &[], None)
                .map_err(|e| request_error("cannot list", bucket, *e))?;
            let body = read_body(response)?;
            let page = parse_list_objects(&body);
            keys.extend(page.contents.into_iter().map(|(k, _, _)| k));
            match page.next_continuation_token {
                Some(token) if !token.is_empty() => continuation = Some(token),
                _ => return Ok(keys),
            }
        }
    }

    /// `Some((size, modified_ms))` when the object exists; `None` on a
    /// 404, since callers use that to fall back to a directory check.
    fn head_object(&self, bucket: &str, key: &str) -> Result<Option<(u64, i64)>, String> {
        match self.request(Method::Head, bucket, key, &[], &[], None) {
            Ok(response) => {
                let size = response
                    .header("Content-Length")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let modified_ms = response
                    .header("Last-Modified")
                    .and_then(parse_rfc1123_to_ms)
                    .unwrap_or(0);
                Ok(Some((size, modified_ms)))
            }
            Err(boxed) => match *boxed {
                ureq::Error::Status(404, _) => Ok(None),
                e => Err(format!("cannot stat {bucket}/{key}: {}", error_string(e))),
            },
        }
    }

    fn head_bucket(&self, bucket: &str) -> Result<(), String> {
        self.request(Method::Head, bucket, "", &[], &[], None)
            .map(|_| ())
            .map_err(|e| request_error("cannot stat", bucket, *e))
    }

    /// True when at least one object exists under `prefix`. Used to
    /// tell a virtual folder from a path that does not exist at all.
    fn prefix_exists(&self, bucket: &str, prefix: &str) -> Result<bool, String> {
        let query = vec![
            ("list-type".to_string(), "2".to_string()),
            ("prefix".to_string(), prefix.to_string()),
            ("max-keys".to_string(), "1".to_string()),
        ];
        let response = self
            .request(Method::Get, bucket, "", &query, &[], None)
            .map_err(|e| request_error("cannot list", bucket, *e))?;
        let body = read_body(response)?;
        Ok(!parse_list_objects(&body).contents.is_empty())
    }

    fn put_object(&self, bucket: &str, key: &str, body: &[u8]) -> Result<(), String> {
        self.request(Method::Put, bucket, key, &[], &[], Some(body))
            .map(|_| ())
            .map_err(|e| request_error("cannot write", &format!("{bucket}/{key}"), *e))
    }

    /// Deletes one object. S3 treats `DeleteObject` on a missing key as
    /// success, so this never reports "not found"; see the module doc
    /// comment.
    fn delete_object(&self, bucket: &str, key: &str) -> Result<(), String> {
        self.request(Method::Delete, bucket, key, &[], &[], None)
            .map(|_| ())
            .map_err(|e| request_error("cannot delete", &format!("{bucket}/{key}"), *e))
    }

    /// Server-side copy within the same account. Works across buckets
    /// as long as both are reachable with these credentials.
    fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<(), String> {
        let encoded_key = src_key
            .split('/')
            .map(url_encode)
            .collect::<Vec<_>>()
            .join("/");
        let source = format!("/{}/{encoded_key}", url_encode(src_bucket));
        let extra_headers = [("x-amz-copy-source", source)];
        self.request(Method::Put, dst_bucket, dst_key, &[], &extra_headers, None)
            .map(|_| ())
            .map_err(|e| request_error("cannot copy", &format!("{src_bucket}/{src_key}"), *e))
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

fn read_body(response: ureq::Response) -> Result<String, String> {
    let mut body = String::new();
    response
        .into_reader()
        .read_to_string(&mut body)
        .map_err(|e| format!("cannot read response: {e}"))?;
    Ok(body)
}

/// One live S3 connection. Every call signs its own request, so calls
/// can run concurrently on the shared agent.
pub struct S3Backend {
    core: Arc<S3Core>,
}

impl FsBackend for S3Backend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            is_local: false,
            can_trash: false,
            can_watch: false,
            // Not atomic: implemented as copy-then-delete. See the
            // module doc comment for the rationale.
            can_rename: true,
            server_side_copy: true,
            preserves_permissions: false,
        }
    }

    fn list_dir(&self, path: &str, opts: &ListOptions) -> Result<Vec<Entry>, String> {
        let (bucket, prefix) = split_bucket_key(path);
        let mut entries = if bucket.is_empty() {
            self.core.list_buckets()?
        } else {
            self.core.list_objects(&bucket, &prefix)?
        };
        if !opts.include_hidden {
            entries.retain(|e| !e.is_hidden);
        }
        if opts.dirs_only {
            entries.retain(|e| e.is_dir);
        }
        crate::sort_entries(&mut entries);
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let (bucket, key) = split_bucket_key(path);
        if bucket.is_empty() {
            return Err("cannot stat the S3 account root".to_string());
        }
        if key.is_empty() {
            self.core.head_bucket(&bucket)?;
            return Ok(Entry {
                is_hidden: bucket.starts_with('.'),
                path: format!("/{bucket}"),
                name: bucket,
                is_dir: true,
                size: 0,
                modified_ms: 0,
                is_symlink: false,
            });
        }
        let exact = key.trim_end_matches('/');
        let name = exact.rsplit('/').next().unwrap_or(exact).to_string();
        if let Some((size, modified_ms)) = self.core.head_object(&bucket, exact)? {
            return Ok(Entry {
                is_hidden: name.starts_with('.'),
                name,
                path: format!("/{bucket}/{exact}"),
                is_dir: false,
                size,
                modified_ms,
                is_symlink: false,
            });
        }
        let dir_prefix = format!("{exact}/");
        if self.core.prefix_exists(&bucket, &dir_prefix)? {
            return Ok(Entry {
                is_hidden: name.starts_with('.'),
                name,
                path: format!("/{bucket}/{exact}"),
                is_dir: true,
                size: 0,
                modified_ms: 0,
                is_symlink: false,
            });
        }
        Err(format!("{path}: not found"))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        let (bucket, key) = split_bucket_key(path);
        if bucket.is_empty() || key.trim_end_matches('/').is_empty() {
            return Err(format!("{path}: not a file"));
        }
        let response = self
            .core
            .request(Method::Get, &bucket, key.trim_end_matches('/'), &[], &[], None)
            .map_err(|e| request_error("cannot open", path, *e))?;
        Ok(response_reader(response))
    }

    fn create_write(
        &self,
        path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        let (bucket, key) = split_bucket_key(path);
        let exact = key.trim_end_matches('/');
        if bucket.is_empty() || exact.is_empty() {
            return Err(format!("{path}: cannot write here"));
        }
        Ok(Box::new(S3Writer {
            core: self.core.clone(),
            bucket,
            key: exact.to_string(),
            buffer: Vec::new(),
            finished: false,
        }))
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let (bucket, key) = split_bucket_key(path);
        if bucket.is_empty() {
            return Err("cannot delete the S3 account root".to_string());
        }
        let exact = key.trim_end_matches('/');
        if exact.is_empty() {
            return Err("cannot delete a bucket; remove its objects individually".to_string());
        }
        if recursive {
            let prefix = format!("{exact}/");
            for child_key in self.core.list_all_keys(&bucket, &prefix)? {
                self.core.delete_object(&bucket, &child_key)?;
            }
        }
        // Also removes a plain file or a lone folder-marker object.
        // See the module doc comment on S3's idempotent delete.
        self.core.delete_object(&bucket, exact)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let (src_bucket, src_key) = split_bucket_key(from);
        let (dst_bucket, dst_key) = split_bucket_key(to);
        if src_bucket.is_empty() || dst_bucket.is_empty() {
            return Err("cannot rename the S3 account root".to_string());
        }
        let src_exact = src_key.trim_end_matches('/');
        let dst_exact = dst_key.trim_end_matches('/');
        if src_exact.is_empty() || dst_exact.is_empty() {
            return Err("cannot rename a bucket".to_string());
        }
        match self
            .core
            .copy_object(&src_bucket, src_exact, &dst_bucket, dst_exact)
        {
            Ok(()) => return self.core.delete_object(&src_bucket, src_exact),
            Err(e) if e.contains("not found") => {}
            Err(e) => return Err(e),
        }
        // The source was not a single object; try it as a folder.
        let src_prefix = format!("{src_exact}/");
        let dst_prefix = format!("{dst_exact}/");
        let keys = self.core.list_all_keys(&src_bucket, &src_prefix)?;
        if keys.is_empty() {
            return Err(format!("{from}: not found"));
        }
        for key in &keys {
            let suffix = key.strip_prefix(&src_prefix).unwrap_or(key);
            let dest_key = format!("{dst_prefix}{suffix}");
            self.core
                .copy_object(&src_bucket, key, &dst_bucket, &dest_key)?;
        }
        for key in &keys {
            self.core.delete_object(&src_bucket, key)?;
        }
        Ok(())
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let (bucket, key) = split_bucket_key(path);
        if bucket.is_empty() {
            return Err("cannot create the S3 account root".to_string());
        }
        let exact = key.trim_end_matches('/');
        if exact.is_empty() {
            return Err("cannot create a bucket from a folder path; add it as its own connection".to_string());
        }
        self.core.put_object(&bucket, &format!("{exact}/"), &[])
    }

    /// A single-object server-side copy via `CopyObject`. Bucket-level
    /// paths fall through to `None` so the caller's own error handling
    /// applies.
    fn copy_native(&self, from: &str, to: &str) -> Option<Result<(), String>> {
        let (src_bucket, src_key) = split_bucket_key(from);
        let (dst_bucket, dst_key) = split_bucket_key(to);
        let src_exact = src_key.trim_end_matches('/');
        let dst_exact = dst_key.trim_end_matches('/');
        if src_bucket.is_empty() || dst_bucket.is_empty() || src_exact.is_empty() || dst_exact.is_empty() {
            return None;
        }
        Some(
            self.core
                .copy_object(&src_bucket, src_exact, &dst_bucket, dst_exact),
        )
    }
}

/// Buffers a whole object in memory and issues one `PutObject` when
/// the write finishes. No multipart; see the module doc comment.
struct S3Writer {
    core: Arc<S3Core>,
    bucket: String,
    key: String,
    buffer: Vec<u8>,
    finished: bool,
}

impl S3Writer {
    fn finish_inner(&mut self) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        self.core.put_object(&self.bucket, &self.key, &self.buffer)
    }
}

impl std::io::Write for S3Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl WriteFinish for S3Writer {
    fn finish(mut self: Box<Self>) -> Result<(), String> {
        self.finish_inner()
    }
}

impl Drop for S3Writer {
    /// Best-effort backstop for an abandoned writer, matching the
    /// other backends' `Drop` behavior: closing without an explicit
    /// `finish` still uploads. Callers that need the result must use
    /// [`WriteFinish::finish`].
    fn drop(&mut self) {
        let _ = self.finish_inner();
    }
}

// --- SigV4 signing (pure functions; see the tests below) -----------

/// Percent-encodes and sorts query parameters into the canonical query
/// string. AWS sorts by the encoded key; every key this backend sends
/// is a plain ASCII identifier, so sorting the raw keys gives the same
/// order as sorting the encoded ones.
fn canonical_query_string(params: &[(String, String)]) -> String {
    let mut sorted: Vec<(String, String)> = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Lowercases, trims, and sorts headers into the SigV4 canonical form:
/// one `name:value\n` line per header, plus the `;`-joined signed
/// header name list.
fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical = sorted
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect::<String>();
    let signed = sorted
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    (canonical, signed)
}

/// Builds the SigV4 canonical request: method, URI, query string,
/// canonical headers, signed header list, and the payload hash, each
/// on its own line.
fn canonical_request(
    method: &str,
    uri: &str,
    query_string: &str,
    canonical_headers: &str,
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    format!("{method}\n{uri}\n{query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}")
}

/// Builds the SigV4 string to sign from the canonical request's hash.
fn string_to_sign(amz_date: &str, credential_scope: &str, canonical_request: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

/// Derives the SigV4 signing key through the date/region/service/
/// request chain of HMACs.
fn signing_key(secret_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn authorization_header(
    access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
    signed_headers: &str,
    signature_hex: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{date_stamp}/{region}/{service}/aws4_request, \
         SignedHeaders={signed_headers}, Signature={signature_hex}"
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `x-amz-date` (`YYYYMMDDTHHMMSSZ`) and the date stamp (`YYYYMMDD`)
/// for the current UTC time, from milliseconds since the Unix epoch.
fn amz_datetime(unix_ms: i64) -> (String, String) {
    let secs = unix_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let amz_date = format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    );
    let date_stamp = format!("{year:04}{month:02}{day:02}");
    (amz_date, date_stamp)
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

// --- Minimal XML reading for the ListBuckets/ListObjectsV2 shapes ---
//
// S3 speaks XML, not JSON, and this codebase has no XML crate. Rather
// than take on a new dependency for a handful of always-leaf fields
// (Name, Key, Size, LastModified, Prefix, NextContinuationToken), this
// scans for `<tag>...</tag>` text directly, matching how AWS actually
// shapes these specific responses. It is not a general XML parser.

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Text between the first `<tag>` and the next `</tag>`, unescaped.
fn extract_first(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml_unescape(&xml[start..end]))
}

/// Inner content of every non-overlapping `<tag>...</tag>` occurrence,
/// scanned left to right. Used for repeated elements like `<Contents>`
/// and `<CommonPrefixes>`.
fn extract_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start_rel) = rest.find(&open) {
        let after_open = &rest[start_rel + open.len()..];
        match after_open.find(&close) {
            Some(end_rel) => {
                out.push(&after_open[..end_rel]);
                rest = &after_open[end_rel + close.len()..];
            }
            None => break,
        }
    }
    out
}

struct BucketEntry {
    name: String,
    creation_ms: i64,
}

fn parse_list_buckets(xml: &str) -> Vec<BucketEntry> {
    extract_blocks(xml, "Bucket")
        .iter()
        .filter_map(|block| {
            let name = extract_first(block, "Name")?;
            let creation_ms = extract_first(block, "CreationDate")
                .and_then(|s| parse_rfc3339_to_ms(&s))
                .unwrap_or(0);
            Some(BucketEntry { name, creation_ms })
        })
        .collect()
}

struct ObjectPage {
    contents: Vec<(String, u64, i64)>,
    common_prefixes: Vec<String>,
    next_continuation_token: Option<String>,
}

fn parse_list_objects(xml: &str) -> ObjectPage {
    let contents = extract_blocks(xml, "Contents")
        .iter()
        .filter_map(|block| {
            let key = extract_first(block, "Key")?;
            let size = extract_first(block, "Size")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let modified_ms = extract_first(block, "LastModified")
                .and_then(|s| parse_rfc3339_to_ms(&s))
                .unwrap_or(0);
            Some((key, size, modified_ms))
        })
        .collect();
    let common_prefixes = extract_blocks(xml, "CommonPrefixes")
        .iter()
        .filter_map(|block| extract_first(block, "Prefix"))
        .collect();
    let next_continuation_token = extract_first(xml, "NextContinuationToken");
    ObjectPage {
        contents,
        common_prefixes,
        next_continuation_token,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{join_uri, Scheme, VPath};

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
            scheme: Scheme::S3,
            host: "s3.amazonaws.com".to_string(),
            port: 443,
            username: "AKIDEXAMPLE".to_string(),
            initial_path: "/".to_string(),
            auth,
        }
    }

    // --- bucket/key path parsing ------------------------------------

    #[test]
    fn split_bucket_key_handles_root_and_bucket_only() {
        assert_eq!(split_bucket_key(""), (String::new(), String::new()));
        assert_eq!(split_bucket_key("/"), (String::new(), String::new()));
        assert_eq!(
            split_bucket_key("/bucket"),
            ("bucket".to_string(), String::new())
        );
    }

    #[test]
    fn split_bucket_key_handles_trailing_slash_on_bucket() {
        assert_eq!(
            split_bucket_key("/bucket/"),
            ("bucket".to_string(), String::new())
        );
    }

    #[test]
    fn split_bucket_key_handles_simple_key() {
        assert_eq!(
            split_bucket_key("/bucket/key"),
            ("bucket".to_string(), "key".to_string())
        );
    }

    #[test]
    fn split_bucket_key_preserves_internal_slashes_and_deep_nesting() {
        assert_eq!(
            split_bucket_key("/bucket/a/b/c"),
            ("bucket".to_string(), "a/b/c".to_string())
        );
        assert_eq!(
            split_bucket_key("/bucket/dir/"),
            ("bucket".to_string(), "dir/".to_string())
        );
    }

    #[test]
    fn split_bucket_key_without_leading_slash() {
        // join_uri repairs a missing leading slash before this ever
        // sees a path, but the parser stays defensive.
        assert_eq!(
            split_bucket_key("bucket/key"),
            ("bucket".to_string(), "key".to_string())
        );
    }

    // --- region-from-host derivation ---------------------------------

    #[test]
    fn region_from_host_matches_standard_aws_forms() {
        assert_eq!(region_from_host("s3.amazonaws.com"), "us-east-1");
        assert_eq!(region_from_host("s3.eu-west-1.amazonaws.com"), "eu-west-1");
        assert_eq!(
            region_from_host("s3.ap-southeast-2.amazonaws.com"),
            "ap-southeast-2"
        );
        // Legacy hyphenated regional form.
        assert_eq!(region_from_host("s3-us-west-2.amazonaws.com"), "us-west-2");
    }

    #[test]
    fn region_from_host_defaults_for_custom_endpoints() {
        assert_eq!(region_from_host("minio.example.com"), "us-east-1");
        assert_eq!(
            region_from_host("nyc3.digitaloceanspaces.com"),
            "us-east-1"
        );
        assert_eq!(region_from_host(""), "us-east-1");
    }

    // --- SigV4 pure-function signing ----------------------------------

    /// RFC 4231 test case 2: key "Jefe", message
    /// "what do ya want for nothing?". Reused from adls.rs's approach
    /// of testing the HMAC primitive against a published vector.
    #[test]
    fn hmac_matches_published_vector() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(hex_encode(&hmac_sha256(key, message)), expected);
    }

    /// NIST's published SHA-256 test vectors for the empty string and
    /// "abc".
    #[test]
    fn sha256_hex_matches_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn canonical_uri_covers_root_bucket_and_key() {
        assert_eq!(S3Core::canonical_uri("", ""), "/");
        assert_eq!(S3Core::canonical_uri("bucket", ""), "/bucket");
        assert_eq!(S3Core::canonical_uri("bucket", "key"), "/bucket/key");
        assert_eq!(
            S3Core::canonical_uri("bucket", "a/b c.txt"),
            "/bucket/a/b%20c.txt"
        );
        assert_eq!(S3Core::canonical_uri("bucket", "dir/"), "/bucket/dir/");
    }

    /// A `.`/`..` key segment must be escaped, not passed through
    /// literally: an HTTP client normalizes `/a/../b` to `/b` in the
    /// URL it sends, after this backend has already signed `/a/../b`,
    /// which SigV4 would reject as a signature mismatch (or worse,
    /// silently resolve to the wrong key).
    #[test]
    fn canonical_uri_escapes_dot_segments() {
        assert_eq!(
            S3Core::canonical_uri("bucket", "a/../b"),
            "/bucket/a/%2E%2E/b"
        );
        assert_eq!(S3Core::canonical_uri("bucket", "./x"), "/bucket/%2E/x");
        assert_eq!(S3Core::canonical_uri("bucket", ".."), "/bucket/%2E%2E");
        // A dot that isn't a whole segment is an ordinary character.
        assert_eq!(
            S3Core::canonical_uri("bucket", "a..b/c.txt"),
            "/bucket/a..b/c.txt"
        );
    }

    #[test]
    fn canonical_query_string_sorts_and_encodes() {
        let query = vec![
            ("prefix".to_string(), "a b/c".to_string()),
            ("delimiter".to_string(), "/".to_string()),
            ("list-type".to_string(), "2".to_string()),
        ];
        assert_eq!(
            canonical_query_string(&query),
            "delimiter=%2F&list-type=2&prefix=a%20b%2Fc"
        );
        assert_eq!(canonical_query_string(&[]), "");
    }

    #[test]
    fn canonical_headers_lowercase_trim_and_sort() {
        let headers = vec![
            ("X-Amz-Date".to_string(), " 20150830T123600Z ".to_string()),
            ("Host".to_string(), "example.amazonaws.com".to_string()),
        ];
        let (block, signed) = canonical_headers(&headers);
        assert_eq!(
            block,
            "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n"
        );
        assert_eq!(signed, "host;x-amz-date");
    }

    /// The classic AWS SigV4 "get-vanilla" example from the public
    /// signature test suite (host example.amazonaws.com, empty path,
    /// no query, date 20150830T123600Z, region us-east-1, service
    /// "service"). This checks the canonical request and string-to-
    /// sign *formatting* exactly; it does not assert a specific
    /// signature hash, since that would require independently
    /// reproducing AWS's published output rather than this
    /// implementation's own derivation of it.
    #[test]
    fn canonical_request_matches_the_get_vanilla_shape() {
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let (block, signed) = canonical_headers(&headers);
        let payload_hash = sha256_hex(b"");
        let creq = canonical_request("GET", "/", "", &block, &signed, &payload_hash);
        let expected = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(creq, expected);

        let credential_scope = "20150830/us-east-1/service/aws4_request";
        let sts = string_to_sign("20150830T123600Z", credential_scope, &creq);
        let expected_sts = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n{}",
            sha256_hex(creq.as_bytes())
        );
        assert_eq!(sts, expected_sts);
    }

    #[test]
    fn authorization_header_has_the_documented_shape() {
        let header =
            authorization_header("AKIDEXAMPLE", "20150830", "us-east-1", "s3", "host;x-amz-date", "deadbeef");
        assert_eq!(
            header,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=deadbeef"
        );
    }

    #[test]
    fn signing_key_changes_with_any_input() {
        let base = signing_key("secret", "20150830", "us-east-1", "s3");
        assert_ne!(base, signing_key("other-secret", "20150830", "us-east-1", "s3"));
        assert_ne!(base, signing_key("secret", "20150831", "us-east-1", "s3"));
        assert_ne!(base, signing_key("secret", "20150830", "eu-west-1", "s3"));
        assert_ne!(base, signing_key("secret", "20150830", "us-east-1", "iam"));
        // Deterministic for the same inputs.
        assert_eq!(base, signing_key("secret", "20150830", "us-east-1", "s3"));
    }

    #[test]
    fn amz_datetime_formats_known_instant() {
        // 2023-05-31T15:14:23Z, cross-checked against
        // http::parse_rfc3339_to_ms's own test for the same instant.
        let (amz_date, date_stamp) = amz_datetime(1_685_546_063_000);
        assert_eq!(amz_date, "20230531T151423Z");
        assert_eq!(date_stamp, "20230531");
    }

    // --- XML extraction -------------------------------------------------

    #[test]
    fn parse_list_buckets_reads_names_and_dates() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <ListAllMyBucketsResult>
            <Buckets>
                <Bucket><Name>media</Name><CreationDate>2023-05-31T15:14:23.000Z</CreationDate></Bucket>
                <Bucket><Name>logs</Name><CreationDate>2022-01-01T00:00:00.000Z</CreationDate></Bucket>
            </Buckets>
        </ListAllMyBucketsResult>"#;
        let buckets = parse_list_buckets(xml);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].name, "media");
        assert_eq!(buckets[0].creation_ms, 1_685_546_063_000);
        assert_eq!(buckets[1].name, "logs");
    }

    #[test]
    fn parse_list_objects_reads_contents_and_common_prefixes() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <ListBucketResult>
            <Name>media</Name>
            <Prefix>photos/</Prefix>
            <KeyCount>2</KeyCount>
            <Contents>
                <Key>photos/a.jpg</Key>
                <Size>1024</Size>
                <LastModified>2023-05-31T15:14:23.000Z</LastModified>
            </Contents>
            <Contents>
                <Key>photos/</Key>
                <Size>0</Size>
                <LastModified>2023-01-01T00:00:00.000Z</LastModified>
            </Contents>
            <CommonPrefixes><Prefix>photos/2023/</Prefix></CommonPrefixes>
            <IsTruncated>true</IsTruncated>
            <NextContinuationToken>token-1</NextContinuationToken>
        </ListBucketResult>"#;
        let page = parse_list_objects(xml);
        assert_eq!(page.contents.len(), 2);
        assert_eq!(page.contents[0], ("photos/a.jpg".to_string(), 1024, 1_685_546_063_000));
        assert_eq!(page.common_prefixes, vec!["photos/2023/".to_string()]);
        assert_eq!(page.next_continuation_token, Some("token-1".to_string()));
    }

    #[test]
    fn xml_unescape_handles_the_five_basic_entities() {
        assert_eq!(
            xml_unescape("a &lt;b&gt; &amp; &quot;c&quot; &apos;d&apos;"),
            "a <b> & \"c\" 'd'"
        );
    }

    // --- INI profile parsing ---------------------------------------------

    #[test]
    fn parse_ini_section_finds_the_named_profile() {
        let contents = "[default]\naws_access_key_id = AKIA_DEFAULT\naws_secret_access_key = default-secret\n\n[work]\naws_access_key_id=AKIA_WORK\naws_secret_access_key=work-secret\n";
        let default = parse_ini_section(contents, "default").unwrap();
        assert_eq!(default.get("aws_access_key_id").unwrap(), "AKIA_DEFAULT");
        let work = parse_ini_section(contents, "work").unwrap();
        assert_eq!(work.get("aws_secret_access_key").unwrap(), "work-secret");
        assert!(parse_ini_section(contents, "missing").is_none());
    }

    #[test]
    fn parse_ini_section_ignores_comments_and_blank_lines() {
        let contents = "# a comment\n; another\n\n[profile work]\naws_access_key_id = AKIA\n";
        let section = parse_ini_section(contents, "profile work").unwrap();
        assert_eq!(section.get("aws_access_key_id").unwrap(), "AKIA");
    }

    // --- factory / auth rejection ----------------------------------------

    #[test]
    fn wrong_auth_is_rejected() {
        for auth in [
            AuthMethod::Password,
            AuthMethod::SshAgent,
            AuthMethod::OAuthToken,
            AuthMethod::SharedKey,
            AuthMethod::None,
            AuthMethod::SshKey {
                key_path: "~/.ssh/id_ed25519".to_string(),
            },
        ] {
            let start = std::time::Instant::now();
            let err = S3Factory
                .connect(&config(auth), Arc::new(NoSecrets))
                .err()
                .expect("must fail");
            assert!(err.contains("wrong auth method"), "got: {err}");
            assert!(start.elapsed() < std::time::Duration::from_secs(1));
        }
    }

    #[test]
    fn factory_rejects_missing_secret_before_network() {
        let err = build_core(&config(AuthMethod::S3Keys), &NoSecrets)
            .err()
            .expect("must fail");
        assert!(
            err.contains("no secret access key stored"),
            "got: {err}"
        );
    }

    #[test]
    fn factory_rejects_empty_username_for_s3_keys() {
        let mut cfg = config(AuthMethod::S3Keys);
        cfg.username = String::new();
        let err = build_core(&cfg, &StaticSecrets("secret"))
            .err()
            .expect("must fail");
        assert!(err.contains("access key id"), "got: {err}");
    }

    #[test]
    fn factory_rejects_bad_host() {
        let mut cfg = config(AuthMethod::S3Keys);
        cfg.host = String::new();
        let err = build_core(&cfg, &StaticSecrets("secret"))
            .err()
            .expect("must fail");
        assert!(err.contains("host is empty"), "got: {err}");

        cfg.host = "https://s3.amazonaws.com".to_string();
        let err = build_core(&cfg, &StaticSecrets("secret"))
            .err()
            .expect("must fail");
        assert!(err.contains("must not contain a scheme"), "got: {err}");
    }

    #[test]
    fn factory_accepts_s3_keys_and_derives_region() {
        let core = build_core(&config(AuthMethod::S3Keys), &StaticSecrets("secret"))
            .expect("must succeed offline");
        assert_eq!(core.access_key, "AKIDEXAMPLE");
        assert_eq!(core.secret_key, "secret");
        assert_eq!(core.region, "us-east-1");
    }

    #[test]
    fn factory_rejects_missing_profile_credentials() {
        // A fixture directory with no credentials/config files, not a
        // mutated HOME: mutating a process-wide environment variable
        // would race with any other test in this binary that reads
        // HOME (Rust runs unit tests on parallel threads in one
        // process), which is exactly what made this test flaky before.
        let empty_aws_dir = tempfile::tempdir().unwrap();
        let err = load_profile_from_dir("default", empty_aws_dir.path())
            .expect_err("must fail");
        assert!(err.contains("no credentials found"), "got: {err}");
    }

    #[test]
    fn error_messages_never_contain_the_secret() {
        // A valid secret must not leak into any error text, including
        // one from a later, unrelated failure on the same core. The
        // reserved "invalid" TLD (RFC 2606) never resolves, so this
        // never reaches a real network.
        let secret = "super-secret-value";
        let mut cfg = config(AuthMethod::S3Keys);
        cfg.host = "s3.host.invalid".to_string();
        let core = build_core(&cfg, &StaticSecrets(secret)).expect("must succeed offline");
        let err = core
            .head_bucket("some-bucket")
            .expect_err("an unresolvable host must fail");
        assert!(!err.contains(secret), "got: {err}");
    }

    #[test]
    fn uri_form_round_trips_through_vpath_parse() {
        let uri = join_uri(Scheme::S3, "media", "/bucket/key");
        assert_eq!(uri, "s3://media/bucket/key");
        assert_eq!(VPath::parse(&uri).to_uri_string(), uri);
    }
}
