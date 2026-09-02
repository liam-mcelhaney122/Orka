//! Virtual filesystem backends.
//!
//! [`VPath`] classifies a path string as local or remote. [`FsBackend`]
//! is the seam that later SFTP, S3, and FTP backends implement.
//! [`BackendRouter`] maps a path to the backend that serves it. The local
//! fast paths in `ops` stay direct; the router exists so remote support
//! can land without another refactor.

pub mod adls;
pub mod connections;
pub mod dropbox;
pub mod ftp;
pub mod gdrive;
pub mod http;
pub mod local;
pub mod mount;
pub mod oauth;
pub mod s3;
pub mod secret;
pub mod sftp;

pub use local::LocalBackend;

use crate::{Entry, ListOptions};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Remote protocol schemes Orka supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Sftp,
    S3,
    Ftp,
    Ftps,
    Smb,
    Nfs,
    Adls,
    Gdrive,
    Dropbox,
    Rsync,
}

impl Scheme {
    fn as_str(&self) -> &'static str {
        match self {
            Scheme::Sftp => "sftp",
            Scheme::S3 => "s3",
            Scheme::Ftp => "ftp",
            Scheme::Ftps => "ftps",
            Scheme::Smb => "smb",
            Scheme::Nfs => "nfs",
            Scheme::Adls => "adls",
            Scheme::Gdrive => "gdrive",
            Scheme::Dropbox => "dropbox",
            Scheme::Rsync => "rsync",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "sftp" => Some(Scheme::Sftp),
            "s3" => Some(Scheme::S3),
            "ftp" => Some(Scheme::Ftp),
            "ftps" => Some(Scheme::Ftps),
            "smb" => Some(Scheme::Smb),
            "nfs" => Some(Scheme::Nfs),
            "adls" => Some(Scheme::Adls),
            "gdrive" => Some(Scheme::Gdrive),
            "dropbox" => Some(Scheme::Dropbox),
            "rsync" => Some(Scheme::Rsync),
            _ => None,
        }
    }
}

/// A local path or a remote location.
///
/// For `Remote`, `path` keeps its leading slash (or is empty when the
/// URI has none) so [`VPath::to_uri_string`] round-trips exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VPath {
    Local(PathBuf),
    Remote {
        scheme: Scheme,
        connection: String,
        path: String,
    },
}

impl VPath {
    /// Classifies a path string.
    ///
    /// A string that starts with `/` or `~` is local. Otherwise the
    /// string is parsed as `scheme://connection/path`. An unknown scheme
    /// leaves the whole string local, so odd filenames never break.
    pub fn parse(s: &str) -> VPath {
        if s.starts_with('/') || s.starts_with('~') {
            return VPath::Local(PathBuf::from(s));
        }
        if let Some((scheme_str, rest)) = s.split_once("://") {
            if let Some(scheme) = Scheme::parse(scheme_str) {
                let (connection, path) = match rest.find('/') {
                    Some(idx) => (&rest[..idx], &rest[idx..]),
                    None => (rest, ""),
                };
                return VPath::Remote {
                    scheme,
                    connection: connection.to_string(),
                    path: path.to_string(),
                };
            }
        }
        VPath::Local(PathBuf::from(s))
    }

    /// The exact string form. Inverse of [`VPath::parse`].
    pub fn to_uri_string(&self) -> String {
        match self {
            VPath::Local(p) => p.to_string_lossy().into_owned(),
            VPath::Remote {
                scheme,
                connection,
                path,
            } => format!("{}://{connection}{path}", scheme.as_str()),
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, VPath::Local(_))
    }
}

/// Builds the full remote URI for a backend-local path. Backends return
/// local paths; consumers of entry paths need the full URI. A path with
/// no leading slash gets one, so the result always parses back to the
/// same connection and path via [`VPath::parse`].
pub fn join_uri(scheme: Scheme, connection: &str, path: &str) -> String {
    if path.is_empty() || path.starts_with('/') {
        format!("{}://{connection}{path}", scheme.as_str())
    } else {
        format!("{}://{connection}/{path}", scheme.as_str())
    }
}

/// What a backend can do. The shell gates UI actions on these flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub is_local: bool,
    pub can_trash: bool,
    pub can_watch: bool,
    pub can_rename: bool,
    pub server_side_copy: bool,
    pub preserves_permissions: bool,
}

impl Capabilities {
    /// The safe default for an unresolved or unknown location.
    pub fn none() -> Self {
        Self {
            is_local: false,
            can_trash: false,
            can_watch: false,
            can_rename: false,
            server_side_copy: false,
            preserves_permissions: false,
        }
    }
}

/// A write stream with an explicit close step. `Write` alone cannot
/// report a failure that the backend detects only at close.
pub trait WriteFinish: std::io::Write + Send {
    /// Completes the write and surfaces errors that only appear at
    /// close time (quota, dropped connection, deferred network-mount
    /// errors).
    fn finish(self: Box<Self>) -> Result<(), String>;
}

/// One filesystem backend. Paths are backend-local strings.
///
/// Errors are `String` to match the rest of the core; a typed error
/// enum is out of scope for this milestone.
pub trait FsBackend: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    fn list_dir(&self, path: &str, opts: &ListOptions) -> Result<Vec<Entry>, String>;
    fn stat(&self, path: &str) -> Result<Entry, String>;
    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String>;
    fn create_write(
        &self,
        path: &str,
        size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String>;
    fn delete(&self, path: &str, recursive: bool) -> Result<(), String>;
    fn rename(&self, from: &str, to: &str) -> Result<(), String>;
    fn mkdir(&self, path: &str) -> Result<(), String>;

    /// A backend-native copy that beats the generic read/write stream.
    /// `None` means the caller must stream.
    fn copy_native(&self, _from: &str, _to: &str) -> Option<Result<(), String>> {
        None
    }
}

/// Maps a path string to the backend that serves it.
pub struct BackendRouter {
    local: Arc<LocalBackend>,
    remotes: RwLock<HashMap<String, Arc<dyn FsBackend>>>,
}

impl Default for BackendRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendRouter {
    pub fn new() -> Self {
        Self {
            local: Arc::new(LocalBackend),
            remotes: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a remote backend under a connection name.
    pub fn register(&self, connection: String, backend: Arc<dyn FsBackend>) {
        self.remotes.write().unwrap().insert(connection, backend);
    }

    /// Removes the backend for a connection name. A miss is a no-op.
    pub fn unregister(&self, connection: &str) {
        self.remotes.write().unwrap().remove(connection);
    }

    /// Resolves a path to its backend and the backend-local path.
    pub fn resolve(&self, path: &str) -> Result<(Arc<dyn FsBackend>, String), String> {
        match VPath::parse(path) {
            VPath::Local(p) => Ok((
                self.local.clone() as Arc<dyn FsBackend>,
                p.to_string_lossy().into_owned(),
            )),
            VPath::Remote {
                connection, path, ..
            } => {
                let remotes = self.remotes.read().unwrap();
                match remotes.get(&connection) {
                    Some(backend) => Ok((backend.clone(), path)),
                    None => Err(format!("unknown connection: {connection}")),
                }
            }
        }
    }

    /// Capabilities for the backend that serves `path`.
    /// An unresolved location reports no capabilities.
    pub fn capabilities(&self, path: &str) -> Capabilities {
        match self.resolve(path) {
            Ok((backend, _)) => backend.capabilities(),
            Err(_) => Capabilities::none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trips(s: &str) {
        assert_eq!(VPath::parse(s).to_uri_string(), s, "round-trip of {s:?}");
    }

    #[test]
    fn absolute_and_tilde_paths_are_local() {
        assert!(VPath::parse("/").is_local());
        assert!(VPath::parse("/Users/x/Documents").is_local());
        assert!(VPath::parse("~/Downloads").is_local());
    }

    #[test]
    fn known_schemes_are_remote() {
        assert_eq!(
            VPath::parse("sftp://work"),
            VPath::Remote {
                scheme: Scheme::Sftp,
                connection: "work".to_string(),
                path: String::new(),
            }
        );
        assert_eq!(
            VPath::parse("s3://media/bucket/key"),
            VPath::Remote {
                scheme: Scheme::S3,
                connection: "media".to_string(),
                path: "/bucket/key".to_string(),
            }
        );
        assert!(!VPath::parse("ftp://host/dir").is_local());
    }

    #[test]
    fn unknown_scheme_is_local() {
        assert!(VPath::parse("http://example.com/x").is_local());
        assert!(VPath::parse("webdav://host/dir").is_local());
        assert!(VPath::parse("relative/path").is_local());
    }

    #[test]
    fn new_schemes_are_remote() {
        for uri in [
            "ftps://host/dir",
            "smb://server/share",
            "nfs://host/export",
            "adls://store/fs/dir",
            "gdrive://acct/folder/file.txt",
            "dropbox://acct/Notes/todo.md",
            "rsync://host/home/liam",
        ] {
            assert!(!VPath::parse(uri).is_local(), "{uri} must be remote");
        }
        assert_eq!(
            VPath::parse("dropbox://acct/Notes/todo.md"),
            VPath::Remote {
                scheme: Scheme::Dropbox,
                connection: "acct".to_string(),
                path: "/Notes/todo.md".to_string(),
            }
        );
    }

    #[test]
    fn join_uri_round_trips_through_parse() {
        let uri = join_uri(Scheme::Sftp, "work", "/home/liam");
        assert_eq!(uri, "sftp://work/home/liam");
        assert_eq!(
            VPath::parse(&uri),
            VPath::Remote {
                scheme: Scheme::Sftp,
                connection: "work".to_string(),
                path: "/home/liam".to_string(),
            }
        );
        // A missing leading slash on the backend path is repaired.
        assert_eq!(
            join_uri(Scheme::S3, "media", "bucket/key"),
            "s3://media/bucket/key"
        );
        assert_eq!(
            VPath::parse(&join_uri(Scheme::S3, "media", "bucket/key")),
            VPath::Remote {
                scheme: Scheme::S3,
                connection: "media".to_string(),
                path: "/bucket/key".to_string(),
            }
        );
        assert_eq!(join_uri(Scheme::Ftp, "host", ""), "ftp://host");
    }

    #[test]
    fn uri_strings_round_trip_exactly() {
        round_trips("/");
        round_trips("/Users/x/My Files/");
        round_trips("~/Documents");
        round_trips("sftp://work");
        round_trips("sftp://work/");
        round_trips("sftp://work/home/liam");
        round_trips("s3://media/bucket/key");
        round_trips("s3://media/bucket/prefix/");
        round_trips("ftp://host");
        round_trips("http://example.com/x");
        round_trips("relative/path");
    }
}
