//! Filesystem model and directory listing for Orka.
//!
//! This module is UI-agnostic. The FFI layer wraps these types for Swift.

pub mod archives;
pub mod git;
pub mod gitlog;
pub mod ops;
pub mod search;
pub mod sizes;
pub mod vfs;
pub mod watch;

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    /// Full path as a string. Local entries use the native path form;
    /// remote entries will use the URI form.
    pub path: String,
    pub is_dir: bool,
    /// Size in bytes. 0 for directories.
    pub size: u64,
    /// Modification time as milliseconds since the Unix epoch. 0 if unavailable.
    pub modified_ms: i64,
    pub is_hidden: bool,
    pub is_symlink: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("path is not a directory: {0}")]
    NotADirectory(PathBuf),
    #[error("permission denied: {0}")]
    PermissionDenied(PathBuf),
    #[error("not found: {0}")]
    NotFound(PathBuf),
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub include_hidden: bool,
    /// Return only directories. The sidebar tree uses this to keep loads cheap.
    pub dirs_only: bool,
}

/// List the entries of `path`, sorted directories-first, then by
/// case-insensitive name.
pub fn list_dir(path: &Path, opts: &ListOptions) -> Result<Vec<Entry>, CoreError> {
    let read = std::fs::read_dir(path).map_err(|e| map_io_error(path, e))?;
    let mut entries = Vec::new();
    for item in read {
        let item = item.map_err(|e| map_io_error(path, e))?;
        let name = item.file_name().to_string_lossy().into_owned();
        let is_hidden = name.starts_with('.');
        if is_hidden && !opts.include_hidden {
            continue;
        }
        let entry = match entry_from_path(&item.path(), name) {
            Some(e) => e,
            None => continue,
        };
        if opts.dirs_only && !entry.is_dir {
            continue;
        }
        entries.push(entry);
    }
    sort_entries(&mut entries);
    Ok(entries)
}

/// Build an [`Entry`] for one path. Uses `symlink_metadata` so a broken
/// symlink still lists. Returns `None` when the metadata read fails.
pub(crate) fn entry_from_path(path: &Path, name: String) -> Option<Entry> {
    let meta = path.symlink_metadata().ok()?;
    let is_symlink = meta.is_symlink();
    // For symlinks, report the target's kind when the target resolves.
    let target_meta = if is_symlink {
        std::fs::metadata(path).ok()
    } else {
        None
    };
    let effective = target_meta.as_ref().unwrap_or(&meta);
    let is_dir = effective.is_dir();
    let modified_ms = effective
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Some(Entry {
        is_hidden: name.starts_with('.'),
        name,
        path: path.to_string_lossy().into_owned(),
        is_dir,
        size: if is_dir { 0 } else { effective.len() },
        modified_ms,
        is_symlink,
    })
}

/// Sort directories first, then case-insensitive by name.
pub fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

fn map_io_error(path: &Path, e: std::io::Error) -> CoreError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => CoreError::NotFound(path.to_path_buf()),
        ErrorKind::PermissionDenied => CoreError::PermissionDenied(path.to_path_buf()),
        ErrorKind::NotADirectory => CoreError::NotADirectory(path.to_path_buf()),
        _ => CoreError::Io {
            path: path.to_path_buf(),
            source: e,
        },
    }
}
