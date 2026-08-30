//! Local filesystem backend over `std::fs`.

use super::{Capabilities, FsBackend, WriteFinish};
use crate::{Entry, ListOptions};
use std::io::Write;
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Local semantics are flush then drop; the drop closes the
/// descriptor. No sync_all: durability policy is unchanged.
impl WriteFinish for std::fs::File {
    fn finish(mut self: Box<Self>) -> Result<(), String> {
        self.flush().map_err(|e| e.to_string())
    }
}

/// Serves the local filesystem. Stateless; one instance covers all paths.
pub struct LocalBackend;

impl FsBackend for LocalBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            is_local: true,
            can_trash: true,
            can_watch: true,
            can_rename: true,
            // APFS clones via copyfile(3).
            server_side_copy: true,
            preserves_permissions: true,
        }
    }

    fn list_dir(&self, path: &str, opts: &ListOptions) -> Result<Vec<Entry>, String> {
        crate::list_dir(Path::new(path), opts).map_err(|e| e.to_string())
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let path = Path::new(path);
        let meta = path.symlink_metadata().map_err(|e| e.to_string())?;
        let is_symlink = meta.is_symlink();
        // For symlinks, report the target's kind when the target resolves.
        let target_meta = if is_symlink {
            std::fs::metadata(path).ok()
        } else {
            None
        };
        let effective = target_meta.as_ref().unwrap_or(&meta);
        let is_dir = effective.is_dir();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        let modified_ms = effective
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Ok(Entry {
            is_hidden: name.starts_with('.'),
            name,
            path: path.to_string_lossy().into_owned(),
            is_dir,
            size: if is_dir { 0 } else { effective.len() },
            modified_ms,
            is_symlink,
        })
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        std::fs::File::open(path)
            .map(|f| Box::new(f) as Box<dyn std::io::Read + Send>)
            .map_err(|e| e.to_string())
    }

    fn create_write(
        &self,
        path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        std::fs::File::create(path)
            .map(|f| Box::new(f) as Box<dyn WriteFinish>)
            .map_err(|e| e.to_string())
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let path = Path::new(path);
        let meta = path.symlink_metadata().map_err(|e| e.to_string())?;
        let result = if meta.is_dir() {
            if recursive {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_dir(path)
            }
        } else {
            std::fs::remove_file(path)
        };
        result.map_err(|e| e.to_string())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        std::fs::rename(from, to).map_err(|e| e.to_string())
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        std::fs::create_dir(path).map_err(|e| e.to_string())
    }

    fn copy_native(&self, from: &str, to: &str) -> Option<Result<(), String>> {
        // Single-file fast path. `ops` keeps its own direct copy code;
        // this exists for the future generic transfer path.
        Some(crate::ops::clone_or_copy_file(
            Path::new(from),
            Path::new(to),
        ))
    }
}
