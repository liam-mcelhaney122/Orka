//! Recursive folder sizes streamed to a sink.
//!
//! A request walks each directory with the `ignore` crate and sums the
//! sizes of everything below it. One event per finished directory
//! streams to a [`SizeSink`], so the UI can fill its Size column as
//! results arrive instead of waiting for the whole listing.

use crate::vfs::VPath;
use ignore::{WalkBuilder, WalkState};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Recursive totals for one directory.
#[derive(Debug, Clone, PartialEq)]
pub struct PathSize {
    pub path: String,
    /// Sum of file sizes below the path. Symlinks count their own size;
    /// their targets are never followed.
    pub bytes: u64,
    /// Count of entries below the path, directories included.
    pub items: u64,
}

/// Receives per-directory totals. Called from a size coordinator thread.
pub trait SizeSink: Send + Sync {
    fn folder_sizes(&self, request_id: u64, sizes: Vec<PathSize>, done: bool);
}

/// Runs at most one live request. Starting a request cancels all
/// previous ones; a navigation supersedes the old listing's sizes.
/// Worker threads detach; the cancel flag is their only shutdown
/// signal. Call [`SizeEngine::cancel_all`] before teardown so no
/// further event reaches the sink.
pub struct SizeEngine {
    sink: Arc<dyn SizeSink>,
    /// Cancel flags by request id. Shared with each coordinator so it
    /// can remove its own entry when it finishes.
    active: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
    next_id: AtomicU64,
    /// Serves a remote directory's totals through its connection.
    router: Arc<crate::vfs::BackendRouter>,
}

impl SizeEngine {
    pub fn new(sink: Arc<dyn SizeSink>, router: Arc<crate::vfs::BackendRouter>) -> Self {
        Self {
            sink,
            active: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(0),
            router,
        }
    }

    /// Starts a request for the given directories and returns its id.
    /// Requests run independently so a listing request and a Get Info
    /// request never cancel each other; the caller cancels superseded
    /// ids explicitly. The directories are siblings from one listing;
    /// the coordinator walks them one at a time to bound disk pressure,
    /// while each walk runs in parallel. A remote directory is walked
    /// through its connection's backend; an unresolvable connection is
    /// skipped silently, like a local path that no longer exists.
    pub fn compute(&self, dirs: Vec<String>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let cancel = Arc::new(AtomicBool::new(false));
        self.active.lock().unwrap().insert(id, cancel.clone());
        let sink = self.sink.clone();
        let active = self.active.clone();
        let router = self.router.clone();
        std::thread::spawn(move || {
            run_request(id, dirs, &cancel, &*sink, &router);
            active.lock().unwrap().remove(&id);
        });
        // The coordinator and walk threads detach. See the type docs.
        id
    }

    pub fn cancel(&self, id: u64) {
        if let Some(flag) = self.active.lock().unwrap().remove(&id) {
            flag.store(true, Ordering::Relaxed);
        }
    }

    pub fn cancel_all(&self) {
        for (_, flag) in self.active.lock().unwrap().drain() {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

/// Walks each directory in order and emits its totals. Runs on a
/// detached coordinator thread.
fn run_request(
    id: u64,
    dirs: Vec<String>,
    cancel: &Arc<AtomicBool>,
    sink: &dyn SizeSink,
    router: &crate::vfs::BackendRouter,
) {
    for dir in dirs {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let size = if VPath::parse(&dir).is_local() {
            walk_dir(&dir, cancel)
        } else {
            match walk_dir_remote(router, &dir, cancel) {
                Some(size) => size,
                // An unresolvable connection is skipped, like a local
                // path that no longer exists; a cancelled walk stops
                // the whole request instead.
                None if cancel.load(Ordering::Relaxed) => return,
                None => continue,
            }
        };
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        sink.folder_sizes(id, vec![size], false);
    }
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    sink.folder_sizes(id, Vec::new(), true);
}

/// Sums sizes and counts items below a remote directory through its
/// backend. `None` means the connection could not be resolved or the
/// walk was cancelled; the caller tells the two apart with `cancel`.
/// Mirrors `walk_dir`'s counting rule: every listed entry counts,
/// directories included, and a symlink is never followed.
fn walk_dir_remote(
    router: &crate::vfs::BackendRouter,
    dir: &str,
    cancel: &Arc<AtomicBool>,
) -> Option<PathSize> {
    let (backend, root_path) = router.resolve(dir).ok()?;
    let opts = crate::ListOptions {
        include_hidden: true,
        dirs_only: false,
    };
    let mut bytes = 0u64;
    let mut items = 0u64;
    let mut stack = vec![root_path];
    while let Some(path) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        let Ok(children) = backend.list_dir(&path, &opts) else {
            continue;
        };
        for child in children {
            items += 1;
            if child.is_dir && !child.is_symlink {
                stack.push(child.path);
            } else {
                bytes += child.size;
            }
        }
    }
    Some(PathSize {
        path: dir.to_string(),
        bytes,
        items,
    })
}

/// Sums sizes and counts items below `dir` with a parallel walk.
/// Every entry counts, hidden files included; the Size column must
/// match what the disk holds, not what a listing shows.
fn walk_dir(dir: &str, cancel: &Arc<AtomicBool>) -> PathSize {
    let bytes = AtomicU64::new(0);
    let items = AtomicU64::new(0);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8);
    let walker = WalkBuilder::new(dir)
        // Sizes must include everything: no ignore files, no hidden
        // filter.
        .standard_filters(false)
        .follow_links(false)
        .threads(threads)
        .build_parallel();
    walker.run(|| {
        let bytes = &bytes;
        let items = &items;
        Box::new(move |result| {
            if cancel.load(Ordering::Relaxed) {
                return WalkState::Quit;
            }
            let Ok(dirent) = result else {
                return WalkState::Continue;
            };
            // Depth 0 is the directory itself.
            if dirent.depth() == 0 {
                return WalkState::Continue;
            }
            items.fetch_add(1, Ordering::Relaxed);
            // symlink_metadata never follows the link, so a symlink
            // counts its own size and a target outside the tree stays
            // out of the total.
            let Ok(meta) = dirent.path().symlink_metadata() else {
                return WalkState::Continue;
            };
            if !meta.is_dir() {
                bytes.fetch_add(meta.len(), Ordering::Relaxed);
            }
            WalkState::Continue
        })
    });
    PathSize {
        path: dir.to_string(),
        bytes: bytes.into_inner(),
        items: items.into_inner(),
    }
}
