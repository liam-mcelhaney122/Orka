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
}

impl SizeEngine {
    pub fn new(sink: Arc<dyn SizeSink>) -> Self {
        Self {
            sink,
            active: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(0),
        }
    }

    /// Starts a request for the given directories and returns its id.
    /// Requests run independently so a listing request and a Get Info
    /// request never cancel each other; the caller cancels superseded
    /// ids explicitly. The directories are siblings from one listing;
    /// the coordinator walks them one at a time to bound disk pressure,
    /// while each walk runs in parallel. Non-local paths are skipped
    /// silently.
    pub fn compute(&self, dirs: Vec<String>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let cancel = Arc::new(AtomicBool::new(false));
        self.active.lock().unwrap().insert(id, cancel.clone());
        let sink = self.sink.clone();
        let active = self.active.clone();
        std::thread::spawn(move || {
            run_request(id, dirs, &cancel, &*sink);
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
fn run_request(id: u64, dirs: Vec<String>, cancel: &Arc<AtomicBool>, sink: &dyn SizeSink) {
    for dir in dirs {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        // Remote backends have no walker yet.
        if !VPath::parse(&dir).is_local() {
            continue;
        }
        let size = walk_dir(&dir, cancel);
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
