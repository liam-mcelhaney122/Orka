//! Directory watcher.
//!
//! Wraps the platform file-system events API through the `notify` crate.
//! Raw events are coalesced for ~200 ms and reduced to directory
//! granularity: the shell reaction is always "re-list this directory".
//! Watches are refcounted so two views of one directory share one watch.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const COALESCE_WINDOW: Duration = Duration::from_millis(200);

/// Receives coalesced change notifications on the dispatcher thread.
/// Implementations must not block.
pub trait WatchSink: Send + Sync {
    fn directories_changed(&self, paths: Vec<PathBuf>);
}

enum Msg {
    Changed(PathBuf),
    Shutdown,
}

/// Refcounted watch state. Keys are canonical paths because the platform
/// reports resolved paths; the value keeps the caller's original spelling
/// so emitted paths match what the caller watched.
#[derive(Default)]
struct WatchMap {
    entries: HashMap<PathBuf, (u32, PathBuf)>,
}

pub struct DirWatcher {
    watcher: Mutex<RecommendedWatcher>,
    watches: Arc<Mutex<WatchMap>>,
    tx: Sender<Msg>,
    dispatcher: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl DirWatcher {
    pub fn new(sink: Arc<dyn WatchSink>) -> Result<Self, String> {
        let (tx, rx) = channel::<Msg>();
        let event_tx = tx.clone();
        let watcher =
            notify::recommended_watcher(move |result: Result<notify::Event, notify::Error>| {
                if let Ok(event) = result {
                    for path in event.paths {
                        let _ = event_tx.send(Msg::Changed(path));
                    }
                }
            })
            .map_err(|e| e.to_string())?;

        let watches = Arc::new(Mutex::new(WatchMap::default()));
        let dispatcher_watches = watches.clone();
        let dispatcher = std::thread::Builder::new()
            .name("orka-watch".into())
            .spawn(move || {
                dispatch_loop(&rx, &dispatcher_watches, sink.as_ref());
            })
            .map_err(|e| e.to_string())?;

        Ok(Self {
            watcher: Mutex::new(watcher),
            watches,
            tx,
            dispatcher: Mutex::new(Some(dispatcher)),
        })
    }

    pub fn watch(&self, path: &Path) -> Result<(), String> {
        let canonical = canonical(path);
        let mut map = self.watches.lock().unwrap();
        if let Some((count, _)) = map.entries.get_mut(&canonical) {
            *count += 1;
            return Ok(());
        }
        self.watcher
            .lock()
            .unwrap()
            .watch(&canonical, RecursiveMode::NonRecursive)
            .map_err(|e| e.to_string())?;
        map.entries.insert(canonical, (1, path.to_path_buf()));
        Ok(())
    }

    pub fn unwatch(&self, path: &Path) {
        let canonical = canonical(path);
        let mut map = self.watches.lock().unwrap();
        let Some((count, _)) = map.entries.get_mut(&canonical) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            map.entries.remove(&canonical);
            let _ = self.watcher.lock().unwrap().unwatch(&canonical);
        }
    }

    /// Stops the dispatcher thread. Call before the app exits so no
    /// notification fires into a dead runtime.
    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
        if let Some(handle) = self.dispatcher.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn dispatch_loop(
    rx: &std::sync::mpsc::Receiver<Msg>,
    watches: &Mutex<WatchMap>,
    sink: &dyn WatchSink,
) {
    while let Ok(Msg::Changed(first)) = rx.recv() {
        let mut pending: HashSet<PathBuf> = HashSet::new();
        add_targets(watches, &mut pending, &first);
        let deadline = Instant::now() + COALESCE_WINDOW;
        'coalesce: loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(Msg::Changed(path)) => add_targets(watches, &mut pending, &path),
                Ok(Msg::Shutdown) | Err(RecvTimeoutError::Disconnected) => break 'coalesce,
                Err(RecvTimeoutError::Timeout) => break,
            }
        }
        if !pending.is_empty() {
            sink.directories_changed(pending.into_iter().collect());
        }
    }
}

/// Maps one raw event path to the watched directories it affects, in the
/// caller's original spelling.
fn add_targets(watches: &Mutex<WatchMap>, pending: &mut HashSet<PathBuf>, path: &Path) {
    let map = watches.lock().unwrap();
    if let Some((_, original)) = map.entries.get(path) {
        pending.insert(original.clone());
    }
    if let Some(parent) = path.parent() {
        if let Some((_, original)) = map.entries.get(parent) {
            pending.insert(original.clone());
        }
    }
}
