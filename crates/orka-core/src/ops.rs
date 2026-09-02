//! File operations engine.
//!
//! Local jobs run FIFO on one worker thread, so their events stay ordered
//! and calls never overlap. A job that touches a remote path instead runs
//! on a small transfer lane (see [`TRANSFER_LANE_WORKERS`]), so one slow
//! network job cannot block another. Each job is cancellable and reports
//! progress through an [`EventSink`].

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    Replace,
    KeepBoth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpKind {
    Copy {
        sources: Vec<PathBuf>,
        dest_dir: PathBuf,
    },
    Move {
        sources: Vec<PathBuf>,
        dest_dir: PathBuf,
    },
    ResolveLocalConflict {
        source: PathBuf,
        dest_dir: PathBuf,
        is_move: bool,
        resolution: ConflictResolution,
    },
    Duplicate {
        sources: Vec<PathBuf>,
    },
    Trash {
        sources: Vec<PathBuf>,
    },
    /// Permanent delete through each path's backend. Never journaled;
    /// there is no undo for a permanent delete.
    Delete {
        sources: Vec<PathBuf>,
    },
    /// Compresses the sources into one archive inside `dest_dir`. The
    /// archive file name is picked inside the job so two rapid clicks
    /// cannot collide.
    Archive {
        sources: Vec<PathBuf>,
        dest_dir: PathBuf,
        format: crate::archives::ArchiveFormat,
    },
    /// Extracts an archive into a sibling directory next to it.
    Extract {
        archive: PathBuf,
    },
    /// Executes journal actions for undo or redo. `to_redo` is true when
    /// this job comes from `undo()`; its counter-entry goes to the redo
    /// stack.
    Revert {
        actions: Vec<UndoAction>,
        description: String,
        to_redo: bool,
    },
}

/// Platform services the core cannot provide itself. The shell implements
/// this trait; tests inject a fake.
pub trait PlatformDelegate: Send + Sync {
    /// Moves the item to the user's trash. Returns the item's new path
    /// inside the trash so undo can restore it.
    fn trash_item(&self, path: &Path) -> Result<PathBuf, String>;
}

/// One inverse step in the undo journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoAction {
    /// Move the item at `from` to `to`.
    Move { from: PathBuf, to: PathBuf },
    /// Move the item to the trash. Undoing a copy never deletes data.
    Trash { path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct UndoEntry {
    pub description: String,
    pub actions: Vec<UndoAction>,
}

#[derive(Default)]
struct Journal {
    undo: Vec<UndoEntry>,
    redo: Vec<UndoEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Preparing,
    Running,
    Cancelled,
    Failed,
    Done,
}

#[derive(Debug, Clone)]
pub struct Progress {
    pub job_id: u64,
    pub state: JobState,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub items_done: u64,
    pub items_total: u64,
    pub current_path: String,
}

/// One failed item inside a job. The job continues past item failures.
#[derive(Debug, Clone)]
pub struct ItemError {
    pub path: String,
    pub message: String,
}

pub trait EventSink: Send + Sync {
    fn job_progress(&self, progress: Progress);
    fn job_finished(&self, job_id: u64, state: JobState, errors: Vec<ItemError>);
}

struct Job {
    id: u64,
    kind: OpKind,
    description: String,
    cancel: Arc<AtomicBool>,
}

enum WorkerMessage {
    Run(Job),
    Shutdown,
}

pub struct OpsEngine {
    tx: Sender<WorkerMessage>,
    transfer_tx: Sender<WorkerMessage>,
    next_id: AtomicU64,
    cancel_flags: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    journal: Arc<Mutex<Journal>>,
    /// Local jobs never touch this. It backs the transfer lane and
    /// `run_delete`, both of which resolve every path through it.
    router: Arc<crate::vfs::BackendRouter>,
}

impl OpsEngine {
    pub fn new(sink: Arc<dyn EventSink>, delegate: Arc<dyn PlatformDelegate>) -> Self {
        let (tx, rx) = channel::<WorkerMessage>();
        let (transfer_tx, transfer_rx) = channel::<WorkerMessage>();
        let transfer_rx = Arc::new(Mutex::new(transfer_rx));
        let journal = Arc::new(Mutex::new(Journal::default()));
        let router = Arc::new(crate::vfs::BackendRouter::new());
        let cancel_flags: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut workers = Vec::new();

        // Local lane: unchanged FIFO ordering on one worker thread.
        {
            let sink = sink.clone();
            let delegate = delegate.clone();
            let journal = journal.clone();
            let router = router.clone();
            let cancel_flags = cancel_flags.clone();
            workers.push(
                std::thread::Builder::new()
                    .name("orka-ops".into())
                    .spawn(move || {
                        while let Ok(WorkerMessage::Run(job)) = rx.recv() {
                            let id = job.id;
                            run_job(&job, sink.as_ref(), delegate.as_ref(), &journal, &router);
                            cancel_flags.lock().unwrap().remove(&id);
                        }
                    })
                    .expect("spawn ops worker"),
            );
        }

        // Transfer lane: a small pool so one slow remote job cannot block
        // another. Each worker releases the shared receiver's lock before
        // it runs a job - holding the lock across `run_job` would
        // serialize the lane and remove its concurrency.
        for n in 1..=TRANSFER_LANE_WORKERS {
            let sink = sink.clone();
            let delegate = delegate.clone();
            let journal = journal.clone();
            let router = router.clone();
            let cancel_flags = cancel_flags.clone();
            let transfer_rx = transfer_rx.clone();
            workers.push(
                std::thread::Builder::new()
                    .name(format!("orka-transfer-{n}"))
                    .spawn(move || loop {
                        let message = transfer_rx.lock().unwrap().recv();
                        match message {
                            Ok(WorkerMessage::Run(job)) => {
                                let id = job.id;
                                run_job(&job, sink.as_ref(), delegate.as_ref(), &journal, &router);
                                cancel_flags.lock().unwrap().remove(&id);
                            }
                            Ok(WorkerMessage::Shutdown) | Err(_) => break,
                        }
                    })
                    .expect("spawn transfer worker"),
            );
        }

        Self {
            tx,
            transfer_tx,
            next_id: AtomicU64::new(1),
            cancel_flags,
            workers: Mutex::new(workers),
            journal,
            router,
        }
    }

    /// The backend router this engine will use for remote transfers.
    pub fn router(&self) -> Arc<crate::vfs::BackendRouter> {
        self.router.clone()
    }

    pub fn copy(&self, sources: Vec<PathBuf>, dest_dir: PathBuf) -> u64 {
        let description = format!("Copy of {}", count_phrase(sources.len()));
        self.enqueue(OpKind::Copy { sources, dest_dir }, description)
    }

    pub fn r#move(&self, sources: Vec<PathBuf>, dest_dir: PathBuf) -> u64 {
        let description = format!("Move of {}", count_phrase(sources.len()));
        self.enqueue(OpKind::Move { sources, dest_dir }, description)
    }

    pub fn resolve_local_conflict(
        &self,
        source: PathBuf,
        dest_dir: PathBuf,
        is_move: bool,
        resolution: ConflictResolution,
    ) -> u64 {
        let operation = if is_move { "Move" } else { "Copy" };
        self.enqueue(
            OpKind::ResolveLocalConflict {
                source,
                dest_dir,
                is_move,
                resolution,
            },
            format!("{operation} with conflict resolution"),
        )
    }

    pub fn duplicate(&self, sources: Vec<PathBuf>) -> u64 {
        let description = format!("Duplicate of {}", count_phrase(sources.len()));
        self.enqueue(OpKind::Duplicate { sources }, description)
    }

    /// Queues a job that compresses the sources into one archive inside
    /// `dest_dir`. The archive format is the caller's choice; the file
    /// name is picked inside the job to avoid collisions.
    pub fn archive(
        &self,
        sources: Vec<PathBuf>,
        dest_dir: PathBuf,
        format: crate::archives::ArchiveFormat,
    ) -> u64 {
        let description = format!("Compress of {}", count_phrase(sources.len()));
        self.enqueue(
            OpKind::Archive {
                sources,
                dest_dir,
                format,
            },
            description,
        )
    }

    /// Queues a job that extracts an archive into a fresh sibling folder.
    pub fn extract(&self, archive: PathBuf) -> u64 {
        let file_name = archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let description = format!("Extract of \u{201c}{file_name}\u{201d}");
        self.enqueue(OpKind::Extract { archive }, description)
    }

    pub fn trash(&self, sources: Vec<PathBuf>) -> u64 {
        let description = format!("Trash of {}", count_phrase(sources.len()));
        self.enqueue(OpKind::Trash { sources }, description)
    }

    /// Permanently deletes items through their backends. Works for local
    /// and remote paths. Records no undo entry.
    pub fn delete(&self, sources: Vec<PathBuf>) -> u64 {
        let description = format!("Delete of {}", count_phrase(sources.len()));
        self.enqueue(OpKind::Delete { sources }, description)
    }

    /// Pops the newest undo entry and runs its inverse as a normal job.
    /// Returns the job id, or None when the undo stack is empty.
    pub fn undo(&self) -> Option<u64> {
        let entry = self.journal.lock().unwrap().undo.pop()?;
        Some(self.enqueue(
            OpKind::Revert {
                actions: entry.actions,
                description: entry.description.clone(),
                to_redo: true,
            },
            entry.description,
        ))
    }

    pub fn redo(&self) -> Option<u64> {
        let entry = self.journal.lock().unwrap().redo.pop()?;
        Some(self.enqueue(
            OpKind::Revert {
                actions: entry.actions,
                description: entry.description.clone(),
                to_redo: false,
            },
            entry.description,
        ))
    }

    pub fn undo_description(&self) -> Option<String> {
        self.journal
            .lock()
            .unwrap()
            .undo
            .last()
            .map(|e| e.description.clone())
    }

    pub fn redo_description(&self) -> Option<String> {
        self.journal
            .lock()
            .unwrap()
            .redo
            .last()
            .map(|e| e.description.clone())
    }

    /// Synchronous rename with an undo entry. Works for a local path or
    /// a remote URI. Undo is recorded only for a local rename; a remote
    /// backend has no restore-from-trash step yet.
    pub fn rename(&self, path: &Path, new_name: &str) -> Result<PathBuf, ItemError> {
        let path_str = path.to_string_lossy().into_owned();
        let dest = rename_item_at(&self.router, &path_str, new_name)?;
        if crate::vfs::VPath::parse(&path_str).is_local() {
            let old_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            self.push_undo(UndoEntry {
                description: format!("Rename of \u{201c}{old_name}\u{201d}"),
                actions: vec![UndoAction::Move {
                    from: PathBuf::from(&dest),
                    to: path.to_path_buf(),
                }],
            });
        }
        Ok(PathBuf::from(dest))
    }

    /// Synchronous folder creation with an undo entry. Works for a local
    /// path or a remote URI. Undo is recorded only for a local folder.
    pub fn create_folder(&self, parent: &Path, name: &str) -> Result<PathBuf, ItemError> {
        let parent_str = parent.to_string_lossy().into_owned();
        let created = create_folder_at(&self.router, &parent_str, name)?;
        if crate::vfs::VPath::parse(&parent_str).is_local() {
            self.push_undo(UndoEntry {
                description: "New Folder".to_string(),
                actions: vec![UndoAction::Trash {
                    path: PathBuf::from(&created),
                }],
            });
        }
        Ok(PathBuf::from(created))
    }

    /// Synchronous empty-file creation with an undo entry. Works for a
    /// local path or a remote URI. Undo is recorded only for a local
    /// file.
    pub fn create_file(&self, parent: &Path, name: &str) -> Result<PathBuf, ItemError> {
        let parent_str = parent.to_string_lossy().into_owned();
        let created = create_file_at(&self.router, &parent_str, name)?;
        if crate::vfs::VPath::parse(&parent_str).is_local() {
            self.push_undo(UndoEntry {
                description: "New File".to_string(),
                actions: vec![UndoAction::Trash {
                    path: PathBuf::from(&created),
                }],
            });
        }
        Ok(PathBuf::from(created))
    }

    fn push_undo(&self, entry: UndoEntry) {
        let mut journal = self.journal.lock().unwrap();
        journal.undo.push(entry);
        journal.redo.clear();
    }

    pub fn cancel(&self, job_id: u64) {
        if let Some(flag) = self.cancel_flags.lock().unwrap().get(&job_id) {
            flag.store(true, Ordering::Relaxed);
        }
    }

    /// Stops every worker after its current job. Call before the app exits
    /// so no event fires into a dead runtime.
    pub fn shutdown(&self) {
        let _ = self.tx.send(WorkerMessage::Shutdown);
        // One Shutdown per transfer worker: each worker consumes exactly
        // one message, so a lone Shutdown would stop only one of them.
        for _ in 0..TRANSFER_LANE_WORKERS {
            let _ = self.transfer_tx.send(WorkerMessage::Shutdown);
        }
        for handle in self.workers.lock().unwrap().drain(..) {
            let _ = handle.join();
        }
    }

    fn enqueue(&self, kind: OpKind, description: String) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel_flags.lock().unwrap().insert(id, cancel.clone());
        let is_local = job_is_local(&kind);
        let job = Job {
            id,
            kind,
            description,
            cancel,
        };
        // The same predicate `run_job` dispatches on, so a job's lane and
        // its execution path can never disagree.
        let sender = if is_local {
            &self.tx
        } else {
            &self.transfer_tx
        };
        let _ = sender.send(WorkerMessage::Run(job));
        id
    }
}

fn count_phrase(count: usize) -> String {
    if count == 1 {
        "1 Item".to_string()
    } else {
        format!("{count} Items")
    }
}

/// Rejects a remote URI. A function that only supports the local
/// filesystem must call this first, so a URI string can never turn into
/// a meaningless relative `PathBuf` that reaches `std::fs`.
fn require_local(path: &str) -> Result<PathBuf, ItemError> {
    match crate::vfs::VPath::parse(path) {
        crate::vfs::VPath::Local(p) => Ok(p),
        crate::vfs::VPath::Remote { .. } => Err(ItemError {
            path: path.to_string(),
            message: "remote locations are not supported here".to_string(),
        }),
    }
}

/// The first path in `paths` that is not local, reported as an error.
/// `None` means every path is local. Used as a defense-in-depth check
/// ahead of a local-only code path that a remote job should never reach.
fn first_remote<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Option<ItemError> {
    paths
        .into_iter()
        .find_map(|p| require_local(&p.to_string_lossy()).err())
}

/// Picks a name that is not already taken, appending " 2", " 3", … like
/// Finder's "untitled folder" behavior. `candidate_for(n)` builds the
/// name to try at step `n` (starting at 2); `exists` reports whether a
/// candidate name is taken. Local and remote callers share this rule
/// through their own `exists` closure, so the two can never drift apart.
fn numbered_name(
    name: &str,
    candidate_for: impl Fn(u32) -> String,
    exists: impl Fn(&str) -> bool,
) -> String {
    if !exists(name) {
        return name.to_string();
    }
    let mut counter = 2;
    loop {
        let candidate = candidate_for(counter);
        if !exists(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

/// Renames an item inside its directory. Synchronous: a single atomic
/// `rename(2)`; the UI needs the result inline. Local paths only; see
/// [`rename_item_at`] for a path that may be remote.
pub fn rename_item(path: &Path, new_name: &str) -> Result<PathBuf, ItemError> {
    if new_name.is_empty() || new_name.contains('/') {
        return Err(item_error(path, "invalid name"));
    }
    let dest = path.with_file_name(new_name);
    if dest.symlink_metadata().is_ok() {
        return Err(item_error(&dest, "an item with this name already exists"));
    }
    std::fs::rename(path, &dest).map_err(|e| item_error(path, &e.to_string()))?;
    Ok(dest)
}

/// Creates a new folder. Appends " 2", " 3", … when the name is taken,
/// like Finder's "untitled folder" behavior. Local paths only; see
/// [`create_folder_at`] for a path that may be remote.
pub fn create_folder(parent: &Path, name: &str) -> Result<PathBuf, ItemError> {
    let exists = |candidate: &str| parent.join(candidate).symlink_metadata().is_ok();
    let chosen = numbered_name(name, |n| format!("{name} {n}"), exists);
    let candidate = parent.join(chosen);
    std::fs::create_dir(&candidate).map_err(|e| item_error(parent, &e.to_string()))?;
    Ok(candidate)
}

/// Creates an empty file. Appends " 2", " 3", … when the name is taken,
/// mirroring the folder behavior. Local paths only; see
/// [`create_file_at`] for a path that may be remote.
pub fn create_file(parent: &Path, name: &str) -> Result<PathBuf, ItemError> {
    if name.is_empty() || name.contains('/') {
        return Err(item_error(parent, "invalid name"));
    }
    let stem_ext = split_stem(name);
    let exists = |candidate: &str| parent.join(candidate).symlink_metadata().is_ok();
    let chosen = numbered_name(
        name,
        |n| match &stem_ext {
            Some((stem, ext)) => format!("{stem} {n}.{ext}"),
            None => format!("{name} {n}"),
        },
        exists,
    );
    let candidate = parent.join(chosen);
    std::fs::File::create(&candidate).map_err(|e| item_error(parent, &e.to_string()))?;
    Ok(candidate)
}

/// Splits a backend-local path into its parent directory and final
/// name component. The root path itself yields an empty name.
fn split_backend_path(path: &str) -> (&str, &str) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(idx) => (&trimmed[..idx], &trimmed[idx + 1..]),
        None => ("", trimmed),
    }
}

/// Renames an item through the router: the local fast path for a local
/// path, or the item's backend for a remote URI. Returns the new path
/// in the same form as `path` — a plain local path or a full URI.
pub fn rename_item_at(
    router: &crate::vfs::BackendRouter,
    path: &str,
    new_name: &str,
) -> Result<String, ItemError> {
    match crate::vfs::VPath::parse(path) {
        crate::vfs::VPath::Local(p) => {
            rename_item(&p, new_name).map(|dest| dest.display().to_string())
        }
        crate::vfs::VPath::Remote {
            scheme, connection, ..
        } => {
            if new_name.is_empty() || new_name.contains('/') {
                return Err(ItemError {
                    path: path.to_string(),
                    message: "invalid name".to_string(),
                });
            }
            let (backend, backend_path) = router.resolve(path).map_err(|message| ItemError {
                path: path.to_string(),
                message,
            })?;
            if !backend.capabilities().can_rename {
                return Err(ItemError {
                    path: path.to_string(),
                    message: "rename is not supported on this connection".to_string(),
                });
            }
            let (parent, _name) = split_backend_path(&backend_path);
            let dest_path = join_backend_path(parent, new_name);
            if backend.stat(&dest_path).is_ok() {
                return Err(ItemError {
                    path: crate::vfs::join_uri(scheme, &connection, &dest_path),
                    message: "an item with this name already exists".to_string(),
                });
            }
            backend
                .rename(&backend_path, &dest_path)
                .map_err(|message| ItemError {
                    path: path.to_string(),
                    message,
                })?;
            Ok(crate::vfs::join_uri(scheme, &connection, &dest_path))
        }
    }
}

/// Creates a new folder through the router. Appends " 2", " 3", … when
/// the name is taken, using the same rule as the local fast path.
/// Returns the new path in the same form as `parent`.
pub fn create_folder_at(
    router: &crate::vfs::BackendRouter,
    parent: &str,
    name: &str,
) -> Result<String, ItemError> {
    match crate::vfs::VPath::parse(parent) {
        crate::vfs::VPath::Local(p) => {
            create_folder(&p, name).map(|dest| dest.display().to_string())
        }
        crate::vfs::VPath::Remote {
            scheme, connection, ..
        } => {
            let (backend, backend_parent) =
                router.resolve(parent).map_err(|message| ItemError {
                    path: parent.to_string(),
                    message,
                })?;
            let exists =
                |candidate: &str| backend.stat(&join_backend_path(&backend_parent, candidate)).is_ok();
            let chosen = numbered_name(name, |n| format!("{name} {n}"), exists);
            let dest_path = join_backend_path(&backend_parent, &chosen);
            backend.mkdir(&dest_path).map_err(|message| ItemError {
                path: parent.to_string(),
                message,
            })?;
            Ok(crate::vfs::join_uri(scheme, &connection, &dest_path))
        }
    }
}

/// Creates an empty file through the router. Appends " 2", " 3", … into
/// the stem when the name is taken, mirroring the folder behavior.
/// Returns the new path in the same form as `parent`.
pub fn create_file_at(
    router: &crate::vfs::BackendRouter,
    parent: &str,
    name: &str,
) -> Result<String, ItemError> {
    if name.is_empty() || name.contains('/') {
        return Err(ItemError {
            path: parent.to_string(),
            message: "invalid name".to_string(),
        });
    }
    match crate::vfs::VPath::parse(parent) {
        crate::vfs::VPath::Local(p) => {
            create_file(&p, name).map(|dest| dest.display().to_string())
        }
        crate::vfs::VPath::Remote {
            scheme, connection, ..
        } => {
            let (backend, backend_parent) =
                router.resolve(parent).map_err(|message| ItemError {
                    path: parent.to_string(),
                    message,
                })?;
            let stem_ext = split_stem(name);
            let exists =
                |candidate: &str| backend.stat(&join_backend_path(&backend_parent, candidate)).is_ok();
            let chosen = numbered_name(
                name,
                |n| match &stem_ext {
                    Some((stem, ext)) => format!("{stem} {n}.{ext}"),
                    None => format!("{name} {n}"),
                },
                exists,
            );
            let dest_path = join_backend_path(&backend_parent, &chosen);
            let writer = backend
                .create_write(&dest_path, Some(0))
                .map_err(|message| ItemError {
                    path: parent.to_string(),
                    message,
                })?;
            writer.finish().map_err(|message| ItemError {
                path: parent.to_string(),
                message,
            })?;
            Ok(crate::vfs::join_uri(scheme, &connection, &dest_path))
        }
    }
}

/// Splits "report.txt" into ("report", "txt"). None for names without
/// a dot in their last component.
fn split_stem(name: &str) -> Option<(String, String)> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some((stem.to_string(), ext.to_string()))
}

// ---------------------------------------------------------------------------
// Job execution
// ---------------------------------------------------------------------------

struct JobContext<'a> {
    job_id: u64,
    cancel: &'a AtomicBool,
    sink: &'a dyn EventSink,
    bytes_done: u64,
    bytes_total: u64,
    items_done: u64,
    items_total: u64,
    errors: Vec<ItemError>,
    /// Inverse actions for the work that succeeded, in execution order.
    recorded: Vec<UndoAction>,
    /// A conflict job reached its commit point. Later cancellation cannot
    /// roll back a replacement whose old backup cleanup has started.
    committed: bool,
    last_emit: Instant,
}

impl JobContext<'_> {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn item_finished(&mut self, path: &Path, bytes: u64) {
        self.items_done += 1;
        self.bytes_done += bytes;
        self.maybe_emit(path);
    }

    /// Byte progress inside one file. Streaming transfers call this per
    /// chunk; `item_finished` still closes the item.
    fn add_bytes(&mut self, path: &Path, bytes: u64) {
        self.bytes_done += bytes;
        self.maybe_emit(path);
    }

    fn maybe_emit(&mut self, path: &Path) {
        // Throttle: at most ~20 progress events per second.
        if self.last_emit.elapsed() >= Duration::from_millis(50) {
            self.last_emit = Instant::now();
            self.sink.job_progress(Progress {
                job_id: self.job_id,
                state: JobState::Running,
                bytes_done: self.bytes_done,
                bytes_total: self.bytes_total,
                items_done: self.items_done,
                items_total: self.items_total,
                current_path: path.display().to_string(),
            });
        }
    }

    fn fail_item(&mut self, path: &Path, message: &str) {
        self.errors.push(item_error(path, message));
    }
}

/// True when every path the job touches is on the local filesystem.
fn job_is_local(kind: &OpKind) -> bool {
    let path_is_local = |p: &PathBuf| crate::vfs::VPath::parse(&p.to_string_lossy()).is_local();
    match kind {
        OpKind::Copy { sources, dest_dir } | OpKind::Move { sources, dest_dir } => {
            sources.iter().all(path_is_local) && path_is_local(dest_dir)
        }
        OpKind::ResolveLocalConflict {
            source, dest_dir, ..
        } => path_is_local(source) && path_is_local(dest_dir),
        OpKind::Duplicate { sources } | OpKind::Trash { sources } | OpKind::Delete { sources } => {
            sources.iter().all(path_is_local)
        }
        OpKind::Archive {
            sources, dest_dir, ..
        } => sources.iter().all(path_is_local) && path_is_local(dest_dir),
        OpKind::Extract { archive } => path_is_local(archive),
        OpKind::Revert { actions, .. } => actions.iter().all(|a| match a {
            UndoAction::Move { from, to } => path_is_local(from) && path_is_local(to),
            UndoAction::Trash { path } => path_is_local(path),
        }),
    }
}

fn run_job(
    job: &Job,
    sink: &dyn EventSink,
    delegate: &dyn PlatformDelegate,
    journal: &Mutex<Journal>,
    router: &crate::vfs::BackendRouter,
) {
    // A job cancelled while still queued never needs to run at all.
    if job.cancel.load(Ordering::Relaxed) {
        sink.job_finished(job.id, JobState::Cancelled, Vec::new());
        return;
    }

    // Delete always routes through backends, local or remote.
    if let OpKind::Delete { sources } = &job.kind {
        run_delete(job, sink, router, sources);
        return;
    }

    // A job with a remote endpoint takes the generic transfer path.
    // All-local jobs run the unchanged fast path below.
    if !job_is_local(&job.kind) {
        match &job.kind {
            OpKind::Copy { sources, dest_dir } => {
                run_generic_transfer(job, sink, router, sources, dest_dir, false);
            }
            OpKind::Move { sources, dest_dir } => {
                run_generic_transfer(job, sink, router, sources, dest_dir, true);
            }
            OpKind::ResolveLocalConflict { .. } => {
                sink.job_finished(
                    job.id,
                    JobState::Failed,
                    vec![ItemError {
                        path: String::new(),
                        message: "conflict resolution supports local paths only".to_string(),
                    }],
                );
            }
            OpKind::Duplicate { sources } => {
                run_duplicate_via_router(job, sink, router, sources);
            }
            OpKind::Trash { .. } | OpKind::Archive { .. } => {
                sink.job_finished(
                    job.id,
                    JobState::Failed,
                    vec![ItemError {
                        path: String::new(),
                        message: "not supported on remote locations yet".to_string(),
                    }],
                );
            }
            OpKind::Extract { .. } => {
                sink.job_finished(
                    job.id,
                    JobState::Failed,
                    vec![ItemError {
                        path: String::new(),
                        message: "not supported for remote items".to_string(),
                    }],
                );
            }
            OpKind::Revert { .. } => {
                // Remote jobs record no undo, so a remote Revert is a
                // logic error somewhere upstream.
                debug_assert!(false, "revert job contains a remote path");
                sink.job_finished(
                    job.id,
                    JobState::Failed,
                    vec![ItemError {
                        path: String::new(),
                        message: "cannot revert a remote operation".to_string(),
                    }],
                );
            }
            OpKind::Delete { .. } => unreachable!("delete is handled above"),
        }
        return;
    }

    sink.job_progress(Progress {
        job_id: job.id,
        state: JobState::Preparing,
        bytes_done: 0,
        bytes_total: 0,
        items_done: 0,
        items_total: 0,
        current_path: String::new(),
    });

    // Trash and Revert work on whole items; a deep pre-scan adds no value.
    let (items_total, bytes_total) = match &job.kind {
        OpKind::Copy { sources, .. }
        | OpKind::Move { sources, .. }
        | OpKind::Duplicate { sources } => measure(sources),
        OpKind::ResolveLocalConflict { source, .. } => measure(std::slice::from_ref(source)),
        OpKind::Trash { sources } => (sources.len() as u64, 0),
        OpKind::Archive { sources, .. } => measure(sources),
        OpKind::Extract { archive } => measure(std::slice::from_ref(archive)),
        OpKind::Revert { actions, .. } => (actions.len() as u64, 0),
        OpKind::Delete { .. } => unreachable!("delete is handled above"),
    };
    let mut ctx = JobContext {
        job_id: job.id,
        cancel: &job.cancel,
        sink,
        bytes_done: 0,
        bytes_total,
        items_done: 0,
        items_total,
        errors: Vec::new(),
        recorded: Vec::new(),
        committed: false,
        last_emit: Instant::now(),
    };

    match &job.kind {
        OpKind::Copy { sources, dest_dir } => {
            for source in sources {
                if ctx.cancelled() {
                    break;
                }
                let dest = dest_dir.join(file_name(source));
                let errors_before = ctx.errors.len();
                let outcome = copy_item(&mut ctx, source, &dest);
                // Record only items this job created. A conflict leaves a
                // pre-existing destination; undo must never trash it.
                if ctx.errors.len() == errors_before
                    && outcome.complete
                    && rollback_ownership(&dest, &outcome) == RollbackOwnership::Owned
                {
                    ctx.recorded.push(UndoAction::Trash { path: dest });
                }
            }
        }
        OpKind::Move { sources, dest_dir } => {
            for source in sources {
                if ctx.cancelled() {
                    break;
                }
                let dest = dest_dir.join(file_name(source));
                let errors_before = ctx.errors.len();
                let outcome = move_item(&mut ctx, source, &dest);
                if ctx.errors.len() == errors_before
                    && !ctx.cancelled()
                    && outcome.complete
                    && rollback_ownership(&dest, &outcome) == RollbackOwnership::Owned
                {
                    ctx.recorded.push(UndoAction::Move {
                        from: dest,
                        to: source.clone(),
                    });
                }
            }
        }
        OpKind::ResolveLocalConflict {
            source,
            dest_dir,
            is_move,
            resolution,
        } => resolve_local_conflict(&mut ctx, source, dest_dir, *is_move, *resolution),
        OpKind::Duplicate { sources } => {
            for source in sources {
                if ctx.cancelled() {
                    break;
                }
                match duplicate_name(source) {
                    Ok(dest) => {
                        let errors_before = ctx.errors.len();
                        let outcome = copy_item(&mut ctx, source, &dest);
                        if ctx.errors.len() == errors_before
                            && outcome.complete
                            && rollback_ownership(&dest, &outcome) == RollbackOwnership::Owned
                        {
                            ctx.recorded.push(UndoAction::Trash { path: dest });
                        }
                    }
                    Err(e) => ctx.errors.push(e),
                }
            }
        }
        OpKind::Archive {
            sources,
            dest_dir,
            format,
        } => {
            // job_is_local already guarantees this, but a local-only
            // operation must never build a relative PathBuf from a URI,
            // so the check runs again here at the point of use.
            let remote_source = first_remote(
                sources
                    .iter()
                    .map(PathBuf::as_path)
                    .chain(std::iter::once(dest_dir.as_path())),
            );
            if let Some(error) = remote_source {
                ctx.fail_item(Path::new(&error.path), &error.message);
            } else {
                let dest = crate::archives::choose_archive_name(dest_dir, sources, *format);
                let mut last_done: u64 = 0;
                // Each progress callback closes one walked member, so item and
                // byte counters track the pre-scan exactly.
                let mut progress = |done: u64, _total: u64, current: &str| {
                    let delta = done.saturating_sub(last_done);
                    last_done = done;
                    ctx.item_finished(Path::new(current), delta);
                };
                let cancel_check = || job.cancel.load(Ordering::Relaxed);
                match crate::archives::create_archive(
                    sources,
                    &dest,
                    *format,
                    &mut progress,
                    &cancel_check,
                ) {
                    Ok(()) => {
                        // Undo trashes the archive; it never deletes user data.
                        ctx.recorded.push(UndoAction::Trash { path: dest });
                    }
                    Err(message) => {
                        // A partial archive is worthless; remove it always.
                        let _ = remove_recursively(&dest);
                        if message != "cancelled" {
                            let path = sources.first().cloned().unwrap_or_default();
                            ctx.fail_item(&path, &message);
                        }
                    }
                }
            }
        }
        OpKind::Extract { archive } => {
            let remote_source = first_remote(std::iter::once(archive.as_path()));
            if let Some(error) = remote_source {
                ctx.fail_item(Path::new(&error.path), &error.message);
            } else {
                let dest_dir = crate::archives::choose_extract_dir(archive);
                let existed_before = dest_dir.symlink_metadata().is_ok();
                match std::fs::create_dir_all(&dest_dir) {
                    Ok(()) => {
                        let mut last_done: u64 = 0;
                        let mut progress = |done: u64, _total: u64, current: &str| {
                            let delta = done.saturating_sub(last_done);
                            last_done = done;
                            ctx.add_bytes(Path::new(current), delta);
                        };
                        let cancel_check = || job.cancel.load(Ordering::Relaxed);
                        match crate::archives::extract(
                            archive,
                            &dest_dir,
                            &mut progress,
                            &cancel_check,
                        ) {
                            Ok(items) => {
                                for item in items {
                                    if item.symlink_metadata().is_ok() {
                                        ctx.recorded.push(UndoAction::Trash { path: item });
                                    }
                                }
                                ctx.item_finished(archive, 0);
                            }
                            Err(message) => {
                                // A cancelled or failed extract leaves no undo
                                // entry, so its fresh empty folder is clutter.
                                if message != "cancelled" {
                                    ctx.fail_item(archive, &message);
                                }
                                remove_dir_if_empty_and_fresh(&dest_dir, existed_before);
                            }
                        }
                    }
                    Err(e) => ctx.fail_item(archive, &e.to_string()),
                }
            }
        }
        OpKind::Trash { sources } => {
            for source in sources {
                if ctx.cancelled() {
                    break;
                }
                // job_is_local already guarantees this item is local; the
                // check runs again so trash_one never receives a URI.
                if let Err(error) = require_local(&source.to_string_lossy()) {
                    ctx.errors.push(error);
                    continue;
                }
                trash_one(&mut ctx, delegate, source);
            }
        }
        OpKind::Delete { .. } => unreachable!("delete is handled above"),
        OpKind::Revert { actions, .. } => {
            // Reverse order: last recorded action reverts first.
            for action in actions.iter().rev() {
                if ctx.cancelled() {
                    break;
                }
                match action {
                    UndoAction::Move { from, to } => {
                        let errors_before = ctx.errors.len();
                        let outcome = move_item(&mut ctx, from, to);
                        if ctx.errors.len() == errors_before
                            && !ctx.cancelled()
                            && outcome.complete
                            && rollback_ownership(to, &outcome) == RollbackOwnership::Owned
                        {
                            ctx.recorded.push(UndoAction::Move {
                                from: to.clone(),
                                to: from.clone(),
                            });
                        }
                    }
                    UndoAction::Trash { path } => {
                        trash_one(&mut ctx, delegate, path);
                    }
                }
            }
        }
    }

    let state = if ctx.committed {
        if ctx.errors.is_empty() {
            JobState::Done
        } else {
            JobState::Failed
        }
    } else if ctx.cancelled() {
        JobState::Cancelled
    } else if ctx.errors.is_empty() {
        JobState::Done
    } else {
        JobState::Failed
    };

    // Update the journal before the finished event so the shell reads
    // fresh undo/redo descriptions in its event handler.
    let recorded = std::mem::take(&mut ctx.recorded);
    if !recorded.is_empty() {
        let mut journal = journal.lock().unwrap();
        match &job.kind {
            OpKind::Revert { to_redo, .. } => {
                let entry = UndoEntry {
                    description: job.description.clone(),
                    actions: recorded,
                };
                if *to_redo {
                    journal.redo.push(entry);
                } else {
                    journal.undo.push(entry);
                }
            }
            _ => {
                journal.undo.push(UndoEntry {
                    description: job.description.clone(),
                    actions: recorded,
                });
                journal.redo.clear();
            }
        }
    }

    let errors = std::mem::take(&mut ctx.errors);
    sink.job_finished(job.id, state, errors);
}

/// Trashes one item through the delegate and records the restore action.
fn trash_one(ctx: &mut JobContext, delegate: &dyn PlatformDelegate, path: &Path) {
    match delegate.trash_item(path) {
        Ok(trashed) => {
            ctx.recorded.push(UndoAction::Move {
                from: trashed,
                to: path.to_path_buf(),
            });
            ctx.item_finished(path, 0);
        }
        Err(message) => ctx.fail_item(path, &message),
    }
}

// ---------------------------------------------------------------------------
// Router-based jobs: permanent delete and cross-backend transfers
// ---------------------------------------------------------------------------

/// Remote jobs run on a small pool instead of the single local worker, so
/// one slow network transfer cannot block another.
const TRANSFER_LANE_WORKERS: usize = 2;

/// Streamed transfers move data in chunks of this size.
const TRANSFER_CHUNK: usize = 256 * 1024;

/// Pre-scan stops past this many items; totals become indeterminate.
const TRANSFER_SCAN_CAP: u64 = 10_000;

fn preparing_progress(job_id: u64) -> Progress {
    Progress {
        job_id,
        state: JobState::Preparing,
        bytes_done: 0,
        bytes_total: 0,
        items_done: 0,
        items_total: 0,
        current_path: String::new(),
    }
}

fn finish_state(ctx: &JobContext) -> JobState {
    if ctx.cancelled() {
        JobState::Cancelled
    } else if ctx.errors.is_empty() {
        JobState::Done
    } else {
        JobState::Failed
    }
}

/// Permanent delete through each path's backend. Records no undo entry;
/// deleted data cannot be restored.
fn run_delete(
    job: &Job,
    sink: &dyn EventSink,
    router: &crate::vfs::BackendRouter,
    sources: &[PathBuf],
) {
    sink.job_progress(preparing_progress(job.id));
    let mut ctx = JobContext {
        job_id: job.id,
        cancel: &job.cancel,
        sink,
        bytes_done: 0,
        bytes_total: 0,
        items_done: 0,
        items_total: sources.len() as u64,
        errors: Vec::new(),
        recorded: Vec::new(),
        committed: false,
        last_emit: Instant::now(),
    };
    for source in sources {
        if ctx.cancelled() {
            break;
        }
        match router.resolve(&source.to_string_lossy()) {
            Ok((backend, path)) => match backend.delete(&path, true) {
                Ok(()) => ctx.item_finished(source, 0),
                Err(message) => ctx.fail_item(source, &message),
            },
            Err(message) => ctx.fail_item(source, &message),
        }
    }
    let state = finish_state(&ctx);
    sink.job_finished(job.id, state, std::mem::take(&mut ctx.errors));
}

/// Copy or Move with at least one remote endpoint. Streams file data
/// between backends. Records no undo entry.
fn run_generic_transfer(
    job: &Job,
    sink: &dyn EventSink,
    router: &crate::vfs::BackendRouter,
    sources: &[PathBuf],
    dest_dir: &Path,
    is_move: bool,
) {
    sink.job_progress(preparing_progress(job.id));
    let dest_uri = dest_dir.to_string_lossy();
    let (dest_backend, dest_base) = match router.resolve(&dest_uri) {
        Ok(resolved) => resolved,
        Err(message) => {
            sink.job_finished(
                job.id,
                JobState::Failed,
                vec![item_error(dest_dir, &message)],
            );
            return;
        }
    };
    // A cancel that lands while queued or during dest resolution should
    // skip the network pre-scan entirely, not just the transfer loop.
    if job.cancel.load(Ordering::Relaxed) {
        sink.job_finished(job.id, JobState::Cancelled, Vec::new());
        return;
    }
    let (items_total, bytes_total) = measure_via_router(router, sources);
    let mut ctx = JobContext {
        job_id: job.id,
        cancel: &job.cancel,
        sink,
        bytes_done: 0,
        bytes_total,
        items_done: 0,
        items_total,
        errors: Vec::new(),
        recorded: Vec::new(),
        committed: false,
        last_emit: Instant::now(),
    };
    for source in sources {
        if ctx.cancelled() {
            break;
        }
        let source_uri = source.to_string_lossy();
        let (src_backend, src_path) = match router.resolve(&source_uri) {
            Ok(resolved) => resolved,
            Err(message) => {
                ctx.fail_item(source, &message);
                continue;
            }
        };
        let name = src_path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("");
        if name.is_empty() {
            ctx.fail_item(source, "invalid source path");
            continue;
        }
        let dest_path = join_backend_path(&dest_base, name);
        if Arc::ptr_eq(&src_backend, &dest_backend)
            && dest_path.starts_with(&format!("{}/", src_path.trim_end_matches('/')))
        {
            ctx.fail_item(source, "cannot copy a folder into itself");
            continue;
        }
        let errors_before = ctx.errors.len();
        transfer_entry(&mut ctx, &src_backend, &src_path, &dest_backend, &dest_path);
        // Move: remove a top-level source only after a clean copy.
        if is_move && ctx.errors.len() == errors_before && !ctx.cancelled() {
            if let Err(message) = src_backend.delete(&src_path, true) {
                ctx.fail_item(source, &message);
            }
        }
    }
    let state = finish_state(&ctx);
    sink.job_finished(job.id, state, std::mem::take(&mut ctx.errors));
}

/// Joins a backend-local directory path and a child name. An empty base
/// or a bare "/" both yield "/name".
fn join_backend_path(base: &str, name: &str) -> String {
    format!("{}/{name}", base.trim_end_matches('/'))
}

/// Duplicate with at least one remote source. Every item resolves
/// through the router, so a local item in the same list is served by
/// the router's built-in local backend and a mixed list works per item
/// with no special-casing. A duplicate always stays on one backend, so
/// [`transfer_entry`] can use a native copy when the backend has one.
fn run_duplicate_via_router(
    job: &Job,
    sink: &dyn EventSink,
    router: &crate::vfs::BackendRouter,
    sources: &[PathBuf],
) {
    sink.job_progress(preparing_progress(job.id));
    if job.cancel.load(Ordering::Relaxed) {
        sink.job_finished(job.id, JobState::Cancelled, Vec::new());
        return;
    }
    let (items_total, bytes_total) = measure_via_router(router, sources);
    let mut ctx = JobContext {
        job_id: job.id,
        cancel: &job.cancel,
        sink,
        bytes_done: 0,
        bytes_total,
        items_done: 0,
        items_total,
        errors: Vec::new(),
        recorded: Vec::new(),
        committed: false,
        last_emit: Instant::now(),
    };
    for source in sources {
        if ctx.cancelled() {
            break;
        }
        let source_uri = source.to_string_lossy();
        let (backend, src_path) = match router.resolve(&source_uri) {
            Ok(resolved) => resolved,
            Err(message) => {
                ctx.fail_item(source, &message);
                continue;
            }
        };
        let dest_path = match duplicate_backend_name(&backend, &src_path) {
            Ok(path) => path,
            Err(message) => {
                ctx.fail_item(source, &message);
                continue;
            }
        };
        transfer_entry(&mut ctx, &backend, &src_path, &backend, &dest_path);
    }
    let state = finish_state(&ctx);
    sink.job_finished(job.id, state, std::mem::take(&mut ctx.errors));
}

/// "photo.jpg" -> "photo copy.jpg", then "photo copy 2.jpg", … using a
/// backend's own existence check. Mirrors [`duplicate_name`] for the
/// local filesystem. A directory keeps its whole name as the stem, the
/// same rule [`copy_name_in`] uses locally.
fn duplicate_backend_name(
    backend: &Arc<dyn crate::vfs::FsBackend>,
    src_path: &str,
) -> Result<String, String> {
    let (parent, name) = split_backend_path(src_path);
    let is_dir = backend
        .stat(src_path)
        .map(|entry| entry.is_dir)
        .unwrap_or(false);
    let (stem, ext) = if is_dir {
        (name.to_string(), String::new())
    } else {
        match name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => {
                (stem.to_string(), format!(".{ext}"))
            }
            _ => (name.to_string(), String::new()),
        }
    };
    let exists = |candidate: &str| backend.stat(&join_backend_path(parent, candidate)).is_ok();
    let chosen = numbered_name(
        &format!("{stem} copy{ext}"),
        |n| format!("{stem} copy {n}{ext}"),
        exists,
    );
    Ok(join_backend_path(parent, &chosen))
}

/// Pre-scan through the router: item count and byte size for progress.
/// Returns (0, 0) past the cap; zero totals mean indeterminate.
fn measure_via_router(router: &crate::vfs::BackendRouter, sources: &[PathBuf]) -> (u64, u64) {
    let opts = crate::ListOptions {
        include_hidden: true,
        dirs_only: false,
    };
    let mut items = 0u64;
    let mut bytes = 0u64;
    let mut stack: Vec<(Arc<dyn crate::vfs::FsBackend>, crate::Entry)> = Vec::new();
    for source in sources {
        if let Ok((backend, path)) = router.resolve(&source.to_string_lossy()) {
            if let Ok(entry) = backend.stat(&path) {
                stack.push((backend, entry));
            }
        }
    }
    while let Some((backend, entry)) = stack.pop() {
        items += 1;
        if items > TRANSFER_SCAN_CAP {
            return (0, 0);
        }
        if entry.is_dir && !entry.is_symlink {
            if let Ok(children) = backend.list_dir(&entry.path, &opts) {
                for child in children {
                    stack.push((backend.clone(), child));
                }
            }
        } else {
            bytes += entry.size;
        }
    }
    (items, bytes)
}

/// Copies one item (file or directory tree) between backends.
fn transfer_entry(
    ctx: &mut JobContext,
    src: &Arc<dyn crate::vfs::FsBackend>,
    src_path: &str,
    dst: &Arc<dyn crate::vfs::FsBackend>,
    dest_path: &str,
) {
    let entry = match src.stat(src_path) {
        Ok(entry) => entry,
        Err(message) => {
            ctx.fail_item(Path::new(src_path), &message);
            return;
        }
    };
    if entry.is_symlink {
        // A symlink target has no meaning on the other endpoint.
        ctx.fail_item(Path::new(src_path), "symlinks are not transferred");
        return;
    }
    if dst.stat(dest_path).is_ok() {
        ctx.fail_item(
            Path::new(dest_path),
            "an item with this name already exists",
        );
        return;
    }
    if entry.is_dir {
        if let Err(message) = dst.mkdir(dest_path) {
            ctx.fail_item(Path::new(dest_path), &message);
            return;
        }
        ctx.item_finished(Path::new(src_path), 0);
        let opts = crate::ListOptions {
            include_hidden: true,
            dirs_only: false,
        };
        let children = match src.list_dir(src_path, &opts) {
            Ok(children) => children,
            Err(message) => {
                ctx.fail_item(Path::new(src_path), &message);
                return;
            }
        };
        for child in children {
            if ctx.cancelled() {
                return;
            }
            let child_dest = join_backend_path(dest_path, &child.name);
            transfer_entry(ctx, src, &child.path, dst, &child_dest);
        }
    } else {
        transfer_file(ctx, src, src_path, entry.size, dst, dest_path);
    }
}

/// Streams one file between backends in chunks. Cancellation and write
/// failures remove the partial destination, best effort.
fn transfer_file(
    ctx: &mut JobContext,
    src: &Arc<dyn crate::vfs::FsBackend>,
    src_path: &str,
    size: u64,
    dst: &Arc<dyn crate::vfs::FsBackend>,
    dest_path: &str,
) {
    use std::io::{Read, Write};

    // Same backend: a native copy beats streaming through this process.
    if Arc::ptr_eq(src, dst) {
        if let Some(result) = src.copy_native(src_path, dest_path) {
            match result {
                Ok(()) => ctx.item_finished(Path::new(src_path), size),
                Err(message) => ctx.fail_item(Path::new(src_path), &message),
            }
            return;
        }
    }

    let mut reader = match src.open_read(src_path) {
        Ok(reader) => reader,
        Err(message) => {
            ctx.fail_item(Path::new(src_path), &message);
            return;
        }
    };
    let mut writer = match dst.create_write(dest_path, Some(size)) {
        Ok(writer) => writer,
        Err(message) => {
            ctx.fail_item(Path::new(dest_path), &message);
            return;
        }
    };
    let mut buf = vec![0u8; TRANSFER_CHUNK];
    let remove_partial = |writer: Box<dyn crate::vfs::WriteFinish>| {
        // Close the writer before the delete so the backend holds no
        // open handle on the partial file.
        drop(writer);
        let _ = dst.delete(dest_path, false);
    };
    let mut copied = 0u64;
    loop {
        if ctx.cancelled() {
            remove_partial(writer);
            return;
        }
        let n = match reader.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                remove_partial(writer);
                ctx.fail_item(Path::new(src_path), &e.to_string());
                return;
            }
        };
        if n == 0 {
            break;
        }
        if let Err(e) = writer.write_all(&buf[..n]) {
            remove_partial(writer);
            ctx.fail_item(Path::new(dest_path), &e.to_string());
            return;
        }
        copied += n as u64;
        ctx.add_bytes(Path::new(src_path), n as u64);
    }
    // A cancel during the last chunk must not commit the item.
    if ctx.cancelled() {
        remove_partial(writer);
        return;
    }
    // A reader that maps a lost connection to end of file would
    // otherwise commit a truncated destination.
    if copied != size {
        remove_partial(writer);
        ctx.fail_item(
            Path::new(src_path),
            &format!("source ended early: {copied} of {size} bytes"),
        );
        return;
    }
    // The close is where quota and dropped-connection errors surface;
    // a failed close leaves a partial or corrupt destination.
    if let Err(message) = writer.finish() {
        let _ = dst.delete(dest_path, false);
        ctx.fail_item(Path::new(dest_path), &message);
        return;
    }
    ctx.item_finished(Path::new(src_path), 0);
}

/// Pre-scan pass: total item count and byte size for progress reporting.
fn measure(sources: &[PathBuf]) -> (u64, u64) {
    let mut items = 0u64;
    let mut bytes = 0u64;
    let mut stack: Vec<PathBuf> = sources.to_vec();
    while let Some(path) = stack.pop() {
        let Ok(meta) = path.symlink_metadata() else {
            continue;
        };
        items += 1;
        if meta.is_dir() {
            if let Ok(read) = std::fs::read_dir(&path) {
                stack.extend(read.flatten().map(|e| e.path()));
            }
        } else {
            bytes += meta.len();
        }
    }
    (items, bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct OwnedPath {
    path: PathBuf,
    ownership: OwnershipManifest,
}

impl OwnedPath {
    fn from_moved(source: &Path, path: PathBuf, ownership: OwnershipManifest) -> Option<Self> {
        let ownership = remap_manifest(ownership, source, &path)?;
        Some(Self { path, ownership })
    }

    fn is_current(&self) -> bool {
        ownership_manifest(&self.path).is_ok_and(|current| current == self.ownership)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnershipManifest {
    identities: HashMap<PathBuf, FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DestinationOwnership {
    None,
    Owned(OwnershipManifest),
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferOutcome {
    ownership: DestinationOwnership,
    complete: bool,
}

impl TransferOutcome {
    fn none() -> Self {
        Self {
            ownership: DestinationOwnership::None,
            complete: false,
        }
    }

    fn uncertain() -> Self {
        Self {
            ownership: DestinationOwnership::Uncertain,
            complete: false,
        }
    }

    fn owned_path(dest: &Path, complete: bool) -> Self {
        match file_identity(dest) {
            Some(identity) => Self {
                ownership: DestinationOwnership::Owned(OwnershipManifest {
                    identities: HashMap::from([(dest.to_path_buf(), identity)]),
                }),
                complete,
            },
            None => Self::uncertain(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollbackOwnership {
    Absent,
    Owned,
    Uncertain,
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    path.symlink_metadata().ok().map(|metadata| FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn ownership_manifest(root: &Path) -> Result<OwnershipManifest, String> {
    let mut identities = HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
        identities.insert(
            path.clone(),
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        );
        if metadata.is_dir() {
            let entries = std::fs::read_dir(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| format!("could not read {}: {error}", path.display()))?;
                stack.push(entry.path());
            }
        }
    }
    Ok(OwnershipManifest { identities })
}

fn remap_manifest(
    ownership: OwnershipManifest,
    source_root: &Path,
    dest_root: &Path,
) -> Option<OwnershipManifest> {
    let mut identities = HashMap::new();
    for (path, identity) in ownership.identities {
        let relative = path.strip_prefix(source_root).ok()?;
        let remapped = if relative.as_os_str().is_empty() {
            dest_root.to_path_buf()
        } else {
            dest_root.join(relative)
        };
        identities.insert(remapped, identity);
    }
    Some(OwnershipManifest { identities })
}

fn remove_owned_manifest(ownership: &OwnershipManifest) -> Result<(), String> {
    let mut paths: Vec<_> = ownership.identities.keys().cloned().collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in paths {
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
        let current = FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        if ownership.identities.get(&path) != Some(&current) {
            return Err(format!("ownership changed at {}", path.display()));
        }
        let result = if metadata.is_dir() {
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        };
        result.map_err(|error| format!("could not remove {}: {error}", path.display()))?;
    }
    Ok(())
}

fn rollback_ownership(dest: &Path, outcome: &TransferOutcome) -> RollbackOwnership {
    match &outcome.ownership {
        DestinationOwnership::Owned(expected) => match ownership_manifest(dest) {
            Ok(current) if current == *expected => RollbackOwnership::Owned,
            Ok(_) => RollbackOwnership::Uncertain,
            Err(_)
                if dest
                    .symlink_metadata()
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                RollbackOwnership::Absent
            }
            Err(_) => RollbackOwnership::Uncertain,
        },
        DestinationOwnership::None => {
            if dest
                .symlink_metadata()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
                RollbackOwnership::Absent
            } else {
                RollbackOwnership::Uncertain
            }
        }
        DestinationOwnership::Uncertain => RollbackOwnership::Uncertain,
    }
}

fn destination_before_transfer(ctx: &mut JobContext, dest: &Path) -> Option<TransferOutcome> {
    match dest.symlink_metadata() {
        Ok(_) => {
            ctx.fail_item(dest, "an item with this name already exists");
            Some(TransferOutcome::uncertain())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            ctx.fail_item(dest, &format!("could not inspect the destination: {error}"));
            Some(TransferOutcome::uncertain())
        }
    }
}

fn outcome_after_failed_create(dest: &Path) -> TransferOutcome {
    match dest.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TransferOutcome::none(),
        _ => TransferOutcome::uncertain(),
    }
}

fn copy_item(ctx: &mut JobContext, source: &Path, dest: &Path) -> TransferOutcome {
    if dest.starts_with(source) {
        ctx.fail_item(source, "cannot copy a folder into itself");
        return TransferOutcome::none();
    }
    if let Some(outcome) = destination_before_transfer(ctx, dest) {
        return outcome;
    }
    let meta = match source.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            ctx.fail_item(source, &format!("could not inspect the source: {error}"));
            return TransferOutcome::none();
        }
    };
    if meta.is_dir() {
        copy_dir(ctx, source, dest)
    } else {
        match clone_or_copy_file(source, dest) {
            Ok(()) => {
                let outcome = TransferOutcome::owned_path(dest, true);
                if outcome.ownership == DestinationOwnership::Uncertain {
                    ctx.fail_item(dest, "could not verify destination ownership");
                    return outcome;
                }
                ctx.item_finished(source, meta.len());
                outcome
            }
            Err(message) => {
                ctx.fail_item(source, &message);
                outcome_after_failed_create(dest)
            }
        }
    }
}

fn copy_dir(ctx: &mut JobContext, source: &Path, dest: &Path) -> TransferOutcome {
    if let Err(e) = std::fs::create_dir(dest) {
        ctx.fail_item(dest, &e.to_string());
        return outcome_after_failed_create(dest);
    }
    let mut outcome = TransferOutcome::owned_path(dest, false);
    if outcome.ownership == DestinationOwnership::Uncertain {
        ctx.fail_item(dest, "could not verify destination ownership");
        return outcome;
    }
    ctx.item_finished(source, 0);
    let read = match std::fs::read_dir(source) {
        Ok(read) => read,
        Err(error) => {
            ctx.fail_item(source, &format!("could not read the directory: {error}"));
            return outcome;
        }
    };
    let errors_before = ctx.errors.len();
    for entry in read {
        if ctx.cancelled() {
            return outcome;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                ctx.fail_item(
                    source,
                    &format!("could not read a directory entry: {error}"),
                );
                continue;
            }
        };
        let child_source = entry.path();
        let child_dest = dest.join(entry.file_name());
        let child_outcome = copy_item(ctx, &child_source, &child_dest);
        match (&mut outcome.ownership, child_outcome.ownership) {
            (DestinationOwnership::Owned(owned), DestinationOwnership::Owned(child_owned)) => {
                owned.identities.extend(child_owned.identities)
            }
            (_, DestinationOwnership::Uncertain) => {
                outcome.ownership = DestinationOwnership::Uncertain;
                ctx.fail_item(&child_dest, "could not verify copied child ownership");
            }
            _ => {}
        }
    }
    outcome.complete = ctx.errors.len() == errors_before && !ctx.cancelled();
    outcome
}

fn move_item(ctx: &mut JobContext, source: &Path, dest: &Path) -> TransferOutcome {
    if let Some(outcome) = destination_before_transfer(ctx, dest) {
        return outcome;
    }
    let source_ownership = ownership_manifest(source).ok();
    match rename_no_replace(source, dest) {
        Ok(()) => {
            let outcome = source_ownership
                .and_then(|ownership| remap_manifest(ownership, source, dest))
                .map(|ownership| TransferOutcome {
                    ownership: DestinationOwnership::Owned(ownership),
                    complete: true,
                })
                .unwrap_or_else(TransferOutcome::uncertain);
            if rollback_ownership(dest, &outcome) != RollbackOwnership::Owned {
                ctx.fail_item(dest, "could not verify destination ownership");
                return outcome;
            }
            let bytes = dest.symlink_metadata().map(|m| m.len()).unwrap_or(0);
            ctx.item_finished(source, bytes);
            outcome
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            // Cross-volume move: copy, then remove the source on success.
            let outcome = copy_item(ctx, source, dest);
            if outcome.complete
                && !ctx.cancelled()
                && rollback_ownership(dest, &outcome) == RollbackOwnership::Owned
            {
                if let Err(e) = remove_recursively(source) {
                    ctx.fail_item(source, &e);
                }
            }
            outcome
        }
        Err(e) => {
            ctx.fail_item(source, &e.to_string());
            outcome_after_failed_create(dest)
        }
    }
}

fn resolve_local_conflict(
    ctx: &mut JobContext,
    source: &Path,
    dest_dir: &Path,
    is_move: bool,
    resolution: ConflictResolution,
) {
    if ctx.cancelled() {
        return;
    }
    let Some(source_name) = source.file_name() else {
        ctx.fail_item(source, "invalid source name");
        return;
    };
    let dest = match resolution {
        ConflictResolution::KeepBoth => match copy_name_in(source, dest_dir) {
            Ok(dest) => dest,
            Err(error) => {
                ctx.errors.push(error);
                return;
            }
        },
        ConflictResolution::Replace => dest_dir.join(source_name),
    };

    if resolution == ConflictResolution::KeepBoth {
        let errors_before = ctx.errors.len();
        let outcome = if is_move {
            move_item(ctx, source, &dest)
        } else {
            copy_item(ctx, source, &dest)
        };
        let transfer_succeeded = ctx.errors.len() == errors_before
            && !ctx.cancelled()
            && outcome.complete
            && rollback_ownership(&dest, &outcome) == RollbackOwnership::Owned;
        if transfer_succeeded {
            ctx.committed = true;
            return;
        }
        if is_move && !restore_move_for_rollback(ctx, source, &dest, &outcome, None) {
            return;
        }
        cleanup_conflict_destination(ctx, &dest, &outcome, None, "partial copy");
        return;
    }

    replace_item(ctx, source, &dest, is_move);
}

fn replace_item(ctx: &mut JobContext, source: &Path, dest: &Path, is_move: bool) {
    let backup = match dest.symlink_metadata() {
        Ok(_) => {
            let previous_ownership = match ownership_manifest(dest) {
                Ok(ownership) => ownership,
                Err(error) => {
                    ctx.fail_item(dest, &format!("could not inspect the destination: {error}"));
                    return;
                }
            };
            let backup_path = unique_replace_backup(dest, ctx.job_id);
            if let Err(error) = rename_no_replace(dest, &backup_path) {
                ctx.fail_item(dest, &format!("could not back up the destination: {error}"));
                return;
            }
            let Some(backup) = OwnedPath::from_moved(dest, backup_path.clone(), previous_ownership)
            else {
                ctx.fail_item(
                    &backup_path,
                    &format!(
                        "could not verify the previous destination backup; preserve it at {}",
                        backup_path.display()
                    ),
                );
                return;
            };
            if !backup.is_current() {
                ctx.fail_item(
                    &backup.path,
                    &format!(
                        "previous destination backup changed; preserve it at {}",
                        backup.path.display()
                    ),
                );
                return;
            }
            Some(backup)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            ctx.fail_item(dest, &format!("could not inspect the destination: {error}"));
            return;
        }
    };

    let errors_before = ctx.errors.len();
    let outcome = if is_move {
        move_item(ctx, source, dest)
    } else {
        copy_item(ctx, source, dest)
    };
    let transfer_succeeded = ctx.errors.len() == errors_before
        && !ctx.cancelled()
        && outcome.complete
        && rollback_ownership(dest, &outcome) == RollbackOwnership::Owned;

    if transfer_succeeded {
        ctx.committed = true;
        if let Some(backup) = backup {
            if !backup.is_current() {
                ctx.fail_item(
                    &backup.path,
                    &format!(
                        "replacement succeeded, but backup ownership changed; preserve the item at {}",
                        backup.path.display()
                    ),
                );
            } else if let Err(error) = remove_owned_manifest(&backup.ownership) {
                ctx.fail_item(
                    &backup.path,
                    &format!("replacement succeeded, but backup cleanup failed: {error}"),
                );
            }
        }
        return;
    }

    if is_move
        && !restore_move_for_rollback(
            ctx,
            source,
            dest,
            &outcome,
            backup.as_ref().map(|item| item.path.as_path()),
        )
    {
        return;
    }

    if let Some(backup) = backup {
        if !cleanup_conflict_destination(
            ctx,
            dest,
            &outcome,
            Some(&backup.path),
            "partial replacement",
        ) {
            return;
        }
        if !backup.is_current() {
            ctx.fail_item(
                &backup.path,
                &format!(
                    "could not restore the previous destination because backup ownership changed; preserve the item at {}",
                    backup.path.display()
                ),
            );
        } else if let Err(error) = rename_no_replace(&backup.path, dest) {
            ctx.fail_item(
                &backup.path,
                &format!("could not restore the previous destination: {error}"),
            );
        }
    } else {
        cleanup_conflict_destination(ctx, dest, &outcome, None, "partial replacement");
    }
}

fn cleanup_conflict_destination(
    ctx: &mut JobContext,
    dest: &Path,
    outcome: &TransferOutcome,
    backup: Option<&Path>,
    label: &str,
) -> bool {
    match rollback_ownership(dest, outcome) {
        RollbackOwnership::Absent => true,
        RollbackOwnership::Uncertain => {
            report_preserved_paths(ctx, dest, backup);
            false
        }
        RollbackOwnership::Owned => {
            let DestinationOwnership::Owned(ownership) = &outcome.ownership else {
                unreachable!("owned rollback requires an ownership manifest");
            };
            match remove_owned_manifest(ownership) {
                Ok(()) => true,
                Err(error) => {
                    ctx.fail_item(dest, &format!("could not remove the {label}: {error}"));
                    report_preserved_paths(ctx, dest, backup);
                    false
                }
            }
        }
    }
}

fn report_preserved_paths(ctx: &mut JobContext, dest: &Path, backup: Option<&Path>) {
    let message = match backup {
        Some(backup) => format!(
            "rollback preserved the destination at {} and the previous destination at {}",
            dest.display(),
            backup.display()
        ),
        None => format!(
            "rollback preserved the destination at {} because ownership is uncertain",
            dest.display()
        ),
    };
    ctx.fail_item(dest, &message);
}

fn restore_move_for_rollback(
    ctx: &mut JobContext,
    source: &Path,
    dest: &Path,
    outcome: &TransferOutcome,
    backup: Option<&Path>,
) -> bool {
    if !outcome.complete {
        return true;
    }
    if rollback_ownership(dest, outcome) != RollbackOwnership::Owned
        || !restore_moved_source(ctx, source, dest)
    {
        report_preserved_paths(ctx, dest, backup);
        return false;
    }
    true
}

fn restore_moved_source(ctx: &mut JobContext, source: &Path, dest: &Path) -> bool {
    match source.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match rename_no_replace(dest, source) {
                Ok(()) => return true,
                Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {}
                Err(error) => {
                    ctx.fail_item(source, &format!("could not restore the source: {error}"));
                    return false;
                }
            }
        }
        Err(error) => {
            ctx.fail_item(source, &format!("could not inspect the source: {error}"));
            return false;
        }
        Ok(_) => {
            ctx.fail_item(
                source,
                &format!(
                    "source restore stopped because the source path is occupied; preserve the occupant at {} and the incoming item at {}",
                    source.display(),
                    dest.display()
                ),
            );
            return false;
        }
    }

    let no_cancel = AtomicBool::new(false);
    let mut restore_ctx = JobContext {
        job_id: ctx.job_id,
        cancel: &no_cancel,
        sink: ctx.sink,
        bytes_done: 0,
        bytes_total: 0,
        items_done: 0,
        items_total: 0,
        errors: Vec::new(),
        recorded: Vec::new(),
        committed: false,
        last_emit: Instant::now(),
    };
    let restore_outcome = copy_item(&mut restore_ctx, dest, source);
    if restore_ctx.errors.is_empty()
        && restore_outcome.complete
        && rollback_ownership(source, &restore_outcome) == RollbackOwnership::Owned
    {
        return true;
    }

    let detail = restore_ctx
        .errors
        .first()
        .map(|error| error.message.as_str())
        .unwrap_or("the restored source is missing");
    ctx.fail_item(source, &format!("could not restore the source: {detail}"));
    match rollback_ownership(source, &restore_outcome) {
        RollbackOwnership::Owned => {
            cleanup_conflict_destination(
                ctx,
                source,
                &restore_outcome,
                None,
                "partial source restore",
            );
        }
        RollbackOwnership::Uncertain => {
            report_preserved_paths(ctx, source, None);
            return false;
        }
        RollbackOwnership::Absent => {}
    }
    false
}

fn unique_replace_backup(dest: &Path, job_id: u64) -> PathBuf {
    unique_hidden_sibling(dest, job_id, "replace")
}

fn unique_hidden_sibling(path: &Path, job_id: u64, label: &str) -> PathBuf {
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut candidate = parent.join(format!(".orka-{label}-{job_id}"));
    let mut counter = 2u64;
    while candidate.symlink_metadata().is_ok() {
        candidate = parent.join(format!(".orka-{label}-{job_id}-{counter}"));
        counter += 1;
    }
    candidate
}

fn remove_recursively(path: &Path) -> Result<(), String> {
    let meta = path.symlink_metadata().map_err(|e| e.to_string())?;
    let result = if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    result.map_err(|e| e.to_string())
}

/// Removes an extract folder this job created when nothing landed inside.
/// A folder that existed before the job is never touched.
fn remove_dir_if_empty_and_fresh(dir: &Path, existed_before: bool) {
    if existed_before {
        return;
    }
    let Ok(mut read) = std::fs::read_dir(dir) else {
        return;
    };
    if read.next().is_some() {
        return;
    }
    let _ = std::fs::remove_dir(dir);
}

/// "photo.jpg" -> "photo copy.jpg", then "photo copy 2.jpg", …
fn duplicate_name(source: &Path) -> Result<PathBuf, ItemError> {
    let parent = source.parent().unwrap_or(Path::new("."));
    copy_name_in(source, parent)
}

fn copy_name_in(source: &Path, parent: &Path) -> Result<PathBuf, ItemError> {
    let Some(name) = source.file_name() else {
        return Err(item_error(source, "invalid source name"));
    };
    let is_dir = source
        .symlink_metadata()
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false);
    let (stem, ext) = if is_dir {
        (name.to_string_lossy().into_owned(), String::new())
    } else {
        (
            source
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default(),
            source
                .extension()
                .map(|extension| format!(".{}", extension.to_string_lossy()))
                .unwrap_or_default(),
        )
    };
    let mut candidate = parent.join(format!("{stem} copy{ext}"));
    let mut counter = 2;
    while candidate.symlink_metadata().is_ok() {
        candidate = parent.join(format!("{stem} copy {counter}{ext}"));
        counter += 1;
    }
    Ok(candidate)
}

fn file_name(path: &Path) -> std::ffi::OsString {
    path.file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| path.as_os_str().to_os_string())
}

fn item_error(path: &Path, message: &str) -> ItemError {
    ItemError {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn rename_no_replace(source: &Path, dest: &Path) -> std::io::Result<()> {
    const RENAME_EXCL: u32 = 0x0000_0004;

    extern "C" {
        fn renamex_np(
            from: *const libc::c_char,
            to: *const libc::c_char,
            flags: u32,
        ) -> libc::c_int;
    }

    let from = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid source path")
    })?;
    let to = CString::new(dest.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid destination path")
    })?;
    let status = unsafe { renamex_np(from.as_ptr(), to.as_ptr(), RENAME_EXCL) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn rename_no_replace(source: &Path, dest: &Path) -> std::io::Result<()> {
    if dest.symlink_metadata().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    std::fs::rename(source, dest)
}

// ---------------------------------------------------------------------------
// copyfile(3): APFS clones when possible; preserves xattrs, ACLs, and
// resource forks; copies symlinks as links, not their targets.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub(crate) fn clone_or_copy_file(source: &Path, dest: &Path) -> Result<(), String> {
    // Flag values from <copyfile.h>.
    const COPYFILE_ALL: u32 = 0x0F; // ACL | STAT | XATTR | DATA
    const COPYFILE_NOFOLLOW: u32 = (1 << 18) | (1 << 19);
    const COPYFILE_EXCL: u32 = 1 << 17;
    const COPYFILE_CLONE: u32 = 1 << 24;

    extern "C" {
        fn copyfile(
            from: *const libc::c_char,
            to: *const libc::c_char,
            state: *mut libc::c_void,
            flags: u32,
        ) -> libc::c_int;
    }

    let from =
        CString::new(source.as_os_str().as_bytes()).map_err(|_| "invalid path".to_string())?;
    let to = CString::new(dest.as_os_str().as_bytes()).map_err(|_| "invalid path".to_string())?;
    let status = unsafe {
        copyfile(
            from.as_ptr(),
            to.as_ptr(),
            std::ptr::null_mut(),
            COPYFILE_ALL | COPYFILE_NOFOLLOW | COPYFILE_EXCL | COPYFILE_CLONE,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn clone_or_copy_file(source: &Path, dest: &Path) -> Result<(), String> {
    std::fs::copy(source, dest)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, Receiver, Sender};

    type Finished = (u64, JobState, Vec<ItemError>);

    struct TestSink {
        finished: Mutex<Sender<Finished>>,
        /// Runs once on the first progress event. The cancel test uses it
        /// to cancel from inside the running job.
        on_first_progress: Mutex<Option<Box<dyn Fn(u64) + Send>>>,
    }

    impl EventSink for TestSink {
        fn job_progress(&self, progress: Progress) {
            let hook = self.on_first_progress.lock().unwrap().take();
            if let Some(hook) = hook {
                hook(progress.job_id);
            }
        }
        fn job_finished(&self, job_id: u64, state: JobState, errors: Vec<ItemError>) {
            let _ = self.finished.lock().unwrap().send((job_id, state, errors));
        }
    }

    /// Moves items into a plain directory instead of the real trash.
    struct FakeTrash {
        dir: PathBuf,
    }

    impl PlatformDelegate for FakeTrash {
        fn trash_item(&self, path: &Path) -> Result<PathBuf, String> {
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let dest = self.dir.join(name);
            std::fs::rename(path, &dest).map_err(|e| e.to_string())?;
            Ok(dest)
        }
    }

    fn engine(trash: &Path) -> (OpsEngine, Receiver<Finished>) {
        let (tx, rx) = channel();
        let sink = Arc::new(TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(None),
        });
        let delegate = Arc::new(FakeTrash {
            dir: trash.to_path_buf(),
        });
        (OpsEngine::new(sink, delegate), rx)
    }

    fn wait(rx: &Receiver<Finished>, job_id: u64) -> Finished {
        loop {
            let event = rx
                .recv_timeout(Duration::from_secs(10))
                .expect("job did not finish in time");
            if event.0 == job_id {
                return event;
            }
        }
    }

    fn make_tree(root: &Path) {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.txt"), b"alpha").unwrap();
        std::fs::write(root.join("sub/nested.txt"), b"nested").unwrap();
    }

    #[test]
    fn uncertain_rollback_preserves_raced_destination_and_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("item.txt");
        let backup = tmp.path().join(".orka-replace-7");
        std::fs::write(&dest, b"external").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let (tx, _rx) = channel();
        let sink = TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(None),
        };
        let cancel = AtomicBool::new(false);
        let mut ctx = JobContext {
            job_id: 7,
            cancel: &cancel,
            sink: &sink,
            bytes_done: 0,
            bytes_total: 0,
            items_done: 0,
            items_total: 0,
            errors: Vec::new(),
            recorded: Vec::new(),
            committed: false,
            last_emit: Instant::now(),
        };

        let removed = cleanup_conflict_destination(
            &mut ctx,
            &dest,
            &TransferOutcome::none(),
            Some(&backup),
            "partial replacement",
        );

        assert!(!removed);
        assert_eq!(std::fs::read(&dest).unwrap(), b"external");
        assert_eq!(std::fs::read(&backup).unwrap(), b"old");
        assert!(ctx.errors.iter().any(|error| {
            error.message.contains(&dest.display().to_string())
                && error.message.contains(&backup.display().to_string())
        }));
    }

    #[test]
    fn rollback_preserves_owned_directory_with_unexpected_child() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("folder");
        let backup = tmp.path().join(".orka-replace-9");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("copied.txt"), b"copied").unwrap();
        let outcome = TransferOutcome {
            ownership: DestinationOwnership::Owned(ownership_manifest(&dest).unwrap()),
            complete: false,
        };
        std::fs::write(dest.join("external.txt"), b"external").unwrap();
        std::fs::create_dir(&backup).unwrap();
        std::fs::write(backup.join("old.txt"), b"old").unwrap();
        let (tx, _rx) = channel();
        let sink = TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(None),
        };
        let cancel = AtomicBool::new(false);
        let mut ctx = JobContext {
            job_id: 9,
            cancel: &cancel,
            sink: &sink,
            bytes_done: 0,
            bytes_total: 0,
            items_done: 0,
            items_total: 0,
            errors: Vec::new(),
            recorded: Vec::new(),
            committed: false,
            last_emit: Instant::now(),
        };

        let removed = cleanup_conflict_destination(
            &mut ctx,
            &dest,
            &outcome,
            Some(&backup),
            "partial replacement",
        );

        assert!(!removed);
        assert_eq!(std::fs::read(dest.join("copied.txt")).unwrap(), b"copied");
        assert_eq!(
            std::fs::read(dest.join("external.txt")).unwrap(),
            b"external"
        );
        assert_eq!(std::fs::read(backup.join("old.txt")).unwrap(), b"old");
        assert!(ctx.errors.iter().any(|error| {
            error.message.contains(&dest.display().to_string())
                && error.message.contains(&backup.display().to_string())
        }));
    }

    #[test]
    fn move_rollback_preserves_an_occupied_source_and_both_destinations() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("item.txt");
        let dest = tmp.path().join("destination/item.txt");
        let backup = tmp.path().join("destination/.orka-replace-10");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&source, b"external source occupant").unwrap();
        std::fs::write(&dest, b"incoming moved item").unwrap();
        std::fs::write(&backup, b"old destination").unwrap();
        let outcome = TransferOutcome::owned_path(&dest, true);
        let (tx, _rx) = channel();
        let sink = TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(None),
        };
        let cancel = AtomicBool::new(false);
        let mut ctx = JobContext {
            job_id: 10,
            cancel: &cancel,
            sink: &sink,
            bytes_done: 0,
            bytes_total: 0,
            items_done: 0,
            items_total: 0,
            errors: Vec::new(),
            recorded: Vec::new(),
            committed: false,
            last_emit: Instant::now(),
        };

        let restored = restore_move_for_rollback(&mut ctx, &source, &dest, &outcome, Some(&backup));

        assert!(!restored);
        assert_eq!(std::fs::read(&source).unwrap(), b"external source occupant");
        assert_eq!(std::fs::read(&dest).unwrap(), b"incoming moved item");
        assert_eq!(std::fs::read(&backup).unwrap(), b"old destination");
        assert!(ctx.errors.iter().any(|error| {
            error.message.contains(&source.display().to_string())
                && error.message.contains(&dest.display().to_string())
        }));
        assert!(ctx.errors.iter().any(|error| {
            error.message.contains(&dest.display().to_string())
                && error.message.contains(&backup.display().to_string())
        }));
    }

    #[test]
    fn directory_read_failure_marks_owned_copy_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("not-a-directory");
        let dest = tmp.path().join("copy");
        std::fs::write(&source, b"data").unwrap();
        let (tx, _rx) = channel();
        let sink = TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(None),
        };
        let cancel = AtomicBool::new(false);
        let mut ctx = JobContext {
            job_id: 8,
            cancel: &cancel,
            sink: &sink,
            bytes_done: 0,
            bytes_total: 0,
            items_done: 0,
            items_total: 0,
            errors: Vec::new(),
            recorded: Vec::new(),
            committed: false,
            last_emit: Instant::now(),
        };

        let outcome = copy_dir(&mut ctx, &source, &dest);

        assert!(!outcome.complete);
        assert_eq!(
            rollback_ownership(&dest, &outcome),
            RollbackOwnership::Owned
        );
        assert!(ctx
            .errors
            .iter()
            .any(|error| error.message.contains("could not read the directory")));
        assert!(cleanup_conflict_destination(
            &mut ctx,
            &dest,
            &outcome,
            None,
            "partial replacement",
        ));
        assert!(!dest.exists());
    }

    #[test]
    fn copy_replace_preserves_source_and_replaces_file() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let source_dir = tmp.path().join("source");
        let dest_dir = tmp.path().join("destination");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();
        let source = source_dir.join("photo.jpg");
        let dest = dest_dir.join("photo.jpg");
        std::fs::write(&source, b"incoming").unwrap();
        std::fs::write(&dest, b"old").unwrap();

        let (engine, rx) = engine(trash.path());
        let job = engine.resolve_local_conflict(
            source.clone(),
            dest_dir.clone(),
            false,
            ConflictResolution::Replace,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(std::fs::read(&source).unwrap(), b"incoming");
        assert_eq!(std::fs::read(&dest).unwrap(), b"incoming");
        assert!(engine.undo_description().is_none());
        assert!(!dest_dir.join(format!(".orka-replace-{job}")).exists());
        engine.shutdown();
    }

    #[test]
    fn move_replace_removes_source_only_after_success() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let source_dir = tmp.path().join("source");
        let dest_dir = tmp.path().join("destination");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();
        let source = source_dir.join("notes.txt");
        let dest = dest_dir.join("notes.txt");
        std::fs::write(&source, b"incoming").unwrap();
        std::fs::write(&dest, b"old").unwrap();

        let (engine, rx) = engine(trash.path());
        let job = engine.resolve_local_conflict(
            source.clone(),
            dest_dir,
            true,
            ConflictResolution::Replace,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert!(!source.exists());
        assert_eq!(std::fs::read(&dest).unwrap(), b"incoming");
        engine.shutdown();
    }

    #[test]
    fn keep_both_uses_finder_numbering_for_copy_and_move() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let copy_source_dir = tmp.path().join("copy-source");
        let move_source_dir = tmp.path().join("move-source");
        let dest_dir = tmp.path().join("destination");
        std::fs::create_dir_all(&copy_source_dir).unwrap();
        std::fs::create_dir_all(&move_source_dir).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();
        let copy_source = copy_source_dir.join("photo.jpg");
        let move_source = move_source_dir.join("photo.jpg");
        std::fs::write(&copy_source, b"copy incoming").unwrap();
        std::fs::write(&move_source, b"move incoming").unwrap();
        std::fs::write(dest_dir.join("photo.jpg"), b"old").unwrap();
        std::fs::write(dest_dir.join("photo copy.jpg"), b"older copy").unwrap();

        let (engine, rx) = engine(trash.path());
        let copy_job = engine.resolve_local_conflict(
            copy_source.clone(),
            dest_dir.clone(),
            false,
            ConflictResolution::KeepBoth,
        );
        let (_, state, errors) = wait(&rx, copy_job);
        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(
            std::fs::read(dest_dir.join("photo copy 2.jpg")).unwrap(),
            b"copy incoming"
        );
        assert!(copy_source.exists());

        let move_job = engine.resolve_local_conflict(
            move_source.clone(),
            dest_dir.clone(),
            true,
            ConflictResolution::KeepBoth,
        );
        let (_, state, errors) = wait(&rx, move_job);
        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(
            std::fs::read(dest_dir.join("photo copy 3.jpg")).unwrap(),
            b"move incoming"
        );
        assert!(!move_source.exists());

        let directory_source = copy_source_dir.join("album.v1");
        std::fs::create_dir(&directory_source).unwrap();
        std::fs::write(directory_source.join("cover.jpg"), b"cover").unwrap();
        std::fs::create_dir(dest_dir.join("album.v1")).unwrap();
        std::fs::create_dir(dest_dir.join("album.v1 copy")).unwrap();
        let directory_job = engine.resolve_local_conflict(
            directory_source,
            dest_dir.clone(),
            false,
            ConflictResolution::KeepBoth,
        );
        let (_, state, errors) = wait(&rx, directory_job);
        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(
            std::fs::read(dest_dir.join("album.v1 copy 2/cover.jpg")).unwrap(),
            b"cover"
        );
        engine.shutdown();
    }

    #[test]
    fn directory_replace_replaces_the_complete_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let source_parent = tmp.path().join("source");
        let dest_parent = tmp.path().join("destination");
        let source = source_parent.join("folder");
        let dest = dest_parent.join("folder");
        make_tree(&source);
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("old.txt"), b"old").unwrap();

        let (engine, rx) = engine(trash.path());
        let job = engine.resolve_local_conflict(
            source.clone(),
            dest_parent,
            false,
            ConflictResolution::Replace,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(dest.join("sub/nested.txt")).unwrap(),
            b"nested"
        );
        assert!(!dest.join("old.txt").exists());
        assert!(source.exists());
        engine.shutdown();
    }

    #[test]
    fn replace_restores_old_destination_when_source_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let dest_dir = tmp.path().join("destination");
        std::fs::create_dir_all(&dest_dir).unwrap();
        let source = tmp.path().join("missing/item.txt");
        let dest = dest_dir.join("item.txt");
        std::fs::write(&dest, b"old").unwrap();

        let (engine, rx) = engine(trash.path());
        let job = engine.resolve_local_conflict(
            source.clone(),
            dest_dir,
            true,
            ConflictResolution::Replace,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Failed);
        assert!(!errors.is_empty());
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert!(!source.exists());
        engine.shutdown();
    }

    #[test]
    fn replace_restores_old_destination_when_transfer_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let dest_dir = source.join("inside");
        let dest = dest_dir.join("source");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(source.join("incoming.txt"), b"incoming").unwrap();
        std::fs::write(dest.join("old.txt"), b"old").unwrap();

        let (engine, rx) = engine(trash.path());
        let job = engine.resolve_local_conflict(
            source.clone(),
            dest_dir,
            false,
            ConflictResolution::Replace,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Failed);
        assert!(errors
            .iter()
            .any(|error| error.message == "cannot copy a folder into itself"));
        assert_eq!(std::fs::read(dest.join("old.txt")).unwrap(), b"old");
        assert_eq!(
            std::fs::read(source.join("incoming.txt")).unwrap(),
            b"incoming"
        );
        engine.shutdown();
    }

    #[test]
    fn remote_conflict_resolution_fails_as_a_local_only_job() {
        let trash = tempfile::tempdir().unwrap();
        let (engine, rx) = engine(trash.path());
        let job = engine.resolve_local_conflict(
            PathBuf::from("sftp://work/photo.jpg"),
            PathBuf::from("/tmp"),
            false,
            ConflictResolution::Replace,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Failed);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].message,
            "conflict resolution supports local paths only"
        );
        engine.shutdown();
    }

    #[test]
    fn conflict_resolution_preserves_the_existing_journal() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let first_dest = tmp.path().join("first-destination");
        let conflict_dest = tmp.path().join("conflict-destination");
        std::fs::create_dir_all(&first_dest).unwrap();
        std::fs::create_dir_all(&conflict_dest).unwrap();
        let first_source = tmp.path().join("first.txt");
        let conflict_source = tmp.path().join("conflict.txt");
        std::fs::write(&first_source, b"first").unwrap();
        std::fs::write(&conflict_source, b"incoming").unwrap();
        std::fs::write(conflict_dest.join("conflict.txt"), b"old").unwrap();

        let (engine, rx) = engine(trash.path());
        let copy_job = engine.copy(vec![first_source], first_dest);
        let (_, state, errors) = wait(&rx, copy_job);
        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(engine.undo_description(), Some("Copy of 1 Item".into()));

        let conflict_job = engine.resolve_local_conflict(
            conflict_source,
            conflict_dest,
            false,
            ConflictResolution::Replace,
        );
        let (_, state, errors) = wait(&rx, conflict_job);
        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(engine.undo_description(), Some("Copy of 1 Item".into()));
        engine.shutdown();
    }

    #[test]
    fn archive_job_creates_zip_and_undo_trashes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let src = tmp.path().join("tree");
        make_tree(&src);

        let (engine, rx) = engine(trash.path());
        let job = engine.archive(
            vec![src.clone()],
            tmp.path().to_path_buf(),
            crate::archives::ArchiveFormat::Zip,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        // A single source names the archive after itself.
        let archive = tmp.path().join("tree.zip");
        assert!(archive.exists());
        assert!(src.exists(), "compression must not remove the source");
        assert_eq!(engine.undo_description(), Some("Compress of 1 Item".into()));

        let undo_job = engine.undo().expect("undo entry exists");
        let (_, state, _) = wait(&rx, undo_job);
        assert_eq!(state, JobState::Done);
        assert!(!archive.exists());
        assert!(src.exists());
        engine.shutdown();
    }

    #[test]
    fn extract_job_extracts_and_undo_trashes_items() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let src = tmp.path().join("photos");
        make_tree(&src);
        let archive = tmp.path().join("bundle.zip");
        let mut no_progress = |_: u64, _: u64, _: &str| {};
        let no_cancel = || false;
        crate::archives::create_archive(
            &[src],
            &archive,
            crate::archives::ArchiveFormat::Zip,
            &mut no_progress,
            &no_cancel,
        )
        .unwrap();

        let (engine, rx) = engine(trash.path());
        let job = engine.extract(archive.clone());
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        let extracted = tmp.path().join("bundle/photos");
        assert_eq!(
            std::fs::read(extracted.join("a.txt")).unwrap(),
            b"alpha".to_vec()
        );
        assert_eq!(
            engine.undo_description(),
            Some("Extract of \u{201c}bundle.zip\u{201d}".into())
        );

        let undo_job = engine.undo().expect("undo entry exists");
        let (_, state, _) = wait(&rx, undo_job);
        assert_eq!(state, JobState::Done);
        // Undo trashes the extracted items; the fresh extract folder stays.
        assert!(!extracted.exists());
        engine.shutdown();
    }

    #[test]
    fn remote_archive_fails_without_side_effects() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let (engine, rx) = engine(trash.path());

        let job = engine.archive(
            vec![PathBuf::from("sftp://work/etc/hosts")],
            tmp.path().to_path_buf(),
            crate::archives::ArchiveFormat::Zip,
        );
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Failed);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "not supported on remote locations yet");
        assert!(engine.undo_description().is_none());
        engine.shutdown();
    }

    #[test]
    fn cancel_during_archive_removes_the_partial_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tempfile::tempdir().unwrap();
        let src = tmp.path().join("big");
        std::fs::create_dir(&src).unwrap();
        // Enough payload that the job outlives the progress throttle.
        for i in 0..40 {
            std::fs::write(src.join(format!("f{i}.bin")), vec![0u8; 1024 * 1024]).unwrap();
        }

        let engine_slot: Arc<Mutex<Option<Arc<OpsEngine>>>> = Arc::new(Mutex::new(None));
        let slot = engine_slot.clone();
        let (tx, rx) = channel();
        let sink = Arc::new(TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(Some(Box::new(move |job_id: u64| {
                if let Some(engine) = slot.lock().unwrap().as_ref() {
                    engine.cancel(job_id);
                }
            }))),
        });
        let delegate = Arc::new(FakeTrash {
            dir: trash.path().to_path_buf(),
        });
        let engine = Arc::new(OpsEngine::new(sink, delegate));
        *engine_slot.lock().unwrap() = Some(engine.clone());

        let job = engine.archive(
            vec![src],
            tmp.path().to_path_buf(),
            crate::archives::ArchiveFormat::Zip,
        );
        let (_, state, _) = wait(&rx, job);

        assert_eq!(state, JobState::Cancelled);
        assert!(!tmp.path().join("Archive.zip").exists());
        assert!(engine.undo_description().is_none());
        engine.shutdown();
    }

    // -----------------------------------------------------------------
    // Transfer lane
    // -----------------------------------------------------------------

    /// Trashes an item by parking on a channel until the test releases
    /// it. Occupies the local lane's one worker so a test can prove a
    /// remote job does not wait behind it.
    struct BlockingTrash {
        /// Fires once, the first time `trash_item` is entered.
        arrived: Mutex<Option<Sender<()>>>,
        release: Mutex<Receiver<()>>,
    }

    impl PlatformDelegate for BlockingTrash {
        fn trash_item(&self, _path: &Path) -> Result<PathBuf, String> {
            if let Some(tx) = self.arrived.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let _ = self.release.lock().unwrap().recv();
            Ok(PathBuf::from("/dev/null"))
        }
    }

    /// Signals arrival once, then blocks until the test sends a release.
    /// Backs [`GateBackend::open_read`] so a test can hold a transfer
    /// mid-stream and control exactly when it completes.
    struct GateReader {
        arrived: Option<Sender<()>>,
        release: Arc<Mutex<Receiver<()>>>,
    }

    impl std::io::Read for GateReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(tx) = self.arrived.take() {
                let _ = tx.send(());
            }
            let _ = self.release.lock().unwrap().recv();
            Ok(0)
        }
    }

    /// Minimal remote backend for concurrency tests. `stat` reports a
    /// small file for every registered path; `open_read` gates on a
    /// channel. The other methods are stubs that these tests never call.
    struct GateBackend {
        gates: Mutex<HashMap<String, (Sender<()>, Arc<Mutex<Receiver<()>>>)>>,
    }

    impl crate::vfs::FsBackend for GateBackend {
        fn capabilities(&self) -> crate::vfs::Capabilities {
            crate::vfs::Capabilities::none()
        }
        fn list_dir(
            &self,
            _path: &str,
            _opts: &crate::ListOptions,
        ) -> Result<Vec<crate::Entry>, String> {
            Err("not supported".to_string())
        }
        fn stat(&self, path: &str) -> Result<crate::Entry, String> {
            if self.gates.lock().unwrap().contains_key(path) {
                Ok(crate::Entry {
                    name: path.trim_start_matches('/').to_string(),
                    path: path.to_string(),
                    is_dir: false,
                    size: 0,
                    modified_ms: 0,
                    is_hidden: false,
                    is_symlink: false,
                })
            } else {
                Err("not found".to_string())
            }
        }
        fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
            let (arrived, release) = self
                .gates
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| "not found".to_string())?;
            Ok(Box::new(GateReader {
                arrived: Some(arrived),
                release,
            }))
        }
        fn create_write(
            &self,
            _path: &str,
            _size_hint: Option<u64>,
        ) -> Result<Box<dyn crate::vfs::WriteFinish>, String> {
            Err("not supported".to_string())
        }
        fn delete(&self, _path: &str, _recursive: bool) -> Result<(), String> {
            Ok(())
        }
        fn rename(&self, _from: &str, _to: &str) -> Result<(), String> {
            Err("not supported".to_string())
        }
        fn mkdir(&self, _path: &str) -> Result<(), String> {
            Err("not supported".to_string())
        }
    }

    #[test]
    fn remote_job_bypasses_a_blocked_local_lane() {
        let trash = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let (occupy_tx, occupy_rx) = channel::<()>();
        let (release_tx, release_rx) = channel::<()>();
        let delegate = Arc::new(BlockingTrash {
            arrived: Mutex::new(Some(occupy_tx)),
            release: Mutex::new(release_rx),
        });
        let (tx, rx) = channel();
        let sink = Arc::new(TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(None),
        });
        let engine = OpsEngine::new(sink, delegate);

        // Occupies the local lane's only worker; it stays parked until
        // this test releases it below.
        let occupy_job = engine.trash(vec![trash.path().join("occupy.txt")]);
        occupy_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("trash job did not start");

        // An unknown connection fails fast. The result is meaningful only
        // when the job runs while the local lane is still blocked.
        let remote_job = engine.copy(
            vec![PathBuf::from("sftp://nowhere/x")],
            dest.path().to_path_buf(),
        );
        let (_, state, errors) = wait(&rx, remote_job);
        assert_eq!(state, JobState::Failed);
        assert!(
            errors[0].message.contains("unknown connection"),
            "unexpected error: {:?}",
            errors[0]
        );

        release_tx.send(()).unwrap();
        let (_, occupy_state, _) = wait(&rx, occupy_job);
        assert_eq!(occupy_state, JobState::Done);
        engine.shutdown();
    }

    #[test]
    fn queued_job_cancelled_before_running_finishes_cancelled() {
        let trash = tempfile::tempdir().unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let src_file = src_dir.path().join("a.txt");
        std::fs::write(&src_file, b"alpha").unwrap();

        let (occupy_tx, occupy_rx) = channel::<()>();
        let (release_tx, release_rx) = channel::<()>();
        let delegate = Arc::new(BlockingTrash {
            arrived: Mutex::new(Some(occupy_tx)),
            release: Mutex::new(release_rx),
        });
        let (tx, rx) = channel();
        let sink = Arc::new(TestSink {
            finished: Mutex::new(tx),
            on_first_progress: Mutex::new(None),
        });
        let engine = OpsEngine::new(sink, delegate);

        let occupy_job = engine.trash(vec![trash.path().join("occupy.txt")]);
        occupy_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("occupy job did not start");

        // The local lane's one worker is busy, so this copy is still
        // sitting in the queue when we cancel it.
        let copy_job = engine.copy(vec![src_file], dest_dir.path().to_path_buf());
        engine.cancel(copy_job);

        release_tx.send(()).unwrap();
        let (_, occupy_state, _) = wait(&rx, occupy_job);
        assert_eq!(occupy_state, JobState::Done);

        let (_, state, _) = wait(&rx, copy_job);
        assert_eq!(state, JobState::Cancelled);
        assert!(!dest_dir.path().join("a.txt").exists());
        engine.shutdown();
    }

    #[test]
    fn transfer_lane_runs_two_remote_jobs_at_once() {
        let trash = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let (engine, rx) = engine(trash.path());

        let mut gates = HashMap::new();
        let mut arrivals = HashMap::new();
        let mut releases = HashMap::new();
        for name in ["a", "b", "c"] {
            let (arrived_tx, arrived_rx) = channel::<()>();
            let (release_tx, release_rx) = channel::<()>();
            gates.insert(
                format!("/{name}"),
                (arrived_tx, Arc::new(Mutex::new(release_rx))),
            );
            arrivals.insert(name, arrived_rx);
            releases.insert(name, release_tx);
        }
        let backend = Arc::new(GateBackend {
            gates: Mutex::new(gates),
        });
        engine.router().register("fake".to_string(), backend);

        let job_a = engine.copy(
            vec![PathBuf::from("sftp://fake/a")],
            dest_dir.path().to_path_buf(),
        );
        let job_b = engine.copy(
            vec![PathBuf::from("sftp://fake/b")],
            dest_dir.path().to_path_buf(),
        );

        // Both readers must reach the gate before either is released:
        // proof the two jobs run at the same time, not back to back.
        arrivals["a"]
            .recv_timeout(Duration::from_secs(5))
            .expect("job a did not arrive");
        arrivals["b"]
            .recv_timeout(Duration::from_secs(5))
            .expect("job b did not arrive");

        let job_c = engine.copy(
            vec![PathBuf::from("sftp://fake/c")],
            dest_dir.path().to_path_buf(),
        );
        // The lane is capped at TRANSFER_LANE_WORKERS: a third job must
        // wait for a slot instead of starting immediately.
        assert!(
            arrivals["c"]
                .recv_timeout(Duration::from_millis(200))
                .is_err(),
            "a third job started before a slot freed up"
        );

        releases["a"].send(()).unwrap();
        let (_, state_a, errors_a) = wait(&rx, job_a);
        assert_eq!(state_a, JobState::Done, "errors: {errors_a:?}");

        arrivals["c"]
            .recv_timeout(Duration::from_secs(5))
            .expect("job c did not arrive after a slot freed up");

        releases["b"].send(()).unwrap();
        let (_, state_b, errors_b) = wait(&rx, job_b);
        assert_eq!(state_b, JobState::Done, "errors: {errors_b:?}");

        releases["c"].send(()).unwrap();
        let (_, state_c, errors_c) = wait(&rx, job_c);
        assert_eq!(state_c, JobState::Done, "errors: {errors_c:?}");

        engine.shutdown();
    }

    #[test]
    fn finished_jobs_release_their_cancel_flags() {
        let trash = tempfile::tempdir().unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let src_file = src_dir.path().join("a.txt");
        std::fs::write(&src_file, b"alpha").unwrap();
        let (engine, rx) = engine(trash.path());

        let job = engine.copy(vec![src_file], dest_dir.path().to_path_buf());
        let (_, state, errors) = wait(&rx, job);
        assert_eq!(state, JobState::Done, "errors: {errors:?}");

        // Pruning happens just after the finished event is sent, so poll
        // instead of asserting immediately after `wait` returns.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if engine.cancel_flags.lock().unwrap().is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "cancel flag was never pruned");
            std::thread::sleep(Duration::from_millis(10));
        }
        engine.shutdown();
    }

    // -----------------------------------------------------------------
    // Remote routing: rename, create folder/file, duplicate
    // -----------------------------------------------------------------

    /// Minimal in-memory backend for remote-routing tests: only the
    /// operations `ops.rs` exercises (stat, list, mkdir, create_write,
    /// rename, delete). Not a general-purpose fake.
    #[derive(Default)]
    struct MemFsState {
        dirs: std::collections::HashSet<String>,
        files: HashMap<String, Vec<u8>>,
    }

    struct MemFs {
        state: Arc<Mutex<MemFsState>>,
        can_rename: bool,
    }

    impl MemFs {
        fn new() -> Self {
            let mut state = MemFsState::default();
            state.dirs.insert("/".to_string());
            Self {
                state: Arc::new(Mutex::new(state)),
                can_rename: true,
            }
        }

        fn without_rename(mut self) -> Self {
            self.can_rename = false;
            self
        }

        fn add_dir(&self, path: &str) {
            self.state.lock().unwrap().dirs.insert(path.to_string());
        }

        fn add_file(&self, path: &str, bytes: &[u8]) {
            self.state
                .lock()
                .unwrap()
                .files
                .insert(path.to_string(), bytes.to_vec());
        }

        fn file(&self, path: &str) -> Option<Vec<u8>> {
            self.state.lock().unwrap().files.get(path).cloned()
        }
    }

    fn mem_name_of(path: &str) -> &str {
        path.trim_end_matches('/').rsplit('/').next().unwrap_or(path)
    }

    fn mem_parent_of(path: &str) -> &str {
        let trimmed = path.trim_end_matches('/');
        match trimmed.rfind('/') {
            Some(0) => "/",
            Some(i) => &trimmed[..i],
            None => "/",
        }
    }

    fn mem_entry(path: &str, is_dir: bool, size: u64) -> crate::Entry {
        crate::Entry {
            name: mem_name_of(path).to_string(),
            path: path.to_string(),
            is_dir,
            size,
            modified_ms: 0,
            is_hidden: false,
            is_symlink: false,
        }
    }

    /// Commits its buffer to the shared map on finish, mirroring the
    /// close-time commit real network backends need.
    struct MemWriter {
        state: Arc<Mutex<MemFsState>>,
        path: String,
        buf: Vec<u8>,
    }

    impl std::io::Write for MemWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::vfs::WriteFinish for MemWriter {
        fn finish(self: Box<Self>) -> Result<(), String> {
            self.state
                .lock()
                .unwrap()
                .files
                .insert(self.path.clone(), self.buf.clone());
            Ok(())
        }
    }

    impl crate::vfs::FsBackend for MemFs {
        fn capabilities(&self) -> crate::vfs::Capabilities {
            crate::vfs::Capabilities {
                is_local: false,
                can_trash: false,
                can_watch: false,
                can_rename: self.can_rename,
                server_side_copy: false,
                preserves_permissions: false,
            }
        }

        fn list_dir(
            &self,
            path: &str,
            _opts: &crate::ListOptions,
        ) -> Result<Vec<crate::Entry>, String> {
            let state = self.state.lock().unwrap();
            let dir = if path == "/" {
                "/"
            } else {
                path.trim_end_matches('/')
            };
            if !state.dirs.contains(dir) {
                return Err(format!("not found: {path}"));
            }
            let mut entries = Vec::new();
            for d in &state.dirs {
                if d != dir && mem_parent_of(d) == dir {
                    entries.push(mem_entry(d, true, 0));
                }
            }
            for (f, bytes) in &state.files {
                if mem_parent_of(f) == dir {
                    entries.push(mem_entry(f, false, bytes.len() as u64));
                }
            }
            Ok(entries)
        }

        fn stat(&self, path: &str) -> Result<crate::Entry, String> {
            let state = self.state.lock().unwrap();
            let key = if path == "/" {
                "/"
            } else {
                path.trim_end_matches('/')
            };
            if state.dirs.contains(key) {
                return Ok(mem_entry(key, true, 0));
            }
            if let Some(bytes) = state.files.get(key) {
                return Ok(mem_entry(key, false, bytes.len() as u64));
            }
            Err(format!("not found: {path}"))
        }

        fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
            let bytes = self.file(path).ok_or_else(|| format!("not found: {path}"))?;
            Ok(Box::new(std::io::Cursor::new(bytes)))
        }

        fn create_write(
            &self,
            path: &str,
            _size_hint: Option<u64>,
        ) -> Result<Box<dyn crate::vfs::WriteFinish>, String> {
            Ok(Box::new(MemWriter {
                state: self.state.clone(),
                path: path.to_string(),
                buf: Vec::new(),
            }))
        }

        fn delete(&self, path: &str, _recursive: bool) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            if state.files.remove(path).is_some() {
                return Ok(());
            }
            if state.dirs.remove(path) {
                return Ok(());
            }
            Err(format!("not found: {path}"))
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            if let Some(bytes) = state.files.remove(from) {
                state.files.insert(to.to_string(), bytes);
                return Ok(());
            }
            if state.dirs.remove(from) {
                state.dirs.insert(to.to_string());
                return Ok(());
            }
            Err(format!("not found: {from}"))
        }

        fn mkdir(&self, path: &str) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            if state.dirs.contains(path) || state.files.contains_key(path) {
                return Err(format!("already exists: {path}"));
            }
            state.dirs.insert(path.to_string());
            Ok(())
        }
    }

    #[test]
    fn remote_rename_happy_path() {
        let router = crate::vfs::BackendRouter::new();
        let backend = Arc::new(MemFs::new());
        backend.add_dir("/dir");
        backend.add_file("/dir/old.txt", b"hi");
        router.register("fake".to_string(), backend.clone());

        let new_path = rename_item_at(&router, "sftp://fake/dir/old.txt", "new.txt").unwrap();

        assert_eq!(new_path, "sftp://fake/dir/new.txt");
        assert_eq!(backend.file("/dir/new.txt"), Some(b"hi".to_vec()));
        assert!(backend.file("/dir/old.txt").is_none());
    }

    #[test]
    fn remote_rename_refused_when_backend_disallows_it() {
        let router = crate::vfs::BackendRouter::new();
        let backend = Arc::new(MemFs::new().without_rename());
        backend.add_file("/a.txt", b"x");
        router.register("fake".to_string(), backend.clone());

        let error = rename_item_at(&router, "sftp://fake/a.txt", "b.txt").unwrap_err();

        assert_eq!(error.message, "rename is not supported on this connection");
        assert!(backend.file("/a.txt").is_some());
    }

    #[test]
    fn remote_create_folder_numbers_duplicates() {
        let router = crate::vfs::BackendRouter::new();
        let backend = Arc::new(MemFs::new());
        backend.add_dir("/dir");
        backend.add_dir("/dir/untitled folder");
        router.register("fake".to_string(), backend.clone());

        let created = create_folder_at(&router, "sftp://fake/dir", "untitled folder").unwrap();

        assert_eq!(created, "sftp://fake/dir/untitled folder 2");
    }

    #[test]
    fn remote_create_file_numbers_duplicates_into_the_stem() {
        let router = crate::vfs::BackendRouter::new();
        let backend = Arc::new(MemFs::new());
        backend.add_dir("/dir");
        backend.add_file("/dir/report.txt", b"x");
        router.register("fake".to_string(), backend.clone());

        let created = create_file_at(&router, "sftp://fake/dir", "report.txt").unwrap();

        assert_eq!(created, "sftp://fake/dir/report 2.txt");
        assert_eq!(backend.file("/dir/report 2.txt"), Some(Vec::new()));
    }

    #[test]
    fn remote_duplicate_produces_a_copy_with_the_same_content() {
        let trash = tempfile::tempdir().unwrap();
        let (engine, rx) = engine(trash.path());
        let backend = Arc::new(MemFs::new());
        backend.add_file("/photo.jpg", b"bytes");
        engine.router().register("fake".to_string(), backend.clone());

        let job = engine.duplicate(vec![PathBuf::from("sftp://fake/photo.jpg")]);
        let (_, state, errors) = wait(&rx, job);

        assert_eq!(state, JobState::Done, "errors: {errors:?}");
        assert_eq!(backend.file("/photo copy.jpg"), Some(b"bytes".to_vec()));
        assert_eq!(backend.file("/photo.jpg"), Some(b"bytes".to_vec()));
        // Duplicate records no undo for a remote item.
        assert!(engine.undo_description().is_none());
        engine.shutdown();
    }

    #[test]
    fn require_local_rejects_a_uri() {
        assert!(require_local("/Users/x/Documents").is_ok());
        let error = require_local("sftp://work/etc/hosts").unwrap_err();
        assert_eq!(error.message, "remote locations are not supported here");
    }
}
