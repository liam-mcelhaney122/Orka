//! File operations engine.
//!
//! Jobs run FIFO on one worker thread. Each job is cancellable and reports
//! progress through an [`EventSink`]. All events for one engine are emitted
//! from the worker thread, so their order is deterministic and calls never
//! overlap.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    next_id: AtomicU64,
    cancel_flags: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    journal: Arc<Mutex<Journal>>,
    /// Not used by local jobs yet. Remote transfers route through it in
    /// a later milestone.
    router: Arc<crate::vfs::BackendRouter>,
}

impl OpsEngine {
    pub fn new(sink: Arc<dyn EventSink>, delegate: Arc<dyn PlatformDelegate>) -> Self {
        let (tx, rx) = channel::<WorkerMessage>();
        let journal = Arc::new(Mutex::new(Journal::default()));
        let worker_journal = journal.clone();
        let router = Arc::new(crate::vfs::BackendRouter::new());
        let worker_router = router.clone();
        let worker = std::thread::Builder::new()
            .name("orka-ops".into())
            .spawn(move || {
                while let Ok(WorkerMessage::Run(job)) = rx.recv() {
                    run_job(
                        &job,
                        sink.as_ref(),
                        delegate.as_ref(),
                        &worker_journal,
                        &worker_router,
                    );
                }
            })
            .expect("spawn ops worker");
        Self {
            tx,
            next_id: AtomicU64::new(1),
            cancel_flags: Mutex::new(HashMap::new()),
            worker: Mutex::new(Some(worker)),
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

    /// Synchronous rename with an undo entry.
    pub fn rename(&self, path: &Path, new_name: &str) -> Result<PathBuf, ItemError> {
        let old_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dest = rename_item(path, new_name)?;
        self.push_undo(UndoEntry {
            description: format!("Rename of \u{201c}{old_name}\u{201d}"),
            actions: vec![UndoAction::Move {
                from: dest.clone(),
                to: path.to_path_buf(),
            }],
        });
        Ok(dest)
    }

    /// Synchronous folder creation with an undo entry.
    pub fn create_folder(&self, parent: &Path, name: &str) -> Result<PathBuf, ItemError> {
        let created = create_folder(parent, name)?;
        self.push_undo(UndoEntry {
            description: "New Folder".to_string(),
            actions: vec![UndoAction::Trash {
                path: created.clone(),
            }],
        });
        Ok(created)
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

    /// Stops the worker after the current job. Call before the app exits so
    /// no event fires into a dead runtime.
    pub fn shutdown(&self) {
        let _ = self.tx.send(WorkerMessage::Shutdown);
        if let Some(handle) = self.worker.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    fn enqueue(&self, kind: OpKind, description: String) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel_flags.lock().unwrap().insert(id, cancel.clone());
        let _ = self.tx.send(WorkerMessage::Run(Job {
            id,
            kind,
            description,
            cancel,
        }));
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

/// Renames an item inside its directory. Synchronous: a single atomic
/// `rename(2)`; the UI needs the result inline.
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
/// like Finder's "untitled folder" behavior.
pub fn create_folder(parent: &Path, name: &str) -> Result<PathBuf, ItemError> {
    let mut candidate = parent.join(name);
    let mut counter = 2;
    while candidate.symlink_metadata().is_ok() {
        candidate = parent.join(format!("{name} {counter}"));
        counter += 1;
    }
    std::fs::create_dir(&candidate).map_err(|e| item_error(parent, &e.to_string()))?;
    Ok(candidate)
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
            OpKind::Duplicate { .. }
            | OpKind::Trash { .. }
            | OpKind::Archive { .. }
            | OpKind::Extract { .. } => {
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
                copy_item(&mut ctx, source, &dest);
                // Record only items this job created. A conflict leaves a
                // pre-existing destination; undo must never trash it.
                if ctx.errors.len() == errors_before && dest.symlink_metadata().is_ok() {
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
                move_item(&mut ctx, source, &dest);
                if ctx.errors.len() == errors_before && !ctx.cancelled() {
                    ctx.recorded.push(UndoAction::Move {
                        from: dest,
                        to: source.clone(),
                    });
                }
            }
        }
        OpKind::Duplicate { sources } => {
            for source in sources {
                if ctx.cancelled() {
                    break;
                }
                match duplicate_name(source) {
                    Ok(dest) => {
                        let errors_before = ctx.errors.len();
                        copy_item(&mut ctx, source, &dest);
                        if ctx.errors.len() == errors_before && dest.symlink_metadata().is_ok() {
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
        OpKind::Extract { archive } => {
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
                    match crate::archives::extract(archive, &dest_dir, &mut progress, &cancel_check)
                    {
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
        OpKind::Trash { sources } => {
            for source in sources {
                if ctx.cancelled() {
                    break;
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
                        move_item(&mut ctx, from, to);
                        if ctx.errors.len() == errors_before && !ctx.cancelled() {
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

    let state = if ctx.cancelled() {
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

fn copy_item(ctx: &mut JobContext, source: &Path, dest: &Path) {
    if dest.starts_with(source) {
        ctx.fail_item(source, "cannot copy a folder into itself");
        return;
    }
    if dest.symlink_metadata().is_ok() {
        ctx.fail_item(dest, "an item with this name already exists");
        return;
    }
    let Ok(meta) = source.symlink_metadata() else {
        ctx.fail_item(source, "source no longer exists");
        return;
    };
    if meta.is_dir() {
        copy_dir(ctx, source, dest);
    } else {
        match clone_or_copy_file(source, dest) {
            Ok(()) => ctx.item_finished(source, meta.len()),
            Err(message) => ctx.fail_item(source, &message),
        }
    }
}

fn copy_dir(ctx: &mut JobContext, source: &Path, dest: &Path) {
    if let Err(e) = std::fs::create_dir(dest) {
        ctx.fail_item(dest, &e.to_string());
        return;
    }
    ctx.item_finished(source, 0);
    let Ok(read) = std::fs::read_dir(source) else {
        ctx.fail_item(source, "cannot read directory");
        return;
    };
    for entry in read.flatten() {
        if ctx.cancelled() {
            return;
        }
        let child_source = entry.path();
        let child_dest = dest.join(entry.file_name());
        let Ok(meta) = child_source.symlink_metadata() else {
            continue;
        };
        if meta.is_dir() {
            copy_dir(ctx, &child_source, &child_dest);
        } else {
            match clone_or_copy_file(&child_source, &child_dest) {
                Ok(()) => ctx.item_finished(&child_source, meta.len()),
                Err(message) => ctx.fail_item(&child_source, &message),
            }
        }
    }
}

fn move_item(ctx: &mut JobContext, source: &Path, dest: &Path) {
    if dest.symlink_metadata().is_ok() {
        ctx.fail_item(dest, "an item with this name already exists");
        return;
    }
    match std::fs::rename(source, dest) {
        Ok(()) => {
            let bytes = dest.symlink_metadata().map(|m| m.len()).unwrap_or(0);
            ctx.item_finished(source, bytes);
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            // Cross-volume move: copy, then remove the source on success.
            let errors_before = ctx.errors.len();
            copy_item(ctx, source, dest);
            if ctx.errors.len() == errors_before && !ctx.cancelled() {
                if let Err(e) = remove_recursively(source) {
                    ctx.fail_item(source, &e);
                }
            }
        }
        Err(e) => ctx.fail_item(source, &e.to_string()),
    }
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
    let stem = source
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = source
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = source.parent().unwrap_or(Path::new("."));
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

// ---------------------------------------------------------------------------
// copyfile(3): APFS clones when possible; preserves xattrs, ACLs, and
// resource forks; copies symlinks as links, not their targets.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub(crate) fn clone_or_copy_file(source: &Path, dest: &Path) -> Result<(), String> {
    // Flag values from <copyfile.h>.
    const COPYFILE_ALL: u32 = 0x0F; // ACL | STAT | XATTR | DATA
    const COPYFILE_NOFOLLOW: u32 = (1 << 18) | (1 << 19);
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
            COPYFILE_ALL | COPYFILE_NOFOLLOW | COPYFILE_CLONE,
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
        assert_eq!(errors[0].message, "not supported for remote items");
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
}
