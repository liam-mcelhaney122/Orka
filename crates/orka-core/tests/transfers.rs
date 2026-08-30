//! Cross-backend transfer and permanent-delete tests. An in-memory
//! backend registered on the engine router stands in for a remote
//! server.

use orka_core::ops::{EventSink, ItemError, JobState, OpsEngine, PlatformDelegate, Progress};
use orka_core::vfs::{Capabilities, FsBackend, WriteFinish};
use orka_core::{Entry, ListOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemoryState {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
    /// Every path passed to `delete`, in call order.
    deleted: Vec<String>,
}

/// Blocks one `create_write` call so a test can cancel mid-transfer.
struct WriteGate {
    path: String,
    started: Mutex<Sender<()>>,
    release: Mutex<Receiver<()>>,
}

struct MemoryBackend {
    state: Arc<Mutex<MemoryState>>,
    /// `create_write` fails for these paths.
    fail_writes: BTreeSet<String>,
    /// `finish` fails for these paths without committing the bytes.
    fail_finish: BTreeSet<String>,
    /// `open_read` returns only this many bytes for these paths, so
    /// the stream ends before the size that `stat` reported.
    truncate_reads: BTreeMap<String, usize>,
    gate: Option<WriteGate>,
}

impl MemoryBackend {
    fn new() -> Self {
        let mut state = MemoryState::default();
        state.dirs.insert("/".to_string());
        Self {
            state: Arc::new(Mutex::new(state)),
            fail_writes: BTreeSet::new(),
            fail_finish: BTreeSet::new(),
            truncate_reads: BTreeMap::new(),
            gate: None,
        }
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

    fn deleted(&self) -> Vec<String> {
        self.state.lock().unwrap().deleted.clone()
    }
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => "/",
    }
}

fn entry_for(path: &str, is_dir: bool, size: u64) -> Entry {
    Entry {
        name: name_of(path).to_string(),
        path: path.to_string(),
        is_dir,
        size,
        modified_ms: 0,
        is_hidden: false,
        is_symlink: false,
    }
}

/// Commits its buffer to the shared map on finish. Drop is the
/// backstop for an abandoned writer, so a cancelled transfer still
/// leaves a partial file for the cleanup delete to find.
struct MemoryWriter {
    state: Arc<Mutex<MemoryState>>,
    path: String,
    buf: Vec<u8>,
    fail_finish: bool,
    finished: bool,
}

impl MemoryWriter {
    fn commit(&self) {
        self.state
            .lock()
            .unwrap()
            .files
            .insert(self.path.clone(), self.buf.clone());
    }
}

impl std::io::Write for MemoryWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl WriteFinish for MemoryWriter {
    fn finish(mut self: Box<Self>) -> Result<(), String> {
        // Finish owns the outcome; the drop below must not commit.
        self.finished = true;
        if self.fail_finish {
            return Err(format!("close failed: {}", self.path));
        }
        self.commit();
        Ok(())
    }
}

impl Drop for MemoryWriter {
    fn drop(&mut self) {
        if !self.finished {
            self.commit();
        }
    }
}

impl FsBackend for MemoryBackend {
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

    fn list_dir(&self, path: &str, _opts: &ListOptions) -> Result<Vec<Entry>, String> {
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
            if d != dir && parent_of(d) == dir {
                entries.push(entry_for(d, true, 0));
            }
        }
        for (f, bytes) in &state.files {
            if parent_of(f) == dir {
                entries.push(entry_for(f, false, bytes.len() as u64));
            }
        }
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let state = self.state.lock().unwrap();
        let key = if path == "/" {
            "/"
        } else {
            path.trim_end_matches('/')
        };
        if state.dirs.contains(key) {
            return Ok(entry_for(key, true, 0));
        }
        if let Some(bytes) = state.files.get(key) {
            return Ok(entry_for(key, false, bytes.len() as u64));
        }
        Err(format!("not found: {path}"))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        let mut bytes = self
            .file(path)
            .ok_or_else(|| format!("not found: {path}"))?;
        // A truncated stream ends cleanly, like a reader that maps a
        // lost connection to end of file.
        if let Some(len) = self.truncate_reads.get(path) {
            bytes.truncate(*len);
        }
        Ok(Box::new(std::io::Cursor::new(bytes)))
    }

    fn create_write(
        &self,
        path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        if self.fail_writes.contains(path) {
            return Err(format!("write refused: {path}"));
        }
        if let Some(gate) = &self.gate {
            if gate.path == path {
                let _ = gate.started.lock().unwrap().send(());
                let _ = gate
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10));
            }
        }
        Ok(Box::new(MemoryWriter {
            state: self.state.clone(),
            path: path.to_string(),
            buf: Vec::new(),
            fail_finish: self.fail_finish.contains(path),
            finished: false,
        }))
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if state.files.remove(path).is_some() {
            state.deleted.push(path.to_string());
            return Ok(());
        }
        if state.dirs.contains(path) {
            if !recursive {
                let has_children = state.dirs.iter().any(|d| parent_of(d) == path && d != path)
                    || state.files.keys().any(|f| parent_of(f) == path);
                if has_children {
                    return Err(format!("directory not empty: {path}"));
                }
            }
            let prefix = format!("{}/", path.trim_end_matches('/'));
            state.dirs.retain(|d| d != path && !d.starts_with(&prefix));
            state.files.retain(|f, _| !f.starts_with(&prefix));
            state.deleted.push(path.to_string());
            return Ok(());
        }
        Err(format!("not found: {path}"))
    }

    fn rename(&self, _from: &str, _to: &str) -> Result<(), String> {
        Err("unsupported".into())
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if state.dirs.contains(path) || state.files.contains_key(path) {
            return Err(format!("already exists: {path}"));
        }
        if !state.dirs.contains(parent_of(path)) {
            return Err(format!("parent missing: {path}"));
        }
        state.dirs.insert(path.to_string());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type Finished = (u64, JobState, Vec<ItemError>);

struct TestSink {
    finished: Mutex<Sender<Finished>>,
    progress_events: AtomicU64,
}

impl EventSink for TestSink {
    fn job_progress(&self, _progress: Progress) {
        self.progress_events.fetch_add(1, Ordering::Relaxed);
    }

    fn job_finished(&self, job_id: u64, state: JobState, errors: Vec<ItemError>) {
        let _ = self.finished.lock().unwrap().send((job_id, state, errors));
    }
}

/// Transfers and deletes never touch the trash.
struct NoTrash;

impl PlatformDelegate for NoTrash {
    fn trash_item(&self, _path: &Path) -> Result<PathBuf, String> {
        Err("trash is unavailable in transfer tests".into())
    }
}

fn engine_with(mock: Arc<MemoryBackend>) -> (OpsEngine, Receiver<Finished>, Arc<TestSink>) {
    let (tx, rx) = channel();
    let sink = Arc::new(TestSink {
        finished: Mutex::new(tx),
        progress_events: AtomicU64::new(0),
    });
    let engine = OpsEngine::new(sink.clone(), Arc::new(NoTrash));
    engine
        .router()
        .register("mock".to_string(), mock as Arc<dyn FsBackend>);
    (engine, rx, sink)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn upload_local_tree_to_mock() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("data");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    fs::write(src.join("b.txt"), b"beta").unwrap();
    fs::write(src.join("sub/nested.txt"), b"nested").unwrap();

    let mock = Arc::new(MemoryBackend::new());
    let (engine, rx, sink) = engine_with(mock.clone());
    let job = engine.copy(vec![src], PathBuf::from("sftp://mock/"));
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Done, "errors: {errors:?}");
    assert_eq!(mock.file("/data/a.txt").unwrap(), b"alpha".to_vec());
    assert_eq!(mock.file("/data/b.txt").unwrap(), b"beta".to_vec());
    assert_eq!(
        mock.file("/data/sub/nested.txt").unwrap(),
        b"nested".to_vec()
    );
    assert!(sink.progress_events.load(Ordering::Relaxed) > 0);
    // Remote transfers record no undo.
    assert!(engine.undo_description().is_none());
    engine.shutdown();
}

#[test]
fn download_mock_tree_to_local() {
    // Multiple chunks: the file is larger than the 256 KiB chunk size.
    let big: Vec<u8> = (0..600_000u32).map(|i| (i % 251) as u8).collect();
    let mock = Arc::new(MemoryBackend::new());
    mock.add_dir("/src");
    mock.add_dir("/src/sub");
    mock.add_file("/src/a.bin", &big);
    mock.add_file("/src/sub/b.txt", b"small");

    let tmp = tempfile::tempdir().unwrap();
    let (engine, rx, _sink) = engine_with(mock);
    let job = engine.copy(
        vec![PathBuf::from("sftp://mock/src")],
        tmp.path().to_path_buf(),
    );
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Done, "errors: {errors:?}");
    assert_eq!(fs::read(tmp.path().join("src/a.bin")).unwrap(), big);
    assert_eq!(
        fs::read(tmp.path().join("src/sub/b.txt")).unwrap(),
        b"small".to_vec()
    );
    engine.shutdown();
}

#[test]
fn cancel_mid_transfer_removes_partial_dest() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("data");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("a.txt"), b"first").unwrap();
    fs::write(src.join("b.txt"), b"second").unwrap();

    let (started_tx, started_rx) = channel();
    let (release_tx, release_rx) = channel();
    let mut mock = MemoryBackend::new();
    mock.gate = Some(WriteGate {
        path: "/data/a.txt".to_string(),
        started: Mutex::new(started_tx),
        release: Mutex::new(release_rx),
    });
    let mock = Arc::new(mock);

    let (engine, rx, _sink) = engine_with(mock.clone());
    let job = engine.copy(vec![src], PathBuf::from("sftp://mock/"));
    started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("gated write never started");
    engine.cancel(job);
    release_tx.send(()).unwrap();
    let (_, state, _) = wait(&rx, job);

    assert_eq!(state, JobState::Cancelled);
    // The partial destination is gone and the later file never started.
    assert!(mock.file("/data/a.txt").is_none());
    assert!(mock.file("/data/b.txt").is_none());
    assert!(mock.deleted().contains(&"/data/a.txt".to_string()));
    engine.shutdown();
}

#[test]
fn move_to_mock_removes_only_copied_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a.txt");
    let b = tmp.path().join("b.txt");
    fs::write(&a, b"moves").unwrap();
    fs::write(&b, b"stays").unwrap();

    let mock = Arc::new(MemoryBackend::new());
    // The pre-existing destination makes b.txt a conflict.
    mock.add_file("/b.txt", b"existing");

    let (engine, rx, _sink) = engine_with(mock.clone());
    let job = engine.r#move(vec![a.clone(), b.clone()], PathBuf::from("sftp://mock/"));
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Failed);
    assert_eq!(errors.len(), 1);
    assert!(!a.exists(), "the copied source must be removed");
    assert!(b.exists(), "the conflicting source must stay");
    assert_eq!(mock.file("/a.txt").unwrap(), b"moves".to_vec());
    assert_eq!(mock.file("/b.txt").unwrap(), b"existing".to_vec());
    assert!(engine.undo_description().is_none());
    engine.shutdown();
}

#[test]
fn delete_job_removes_items_and_records_no_undo() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("y.txt");
    fs::write(&local, b"local").unwrap();

    let mock = Arc::new(MemoryBackend::new());
    mock.add_dir("/nest");
    mock.add_file("/x.txt", b"remote");
    mock.add_file("/nest/deep.txt", b"deep");

    let (engine, rx, _sink) = engine_with(mock.clone());
    let job = engine.delete(vec![
        PathBuf::from("sftp://mock/x.txt"),
        PathBuf::from("sftp://mock/nest"),
        local.clone(),
    ]);
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Done, "errors: {errors:?}");
    assert!(mock.file("/x.txt").is_none());
    assert!(mock.file("/nest/deep.txt").is_none());
    assert!(!local.exists());
    // A permanent delete never enters the undo journal.
    assert!(engine.undo_description().is_none());
    engine.shutdown();
}

#[test]
fn failing_create_write_errors_item_and_continues() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("bad.txt");
    let good = tmp.path().join("good.txt");
    fs::write(&bad, b"refused").unwrap();
    fs::write(&good, b"accepted").unwrap();

    let mut mock = MemoryBackend::new();
    mock.fail_writes.insert("/bad.txt".to_string());
    let mock = Arc::new(mock);

    let (engine, rx, _sink) = engine_with(mock.clone());
    let job = engine.copy(vec![bad, good], PathBuf::from("sftp://mock/"));
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Failed);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("write refused"));
    assert!(mock.file("/bad.txt").is_none());
    assert_eq!(mock.file("/good.txt").unwrap(), b"accepted".to_vec());
    engine.shutdown();
}

#[test]
fn symlink_sources_error_per_item() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("data");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", src.join("link.txt")).unwrap();

    let mock = Arc::new(MemoryBackend::new());
    let (engine, rx, _sink) = engine_with(mock.clone());
    let job = engine.copy(vec![src], PathBuf::from("sftp://mock/"));
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Failed);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("symlinks are not transferred"));
    assert_eq!(mock.file("/data/real.txt").unwrap(), b"real".to_vec());
    assert!(mock.file("/data/link.txt").is_none());
    engine.shutdown();
}
