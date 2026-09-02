use orka_core::sizes::{PathSize, SizeEngine, SizeSink};
use orka_core::vfs::{BackendRouter, Capabilities, FsBackend, WriteFinish};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Minimal remote backend for the folder-size walk: `list_dir` serves a
/// fixed tree, keyed by backend-local path. The other operations are
/// stubs the size walk never calls.
struct FakeRemoteFs {
    listings: HashMap<String, Vec<orka_core::Entry>>,
}

impl FsBackend for FakeRemoteFs {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            is_local: false,
            can_trash: false,
            can_watch: false,
            can_rename: false,
            server_side_copy: false,
            preserves_permissions: false,
        }
    }

    fn list_dir(&self, path: &str, _opts: &orka_core::ListOptions) -> Result<Vec<orka_core::Entry>, String> {
        self.listings
            .get(path)
            .cloned()
            .ok_or_else(|| format!("not found: {path}"))
    }

    fn stat(&self, _path: &str) -> Result<orka_core::Entry, String> {
        Err("not supported".to_string())
    }

    fn open_read(&self, _path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        Err("not supported".to_string())
    }

    fn create_write(
        &self,
        _path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        Err("not supported".to_string())
    }

    fn delete(&self, _path: &str, _recursive: bool) -> Result<(), String> {
        Err("not supported".to_string())
    }

    fn rename(&self, _from: &str, _to: &str) -> Result<(), String> {
        Err("not supported".to_string())
    }

    fn mkdir(&self, _path: &str) -> Result<(), String> {
        Err("not supported".to_string())
    }
}

fn remote_entry(path: &str, is_dir: bool, size: u64) -> orka_core::Entry {
    orka_core::Entry {
        name: path.rsplit('/').next().unwrap_or(path).to_string(),
        path: path.to_string(),
        is_dir,
        size,
        modified_ms: 0,
        is_hidden: false,
        is_symlink: false,
    }
}

struct Event {
    request_id: u64,
    sizes: Vec<PathSize>,
    done: bool,
}

struct TestSink {
    tx: Mutex<Sender<Event>>,
}

impl SizeSink for TestSink {
    fn folder_sizes(&self, request_id: u64, sizes: Vec<PathSize>, done: bool) {
        let _ = self.tx.lock().unwrap().send(Event {
            request_id,
            sizes,
            done,
        });
    }
}

fn engine() -> (SizeEngine, Receiver<Event>) {
    let (engine, rx, _router) = engine_with_router();
    (engine, rx)
}

fn engine_with_router() -> (SizeEngine, Receiver<Event>, Arc<BackendRouter>) {
    let (tx, rx) = channel();
    let sink = Arc::new(TestSink { tx: Mutex::new(tx) });
    let router = Arc::new(BackendRouter::new());
    (SizeEngine::new(sink, router.clone()), rx, router)
}

/// Collects every per-directory event of `id` until the done event.
fn collect(rx: &Receiver<Event>, id: u64) -> Vec<PathSize> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut sizes = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("no done event in time");
        let event = rx.recv_timeout(remaining).expect("no event in time");
        if event.request_id != id {
            continue;
        }
        if event.done {
            assert!(event.sizes.is_empty(), "done event must carry no sizes");
            return sizes;
        }
        sizes.extend(event.sizes);
    }
}

fn write_bytes(root: &Path, rel: &str, len: usize) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![0u8; len]).unwrap();
}

#[test]
fn totals_count_nested_and_hidden_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("folder");
    write_bytes(&dir, "a.bin", 100);
    write_bytes(&dir, "sub/b.bin", 50);
    write_bytes(&dir, "sub/deep/c.bin", 25);
    write_bytes(&dir, ".hidden", 7);

    let (engine, rx) = engine();
    let id = engine.compute(vec![dir.to_string_lossy().into_owned()]);
    let sizes = collect(&rx, id);
    assert_eq!(sizes.len(), 1);
    assert_eq!(sizes[0].path, dir.to_string_lossy());
    assert_eq!(sizes[0].bytes, 182);
    // 4 files + 2 directories.
    assert_eq!(sizes[0].items, 6);
}

#[test]
fn symlink_target_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    // The big target sits outside the sized directory. Only the link's
    // own size may count.
    let target = tmp.path().join("big_target.bin");
    fs::write(&target, vec![0u8; 10_000]).unwrap();
    let dir = tmp.path().join("folder");
    write_bytes(&dir, "a.bin", 10);
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let link_len = link.symlink_metadata().unwrap().len();
    assert!(link_len < 10_000);

    // A directory symlink must not be walked either.
    let target_dir = tmp.path().join("big_dir");
    write_bytes(&target_dir, "huge.bin", 20_000);
    let dir_link = dir.join("dir_link");
    std::os::unix::fs::symlink(&target_dir, &dir_link).unwrap();
    let dir_link_len = dir_link.symlink_metadata().unwrap().len();

    let (engine, rx) = engine();
    let id = engine.compute(vec![dir.to_string_lossy().into_owned()]);
    let sizes = collect(&rx, id);
    assert_eq!(sizes.len(), 1);
    assert_eq!(sizes[0].bytes, 10 + link_len + dir_link_len);
    // One file and two symlinks.
    assert_eq!(sizes[0].items, 3);
}

#[test]
fn each_directory_emits_one_event() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    write_bytes(&a, "x.bin", 5);
    write_bytes(&b, "y.bin", 9);
    write_bytes(&b, "sub/z.bin", 1);

    let (engine, rx) = engine();
    let id = engine.compute(vec![
        a.to_string_lossy().into_owned(),
        b.to_string_lossy().into_owned(),
    ]);
    let sizes = collect(&rx, id);
    assert_eq!(sizes.len(), 2);
    assert_eq!(sizes[0].path, a.to_string_lossy());
    assert_eq!(sizes[0].bytes, 5);
    assert_eq!(sizes[0].items, 1);
    assert_eq!(sizes[1].path, b.to_string_lossy());
    assert_eq!(sizes[1].bytes, 10);
    assert_eq!(sizes[1].items, 3);
}

#[test]
fn non_local_directories_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("local");
    write_bytes(&local, "x.bin", 3);

    let (engine, rx) = engine();
    let id = engine.compute(vec![
        "sftp://host/some/dir".to_string(),
        local.to_string_lossy().into_owned(),
    ]);
    let sizes = collect(&rx, id);
    assert_eq!(sizes.len(), 1);
    assert_eq!(sizes[0].path, local.to_string_lossy());
    assert_eq!(sizes[0].bytes, 3);
}

#[test]
fn cancel_stops_emissions() {
    let tmp = tempfile::tempdir().unwrap();
    // A wide tree keeps the walk busy long enough to observe the cancel.
    let dir = tmp.path().join("busy");
    for d in 0..40 {
        for f in 0..25 {
            write_bytes(&dir, &format!("dir{d}/file{f}.bin"), 1);
        }
    }
    let (engine, rx) = engine();
    let id = engine.compute(vec![dir.to_string_lossy().into_owned()]);
    engine.cancel(id);

    // An event already in flight may arrive, but never a done one.
    let deadline = Instant::now() + Duration::from_millis(500);
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(event) => assert!(!event.done, "cancelled request still finished"),
            Err(_) => break,
        }
    }
}

#[test]
fn concurrent_requests_both_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("folder");
    write_bytes(&dir, "x.bin", 4);

    // A listing request and a Get Info request may overlap; neither
    // may cancel the other.
    let (engine, rx) = engine();
    let first = engine.compute(vec![dir.to_string_lossy().into_owned()]);
    let second = engine.compute(vec![dir.to_string_lossy().into_owned()]);
    assert_ne!(first, second);

    // Events from both requests interleave on one channel; bucket them.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = std::collections::HashMap::new();
    let mut done = std::collections::HashSet::new();
    while done.len() < 2 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("requests did not finish in time");
        let event = rx.recv_timeout(remaining).expect("no event in time");
        if event.done {
            done.insert(event.request_id);
        } else {
            for s in event.sizes {
                *bytes.entry(event.request_id).or_insert(0) += s.bytes;
            }
        }
    }
    assert_eq!(bytes.get(&first), Some(&4));
    assert_eq!(bytes.get(&second), Some(&4));
}

#[test]
fn remote_folder_size_sums_nested_files() {
    let (engine, rx, router) = engine_with_router();
    let mut listings = HashMap::new();
    listings.insert(
        "/dir".to_string(),
        vec![
            remote_entry("/dir/a.bin", false, 10),
            remote_entry("/dir/sub", true, 0),
        ],
    );
    listings.insert(
        "/dir/sub".to_string(),
        vec![remote_entry("/dir/sub/b.bin", false, 5)],
    );
    router.register("fake".to_string(), Arc::new(FakeRemoteFs { listings }));

    let id = engine.compute(vec!["sftp://fake/dir".to_string()]);
    let sizes = collect(&rx, id);

    assert_eq!(sizes.len(), 1);
    assert_eq!(sizes[0].path, "sftp://fake/dir");
    assert_eq!(sizes[0].bytes, 15);
    // a.bin, the sub directory, and b.bin.
    assert_eq!(sizes[0].items, 3);
}
