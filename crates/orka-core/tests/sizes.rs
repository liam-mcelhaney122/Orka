use orka_core::sizes::{PathSize, SizeEngine, SizeSink};
use std::fs;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    let (tx, rx) = channel();
    let sink = Arc::new(TestSink { tx: Mutex::new(tx) });
    (SizeEngine::new(sink), rx)
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
