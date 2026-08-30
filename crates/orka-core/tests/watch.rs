use orka_core::watch::{DirWatcher, WatchSink};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct TestSink {
    tx: Mutex<Sender<Vec<PathBuf>>>,
}

impl WatchSink for TestSink {
    fn directories_changed(&self, paths: Vec<PathBuf>) {
        let _ = self.tx.lock().unwrap().send(paths);
    }
}

fn watcher() -> (DirWatcher, Receiver<Vec<PathBuf>>) {
    let (tx, rx) = channel();
    let sink = Arc::new(TestSink { tx: Mutex::new(tx) });
    (DirWatcher::new(sink).unwrap(), rx)
}

/// FSEvents needs a moment before it reports changes for a new watch.
fn settle() {
    std::thread::sleep(Duration::from_millis(300));
}

fn expect_change(rx: &Receiver<Vec<PathBuf>>, dir: &PathBuf) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .expect("no change notification for the watched directory");
        let paths = rx.recv_timeout(remaining).expect("no notification in time");
        if paths.contains(dir) {
            return;
        }
    }
}

#[test]
fn file_write_notifies_the_watched_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let (watcher, rx) = watcher();
    watcher.watch(&dir).unwrap();
    settle();

    fs::write(dir.join("new.txt"), b"x").unwrap();
    expect_change(&rx, &dir);
    watcher.shutdown();
}

#[test]
fn burst_of_changes_coalesces_into_few_events() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let (watcher, rx) = watcher();
    watcher.watch(&dir).unwrap();
    settle();

    for i in 0..50 {
        fs::write(dir.join(format!("f{i}.txt")), b"x").unwrap();
    }
    expect_change(&rx, &dir);
    // Drain everything that follows; far fewer events than changes.
    let mut extra = 0;
    while rx.recv_timeout(Duration::from_millis(600)).is_ok() {
        extra += 1;
    }
    assert!(extra < 10, "expected coalescing, got {extra} extra events");
    watcher.shutdown();
}

#[test]
fn unwatch_stops_notifications_and_refcounts() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let (watcher, rx) = watcher();

    // Two watches on one directory share one platform watch.
    watcher.watch(&dir).unwrap();
    watcher.watch(&dir).unwrap();
    watcher.unwatch(&dir);
    settle();

    // One reference remains: changes still notify.
    fs::write(dir.join("a.txt"), b"x").unwrap();
    expect_change(&rx, &dir);

    watcher.unwatch(&dir);
    // Drain in-flight events from before the unwatch.
    while rx.recv_timeout(Duration::from_millis(400)).is_ok() {}

    fs::write(dir.join("b.txt"), b"x").unwrap();
    assert!(
        rx.recv_timeout(Duration::from_secs(1)).is_err(),
        "no notification after the last unwatch"
    );
    watcher.shutdown();
}
