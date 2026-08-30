use orka_core::search::{SearchEngine, SearchOptions, SearchSink};
use orka_core::Entry;
use std::fs;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Event {
    query_id: u64,
    results: Vec<Entry>,
    done: bool,
}

struct TestSink {
    tx: Mutex<Sender<Event>>,
}

impl SearchSink for TestSink {
    fn search_results(&self, query_id: u64, results: Vec<Entry>, done: bool) {
        let _ = self.tx.lock().unwrap().send(Event {
            query_id,
            results,
            done,
        });
    }
}

fn engine() -> (SearchEngine, Receiver<Event>) {
    let (tx, rx) = channel();
    let sink = Arc::new(TestSink { tx: Mutex::new(tx) });
    (SearchEngine::new(sink), rx)
}

/// Waits for the final snapshot of `id` and returns its results.
fn final_results(rx: &Receiver<Event>, id: u64) -> Vec<Entry> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("no done snapshot in time");
        let event = rx.recv_timeout(remaining).expect("no event in time");
        if event.query_id == id && event.done {
            return event.results;
        }
    }
}

fn names(results: &[Entry]) -> Vec<&str> {
    results.iter().map(|e| e.name.as_str()).collect()
}

fn write(root: &Path, rel: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"x").unwrap();
}

fn fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "report.txt");
    write(root, "notes.md");
    write(root, "photo.png");
    write(root, "sub/deep/report.txt");
    write(root, "sub/deep/summary.txt");
    write(root, ".secret.txt");
    write(root, "node_modules/pkg/inside_node_modules.txt");
    write(root, "target/debug/inside_target.txt");
    write(root, ".git/objects/inside_git.txt");
    tmp
}

fn search(engine: &SearchEngine, root: &Path, query: &str, include_hidden: bool) -> u64 {
    engine.start(
        root.to_path_buf(),
        query,
        SearchOptions {
            include_hidden,
            max_results: 500,
        },
    )
}

#[test]
fn exact_name_ranks_above_deeper_copy() {
    let tmp = fixture();
    let (engine, rx) = engine();
    let id = search(&engine, tmp.path(), "report", false);
    let results = final_results(&rx, id);
    let report_paths: Vec<&str> = results
        .iter()
        .filter(|e| e.name == "report.txt")
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(report_paths.len(), 2, "results: {:?}", names(&results));
    assert_eq!(
        report_paths[0],
        tmp.path().join("report.txt").to_str().unwrap()
    );
    // The best hit overall is the shallow exact match.
    assert_eq!(results[0].path, report_paths[0]);
}

#[test]
fn extension_filter_returns_only_matching_files() {
    let tmp = fixture();
    let (engine, rx) = engine();
    let id = search(&engine, tmp.path(), "*.txt", false);
    let results = final_results(&rx, id);
    assert!(!results.is_empty());
    assert!(results.iter().all(|e| e.name.ends_with(".txt")));
    assert!(results.iter().all(|e| !e.is_dir));
    assert!(results.iter().any(|e| e.name == "summary.txt"));
}

#[test]
fn fuzzy_and_extension_combine() {
    let tmp = fixture();
    let (engine, rx) = engine();
    let id = search(&engine, tmp.path(), "report .txt", false);
    let results = final_results(&rx, id);
    assert!(!results.is_empty());
    assert!(results.iter().all(|e| e.name.ends_with(".txt")));
    assert!(results.iter().any(|e| e.name == "report.txt"));
    assert!(!results.iter().any(|e| e.name == "notes.md"));
}

#[test]
fn skip_list_directories_never_appear() {
    let tmp = fixture();
    let (engine, rx) = engine();
    let id = search(&engine, tmp.path(), "inside", true);
    let results = final_results(&rx, id);
    assert!(
        results.is_empty(),
        "skip-list contents leaked: {:?}",
        names(&results)
    );
}

#[test]
fn hidden_files_require_include_hidden() {
    let tmp = fixture();
    let (engine, rx) = engine();

    let id = search(&engine, tmp.path(), "secret", false);
    let results = final_results(&rx, id);
    assert!(results.is_empty(), "hidden leaked: {:?}", names(&results));

    let id = search(&engine, tmp.path(), "secret", true);
    let results = final_results(&rx, id);
    assert_eq!(names(&results), vec![".secret.txt"]);
    assert!(results[0].is_hidden);
}

#[test]
fn directories_match_by_name() {
    let tmp = fixture();
    let (engine, rx) = engine();
    let id = search(&engine, tmp.path(), "deep", false);
    let results = final_results(&rx, id);
    assert!(results.iter().any(|e| e.name == "deep" && e.is_dir));
}

#[test]
fn cancel_stops_emissions() {
    let tmp = tempfile::tempdir().unwrap();
    // A wide tree keeps the walk busy long enough to observe the cancel.
    for d in 0..40 {
        for f in 0..25 {
            write(tmp.path(), &format!("dir{d}/file{f}.txt"));
        }
    }
    let (engine, rx) = engine();
    let id = engine.start(tmp.path().to_path_buf(), "file", SearchOptions::default());
    engine.cancel(id);

    // A snapshot already in flight may arrive, but never a done one.
    let deadline = Instant::now() + Duration::from_millis(500);
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(event) => assert!(!event.done, "cancelled query still finished"),
            Err(_) => break,
        }
    }
}

#[test]
fn non_local_root_finishes_empty() {
    let (engine, rx) = engine();
    let id = engine.start(
        "sftp://host/some/dir".into(),
        "report",
        SearchOptions::default(),
    );
    let results = final_results(&rx, id);
    assert!(results.is_empty());
}

#[test]
fn empty_query_finishes_empty() {
    let tmp = fixture();
    let (engine, rx) = engine();
    let id = search(&engine, tmp.path(), "   ", false);
    let results = final_results(&rx, id);
    assert!(results.is_empty());
}

#[test]
fn new_query_cancels_the_previous_one() {
    let tmp = fixture();
    let (engine, rx) = engine();
    let first = search(&engine, tmp.path(), "report", false);
    let second = search(&engine, tmp.path(), "notes", false);
    assert_ne!(first, second);
    let results = final_results(&rx, second);
    assert_eq!(names(&results), vec!["notes.md"]);
}
