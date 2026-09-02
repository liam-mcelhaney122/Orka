use orka_core::ops::{
    create_file, create_folder, rename_item, EventSink, ItemError, JobState, OpsEngine,
    PlatformDelegate,
    Progress,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Finished = (u64, JobState, Vec<ItemError>);

struct TestSink {
    finished: Mutex<Sender<Finished>>,
}

impl EventSink for TestSink {
    fn job_progress(&self, _progress: Progress) {}
    fn job_finished(&self, job_id: u64, state: JobState, errors: Vec<ItemError>) {
        let _ = self.finished.lock().unwrap().send((job_id, state, errors));
    }
}

/// Moves items into a plain directory instead of the real trash. A counter
/// prefix keeps same-named items from colliding, like macOS does.
struct FakeTrash {
    dir: PathBuf,
    counter: AtomicU64,
}

impl PlatformDelegate for FakeTrash {
    fn trash_item(&self, path: &Path) -> Result<PathBuf, String> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dest = self.dir.join(format!("{n}-{name}"));
        fs::rename(path, &dest).map_err(|e| e.to_string())?;
        Ok(dest)
    }
}

fn engine_with_trash(trash_dir: &Path) -> (OpsEngine, Receiver<Finished>) {
    let (tx, rx) = channel();
    let sink = Arc::new(TestSink {
        finished: Mutex::new(tx),
    });
    let delegate = Arc::new(FakeTrash {
        dir: trash_dir.to_path_buf(),
        counter: AtomicU64::new(0),
    });
    (OpsEngine::new(sink, delegate), rx)
}

fn engine() -> (OpsEngine, Receiver<Finished>, tempfile::TempDir) {
    let trash = tempfile::tempdir().unwrap();
    let (engine, rx) = engine_with_trash(trash.path());
    (engine, rx, trash)
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

fn make_tree(root: &Path, files: usize) {
    fs::create_dir_all(root.join("sub")).unwrap();
    for i in 0..files {
        fs::write(root.join(format!("f{i}.txt")), format!("data{i}")).unwrap();
    }
    fs::write(root.join("sub/nested.txt"), b"nested").unwrap();
}

#[test]
fn copy_directory_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree");
    let dest_dir = tmp.path().join("out");
    make_tree(&src, 3);
    fs::create_dir(&dest_dir).unwrap();

    let (engine, rx, _trash) = engine();
    let job = engine.copy(vec![src.clone()], dest_dir.clone());
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Done, "errors: {errors:?}");
    assert_eq!(
        fs::read(dest_dir.join("tree/f0.txt")).unwrap(),
        b"data0".to_vec()
    );
    assert_eq!(
        fs::read(dest_dir.join("tree/sub/nested.txt")).unwrap(),
        b"nested".to_vec()
    );
    assert!(src.exists(), "copy must not remove the source");
}

#[test]
fn copy_conflict_fails_item_but_continues() {
    let tmp = tempfile::tempdir().unwrap();
    let dest_dir = tmp.path().join("out");
    fs::create_dir(&dest_dir).unwrap();
    fs::write(tmp.path().join("a.txt"), b"a").unwrap();
    fs::write(tmp.path().join("b.txt"), b"b").unwrap();
    fs::write(dest_dir.join("a.txt"), b"existing").unwrap();

    let (engine, rx, _trash) = engine();
    let job = engine.copy(
        vec![tmp.path().join("a.txt"), tmp.path().join("b.txt")],
        dest_dir.clone(),
    );
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Failed);
    assert_eq!(errors.len(), 1);
    // The conflicting destination is untouched; the other item copied.
    assert_eq!(
        fs::read(dest_dir.join("a.txt")).unwrap(),
        b"existing".to_vec()
    );
    assert_eq!(fs::read(dest_dir.join("b.txt")).unwrap(), b"b".to_vec());
}

#[test]
fn move_within_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let dest_dir = tmp.path().join("out");
    fs::create_dir(&dest_dir).unwrap();
    fs::write(tmp.path().join("a.txt"), b"a").unwrap();

    let (engine, rx, _trash) = engine();
    let job = engine.r#move(vec![tmp.path().join("a.txt")], dest_dir.clone());
    let (_, state, _) = wait(&rx, job);

    assert_eq!(state, JobState::Done);
    assert!(!tmp.path().join("a.txt").exists());
    assert_eq!(fs::read(dest_dir.join("a.txt")).unwrap(), b"a".to_vec());
}

#[test]
fn duplicate_names_like_finder() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("photo.jpg");
    fs::write(&file, b"x").unwrap();

    let (engine, rx, _trash) = engine();
    let job1 = engine.duplicate(vec![file.clone()]);
    wait(&rx, job1);
    let job2 = engine.duplicate(vec![file.clone()]);
    wait(&rx, job2);

    assert!(tmp.path().join("photo copy.jpg").exists());
    assert!(tmp.path().join("photo copy 2.jpg").exists());
}

#[test]
fn queued_job_can_be_cancelled_before_it_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree");
    make_tree(&src, 500);
    let dest1 = tmp.path().join("out1");
    let dest2 = tmp.path().join("out2");
    fs::create_dir(&dest1).unwrap();
    fs::create_dir(&dest2).unwrap();

    let (engine, rx, _trash) = engine();
    // Job 1 occupies the worker; job 2 is cancelled while still queued.
    let job1 = engine.copy(vec![src.clone()], dest1);
    let job2 = engine.copy(vec![src.clone()], dest2.clone());
    engine.cancel(job2);

    let (_, state1, _) = wait(&rx, job1);
    let (_, state2, _) = wait(&rx, job2);
    assert_eq!(state1, JobState::Done);
    assert_eq!(state2, JobState::Cancelled);
    assert!(
        !dest2.join("tree").exists() || fs::read_dir(dest2.join("tree")).unwrap().count() < 502
    );
}

#[test]
fn copy_into_itself_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree");
    make_tree(&src, 2);

    let (engine, rx, _trash) = engine();
    let job = engine.copy(vec![src.clone()], src.clone());
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Failed);
    assert_eq!(errors.len(), 1);
    assert!(!src.join("tree").exists());
}

#[test]
fn rename_and_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("old.txt");
    fs::write(&file, b"x").unwrap();

    let renamed = rename_item(&file, "new.txt").unwrap();
    assert_eq!(renamed, tmp.path().join("new.txt"));
    assert!(renamed.exists());

    fs::write(&file, b"y").unwrap();
    assert!(rename_item(&file, "new.txt").is_err());
    assert!(rename_item(&file, "bad/name").is_err());
}

#[test]
fn create_folder_numbers_duplicates() {
    let tmp = tempfile::tempdir().unwrap();
    let first = create_folder(tmp.path(), "untitled folder").unwrap();
    let second = create_folder(tmp.path(), "untitled folder").unwrap();
    assert_eq!(first, tmp.path().join("untitled folder"));
    assert_eq!(second, tmp.path().join("untitled folder 2"));
}

#[test]
fn create_file_numbers_duplicates_into_the_stem() {
    let tmp = tempfile::tempdir().unwrap();
    let first = create_file(tmp.path(), "untitled.txt").unwrap();
    let second = create_file(tmp.path(), "untitled.txt").unwrap();
    assert_eq!(first, tmp.path().join("untitled.txt"));
    assert_eq!(second, tmp.path().join("untitled 2.txt"));
}

#[test]
fn create_file_rejects_invalid_names() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(create_file(tmp.path(), "").is_err());
    assert!(create_file(tmp.path(), "bad/name").is_err());
}

#[test]
fn copy_preserves_symlinks_as_links() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", src.join("link.txt")).unwrap();
    let dest_dir = tmp.path().join("out");
    fs::create_dir(&dest_dir).unwrap();

    let (engine, rx, _trash) = engine();
    let job = engine.copy(vec![src], dest_dir.clone());
    let (_, state, errors) = wait(&rx, job);

    assert_eq!(state, JobState::Done, "errors: {errors:?}");
    let copied_link = dest_dir.join("tree/link.txt");
    assert!(copied_link.symlink_metadata().unwrap().is_symlink());
}

// ---------------------------------------------------------------------------
// Trash and undo
// ---------------------------------------------------------------------------

#[test]
fn trash_then_undo_restores() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a.txt");
    let b = tmp.path().join("b.txt");
    fs::write(&a, b"a").unwrap();
    fs::write(&b, b"b").unwrap();

    let (engine, rx, trash) = engine();
    let job = engine.trash(vec![a.clone(), b.clone()]);
    let (_, state, _) = wait(&rx, job);
    assert_eq!(state, JobState::Done);
    assert!(!a.exists() && !b.exists());
    assert_eq!(fs::read_dir(trash.path()).unwrap().count(), 2);
    assert_eq!(engine.undo_description(), Some("Trash of 2 Items".into()));

    let undo_job = engine.undo().expect("undo entry exists");
    let (_, state, errors) = wait(&rx, undo_job);
    assert_eq!(state, JobState::Done, "errors: {errors:?}");
    assert_eq!(fs::read(&a).unwrap(), b"a".to_vec());
    assert_eq!(fs::read(&b).unwrap(), b"b".to_vec());
    assert_eq!(engine.undo_description(), None);
    assert_eq!(engine.redo_description(), Some("Trash of 2 Items".into()));
}

#[test]
fn undo_of_copy_trashes_the_copies() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("a.txt");
    let dest_dir = tmp.path().join("out");
    fs::write(&src, b"a").unwrap();
    fs::create_dir(&dest_dir).unwrap();

    let (engine, rx, trash) = engine();
    let job = engine.copy(vec![src.clone()], dest_dir.clone());
    wait(&rx, job);
    assert!(dest_dir.join("a.txt").exists());

    let undo_job = engine.undo().expect("undo entry exists");
    let (_, state, _) = wait(&rx, undo_job);
    assert_eq!(state, JobState::Done);
    // The copy went to the trash; the source is untouched.
    assert!(!dest_dir.join("a.txt").exists());
    assert!(src.exists());
    assert_eq!(fs::read_dir(trash.path()).unwrap().count(), 1);
}

#[test]
fn undo_and_redo_of_move() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("a.txt");
    let dest_dir = tmp.path().join("out");
    fs::write(&src, b"a").unwrap();
    fs::create_dir(&dest_dir).unwrap();

    let (engine, rx, _trash) = engine();
    let job = engine.r#move(vec![src.clone()], dest_dir.clone());
    wait(&rx, job);
    assert!(!src.exists());

    let undo_job = engine.undo().expect("undo entry exists");
    let (_, state, _) = wait(&rx, undo_job);
    assert_eq!(state, JobState::Done);
    assert!(src.exists());
    assert!(!dest_dir.join("a.txt").exists());

    let redo_job = engine.redo().expect("redo entry exists");
    let (_, state, _) = wait(&rx, redo_job);
    assert_eq!(state, JobState::Done);
    assert!(!src.exists());
    assert!(dest_dir.join("a.txt").exists());
    assert_eq!(engine.undo_description(), Some("Move of 1 Item".into()));
}

#[test]
fn undo_of_rename_restores_the_name() {
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("old.txt");
    fs::write(&old, b"x").unwrap();

    let (engine, rx, _trash) = engine();
    let renamed = engine.rename(&old, "new.txt").unwrap();
    assert!(renamed.exists());
    assert_eq!(
        engine.undo_description(),
        Some("Rename of \u{201c}old.txt\u{201d}".into())
    );

    let undo_job = engine.undo().expect("undo entry exists");
    let (_, state, _) = wait(&rx, undo_job);
    assert_eq!(state, JobState::Done);
    assert!(old.exists());
    assert!(!renamed.exists());
}

#[test]
fn undo_of_new_folder_trashes_it() {
    let tmp = tempfile::tempdir().unwrap();

    let (engine, rx, trash) = engine();
    let created = engine.create_folder(tmp.path(), "untitled folder").unwrap();
    assert!(created.is_dir());
    assert_eq!(engine.undo_description(), Some("New Folder".into()));

    let undo_job = engine.undo().expect("undo entry exists");
    let (_, state, _) = wait(&rx, undo_job);
    assert_eq!(state, JobState::Done);
    assert!(!created.exists());
    assert_eq!(fs::read_dir(trash.path()).unwrap().count(), 1);
}

#[test]
fn new_operation_clears_the_redo_stack() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a.txt");
    fs::write(&a, b"a").unwrap();

    let (engine, rx, _trash) = engine();
    let job = engine.trash(vec![a.clone()]);
    wait(&rx, job);
    let undo_job = engine.undo().unwrap();
    wait(&rx, undo_job);
    assert!(engine.redo_description().is_some());

    let renamed = engine.rename(&a, "b.txt").unwrap();
    assert!(renamed.exists());
    assert_eq!(engine.redo_description(), None);
}

#[test]
fn undo_conflict_fails_item_and_keeps_data() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("a.txt");
    let dest_dir = tmp.path().join("out");
    fs::write(&src, b"moved").unwrap();
    fs::create_dir(&dest_dir).unwrap();

    let (engine, rx, _trash) = engine();
    let job = engine.r#move(vec![src.clone()], dest_dir.clone());
    wait(&rx, job);

    // A new file now blocks the original location.
    fs::write(&src, b"blocker").unwrap();
    let undo_job = engine.undo().expect("undo entry exists");
    let (_, state, errors) = wait(&rx, undo_job);
    assert_eq!(state, JobState::Failed);
    assert_eq!(errors.len(), 1);
    assert_eq!(fs::read(&src).unwrap(), b"blocker".to_vec());
    assert_eq!(fs::read(dest_dir.join("a.txt")).unwrap(), b"moved".to_vec());
}

#[test]
fn unknown_connection_fails_without_side_effects() {
    let (engine, rx, _trash) = engine();
    let dest = tempfile::tempdir().unwrap();

    let id = engine.copy(
        vec![PathBuf::from("sftp://work/etc/hosts")],
        dest.path().to_path_buf(),
    );
    let (_, state, errors) = wait(&rx, id);

    assert_eq!(state, JobState::Failed);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("unknown connection"));
    // The failed job must not enter the undo journal.
    assert!(engine.undo_description().is_none());
    assert_eq!(fs::read_dir(dest.path()).unwrap().count(), 0);
    engine.shutdown();
}
