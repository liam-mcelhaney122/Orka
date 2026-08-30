use orka_core::{list_dir, CoreError, ListOptions};
use std::fs;
use std::path::Path;

fn opts(include_hidden: bool) -> ListOptions {
    ListOptions {
        include_hidden,
        ..Default::default()
    }
}

fn names(dir: &Path, include_hidden: bool) -> Vec<String> {
    list_dir(dir, &opts(include_hidden))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

#[test]
fn sorts_directories_first_then_case_insensitive() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("banana.txt"), b"x").unwrap();
    fs::write(tmp.path().join("Apple.txt"), b"x").unwrap();
    fs::create_dir(tmp.path().join("zebra")).unwrap();
    fs::create_dir(tmp.path().join("Alpha")).unwrap();

    assert_eq!(
        names(tmp.path(), false),
        vec!["Alpha", "zebra", "Apple.txt", "banana.txt"]
    );
}

#[test]
fn hidden_files_excluded_by_default_and_included_on_request() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join(".hidden"), b"x").unwrap();
    fs::write(tmp.path().join("visible"), b"x").unwrap();

    assert_eq!(names(tmp.path(), false), vec!["visible"]);
    assert_eq!(names(tmp.path(), true), vec![".hidden", "visible"]);

    let all = list_dir(tmp.path(), &opts(true)).unwrap();
    let hidden = all.iter().find(|e| e.name == ".hidden").unwrap();
    assert!(hidden.is_hidden);
}

#[test]
fn reports_size_kind_and_mtime() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("data.bin"), vec![0u8; 1234]).unwrap();
    fs::create_dir(tmp.path().join("sub")).unwrap();

    let entries = list_dir(tmp.path(), &opts(false)).unwrap();
    let file = entries.iter().find(|e| e.name == "data.bin").unwrap();
    let dir = entries.iter().find(|e| e.name == "sub").unwrap();

    assert!(!file.is_dir);
    assert_eq!(file.size, 1234);
    assert!(file.modified_ms > 0);
    assert!(dir.is_dir);
    assert_eq!(dir.size, 0);
}

#[test]
fn dirs_only_excludes_files_but_keeps_dir_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("file.txt"), b"x").unwrap();
    fs::create_dir(tmp.path().join("sub")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("sub"), tmp.path().join("sublink")).unwrap();

    let o = ListOptions {
        include_hidden: false,
        dirs_only: true,
    };
    let names: Vec<String> = list_dir(tmp.path(), &o)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["sub", "sublink"]);
}

#[test]
fn missing_path_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");
    match list_dir(&missing, &opts(false)) {
        Err(CoreError::NotFound(p)) => assert_eq!(p, missing),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn file_path_is_not_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("plain.txt");
    fs::write(&file, b"x").unwrap();
    // macOS reports ENOTDIR; accept the Io fallback for other kernels.
    match list_dir(&file, &opts(false)) {
        Err(CoreError::NotADirectory(_)) | Err(CoreError::Io { .. }) => {}
        other => panic!("expected NotADirectory or Io, got {other:?}"),
    }
}

#[test]
fn symlink_to_directory_reports_both_flags() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("real")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).unwrap();

    let entries = list_dir(tmp.path(), &opts(false)).unwrap();
    let link = entries.iter().find(|e| e.name == "link").unwrap();
    assert!(link.is_symlink);
    assert!(link.is_dir);
}

#[test]
fn broken_symlink_still_lists() {
    let tmp = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(tmp.path().join("gone"), tmp.path().join("dangling")).unwrap();

    let entries = list_dir(tmp.path(), &opts(false)).unwrap();
    let link = entries.iter().find(|e| e.name == "dangling").unwrap();
    assert!(link.is_symlink);
    assert!(!link.is_dir);
}
