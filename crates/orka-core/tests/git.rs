//! Tests for per-directory git status.
//!
//! Fixture repos are built with the git2 API in tempdirs. No test runs
//! a git command or touches a repo outside its tempdir.

use orka_core::git::{DirGitStatus, FileGitState, GitStatusService};
use std::fs;
use std::path::Path;

/// Creates a repo with initial branch "main" so branch assertions do
/// not depend on the user's git config.
fn init_repo(dir: &Path) -> git2::Repository {
    let mut opts = git2::RepositoryInitOptions::new();
    opts.initial_head("refs/heads/main");
    git2::Repository::init_opts(dir, &opts).expect("init repo")
}

fn signature() -> git2::Signature<'static> {
    git2::Signature::now("Test", "test@example.com").expect("signature")
}

/// Writes `content` to `rel` under the work tree, creating parents.
fn write_file(repo: &git2::Repository, rel: &str, content: &str) {
    let path = repo.workdir().unwrap().join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parents");
    }
    fs::write(path, content).expect("write file");
}

fn stage(repo: &git2::Repository, rel: &str) {
    let mut index = repo.index().expect("index");
    index.add_path(Path::new(rel)).expect("add path");
    index.write().expect("write index");
}

/// Commits the current index to HEAD.
fn commit(repo: &git2::Repository, message: &str) -> git2::Oid {
    let mut index = repo.index().expect("index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let sig = signature();
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)
        .expect("commit")
}

/// Repo with one committed file at the root.
fn committed_repo(dir: &Path) -> git2::Repository {
    let repo = init_repo(dir);
    write_file(&repo, "base.txt", "base\n");
    stage(&repo, "base.txt");
    commit(&repo, "initial");
    repo
}

fn status_of(dir: &Path) -> Option<DirGitStatus> {
    GitStatusService::new().status_for_dir(&dir.display().to_string())
}

fn entry_state(status: &DirGitStatus, name: &str) -> Option<FileGitState> {
    status
        .entries
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, s)| *s)
}

#[test]
fn clean_repo_reports_branch_and_no_entries() {
    let tmp = tempfile::tempdir().unwrap();
    committed_repo(tmp.path());
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(status.branch.as_deref(), Some("main"));
    assert_eq!(status.head_short.len(), 7);
    assert!(status.entries.is_empty(), "entries: {:?}", status.entries);
}

#[test]
fn modified_file_reports_modified() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, "base.txt", "changed\n");
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(
        entry_state(&status, "base.txt"),
        Some(FileGitState::Modified)
    );
}

#[test]
fn staged_new_file_reports_staged() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, "new.txt", "new\n");
    stage(&repo, "new.txt");
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(entry_state(&status, "new.txt"), Some(FileGitState::Staged));
}

#[test]
fn staged_then_edited_reports_staged_and_modified() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, "new.txt", "new\n");
    stage(&repo, "new.txt");
    write_file(&repo, "new.txt", "edited after staging\n");
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(
        entry_state(&status, "new.txt"),
        Some(FileGitState::StagedAndModified)
    );
}

#[test]
fn untracked_file_reports_untracked() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, "loose.txt", "loose\n");
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(
        entry_state(&status, "loose.txt"),
        Some(FileGitState::Untracked)
    );
}

#[test]
fn ignored_file_reports_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, ".gitignore", "ignored.txt\n");
    stage(&repo, ".gitignore");
    commit(&repo, "add gitignore");
    write_file(&repo, "ignored.txt", "ignored\n");
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(
        entry_state(&status, "ignored.txt"),
        Some(FileGitState::Ignored)
    );
}

#[test]
fn deep_dirty_file_rolls_up_to_top_level_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, "outer/inner/deep.txt", "deep\n");
    stage(&repo, "outer/inner/deep.txt");
    commit(&repo, "add deep file");
    write_file(&repo, "outer/inner/deep.txt", "changed\n");
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(entry_state(&status, "outer"), Some(FileGitState::Modified));
    assert_eq!(status.entries.len(), 1, "entries: {:?}", status.entries);
}

#[test]
fn non_repo_dir_reports_none() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("plain.txt"), "plain\n").unwrap();
    assert_eq!(status_of(tmp.path()), None);
}

#[test]
fn subdirectory_listing_reports_only_its_subtree() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, "sub/kept.txt", "kept\n");
    stage(&repo, "sub/kept.txt");
    commit(&repo, "add sub");
    // Dirty file inside the listed subdir; untracked file outside it.
    write_file(&repo, "sub/kept.txt", "changed\n");
    write_file(&repo, "outside.txt", "outside\n");
    let status = status_of(&tmp.path().join("sub")).expect("status");
    assert_eq!(
        entry_state(&status, "kept.txt"),
        Some(FileGitState::Modified)
    );
    assert_eq!(status.entries.len(), 1, "entries: {:?}", status.entries);
}

#[test]
fn glob_characters_in_directory_names_match_literally() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    // Pathspecs are fnmatch patterns; "app [old]" must match itself.
    write_file(&repo, "app [old]/kept.txt", "kept\n");
    stage(&repo, "app [old]/kept.txt");
    commit(&repo, "add glob dir");
    write_file(&repo, "app [old]/kept.txt", "changed\n");
    let status = status_of(&tmp.path().join("app [old]")).expect("status");
    assert_eq!(
        entry_state(&status, "kept.txt"),
        Some(FileGitState::Modified)
    );
}

#[test]
fn detached_head_reports_no_branch_and_short_oid() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    let oid = repo.head().unwrap().target().unwrap();
    repo.set_head_detached(oid).expect("detach");
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(status.branch, None);
    assert_eq!(status.head_short, oid.to_string()[..7]);
}

#[test]
fn unborn_head_reports_default_branch() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let status = status_of(tmp.path()).expect("status");
    assert_eq!(status.branch.as_deref(), Some("main"));
    assert_eq!(status.head_short, "");
}
