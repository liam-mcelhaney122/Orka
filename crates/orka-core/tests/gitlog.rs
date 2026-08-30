//! Tests for the commit graph service and worktree discovery.
//!
//! Fixture repos are built with the git2 API in tempdirs. No test runs
//! a git command or touches a repo outside its tempdir.

use orka_core::git::{DirGitStatus, GitStatusService};
use orka_core::gitlog::{GitGraphService, DEFAULT_LIMIT};
use std::fs;
use std::path::Path;

fn init_repo(dir: &Path) -> git2::Repository {
    let mut opts = git2::RepositoryInitOptions::new();
    opts.initial_head("refs/heads/main");
    git2::Repository::init_opts(dir, &opts).expect("init repo")
}

fn signature() -> git2::Signature<'static> {
    git2::Signature::now("Test", "test@example.com").expect("signature")
}

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

/// Commits the index with explicit parents, for merge commits.
fn commit_with_parents(
    repo: &git2::Repository,
    message: &str,
    parents: &[&git2::Commit],
) -> git2::Oid {
    let mut index = repo.index().expect("index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let sig = signature();
    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, parents)
        .expect("commit")
}

fn committed_repo(dir: &Path) -> git2::Repository {
    let repo = init_repo(dir);
    write_file(&repo, "base.txt", "base\n");
    stage(&repo, "base.txt");
    commit(&repo, "initial");
    repo
}

fn graph_of(dir: &Path) -> Option<orka_core::gitlog::GitGraph> {
    GitGraphService::new().graph_for_dir(&dir.display().to_string(), DEFAULT_LIMIT)
}

fn status_of(dir: &Path) -> Option<DirGitStatus> {
    GitStatusService::new().status_for_dir(&dir.display().to_string())
}

#[test]
fn linear_history_has_single_lane_and_ordered_parents() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    write_file(&repo, "a.txt", "a\n");
    stage(&repo, "a.txt");
    commit(&repo, "second");
    write_file(&repo, "b.txt", "b\n");
    stage(&repo, "b.txt");
    commit(&repo, "third");

    let graph = graph_of(tmp.path()).expect("graph");
    assert_eq!(graph.branch.as_deref(), Some("main"));
    assert_eq!(graph.commits.len(), 3);
    assert!(!graph.truncated);

    // Newest first, one lane, each parent is the next row.
    assert_eq!(graph.commits[0].summary, "third");
    assert_eq!(graph.commits[1].summary, "second");
    assert_eq!(graph.commits[2].summary, "initial");
    for commit in &graph.commits {
        assert_eq!(commit.lane, 0);
    }
    assert_eq!(graph.commits[0].parents, vec![1]);
    assert_eq!(graph.commits[1].parents, vec![2]);
    assert!(graph.commits[2].parents.is_empty());
    assert!(graph.commits[0].is_head);
    assert!(!graph.commits[1].is_head);
}

#[test]
fn merge_commit_has_two_parents_and_branch_lanes() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());

    // Feature branch with one commit.
    let base = repo.head().unwrap().peel_to_commit().unwrap();
    repo.branch("feature", &base, false).expect("create branch");
    repo.checkout_tree(base.as_object(), None)
        .expect("checkout tree");
    repo.set_head("refs/heads/feature")
        .expect("switch to feature");
    write_file(&repo, "feature.txt", "feature\n");
    stage(&repo, "feature.txt");
    let feature_tip = repo
        .find_commit(commit(&repo, "feature work"))
        .expect("feature commit");

    // Back on main, then advance the feature ref. git2 commits update
    // HEAD, not the branch ref; a ref update needs the branch free.
    repo.set_head("refs/heads/main").expect("switch to main");
    repo.branch("feature", &feature_tip, true)
        .expect("advance feature");
    let main_commit = repo.find_commit(base.id()).expect("main commit");
    repo.checkout_tree(main_commit.as_object(), None)
        .expect("checkout");
    write_file(&repo, "main.txt", "main\n");
    stage(&repo, "main.txt");
    let main_tip = repo
        .find_commit(commit(&repo, "main work"))
        .expect("main commit");
    let merge_oid = commit_with_parents(&repo, "merge feature", &[&main_tip, &feature_tip]);

    let graph = graph_of(tmp.path()).expect("graph");
    assert_eq!(graph.commits[0].oid, merge_oid.to_string());
    assert_eq!(graph.commits[0].parents.len(), 2);

    // The two parents sit in different lanes: the merge pulled the
    // feature chain into its own column.
    let main_row = graph.commits[0].parents[0] as usize;
    let feature_row = graph.commits[0].parents[1] as usize;
    assert_eq!(graph.commits[main_row].summary, "main work");
    assert_eq!(graph.commits[feature_row].summary, "feature work");
    assert_ne!(
        graph.commits[main_row].lane,
        graph.commits[feature_row].lane
    );

    // Branch list carries both branches with the right flags.
    let main_branch = graph
        .branches
        .iter()
        .find(|b| b.name == "main")
        .expect("main branch");
    let feature_branch = graph
        .branches
        .iter()
        .find(|b| b.name == "feature")
        .expect("feature branch");
    assert!(main_branch.is_local && main_branch.is_head);
    assert!(feature_branch.is_local && !feature_branch.is_head);

    // Feature tip row matches where the branch points.
    assert_eq!(feature_branch.head_commit, Some(feature_row as u32));
}

#[test]
fn detached_head_marks_head_commit_without_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    let oid = repo.head().unwrap().target().unwrap();
    repo.set_head_detached(oid).expect("detach");

    let graph = graph_of(tmp.path()).expect("graph");
    assert_eq!(graph.branch, None);
    assert_eq!(graph.commits[0].oid, oid.to_string());
    assert!(graph.commits[0].is_head);
}

#[test]
fn limit_truncates_the_graph() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    for i in 0..5 {
        write_file(&repo, &format!("f{i}.txt"), "x\n");
        stage(&repo, &format!("f{i}.txt"));
        commit(&repo, &format!("commit {i}"));
    }
    let graph = GitGraphService::new()
        .graph_for_dir(&tmp.path().display().to_string(), 3)
        .unwrap();
    assert_eq!(graph.commits.len(), 3);
    assert!(graph.truncated);
}

#[test]
fn non_repo_dir_has_no_graph() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("plain.txt"), "plain\n").unwrap();
    assert_eq!(graph_of(tmp.path()), None);
}

#[test]
fn linked_worktree_reports_its_own_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = committed_repo(tmp.path());
    let worktree_parent = tempfile::tempdir().unwrap();
    let worktree_path = worktree_parent.path().join("linked");
    repo.worktree("linked", &worktree_path, None)
        .expect("add worktree");

    // The worktree checks out its own branch and reports it.
    let status = status_of(&worktree_path).expect("status");
    assert_eq!(status.branch.as_deref(), Some("linked"));

    // Dirtying a file inside the worktree shows only there.
    let wt_repo = git2::Repository::discover(&worktree_path).expect("discover");
    write_file(&wt_repo, "base.txt", "changed in worktree\n");
    let status = status_of(&worktree_path).expect("status");
    assert!(status.entries.iter().any(|(name, _)| name == "base.txt"));

    let graph = graph_of(&worktree_path).expect("graph");
    assert_eq!(graph.branch.as_deref(), Some("linked"));
    assert!(graph.commits[0].is_head);
}
