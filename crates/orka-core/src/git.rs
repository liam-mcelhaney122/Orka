//! Read-only git status for one listed directory.
//!
//! [`GitStatusService`] maps a directory to the repo state of its direct
//! children. Deeper status paths roll up to their top-level child. The
//! service caches results briefly; the watch pipeline invalidates them.

use crate::vfs::VPath;
use git2::{BranchType, Repository, Status, StatusOptions};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fresh results stay valid this long between watch invalidations.
const RESULT_TTL: Duration = Duration::from_secs(2);
/// Branch-only fallback lifetime for repos with slow status calls.
const SLOW_TTL: Duration = Duration::from_secs(60);
/// A status call slower than this marks the repo as slow.
const SLOW_THRESHOLD: Duration = Duration::from_millis(400);
/// Cap for each cache map. Overflow drops the whole map; a rebuild is cheap.
const CACHE_CAP: usize = 256;

/// Git state of one child of the listed directory. Clean children have
/// no state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileGitState {
    Modified,
    Staged,
    StagedAndModified,
    Untracked,
    Ignored,
    Conflicted,
}

impl FileGitState {
    /// Precedence when multiple statuses roll up to one child.
    fn rank(self) -> u8 {
        match self {
            FileGitState::Conflicted => 5,
            FileGitState::StagedAndModified => 4,
            FileGitState::Modified => 3,
            FileGitState::Staged => 2,
            FileGitState::Untracked => 1,
            FileGitState::Ignored => 0,
        }
    }
}

/// Git status for one listed directory.
#[derive(Debug, Clone, PartialEq)]
pub struct DirGitStatus {
    pub repo_root: String,
    /// Branch name. `None` means detached HEAD.
    pub branch: Option<String>,
    /// Short OID for detached display. Empty on an unborn HEAD.
    pub head_short: String,
    /// Child name in the listed dir -> state. Clean children absent.
    pub entries: Vec<(String, FileGitState)>,
}

#[derive(Default)]
struct Caches {
    /// Canonical dir -> canonical work tree root.
    roots: HashMap<PathBuf, PathBuf>,
    /// Canonical dirs with no repo (or a bare repo) around them.
    non_repos: HashSet<PathBuf>,
    /// (repo root, dir relative to root) -> cached result.
    results: HashMap<(PathBuf, PathBuf), (Instant, DirGitStatus)>,
    /// Repo roots with slow status calls -> branch-only fallback.
    slow: HashMap<PathBuf, (Instant, DirGitStatus)>,
}

/// Computes and caches per-directory git status.
///
/// The service never holds a `git2::Repository` across calls. A repo
/// open per call is cheap and `Repository` is not `Sync`.
#[derive(Default)]
pub struct GitStatusService {
    caches: Mutex<Caches>,
}

enum Computed {
    Full(DirGitStatus),
    /// The status call exceeded [`SLOW_THRESHOLD`]; entries are empty.
    Slow(DirGitStatus),
}

impl GitStatusService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the git status for the direct children of `dir`.
    /// Returns `None` when `dir` is remote, not inside a work tree, or
    /// inside a bare repo.
    pub fn status_for_dir(&self, dir: &str) -> Option<DirGitStatus> {
        if !VPath::parse(dir).is_local() {
            return None;
        }
        // Canonicalize so cache keys and prefix math survive symlinked
        // paths such as /tmp on macOS.
        let dir = std::fs::canonicalize(dir).ok()?;

        let cached_root = {
            let caches = self.caches.lock().unwrap();
            if caches.non_repos.contains(&dir) {
                return None;
            }
            caches.roots.get(&dir).cloned()
        };
        let root = match cached_root {
            Some(root) => root,
            None => match discover_root(&dir) {
                Some(root) => {
                    let mut caches = self.caches.lock().unwrap();
                    if caches.roots.len() >= CACHE_CAP {
                        caches.roots.clear();
                    }
                    caches.roots.insert(dir.clone(), root.clone());
                    root
                }
                None => {
                    let mut caches = self.caches.lock().unwrap();
                    if caches.non_repos.len() >= CACHE_CAP {
                        caches.non_repos.clear();
                    }
                    caches.non_repos.insert(dir);
                    return None;
                }
            },
        };
        let rel = dir.strip_prefix(&root).ok()?.to_path_buf();

        {
            let caches = self.caches.lock().unwrap();
            if let Some((at, status)) = caches.slow.get(&root) {
                if at.elapsed() < SLOW_TTL {
                    return Some(status.clone());
                }
            }
            if let Some((at, status)) = caches.results.get(&(root.clone(), rel.clone())) {
                if at.elapsed() < RESULT_TTL {
                    return Some(status.clone());
                }
            }
        }

        let computed = compute_status(&root, &rel);
        let mut caches = self.caches.lock().unwrap();
        match computed {
            Some(Computed::Full(status)) => {
                if caches.results.len() >= CACHE_CAP {
                    caches.results.clear();
                }
                caches
                    .results
                    .insert((root, rel), (Instant::now(), status.clone()));
                Some(status)
            }
            Some(Computed::Slow(status)) => {
                if caches.slow.len() >= CACHE_CAP {
                    caches.slow.clear();
                }
                caches.slow.insert(root, (Instant::now(), status.clone()));
                Some(status)
            }
            None => {
                // The cached root went stale; rediscover next call.
                caches.roots.remove(&dir);
                None
            }
        }
    }

    /// Drops cached state affected by a filesystem change at `changed`.
    pub fn invalidate_under(&self, changed: &str) {
        let changed = Path::new(changed);
        let changed = std::fs::canonicalize(changed).unwrap_or_else(|_| changed.to_path_buf());
        let mut caches = self.caches.lock().unwrap();
        caches
            .results
            .retain(|(root, _), _| !changed.starts_with(root));
        caches.slow.retain(|root, _| !changed.starts_with(root));
        // A change can create or delete a repo, so the negative entries
        // near the change are no longer trustworthy.
        caches
            .non_repos
            .retain(|dir| !(changed.starts_with(dir) || dir.starts_with(&changed)));
    }
}

/// Finds the canonical work tree root above `dir`. `None` for non-repo
/// dirs and bare repos.
pub(crate) fn discover_root(dir: &Path) -> Option<PathBuf> {
    let repo = Repository::discover(dir).ok()?;
    let workdir = repo.workdir()?.to_path_buf();
    Some(std::fs::canonicalize(&workdir).unwrap_or(workdir))
}

fn compute_status(root: &Path, rel: &Path) -> Option<Computed> {
    let repo = Repository::open(root).ok()?;
    let (branch, head_short) = head_info(&repo);
    let repo_root = root.display().to_string();

    let mut opts = StatusOptions::new();
    opts.include_untracked(true)
        .include_ignored(true)
        .recurse_untracked_dirs(false)
        .update_index(false);
    let rel_str = rel.to_string_lossy();
    // An empty pathspec matches nothing; omit it for the repo root.
    // Literal matching is required: fnmatch mode silently matches
    // nothing when the directory name contains glob characters, even
    // with backslash escaping. A literal directory pathspec still
    // prefix-matches its whole subtree.
    if !rel_str.is_empty() {
        opts.disable_pathspec_match(true);
        opts.pathspec(rel_str.as_ref());
    }

    let started = Instant::now();
    let statuses = repo.statuses(Some(&mut opts)).ok()?;
    if started.elapsed() > SLOW_THRESHOLD {
        return Some(Computed::Slow(DirGitStatus {
            repo_root,
            branch,
            head_short,
            entries: Vec::new(),
        }));
    }

    let prefix = if rel_str.is_empty() {
        String::new()
    } else {
        format!("{}/", rel_str)
    };
    let mut by_child: HashMap<String, FileGitState> = HashMap::new();
    for entry in statuses.iter() {
        let Ok(path) = entry.path() else { continue };
        let sub = match path.strip_prefix(prefix.as_str()) {
            Some(sub) => sub.trim_end_matches('/'),
            None => continue,
        };
        // An untracked or ignored listed dir reports as itself; it has
        // no child to mark.
        if sub.is_empty() {
            continue;
        }
        let (name, is_descendant) = match sub.find('/') {
            Some(i) => (&sub[..i], true),
            None => (sub, false),
        };
        let Some(mut state) = state_for(entry.status()) else {
            continue;
        };
        if is_descendant {
            match state {
                FileGitState::Conflicted => {}
                // An ignored descendant does not dirty the child.
                FileGitState::Ignored => continue,
                // Any dirty descendant marks the child folder Modified.
                _ => state = FileGitState::Modified,
            }
        }
        by_child
            .entry(name.to_string())
            .and_modify(|prev| {
                if state.rank() > prev.rank() {
                    *prev = state;
                }
            })
            .or_insert(state);
    }
    let mut entries: Vec<(String, FileGitState)> = by_child.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    Some(Computed::Full(DirGitStatus {
        repo_root,
        branch,
        head_short,
        entries,
    }))
}

/// Branch name and short OID for HEAD. Detached HEAD gives no branch.
/// An unborn HEAD gives the default branch name and an empty OID.
fn head_info(repo: &Repository) -> (Option<String>, String) {
    match repo.head() {
        Ok(head) => {
            let short = head
                .target()
                .map(|oid| oid.to_string()[..7].to_string())
                .unwrap_or_default();
            if repo.head_detached().unwrap_or(false) {
                (None, short)
            } else {
                (head.shorthand().ok().map(str::to_owned), short)
            }
        }
        Err(_) => {
            let name = repo
                .find_reference("HEAD")
                .ok()
                .and_then(|r| r.symbolic_target().ok().flatten().map(str::to_owned))
                .map(|target| target.trim_start_matches("refs/heads/").to_string());
            (name, String::new())
        }
    }
}

/// One branch in the repository. Remote-tracking branches carry their
/// short name without the `origin/` prefix stripped; the name is the
/// reference shorthand verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchEntry {
    pub name: String,
    pub is_head: bool,
    pub is_local: bool,
}

/// Why a branch switch failed.
#[derive(Debug, thiserror::Error)]
pub enum BranchError {
    #[error("branch not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Checkout(String),
}

/// Lists every local and remote-tracking branch of the repo around
/// `dir`. Local branches come first, both groups sorted by name.
pub fn list_branches(dir: &str) -> Option<Vec<BranchEntry>> {
    if !VPath::parse(dir).is_local() {
        return None;
    }
    let dir = std::fs::canonicalize(dir).ok()?;
    let repo = Repository::discover(&dir).ok()?;
    let head = repo.head().ok().and_then(|h| h.shorthand().ok().map(str::to_owned));

    let mut branches = Vec::new();
    for (kind, is_local) in [(BranchType::Local, true), (BranchType::Remote, false)] {
        let iter = repo.branches(Some(kind)).ok()?;
        let mut group: Vec<BranchEntry> = Vec::new();
        for entry in iter.flatten() {
            let (branch_ref, _) = entry;
            let Ok(Some(name)) = branch_ref.name() else {
                continue;
            };
            group.push(BranchEntry {
                name: name.to_string(),
                is_head: is_local && head.as_deref() == Some(name),
                is_local,
            });
        }
        group.sort_by(|a, b| a.name.cmp(&b.name));
        branches.extend(group);
    }
    Some(branches)
}

/// Checks out the local branch `name` in the repo around `dir`.
///
/// When `create` is set and the branch does not exist, it is created
/// from `base`, a branch shorthand such as "main" or "origin/main",
/// or from HEAD when `base` is `None`. A remote-tracking base makes
/// the new branch track it, like `git checkout -b name origin/name`.
/// An existing branch is checked out either way; `base` is ignored.
///
/// The checkout uses the safe strategy, so git refuses to overwrite
/// uncommitted changes instead of discarding them. Detached HEAD is
/// fine as a base; the new branch starts at the current commit.
pub fn checkout_branch(
    dir: &str,
    name: &str,
    base: Option<&str>,
    create: bool,
) -> Result<(), BranchError> {
    if !VPath::parse(dir).is_local() {
        return Err(BranchError::Checkout(format!(
            "not a local path: {dir}"
        )));
    }
    let dir = std::fs::canonicalize(dir)
        .map_err(|e| BranchError::Checkout(format!("{dir}: {e}")))?;
    let repo = Repository::discover(&dir)
        .map_err(|e| BranchError::Checkout(format!("no git repo at {}: {e}", dir.display())))?;

    if repo.find_branch(name, BranchType::Local).is_err() {
        if !create {
            return Err(BranchError::NotFound(name.to_string()));
        }
        let base_ref = base.unwrap_or("HEAD");
        let commit = repo
            .revparse_single(base_ref)
            .and_then(|obj| obj.peel_to_commit())
            .map_err(|e| BranchError::Checkout(format!("cannot resolve {base_ref}: {e}")))?;
        repo.branch(name, &commit, false)
            .map_err(|e| BranchError::Checkout(format!("cannot create {name}: {e}")))?;
        // A remote-tracking base marks the new branch as tracking it.
        // Failures here are best effort; the branch itself is usable.
        if repo.find_branch(base_ref, BranchType::Remote).is_ok() {
            if let Ok(mut local) = repo.find_branch(name, BranchType::Local) {
                let _ = local.set_upstream(Some(base_ref));
            }
        }
    }

    let commit = repo
        .find_branch(name, BranchType::Local)
        .and_then(|b| b.get().peel_to_commit())
        .map_err(|e| BranchError::Checkout(format!("{name}: {e}")))?;
    let mut opts = git2::build::CheckoutBuilder::new();
    opts.safe();
    repo.checkout_tree(commit.as_object(), Some(&mut opts))
        .map_err(|e| {
            BranchError::Checkout(format!(
                "git refused to switch (uncommitted changes?): {e}"
            ))
        })?;
    let refname = format!("refs/heads/{name}");
    repo.set_head(&refname)
        .map_err(|e| BranchError::Checkout(format!("cannot set HEAD to {name}: {e}")))?;
    Ok(())
}

/// Maps raw status bits to one child state. `None` means clean.
fn state_for(status: Status) -> Option<FileGitState> {
    if status.is_conflicted() {
        return Some(FileGitState::Conflicted);
    }
    let staged = status.intersects(
        Status::INDEX_NEW
            | Status::INDEX_MODIFIED
            | Status::INDEX_DELETED
            | Status::INDEX_RENAMED
            | Status::INDEX_TYPECHANGE,
    );
    // WT_DELETED counts as dirty so a deletion inside a folder marks it.
    let dirty = status.intersects(
        Status::WT_MODIFIED | Status::WT_TYPECHANGE | Status::WT_RENAMED | Status::WT_DELETED,
    );
    if staged && dirty {
        return Some(FileGitState::StagedAndModified);
    }
    if staged {
        return Some(FileGitState::Staged);
    }
    if dirty {
        return Some(FileGitState::Modified);
    }
    if status.is_wt_new() {
        return Some(FileGitState::Untracked);
    }
    if status.is_ignored() {
        return Some(FileGitState::Ignored);
    }
    None
}
