//! Commit graph for the branch panel.
//!
//! [`GitGraphService`] builds a GitKraken-style graph: a topological walk
//! over every local branch, remote-tracking branch, and tag tip, plus
//! HEAD. Each commit gets a lane index so the Swift panel can draw the
//! merges. Results are cached briefly and invalidated by the watch
//! pipeline like the status cache.

use crate::git::discover_root;
use crate::vfs::VPath;
use git2::{BranchType, Oid, Repository, Sort};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fresh graphs stay valid this long between watch invalidations.
const GRAPH_TTL: Duration = Duration::from_secs(2);
/// Cap for the cache map. Overflow drops the whole map; a rebuild is cheap.
const CACHE_CAP: usize = 32;
/// Default commit window for one graph.
pub const DEFAULT_LIMIT: usize = 300;

/// One commit in the graph, newest first.
#[derive(Debug, Clone, PartialEq)]
pub struct GitCommit {
    /// Full object id.
    pub oid: String,
    /// First seven characters, for display.
    pub short_oid: String,
    /// First line of the commit message.
    pub summary: String,
    pub author_name: String,
    /// Committer time in milliseconds since the Unix epoch.
    pub time_ms: i64,
    /// Row indices of the parents. Always later rows than this commit.
    pub parents: Vec<u32>,
    /// Branch and tag names that point at this commit.
    pub refs: Vec<String>,
    /// Graph column. The Swift renderer turns this into an x offset.
    pub lane: u32,
    /// True when HEAD resolves to this commit.
    pub is_head: bool,
}

/// One branch shown in the panel's branch list.
#[derive(Debug, Clone, PartialEq)]
pub struct GitBranch {
    pub name: String,
    pub is_head: bool,
    pub is_local: bool,
    /// Row of the branch tip. None when the tip lies beyond the walk
    /// window.
    pub head_commit: Option<u32>,
}

/// The complete graph for one repository.
#[derive(Debug, Clone, PartialEq)]
pub struct GitGraph {
    pub repo_root: String,
    /// Checked-out branch name. None means detached HEAD.
    pub branch: Option<String>,
    pub commits: Vec<GitCommit>,
    pub branches: Vec<GitBranch>,
    /// True when the walk hit the limit before reaching the roots.
    pub truncated: bool,
    /// URL of the "origin" remote, or of the first remote when there is
    /// no "origin". None when the repository has no remotes. The value
    /// is the configured fetch URL, verbatim.
    pub remote_url: Option<String>,
}

/// Builds and caches commit graphs.
#[derive(Default)]
pub struct GitGraphService {
    /// Canonical repo root -> cached graph.
    caches: Mutex<HashMap<PathBuf, (Instant, GitGraph)>>,
}

impl GitGraphService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the graph for the repo around `dir`, or None when `dir`
    /// is remote or outside a work tree.
    pub fn graph_for_dir(&self, dir: &str, limit: usize) -> Option<GitGraph> {
        if !VPath::parse(dir).is_local() {
            return None;
        }
        let dir = std::fs::canonicalize(dir).ok()?;
        let root = discover_root(&dir)?;
        {
            let caches = self.caches.lock().unwrap();
            if let Some((at, graph)) = caches.get(&root) {
                if at.elapsed() < GRAPH_TTL {
                    return Some(graph.clone());
                }
            }
        }
        let graph = build_graph(&root, limit)?;
        let mut caches = self.caches.lock().unwrap();
        if caches.len() >= CACHE_CAP {
            caches.clear();
        }
        caches.insert(root, (Instant::now(), graph.clone()));
        Some(graph)
    }

    /// Drops cached graphs affected by a filesystem change at `changed`.
    pub fn invalidate_under(&self, changed: &str) {
        let changed = Path::new(changed);
        let changed = std::fs::canonicalize(changed).unwrap_or_else(|_| changed.to_path_buf());
        let mut caches = self.caches.lock().unwrap();
        caches.retain(|root, _| !changed.starts_with(root));
    }
}

fn build_graph(root: &Path, limit: usize) -> Option<GitGraph> {
    let repo = Repository::open(root).ok()?;
    let repo_root = root.display().to_string();

    // HEAD identity.
    let head = repo.head().ok();
    let head_oid = head.as_ref().and_then(|h| h.target());
    let branch = head
        .as_ref()
        .filter(|_| !repo.head_detached().unwrap_or(false))
        .and_then(|h| h.shorthand().ok().map(|s| s.to_owned()));

    // Branch and tag tips. Remote-tracking branches are walk roots so
    // their merges show, but they list in their own section.
    let mut branches: Vec<GitBranch> = Vec::new();
    let mut tips: Vec<Oid> = Vec::new();
    let mut refs_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut branch_oid: HashMap<String, String> = HashMap::new();

    for (kind, is_local) in [(BranchType::Local, true), (BranchType::Remote, false)] {
        let Ok(iter) = repo.branches(Some(kind)) else {
            continue;
        };
        for entry in iter.flatten() {
            let (branch_ref, _) = entry;
            let Ok(Some(name)) = branch_ref.name() else {
                continue;
            };
            let Ok(commit) = branch_ref.get().peel_to_commit() else {
                continue;
            };
            let oid = commit.id();
            let oid_str = oid.to_string();
            tips.push(oid);
            refs_of
                .entry(oid_str.clone())
                .or_default()
                .push(name.to_string());
            branch_oid.insert(name.to_string(), oid_str);
            branches.push(GitBranch {
                name: name.to_string(),
                is_head: branch.as_deref() == Some(name),
                is_local,
                head_commit: None,
            });
        }
    }
    if let Ok(names) = repo.tag_names(None) {
        for name in names.iter().flatten().flatten() {
            let Ok(reference) = repo.find_reference(&format!("refs/tags/{name}")) else {
                continue;
            };
            let Ok(commit) = reference.peel_to_commit() else {
                continue;
            };
            refs_of
                .entry(commit.id().to_string())
                .or_default()
                .push(name.to_string());
        }
    }
    if let Some(oid) = head_oid {
        tips.push(oid);
    }

    // Topological walk over all tips. Parents always appear after their
    // children, which the lane algorithm below relies on.
    let mut walk = repo.revwalk().ok()?;
    walk.set_sorting(Sort::TOPOLOGICAL | Sort::TIME).ok()?;
    for tip in &tips {
        walk.push(*tip).ok()?;
    }

    let mut raw: Vec<(String, git2::Commit)> = Vec::new();
    let mut seen: HashSet<Oid> = HashSet::new();
    let mut truncated = false;
    for oid in &mut walk {
        let Ok(oid) = oid else { continue };
        if raw.len() >= limit {
            truncated = true;
            break;
        }
        let Ok(commit) = repo.find_commit(oid) else {
            continue;
        };
        if !seen.insert(oid) {
            continue;
        }
        raw.push((oid.to_string(), commit));
    }

    // Row index by oid, so parent oids map to rows.
    let row_of: HashMap<String, u32> = raw
        .iter()
        .enumerate()
        .map(|(row, (oid, _))| (oid.clone(), row as u32))
        .collect();

    let mut commits: Vec<GitCommit> = raw
        .iter()
        .map(|(oid, commit)| GitCommit {
            short_oid: oid.chars().take(7).collect(),
            summary: commit
                .summary()
                .ok()
                .flatten()
                .map(str::trim)
                .unwrap_or("")
                .to_string(),
            author_name: commit.author().name().unwrap_or("").to_string(),
            time_ms: commit.time().seconds() * 1000,
            parents: commit
                .parent_ids()
                .filter_map(|p| row_of.get(&p.to_string()).copied())
                .collect(),
            refs: Vec::new(),
            lane: 0,
            is_head: Some(commit.id()) == head_oid,
            oid: oid.clone(),
        })
        .collect();

    // Parents that fall outside the window drop their edges; a line to
    // nothing would draw past the last row.
    assign_lanes(&mut commits);

    for commit in &mut commits {
        commit.refs = refs_of.get(&commit.oid).cloned().unwrap_or_default();
    }

    // Branch rows are only known after the walk.
    for branch in &mut branches {
        branch.head_commit = branch_oid
            .get(&branch.name)
            .and_then(|oid| row_of.get(oid).copied());
    }

    let remote_url = repo
        .find_remote("origin")
        .ok()
        .and_then(|r| r.url().ok().map(str::to_owned))
        .or_else(|| {
            let names = repo.remotes().ok()?;
            let first = names.get(0).ok()??.to_owned();
            let remote = repo.find_remote(&first).ok()?;
            remote.url().ok().map(str::to_owned)
        });

    Some(GitGraph {
        repo_root,
        branch,
        commits,
        branches,
        truncated,
        remote_url,
    })
}

/// Assigns graph lanes to commits in row order (children before
/// parents). Each commit takes the lane its first child reserved for it,
/// or the first free lane. A merge opens new lanes for its later
/// parents; those lanes close when the chain reaches a commit with no
/// first parent in the same lane.
fn assign_lanes(commits: &mut [GitCommit]) {
    // Lane -> oid currently reserved at the bottom of the lane.
    let mut lanes: Vec<Option<String>> = Vec::new();
    // Oid -> reserved lane.
    let mut lane_of: HashMap<String, u32> = HashMap::new();

    for index in 0..commits.len() {
        let oid = commits[index].oid.clone();
        // Take the reserved lane, if a child left one.
        let lane = match lane_of.remove(&oid) {
            Some(lane) => lane,
            None => first_free(&lanes),
        };
        commits[index].lane = lane;
        if lanes.len() <= lane as usize {
            lanes.resize(lane as usize + 1, None);
        }
        lanes[lane as usize] = None;

        // Reserve lanes for the parents: the first parent continues
        // this lane, later parents branch off into fresh lanes.
        for (parent_index, parent_row) in commits[index].parents.iter().enumerate() {
            let parent_oid = commits[*parent_row as usize].oid.clone();
            if lane_of.contains_key(&parent_oid) {
                continue;
            }
            let parent_lane = if parent_index == 0 {
                lane
            } else {
                first_free(&lanes)
            };
            if lanes.len() <= parent_lane as usize {
                lanes.resize(parent_lane as usize + 1, None);
            }
            lanes[parent_lane as usize] = Some(parent_oid.clone());
            lane_of.insert(parent_oid, parent_lane);
        }
    }
}

/// The lowest free lane index.
fn first_free(lanes: &[Option<String>]) -> u32 {
    lanes
        .iter()
        .position(|slot| slot.is_none())
        .map(|i| i as u32)
        .unwrap_or(lanes.len() as u32)
}
