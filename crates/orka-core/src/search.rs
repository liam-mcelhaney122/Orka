//! Recursive file-name search with fuzzy ranking.
//!
//! A query walks the tree in parallel with the `ignore` crate and ranks
//! hits with `nucleo-matcher`. Results stream to a [`SearchSink`] as
//! full top-N snapshots, so the UI can replace its list on each event.

use crate::vfs::VPath;
use crate::Entry;
use ignore::{WalkBuilder, WalkState};
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Directory names that never hold useful results. Skipped even when
/// hidden files are included.
const SKIP_NAMES: &[&str] = &[
    ".git",
    "node_modules",
    ".build",
    "DerivedData",
    "target",
    ".cache",
    "__pycache__",
    ".Trash",
];

/// System trees skipped only when they sit strictly below the search
/// root. A search rooted inside one of them still works.
const SKIP_ABSOLUTE: &[&str] = &["/System", "/Library", "/private", "/Volumes"];

/// Path matches score lower than name matches by this amount.
const PATH_MATCH_PENALTY: i64 = 40;
/// Score cost for each directory level below the root.
const DEPTH_PENALTY: i64 = 4;
/// Bonus when the file name starts with the fuzzy pattern.
const PREFIX_BONUS: i64 = 25;

const EMIT_INTERVAL: Duration = Duration::from_millis(100);
const EMIT_HIT_BATCH: usize = 200;

#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub include_hidden: bool,
    pub max_results: u32,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_results: 500,
        }
    }
}

/// Receives result snapshots. Called from a search coordinator thread.
pub trait SearchSink: Send + Sync {
    fn search_results(&self, query_id: u64, results: Vec<Entry>, done: bool);
}

/// Runs at most one live query. Starting a query cancels all previous
/// ones. Worker threads detach; the cancel flag is their only shutdown
/// signal, and they exit soon after the flag is set. Call
/// [`SearchEngine::cancel_all`] before teardown so no further snapshot
/// reaches the sink.
pub struct SearchEngine {
    sink: Arc<dyn SearchSink>,
    /// Cancel flags by query id. Shared with each coordinator so it can
    /// remove its own entry when it finishes.
    active: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
    next_id: AtomicU64,
}

impl SearchEngine {
    pub fn new(sink: Arc<dyn SearchSink>) -> Self {
        Self {
            sink,
            active: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(0),
        }
    }

    /// Starts a query and returns its id. Cancels every previous query
    /// first; the UI shows one result list at a time.
    pub fn start(&self, root: PathBuf, query: &str, opts: SearchOptions) -> u64 {
        self.cancel_all();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        // Remote backends have no walker yet. Report an empty final
        // snapshot so the UI leaves its loading state.
        if !VPath::parse(&root.to_string_lossy()).is_local() {
            self.sink.search_results(id, Vec::new(), true);
            return id;
        }
        let parsed = parse_query(query);
        if parsed.fuzzy.is_empty() && parsed.extensions.is_empty() {
            self.sink.search_results(id, Vec::new(), true);
            return id;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.active.lock().unwrap().insert(id, cancel.clone());
        let sink = self.sink.clone();
        let active = self.active.clone();
        let max = opts.max_results.max(1) as usize;
        let include_hidden = opts.include_hidden;
        std::thread::spawn(move || {
            run_query(id, root, parsed, include_hidden, max, &cancel, &*sink);
            active.lock().unwrap().remove(&id);
        });
        // The coordinator and walk threads detach. See the type docs.
        id
    }

    pub fn cancel(&self, id: u64) {
        if let Some(flag) = self.active.lock().unwrap().remove(&id) {
            flag.store(true, Ordering::Relaxed);
        }
    }

    pub fn cancel_all(&self) {
        for (_, flag) in self.active.lock().unwrap().drain() {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct ParsedQuery {
    /// Space-joined fuzzy words. Empty when the query only has filters.
    pub fuzzy: String,
    /// Lowercase extension filters. Any one may match (OR).
    pub extensions: Vec<String>,
}

/// Splits a query into fuzzy words and extension filters. A token of
/// the form "*.ext" or ".ext" is an extension filter; everything else
/// joins into the fuzzy pattern.
pub(crate) fn parse_query(query: &str) -> ParsedQuery {
    let mut fuzzy_words = Vec::new();
    let mut extensions = Vec::new();
    for token in query.split_whitespace() {
        let ext = token.strip_prefix("*.").or_else(|| token.strip_prefix('.'));
        match ext {
            // A bare "." or a dotted rest like "tar.gz" is not a filter.
            Some(e) if !e.is_empty() && !e.contains('.') => extensions.push(e.to_lowercase()),
            _ => fuzzy_words.push(token),
        }
    }
    ParsedQuery {
        fuzzy: fuzzy_words.join(" "),
        extensions,
    }
}

/// Walks `root`, scores hits, and streams snapshots to `sink`. Runs on
/// a detached coordinator thread.
fn run_query(
    id: u64,
    root: PathBuf,
    parsed: ParsedQuery,
    include_hidden: bool,
    max: usize,
    cancel: &Arc<AtomicBool>,
    sink: &dyn SearchSink,
) {
    let (tx, rx) = mpsc::channel::<(i64, Entry)>();
    spawn_walk(root, parsed, include_hidden, tx, cancel.clone());

    let mut best: Vec<(i64, Entry)> = Vec::new();
    let mut new_hits = 0usize;
    let mut last_emit = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(hit) => {
                best.push(hit);
                new_hits += 1;
                // Bound memory between emits.
                if best.len() > max * 2 {
                    trim(&mut best, max);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            // All walker senders dropped: the walk is complete.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        if new_hits > 0 && (new_hits >= EMIT_HIT_BATCH || last_emit.elapsed() >= EMIT_INTERVAL) {
            trim(&mut best, max);
            sink.search_results(id, snapshot(&best), false);
            new_hits = 0;
            last_emit = Instant::now();
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    trim(&mut best, max);
    sink.search_results(id, snapshot(&best), true);
}

/// Spawns the parallel walk on its own thread. The walk signals
/// completion by dropping every clone of `tx`.
fn spawn_walk(
    root: PathBuf,
    parsed: ParsedQuery,
    include_hidden: bool,
    tx: mpsc::Sender<(i64, Entry)>,
    cancel: Arc<AtomicBool>,
) {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8);
    let home_library = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library"));
    // Empty fuzzy pattern with an extension filter matches every file
    // that has the extension.
    let pattern = if parsed.fuzzy.is_empty() {
        None
    } else {
        Some(Pattern::parse(
            &parsed.fuzzy,
            CaseMatching::Smart,
            Normalization::Smart,
        ))
    };
    let fuzzy_lower = parsed.fuzzy.to_lowercase();
    let extensions = Arc::new(parsed.extensions);
    let filter_root = root.clone();

    std::thread::spawn(move || {
        let walker = WalkBuilder::new(&root)
            .hidden(!include_hidden)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .follow_links(false)
            .threads(threads)
            .filter_entry(move |entry| {
                if !entry.file_type().is_some_and(|t| t.is_dir()) {
                    return true;
                }
                let name = entry.file_name().to_string_lossy();
                if SKIP_NAMES.iter().any(|s| *s == name) {
                    return false;
                }
                let path = entry.path();
                // The root may sit inside a system tree; skip these
                // trees only when the walk reaches them from above.
                if path != filter_root {
                    if SKIP_ABSOLUTE.iter().any(|s| Path::new(s) == path) {
                        return false;
                    }
                    if home_library.as_deref() == Some(path) {
                        return false;
                    }
                }
                true
            })
            .build_parallel();
        walker.run(|| {
            let tx = tx.clone();
            let cancel = cancel.clone();
            let pattern = pattern.clone();
            let fuzzy_lower = fuzzy_lower.clone();
            let extensions = extensions.clone();
            let root = root.clone();
            let mut matcher = Matcher::new(Config::DEFAULT);
            let mut buf = Vec::new();
            Box::new(move |result| {
                if cancel.load(Ordering::Relaxed) {
                    return WalkState::Quit;
                }
                let Ok(dirent) = result else {
                    return WalkState::Continue;
                };
                // Depth 0 is the root itself.
                if dirent.depth() == 0 {
                    return WalkState::Continue;
                }
                let is_dir = dirent.file_type().is_some_and(|t| t.is_dir());
                // An extension filter selects files only.
                if !extensions.is_empty() {
                    if is_dir {
                        return WalkState::Continue;
                    }
                    let ext = dirent
                        .path()
                        .extension()
                        .map(|e| e.to_string_lossy().to_lowercase());
                    match ext {
                        Some(e) if extensions.contains(&e) => {}
                        _ => return WalkState::Continue,
                    }
                }
                let name = dirent.file_name().to_string_lossy().into_owned();
                let Some(mut score) = score_entry(
                    &pattern,
                    &name,
                    dirent.path(),
                    &root,
                    &mut matcher,
                    &mut buf,
                ) else {
                    return WalkState::Continue;
                };
                score -= dirent.depth() as i64 * DEPTH_PENALTY;
                if !fuzzy_lower.is_empty() && name.to_lowercase().starts_with(&fuzzy_lower) {
                    score += PREFIX_BONUS;
                }
                let Some(entry) = crate::entry_from_path(dirent.path(), name) else {
                    return WalkState::Continue;
                };
                // A closed channel means the coordinator is gone.
                if tx.send((score, entry)).is_err() {
                    return WalkState::Quit;
                }
                WalkState::Continue
            })
        });
    });
}

/// Base match score before depth and prefix adjustments. Prefers a
/// name match; falls back to the root-relative path at a penalty.
fn score_entry(
    pattern: &Option<Pattern>,
    name: &str,
    path: &Path,
    root: &Path,
    matcher: &mut Matcher,
    buf: &mut Vec<char>,
) -> Option<i64> {
    let Some(pattern) = pattern else {
        // Filter-only query: every candidate matches equally.
        return Some(0);
    };
    if let Some(s) = pattern.score(Utf32Str::new(name, buf), matcher) {
        return Some(s as i64);
    }
    let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy();
    pattern
        .score(Utf32Str::new(&rel, buf), matcher)
        .map(|s| s as i64 - PATH_MATCH_PENALTY)
}

/// Keeps the best `max` hits, ordered by descending score. Path breaks
/// ties so snapshots are stable.
fn trim(best: &mut Vec<(i64, Entry)>, max: usize) {
    best.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.path.cmp(&b.1.path)));
    best.truncate(max);
}

fn snapshot(best: &[(i64, Entry)]) -> Vec<Entry> {
    best.iter().map(|(_, e)| e.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(fuzzy: &str, extensions: &[&str]) -> ParsedQuery {
        ParsedQuery {
            fuzzy: fuzzy.to_string(),
            extensions: extensions.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn parse_plain_words() {
        assert_eq!(parse_query("hello world"), parsed("hello world", &[]));
    }

    #[test]
    fn parse_extension_forms() {
        assert_eq!(parse_query("*.txt"), parsed("", &["txt"]));
        assert_eq!(parse_query(".txt"), parsed("", &["txt"]));
        assert_eq!(parse_query("*.TXT"), parsed("", &["txt"]));
    }

    #[test]
    fn parse_mixed_query() {
        assert_eq!(parse_query("report .txt"), parsed("report", &["txt"]));
        assert_eq!(
            parse_query("*.png *.jpg photo"),
            parsed("photo", &["png", "jpg"])
        );
    }

    #[test]
    fn parse_non_filter_dots() {
        // A file name with an inner dot is a fuzzy word, not a filter.
        assert_eq!(parse_query("report.txt"), parsed("report.txt", &[]));
        // A double extension is a fuzzy word; the filter takes one part.
        assert_eq!(parse_query(".tar.gz"), parsed(".tar.gz", &[]));
        // A bare dot or star-dot is not a filter.
        assert_eq!(parse_query(". *."), parsed(". *.", &[]));
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse_query("   "), parsed("", &[]));
    }
}
