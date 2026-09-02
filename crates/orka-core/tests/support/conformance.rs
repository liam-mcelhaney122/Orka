//! One conformance suite for every `FsBackend`.
//!
//! [`exercise_backend`] runs the same sequence of file operations
//! against any backend, so a new backend proves the shared contract
//! instead of a bespoke, easily incomplete test file. The suite never
//! assumes a leading `/`: `S3` paths look like `bucket/key`, `SFTP`
//! paths look like `/abs/path`, and a mounted share uses a plain local
//! path. Use [`join`] to build a child path from `root`.
//!
//! `support::mod` marks this whole module `#[allow(dead_code)]`: a
//! test binary that uses only part of the suite must not warn on the
//! rest.

use orka_core::vfs::FsBackend;
use orka_core::ListOptions;
use std::io::{Read, Write};

/// Tunable knobs for [`exercise_backend_with`]. [`exercise_backend`]
/// uses the default values.
pub struct ConformanceOptions {
    /// Size of the large round-trip file, in bytes. Large enough to
    /// cross a remote backend's multipart-upload or chunked-upload
    /// threshold. Default: 3 MiB.
    pub large_file_bytes: usize,
    /// Set to `false` for a backend that never filters hidden entries
    /// out of a directory listing. Default: `true`.
    pub expect_hidden_filtering: bool,
}

impl Default for ConformanceOptions {
    fn default() -> Self {
        Self {
            large_file_bytes: 3 * 1024 * 1024,
            expect_hidden_filtering: true,
        }
    }
}

/// Joins a child name onto a backend-local directory path.
///
/// An empty `root` returns `name` unchanged. A `root` of exactly `/`
/// returns `/name`. Any other `root` gets exactly one `/` before
/// `name`, so a trailing slash on `root` never doubles up.
pub fn join(root: &str, name: &str) -> String {
    if root.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", root.trim_end_matches('/'), name)
    }
}

/// Runs the conformance suite with the default [`ConformanceOptions`].
///
/// `root` must be an existing, empty directory in the backend's own
/// path form. The suite leaves `root` empty when it returns, and also
/// on panic, through a cleanup guard.
pub fn exercise_backend(backend: &dyn FsBackend, root: &str) {
    exercise_backend_with(backend, root, &ConformanceOptions::default());
}

/// Runs the conformance suite with explicit [`ConformanceOptions`].
///
/// See [`exercise_backend`] for the contract on `root`.
pub fn exercise_backend_with(backend: &dyn FsBackend, root: &str, opts: &ConformanceOptions) {
    // Declared first so it drops last: a best-effort sweep of `root`
    // that runs on a normal return and while a panic unwinds.
    let _cleanup = CleanupGuard { backend, root };

    let empty = expect_ok(
        backend.list_dir(root, &ListOptions::default()),
        "list the empty root",
        root,
    );
    assert!(
        empty.is_empty(),
        "root must start empty at {root}, found: {empty:?}"
    );

    let dir = join(root, "dir1");
    expect_ok(backend.mkdir(&dir), "mkdir", &dir);

    let file = join(root, "file1.txt");
    write_text(backend, &file, b"hello world");
    let read_back = read_all(backend, &file);
    assert_eq!(read_back, b"hello world", "round-trip content at {file}");

    // `stat` on the file: size, kind, and a real modification time.
    // A directory's `modified_ms` is not checked: some remote
    // backends synthesize directories and report 0 for them.
    let file_stat = expect_ok(backend.stat(&file), "stat the file", &file);
    assert_eq!(file_stat.size, 11, "stat size at {file}");
    assert!(!file_stat.is_dir, "stat is_dir must be false for {file}");
    assert!(
        file_stat.modified_ms > 0,
        "stat modified_ms must be greater than zero for {file}, got {}",
        file_stat.modified_ms
    );

    let dir_stat = expect_ok(backend.stat(&dir), "stat the directory", &dir);
    assert!(dir_stat.is_dir, "stat is_dir must be true for {dir}");

    // Listing the root shows both the file and the directory.
    let listing = expect_ok(
        backend.list_dir(root, &ListOptions::default()),
        "list root with entries",
        root,
    );
    let file_entry = listing
        .iter()
        .find(|e| e.name == "file1.txt")
        .unwrap_or_else(|| panic!("listing at {root} is missing file1.txt: {listing:?}"));
    assert!(!file_entry.is_dir, "file1.txt entry must report is_dir=false");
    assert!(!file_entry.path.is_empty(), "file1.txt entry path must be non-empty");
    let dir_entry = listing
        .iter()
        .find(|e| e.name == "dir1")
        .unwrap_or_else(|| panic!("listing at {root} is missing dir1: {listing:?}"));
    assert!(dir_entry.is_dir, "dir1 entry must report is_dir=true");
    assert!(!dir_entry.path.is_empty(), "dir1 entry path must be non-empty");

    if opts.expect_hidden_filtering {
        step_hidden_filtering(backend, root);
    }

    // `dirs_only` returns only directories, and still includes dir1.
    let dirs_only = expect_ok(
        backend.list_dir(
            root,
            &ListOptions {
                include_hidden: true,
                dirs_only: true,
            },
        ),
        "list dirs_only",
        root,
    );
    assert!(
        dirs_only.iter().all(|e| e.is_dir),
        "dirs_only must return only directories at {root}: {dirs_only:?}"
    );
    assert!(
        dirs_only.iter().any(|e| e.name == "dir1"),
        "dirs_only must include dir1 at {root}"
    );

    // Overwriting an existing file updates its size and content.
    write_text(backend, &file, b"a longer replacement body");
    let overwritten_stat = expect_ok(backend.stat(&file), "stat the overwritten file", &file);
    assert_eq!(
        overwritten_stat.size,
        "a longer replacement body".len() as u64,
        "overwrite must update size at {file}"
    );
    let overwritten_content = read_all(backend, &file);
    assert_eq!(
        overwritten_content, b"a longer replacement body",
        "overwrite must update content at {file}"
    );

    step_large_file_round_trip(backend, root, opts.large_file_bytes);
    step_rename(backend, root);
    step_copy_native(backend, root);
    step_nested_tree(backend, root);
    step_delete_file(backend, root);
    step_missing_path_errors(backend, root);

    // A repeat `mkdir` on an existing directory may succeed or fail;
    // either way the directory must still be there afterward.
    let _ = backend.mkdir(&dir);
    let dir_after_repeat = expect_ok(
        backend.stat(&dir),
        "stat the directory after a repeat mkdir",
        &dir,
    );
    assert!(
        dir_after_repeat.is_dir,
        "the directory must survive a repeat mkdir at {dir}"
    );

    cleanup_path(backend, &dir, true);
    cleanup_path(backend, &file, false);

    // The cleanup guard sweeps anything left over when this function
    // returns (or unwinds), so `root` ends up empty either way.
}

fn step_hidden_filtering(backend: &dyn FsBackend, root: &str) {
    let hidden = join(root, ".secret");
    write_text(backend, &hidden, b"shh");

    let visible_only = expect_ok(
        backend.list_dir(
            root,
            &ListOptions {
                include_hidden: false,
                dirs_only: false,
            },
        ),
        "list without hidden entries",
        root,
    );
    assert!(
        !visible_only.iter().any(|e| e.name == ".secret"),
        "include_hidden=false must hide .secret at {root}: {visible_only:?}"
    );

    let with_hidden = expect_ok(
        backend.list_dir(
            root,
            &ListOptions {
                include_hidden: true,
                dirs_only: false,
            },
        ),
        "list with hidden entries",
        root,
    );
    let hidden_entry = with_hidden
        .iter()
        .find(|e| e.name == ".secret")
        .unwrap_or_else(|| panic!("include_hidden=true must show .secret at {root}: {with_hidden:?}"));
    assert!(
        hidden_entry.is_hidden,
        ".secret entry must report is_hidden=true at {root}"
    );

    cleanup_path(backend, &hidden, false);
}

/// A large file, with a deterministic byte pattern, round-trips
/// exactly. The pattern uses a prime period so it does not repeat on
/// a power-of-two chunk boundary, which would hide a boundary bug in
/// a multipart or chunked upload.
fn step_large_file_round_trip(backend: &dyn FsBackend, root: &str, size: usize) {
    let path = join(root, "large.bin");
    let mut data = vec![0u8; size];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }

    {
        let mut writer = expect_ok(
            backend.create_write(&path, Some(size as u64)),
            "create the large file",
            &path,
        );
        writer
            .write_all(&data)
            .unwrap_or_else(|e| panic!("write the large file failed for {path}: {e}"));
        writer
            .finish()
            .unwrap_or_else(|e| panic!("finish the large file failed for {path}: {e}"));
    }

    let mut reader = expect_ok(backend.open_read(&path), "open the large file", &path);
    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .unwrap_or_else(|e| panic!("read the large file failed for {path}: {e}"));
    assert_eq!(
        actual.len(),
        data.len(),
        "large file round-trip size at {path}"
    );
    assert_eq!(actual, data, "large file round-trip content at {path}");

    cleanup_path(backend, &path, false);
}

fn step_rename(backend: &dyn FsBackend, root: &str) {
    let caps = backend.capabilities();
    let src = join(root, "rename_src.txt");
    write_text(backend, &src, b"rename me");
    let dst = join(root, "rename_dst.txt");

    if !caps.can_rename {
        let result = backend.rename(&src, &dst);
        assert!(
            result.is_err(),
            "rename must return Err when can_rename is false, from {src} to {dst}"
        );
        cleanup_path(backend, &src, false);
        return;
    }

    expect_ok(backend.rename(&src, &dst), "rename the file", &src);
    let content = read_all(backend, &dst);
    assert_eq!(content, b"rename me", "renamed file content at {dst}");
    cleanup_path(backend, &dst, false);

    // A directory rename carries its contents along.
    let dir_src = join(root, "rename_dir_src");
    expect_ok(backend.mkdir(&dir_src), "mkdir the rename source directory", &dir_src);
    write_text(backend, &join(&dir_src, "inner.txt"), b"inner");
    let dir_dst = join(root, "rename_dir_dst");
    expect_ok(backend.rename(&dir_src, &dir_dst), "rename the directory", &dir_src);
    let listing = expect_ok(
        backend.list_dir(&dir_dst, &ListOptions::default()),
        "list the renamed directory",
        &dir_dst,
    );
    assert!(
        listing.iter().any(|e| e.name == "inner.txt"),
        "renamed directory must keep its file at {dir_dst}: {listing:?}"
    );
    cleanup_path(backend, &dir_dst, true);
}

fn step_copy_native(backend: &dyn FsBackend, root: &str) {
    let src = join(root, "copy_src.txt");
    write_text(backend, &src, b"copy me please");
    let dst = join(root, "copy_dst.txt");

    if let Some(result) = backend.copy_native(&src, &dst) {
        expect_ok(result, "copy_native", &src);
        let dst_content = read_all(backend, &dst);
        assert_eq!(
            dst_content, b"copy me please",
            "copy_native content at {dst}"
        );
        expect_ok(
            backend.stat(&src),
            "stat the copy_native source after the copy",
            &src,
        );
        cleanup_path(backend, &dst, false);
    }

    cleanup_path(backend, &src, false);
}

/// A tree three levels deep, with a file at each level, lists
/// correctly at every level and comes out with one recursive delete.
fn step_nested_tree(backend: &dyn FsBackend, root: &str) {
    let level1 = join(root, "tree");
    expect_ok(backend.mkdir(&level1), "mkdir tree level 1", &level1);
    write_text(backend, &join(&level1, "l1.txt"), b"level one");

    let level2 = join(&level1, "sub2");
    expect_ok(backend.mkdir(&level2), "mkdir tree level 2", &level2);
    write_text(backend, &join(&level2, "l2.txt"), b"level two");

    let level3 = join(&level2, "sub3");
    expect_ok(backend.mkdir(&level3), "mkdir tree level 3", &level3);
    write_text(backend, &join(&level3, "l3.txt"), b"level three");

    for (level_path, expected_name) in [
        (&level1, "l1.txt"),
        (&level2, "l2.txt"),
        (&level3, "l3.txt"),
    ] {
        let listing = expect_ok(
            backend.list_dir(level_path, &ListOptions::default()),
            "list a tree level",
            level_path,
        );
        assert!(
            listing.iter().any(|e| e.name == expected_name),
            "tree level {level_path} is missing {expected_name}: {listing:?}"
        );
    }

    expect_ok(backend.delete(&level1, true), "delete the tree recursively", &level1);
    let missing = backend.stat(&level1);
    assert!(
        missing.is_err(),
        "the tree root must be gone after a recursive delete at {level1}"
    );
}

fn step_delete_file(backend: &dyn FsBackend, root: &str) {
    let path = join(root, "to_delete.txt");
    write_text(backend, &path, b"bye");
    expect_ok(backend.delete(&path, false), "delete the file", &path);
    let missing = backend.stat(&path);
    assert!(
        missing.is_err(),
        "the file must be gone after delete at {path}"
    );
}

fn step_missing_path_errors(backend: &dyn FsBackend, root: &str) {
    let missing = join(root, "does_not_exist.txt");
    expect_err(backend.stat(&missing), "stat a missing path", &missing);
    expect_err(backend.open_read(&missing), "open_read a missing path", &missing);
}

/// Writes `content` to `path` through `create_write`, then `finish`.
fn write_text(backend: &dyn FsBackend, path: &str, content: &[u8]) {
    let mut writer = expect_ok(
        backend.create_write(path, Some(content.len() as u64)),
        "create the file",
        path,
    );
    writer
        .write_all(content)
        .unwrap_or_else(|e| panic!("write failed for {path}: {e}"));
    writer
        .finish()
        .unwrap_or_else(|e| panic!("finish failed for {path}: {e}"));
}

/// Reads all of `path` through `open_read`.
fn read_all(backend: &dyn FsBackend, path: &str) -> Vec<u8> {
    let mut reader = expect_ok(backend.open_read(path), "open the file", path);
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("read failed for {path}: {e}"));
    buf
}

/// Deletes `path` and ignores the result. Used for tidying up a step's
/// own artifacts; the cleanup guard is the safety net for the rest.
fn cleanup_path(backend: &dyn FsBackend, path: &str, recursive: bool) {
    let _ = backend.delete(path, recursive);
}

/// Reports the step name and the path on an `Err`, instead of a bare
/// `unwrap` that hides both.
fn expect_ok<T>(result: Result<T, String>, step: &str, path: &str) -> T {
    match result {
        Ok(value) => value,
        Err(message) => panic!("{step} failed for {path}: {message}"),
    }
}

/// Asserts that `result` is an `Err`, with a message that names the
/// step and the path.
fn expect_err<T>(result: Result<T, String>, step: &str, path: &str) {
    assert!(
        result.is_err(),
        "{step} unexpectedly succeeded for {path}"
    );
}

/// Sweeps every entry directly under `root` on drop, so a panic
/// partway through the suite still leaves `root` empty. Best effort:
/// a drop must never panic, so every error here is swallowed.
struct CleanupGuard<'a> {
    backend: &'a dyn FsBackend,
    root: &'a str,
}

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        if let Ok(entries) = self.backend.list_dir(
            self.root,
            &ListOptions {
                include_hidden: true,
                dirs_only: false,
            },
        ) {
            for entry in entries {
                let _ = self.backend.delete(&entry.path, true);
            }
        }
    }
}
