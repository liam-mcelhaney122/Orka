//! Proves the shared conformance suite against `LocalBackend`, and
//! shows its `can_rename == false` branch with a small wrapper backend.

mod support;

use orka_core::vfs::{Capabilities, FsBackend, LocalBackend, WriteFinish};
use orka_core::{Entry, ListOptions};
use support::conformance::{exercise_backend, exercise_backend_with, ConformanceOptions};

#[test]
fn local_backend_meets_the_conformance_suite() {
    let tmp = tempfile::tempdir().expect("create a temp directory for the conformance root");
    exercise_backend(&LocalBackend, &tmp.path().to_string_lossy());
}

/// The default suite writes a 3 MiB file. Local disk is fast enough
/// to run that every time, but a small size keeps this second run
/// quick when a caller wants a fast smoke test instead.
#[test]
fn local_backend_meets_the_conformance_suite_with_a_small_large_file() {
    let tmp = tempfile::tempdir().expect("create a temp directory for the conformance root");
    let opts = ConformanceOptions {
        large_file_bytes: 64 * 1024,
        ..ConformanceOptions::default()
    };
    exercise_backend_with(&LocalBackend, &tmp.path().to_string_lossy(), &opts);
}

/// Wraps `LocalBackend` but refuses every rename and reports
/// `can_rename: false`. This exercises the suite's branch for a
/// backend that cannot rename in place.
struct NoRenameBackend;

impl FsBackend for NoRenameBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            can_rename: false,
            ..LocalBackend.capabilities()
        }
    }

    fn list_dir(&self, path: &str, opts: &ListOptions) -> Result<Vec<Entry>, String> {
        LocalBackend.list_dir(path, opts)
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        LocalBackend.stat(path)
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        LocalBackend.open_read(path)
    }

    fn create_write(
        &self,
        path: &str,
        size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        LocalBackend.create_write(path, size_hint)
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        LocalBackend.delete(path, recursive)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        Err(format!("rename is not supported, from {from} to {to}"))
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        LocalBackend.mkdir(path)
    }
}

#[test]
fn a_backend_with_can_rename_false_must_fail_rename() {
    let tmp = tempfile::tempdir().expect("create a temp directory for the conformance root");
    exercise_backend(&NoRenameBackend, &tmp.path().to_string_lossy());
}
