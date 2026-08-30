use orka_core::vfs::{BackendRouter, FsBackend, LocalBackend};
use orka_core::ListOptions;
use std::fs;

#[test]
fn router_resolves_local_paths_to_local_backend() {
    let router = BackendRouter::new();
    let (backend, local_path) = router.resolve("/Users/example/Documents").unwrap();
    assert!(backend.capabilities().is_local);
    assert_eq!(local_path, "/Users/example/Documents");
}

#[test]
fn router_rejects_unknown_connection() {
    let router = BackendRouter::new();
    let err = match router.resolve("sftp://nowhere/home") {
        Err(e) => e,
        Ok(_) => panic!("expected an error for an unknown connection"),
    };
    assert!(err.contains("nowhere"), "error names the connection: {err}");
}

#[test]
fn router_capabilities_reflect_locality() {
    let router = BackendRouter::new();
    assert!(router.capabilities("/tmp").is_local);
    let remote = router.capabilities("s3://media/bucket");
    assert!(!remote.is_local);
    assert!(!remote.can_watch);
}

#[test]
fn local_backend_list_dir_matches_free_function() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("banana.txt"), b"xx").unwrap();
    fs::write(tmp.path().join(".hidden"), b"x").unwrap();
    fs::create_dir(tmp.path().join("Alpha")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("Alpha"), tmp.path().join("link")).unwrap();

    let opts = ListOptions {
        include_hidden: true,
        dirs_only: false,
    };
    let expected = orka_core::list_dir(tmp.path(), &opts).unwrap();
    let actual = LocalBackend
        .list_dir(&tmp.path().to_string_lossy(), &opts)
        .unwrap();
    assert_eq!(actual, expected);
    assert!(!actual.is_empty());
}

#[test]
fn local_backend_stat_matches_listing_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("data.bin");
    fs::write(&file, vec![0u8; 512]).unwrap();

    let entry = LocalBackend.stat(&file.to_string_lossy()).unwrap();
    assert_eq!(entry.name, "data.bin");
    assert_eq!(entry.size, 512);
    assert!(!entry.is_dir);
    assert!(!entry.is_hidden);
    assert!(entry.modified_ms > 0);
}
