//! Connection registry lifecycle tests. A mock factory and an
//! in-memory backend prove the plumbing without a real protocol.

use orka_core::vfs::connections::{
    AuthMethod, BackendFactory, ConnectionConfig, ConnectionRegistry, ConnectionSink,
    ConnectionState, SecretProvider,
};
use orka_core::vfs::{BackendRouter, Capabilities, FsBackend, Scheme, WriteFinish};
use orka_core::{Entry, ListOptions};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// In-memory backend over a map of directory path -> entries.
struct MockBackend {
    dirs: HashMap<String, Vec<Entry>>,
}

impl MockBackend {
    fn with_root_file(name: &str) -> Self {
        let entry = Entry {
            name: name.to_string(),
            path: format!("/{name}"),
            is_dir: false,
            size: 3,
            modified_ms: 0,
            is_hidden: false,
            is_symlink: false,
        };
        let mut dirs = HashMap::new();
        dirs.insert("/".to_string(), vec![entry]);
        Self { dirs }
    }
}

impl FsBackend for MockBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            is_local: false,
            can_trash: false,
            can_watch: false,
            can_rename: true,
            server_side_copy: false,
            preserves_permissions: false,
        }
    }

    fn list_dir(&self, path: &str, _opts: &ListOptions) -> Result<Vec<Entry>, String> {
        self.dirs
            .get(path)
            .cloned()
            .ok_or_else(|| format!("not found: {path}"))
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        self.dirs
            .values()
            .flatten()
            .find(|e| e.path == path)
            .cloned()
            .ok_or_else(|| format!("not found: {path}"))
    }

    fn open_read(&self, _path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        Err("unsupported".into())
    }

    fn create_write(
        &self,
        _path: &str,
        _size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        Err("unsupported".into())
    }

    fn delete(&self, _path: &str, _recursive: bool) -> Result<(), String> {
        Err("unsupported".into())
    }

    fn rename(&self, _from: &str, _to: &str) -> Result<(), String> {
        Err("unsupported".into())
    }

    fn mkdir(&self, _path: &str) -> Result<(), String> {
        Err("unsupported".into())
    }
}

/// Factory that succeeds or fails on demand and can require a secret.
struct MockFactory {
    fail_with: Option<String>,
    require_secret: bool,
}

impl BackendFactory for MockFactory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        if self.require_secret {
            let secret = secrets
                .get_secret(&config.id)
                .ok_or_else(|| format!("no secret for {}", config.id))?;
            assert_eq!(secret, "hunter2");
        }
        if let Some(message) = &self.fail_with {
            return Err(message.clone());
        }
        Ok(Arc::new(MockBackend::with_root_file("readme.txt")))
    }
}

/// Factory that blocks in `connect` until the test sends on `release`.
/// Counts calls so no-op connects are provable.
struct GatedFactory {
    release: Mutex<Receiver<()>>,
    calls: Arc<AtomicUsize>,
}

impl BackendFactory for GatedFactory {
    fn connect(
        &self,
        _config: &ConnectionConfig,
        _secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self
            .release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
        Ok(Arc::new(MockBackend::with_root_file("readme.txt")))
    }
}

/// Records which ids were asked for and answers with one password.
struct MockSecrets {
    asked: Mutex<Vec<String>>,
}

impl SecretProvider for MockSecrets {
    fn get_secret(&self, connection_id: &str) -> Option<String> {
        self.asked.lock().unwrap().push(connection_id.to_string());
        Some("hunter2".to_string())
    }
}

/// Forwards every transition into a channel so tests can wait on the
/// asynchronous connect worker.
struct ChannelSink {
    tx: Mutex<Sender<(String, ConnectionState, Option<String>)>>,
}

impl ConnectionSink for ChannelSink {
    fn connection_state_changed(
        &self,
        connection_id: String,
        state: ConnectionState,
        message: Option<String>,
    ) {
        let _ = self
            .tx
            .lock()
            .unwrap()
            .send((connection_id, state, message));
    }
}

struct Harness {
    registry: ConnectionRegistry,
    router: Arc<BackendRouter>,
    secrets: Arc<MockSecrets>,
    rx: Receiver<(String, ConnectionState, Option<String>)>,
}

fn harness() -> Harness {
    let (tx, rx) = channel();
    let router = Arc::new(BackendRouter::new());
    let secrets = Arc::new(MockSecrets {
        asked: Mutex::new(Vec::new()),
    });
    let registry = ConnectionRegistry::new(
        router.clone(),
        secrets.clone(),
        Arc::new(ChannelSink { tx: Mutex::new(tx) }),
    );
    Harness {
        registry,
        router,
        secrets,
        rx,
    }
}

fn config(id: &str) -> ConnectionConfig {
    ConnectionConfig {
        id: id.to_string(),
        display_name: format!("{id} server"),
        scheme: Scheme::Sftp,
        host: "example.com".to_string(),
        port: 22,
        username: "liam".to_string(),
        initial_path: "/".to_string(),
        auth: AuthMethod::Password,
    }
}

fn next_event(h: &Harness) -> (String, ConnectionState, Option<String>) {
    h.rx.recv_timeout(Duration::from_secs(5))
        .expect("expected a connection event")
}

/// Waits long enough for a stray worker emit and asserts none arrives.
fn assert_no_event(h: &Harness) {
    assert!(
        h.rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "expected no further connection events"
    );
}

#[test]
fn connect_emits_connecting_then_connected_and_registers() {
    let h = harness();
    h.registry.set_configs(vec![config("mockid")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(MockFactory {
            fail_with: None,
            require_secret: false,
        }),
    );
    h.registry.connect("mockid");
    assert_eq!(
        next_event(&h),
        ("mockid".to_string(), ConnectionState::Connecting, None)
    );
    assert_eq!(
        next_event(&h),
        ("mockid".to_string(), ConnectionState::Connected, None)
    );
    assert_eq!(h.registry.state("mockid"), ConnectionState::Connected);

    let (backend, path) = h.router.resolve("sftp://mockid/").expect("resolves");
    assert_eq!(path, "/");
    let entries = backend.list_dir("/", &ListOptions::default()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "readme.txt");
}

#[test]
fn failing_factory_emits_failed_and_does_not_register() {
    let h = harness();
    h.registry.set_configs(vec![config("bad")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(MockFactory {
            fail_with: Some("auth rejected".to_string()),
            require_secret: false,
        }),
    );
    h.registry.connect("bad");
    assert_eq!(
        next_event(&h),
        ("bad".to_string(), ConnectionState::Connecting, None)
    );
    assert_eq!(
        next_event(&h),
        (
            "bad".to_string(),
            ConnectionState::Failed,
            Some("auth rejected".to_string())
        )
    );
    assert_eq!(h.registry.state("bad"), ConnectionState::Failed);
    assert!(h.router.resolve("sftp://bad/").is_err());
}

#[test]
fn disconnect_unregisters_and_emits() {
    let h = harness();
    h.registry.set_configs(vec![config("mockid")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(MockFactory {
            fail_with: None,
            require_secret: false,
        }),
    );
    h.registry.connect("mockid");
    next_event(&h); // Connecting
    next_event(&h); // Connected
    h.registry.disconnect("mockid");
    assert_eq!(
        next_event(&h),
        ("mockid".to_string(), ConnectionState::Disconnected, None)
    );
    assert_eq!(h.registry.state("mockid"), ConnectionState::Disconnected);
    assert!(h.router.resolve("sftp://mockid/").is_err());
}

#[test]
fn set_configs_removing_connected_id_unregisters() {
    let h = harness();
    h.registry
        .set_configs(vec![config("mockid"), config("keep")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(MockFactory {
            fail_with: None,
            require_secret: false,
        }),
    );
    h.registry.connect("mockid");
    next_event(&h); // Connecting
    next_event(&h); // Connected
    h.registry.set_configs(vec![config("keep")]);
    assert_eq!(
        next_event(&h),
        ("mockid".to_string(), ConnectionState::Disconnected, None)
    );
    assert!(h.router.resolve("sftp://mockid/").is_err());
    assert_eq!(h.registry.state("mockid"), ConnectionState::Disconnected);
}

#[test]
fn connect_without_factory_fails_immediately() {
    let h = harness();
    h.registry.set_configs(vec![config("orphan")]);
    h.registry.connect("orphan");
    let (id, state, message) = next_event(&h);
    assert_eq!(id, "orphan");
    assert_eq!(state, ConnectionState::Failed);
    assert!(message.unwrap().contains("no backend for scheme"));
    assert_eq!(h.registry.state("orphan"), ConnectionState::Failed);
}

#[test]
fn disconnect_during_connecting_discards_the_worker_result() {
    let h = harness();
    let (release, gate) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    h.registry.set_configs(vec![config("slow")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(GatedFactory {
            release: Mutex::new(gate),
            calls: calls.clone(),
        }),
    );
    h.registry.connect("slow");
    assert_eq!(
        next_event(&h),
        ("slow".to_string(), ConnectionState::Connecting, None)
    );
    h.registry.disconnect("slow");
    assert_eq!(
        next_event(&h),
        ("slow".to_string(), ConnectionState::Disconnected, None)
    );
    // Let the worker finish; its stale result must not surface.
    release.send(()).unwrap();
    assert_no_event(&h);
    assert_eq!(h.registry.state("slow"), ConnectionState::Disconnected);
    assert!(h.router.resolve("sftp://slow/").is_err());
}

#[test]
fn removal_during_connecting_discards_the_worker_result() {
    let h = harness();
    let (release, gate) = channel();
    h.registry.set_configs(vec![config("gone")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(GatedFactory {
            release: Mutex::new(gate),
            calls: Arc::new(AtomicUsize::new(0)),
        }),
    );
    h.registry.connect("gone");
    assert_eq!(
        next_event(&h),
        ("gone".to_string(), ConnectionState::Connecting, None)
    );
    h.registry.set_configs(vec![]);
    assert_eq!(
        next_event(&h),
        ("gone".to_string(), ConnectionState::Disconnected, None)
    );
    release.send(()).unwrap();
    assert_no_event(&h);
    assert_eq!(h.registry.state("gone"), ConnectionState::Disconnected);
    assert!(h.router.resolve("sftp://gone/").is_err());
}

#[test]
fn connect_on_a_connected_id_is_a_no_op() {
    let h = harness();
    let (release, gate) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    // Pre-load one token so the first worker completes at once.
    release.send(()).unwrap();
    h.registry.set_configs(vec![config("once")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(GatedFactory {
            release: Mutex::new(gate),
            calls: calls.clone(),
        }),
    );
    h.registry.connect("once");
    next_event(&h); // Connecting
    assert_eq!(
        next_event(&h),
        ("once".to_string(), ConnectionState::Connected, None)
    );
    h.registry.connect("once");
    assert_no_event(&h);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.registry.state("once"), ConnectionState::Connected);
}

#[test]
fn config_change_disconnects_a_connected_id() {
    let h = harness();
    h.registry.set_configs(vec![config("edited")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(MockFactory {
            fail_with: None,
            require_secret: false,
        }),
    );
    h.registry.connect("edited");
    next_event(&h); // Connecting
    next_event(&h); // Connected
    let mut changed = config("edited");
    changed.host = "other.example.com".to_string();
    h.registry.set_configs(vec![changed]);
    assert_eq!(
        next_event(&h),
        ("edited".to_string(), ConnectionState::Disconnected, None)
    );
    assert_eq!(h.registry.state("edited"), ConnectionState::Disconnected);
    assert!(h.router.resolve("sftp://edited/").is_err());
}

#[test]
fn secrets_provider_is_passed_to_the_factory() {
    let h = harness();
    h.registry.set_configs(vec![config("vault")]);
    h.registry.register_factory(
        Scheme::Sftp,
        Arc::new(MockFactory {
            fail_with: None,
            require_secret: true,
        }),
    );
    h.registry.connect("vault");
    next_event(&h); // Connecting
    assert_eq!(
        next_event(&h),
        ("vault".to_string(), ConnectionState::Connected, None)
    );
    assert_eq!(*h.secrets.asked.lock().unwrap(), vec!["vault".to_string()]);
}
