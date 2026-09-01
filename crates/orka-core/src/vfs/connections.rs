//! Connection registry and lifecycle for remote backends.
//!
//! [`ConnectionRegistry`] owns the saved connection configs and the
//! live state of each one. Protocol backends are created through the
//! [`BackendFactory`] seam, so SFTP, S3, and FTP support can land in
//! later milestones without changing this module. Secrets never live
//! in these types; a [`SecretProvider`] fetches them on demand.

use super::{BackendRouter, FsBackend, Scheme};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One saved connection. Holds no secret material; the password or
/// key passphrase comes from the [`SecretProvider`] at connect time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub id: String,
    pub display_name: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u32,
    pub username: String,
    /// Directory to open after connecting.
    pub initial_path: String,
    pub auth: AuthMethod,
}

/// How a connection authenticates. No variant carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Password,
    SshKey {
        key_path: String,
    },
    SshAgent,
    S3Profile {
        profile: String,
    },
    S3Keys,
    /// Bearer token from the keychain. Dropbox, Google Drive, and
    /// OAuth-configured ADLS use it. The token comes from
    /// [`SecretProvider::get_secret`] at connect time.
    OAuthToken,
    /// Azure Storage shared-key auth. The secret is the base64
    /// account key; the account name is the connection's host.
    SharedKey,
    /// No credentials: anonymous FTP, guest SMB, or a mount (NFS) whose
    /// transport has no auth step at all.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

/// Fetches a secret for a connection, for example from the keychain.
/// Called on a connect worker thread and can block on user approval.
pub trait SecretProvider: Send + Sync {
    fn get_secret(&self, connection_id: &str) -> Option<String>;
}

/// Receives connection state transitions. Called from connect worker
/// threads and from registry methods; implementations must be
/// thread-safe and must not block.
pub trait ConnectionSink: Send + Sync {
    fn connection_state_changed(
        &self,
        connection_id: String,
        state: ConnectionState,
        message: Option<String>,
    );
}

/// Creates a live backend for a config. One factory per scheme.
/// `connect` may block on network and secret lookups. The provider
/// arrives as an owned `Arc` so a backend can keep it and open more
/// sessions later, for example one per transfer.
pub trait BackendFactory: Send + Sync {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String>;
}

/// Live state shared with connect worker threads. One mutex covers
/// states, epochs, and the shutdown flag so a worker can validate and
/// commit its result under a single lock acquisition.
struct Live {
    states: HashMap<String, ConnectionState>,
    /// Per-id generation. Disconnect, removal, config change, and
    /// shutdown bump it, which invalidates in-flight connect workers.
    epochs: HashMap<String, u64>,
    /// Set once at shutdown. Workers emit no events after this.
    shutdown: bool,
}

/// Owns connection configs, their live states, and the per-scheme
/// factories. Registers connected backends on the shared router so
/// remote paths resolve.
pub struct ConnectionRegistry {
    configs: Mutex<HashMap<String, ConnectionConfig>>,
    live: Arc<Mutex<Live>>,
    factories: Mutex<HashMap<Scheme, Arc<dyn BackendFactory>>>,
    router: Arc<BackendRouter>,
    secrets: Arc<dyn SecretProvider>,
    sink: Arc<dyn ConnectionSink>,
}

impl ConnectionRegistry {
    pub fn new(
        router: Arc<BackendRouter>,
        secrets: Arc<dyn SecretProvider>,
        sink: Arc<dyn ConnectionSink>,
    ) -> Self {
        Self {
            configs: Mutex::new(HashMap::new()),
            live: Arc::new(Mutex::new(Live {
                states: HashMap::new(),
                epochs: HashMap::new(),
                shutdown: false,
            })),
            factories: Mutex::new(HashMap::new()),
            router,
            secrets,
            sink,
        }
    }

    /// Replaces the full config set. A removed id that is live is
    /// disconnected and unregistered from the router. A kept id whose
    /// config changed while live is disconnected, so the next connect
    /// uses the new config.
    pub fn set_configs(&self, configs: Vec<ConnectionConfig>) {
        let next: HashMap<String, ConnectionConfig> =
            configs.into_iter().map(|c| (c.id.clone(), c)).collect();
        let (removed, changed): (Vec<String>, Vec<String>) = {
            let current = self.configs.lock().unwrap();
            let removed = current
                .keys()
                .filter(|id| !next.contains_key(*id))
                .cloned()
                .collect();
            let changed = current
                .iter()
                .filter(|(id, config)| next.get(*id).is_some_and(|n| n != *config))
                .map(|(id, _)| id.clone())
                .collect();
            (removed, changed)
        };
        for id in removed {
            self.disconnect(&id);
            self.live.lock().unwrap().states.remove(&id);
        }
        for id in changed {
            // Only a live connection needs the disconnect; an idle one
            // picks up the new config on its next connect anyway.
            let state = self.state(&id);
            if state == ConnectionState::Connected || state == ConnectionState::Connecting {
                self.disconnect(&id);
            }
        }
        *self.configs.lock().unwrap() = next;
    }

    pub fn register_factory(&self, scheme: Scheme, factory: Arc<dyn BackendFactory>) {
        self.factories.lock().unwrap().insert(scheme, factory);
    }

    /// Connects one saved connection on a worker thread. Emits
    /// `Connecting` first, then `Connected` or `Failed`. A connect
    /// while already `Connecting` or `Connected` is ignored; a
    /// reconnect requires an explicit disconnect first. A missing
    /// factory for the scheme fails immediately.
    pub fn connect(&self, id: &str) {
        let Some(config) = self.configs.lock().unwrap().get(id).cloned() else {
            self.set_state(
                id,
                ConnectionState::Failed,
                Some(format!("unknown connection: {id}")),
            );
            return;
        };
        let factory = self.factories.lock().unwrap().get(&config.scheme).cloned();
        let Some(factory) = factory else {
            self.set_state(
                id,
                ConnectionState::Failed,
                Some(format!("no backend for scheme {:?}", config.scheme)),
            );
            return;
        };
        // Check and set Connecting under one lock so two concurrent
        // connects cannot both start a worker. Capture the epoch here;
        // a later disconnect, removal, or shutdown bumps it and
        // invalidates this worker's result.
        let epoch = {
            let mut live = self.live.lock().unwrap();
            if live.shutdown {
                return;
            }
            match live.states.get(id) {
                Some(ConnectionState::Connecting) | Some(ConnectionState::Connected) => return,
                _ => {}
            }
            live.states
                .insert(id.to_string(), ConnectionState::Connecting);
            *live.epochs.entry(id.to_string()).or_insert(0)
        };
        self.sink
            .connection_state_changed(id.to_string(), ConnectionState::Connecting, None);
        let id = id.to_string();
        let router = self.router.clone();
        let secrets = self.secrets.clone();
        let sink = self.sink.clone();
        let live = self.live.clone();
        std::thread::spawn(move || {
            // The factory may block on the network and the keychain.
            let result = factory.connect(&config, secrets);
            // Validate and commit under one lock. A bumped epoch or a
            // changed state means the result is stale: no registration,
            // no state write, no event. The emit stays inside the lock
            // so no disconnect can order its event before this one.
            let mut live = live.lock().unwrap();
            if live.shutdown
                || live.epochs.get(&id).copied().unwrap_or(0) != epoch
                || live.states.get(&id) != Some(&ConnectionState::Connecting)
            {
                return;
            }
            match result {
                Ok(backend) => {
                    router.register(id.clone(), backend);
                    live.states.insert(id.clone(), ConnectionState::Connected);
                    sink.connection_state_changed(id, ConnectionState::Connected, None);
                }
                Err(message) => {
                    live.states.insert(id.clone(), ConnectionState::Failed);
                    sink.connection_state_changed(id, ConnectionState::Failed, Some(message));
                }
            }
        });
    }

    /// Removes the connection's backend from the router and emits
    /// `Disconnected`. Bumps the epoch so an in-flight connect worker
    /// for this id discards its result. Safe to call for a connection
    /// that is not live.
    pub fn disconnect(&self, id: &str) {
        let suppressed = {
            let mut live = self.live.lock().unwrap();
            *live.epochs.entry(id.to_string()).or_insert(0) += 1;
            live.states
                .insert(id.to_string(), ConnectionState::Disconnected);
            // Unregister inside the lock; a worker registers inside the
            // same lock, so no stale backend can slip in between.
            self.router.unregister(id);
            live.shutdown
        };
        if !suppressed {
            self.sink
                .connection_state_changed(id.to_string(), ConnectionState::Disconnected, None);
        }
    }

    /// Stops event delivery and invalidates all in-flight connect
    /// workers. Call once at app teardown, before the sink's receiver
    /// goes away.
    pub fn shutdown(&self) {
        let mut live = self.live.lock().unwrap();
        live.shutdown = true;
        for epoch in live.epochs.values_mut() {
            *epoch += 1;
        }
    }

    pub fn state(&self, id: &str) -> ConnectionState {
        self.live
            .lock()
            .unwrap()
            .states
            .get(id)
            .copied()
            .unwrap_or(ConnectionState::Disconnected)
    }

    fn set_state(&self, id: &str, state: ConnectionState, message: Option<String>) {
        let suppressed = {
            let mut live = self.live.lock().unwrap();
            live.states.insert(id.to_string(), state);
            live.shutdown
        };
        if !suppressed {
            self.sink
                .connection_state_changed(id.to_string(), state, message);
        }
    }
}
