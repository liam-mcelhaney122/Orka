//! Swift-facing API for Orka. Thin wrappers over `orka-core`.

use orka_core::ops;
use orka_core::vfs::connections;
use std::path::PathBuf;
use std::sync::Arc;

uniffi::setup_scaffolding!();

#[derive(uniffi::Record)]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ms: i64,
    pub is_hidden: bool,
    pub is_symlink: bool,
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum OrkaError {
    #[error("not a directory: {path}")]
    NotADirectory { path: String },
    #[error("permission denied: {path}")]
    PermissionDenied { path: String },
    #[error("not found: {path}")]
    NotFound { path: String },
    #[error("io error: {message}")]
    Io { message: String },
}

impl From<orka_core::CoreError> for OrkaError {
    fn from(e: orka_core::CoreError) -> Self {
        use orka_core::CoreError as C;
        match e {
            C::NotADirectory(p) => Self::NotADirectory {
                path: p.display().to_string(),
            },
            C::PermissionDenied(p) => Self::PermissionDenied {
                path: p.display().to_string(),
            },
            C::NotFound(p) => Self::NotFound {
                path: p.display().to_string(),
            },
            C::Io { path, source } => Self::Io {
                message: format!("{}: {}", path.display(), source),
            },
        }
    }
}

impl From<orka_core::Entry> for FsEntry {
    fn from(e: orka_core::Entry) -> Self {
        Self {
            name: e.name,
            path: e.path,
            is_dir: e.is_dir,
            size: e.size,
            modified_ms: e.modified_ms,
            is_hidden: e.is_hidden,
            is_symlink: e.is_symlink,
        }
    }
}

// ---------------------------------------------------------------------------
// Operations engine
// ---------------------------------------------------------------------------

#[derive(uniffi::Enum)]
pub enum JobState {
    Queued,
    Preparing,
    Running,
    Cancelled,
    Failed,
    Done,
}

#[derive(uniffi::Enum)]
pub enum ConflictResolution {
    Replace,
    KeepBoth,
}

impl From<ops::JobState> for JobState {
    fn from(s: ops::JobState) -> Self {
        match s {
            ops::JobState::Queued => Self::Queued,
            ops::JobState::Preparing => Self::Preparing,
            ops::JobState::Running => Self::Running,
            ops::JobState::Cancelled => Self::Cancelled,
            ops::JobState::Failed => Self::Failed,
            ops::JobState::Done => Self::Done,
        }
    }
}

#[derive(uniffi::Record)]
pub struct JobProgress {
    pub job_id: u64,
    pub state: JobState,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub items_done: u64,
    pub items_total: u64,
    pub current_path: String,
}

#[derive(uniffi::Record)]
pub struct JobItemError {
    pub path: String,
    pub message: String,
}

/// Archive container format. Mirrors
/// `orka_core::archives::ArchiveFormat`.
#[derive(uniffi::Enum)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
}

/// All engine events. Delivery threads differ by source (ops worker,
/// watch dispatcher, search and size coordinators) and calls can
/// overlap. The Swift listener must be thread-safe, hop to the main
/// actor, and never block.
#[derive(uniffi::Enum)]
pub enum OrkaEvent {
    JobProgress {
        progress: JobProgress,
    },
    JobFinished {
        job_id: u64,
        state: JobState,
        errors: Vec<JobItemError>,
    },
    /// Watched directories changed on disk. Re-list them if visible.
    DirectoryChanged {
        paths: Vec<String>,
    },
    /// Streaming search snapshot. Each event carries the full current
    /// top-N for the query, sorted best-first. `done` marks the final
    /// snapshot.
    SearchResults {
        query_id: u64,
        results: Vec<FsEntry>,
        done: bool,
    },
    /// Recursive folder totals for one size request. Each event carries
    /// the directories that finished since the previous event. `done`
    /// marks the end of the request and carries no sizes.
    FolderSizes {
        request_id: u64,
        sizes: Vec<PathSize>,
        done: bool,
    },
    /// A remote connection changed state. `message` carries the failure
    /// reason for `Failed`.
    ConnectionStateChanged {
        connection_id: String,
        state: ConnectionState,
        message: Option<String>,
    },
}

/// Recursive totals for one directory. Mirrors
/// `orka_core::sizes::PathSize`.
#[derive(uniffi::Record)]
pub struct PathSize {
    pub path: String,
    pub bytes: u64,
    pub items: u64,
}

/// Options for `start_search`.
#[derive(uniffi::Record)]
pub struct SearchOptions {
    pub include_hidden: bool,
    pub max_results: u32,
}

#[uniffi::export(with_foreign)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: OrkaEvent);
}

/// Platform services the shell provides to the engine. Called on engine
/// worker threads; implementations must be thread-safe.
#[uniffi::export(with_foreign)]
pub trait PlatformDelegate: Send + Sync {
    /// Moves the item to the user's trash. Returns the item's new path
    /// inside the trash.
    fn trash_item(&self, path: String) -> Result<String, OrkaError>;

    /// Reads the secret for one connection from the keychain. None means
    /// no stored secret; password-based connects then fail.
    fn get_secret(&self, connection_id: String) -> Option<String>;

    /// Stores a refreshed secret for one connection, for example a
    /// renewed OAuth token set.
    fn set_secret(&self, connection_id: String, value: String);
}

struct DelegateAdapter {
    delegate: Arc<dyn PlatformDelegate>,
}

impl ops::PlatformDelegate for DelegateAdapter {
    fn trash_item(&self, path: &std::path::Path) -> Result<PathBuf, String> {
        self.delegate
            .trash_item(path.display().to_string())
            .map(PathBuf::from)
            .map_err(|e| e.to_string())
    }
}

impl connections::SecretProvider for DelegateAdapter {
    fn get_secret(&self, connection_id: &str) -> Option<String> {
        self.delegate.get_secret(connection_id.to_string())
    }

    fn set_secret(&self, connection_id: &str, value: &str) {
        self.delegate
            .set_secret(connection_id.to_string(), value.to_string());
    }
}

struct ListenerSink {
    listener: Arc<dyn EventListener>,
    /// Shared with the engine so watch events can invalidate git caches
    /// before Swift re-lists and re-queries.
    git: Arc<orka_core::git::GitStatusService>,
    gitlog: Arc<orka_core::gitlog::GitGraphService>,
}

impl ops::EventSink for ListenerSink {
    fn job_progress(&self, p: ops::Progress) {
        self.listener.on_event(OrkaEvent::JobProgress {
            progress: JobProgress {
                job_id: p.job_id,
                state: p.state.into(),
                bytes_done: p.bytes_done,
                bytes_total: p.bytes_total,
                items_done: p.items_done,
                items_total: p.items_total,
                current_path: p.current_path,
            },
        });
    }

    fn job_finished(&self, job_id: u64, state: ops::JobState, errors: Vec<ops::ItemError>) {
        self.listener.on_event(OrkaEvent::JobFinished {
            job_id,
            state: state.into(),
            errors: errors
                .into_iter()
                .map(|e| JobItemError {
                    path: e.path,
                    message: e.message,
                })
                .collect(),
        });
    }
}

impl orka_core::search::SearchSink for ListenerSink {
    fn search_results(&self, query_id: u64, results: Vec<orka_core::Entry>, done: bool) {
        self.listener.on_event(OrkaEvent::SearchResults {
            query_id,
            results: results.into_iter().map(FsEntry::from).collect(),
            done,
        });
    }
}

impl orka_core::sizes::SizeSink for ListenerSink {
    fn folder_sizes(&self, request_id: u64, sizes: Vec<orka_core::sizes::PathSize>, done: bool) {
        self.listener.on_event(OrkaEvent::FolderSizes {
            request_id,
            sizes: sizes
                .into_iter()
                .map(|s| PathSize {
                    path: s.path,
                    bytes: s.bytes,
                    items: s.items,
                })
                .collect(),
            done,
        });
    }
}

impl connections::ConnectionSink for ListenerSink {
    fn connection_state_changed(
        &self,
        connection_id: String,
        state: connections::ConnectionState,
        message: Option<String>,
    ) {
        self.listener.on_event(OrkaEvent::ConnectionStateChanged {
            connection_id,
            state: state.into(),
            message,
        });
    }
}

impl orka_core::watch::WatchSink for ListenerSink {
    fn directories_changed(&self, paths: Vec<std::path::PathBuf>) {
        // Invalidate first so a git_status call triggered by this event
        // never returns pre-change cached state.
        for path in &paths {
            self.git.invalidate_under(&path.display().to_string());
            self.gitlog.invalidate_under(&path.display().to_string());
        }
        self.listener.on_event(OrkaEvent::DirectoryChanged {
            paths: paths.iter().map(|p| p.display().to_string()).collect(),
        });
    }
}

#[derive(uniffi::Object)]
pub struct OrkaEngine {
    inner: ops::OpsEngine,
    watcher: Option<orka_core::watch::DirWatcher>,
    search: orka_core::search::SearchEngine,
    sizes: orka_core::sizes::SizeEngine,
    git: Arc<orka_core::git::GitStatusService>,
    gitlog: Arc<orka_core::gitlog::GitGraphService>,
    connections: connections::ConnectionRegistry,
}

#[uniffi::export]
impl OrkaEngine {
    #[uniffi::constructor]
    pub fn new(listener: Arc<dyn EventListener>, delegate: Arc<dyn PlatformDelegate>) -> Arc<Self> {
        let git = Arc::new(orka_core::git::GitStatusService::new());
        let gitlog = Arc::new(orka_core::gitlog::GitGraphService::new());
        let sink = Arc::new(ListenerSink {
            listener,
            git: git.clone(),
            gitlog: gitlog.clone(),
        });
        // One adapter serves the ops engine (trash) and the connection
        // registry (secrets).
        let adapter = Arc::new(DelegateAdapter { delegate });
        let inner = ops::OpsEngine::new(sink.clone(), adapter.clone());
        // The registry shares the ops router so connected backends serve
        // remote transfers and listings alike.
        let connections =
            connections::ConnectionRegistry::new(inner.router(), adapter, sink.clone());
        connections.register_factory(
            orka_core::vfs::Scheme::Sftp,
            Arc::new(orka_core::vfs::sftp::SftpFactory::default()),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Rsync,
            Arc::new(orka_core::vfs::sftp::SftpFactory::rsync()),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::S3,
            Arc::new(orka_core::vfs::s3::S3Factory),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Ftp,
            Arc::new(orka_core::vfs::ftp::FtpFactory::default()),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Ftps,
            Arc::new(orka_core::vfs::ftp::FtpFactory::tls()),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Smb,
            Arc::new(orka_core::vfs::mount::MountFactory),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Nfs,
            Arc::new(orka_core::vfs::mount::MountFactory),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Adls,
            Arc::new(orka_core::vfs::adls::AdlsFactory),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Gdrive,
            Arc::new(orka_core::vfs::gdrive::GdriveFactory),
        );
        connections.register_factory(
            orka_core::vfs::Scheme::Dropbox,
            Arc::new(orka_core::vfs::dropbox::DropboxFactory),
        );
        // Shares the ops router so a remote folder size is walked
        // through the same connected backend as everything else.
        let sizes = orka_core::sizes::SizeEngine::new(sink.clone(), inner.router());
        Arc::new(Self {
            inner,
            // A watcher failure disables live refresh but not the app.
            watcher: orka_core::watch::DirWatcher::new(sink.clone()).ok(),
            search: orka_core::search::SearchEngine::new(sink),
            sizes,
            git,
            gitlog,
            connections,
        })
    }

    /// Starts (or refcounts) a watch on one directory. Changes arrive as
    /// `DirectoryChanged` events.
    pub fn watch_directory(&self, path: String) {
        // Remote locations have no filesystem events.
        if !orka_core::vfs::VPath::parse(&path).is_local() {
            return;
        }
        if let Some(watcher) = &self.watcher {
            let _ = watcher.watch(std::path::Path::new(&path));
        }
    }

    pub fn unwatch_directory(&self, path: String) {
        if let Some(watcher) = &self.watcher {
            watcher.unwatch(std::path::Path::new(&path));
        }
    }

    pub fn copy_items(&self, sources: Vec<String>, dest_dir: String) -> u64 {
        self.inner.copy(
            sources.into_iter().map(PathBuf::from).collect(),
            dest_dir.into(),
        )
    }

    pub fn move_items(&self, sources: Vec<String>, dest_dir: String) -> u64 {
        self.inner.r#move(
            sources.into_iter().map(PathBuf::from).collect(),
            dest_dir.into(),
        )
    }

    pub fn resolve_local_conflict(
        &self,
        source: String,
        dest_dir: String,
        is_move: bool,
        resolution: ConflictResolution,
    ) -> u64 {
        let resolution = match resolution {
            ConflictResolution::Replace => ops::ConflictResolution::Replace,
            ConflictResolution::KeepBoth => ops::ConflictResolution::KeepBoth,
        };
        self.inner.resolve_local_conflict(
            PathBuf::from(source),
            PathBuf::from(dest_dir),
            is_move,
            resolution,
        )
    }

    /// Duplicates local and remote items alike. A remote item is copied
    /// on its own backend, using a native copy when the backend offers
    /// one.
    pub fn duplicate_items(&self, sources: Vec<String>) -> u64 {
        self.inner
            .duplicate(sources.into_iter().map(PathBuf::from).collect())
    }

    pub fn trash_items(&self, sources: Vec<String>) -> u64 {
        self.inner
            .trash(sources.into_iter().map(PathBuf::from).collect())
    }

    /// Permanently deletes items through their backends. Works for local
    /// paths and remote URIs. There is no undo.
    pub fn delete_items(&self, sources: Vec<String>) -> u64 {
        self.inner
            .delete(sources.into_iter().map(PathBuf::from).collect())
    }

    pub fn cancel_job(&self, job_id: u64) {
        self.inner.cancel(job_id);
    }

    /// Runs the newest undo entry as a job. Returns None when the undo
    /// stack is empty.
    pub fn undo(&self) -> Option<u64> {
        self.inner.undo()
    }

    pub fn redo(&self) -> Option<u64> {
        self.inner.redo()
    }

    /// Menu title fragment, for example "Move of 3 Items".
    pub fn undo_description(&self) -> Option<String> {
        self.inner.undo_description()
    }

    pub fn redo_description(&self) -> Option<String> {
        self.inner.redo_description()
    }

    /// Compresses the selected items into a new archive in `dest_dir`.
    /// The engine picks the archive file name; the job reports the
    /// result as a normal job-finished event. Local paths only.
    pub fn archive_items(
        &self,
        sources: Vec<String>,
        dest_dir: String,
        format: ArchiveFormat,
    ) -> u64 {
        let format = match format {
            ArchiveFormat::Zip => orka_core::archives::ArchiveFormat::Zip,
            ArchiveFormat::Tar => orka_core::archives::ArchiveFormat::Tar,
            ArchiveFormat::TarGz => orka_core::archives::ArchiveFormat::TarGz,
        };
        self.inner.archive(
            sources.into_iter().map(PathBuf::from).collect(),
            PathBuf::from(dest_dir),
            format,
        )
    }

    /// Extracts one archive into a sibling folder the engine names
    /// after the archive stem. Local archives only.
    pub fn extract_item(&self, archive: String) -> u64 {
        self.inner.extract(PathBuf::from(archive))
    }

    /// Renames a local item or a remote item through its connection.
    /// Returns the new path in the same form as `path`.
    pub fn rename_item(&self, path: String, new_name: String) -> Result<String, OrkaError> {
        self.inner
            .rename(std::path::Path::new(&path), &new_name)
            .map(|p| p.display().to_string())
            .map_err(item_error_to_orka)
    }

    /// Creates a new folder under a local or a remote parent. Appends
    /// " 2", " 3", … when the name is taken. Returns the new path in
    /// the same form as `parent`.
    pub fn create_folder(&self, parent: String, name: String) -> Result<String, OrkaError> {
        self.inner
            .create_folder(std::path::Path::new(&parent), &name)
            .map(|p| p.display().to_string())
            .map_err(item_error_to_orka)
    }

    /// Creates an empty file under a local or a remote parent. Appends
    /// " 2", " 3", … when the name is taken. Returns the new path in
    /// the same form as `parent`.
    pub fn create_file(&self, parent: String, name: String) -> Result<String, OrkaError> {
        self.inner
            .create_file(std::path::Path::new(&parent), &name)
            .map(|p| p.display().to_string())
            .map_err(item_error_to_orka)
    }

    /// Starts a recursive name search under `root`. Cancels any earlier
    /// query. Results arrive as `SearchResults` events for the returned
    /// query id.
    pub fn start_search(&self, root: String, query: String, options: SearchOptions) -> u64 {
        self.search.start(
            PathBuf::from(root),
            &query,
            orka_core::search::SearchOptions {
                include_hidden: options.include_hidden,
                max_results: options.max_results,
            },
        )
    }

    pub fn cancel_search(&self, query_id: u64) {
        self.search.cancel(query_id);
    }

    /// Starts a recursive size request for the given local or remote
    /// directories. Cancels any earlier request; a navigation supersedes
    /// it. Totals arrive as `FolderSizes` events for the returned
    /// request id.
    pub fn compute_folder_sizes(&self, dirs: Vec<String>) -> u64 {
        self.sizes.compute(dirs)
    }

    pub fn cancel_folder_sizes(&self, request_id: u64) {
        self.sizes.cancel(request_id);
    }

    /// Call from applicationWillTerminate. Joins the worker and the watch
    /// dispatcher so no event fires into a torn-down Swift runtime.
    /// Search and size threads detach; their cancel flags stop further
    /// emissions.
    pub fn shutdown(&self) {
        // Stop connection events first so an in-flight connect worker
        // neither registers a backend nor emits into teardown.
        self.connections.shutdown();
        self.search.cancel_all();
        self.sizes.cancel_all();
        if let Some(watcher) = &self.watcher {
            watcher.shutdown();
        }
        self.inner.shutdown();
    }
}

fn item_error_to_orka(e: ops::ItemError) -> OrkaError {
    OrkaError::Io {
        message: format!("{}: {}", e.path, e.message),
    }
}

#[uniffi::export]
pub fn list_directory(
    path: String,
    include_hidden: bool,
    dirs_only: bool,
) -> Result<Vec<FsEntry>, OrkaError> {
    let opts = orka_core::ListOptions {
        include_hidden,
        dirs_only,
    };
    let entries = orka_core::list_dir(std::path::Path::new(&path), &opts)?;
    Ok(entries.into_iter().map(FsEntry::from).collect())
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/// Remote protocol scheme. Mirrors `orka_core::vfs::Scheme`.
#[derive(uniffi::Enum)]
pub enum Scheme {
    Sftp,
    S3,
    Ftp,
    Ftps,
    Smb,
    Nfs,
    Adls,
    Gdrive,
    Dropbox,
    Rsync,
}

impl From<Scheme> for orka_core::vfs::Scheme {
    fn from(s: Scheme) -> Self {
        match s {
            Scheme::Sftp => Self::Sftp,
            Scheme::S3 => Self::S3,
            Scheme::Ftp => Self::Ftp,
            Scheme::Ftps => Self::Ftps,
            Scheme::Smb => Self::Smb,
            Scheme::Nfs => Self::Nfs,
            Scheme::Adls => Self::Adls,
            Scheme::Gdrive => Self::Gdrive,
            Scheme::Dropbox => Self::Dropbox,
            Scheme::Rsync => Self::Rsync,
        }
    }
}

/// How a connection authenticates. Carries no secret material; secrets
/// come from `PlatformDelegate::get_secret` at connect time.
#[derive(uniffi::Enum)]
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
    /// Bearer token from the keychain. Dropbox and Google Drive.
    OAuthToken,
    /// Azure shared-key auth; the keychain secret is the base64
    /// account key.
    SharedKey,
    /// Azure ADLS Gen2 SAS auth; the keychain secret is the SAS query
    /// string, with or without a leading '?'.
    SasToken,
    /// Azure ADLS Gen2 service-principal auth; the keychain secret is
    /// the client secret.
    ServicePrincipal {
        tenant_id: String,
        client_id: String,
    },
    /// An OAuth app the user signs in to interactively. `tenant_id` is
    /// empty except for ADLS.
    OAuthApp {
        client_id: String,
        tenant_id: String,
    },
    /// Google Drive service-account auth; the keychain secret is the
    /// full service-account JSON key file content.
    ServiceAccount,
    /// SMB or NFS auth using the signed-in user's existing ticket. No
    /// secret.
    Kerberos,
    /// No credentials: anonymous FTP, guest SMB, or a mount (NFS) whose
    /// transport has no auth step at all.
    None,
}

impl From<AuthMethod> for connections::AuthMethod {
    fn from(a: AuthMethod) -> Self {
        match a {
            AuthMethod::Password => Self::Password,
            AuthMethod::SshKey { key_path } => Self::SshKey { key_path },
            AuthMethod::SshAgent => Self::SshAgent,
            AuthMethod::S3Profile { profile } => Self::S3Profile { profile },
            AuthMethod::S3Keys => Self::S3Keys,
            AuthMethod::OAuthToken => Self::OAuthToken,
            AuthMethod::SharedKey => Self::SharedKey,
            AuthMethod::SasToken => Self::SasToken,
            AuthMethod::ServicePrincipal {
                tenant_id,
                client_id,
            } => Self::ServicePrincipal {
                tenant_id,
                client_id,
            },
            AuthMethod::OAuthApp {
                client_id,
                tenant_id,
            } => Self::OAuthApp {
                client_id,
                tenant_id,
            },
            AuthMethod::ServiceAccount => Self::ServiceAccount,
            AuthMethod::Kerberos => Self::Kerberos,
            AuthMethod::None => Self::None,
        }
    }
}

/// Maps an engine scheme to its OAuth provider. Returns an error for a
/// scheme that has no OAuth sign-in.
fn oauth_provider_for(
    scheme: Scheme,
    tenant_id: String,
) -> Result<orka_core::vfs::oauth::Provider, String> {
    use orka_core::vfs::oauth::Provider;
    match scheme {
        Scheme::Gdrive => Ok(Provider::Google),
        Scheme::Dropbox => Ok(Provider::Dropbox),
        Scheme::Adls => Ok(Provider::Azure { tenant_id }),
        _ => Err("oauth sign-in is not supported for this scheme".to_string()),
    }
}

/// Runs the interactive OAuth sign-in flow for `scheme` and returns the
/// resulting token set as JSON. The caller (Swift) stores the JSON as
/// the connection's keychain secret. Blocks on user interaction in the
/// browser; call off the main thread.
#[uniffi::export]
pub fn oauth_sign_in(
    scheme: Scheme,
    client_id: String,
    client_secret: Option<String>,
    tenant_id: String,
) -> Result<String, OrkaError> {
    let provider =
        oauth_provider_for(scheme, tenant_id).map_err(|message| OrkaError::Io { message })?;
    let token_set = orka_core::vfs::oauth::sign_in(provider, &client_id, client_secret.as_deref())
        .map_err(|message| OrkaError::Io { message })?;
    token_set
        .to_json()
        .map_err(|message| OrkaError::Io { message })
}

#[derive(uniffi::Enum)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

impl From<connections::ConnectionState> for ConnectionState {
    fn from(s: connections::ConnectionState) -> Self {
        use connections::ConnectionState as C;
        match s {
            C::Disconnected => Self::Disconnected,
            C::Connecting => Self::Connecting,
            C::Connected => Self::Connected,
            C::Failed => Self::Failed,
        }
    }
}

/// One saved connection. Mirrors
/// `orka_core::vfs::connections::ConnectionConfig`.
#[derive(uniffi::Record)]
pub struct ConnectionConfig {
    pub id: String,
    pub display_name: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u32,
    pub username: String,
    pub initial_path: String,
    pub auth: AuthMethod,
}

impl From<ConnectionConfig> for connections::ConnectionConfig {
    fn from(c: ConnectionConfig) -> Self {
        Self {
            id: c.id,
            display_name: c.display_name,
            scheme: c.scheme.into(),
            host: c.host,
            port: c.port,
            username: c.username,
            initial_path: c.initial_path,
            auth: c.auth.into(),
        }
    }
}

#[uniffi::export]
impl OrkaEngine {
    /// Replaces the saved connection set. A removed id that is live
    /// disconnects and leaves the router.
    pub fn set_connections(&self, configs: Vec<ConnectionConfig>) {
        self.connections
            .set_configs(configs.into_iter().map(Into::into).collect());
    }

    /// Connects on a worker thread. Progress arrives as
    /// `ConnectionStateChanged` events.
    pub fn connect(&self, connection_id: String) {
        self.connections.connect(&connection_id);
    }

    pub fn disconnect(&self, connection_id: String) {
        self.connections.disconnect(&connection_id);
    }

    pub fn connection_state(&self, connection_id: String) -> ConnectionState {
        self.connections.state(&connection_id).into()
    }

    /// Lists a local path or a remote URI through the router. The free
    /// `list_directory` stays local-only for the sidebar tree.
    /// Synchronous and can block on the network; Swift calls it off the
    /// main actor.
    pub fn list_path(
        &self,
        path: String,
        include_hidden: bool,
        dirs_only: bool,
    ) -> Result<Vec<FsEntry>, OrkaError> {
        use orka_core::vfs::VPath;
        let (scheme, connection) = match VPath::parse(&path) {
            VPath::Local(_) => return list_directory(path, include_hidden, dirs_only),
            VPath::Remote {
                scheme, connection, ..
            } => (scheme, connection),
        };
        let (backend, backend_path) = self
            .inner
            .router()
            .resolve(&path)
            .map_err(|message| OrkaError::Io { message })?;
        let opts = orka_core::ListOptions {
            include_hidden,
            dirs_only,
        };
        let entries = backend
            .list_dir(&backend_path, &opts)
            .map_err(|message| OrkaError::Io { message })?;
        // Backends return backend-local paths. Swift treats entry.path
        // as a full path, so rewrite each one to the full URI.
        Ok(entries
            .into_iter()
            .map(|mut e| {
                e.path = orka_core::vfs::join_uri(scheme, &connection, &e.path);
                FsEntry::from(e)
            })
            .collect())
    }

    /// Reads one entry's metadata for a local path or a remote URI
    /// through the router. Synchronous and can block on the network;
    /// Swift calls it off the main actor.
    pub fn stat_path(&self, path: String) -> Result<FsEntry, OrkaError> {
        use orka_core::vfs::VPath;
        let (backend, backend_path) = self
            .inner
            .router()
            .resolve(&path)
            .map_err(|message| OrkaError::Io { message })?;
        let mut entry = backend
            .stat(&backend_path)
            .map_err(|message| OrkaError::Io { message })?;
        // A remote backend returns a backend-local path; Swift treats
        // entry.path as a full path, so rewrite it to the full URI.
        if let VPath::Remote {
            scheme, connection, ..
        } = VPath::parse(&path)
        {
            entry.path = orka_core::vfs::join_uri(scheme, &connection, &entry.path);
        }
        Ok(FsEntry::from(entry))
    }
}

// ---------------------------------------------------------------------------
// Git graph
// ---------------------------------------------------------------------------

/// One commit in the branch-panel graph. Mirrors
/// `orka_core::gitlog::GitCommit`.
#[derive(uniffi::Record)]
pub struct GitCommitInfo {
    pub oid: String,
    pub short_oid: String,
    pub summary: String,
    pub author_name: String,
    pub time_ms: i64,
    /// Row indices of the parents. Always later rows than this commit.
    pub parents: Vec<u32>,
    /// Branch and tag names that point at this commit.
    pub refs: Vec<String>,
    /// Graph column. The Swift renderer turns this into an x offset.
    pub lane: u32,
    pub is_head: bool,
}

/// One branch in the panel's branch list. Mirrors
/// `orka_core::gitlog::GitBranch`.
#[derive(uniffi::Record)]
pub struct GitBranchInfo {
    pub name: String,
    pub is_head: bool,
    pub is_local: bool,
    /// Row of the branch tip. None when the tip lies beyond the walk
    /// window.
    pub head_commit: Option<u32>,
}

/// The complete graph for one repository. Mirrors
/// `orka_core::gitlog::GitGraph`.
#[derive(uniffi::Record)]
pub struct GitGraphInfo {
    pub repo_root: String,
    /// Checked-out branch name. None means detached HEAD.
    pub branch: Option<String>,
    pub commits: Vec<GitCommitInfo>,
    pub branches: Vec<GitBranchInfo>,
    /// True when the walk hit the limit before reaching the roots.
    pub truncated: bool,
    /// URL of the "origin" remote, or of the first remote when there is
    /// no "origin". None when the repository has no remotes.
    pub remote_url: Option<String>,
}

#[uniffi::export]
impl OrkaEngine {
    /// Returns the commit graph for the repository around `dir`. None
    /// when `dir` is not inside a git work tree. Synchronous and can
    /// block on repo IO; Swift calls it off the main actor.
    pub fn git_graph(&self, dir: String, limit: u32) -> Option<GitGraphInfo> {
        let graph = self.gitlog.graph_for_dir(&dir, limit as usize)?;
        Some(GitGraphInfo {
            repo_root: graph.repo_root,
            branch: graph.branch,
            commits: graph
                .commits
                .into_iter()
                .map(|c| GitCommitInfo {
                    oid: c.oid,
                    short_oid: c.short_oid,
                    summary: c.summary,
                    author_name: c.author_name,
                    time_ms: c.time_ms,
                    parents: c.parents,
                    refs: c.refs,
                    lane: c.lane,
                    is_head: c.is_head,
                })
                .collect(),
            branches: graph
                .branches
                .into_iter()
                .map(|b| GitBranchInfo {
                    name: b.name,
                    is_head: b.is_head,
                    is_local: b.is_local,
                    head_commit: b.head_commit,
                })
                .collect(),
            truncated: graph.truncated,
            remote_url: graph.remote_url,
        })
    }
}

/// What the backend behind a path can do. Mirrors
/// `orka_core::vfs::Capabilities` so Swift can gate UI actions.
#[derive(uniffi::Record)]
pub struct PathCapabilities {
    pub is_local: bool,
    pub can_trash: bool,
    pub can_watch: bool,
    pub can_rename: bool,
    pub server_side_copy: bool,
    pub preserves_permissions: bool,
}

// ---------------------------------------------------------------------------
// Git status
// ---------------------------------------------------------------------------

/// Git state of one child of the listed directory. Mirrors
/// `orka_core::git::FileGitState`.
#[derive(uniffi::Enum)]
pub enum GitFileState {
    Modified,
    Staged,
    StagedAndModified,
    Untracked,
    Ignored,
    Conflicted,
}

impl From<orka_core::git::FileGitState> for GitFileState {
    fn from(s: orka_core::git::FileGitState) -> Self {
        use orka_core::git::FileGitState as F;
        match s {
            F::Modified => Self::Modified,
            F::Staged => Self::Staged,
            F::StagedAndModified => Self::StagedAndModified,
            F::Untracked => Self::Untracked,
            F::Ignored => Self::Ignored,
            F::Conflicted => Self::Conflicted,
        }
    }
}

#[derive(uniffi::Record)]
pub struct GitEntryStatus {
    /// Child name in the listed directory, not a path.
    pub name: String,
    pub state: GitFileState,
}

/// Git status for one listed directory. Clean children are absent from
/// `entries`.
#[derive(uniffi::Record)]
pub struct GitDirStatus {
    pub repo_root: String,
    /// Branch name. None means detached HEAD.
    pub branch: Option<String>,
    /// Short OID for detached display. Empty on an unborn HEAD.
    pub head_short: String,
    pub entries: Vec<GitEntryStatus>,
}

#[uniffi::export]
impl OrkaEngine {
    /// Reads capabilities from the engine's shared router so remote
    /// backends registered later are visible to Swift immediately.
    pub fn path_capabilities(&self, path: String) -> PathCapabilities {
        let c = self.inner.router().capabilities(&path);
        PathCapabilities {
            is_local: c.is_local,
            can_trash: c.can_trash,
            can_watch: c.can_watch,
            can_rename: c.can_rename,
            server_side_copy: c.server_side_copy,
            preserves_permissions: c.preserves_permissions,
        }
    }

    /// Returns the git status for the direct children of `dir`. None
    /// when `dir` is not inside a git work tree. Synchronous and can
    /// block on repo IO; Swift calls it off the main actor.
    pub fn git_status(&self, dir: String) -> Option<GitDirStatus> {
        let status = self.git.status_for_dir(&dir)?;
        Some(GitDirStatus {
            repo_root: status.repo_root,
            branch: status.branch,
            head_short: status.head_short,
            entries: status
                .entries
                .into_iter()
                .map(|(name, state)| GitEntryStatus {
                    name,
                    state: state.into(),
                })
                .collect(),
        })
    }

    /// Lists local and remote-tracking branches of the repo around
    /// `dir`. Empty when `dir` is not inside a work tree. Synchronous
    /// and can block on repo IO; Swift calls it off the main actor.
    pub fn git_branches(&self, dir: String) -> Vec<GitBranchInfo> {
        orka_core::git::list_branches(&dir)
            .unwrap_or_default()
            .into_iter()
            .map(|b| GitBranchInfo {
                name: b.name,
                is_head: b.is_head,
                is_local: b.is_local,
                head_commit: None,
            })
            .collect()
    }

    /// Checks out the local branch `name` in the repo around `dir`.
    /// When `create` is set and the branch does not exist, it is
    /// created from `base` (a branch shorthand such as "main" or
    /// "origin/main"), or from HEAD when `base` is None. A remote
    /// base makes the new branch track it. An existing branch is
    /// checked out either way. Refuses to overwrite uncommitted
    /// changes. Callers must reload the pane afterwards; this drops
    /// the cached status and graph so the reload sees the new branch.
    pub fn git_checkout_branch(
        &self,
        dir: String,
        name: String,
        base: Option<String>,
        create: bool,
    ) -> Result<(), OrkaError> {
        orka_core::git::checkout_branch(&dir, &name, base.as_deref(), create)
            .map_err(|e| OrkaError::Io { message: e.to_string() })?;
        self.git.invalidate_under(&dir);
        self.gitlog.invalidate_under(&dir);
        Ok(())
    }
}
