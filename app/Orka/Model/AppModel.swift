import AppKit
import Foundation
import Observation
import Security

/// App-wide state. Owns the Rust engine, the panes, and shared preferences.
@MainActor
@Observable
final class AppModel {
    static let shared = AppModel()

    let engine: OrkaEngine
    /// Live windows, in creation order. Each owns its own tab strip.
    var windowStates: [WindowState] = []
    /// The window that most recently became key. Menu commands and
    /// global events that need "the" window route through it.
    weak var keyWindowState: WindowState?
    /// True once the app started terminating. Window teardown during
    /// quit must not rewrite the saved session or touch the engine.
    var isTerminating = false
    /// A tab torn out of a window, waiting for its new window's scene.
    private var pendingDetachedPane: PaneState?
    /// Screen point (top-left) for the torn-off tab's new window.
    private var pendingWindowOrigin: NSPoint?
    /// Saved window sessions not yet claimed by a scene, oldest first.
    private var pendingSessions: [[String: Any]] = []
    /// True once launch restore spawned the extra saved windows.
    var didSpawnRestoredWindows = false
    /// Opens one more main window. Captured from the SwiftUI
    /// environment by ContentView, because AppKit-driven code (the tab
    /// tear-off) cannot reach `openWindow` directly.
    @ObservationIgnored var openMainWindow: (() -> Void)?
    /// Jobs currently running, keyed by job id.
    var activeJobs: [UInt64: JobProgress] = [:]
    /// Errors from the most recent failed job, shown in the status bar.
    var lastJobErrors: [JobItemError] = []
    /// Paths marked Cut (Cmd+X); shown dimmed until pasted or replaced.
    var cutPaths: Set<String> = []
    /// Live state per connection id, from ConnectionStateChanged events.
    var connectionStates: [String: ConnectionState] = [:]
    /// Message from the most recent failed connection attempt.
    var connectionError: String?
    /// Saved connection configs, persisted to disk.
    let connectionStore: ConnectionStore
    /// Id of the connection the sidebar is waiting to navigate into once
    /// it reports Connected. Cleared on Connected or Failed.
    private var pendingConnectionNavigation: String?
    /// Menu title fragments from the engine journal, for example
    /// "Move of 3 Items". Nil disables the menu item.
    var undoDescription: String?
    var redoDescription: String?
    /// False blocks the whole UI behind the Full Disk Access gate.
    /// A file manager cannot do its job while macOS denies protected
    /// locations like the Trash, so the app is unusable until granted.
    var hasFullDiskAccess = false
    /// Handlers waiting on one job id's `.jobFinished` event, for callers
    /// that need to react to a specific job (for example Quick Look's
    /// remote download) without polling `activeJobs`. Each handler fires
    /// once and is discarded.
    private var jobCompletionHandlers: [UInt64: (JobState) -> Void] = [:]
    /// Recursive folder totals for the Size column.
    let folderSizes = FolderSizeCache()
    /// Registry of every transfer job started by the app, for the
    /// Transfers panel.
    let transfers = TransferManager()
    /// Id of the live Get Info size request. Listing and status-bar
    /// requests live per window; the Get Info sheet keeps one global
    /// slot because it opens one sheet at a time.
    var infoSizeRequestId: UInt64? = nil
    /// Pasteboard state when the cut was taken; a changed pasteboard
    /// invalidates the cut.
    private var cutChangeCount = -1

    var showHidden: Bool {
        didSet {
            UserDefaults.standard.set(showHidden, forKey: "showHidden")
            for pane in allPanes {
                pane.directory.reload(showHidden: showHidden)
            }
        }
    }

    enum ViewMode: String {
        case details
        case icons
    }

    var viewMode: ViewMode {
        didSet {
            UserDefaults.standard.set(viewMode.rawValue, forKey: "viewMode")
        }
    }

    /// Sidebar Favorites, in display order. Persisted across launches.
    var favorites: [String] {
        didSet {
            UserDefaults.standard.set(favorites, forKey: "favorites")
        }
    }

    private init() {
        showHidden = UserDefaults.standard.bool(forKey: "showHidden")
        viewMode = UserDefaults.standard.string(forKey: "viewMode")
            .flatMap(ViewMode.init) ?? .details
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        engine = OrkaEngine(listener: EventBridge(), delegate: TrashDelegate())
        connectionStore = ConnectionStore()
        favorites = UserDefaults.standard.array(forKey: "favorites")
            as? [String] ?? [
                home, home + "/Desktop", home + "/Documents",
                home + "/Downloads", "/Applications",
            ]
        // Saved window sessions wait here; each window scene claims one
        // as it appears.
        pendingSessions = Self.loadWindowSessions()
        engine.setConnections(configs: connectionStore.toEngine())
        checkFullDiskAccess()
        RemotePromiseStager.sweepStaleStagingDirectories()
        transfers.connectionName = { [weak self] id in
            self?.connectionStore.connections
                .first { $0.id == id }?.displayName ?? id
        }
    }

    // MARK: Session persistence

    /// Legacy single-window session key from earlier releases.
    private static let sessionKey = "tabSession"
    private static let windowSessionsKey = "windowSessions"

    /// The start path for a session with nothing to restore: the last
    /// visited folder when it still exists, else the home directory.
    static func startPath() -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let last = UserDefaults.standard.string(forKey: "lastPath")
        var isDir: ObjCBool = false
        let exists = last.map {
            FileManager.default.fileExists(atPath: $0, isDirectory: &isDir)
                && isDir.boolValue
        } ?? false
        return exists ? last! : home
    }

    /// All saved window sessions, oldest window first. Falls back to
    /// the legacy single-window key from earlier releases.
    private static func loadWindowSessions() -> [[String: Any]] {
        if let saved = UserDefaults.standard.array(
            forKey: windowSessionsKey) as? [[String: Any]], !saved.isEmpty
        {
            return saved
        }
        if let legacy = UserDefaults.standard.dictionary(forKey: sessionKey) {
            return [legacy]
        }
        return []
    }

    /// Rebuilds tabs from one saved window session. A local path that no
    /// longer exists drops out; remote URIs restore as-is, since the
    /// connection may not be up yet. An empty result means the
    /// caller falls back to the single start tab.
    private static func loadSessionTabs(_ session: [String: Any]) -> [PaneState] {
        let raw = session["tabs"] as? [[String: Any]] ?? []
        var panes: [PaneState] = []
        for item in raw {
            guard let path = item["path"] as? String, !path.isEmpty else {
                continue
            }
            var isDir: ObjCBool = false
            let isRemote = !OrkaPath.isLocal(path)
            if !isRemote
                && !(FileManager.default.fileExists(
                    atPath: path, isDirectory: &isDir) && isDir.boolValue)
            {
                continue
            }
            let pane = PaneState(path: path)
            if let colorRaw = item["color"] as? String,
                let color = TabColor(rawValue: colorRaw)
            {
                pane.color = color
            }
            panes.append(pane)
        }
        return panes
    }

    /// Writes every window's tab set and active index. Called after
    /// every change that shapes the session: tab open, close, select,
    /// move, navigation, and color edits. An empty window list is not
    /// saved, so closing the last window keeps the previous session.
    func saveSession() {
        guard !isTerminating else { return }
        let sessions = windowStates.map { window -> [String: Any] in
            [
                "tabs": window.panes.map { pane -> [String: Any] in
                    [
                        "path": pane.directory.path,
                        "color": pane.color.rawValue,
                    ]
                },
                "activeIndex": window.activePaneIndex,
            ]
        }
        guard !sessions.isEmpty else { return }
        UserDefaults.standard.set(sessions, forKey: Self.windowSessionsKey)
    }

    // MARK: Windows

    /// State for a new window scene. Priority: a tab torn out of
    /// another window, then the next saved session from launch restore,
    /// then a fresh window at the start path.
    func makeWindowState() -> WindowState {
        let state: WindowState
        if let pane = pendingDetachedPane {
            pendingDetachedPane = nil
            state = WindowState(app: self, panes: [pane], alreadyWatched: true)
            state.pendingOrigin = pendingWindowOrigin
            pendingWindowOrigin = nil
        } else if !pendingSessions.isEmpty {
            let session = pendingSessions.removeFirst()
            state = WindowState(
                app: self,
                panes: Self.loadSessionTabs(session),
                activeIndex: session["activeIndex"] as? Int ?? 0)
        } else {
            state = WindowState(app: self, panes: [])
        }
        windowStates.append(state)
        if keyWindowState == nil { keyWindowState = state }
        return state
    }

    /// Restored windows beyond the first that still wait for a scene.
    var pendingRestoreCount: Int { pendingSessions.count }

    /// The window menu commands and global events act on: the key
    /// window, else the first live window.
    var focusedWindow: WindowState? { keyWindowState ?? windowStates.first }

    var focusedPane: PaneState? { focusedWindow?.activePane }

    /// Every tab across every window, for global refresh fan-out.
    var allPanes: [PaneState] { windowStates.flatMap(\.panes) }

    func window(containing pane: PaneState) -> WindowState? {
        windowStates.first { window in
            window.panes.contains { $0 === pane }
        }
    }

    private func windowState(withPaneID id: UUID) -> (WindowState, Int)? {
        for window in windowStates {
            if let index = window.panes.firstIndex(where: { $0.id == id }) {
                return (window, index)
            }
        }
        return nil
    }

    /// Bookkeeping when a window closes. Panes still in the window
    /// release their engine watches; a pane already moved to another
    /// window is no longer in `panes` and stays watched.
    func windowClosed(_ state: WindowState) {
        guard !isTerminating else { return }
        guard let index = windowStates.firstIndex(where: { $0 === state })
        else { return }
        windowStates.remove(at: index)
        for pane in state.panes {
            releasePane(pane)
        }
        state.cancelDeepSearch()
        if keyWindowState === state {
            keyWindowState = windowStates.first
        }
        saveSession()
    }

    /// Drops a closed pane's engine watch.
    func releasePane(_ pane: PaneState) {
        engine.unwatchDirectory(path: pane.directory.path)
    }

    // MARK: Tab dragging

    /// Moves one tab to `target` at `index`. Covers both a reorder
    /// within one window and a move across windows; a source window
    /// that loses its last tab closes, like a browser window.
    func moveTab(paneID: UUID, to target: WindowState, at index: Int) {
        guard let (source, sourceIndex) = windowState(withPaneID: paneID)
        else { return }
        if source === target {
            let insertAt = min(
                sourceIndex < index ? index - 1 : index,
                source.panes.count - 1)
            guard insertAt != sourceIndex else {
                source.selectTab(sourceIndex)
                return
            }
            let pane = source.panes.remove(at: sourceIndex)
            source.panes.insert(pane, at: insertAt)
            source.activePaneIndex = insertAt
        } else {
            guard let pane = source.removePane(at: sourceIndex) else { return }
            target.insertPane(pane, at: index)
            target.nsWindow?.makeKeyAndOrderFront(nil)
        }
        saveSession()
    }

    /// Tears one tab out into a new window whose top-left lands at
    /// `screenPoint`. A window's only tab moves the whole window
    /// instead, the way a browser moves a one-tab window.
    func detachTab(paneID: UUID, at screenPoint: NSPoint) {
        guard let (source, sourceIndex) = windowState(withPaneID: paneID)
        else { return }
        guard source.panes.count > 1 else {
            source.nsWindow?.setFrameTopLeftPoint(screenPoint)
            return
        }
        guard let pane = source.removePane(at: sourceIndex) else { return }
        pendingDetachedPane = pane
        pendingWindowOrigin = screenPoint
        openMainWindow?()
        saveSession()
    }

    /// Keeps one refcounted engine watch on the pane's visible directory.
    func attachWatch(to pane: PaneState) {
        engine.watchDirectory(path: pane.directory.path)
        pane.directory.onPathChanged = { [weak self, weak pane] old, new in
            guard let self else { return }
            self.engine.unwatchDirectory(path: old)
            self.engine.watchDirectory(path: new)
            if let pane, let window = self.window(containing: pane) {
                // The old pane total no longer matters; a fresh load
                // starts a new request.
                window.cancelPaneSizeRequest()
                window.searchText = ""
            }
            UserDefaults.standard.set(new, forKey: "lastPath")
            self.saveSession()
        }
        pane.directory.onLoaded = { [weak self, weak pane] in
            guard let self, let pane,
                let window = self.window(containing: pane),
                pane === window.activePane
            else { return }
            window.requestFolderSizesForActivePane()
            window.requestPaneFolderSize()
        }
    }

    func navigate(to path: String) {
        focusedWindow?.navigate(to: path)
    }

    /// An explicit navigation cancels any pending connection jump.
    /// The Connected handler clears and reads the pending id before
    /// it calls navigate, so that flow is unaffected.
    func cancelPendingConnectionNavigation() {
        pendingConnectionNavigation = nil
    }

    // MARK: Tabs (menu command routing)

    func newTab() {
        focusedWindow?.newTab()
    }

    func closeActiveTab() {
        focusedWindow?.closeActiveTab()
    }

    func nextTab() {
        focusedWindow?.nextTab()
    }

    func previousTab() {
        focusedWindow?.previousTab()
    }

    // MARK: Favorites

    func addFavorite(_ path: String) {
        guard !favorites.contains(path) else { return }
        favorites.append(path)
    }

    func removeFavorite(_ path: String) {
        favorites.removeAll { $0 == path }
    }

    func moveFavorites(from source: IndexSet, to destination: Int) {
        favorites.move(fromOffsets: source, toOffset: destination)
    }

    func open(_ entry: FsEntry) {
        // .app bundles are directories but must launch, not open as folders.
        if entry.isDir && !entry.path.hasSuffix(".app") {
            navigate(to: entry.path)
            return
        }
        guard OrkaPath.isLocal(entry.path) else {
            // Opening a remote file needs a downloaded copy to hand to
            // NSWorkspace; that path is not wired yet. Quick Look (Space)
            // already downloads and previews it.
            lastJobErrors = [JobItemError(
                path: entry.path,
                message: "Opening a remote file isn't supported yet. Press Space to preview it.")]
            return
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: entry.path))
    }

    func shutdown() {
        // The session write comes first: window teardown during quit is
        // blocked from saving, so this is the final state on disk.
        saveSession()
        isTerminating = true
        engine.shutdown()
    }

    // MARK: Engine events

    func handle(_ event: OrkaEvent) {
        switch event {
        case .jobProgress(let progress):
            activeJobs[progress.jobId] = progress
            _ = transfers.applyProgress(progress)
        case .jobFinished(let jobId, let state, let errors):
            activeJobs[jobId] = nil
            let handled = transfers.applyFinished(
                jobId: jobId, state: state, errors: errors)
            // A job the transfer registry knows keeps its errors on its
            // own row; an unregistered job keeps today's status-bar
            // behavior.
            if !handled {
                lastJobErrors = errors
            }
            refreshJournal()
            if let handler = jobCompletionHandlers.removeValue(forKey: jobId) {
                handler(state)
            }
            // Remote directories have no change watcher; re-list them after
            // every job so deletes and uploads appear without manual Refresh.
            for pane in allPanes where !OrkaPath.isLocal(pane.directory.path) {
                pane.directory.reload(showHidden: showHidden)
            }
        case .directoryChanged(let paths):
            // Drop cached totals under each changed path first; they are
            // stale once the contents move.
            for path in paths {
                folderSizes.invalidate(underPrefix: path)
            }
            // The engine watches each pane's visible directory; re-list the
            // panes that changed. Reload preserves the selection by path.
            let changed = Set(paths)
            for pane in allPanes where changed.contains(pane.directory.path) {
                pane.directory.reload(showHidden: showHidden)
            }
        case .searchResults(let queryId, let results, let done):
            // Snapshots from a cancelled or superseded query are stale.
            // The query id names the window that started the search.
            guard let window = windowStates.first(
                where: { $0.currentDeepSearchId == queryId })
            else { return }
            window.applySearchResults(results, done: done)
        case .folderSizes(let requestId, let sizes, let done):
            // Totals from a cancelled or superseded request are stale.
            // Listing and status-bar requests live per window.
            let isInfo = requestId == infoSizeRequestId
            let listingWindow = windowStates.first {
                $0.currentSizeRequestId == requestId
            }
            let paneWindow = windowStates.first {
                $0.paneSizeRequestId == requestId
            }
            guard isInfo || listingWindow != nil || paneWindow != nil else {
                return
            }
            folderSizes.apply(sizes)
            if done {
                if isInfo { infoSizeRequestId = nil }
                listingWindow?.currentSizeRequestId = nil
                paneWindow?.paneSizeRequestId = nil
            }
        case .connectionStateChanged(let connectionId, let state, let message):
            // A late worker event for a deleted connection must not
            // re-insert its state.
            guard connectionStore.connections.contains(
                where: { $0.id == connectionId })
            else { return }
            connectionStates[connectionId] = state
            switch state {
            case .connected:
                connectionError = nil
                if pendingConnectionNavigation == connectionId {
                    pendingConnectionNavigation = nil
                    if let stored = connectionStore.connections.first(
                        where: { $0.id == connectionId })
                    {
                        navigate(to: stored.uri)
                    }
                }
            case .failed:
                connectionError = message ?? "Connection failed: \(connectionId)"
                if pendingConnectionNavigation == connectionId {
                    pendingConnectionNavigation = nil
                }
            case .disconnected, .connecting:
                break
            }
        }
    }

    // MARK: Connections

    /// Pushes the saved connection set to the engine. Call after every
    /// store mutation so the router stays in sync.
    private func pushConnections() {
        engine.setConnections(configs: connectionStore.toEngine())
    }

    /// Saves a connection's config and, when the editor supplied one, its
    /// secret. Used for both new and edited connections.
    func saveConnection(_ config: StoredConnection, secret: String?) {
        if let secret, !secret.isEmpty {
            KeychainHelper.save(account: config.id, secret: secret)
        } else if !config.auth.needsSecret {
            // The chosen auth kind never uses a secret. Remove any stale
            // secret left from a previous auth choice. For kinds that can
            // use a secret, a blank field means "keep the saved secret".
            KeychainHelper.delete(account: config.id)
        }
        connectionStore.update(config)
        pushConnections()
    }

    func removeConnection(id: String) {
        engine.disconnect(connectionId: id)
        connectionStore.remove(id: id)
        connectionStates[id] = nil
        // A pending jump into a removed connection must not fire.
        if pendingConnectionNavigation == id {
            pendingConnectionNavigation = nil
        }
        KeychainHelper.delete(account: id)
        pushConnections()
    }

    func disconnectConnection(id: String) {
        engine.disconnect(connectionId: id)
    }

    /// Connects a saved connection and navigates into it once the engine
    /// reports Connected. A Failed report instead surfaces
    /// `connectionError` and drops the pending navigation.
    func connectAndNavigate(_ stored: StoredConnection) {
        connectionError = nil
        pendingConnectionNavigation = stored.id
        engine.connect(connectionId: stored.id)
    }

    /// Pulls undo/redo menu titles from the engine journal.
    private func refreshJournal() {
        undoDescription = engine.undoDescription()
        redoDescription = engine.redoDescription()
    }

    func cancelJob(_ jobId: UInt64) {
        engine.cancelJob(jobId: jobId)
    }

    /// Registers a one-shot callback for `jobId`'s `.jobFinished` event.
    func onJobFinished(jobId: UInt64, handler: @escaping (JobState) -> Void) {
        jobCompletionHandlers[jobId] = handler
    }

    // MARK: Clipboard

    // Operations take the window they act in. A context menu passes its
    // own window, because a right-click in a background window does not
    // make it key; a menu-bar command passes nil and gets the key
    // window's pane.

    /// The pane an operation acts on: the given window's active pane,
    /// else the key window's.
    private func pane(in window: WindowState?) -> PaneState? {
        (window ?? focusedWindow)?.activePane
    }

    private func selectedPaths(in window: WindowState?) -> [String] {
        guard let directory = pane(in: window)?.directory else { return [] }
        let selection = directory.selection
        return directory.entries
            .filter { selection.contains($0.path) }
            .map(\.path)
    }

    func copySelection(in window: WindowState? = nil) {
        guard let pane = pane(in: window),
            OrkaPath.isLocal(pane.directory.path)
        else {
            NSSound.beep()
            return
        }
        writeToPasteboard(paths: selectedPaths(in: window))
        cutPaths = []
    }

    func cutSelection(in window: WindowState? = nil) {
        guard let pane = pane(in: window),
            OrkaPath.isLocal(pane.directory.path)
        else {
            NSSound.beep()
            return
        }
        let paths = selectedPaths(in: window)
        writeToPasteboard(paths: paths)
        cutPaths = Set(paths)
        cutChangeCount = NSPasteboard.general.changeCount
    }

    func paste(in window: WindowState? = nil) {
        let pasteboard = NSPasteboard.general
        guard let urls = pasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]) as? [URL],
            !urls.isEmpty,
            let dest = pane(in: window)?.directory.path
        else { return }
        let sources = urls.map(\.path)
        let isCut = !cutPaths.isEmpty
            && pasteboard.changeCount == cutChangeCount
            && Set(sources) == cutPaths
        startEngineTransfer(sources: sources, destDir: dest, move: isCut)
        if isCut {
            cutPaths = []
        }
    }

    var canPaste: Bool {
        NSPasteboard.general.canReadObject(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true])
    }

    private func writeToPasteboard(paths: [String]) {
        guard !paths.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.writeObjects(paths.map { NSURL(fileURLWithPath: $0) })
    }

    /// Writes paths to the pasteboard as newline-joined text, for the
    /// "Copy Path" and "Copy Relative Path" context menu items. When
    /// `relative` is true, each path drops the active directory's prefix;
    /// a path outside that directory keeps its full form.
    func copyPaths(
        _ paths: [String], relative: Bool, in window: WindowState? = nil
    ) {
        guard !paths.isEmpty else { return }
        let text: String
        if relative, let base = pane(in: window)?.directory.path {
            let prefix = base.hasSuffix("/") ? base : base + "/"
            text = paths.map { path in
                path.hasPrefix(prefix)
                    ? String(path.dropFirst(prefix.count)) : path
            }.joined(separator: "\n")
        } else {
            text = paths.joined(separator: "\n")
        }
        let pasteboard = NSPasteboard.general
        pasteboard.declareTypes([.string], owner: nil)
        pasteboard.setString(text, forType: .string)
    }

    // MARK: Operations

    /// True when the path's extension marks a supported archive: zip,
    /// tar, tar.gz, or tgz. One source of truth for the Extract menu
    /// gating in both views and for `extractSelection`.
    static func isArchivePath(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent.lowercased()
        if name.hasSuffix(".tar.gz") { return true }
        let ext = (path as NSString).pathExtension.lowercased()
        return ext == "zip" || ext == "tar" || ext == "tgz"
    }

    func duplicateSelection(in window: WindowState? = nil) {
        guard let pane = pane(in: window),
            OrkaPath.isLocal(pane.directory.path)
        else {
            NSSound.beep()
            return
        }
        let paths = selectedPaths(in: window)
        guard !paths.isEmpty else { return }
        _ = engine.duplicateItems(sources: paths)
    }

    /// Cmd+Delete and both context menus. A local directory trashes the
    /// selection immediately; a remote directory has no trash, so this
    /// opens the permanent-delete confirmation instead.
    func trashSelection(in window: WindowState? = nil) {
        guard let target = window ?? focusedWindow else { return }
        let paths = selectedPaths(in: target)
        guard !paths.isEmpty else { return }
        guard OrkaPath.isLocal(target.activePane.directory.path) else {
            target.confirmingDelete = paths
            return
        }
        _ = engine.trashItems(sources: paths)
    }

    /// Runs the permanent delete the confirmation dialog approved. Works
    /// for local and remote items. There is no undo.
    func confirmPermanentDelete(in window: WindowState) {
        guard let paths = window.confirmingDelete else { return }
        window.confirmingDelete = nil
        _ = engine.deleteItems(sources: paths)
    }

    /// Dismisses the permanent-delete confirmation without deleting.
    func cancelPermanentDelete(in window: WindowState) {
        window.confirmingDelete = nil
    }

    /// Absolute path of the user's Trash directory.
    static var trashPath: String {
        (try? FileManager.default.url(
            for: .trashDirectory, in: .userDomainMask,
            appropriateFor: nil, create: false).path)
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".Trash").path
    }

    /// Probes Full Disk Access by listing the Trash. POSIX permissions
    /// always allow the owner there, so a failure means macOS privacy
    /// protection blocks the app. The launch gate polls this until the
    /// grant arrives. Set ORKA_SKIP_FDA_GATE=1 to skip the gate in
    /// ad-hoc test builds.
    func checkFullDiskAccess() {
        if ProcessInfo.processInfo.environment["ORKA_SKIP_FDA_GATE"] == "1" {
            hasFullDiskAccess = true
            return
        }
        hasFullDiskAccess = (try? FileManager.default
            .contentsOfDirectory(atPath: Self.trashPath)) != nil
    }

    /// Sidebar Trash row. The launch gate guarantees access.
    func openTrash(in window: WindowState? = nil) {
        (window ?? focusedWindow)?.navigate(to: Self.trashPath)
    }

    /// Opens the Privacy & Security > Full Disk Access pane.
    func openFullDiskAccessSettings() {
        let pane = "x-apple.systempreferences:"
            + "com.apple.preference.security?Privacy_AllFiles"
        if let url = URL(string: pane) {
            NSWorkspace.shared.open(url)
        }
    }

    /// Opens the Empty Trash confirmation. An empty Trash beeps instead.
    func requestEmptyTrash(in window: WindowState? = nil) {
        guard !trashContents().isEmpty else {
            NSSound.beep()
            return
        }
        (window ?? focusedWindow)?.confirmingEmptyTrash = true
    }

    /// Runs the permanent delete the Empty Trash confirmation approved.
    /// The contents are listed here, not at request time, so items
    /// trashed while the dialog was open also delete. There is no undo.
    func confirmEmptyTrash(in window: WindowState) {
        window.confirmingEmptyTrash = false
        let paths = trashContents()
        guard !paths.isEmpty else { return }
        _ = engine.deleteItems(sources: paths)
    }

    /// Dismisses the Empty Trash confirmation without deleting.
    func cancelEmptyTrash(in window: WindowState) {
        window.confirmingEmptyTrash = false
    }

    /// Every item in the Trash. The path-based listing includes hidden
    /// files, so dotfiles do not survive an Empty Trash.
    private func trashContents() -> [String] {
        let trash = Self.trashPath
        let names = (try? FileManager.default
            .contentsOfDirectory(atPath: trash)) ?? []
        return names.map { (trash as NSString).appendingPathComponent($0) }
    }

    /// Compresses the selection into an archive in the active directory.
    /// The engine picks the archive file name and dedupes it inside the
    /// job; progress shows in the existing jobs UI. Remote directories
    /// cannot archive, so they beep.
    func compressSelection(
        as format: ArchiveFormat, in window: WindowState? = nil
    ) {
        guard let pane = pane(in: window),
            OrkaPath.isLocal(pane.directory.path)
        else {
            NSSound.beep()
            return
        }
        let paths = selectedPaths(in: window)
        guard !paths.isEmpty else { return }
        _ = engine.archiveItems(
            sources: paths, destDir: pane.directory.path, format: format)
    }

    /// Extracts the one selected archive into a sibling folder named
    /// after the archive stem. Anything other than a single selected
    /// archive reports an error; a remote directory just beeps because
    /// the menu never offers extraction there.
    func extractSelection(in window: WindowState? = nil) {
        guard let pane = pane(in: window),
            OrkaPath.isLocal(pane.directory.path)
        else {
            NSSound.beep()
            return
        }
        let paths = selectedPaths(in: window)
        guard !paths.isEmpty else { return }
        guard paths.count == 1, let path = paths.first,
            Self.isArchivePath(path)
        else {
            lastJobErrors = [JobItemError(
                path: paths.first ?? pane.directory.path,
                message: "Not an archive: \(paths.first ?? pane.directory.path)")]
            return
        }
        _ = engine.extractItem(archive: path)
    }

    /// Cmd+I. Without a selection, shows info for the current folder.
    func getInfo(in window: WindowState? = nil) {
        guard let target = window ?? focusedWindow else { return }
        let path = selectedPaths(in: target).first
            ?? target.activePane.directory.path
        target.infoTarget = InfoTarget(path: path)
    }

    /// Unmounts a volume from the sidebar. Errors land in the status bar.
    func eject(volumeURL: URL) {
        Task.detached(priority: .userInitiated) {
            do {
                try NSWorkspace.shared.unmountAndEjectDevice(at: volumeURL)
            } catch {
                await MainActor.run {
                    AppModel.shared.lastJobErrors = [JobItemError(
                        path: volumeURL.path,
                        message: error.localizedDescription)]
                }
            }
        }
    }

    // MARK: Folder sizes

    /// Requests a fresh recursive total for one folder, for the Get Info
    /// sheet. The result lands in `folderSizes`; the caller reads it back
    /// from there once the request completes. Runs on its own request id
    /// so it never cancels a listing's Size-column request.
    func requestFolderSize(path: String) {
        if let previous = infoSizeRequestId {
            engine.cancelFolderSizes(requestId: previous)
        }
        infoSizeRequestId = engine.computeFolderSizes(dirs: [path])
    }

    /// Cmd+Z. An active rename field editor gets its own text undo first.
    func undo() {
        if let manager = fieldEditorUndoManager {
            manager.undo()
            return
        }
        _ = engine.undo()
        refreshJournal()
    }

    func redo() {
        if let manager = fieldEditorUndoManager {
            manager.redo()
            return
        }
        _ = engine.redo()
        refreshJournal()
    }

    private var fieldEditorUndoManager: UndoManager? {
        guard let editor = NSApp.keyWindow?.firstResponder as? NSText,
            editor.isFieldEditor
        else { return nil }
        return editor.undoManager
    }

    func newFolder(in window: WindowState? = nil) {
        guard let pane = pane(in: window),
            OrkaPath.isLocal(pane.directory.path)
        else {
            NSSound.beep()
            return
        }
        do {
            let created = try engine.createFolder(
                parent: pane.directory.path, name: "untitled folder")
            refreshJournal()
            pane.directory.reload(showHidden: showHidden)
            pane.directory.selection = [created]
        } catch {
            lastJobErrors = [JobItemError(
                path: pane.directory.path,
                message: String(describing: error))]
        }
    }

    /// Returns the new path, or nil after showing the error in the status bar.
    func rename(
        path: String, to newName: String, in window: WindowState? = nil
    ) -> String? {
        guard let pane = pane(in: window),
            OrkaPath.isLocal(pane.directory.path)
        else {
            NSSound.beep()
            return nil
        }
        do {
            let newPath = try engine.renameItem(path: path, newName: newName)
            refreshJournal()
            pane.directory.reload(showHidden: showHidden)
            pane.directory.selection = [newPath]
            return newPath
        } catch {
            lastJobErrors = [JobItemError(
                path: path, message: String(describing: error))]
            return nil
        }
    }

    /// Starts non-conflicting items and prompts for local name conflicts.
    /// The pre-scan touches the filesystem once per item, so it runs off
    /// the main actor; jobs start and conflicts enqueue back on it.
    func transfer(
        sources: [String], to destDir: String, move: Bool,
        in window: WindowState? = nil
    ) {
        guard OrkaPath.isLocal(destDir), sources.allSatisfy(OrkaPath.isLocal)
        else {
            // Remote endpoints have no local conflict scan.
            startEngineTransfer(sources: sources, destDir: destDir, move: move)
            return
        }
        // Resolve the window now; focus can change during the scan.
        let target = window ?? focusedWindow
        Task {
            let scan = await Task.detached(priority: .userInitiated) {
                Self.scanLocalConflicts(
                    sources: sources, destDir: destDir, move: move)
            }.value
            startEngineTransfer(
                sources: scan.ready, destDir: destDir, move: move)
            target?.enqueueTransferConflicts(scan.conflicts)
        }
    }

    /// Splits a local transfer into items that can start now and items
    /// whose destination name is taken. Safe to call off the main actor.
    private nonisolated static func scanLocalConflicts(
        sources: [String], destDir: String, move: Bool
    ) -> (ready: [String], conflicts: [TransferConflict]) {
        var ready: [String] = []
        var conflicts: [TransferConflict] = []
        var claimedDestinations: Set<String> = []
        for source in sources {
            let destination = URL(fileURLWithPath: destDir)
                .appendingPathComponent(
                    URL(fileURLWithPath: source).lastPathComponent).path
            if URL(fileURLWithPath: source).standardizedFileURL.path
                == URL(fileURLWithPath: destination).standardizedFileURL.path
            {
                continue
            }
            let destinationWasClaimed = !claimedDestinations
                .insert(destination).inserted
            if destinationWasClaimed
                || FileManager.default.fileExists(atPath: destination)
            {
                conflicts.append(TransferConflict(
                    source: source,
                    destination: destination,
                    destinationDirectory: destDir,
                    move: move))
            } else {
                ready.append(source)
            }
        }
        return (ready, conflicts)
    }

    private func startEngineTransfer(
        sources: [String], destDir: String, move: Bool
    ) {
        guard !sources.isEmpty else { return }
        let jobId = move
            ? engine.moveItems(sources: sources, destDir: destDir)
            : engine.copyItems(sources: sources, destDir: destDir)
        transfers.register(
            jobId: jobId, sources: sources, destDir: destDir, move: move)
    }

    /// Downloads remote items into a local folder. Always a copy: a
    /// remote source has no "move" the engine can perform across the
    /// wire.
    func downloadItems(_ paths: [String], to localDir: String) {
        transfer(sources: paths, to: localDir, move: false, in: focusedWindow)
    }

    /// Uploads local items into a remote folder. Always a copy, for the
    /// same reason as `downloadItems`.
    func uploadItems(_ paths: [String], to remoteDir: String) {
        transfer(
            sources: paths, to: remoteDir, move: false, in: focusedWindow)
    }

    func resolveTransferConflict(
        _ conflict: TransferConflict, as resolution: ConflictResolution
    ) {
        let jobId = engine.resolveLocalConflict(
            source: conflict.source,
            destDir: conflict.destinationDirectory,
            isMove: conflict.move,
            resolution: resolution)
        // Register the job so the item joins its drop's other items in
        // the Transfers panel instead of erroring through the status bar.
        transfers.register(
            jobId: jobId,
            sources: [conflict.source],
            destDir: conflict.destinationDirectory,
            move: conflict.move)
    }

    // MARK: Terminal

    /// Opens the active directory in the user's default terminal app.
    /// `open -a` resolves the user's chosen terminal; Terminal.app is
    /// the fallback when the preference is unset.
    func openInTerminal(in window: WindowState? = nil) {
        guard let path = pane(in: window)?.directory.path,
            OrkaPath.isLocal(path)
        else { return }
        let defaultApp = UserDefaults.standard.string(
            forKey: "defaultTerminalApp") ?? "Terminal"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = ["-a", defaultApp, path]
        do {
            try process.run()
        } catch {
            lastJobErrors = [JobItemError(
                path: path,
                message: "Could not open a terminal: \(error.localizedDescription)")]
        }
    }
}

/// Identifiable wrapper so a path can drive a SwiftUI sheet.
struct InfoTarget: Identifiable {
    let path: String
    var id: String { path }
}

/// Identifiable wrapper so an upload's local sources can drive the
/// upload picker sheet.
struct UploadTarget: Identifiable {
    let id = UUID()
    let sources: [String]
}

struct TransferConflict: Identifiable {
    let id = UUID()
    let source: String
    let destination: String
    let destinationDirectory: String
    let move: Bool

    var name: String {
        URL(fileURLWithPath: destination).lastPathComponent
    }
}

/// Receives engine events on a Rust thread and hops to the main actor.
/// Must never block.
private final class EventBridge: EventListener {
    func onEvent(event: OrkaEvent) {
        Task { @MainActor in
            AppModel.shared.handle(event)
        }
    }
}

/// Trashes items and reads secrets for the Rust engine.
/// `NSFileManager.trashItem` is the only API that fills the real Finder
/// trash with Put Back support. Runs on engine worker threads; the shared
/// FileManager and the keychain APIs are thread-safe here.
private final class TrashDelegate: PlatformDelegate {
    func trashItem(path: String) throws -> String {
        var trashedURL: NSURL?
        try FileManager.default.trashItem(
            at: URL(fileURLWithPath: path), resultingItemURL: &trashedURL)
        guard let trashed = trashedURL?.path else {
            throw OrkaError.Io(message: "trash returned no path for \(path)")
        }
        return trashed
    }

    /// Reads the connection's password from the keychain. Service is
    /// "Orka"; the account is the connection id. Nil means no stored
    /// secret.
    func getSecret(connectionId: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Orka",
            kSecAttrAccount as String: connectionId,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Stores a refreshed secret for one connection, for example a
    /// renewed OAuth token set.
    func setSecret(connectionId: String, value: String) {
        KeychainHelper.save(account: connectionId, secret: value)
    }
}
