import AppKit
import Foundation
import Observation

/// Per-window state: the tab strip and everything scoped to one window.
/// AppModel stays global (engine, jobs, connections, preferences); each
/// window owns its own tabs, search, panels, and dialogs, so windows
/// stop mirroring each other.
@MainActor
@Observable
final class WindowState: Identifiable {
    let id = UUID()

    /// The global model. Unowned: AppModel.shared outlives every window.
    unowned let app: AppModel

    /// The AppKit window, once WindowChromeConfigurator binds it.
    /// Needed to close an emptied window and to place a torn-off tab.
    @ObservationIgnored weak var nsWindow: NSWindow? {
        didSet { applyPendingOrigin() }
    }

    /// Where a torn-off tab's new window should appear, in screen
    /// coordinates. Consumed when the window binds.
    @ObservationIgnored var pendingOrigin: NSPoint?

    var panes: [PaneState]

    var activePaneIndex = 0 {
        didSet {
            guard oldValue != activePaneIndex else { return }
            requestFolderSizesForActivePane()
            requestPaneFolderSize()
            app.saveSession()
        }
    }

    /// True while the breadcrumb bar shows an editable text path (Cmd+L).
    var isEditingPath = false

    /// Toolbar search field. Non-empty text filters the visible listing
    /// live; Enter runs a deep Spotlight search of the current tree.
    var searchText = "" {
        didSet {
            if searchText.isEmpty {
                activePane.directory.clearSearchResults()
                deepSearchTarget?.clearSearchResults()
                cancelDeepSearch()
            } else if let submitted = submittedQuery, searchText != submitted {
                // The field no longer shows the submitted query. Drop the
                // deep results so the live filter takes over.
                deepSearchTarget?.clearSearchResults()
                cancelDeepSearch()
            }
        }
    }
    var isSearching = false
    /// Id of the live engine search. Events for other ids are stale.
    var currentDeepSearchId: UInt64? = nil
    /// The directory that started the deep search. Results land here,
    /// not in whichever pane is active when a snapshot arrives.
    private(set) weak var deepSearchTarget: DirectoryModel?
    /// The query text as submitted, to detect later edits to the field.
    private var submittedQuery: String?

    /// Id of the live listing size request for this window's active
    /// pane. Events for other ids are stale.
    var currentSizeRequestId: UInt64? = nil
    /// Id of the live status-bar size request for the pane's own
    /// directory. Separate from the listing request so a full-tree walk
    /// never delays the Size column.
    var paneSizeRequestId: UInt64? = nil

    /// Non-nil shows the git graph panel in this window.
    var showingGitGraph = false
    /// The git panel's share of the split area, in 0...1. Persisted as a
    /// shared preference; each window starts from the saved share.
    var gitPanelFraction: Double? {
        didSet {
            UserDefaults.standard.set(
                gitPanelFraction ?? 0, forKey: "gitPanelFraction")
        }
    }
    /// Width the graph content wants, from the panel's latest load.
    var gitPanelIdealWidth: Double = 0

    /// Non-nil shows the Get Info sheet for this path.
    var infoTarget: InfoTarget?
    /// Non-nil shows the upload file picker sheet.
    var uploadPickerTarget: UploadTarget?
    /// Non-nil shows the connection add/edit sheet.
    var editingConnection: ConnectionEditorTarget?
    /// Non-nil shows the permanent-delete confirmation for these paths.
    var confirmingDelete: [String]?
    /// True shows the Empty Trash confirmation.
    var confirmingEmptyTrash = false
    /// Conflict currently shown for a local file transfer.
    var transferConflict: TransferConflict?
    /// Conflicts waiting behind the current prompt.
    private var queuedTransferConflicts: [TransferConflict] = []

    /// `alreadyWatched` marks panes arriving from another window: their
    /// engine watches moved with them, so attaching again would
    /// double-count the refcounted watch.
    init(
        app: AppModel, panes: [PaneState], activeIndex: Int = 0,
        alreadyWatched: Bool = false
    ) {
        self.app = app
        self.panes = panes.isEmpty
            ? [PaneState(path: AppModel.startPath())] : panes
        let savedFraction = UserDefaults.standard.double(
            forKey: "gitPanelFraction")
        gitPanelFraction = savedFraction > 0 ? savedFraction : nil
        activePaneIndex = min(max(0, activeIndex), self.panes.count - 1)
        if !alreadyWatched {
            for pane in self.panes {
                app.attachWatch(to: pane)
            }
        }
    }

    /// The pane the window shows. A window briefly holds no panes when
    /// a tab drag empties it before it closes; a view evaluating in
    /// that gap gets a throwaway pane instead of an index crash.
    var activePane: PaneState {
        guard !panes.isEmpty else {
            return PaneState(path: AppModel.startPath())
        }
        return panes[min(activePaneIndex, panes.count - 1)]
    }

    func enqueueTransferConflicts(_ conflicts: [TransferConflict]) {
        guard !conflicts.isEmpty else { return }
        if transferConflict == nil {
            transferConflict = conflicts[0]
            queuedTransferConflicts.append(contentsOf: conflicts.dropFirst())
        } else {
            queuedTransferConflicts.append(contentsOf: conflicts)
        }
    }

    func finishTransferConflict() {
        transferConflict = nil
        guard !queuedTransferConflicts.isEmpty else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self, self.transferConflict == nil,
                !self.queuedTransferConflicts.isEmpty
            else { return }
            self.transferConflict = self.queuedTransferConflicts.removeFirst()
        }
    }

    // MARK: Tabs

    func newTab() {
        let pane = PaneState(path: activePane.directory.path)
        app.attachWatch(to: pane)
        panes.append(pane)
        activePaneIndex = panes.count - 1
        pane.directory.reload(showHidden: app.showHidden)
        app.saveSession()
    }

    /// Closes one tab. The last tab closes the window instead.
    func closeTab(_ index: Int) {
        guard panes.indices.contains(index) else { return }
        guard panes.count > 1 else {
            nsWindow?.performClose(nil)
            return
        }
        let pane = panes.remove(at: index)
        if pane.directory === deepSearchTarget {
            cancelDeepSearch()
        }
        app.releasePane(pane)
        if activePaneIndex >= panes.count {
            activePaneIndex = panes.count - 1
        } else if index < activePaneIndex {
            activePaneIndex -= 1
        }
        app.saveSession()
    }

    func closeActiveTab() {
        closeTab(activePaneIndex)
    }

    func selectTab(_ index: Int) {
        guard panes.indices.contains(index) else { return }
        activePaneIndex = index
    }

    func nextTab() {
        activePaneIndex = (activePaneIndex + 1) % panes.count
    }

    func previousTab() {
        activePaneIndex = (activePaneIndex + panes.count - 1) % panes.count
    }

    /// Takes one pane out of this window without releasing its engine
    /// watch: the pane continues in another window. An emptied window
    /// closes, the way a browser closes a window that lost its last tab.
    func removePane(at index: Int) -> PaneState? {
        guard panes.indices.contains(index) else { return nil }
        let pane = panes.remove(at: index)
        if pane.directory === deepSearchTarget {
            cancelDeepSearch()
        }
        if panes.isEmpty {
            nsWindow?.close()
        } else if activePaneIndex >= panes.count {
            activePaneIndex = panes.count - 1
        } else if index < activePaneIndex {
            activePaneIndex -= 1
        }
        return pane
    }

    /// Adds a pane arriving from another window and shows it.
    func insertPane(_ pane: PaneState, at index: Int) {
        let clamped = min(max(0, index), panes.count)
        panes.insert(pane, at: clamped)
        activePaneIndex = clamped
    }

    func navigate(to path: String) {
        app.connectionError = nil
        app.cancelPendingConnectionNavigation()
        activePane.navigate(to: path, showHidden: app.showHidden)
    }

    // MARK: Deep search

    /// Enter in the search field: recursive engine search of the current tree.
    func performDeepSearch() {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return }
        if let previous = currentDeepSearchId {
            app.engine.cancelSearch(queryId: previous)
        }
        isSearching = true
        deepSearchTarget = activePane.directory
        submittedQuery = searchText
        currentDeepSearchId = app.engine.startSearch(
            root: activePane.directory.path,
            query: query,
            options: SearchOptions(
                includeHidden: app.showHidden, maxResults: 500))
    }

    /// Cancels the live engine search, if any. Called when the search field
    /// is cleared or edited, or the pane navigates elsewhere.
    func cancelDeepSearch() {
        if let id = currentDeepSearchId {
            app.engine.cancelSearch(queryId: id)
        }
        currentDeepSearchId = nil
        deepSearchTarget = nil
        submittedQuery = nil
        isSearching = false
    }

    /// Routes one search snapshot into this window's target directory.
    func applySearchResults(_ results: [FsEntry], done: Bool) {
        deepSearchTarget?.showSearchResults(results)
        if done {
            isSearching = false
            // A late re-ordered snapshot must not replace the final
            // result list.
            currentDeepSearchId = nil
        }
    }

    // MARK: Folder sizes

    /// Requests recursive totals for the subdirectories shown in the
    /// active pane. Only misses are requested; cached totals carry over.
    func requestFolderSizesForActivePane() {
        // A remote walk is one round trip per directory with no bound.
        // Remote sizes come only from an explicit Get Info request.
        guard OrkaPath.isLocal(activePane.directory.path) else { return }
        let dirs = activePane.directory.entries
            .filter(\.isDir)
            .map(\.path)
            .filter { !app.folderSizes.isFresh($0) }
        guard !dirs.isEmpty else { return }
        if let previous = currentSizeRequestId {
            app.engine.cancelFolderSizes(requestId: previous)
        }
        currentSizeRequestId = app.engine.computeFolderSizes(dirs: dirs)
    }

    /// Requests the recursive total of the pane's own directory, shown
    /// in the status bar next to the free space.
    func requestPaneFolderSize() {
        let path = activePane.directory.path
        // Same bound as above: no automatic walk of a remote tree.
        guard OrkaPath.isLocal(path) else { return }
        guard !app.folderSizes.isFresh(path) else { return }
        if let previous = paneSizeRequestId {
            app.engine.cancelFolderSizes(requestId: previous)
        }
        paneSizeRequestId = app.engine.computeFolderSizes(dirs: [path])
    }

    /// Cancels the status-bar size request after its pane navigates away.
    func cancelPaneSizeRequest() {
        if let previous = paneSizeRequestId {
            app.engine.cancelFolderSizes(requestId: previous)
            paneSizeRequestId = nil
        }
    }

    private func applyPendingOrigin() {
        guard let window = nsWindow, let origin = pendingOrigin else { return }
        pendingOrigin = nil
        window.setFrameTopLeftPoint(origin)
    }
}
