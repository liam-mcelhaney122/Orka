import AppKit
import CryptoKit
import Quartz
import SwiftUI

extension NSPasteboard.PasteboardType {
    /// Internal Orka drag type carrying a remote row's URI. Shared by
    /// the file list drag source and the tab bar drop target.
    static let orkaRemotePath = NSPasteboard.PasteboardType(
        "com.orka.remote-path")
}

/// Details view: an NSTableView wrapped for SwiftUI. NSTableView (not
/// SwiftUI Table) because the MVP needs 100k-row scrolling, type-ahead,
/// inline rename, and file drag and drop.
struct FileListView: NSViewRepresentable {
    @Bindable var model: AppModel
    var window: WindowState

    func makeCoordinator() -> FileListCoordinator {
        FileListCoordinator(model: model, window: window)
    }

    func makeNSView(context: Context) -> NSScrollView {
        context.coordinator.scrollView
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        context.coordinator.sync(directory: window.activePane.directory)
    }
}

@MainActor
final class FileListCoordinator: NSObject {
    private let model: AppModel
    private let window: WindowState
    let scrollView = NSScrollView()
    private let tableView = FileListTableView()

    private var displayed: [FsEntry] = []
    private var lastPath = ""
    private var lastStamp = -1
    private var lastCutPaths: Set<String> = []
    private var lastFilter = ""
    private var lastSizeVersion = -1
    private var lastGitStamp = -1
    /// Guards against selection-change feedback loops between model and view.
    private var isApplyingModelChange = false
    /// Path of the row currently in inline-rename editing, if any.
    private var renamingPath: String?
    /// Targets captured when the context menu builds. The "Open With"
    /// submenu populates lazily on open, after `clickedRow` resets, so
    /// it reads the targets from here.
    private var openWithPaths: [String] = []
    /// Job id of the in-flight Quick Look download for a remote file. A
    /// `.jobFinished` for any other id is stale and ignored.
    private var quickLookJobId: UInt64?
    /// Local cache URLs for remote entries already downloaded for Quick
    /// Look this session, keyed by remote URI.
    private var remoteQuickLookCache: [String: URL] = [:]

    /// Pasteboard type carrying a remote entry's URI. Private to Orka:
    /// an external app (Finder, another editor) does not recognize it, so
    /// a drop outside Orka is inert instead of offering a broken alias
    /// with no real local file.
    private static let remotePathType = NSPasteboard.PasteboardType.orkaRemotePath

    private var directory: DirectoryModel { window.activePane.directory }

    init(model: AppModel, window: WindowState) {
        self.model = model
        self.window = window
        super.init()
        configureTable()
    }

    // MARK: Setup

    private func configureTable() {
        for spec in FileListColumns.specs {
            addColumn(spec)
        }

        // The default sort applies before the data source is wired.
        // Set after wiring, the change callback would fire at launch
        // and overwrite the folder's saved sort with this default.
        tableView.sortDescriptors = [
            NSSortDescriptor(key: "name", ascending: true)
        ]

        tableView.dataSource = self
        tableView.delegate = self
        tableView.actions = self
        tableView.allowsMultipleSelection = true
        tableView.allowsColumnReordering = true
        // The stripes and the selection draw as rounded, inset bands
        // (Finder list look). The built-in flag draws square full-width
        // stripes, so FileListTableView draws its own instead.
        tableView.usesAlternatingRowBackgroundColors = false
        // Transparent table over the pane's glass surface; the stripe
        // bands still draw on top.
        tableView.backgroundColor = .clear
        scrollView.drawsBackground = false
        tableView.usesAutomaticRowHeights = false
        tableView.rowHeight = 26
        tableView.style = .fullWidth
        // Window growth widens the Name column; a data column at the
        // end must not soak up the slack, or its content and every
        // column after it would drift past the window edge.
        tableView.columnAutoresizingStyle = .firstColumnOnlyAutoresizingStyle
        // "V2": the pre-cap autosave data holds a stretched Size width
        // wider than the window, so it must not restore.
        tableView.autosaveName = "FileListColumnsV2"
        tableView.autosaveTableColumns = true
        tableView.target = self
        tableView.doubleAction = #selector(handleDoubleClick)

        tableView.registerForDraggedTypes([.fileURL, Self.remotePathType])
        tableView.setDraggingSourceOperationMask([.copy, .move], forLocal: false)
        tableView.setDraggingSourceOperationMask([.copy, .move], forLocal: true)

        let menu = NSMenu()
        menu.delegate = self
        tableView.menu = menu

        // Right-click on the column headers opens the show/hide menu.
        let headerMenu = NSMenu()
        headerMenu.delegate = self
        tableView.headerView?.menu = headerMenu

        // Visibility applies after autosave restores widths and order,
        // so the saved column set wins at launch.
        applyColumnVisibility()

        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        // A narrow pane (git panel open) cuts off the trailing columns;
        // the horizontal scroller reaches them.
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        // Air between the last row and the horizontal scroller, so the
        // bar never sits directly on a stripe band.
        scrollView.automaticallyAdjustsContentInsets = false
        scrollView.contentInsets = NSEdgeInsets(
            top: 0, left: 0, bottom: 10, right: 0)
    }

    private func addColumn(_ spec: FileColumnSpec) {
        let column = NSTableColumn(
            identifier: NSUserInterfaceItemIdentifier(spec.id))
        column.title = spec.title
        column.width = spec.width
        column.minWidth = spec.minWidth
        column.maxWidth = spec.maxWidth
        column.sortDescriptorPrototype = NSSortDescriptor(
            key: spec.id, ascending: true)
        if spec.rightAligned {
            column.headerCell.alignment = .right
        }
        tableView.addTableColumn(column)
    }

    /// Applies the persisted column set. The Path column is not part of
    /// that set: it follows deep-search state instead.
    private func applyColumnVisibility() {
        let visible = FileListColumns.visibleIds()
        for spec in FileListColumns.specs where spec.toggleable {
            tableView.tableColumn(
                withIdentifier: NSUserInterfaceItemIdentifier(spec.id))?
                .isHidden = !visible.contains(spec.id)
        }
        tableView.tableColumn(
            withIdentifier: NSUserInterfaceItemIdentifier("path"))?
            .isHidden = directory.searchResults == nil
    }

    // MARK: Model -> view sync

    func sync(directory: DirectoryModel) {
        // Read the observed properties so SwiftUI re-runs updateNSView on change.
        let stamp = directory.loadStamp
        let path = directory.path
        let modelSelection = directory.selection
        let cutPaths = model.cutPaths
        let filter = window.searchText
        let sizeVersion = model.folderSizes.version
        let gitStamp = directory.gitStamp

        if path != lastPath || stamp != lastStamp {
            let pathChanged = path != lastPath
            lastPath = path
            lastStamp = stamp
            lastCutPaths = cutPaths
            lastFilter = filter
            lastSizeVersion = sizeVersion
            lastGitStamp = gitStamp
            if pathChanged {
                applySavedSort(for: path)
            }
            resortAndReload(scrollToTop: pathChanged)
        } else if cutPaths != lastCutPaths || filter != lastFilter {
            lastCutPaths = cutPaths
            lastFilter = filter
            lastSizeVersion = sizeVersion
            lastGitStamp = gitStamp
            resortAndReload(scrollToTop: false)
        } else {
            // Selection, size, and git-status updates can land in one pass;
            // an else-if would drop a refresh until the next event.
            if modelSelection != selectedPaths() {
                applySelection(modelSelection)
            }
            if sizeVersion != lastSizeVersion {
                lastSizeVersion = sizeVersion
                reloadSizeColumn()
            }
            if gitStamp != lastGitStamp {
                lastGitStamp = gitStamp
                reloadNameColumn()
            }
        }
    }

    /// Refreshes only the Size column as folder totals stream in, so
    /// selection and any in-progress rename are left untouched.
    private func reloadSizeColumn() {
        guard !displayed.isEmpty else { return }
        let columnIndex = tableView.column(
            withIdentifier: NSUserInterfaceItemIdentifier("size"))
        guard columnIndex >= 0 else { return }
        tableView.reloadData(
            forRowIndexes: IndexSet(0..<displayed.count),
            columnIndexes: IndexSet(integer: columnIndex))
    }

    /// Refreshes only the Name column as git status catches up, so
    /// selection and any in-progress rename are left untouched.
    private func reloadNameColumn() {
        // Reconfiguring the editing row would replace the field editor's
        // text mid-rename. The next full reload refreshes the badge.
        guard renamingPath == nil else { return }
        guard !displayed.isEmpty else { return }
        let columnIndex = tableView.column(
            withIdentifier: NSUserInterfaceItemIdentifier("name"))
        guard columnIndex >= 0 else { return }
        tableView.reloadData(
            forRowIndexes: IndexSet(0..<displayed.count),
            columnIndexes: IndexSet(integer: columnIndex))
    }

    /// The rows to show: deep-search results, a live-filtered listing, or
    /// the plain listing.
    private func currentEntries() -> [FsEntry] {
        if let results = directory.searchResults {
            return results
        }
        let filter = window.searchText
        guard !filter.isEmpty else { return directory.entries }
        return directory.entries.filter {
            $0.name.localizedCaseInsensitiveContains(filter)
        }
    }

    private func resortAndReload(scrollToTop: Bool) {
        let searching = directory.searchResults != nil
        tableView.tableColumn(
            withIdentifier: NSUserInterfaceItemIdentifier("path"))?
            .isHidden = !searching
        displayed = sorted(currentEntries())
        isApplyingModelChange = true
        tableView.reloadData()
        isApplyingModelChange = false
        applySelection(directory.selection)
        if scrollToTop && !displayed.isEmpty {
            tableView.scrollRowToVisible(0)
        }
    }

    private func applySelection(_ paths: Set<String>) {
        let indexes = IndexSet(
            displayed.enumerated()
                .filter { paths.contains($0.element.path) }
                .map(\.offset))
        isApplyingModelChange = true
        tableView.selectRowIndexes(indexes, byExtendingSelection: false)
        isApplyingModelChange = false
    }

    private func selectedPaths() -> Set<String> {
        Set(tableView.selectedRowIndexes.compactMap {
            $0 < displayed.count ? displayed[$0].path : nil
        })
    }

    // MARK: Per-folder sort persistence

    private var restoringSort = false

    private func saveSort(for path: String) {
        guard !restoringSort,
            let descriptor = tableView.sortDescriptors.first,
            let key = descriptor.key
        else { return }
        UserDefaults.standard.set(
            "\(key):\(descriptor.ascending ? 1 : 0)", forKey: "sort:\(path)")
    }

    private func applySavedSort(for path: String) {
        guard let saved = UserDefaults.standard.string(forKey: "sort:\(path)")
        else { return }
        let parts = saved.split(separator: ":")
        guard parts.count == 2 else { return }
        let descriptor = NSSortDescriptor(
            key: String(parts[0]), ascending: parts[1] == "1")
        let current = tableView.sortDescriptors.first
        guard descriptor.key != current?.key
            || descriptor.ascending != current?.ascending
        else { return }
        // Setting sortDescriptors re-enters sortDescriptorsDidChange.
        restoringSort = true
        tableView.sortDescriptors = [descriptor]
        restoringSort = false
    }

    // MARK: Sorting (directories always first, like Explorer)

    private func sorted(_ entries: [FsEntry]) -> [FsEntry] {
        let descriptor = tableView.sortDescriptors.first
            ?? NSSortDescriptor(key: "name", ascending: true)
        let key = descriptor.key ?? "name"
        let ascending = descriptor.ascending
        return entries.sorted { a, b in
            if a.isDir != b.isDir { return a.isDir }
            let result: Bool
            switch key {
            case "modified":
                result = a.modifiedMs < b.modifiedMs
            case "size":
                if a.isDir {
                    // Both sides are dirs here (mixed pairs are already
                    // ordered above); an unknown total sorts as zero.
                    let sizeA = model.folderSizes.sizes[a.path]?.bytes ?? 0
                    let sizeB = model.folderSizes.sizes[b.path]?.bytes ?? 0
                    result = sizeA < sizeB
                } else {
                    result = a.size < b.size
                }
            case "created":
                let da = FileMetadataCache.metadata(for: a).created
                    ?? .distantPast
                let db = FileMetadataCache.metadata(for: b).created
                    ?? .distantPast
                result = da == db ? nameAscending(a, b) : da < db
            case "added":
                let da = FileMetadataCache.metadata(for: a).added
                    ?? .distantPast
                let db = FileMetadataCache.metadata(for: b).added
                    ?? .distantPast
                result = da == db ? nameAscending(a, b) : da < db
            case "extension":
                let ea = (a.name as NSString).pathExtension.lowercased()
                let eb = (b.name as NSString).pathExtension.lowercased()
                result = ea == eb ? nameAscending(a, b) : ea < eb
            case "owner":
                let oa = FileMetadataCache.metadata(for: a).owner ?? ""
                let ob = FileMetadataCache.metadata(for: b).owner ?? ""
                result = oa == ob ? nameAscending(a, b) : oa < ob
            case "permissions":
                let pa = FileMetadataCache.metadata(for: a).permissions ?? ""
                let pb = FileMetadataCache.metadata(for: b).permissions ?? ""
                result = pa == pb ? nameAscending(a, b) : pa < pb
            case "kind":
                let ka = FileKindCache.kind(for: a)
                let kb = FileKindCache.kind(for: b)
                result = ka == kb ? nameAscending(a, b) : ka < kb
            case "path":
                result = a.path.localizedStandardCompare(b.path)
                    == .orderedAscending
            default:
                result = nameAscending(a, b)
            }
            return ascending ? result : !result
        }
    }

    private func nameAscending(_ a: FsEntry, _ b: FsEntry) -> Bool {
        a.name.localizedStandardCompare(b.name) == .orderedAscending
    }

    // MARK: Open

    @objc private func handleDoubleClick() {
        guard tableView.clickedRow >= 0 else { return }
        if tableView.selectedRowIndexes.contains(tableView.clickedRow) {
            openSelection()
        } else {
            model.open(displayed[tableView.clickedRow])
        }
    }

    func openSelection() {
        for index in tableView.selectedRowIndexes where index < displayed.count {
            model.open(displayed[index])
        }
    }

    private func targetEntries() -> [FsEntry] {
        let clicked = tableView.clickedRow
        if clicked >= 0 && !tableView.selectedRowIndexes.contains(clicked) {
            return [displayed[clicked]]
        }
        return tableView.selectedRowIndexes.compactMap {
            $0 < displayed.count ? displayed[$0] : nil
        }
    }

    // MARK: Inline rename

    func beginRenameOnSelection() {
        let row = tableView.selectedRow
        guard row >= 0, tableView.selectedRowIndexes.count == 1,
            row < displayed.count
        else { return }
        guard let cell = tableView.view(
            atColumn: tableView.column(
                withIdentifier: NSUserInterfaceItemIdentifier("name")),
            row: row, makeIfNecessary: false) as? NSTableCellView,
            let textField = cell.textField
        else { return }
        renamingPath = displayed[row].path
        // The cell may show an attributed name plus a git-status dot.
        // Editing must start from the plain file name or the dot text
        // would end up in the new name on disk.
        textField.stringValue = displayed[row].name
        textField.isEditable = true
        textField.delegate = self
        tableView.window?.makeFirstResponder(textField)
        // Select the stem, not the extension, like Finder. Directories,
        // dotfiles, and names with no extension select in full: for those,
        // deletingPathExtension leaves the stem length equal to the name.
        if let editor = textField.currentEditor() {
            let name = textField.stringValue
            let stemLength = displayed[row].isDir
                ? (name as NSString).length
                : ((name as NSString).deletingPathExtension as NSString).length
            editor.selectedRange = NSRange(location: 0, length: stemLength)
        }
    }

    // MARK: Clipboard (called from the table's responder actions)

    func copySelection() { model.copySelection(in: window) }
    func cutSelection() { model.cutSelection(in: window) }
    func paste() { model.paste(in: window) }

    // MARK: Quick Look

    func toggleQuickLook() {
        guard let panel = QLPreviewPanel.shared() else { return }
        if panel.isVisible {
            panel.orderOut(nil)
            return
        }
        guard OrkaPath.isLocal(directory.path) else {
            beginRemoteQuickLook(panel: panel)
            return
        }
        panel.makeKeyAndOrderFront(nil)
    }

    /// Space on a remote selection. Downloads the single selected file to
    /// a cache directory, then presents it once the download finishes.
    /// Multi-selection and directories are not supported here and beep.
    private func beginRemoteQuickLook(panel: QLPreviewPanel) {
        let rows = tableView.selectedRowIndexes
        guard rows.count == 1, let row = rows.first, row < displayed.count
        else {
            NSSound.beep()
            return
        }
        let entry = displayed[row]
        guard !entry.isDir, let localURL = quickLookCacheURL(for: entry)
        else {
            NSSound.beep()
            return
        }
        // A cache hit skips the download: the file already exists at its
        // stable per-path cache location.
        if FileManager.default.fileExists(atPath: localURL.path) {
            remoteQuickLookCache[entry.path] = localURL
            panel.reloadData()
            panel.makeKeyAndOrderFront(nil)
            return
        }
        startQuickLookDownload(entryPath: entry.path, to: localURL, panel: panel)
    }

    /// Runs the download as a normal engine copy job so its progress
    /// shows in the status bar like any other transfer. Presents the
    /// panel from the job's `.jobFinished` callback; a superseded or
    /// failed download does not present anything.
    private func startQuickLookDownload(
        entryPath: String, to localURL: URL, panel: QLPreviewPanel
    ) {
        let destDir = localURL.deletingLastPathComponent().path
        let jobId = model.engine.copyItems(sources: [entryPath], destDir: destDir)
        quickLookJobId = jobId
        model.onJobFinished(jobId: jobId) { [weak self] state in
            guard let self, self.quickLookJobId == jobId else { return }
            self.quickLookJobId = nil
            guard state == .done else { return }
            self.remoteQuickLookCache[entryPath] = localURL
            panel.reloadData()
            panel.makeKeyAndOrderFront(nil)
        }
    }

    /// The stable local cache location for one remote entry's Quick Look
    /// download: `~/Library/Caches/Orka/QuickLook/<connection>/<path
    /// hash>/<name>`. Creates the containing directory. Nil when
    /// `entry.path` does not parse as a remote URI, or the directory
    /// cannot be created.
    private func quickLookCacheURL(for entry: FsEntry) -> URL? {
        guard let split = OrkaPath.splitRemote(entry.path),
            let caches = FileManager.default.urls(
                for: .cachesDirectory, in: .userDomainMask
            ).first
        else { return nil }
        let digest = SHA256.hash(data: Data(split.path.utf8))
        let hash = digest.prefix(8).map { String(format: "%02x", $0) }.joined()
        let dir = caches
            .appendingPathComponent("Orka/QuickLook", isDirectory: true)
            .appendingPathComponent(split.connection, isDirectory: true)
            .appendingPathComponent(hash, isDirectory: true)
        guard (try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)) != nil
        else { return nil }
        return dir.appendingPathComponent(entry.name)
    }

    /// Keeps a visible preview in step with the table selection.
    func refreshQuickLook() {
        guard QLPreviewPanel.sharedPreviewPanelExists(),
            let panel = QLPreviewPanel.shared(), panel.isVisible
        else { return }
        panel.reloadData()
    }

    // MARK: Context menu actions

    @objc private func contextOpen() {
        targetEntries().forEach { model.open($0) }
    }

    @objc private func contextRevealInFinder() {
        let urls = targetEntries().map { URL(fileURLWithPath: $0.path) }
        NSWorkspace.shared.activateFileViewerSelecting(urls)
    }

    @objc private func contextCopyPath() {
        model.copyPaths(targetEntries().map(\.path), relative: false, in: window)
    }

    @objc private func contextCopyRelativePath() {
        model.copyPaths(targetEntries().map(\.path), relative: true, in: window)
    }

    @objc private func contextRename() {
        if let first = targetEntries().first {
            directory.selection = [first.path]
            // Let the selection apply before editing starts.
            DispatchQueue.main.async { [weak self] in
                self?.beginRenameOnSelection()
            }
        }
    }

    @objc private func contextDuplicate() {
        directory.selection = Set(targetEntries().map(\.path))
        model.duplicateSelection(in: window)
    }

    @objc private func contextTrash() {
        directory.selection = Set(targetEntries().map(\.path))
        model.trashSelection(in: window)
    }

    @objc private func contextQuickLook() {
        directory.selection = Set(targetEntries().map(\.path))
        toggleQuickLook()
    }

    @objc private func contextGetInfo() {
        directory.selection = Set(targetEntries().map(\.path))
        model.getInfo(in: window)
    }

    @objc private func contextCopy() {
        directory.selection = Set(targetEntries().map(\.path))
        model.copySelection(in: window)
    }

    @objc private func contextCut() {
        directory.selection = Set(targetEntries().map(\.path))
        model.cutSelection(in: window)
    }

    @objc private func contextPaste() { model.paste(in: window) }

    @objc private func contextNewFolder() { model.newFolder(in: window) }

    @objc private func contextCompressZip() { compressSelectionFromMenu(as: .zip) }
    @objc private func contextCompressTar() { compressSelectionFromMenu(as: .tar) }
    @objc private func contextCompressTarGz() { compressSelectionFromMenu(as: .tarGz) }

    /// The compress submenu targets one shared helper so each format
    /// only differs by the enum case.
    private func compressSelectionFromMenu(as format: ArchiveFormat) {
        directory.selection = Set(targetEntries().map(\.path))
        model.compressSelection(as: format, in: window)
    }

    @objc private func contextExtract() {
        directory.selection = Set(targetEntries().map(\.path))
        model.extractSelection(in: window)
    }

    @objc private func contextAddToFavorites() {
        for entry in targetEntries() { model.addFavorite(entry.path) }
    }
}

// MARK: - Data source & drag and drop

extension FileListCoordinator: NSTableViewDataSource {
    func numberOfRows(in tableView: NSTableView) -> Int {
        displayed.count
    }

    func tableView(
        _ tableView: NSTableView,
        sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]
    ) {
        saveSort(for: directory.path)
        resortAndReload(scrollToTop: false)
    }

    func tableView(
        _ tableView: NSTableView, pasteboardWriterForRow row: Int
    ) -> NSPasteboardWriting? {
        guard row < displayed.count else { return nil }
        let path = displayed[row].path
        if OrkaPath.isLocal(path) {
            return NSURL(fileURLWithPath: path)
        }
        // A remote row carries its URI under a private pasteboard type
        // instead of a file URL, so only an internal Orka drop reads
        // it; a drop onto Finder or another app is inert.
        let item = NSPasteboardItem()
        item.setString(path, forType: Self.remotePathType)
        return item
    }

    func tableView(
        _ tableView: NSTableView, validateDrop info: NSDraggingInfo,
        proposedRow row: Int,
        proposedDropOperation dropOperation: NSTableView.DropOperation
    ) -> NSDragOperation {
        let destDir = dropDestination(row: row, operation: dropOperation)
        if let remoteSources = droppedRemotePaths(info) {
            // A backend-to-backend transfer with no local endpoint is out
            // of scope; only a local destination accepts remote rows.
            guard OrkaPath.isLocal(destDir), !remoteSources.isEmpty
            else { return [] }
            retargetDropRow(row: row, dropOperation: dropOperation)
            return .copy
        }
        guard let sources = droppedPaths(info), !sources.isEmpty else {
            return []
        }
        let effective = transferSources(sources, destDir: destDir)
        guard !effective.isEmpty else { return [] }
        retargetDropRow(row: row, dropOperation: dropOperation)
        return shouldMove(info, sources: effective, destDir: destDir)
            ? .move : .copy
    }

    func tableView(
        _ tableView: NSTableView, acceptDrop info: NSDraggingInfo,
        row: Int, dropOperation: NSTableView.DropOperation
    ) -> Bool {
        let destDir = dropDestination(row: row, operation: dropOperation)
        if let remoteSources = droppedRemotePaths(info) {
            guard OrkaPath.isLocal(destDir), !remoteSources.isEmpty
            else { return false }
            model.transfer(sources: remoteSources, to: destDir, move: false)
            return true
        }
        guard let sources = droppedPaths(info) else { return false }
        let effective = transferSources(sources, destDir: destDir)
        guard !effective.isEmpty else { return false }
        model.transfer(
            sources: effective, to: destDir,
            move: shouldMove(info, sources: effective, destDir: destDir))
        return true
    }

    /// Retargets a drop that did not land squarely on a folder row to the
    /// whole table, so it lands in the current folder.
    private func retargetDropRow(
        row: Int, dropOperation: NSTableView.DropOperation
    ) {
        if !(dropOperation == .on && row >= 0 && rowIsFolder(row)) {
            tableView.setDropRow(-1, dropOperation: .on)
        }
    }

    private func rowIsFolder(_ row: Int) -> Bool {
        row < displayed.count && displayed[row].isDir
            && !displayed[row].path.hasSuffix(".app")
    }

    private func dropDestination(
        row: Int, operation: NSTableView.DropOperation
    ) -> String {
        if operation == .on && row >= 0 && rowIsFolder(row) {
            return displayed[row].path
        }
        return directory.path
    }

    private func droppedPaths(_ info: NSDraggingInfo) -> [String]? {
        let urls = info.draggingPasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]) as? [URL]
        return urls?.map(\.path)
    }

    /// Remote URIs from an internal drag of remote rows (see
    /// `remotePathType`). Nil when the drag carries none, so callers can
    /// tell "no remote sources" apart from "remote sources, but empty".
    private func droppedRemotePaths(_ info: NSDraggingInfo) -> [String]? {
        guard let items = info.draggingPasteboard.pasteboardItems else {
            return nil
        }
        let paths = items.compactMap { $0.string(forType: Self.remotePathType) }
        return paths.isEmpty ? nil : paths
    }

    /// Filters out no-op and unsafe transfers: dropping into the folder the
    /// item is already in, or a folder into itself or its own descendant.
    private func transferSources(
        _ sources: [String], destDir: String
    ) -> [String] {
        sources.filter { source in
            let parent = URL(fileURLWithPath: source)
                .deletingLastPathComponent().path
            if parent == destDir { return false }
            if destDir == source || destDir.hasPrefix(source + "/") {
                return false
            }
            return true
        }
    }

    private func shouldMove(
        _ info: NSDraggingInfo, sources: [String], destDir: String
    ) -> Bool {
        // Option key forces a copy, following macOS convention.
        if info.draggingSourceOperationMask == .copy { return false }
        guard let first = sources.first else { return false }
        return sameVolume(first, destDir)
    }

    private func sameVolume(_ a: String, _ b: String) -> Bool {
        func volumeID(_ path: String) -> AnyHashable? {
            let values = try? URL(fileURLWithPath: path)
                .resourceValues(forKeys: [.volumeIdentifierKey])
            return values?.volumeIdentifier as? AnyHashable
        }
        guard let va = volumeID(a), let vb = volumeID(b) else { return false }
        return va == vb
    }
}

// MARK: - Delegate

extension FileListCoordinator: NSTableViewDelegate {
    func tableView(
        _ tableView: NSTableView, rowViewForRow row: Int
    ) -> NSTableRowView? {
        let id = NSUserInterfaceItemIdentifier("orka-row")
        let view = tableView.makeView(withIdentifier: id, owner: nil)
            as? RoundedSelectionRowView ?? {
                let made = RoundedSelectionRowView()
                made.identifier = id
                return made
            }()
        return view
    }

    func tableView(
        _ tableView: NSTableView, viewFor tableColumn: NSTableColumn?,
        row: Int
    ) -> NSView? {
        guard let column = tableColumn, row < displayed.count else {
            return nil
        }
        let entry = displayed[row]
        let id = column.identifier
        let cell = reusableCell(for: id, withIcon: id.rawValue == "name")

        switch id.rawValue {
        case "name":
            cell.imageView?.image = FileKindCache.icon(forPath: entry.path)
            // Search results span many directories; a name-keyed git-state
            // lookup would mislabel entries from other folders, so skip it.
            let gitState = directory.searchResults == nil
                ? directory.gitStates[entry.name] : nil
            configureNameText(
                entry: entry, state: gitState, textField: cell.textField)
            let cutAlpha: CGFloat =
                model.cutPaths.contains(entry.path) ? 0.5 : 1.0
            cell.alphaValue = gitState == .ignored ? cutAlpha * 0.6 : cutAlpha
            cell.textField?.isEditable = false
            cell.toolTip = gitState.map(Self.gitStateLabel)
        case "modified":
            cell.textField?.stringValue = Self.format(
                modifiedMs: entry.modifiedMs)
            cell.textField?.textColor = .secondaryLabelColor
        case "created":
            cell.textField?.stringValue = Self.format(
                date: FileMetadataCache.metadata(for: entry).created)
            cell.textField?.textColor = .secondaryLabelColor
        case "added":
            cell.textField?.stringValue = Self.format(
                date: FileMetadataCache.metadata(for: entry).added)
            cell.textField?.textColor = .secondaryLabelColor
        case "extension":
            let ext = (entry.name as NSString).pathExtension
            cell.textField?.stringValue =
                entry.isDir || ext.isEmpty ? "—" : ext.lowercased()
            cell.textField?.textColor = .secondaryLabelColor
        case "owner":
            cell.textField?.stringValue =
                FileMetadataCache.metadata(for: entry).owner ?? "—"
            cell.textField?.textColor = .secondaryLabelColor
        case "permissions":
            cell.textField?.stringValue =
                FileMetadataCache.metadata(for: entry).permissions ?? "—"
            cell.textField?.textColor = .secondaryLabelColor
            // Fixed-width glyphs keep the rwx triplets column-aligned.
            cell.textField?.font = .monospacedSystemFont(
                ofSize: 12, weight: .regular)
        case "kind":
            cell.textField?.stringValue = FileKindCache.kind(for: entry)
            cell.textField?.textColor = .secondaryLabelColor
        case "size":
            if entry.isDir {
                cell.textField?.stringValue = model.folderSizes.sizes[entry.path]
                    .map {
                        ByteCountFormatter.string(
                            fromByteCount: Int64($0.bytes), countStyle: .file)
                    } ?? "—"
            } else if entry.size == 0 {
                // "Zero bytes" is noise; an empty cell reads cleaner.
                cell.textField?.stringValue = ""
            } else {
                cell.textField?.stringValue = ByteCountFormatter.string(
                    fromByteCount: Int64(entry.size), countStyle: .file)
            }
            cell.textField?.textColor = .secondaryLabelColor
            cell.textField?.alignment = .right
        case "path":
            // Parent folder; the file name already has its own column.
            cell.textField?.stringValue = (entry.path as NSString)
                .deletingLastPathComponent
            cell.textField?.textColor = .secondaryLabelColor
            cell.textField?.lineBreakMode = .byTruncatingHead
        default:
            break
        }
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        refreshQuickLook()
        guard !isApplyingModelChange else { return }
        directory.selection = selectedPaths()
    }

    func tableView(
        _ tableView: NSTableView, typeSelectStringFor tableColumn: NSTableColumn?,
        row: Int
    ) -> String? {
        // Only match on names; avoids type-ahead hits on dates and sizes.
        guard row < displayed.count else { return nil }
        return tableColumn?.identifier.rawValue == "name"
            ? displayed[row].name : nil
    }

    private func reusableCell(
        for id: NSUserInterfaceItemIdentifier, withIcon: Bool
    ) -> NSTableCellView {
        if let cell = tableView.makeView(withIdentifier: id, owner: self)
            as? NSTableCellView {
            return cell
        }
        let cell = NSTableCellView()
        cell.identifier = id

        let text = NSTextField(labelWithString: "")
        text.font = .systemFont(ofSize: 13)
        text.lineBreakMode = .byTruncatingMiddle
        text.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(text)
        cell.textField = text

        var leading = cell.leadingAnchor
        if withIcon {
            let image = NSImageView()
            image.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(image)
            cell.imageView = image
            NSLayoutConstraint.activate([
                // Clears the rounded corner of the stripe band, so the
                // icon starts inside the band, the way Finder does.
                image.leadingAnchor.constraint(
                    equalTo: cell.leadingAnchor, constant: 10),
                image.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
                image.widthAnchor.constraint(equalToConstant: 16),
                image.heightAnchor.constraint(equalToConstant: 16),
            ])
            leading = image.trailingAnchor
        }
        NSLayoutConstraint.activate([
            text.leadingAnchor.constraint(equalTo: leading, constant: 5),
            text.trailingAnchor.constraint(
                equalTo: cell.trailingAnchor, constant: -2),
            text.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
        return cell
    }

    /// Sets the name text, appending a small colored dot when `state` marks
    /// the entry as touched by git. Ignored entries get no dot; the caller
    /// dims the whole cell for those instead.
    private func configureNameText(
        entry: FsEntry, state: GitFileState?, textField: NSTextField?
    ) {
        guard let textField else { return }
        let baseColor: NSColor =
            state == .ignored ? .secondaryLabelColor
            : entry.isHidden ? .secondaryLabelColor : .labelColor
        guard let state, let dotColor = Self.dotColor(for: state) else {
            textField.textColor = baseColor
            textField.stringValue = entry.name
            return
        }
        let text = NSMutableAttributedString(
            string: entry.name,
            attributes: [
                .foregroundColor: baseColor,
                .font: NSFont.systemFont(ofSize: 13),
            ])
        text.append(NSAttributedString(
            string: "  \u{25CF}",
            attributes: [
                .foregroundColor: dotColor,
                .font: NSFont.systemFont(ofSize: 9),
            ]))
        textField.attributedStringValue = text
    }

    /// Dot color per git state. Ignored entries have no dot; the cell is
    /// dimmed instead.
    private static func dotColor(for state: GitFileState) -> NSColor? {
        switch state {
        case .modified: return .systemOrange
        case .staged, .stagedAndModified: return .systemGreen
        case .untracked: return .tertiaryLabelColor
        case .conflicted: return .systemRed
        case .ignored: return nil
        }
    }

    private static func gitStateLabel(_ state: GitFileState) -> String {
        switch state {
        case .modified: return "Modified"
        case .staged: return "Staged"
        case .stagedAndModified: return "Staged and Modified"
        case .untracked: return "Untracked"
        case .ignored: return "Ignored"
        case .conflicted: return "Conflicted"
        }
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    private static func format(modifiedMs: Int64) -> String {
        guard modifiedMs > 0 else { return "—" }
        return dateFormatter.string(
            from: Date(timeIntervalSince1970: Double(modifiedMs) / 1000))
    }

    private static func format(date: Date?) -> String {
        guard let date else { return "—" }
        return dateFormatter.string(from: date)
    }
}

// MARK: - Rename editing

extension FileListCoordinator: NSTextFieldDelegate {
    func controlTextDidEndEditing(_ notification: Notification) {
        guard let textField = notification.object as? NSTextField else {
            return
        }
        textField.isEditable = false
        textField.delegate = nil
        defer { renamingPath = nil }
        guard let path = renamingPath else { return }
        let newName = textField.stringValue
        let oldName = (path as NSString).lastPathComponent
        guard !newName.isEmpty, newName != oldName else {
            textField.stringValue = oldName
            return
        }
        if model.rename(path: path, to: newName, in: window) == nil {
            textField.stringValue = oldName
        }
    }

    func control(
        _ control: NSControl, textView: NSTextView,
        doCommandBy selector: Selector
    ) -> Bool {
        if selector == #selector(NSResponder.cancelOperation(_:)) {
            // Escape: revert and end editing without renaming.
            if let path = renamingPath {
                (control as? NSTextField)?.stringValue =
                    (path as NSString).lastPathComponent
            }
            renamingPath = nil
            tableView.window?.makeFirstResponder(tableView)
            return true
        }
        return false
    }
}

// MARK: - Context menu

extension FileListCoordinator: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) {
        if menu === tableView.headerView?.menu {
            buildHeaderMenu(menu)
            return
        }
        if menu.title == Self.openWithMenuTitle {
            buildOpenWithMenu(menu)
            return
        }
        menu.removeAllItems()
        let targets = targetEntries()
        guard OrkaPath.isLocal(directory.path) else {
            remoteMenuNeedsUpdate(menu, targets: targets)
            return
        }
        let hasTarget = !targets.isEmpty
        if hasTarget {
            menu.addItem(makeItem("Open", action: #selector(contextOpen)))
            menu.addItem(openWithSubmenu(targets: targets))
            menu.addItem(makeItem(
                "Quick Look", action: #selector(contextQuickLook)))
            menu.addItem(makeItem(
                "Get Info", action: #selector(contextGetInfo)))
            menu.addItem(makeItem(
                "Reveal in Finder", action: #selector(contextRevealInFinder)))
            menu.addItem(.separator())
            menu.addItem(makeItem("Rename", action: #selector(contextRename)))
            menu.addItem(makeItem(
                "Duplicate", action: #selector(contextDuplicate)))
            menu.addItem(compressSubmenu())
            // Only a single selected archive can extract; the item is
            // hidden otherwise, so the menu stays honest by construction.
            if targets.count == 1, let only = targets.first,
                AppModel.isArchivePath(only.path) {
                menu.addItem(makeItem(
                    "Extract Archive", action: #selector(contextExtract)))
            }
            menu.addItem(makeItem(
                "Move to Trash", action: #selector(contextTrash)))
            menu.addItem(.separator())
            menu.addItem(makeItem("Cut", action: #selector(contextCut)))
            menu.addItem(makeItem("Copy", action: #selector(contextCopy)))
        }
        if model.canPaste {
            menu.addItem(makeItem("Paste", action: #selector(contextPaste)))
        }
        if hasTarget {
            menu.addItem(makeItem(
                "Copy Path", action: #selector(contextCopyPath)))
            menu.addItem(makeItem(
                "Copy Relative Path",
                action: #selector(contextCopyRelativePath)))
        }
        if hasTarget, targets.allSatisfy({ $0.isDir }),
            !targets.allSatisfy({ model.favorites.contains($0.path) }) {
            menu.addItem(makeItem(
                "Add to Favorites", action: #selector(contextAddToFavorites)))
        }
        menu.addItem(.separator())
        menu.addItem(makeItem(
            "New Folder", action: #selector(contextNewFolder)))
    }

    /// Checkmark list of the toggleable columns, shown on a header
    /// right-click. Name and Path are absent: Name is always visible
    /// and Path follows deep-search state.
    private func buildHeaderMenu(_ menu: NSMenu) {
        menu.removeAllItems()
        for spec in FileListColumns.specs where spec.toggleable {
            let item = NSMenuItem(
                title: spec.title, action: #selector(toggleColumn(_:)),
                keyEquivalent: "")
            item.target = self
            item.representedObject = spec.id
            let column = tableView.tableColumn(
                withIdentifier: NSUserInterfaceItemIdentifier(spec.id))
            item.state = column?.isHidden == false ? .on : .off
            menu.addItem(item)
        }
    }

    @objc private func toggleColumn(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String,
            let column = tableView.tableColumn(
                withIdentifier: NSUserInterfaceItemIdentifier(id))
        else { return }
        column.isHidden.toggle()
        FileListColumns.setVisible(id, !column.isHidden)
    }

    private func makeItem(_ title: String, action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        return item
    }

    private func compressSubmenu() -> NSMenuItem {
        let container = NSMenuItem(
            title: "Compress", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        sub.addItem(makeItem("ZIP", action: #selector(contextCompressZip)))
        sub.addItem(makeItem("Tar", action: #selector(contextCompressTar)))
        sub.addItem(makeItem(
            "Tar.gz", action: #selector(contextCompressTarGz)))
        container.submenu = sub
        return container
    }

    private static let openWithMenuTitle = "Open With"

    /// Empty "Open With" submenu shell. The delegate fills it when the
    /// submenu opens, so the application scan does not delay the
    /// right-click itself.
    private func openWithSubmenu(targets: [FsEntry]) -> NSMenuItem {
        openWithPaths = targets.map(\.path)
        let container = NSMenuItem(
            title: Self.openWithMenuTitle, action: nil, keyEquivalent: "")
        let sub = NSMenu(title: Self.openWithMenuTitle)
        sub.delegate = self
        container.submenu = sub
        return container
    }

    private func buildOpenWithMenu(_ menu: NSMenu) {
        menu.removeAllItems()
        let apps = OpenWithApps.apps(for: openWithPaths)
        for app in apps {
            let item = NSMenuItem(
                title: app.isDefault
                    ? "\(app.name) (default)" : app.name,
                action: #selector(contextOpenWith(_:)),
                keyEquivalent: "")
            item.target = self
            item.image = app.icon
            item.representedObject = app.url
            menu.addItem(item)
            if app.isDefault, apps.count > 1 {
                menu.addItem(.separator())
            }
        }
        if apps.isEmpty {
            let none = NSMenuItem(
                title: "No Applications", action: nil, keyEquivalent: "")
            none.isEnabled = false
            menu.addItem(none)
        }
        menu.addItem(.separator())
        menu.addItem(makeItem(
            "Other…", action: #selector(contextOpenWithOther)))
    }

    @objc private func contextOpenWith(_ sender: NSMenuItem) {
        guard let url = sender.representedObject as? URL else { return }
        OpenWithApps.open(paths: openWithPaths, with: url)
    }

    @objc private func contextOpenWithOther() {
        OpenWithApps.chooseAndOpen(paths: openWithPaths)
    }

    /// Remote rename and file drag-out to other apps are a later
    /// milestone; the menu offers what already works today. Delete is
    /// permanent (no server trash) and confirms before running.
    private func remoteMenuNeedsUpdate(_ menu: NSMenu, targets: [FsEntry]) {
        let hasTarget = !targets.isEmpty
        if hasTarget {
            if targets.allSatisfy(\.isDir) {
                menu.addItem(makeItem("Open", action: #selector(contextOpen)))
                menu.addItem(.separator())
            }
            menu.addItem(makeItem(
                "Copy Path", action: #selector(contextCopyPath)))
            menu.addItem(makeItem(
                "Copy Relative Path",
                action: #selector(contextCopyRelativePath)))
        }
        if model.canPaste {
            menu.addItem(makeItem("Paste", action: #selector(contextPaste)))
        }
        if hasTarget {
            menu.addItem(.separator())
            menu.addItem(makeItem("Delete", action: #selector(contextTrash)))
        }
    }
}

// MARK: - Quick Look panel

extension FileListCoordinator: @preconcurrency QLPreviewPanelDataSource,
    @preconcurrency QLPreviewPanelDelegate {
    private func quickLookURLs() -> [NSURL] {
        tableView.selectedRowIndexes.compactMap { row -> NSURL? in
            guard row < displayed.count else { return nil }
            let entry = displayed[row]
            if OrkaPath.isLocal(entry.path) {
                return NSURL(fileURLWithPath: entry.path)
            }
            // A remote entry previews from its downloaded cache copy, if
            // any; one not yet downloaded contributes no preview item.
            return remoteQuickLookCache[entry.path].map { $0 as NSURL }
        }
    }

    func numberOfPreviewItems(in panel: QLPreviewPanel!) -> Int {
        quickLookURLs().count
    }

    func previewPanel(
        _ panel: QLPreviewPanel!, previewItemAt index: Int
    ) -> QLPreviewItem! {
        let urls = quickLookURLs()
        guard index < urls.count else { return nil }
        return urls[index]
    }

    func previewPanel(
        _ panel: QLPreviewPanel!, handle event: NSEvent!
    ) -> Bool {
        // Arrow keys move the table selection behind the panel.
        guard event.type == .keyDown else { return false }
        tableView.keyDown(with: event)
        return true
    }

    func previewPanel(
        _ panel: QLPreviewPanel!, sourceFrameOnScreenFor item: QLPreviewItem!
    ) -> NSRect {
        guard let path = (item as? NSURL)?.path else { return .zero }
        // A remote entry previews from its local cache path, which does
        // not match `displayed`'s remote URI; look it up the other way.
        let entryPath = remoteQuickLookCache.first { $0.value.path == path }?.key ?? path
        guard let row = displayed.firstIndex(where: { $0.path == entryPath }),
            let rowView = tableView.rowView(atRow: row, makeIfNecessary: false),
            let window = tableView.window
        else { return .zero }
        let rect = rowView.convert(rowView.bounds, to: nil)
        return window.convertToScreen(rect)
    }
}

/// Row view whose stripe and selection draw as rounded, inset bands
/// congruent with the virtual-row stripes in FileListTableView.
/// The stripe draws here, not through `backgroundColor`: the table
/// resets that property on every added row, so an opaque fill would
/// come back and cover the band.
final class RoundedSelectionRowView: NSTableRowView {
    override func drawBackground(in dirtyRect: NSRect) {
        guard let table = superview as? NSTableView else { return }
        let row = table.row(for: self)
        guard row >= 0, row % 2 == 1 else { return }
        let colors = NSColor.alternatingContentBackgroundColors
        guard colors.count > 1 else { return }
        colors[1].setFill()
        let rect = NSRect(
            x: bounds.minX + FileListTableView.bandInset,
            y: bounds.minY,
            width: bounds.width - FileListTableView.bandInset * 2,
            height: bounds.height)
        NSBezierPath(
            roundedRect: rect,
            xRadius: FileListTableView.bandRadius,
            yRadius: FileListTableView.bandRadius
        ).fill()
    }

    override func drawSelection(in dirtyRect: NSRect) {
        guard selectionHighlightStyle != .none else { return }
        let color = isEmphasized
            ? NSColor.selectedContentBackgroundColor
            : NSColor.unemphasizedSelectedContentBackgroundColor
        color.setFill()
        let rect = NSRect(
            x: bounds.minX + FileListTableView.bandInset,
            y: bounds.minY,
            width: bounds.width - FileListTableView.bandInset * 2,
            height: bounds.height)
        NSBezierPath(
            roundedRect: rect,
            xRadius: FileListTableView.bandRadius,
            yRadius: FileListTableView.bandRadius
        ).fill()
    }
}

// MARK: - Table view subclass: keys and responder-chain clipboard

/// Return renames (Finder convention). Cmd+Down and Cmd+O open.
/// Cut/Copy/Paste arrive here through the responder chain from the Edit menu.
final class FileListTableView: NSTableView {
    weak var actions: FileListCoordinator?

    override func keyDown(with event: NSEvent) {
        let isReturn = event.keyCode == 36
        let isSpace = event.keyCode == 49
            && !event.modifierFlags.contains(.command)
        let isCmdDown = event.keyCode == 125
            && event.modifierFlags.contains(.command)
        let isCmdO = event.charactersIgnoringModifiers == "o"
            && event.modifierFlags.contains(.command)
        if isReturn && selectedRowIndexes.count == 1 {
            actions?.beginRenameOnSelection()
            return
        }
        if isSpace && selectedRow >= 0 {
            actions?.toggleQuickLook()
            return
        }
        if (isCmdDown || isCmdO) && selectedRow >= 0 {
            actions?.openSelection()
            return
        }
        super.keyDown(with: event)
    }

    @objc func copy(_ sender: Any?) { actions?.copySelection() }
    @objc func cut(_ sender: Any?) { actions?.cutSelection() }
    @objc func paste(_ sender: Any?) { actions?.paste() }

    /// Horizontal inset and corner radius of the stripe and selection
    /// bands. Shared so the two backgrounds stay congruent.
    static let bandInset: CGFloat = 8
    static let bandRadius: CGFloat = 7

    /// Draws the alternating stripes as rounded, inset bands across the
    /// full scroll height, including past the last row, the way the
    /// built-in striping does.
    override func drawBackground(inClipRect clipRect: NSRect) {
        backgroundColor.setFill()
        clipRect.fill()
        let colors = NSColor.alternatingContentBackgroundColors
        guard colors.count > 1 else { return }
        colors[1].setFill()
        let pitch = rowHeight + intercellSpacing.height
        guard pitch > 0 else { return }
        let bandRect = { (row: Int) in
            NSRect(
                x: self.bounds.minX + Self.bandInset,
                y: CGFloat(row) * pitch,
                width: self.bounds.width - Self.bandInset * 2,
                height: pitch)
        }
        var row = max(Int(clipRect.minY / pitch), 0)
        while bandRect(row).minY < clipRect.maxY {
            if row % 2 == 1 {
                NSBezierPath(
                    roundedRect: bandRect(row),
                    xRadius: Self.bandRadius,
                    yRadius: Self.bandRadius
                ).fill()
            }
            row += 1
        }
    }

    // MARK: Quick Look panel control (responder chain)

    override func acceptsPreviewPanelControl(_ panel: QLPreviewPanel!) -> Bool {
        true
    }

    override func beginPreviewPanelControl(_ panel: QLPreviewPanel!) {
        panel.dataSource = actions
        panel.delegate = actions
    }

    override func endPreviewPanelControl(_ panel: QLPreviewPanel!) {
        panel.dataSource = nil
        panel.delegate = nil
    }
}
