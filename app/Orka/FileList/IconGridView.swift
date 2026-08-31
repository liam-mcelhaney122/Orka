import AppKit
import SwiftUI
import UniformTypeIdentifiers

extension UTType {
    static let orkaSelectedPaths = UTType(
        exportedAs: "com.orka.selected-paths")
}

/// Icon grid view. The details view stays the primary surface; the grid
/// covers the Finder/Explorer icon-view parity case.
struct IconGridView: View {
    @Bindable var model: AppModel
    var window: WindowState
    /// Anchor for shift-click range selection.
    @State private var anchorPath: String?

    private var directory: DirectoryModel { window.activePane.directory }

    private var entries: [FsEntry] {
        let base: [FsEntry]
        if let results = directory.searchResults {
            base = results
        } else if window.searchText.isEmpty {
            base = directory.entries
        } else {
            base = directory.entries.filter {
                $0.name.localizedCaseInsensitiveContains(window.searchText)
            }
        }
        return base.sorted { a, b in
            if a.isDir != b.isDir { return a.isDir }
            return a.name.localizedStandardCompare(b.name) == .orderedAscending
        }
    }

    var body: some View {
        ZStack {
            ScrollView {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 100), spacing: 4)],
                    spacing: 10
                ) {
                    ForEach(entries, id: \.path) { entry in
                        let gitState = directory.searchResults == nil
                            ? directory.gitStates[entry.name] : nil
                        IconCell(
                            entry: entry,
                            selected: directory.selection.contains(entry.path),
                            cut: model.cutPaths.contains(entry.path),
                            gitState: gitState)
                            .gesture(TapGesture(count: 2).onEnded {
                                model.open(entry)
                            })
                            .simultaneousGesture(TapGesture().onEnded {
                                select(entry)
                            })
                            .onDrag {
                                makeDragProvider(for: entry)
                            }
                            .contextMenu { itemMenu(for: entry) }
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity)
            }
        }
        .contentShape(Rectangle())
        .onDrop(
            of: [TabBarView.remotePathUTType, .orkaSelectedPaths],
            delegate: IconGridDropDelegate(
                model: model, window: window))
        .contextMenu { backgroundMenu }
    }

    private func select(_ entry: FsEntry) {
        let flags = NSApp.currentEvent?.modifierFlags ?? []
        if flags.contains(.command) {
            if directory.selection.contains(entry.path) {
                directory.selection.remove(entry.path)
            } else {
                directory.selection.insert(entry.path)
                anchorPath = entry.path
            }
        } else if flags.contains(.shift), let anchor = anchorPath,
            let from = entries.firstIndex(where: { $0.path == anchor }),
            let to = entries.firstIndex(where: { $0.path == entry.path }) {
            let range = min(from, to)...max(from, to)
            directory.selection = Set(entries[range].map(\.path))
        } else {
            directory.selection = [entry.path]
            anchorPath = entry.path
        }
    }

    @ViewBuilder
    private func itemMenu(for entry: FsEntry) -> some View {
        if OrkaPath.isLocal(directory.path) {
            localItemMenu(for: entry)
        } else {
            remoteItemMenu(for: entry)
        }
    }

    /// Remote rename and file drag-out to other apps are a later
    /// milestone; the menu offers what already works today. Delete is
    /// permanent (no server trash) and confirms before running.
    @ViewBuilder
    private func remoteItemMenu(for entry: FsEntry) -> some View {
        if entry.isDir {
            Button("Open") {
                selectForMenu(entry)
                model.open(entry)
            }
        }
        Button("Copy Path") {
            selectForMenu(entry)
            model.copyPaths(
                Array(directory.selection), relative: false, in: window)
        }
        Button("Copy Relative Path") {
            selectForMenu(entry)
            model.copyPaths(
                Array(directory.selection), relative: true, in: window)
        }
        if model.canPaste {
            Button("Paste") { model.paste(in: window) }
        }
        Divider()
        Button("Delete", role: .destructive) {
            selectForMenu(entry)
            model.trashSelection(in: window)
        }
    }

    @ViewBuilder
    private func localItemMenu(for entry: FsEntry) -> some View {
        Button("Open") {
            selectForMenu(entry)
            model.open(entry)
        }
        openWithMenu(for: entry)
        Button("Get Info") {
            selectForMenu(entry)
            model.getInfo(in: window)
        }
        Button("Reveal in Finder") {
            NSWorkspace.shared.activateFileViewerSelecting(
                [URL(fileURLWithPath: entry.path)])
        }
        Divider()
        Button("Duplicate") {
            selectForMenu(entry)
            model.duplicateSelection(in: window)
        }
        Menu("Compress") {
            Button("ZIP") {
                selectForMenu(entry)
                model.compressSelection(as: .zip, in: window)
            }
            Button("Tar") {
                selectForMenu(entry)
                model.compressSelection(as: .tar, in: window)
            }
            Button("Tar.gz") {
                selectForMenu(entry)
                model.compressSelection(as: .tarGz, in: window)
            }
        }
        // Only a single selected archive can extract; `selectForMenu`
        // narrows the selection to this entry when it was unselected.
        if AppModel.isArchivePath(entry.path) {
            Button("Extract Archive") {
                selectForMenu(entry)
                model.extractSelection(in: window)
            }
        }
        Button("Move to Trash") {
            selectForMenu(entry)
            model.trashSelection(in: window)
        }
        Divider()
        Button("Cut") {
            selectForMenu(entry)
            model.cutSelection(in: window)
        }
        Button("Copy") {
            selectForMenu(entry)
            model.copySelection(in: window)
        }
        Button("Copy Path") {
            selectForMenu(entry)
            model.copyPaths(
                Array(directory.selection), relative: false, in: window)
        }
        Button("Copy Relative Path") {
            selectForMenu(entry)
            model.copyPaths(
                Array(directory.selection), relative: true, in: window)
        }
        if model.canPaste {
            Button("Paste") { model.paste(in: window) }
        }
        if entry.isDir, !model.favorites.contains(entry.path) {
            Button("Add to Favorites") {
                model.addFavorite(entry.path)
            }
        }
    }

    /// "Open With" submenu listing every application that opens the
    /// menu's targets, default application first.
    private func openWithMenu(for entry: FsEntry) -> some View {
        let paths = directory.selection.contains(entry.path)
            ? Array(directory.selection) : [entry.path]
        return Menu("Open With") {
            ForEach(OpenWithApps.apps(for: paths), id: \.url) { app in
                Button {
                    selectForMenu(entry)
                    OpenWithApps.open(paths: paths, with: app.url)
                } label: {
                    Label {
                        Text(app.isDefault
                            ? "\(app.name) (default)" : app.name)
                    } icon: {
                        Image(nsImage: app.icon)
                    }
                }
            }
            Divider()
            Button("Other…") {
                selectForMenu(entry)
                OpenWithApps.chooseAndOpen(paths: paths)
            }
        }
    }

    @ViewBuilder
    private var backgroundMenu: some View {
        if OrkaPath.isLocal(directory.path) {
            Button("New Folder") { model.newFolder(in: window) }
        }
        if model.canPaste {
            Button("Paste") { model.paste(in: window) }
        }
    }

    /// A right-click on an unselected item targets that item, like the
    /// details view.
    private func selectForMenu(_ entry: FsEntry) {
        if !directory.selection.contains(entry.path) {
            directory.selection = [entry.path]
        }
    }

    /// Builds an NSItemProvider for a drag. When the entry is part of a
    /// multi-selection, drags all selected items. Local files carry a
    /// file URL for Finder; a remote set carries a file representation
    /// that downloads on drop; every set carries the selected-paths type
    /// so another Orka window can pick up a multi-item transfer.
    private func makeDragProvider(for entry: FsEntry) -> NSItemProvider {
        let dragging = entries.filter {
            directory.selection.contains($0.path)
        }
        let paths: [String]
        if dragging.isEmpty || !dragging.contains(where: { $0.path == entry.path }) {
            paths = [entry.path]
        } else {
            paths = dragging.map(\.path)
        }
        let provider = NSItemProvider()
        let firstLocal = paths.first(where: { OrkaPath.isLocal($0) })
        if let localPath = firstLocal {
            provider.suggestedName = (localPath as NSString).lastPathComponent
            provider.registerObject(
                NSURL(fileURLWithPath: localPath), visibility: .all)
        } else if let remotePath = paths.first {
            registerRemoteFileRepresentation(
                for: remotePath, on: provider)
        }
        provider.registerDataRepresentation(
            forTypeIdentifier: UTType.orkaSelectedPaths.identifier,
            visibility: .ownProcess
        ) { completion in
            let data = (try? JSONEncoder().encode(paths)) ?? Data()
            completion(data, nil)
            return nil
        }
        return provider
    }

    /// Lets a remote grid item land in Finder: the load handler
    /// downloads the file into a staging directory and hands the staged
    /// URL over. The receiver copies from that URL, so the staging
    /// directory cannot be removed here; the launch sweep collects it.
    private func registerRemoteFileRepresentation(
        for remotePath: String, on provider: NSItemProvider
    ) {
        let name = (remotePath as NSString).lastPathComponent
        provider.suggestedName = name
        let ext = (name as NSString).pathExtension
        let fileType = ext.isEmpty
            ? UTType.data
            : (UTType(filenameExtension: ext) ?? .data)
        let model = self.model
        provider.registerFileRepresentation(
            forTypeIdentifier: fileType.identifier,
            fileOptions: [],
            visibility: .all
        ) { completion in
            Task { @MainActor in
                RemotePromiseStager.download(
                    remotePath: remotePath, model: model
                ) { result in
                    switch result {
                    case .success(let staged):
                        completion(staged, false, nil)
                    case .failure(let error):
                        completion(nil, false, error)
                    }
                }
            }
            return nil
        }
    }
}

private struct IconCell: View {
    let entry: FsEntry
    let selected: Bool
    let cut: Bool
    let gitState: GitFileState?

    var body: some View {
        VStack(spacing: 5) {
            ZStack(alignment: .bottomTrailing) {
                Image(nsImage: FileKindCache.icon(forPath: entry.path, size: 48))
                    .resizable()
                    .frame(width: 48, height: 48)
                if let dotColor = Self.dotColor(for: gitState) {
                    Circle()
                        .fill(dotColor)
                        .frame(width: 8, height: 8)
                }
            }
            Text(entry.name)
                .font(.caption)
                .lineLimit(2)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .foregroundStyle(
                    selected
                        ? AnyShapeStyle(.white)
                        : entry.isHidden
                            ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary)
                )
                .background(
                    RoundedRectangle(cornerRadius: 5)
                        .fill(selected ? Color.accentColor : .clear))
        }
        .frame(width: 100)
        .padding(.vertical, 6)
        .opacity(cellOpacity)
        .contentShape(Rectangle())
    }

    private var cellOpacity: Double {
        let base = cut ? 0.5 : 1.0
        return gitState == .ignored ? base * 0.6 : base
    }

    /// Dot color per git state. Ignored entries have no dot; the cell is
    /// dimmed instead.
    private static func dotColor(for state: GitFileState?) -> Color? {
        switch state {
        case .modified: return Color(nsColor: .systemOrange)
        case .staged, .stagedAndModified: return Color(nsColor: .systemGreen)
        case .untracked: return Color(nsColor: .tertiaryLabelColor)
        case .conflicted: return Color(nsColor: .systemRed)
        case .ignored, nil: return nil
        }
    }
}

// MARK: - Drop delegate

/// Handles file drops onto the icon grid, from Finder and from other
/// Orka views. The ZStack makes the full visible pane a drop target.
private struct IconGridDropDelegate: DropDelegate {
    let model: AppModel
    let window: WindowState

    private var destDir: String { window.activePane.directory.path }

    func validateDrop(info: DropInfo) -> Bool {
        return info.hasItemsConforming(
            to: [.fileURL, TabBarView.remotePathUTType,
                 .orkaSelectedPaths])
    }

    func dropUpdated(info: DropInfo) -> DropProposal? {
        let providers = DropPathLoader.providers(from: info)
        guard !providers.isEmpty else {
            return DropProposal(operation: .cancel)
        }
        return DropProposal(operation: DropTransferPolicy.proposedOperation(
            providers: providers, destDir: destDir))
    }

    func performDrop(info: DropInfo) -> Bool {
        let providers = DropPathLoader.providers(from: info)
        guard !providers.isEmpty else { return false }
        let destination = destDir
        let forceCopy = NSEvent.modifierFlags.contains(.option)
        DropPathLoader.load(providers) { result in
            switch result {
            case .success(let loaded):
                let sources = DropTransferPolicy.transferSources(
                    loaded, destDir: destination)
                guard !sources.isEmpty else { return }
                guard OrkaPath.isLocal(destination)
                    || sources.allSatisfy(OrkaPath.isLocal)
                else { return }
                model.transfer(
                    sources: sources,
                    to: destination,
                    move: DropTransferPolicy.shouldMove(
                        sources: sources, destDir: destination,
                        forceCopy: forceCopy),
                    in: window)
            case .failure(let error):
                model.lastJobErrors = [JobItemError(
                    path: destination,
                    message: error.localizedDescription)]
            }
        }
        return true
    }
}

// MARK: - SwiftUI drop loading

/// Loads paths through the item providers supplied by SwiftUI. A provider
/// can vend its data later, so the AppKit drag pasteboard is not sufficient.
enum DropPathLoader {
    private enum Payload {
        case selectedPaths
        case remotePath
        case fileURL

        var typeIdentifier: String {
            switch self {
            case .selectedPaths: return UTType.orkaSelectedPaths.identifier
            case .remotePath: return TabBarView.remotePathUTType.identifier
            case .fileURL: return UTType.fileURL.identifier
            }
        }
    }

    struct LoadError: LocalizedError {
        var errorDescription: String? {
            "Could not read all items from the drop."
        }
    }

    static func providers(from info: DropInfo) -> [NSItemProvider] {
        info.itemProviders(for: [
            .orkaSelectedPaths,
            TabBarView.remotePathUTType,
            .fileURL,
        ])
    }

    @MainActor
    static func load(
        _ providers: [NSItemProvider],
        completion: @escaping @MainActor (Result<[String], Error>) -> Void
    ) {
        let payload: Payload
        if providers.contains(where: {
            $0.hasItemConformingToTypeIdentifier(
                Payload.selectedPaths.typeIdentifier)
        }) {
            payload = .selectedPaths
        } else if providers.contains(where: {
            $0.hasItemConformingToTypeIdentifier(
                Payload.remotePath.typeIdentifier)
        }) {
            payload = .remotePath
        } else {
            payload = .fileURL
        }

        let matching = providers.filter {
            $0.hasItemConformingToTypeIdentifier(payload.typeIdentifier)
        }
        let group = DispatchGroup()
        let lock = NSLock()
        var loaded = Array(repeating: [String](), count: matching.count)
        var failed = false

        for (index, provider) in matching.enumerated() {
            group.enter()
            switch payload {
            case .fileURL:
                provider.loadObject(ofClass: NSURL.self) { object, _ in
                    lock.lock()
                    if let path = (object as? NSURL)?.path {
                        loaded[index] = [path]
                    } else {
                        failed = true
                    }
                    lock.unlock()
                    group.leave()
                }
            case .selectedPaths, .remotePath:
                provider.loadDataRepresentation(
                    forTypeIdentifier: payload.typeIdentifier
                ) { data, _ in
                    lock.lock()
                    if let data {
                        switch payload {
                        case .selectedPaths:
                            if let paths = try? JSONDecoder().decode(
                                [String].self, from: data) {
                                loaded[index] = paths
                            } else {
                                failed = true
                            }
                        case .remotePath:
                            if let path = String(data: data, encoding: .utf8) {
                                loaded[index] = [path]
                            } else {
                                failed = true
                            }
                        case .fileURL:
                            break
                        }
                    } else {
                        failed = true
                    }
                    lock.unlock()
                    group.leave()
                }
            }
        }

        group.notify(queue: .main) {
            if failed {
                completion(.failure(LoadError()))
            } else {
                completion(.success(loaded.flatMap { $0 }))
            }
        }
    }
}
