import AppKit
import SwiftUI

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
        ScrollView {
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 100), spacing: 4)],
                spacing: 10
            ) {
                ForEach(entries, id: \.path) { entry in
                    // Search results span many directories; a name-keyed
                    // git-state lookup would mislabel entries from other
                    // folders, so skip it while results are showing.
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
                        .contextMenu { itemMenu(for: entry) }
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity)
        }
        // No opaque fill: the pane's glass surface shows through.
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
