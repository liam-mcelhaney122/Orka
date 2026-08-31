import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct SidebarView: View {
    @Bindable var model: AppModel
    @Bindable var window: WindowState
    @State private var homeTree = SidebarNode(
        path: FileManager.default.homeDirectoryForCurrentUser.path)
    @State private var rootTree = SidebarNode(path: "/")
    @State private var volumes: [VolumeInfo] = []

    private var homePath: String {
        FileManager.default.homeDirectoryForCurrentUser.path
    }

    /// Icon for a well-known favorite path; a generic folder icon otherwise.
    private func favoriteIcon(for path: String) -> String {
        switch path {
        case homePath: return "house"
        case homePath + "/Desktop": return "display"
        case homePath + "/Documents": return "doc.text"
        case homePath + "/Downloads": return "arrow.down.circle"
        case "/Applications": return "square.grid.3x3"
        default: return "folder"
        }
    }

    private func favoriteName(for path: String) -> String {
        path == homePath
            ? "Home" : URL(fileURLWithPath: path).lastPathComponent
    }

    var body: some View {
        List {
            Section {
                ForEach(model.favorites, id: \.self) { path in
                    let missing = !FileManager.default.fileExists(atPath: path)
                    sidebarButton(
                        name: favoriteName(for: path),
                        icon: favoriteIcon(for: path), path: path)
                        .modifier(SidebarFolderDropModifier(
                            destination: path, model: model, window: window,
                            enabled: !missing))
                        .foregroundStyle(missing ? .secondary : .primary)
                        .opacity(missing ? 0.5 : 1)
                        .contextMenu {
                            Button("Remove from Favorites") {
                                model.removeFavorite(path)
                            }
                        }
                }
                .onMove { model.moveFavorites(from: $0, to: $1) }
                // Trash lives with Favorites, above the folder trees.
                // At the bottom of the list it scrolls out of view.
                Button {
                    model.openTrash(in: window)
                } label: {
                    Label("Trash", systemImage: "trash")
                }
                .buttonStyle(.plain)
                .help(AppModel.trashPath)
                .contextMenu {
                    Button("Empty Trash…") {
                        model.requestEmptyTrash(in: window)
                    }
                }
            } header: {
                sectionHeader("Favorites")
            }
            Section {
                ForEach(volumes) { volume in
                    HStack {
                        sidebarButton(
                            name: volume.name,
                            icon: volume.isEjectable
                                ? "externaldrive" : "internaldrive",
                            path: volume.path)
                        if volume.isEjectable {
                            Spacer()
                            Button {
                                model.eject(
                                    volumeURL: URL(fileURLWithPath: volume.path))
                            } label: {
                                Image(systemName: "eject")
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.secondary)
                            .help("Eject")
                        }
                    }
                    .modifier(SidebarFolderDropModifier(
                        destination: volume.path, model: model, window: window,
                        enabled: true))
                }
            } header: {
                sectionHeader("Locations")
            }
            Section {
                ForEach(model.connectionStore.connections) { stored in
                    connectionRow(stored)
                }
                Button {
                    window.editingConnection = ConnectionEditorTarget()
                } label: {
                    Label("Add Connection…", systemImage: "plus.circle")
                }
                .buttonStyle(.plain)
                .help("Create a new remote connection")
            } header: {
                sectionHeader("Connections")
            }
            Section {
                SidebarTreeRow(node: homeTree, model: model, window: window)
                SidebarTreeRow(node: rootTree, model: model, window: window)
            } header: {
                sectionHeader("Folders")
            }
        }
        .listStyle(.sidebar)
        // The macOS 26 sidebar metrics are airy; the compact row
        // height keeps the full tree visible in short windows.
        .environment(\.defaultMinListRowHeight, 24)
        // Finder-style floating pane: the list content clips into a
        // rounded glass surface; ContentView insets it from the window
        // edges.
        .scrollContentBackground(.hidden)
        .glassEffect(.regular, in: .rect(cornerRadius: 12))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .onAppear(perform: loadVolumes)
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(
            for: NSWorkspace.didMountNotification)) { _ in loadVolumes() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(
            for: NSWorkspace.didUnmountNotification)) { _ in loadVolumes() }
    }

    /// Section title indented to align with the row icon column,
    /// the way Finder aligns its sidebar headers.
    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .padding(.leading, 16)
    }

    private func sidebarButton(name: String, icon: String, path: String) -> some View {
        Button {
            window.navigate(to: path)
        } label: {
            Label(name, systemImage: icon)
        }
        .buttonStyle(.plain)
        .help(path)
    }

    /// One row for a saved connection. Its icon reflects the live state;
    /// clicking connects (if needed) and navigates once Connected.
    private func connectionRow(_ stored: StoredConnection) -> some View {
        let state = model.connectionStates[stored.id] ?? .disconnected
        return Button {
            if state == .connected {
                window.navigate(to: stored.uri)
            } else {
                model.connectAndNavigate(stored)
            }
        } label: {
            HStack(spacing: 6) {
                connectionIcon(state)
                    .frame(width: 14)
                Text(stored.displayName)
            }
        }
        .buttonStyle(.plain)
        .help(
            state == .connected
                ? "Open \(stored.uri)" : "Connect to \(stored.uri)")
        .contextMenu {
            if state == .connected {
                Button("Disconnect") {
                    model.disconnectConnection(id: stored.id)
                }
            } else {
                Button("Connect") { model.connectAndNavigate(stored) }
            }
            Button("Edit…") {
                window.editingConnection = ConnectionEditorTarget(editing: stored)
            }
            Divider()
            Button("Remove") { model.removeConnection(id: stored.id) }
        }
    }

    @ViewBuilder
    private func connectionIcon(_ state: ConnectionState) -> some View {
        switch state {
        case .connected:
            Image(systemName: "bolt.fill").foregroundStyle(.tint)
        case .connecting:
            ProgressView().controlSize(.mini)
        case .failed:
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.yellow)
        case .disconnected:
            Image(systemName: "bolt.slash").foregroundStyle(.secondary)
        }
    }

    private func loadVolumes() {
        let keys: [URLResourceKey] = [
            .volumeNameKey, .volumeIsEjectableKey, .volumeIsRemovableKey,
        ]
        let urls = FileManager.default.mountedVolumeURLs(
            includingResourceValuesForKeys: keys,
            options: [.skipHiddenVolumes]) ?? []
        volumes = urls.compactMap { url in
            let values = try? url.resourceValues(forKeys: Set(keys))
            let name = values?.volumeName ?? url.lastPathComponent
            let ejectable = (values?.volumeIsEjectable ?? false)
                || (values?.volumeIsRemovable ?? false)
            return VolumeInfo(name: name, path: url.path, isEjectable: ejectable)
        }
    }
}

struct VolumeInfo: Identifiable {
    var id: String { path }
    let name: String
    let path: String
    let isEjectable: Bool
}

/// Recursive lazy tree row. Expanding a node loads its child directories.
struct SidebarTreeRow: View {
    @Bindable var node: SidebarNode
    let model: AppModel
    var window: WindowState

    var body: some View {
        DisclosureGroup(isExpanded: $node.isExpanded) {
            if let children = node.children {
                ForEach(children) { child in
                    SidebarTreeRow(node: child, model: model, window: window)
                }
            } else {
                ProgressView()
                    .controlSize(.small)
            }
        } label: {
            Label(node.name, systemImage: "folder")
                .contentShape(Rectangle())
                .onTapGesture { window.navigate(to: node.path) }
                .modifier(SidebarFolderDropModifier(
                    destination: node.path, model: model, window: window,
                    enabled: true))
        }
    }
}

private struct SidebarFolderDropModifier: ViewModifier {
    let destination: String
    let model: AppModel
    let window: WindowState
    let enabled: Bool
    @State private var isTargeted = false

    func body(content: Content) -> some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .overlay {
                if isTargeted {
                    RoundedRectangle(cornerRadius: 5)
                        .stroke(Color.accentColor, lineWidth: 2)
                        .allowsHitTesting(false)
                    }
            }
            .dropDestination(for: URL.self) { urls, _ in
                guard enabled, isValidDestination else { return false }
                let sources = urls.filter(\.isFileURL).map(\.path)
                guard !sources.isEmpty else { return false }
                model.transfer(
                    sources: sources,
                    to: destination,
                    move: DropTransferPolicy.shouldMove(
                        sources: sources,
                        destDir: destination,
                        forceCopy: NSEvent.modifierFlags.contains(.option)),
                    in: window)
                return true
            } isTargeted: { targeted in
                isTargeted = targeted && enabled && isValidDestination
            }
            .onDrop(
                of: [TabBarView.remotePathUTType, .orkaSelectedPaths],
                delegate: SidebarFolderDropDelegate(
                    destination: destination, model: model, window: window,
                    enabled: enabled, isTargeted: $isTargeted))
    }

    private var isValidDestination: Bool {
        guard OrkaPath.isLocal(destination),
            !destination.lowercased().hasSuffix(".app")
        else { return false }
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(
            atPath: destination, isDirectory: &isDirectory)
            && isDirectory.boolValue
    }
}

private struct SidebarFolderDropDelegate: DropDelegate {
    let destination: String
    let model: AppModel
    let window: WindowState
    let enabled: Bool
    @Binding var isTargeted: Bool

    func validateDrop(info: DropInfo) -> Bool {
        enabled && isValidDestination
            && info.hasItemsConforming(
                to: [TabBarView.remotePathUTType, .orkaSelectedPaths])
    }

    func dropEntered(info: DropInfo) {
        isTargeted = validateDrop(info: info)
    }

    func dropExited(info: DropInfo) {
        isTargeted = false
    }

    func dropUpdated(info: DropInfo) -> DropProposal? {
        guard validateDrop(info: info) else {
            isTargeted = false
            return DropProposal(operation: .cancel)
        }
        let providers = DropPathLoader.providers(from: info)
        guard !providers.isEmpty else {
            isTargeted = false
            return DropProposal(operation: .cancel)
        }
        return DropProposal(operation: DropTransferPolicy.proposedOperation(
            providers: providers, destDir: destination))
    }

    func performDrop(info: DropInfo) -> Bool {
        isTargeted = false
        guard enabled, isValidDestination else { return false }
        let providers = DropPathLoader.providers(from: info)
        guard !providers.isEmpty else { return false }
        let capturedDestination = destination
        let forceCopy = NSEvent.modifierFlags.contains(.option)
        DropPathLoader.load(providers) { result in
            switch result {
            case .success(let loaded):
                let sources = DropTransferPolicy.transferSources(
                    loaded, destDir: capturedDestination)
                guard !sources.isEmpty else { return }
                model.transfer(
                    sources: sources,
                    to: capturedDestination,
                    move: DropTransferPolicy.shouldMove(
                        sources: sources, destDir: capturedDestination,
                        forceCopy: forceCopy),
                    in: window)
            case .failure(let error):
                model.lastJobErrors = [JobItemError(
                    path: capturedDestination,
                    message: error.localizedDescription)]
            }
        }
        return true
    }

    private var isValidDestination: Bool {
        guard OrkaPath.isLocal(destination),
            !destination.lowercased().hasSuffix(".app")
        else { return false }
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(
            atPath: destination, isDirectory: &isDirectory)
            && isDirectory.boolValue
    }
}
