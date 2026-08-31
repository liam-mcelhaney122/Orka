import SwiftUI

/// Two-stage sheet for uploading local items to a remote server: pick a
/// saved connection, then pick a destination folder inside it. Opened
/// via `.sheet(item:)` with an `UploadTarget` naming the local sources.
struct UploadPickerView: View {
    let model: AppModel
    let target: UploadTarget

    @Environment(\.dismiss) private var dismiss

    /// Non-nil once a connection is chosen; this is what switches the
    /// sheet from the connection stage to the browse stage.
    @State private var connection: StoredConnection?

    /// Id of the connection row currently waiting on `engine.connect`.
    @State private var connectingId: String?
    /// Id of the connection row whose last connect attempt failed.
    @State private var failedId: String?

    /// Full remote URI of the folder currently shown in the browse stage.
    @State private var currentPath = ""
    @State private var folders: [FsEntry] = []
    @State private var isLoading = false
    @State private var loadError: String?

    /// Guards a stale `listPath` result from a folder the user already
    /// navigated away from.
    @State private var loadGeneration = 0

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if connection != nil {
                browseStage
            } else {
                connectionStage
            }
            Divider()
            footer
        }
        .frame(width: 480, height: 360)
    }

    private var header: some View {
        Text(connection == nil ? "Choose a Connection" : "Choose a Folder")
            .font(.headline)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
    }

    // MARK: Connection stage

    private var connectionStage: some View {
        Group {
            if model.connectionStore.connections.isEmpty {
                VStack {
                    Spacer()
                    Text("No saved connections.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
            } else {
                List(model.connectionStore.connections) { stored in
                    connectionRow(stored)
                }
                .listStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // Observed at the stage level; a row-level observer misses the
        // state change when List discards a row scrolled out of view.
        .onChange(of: model.connectionStates) { _, states in
            guard let id = connectingId,
                let state = states[id],
                let stored = model.connectionStore.connections
                    .first(where: { $0.id == id })
            else { return }
            handleStateChange(state, for: stored)
        }
    }

    private func connectionRow(_ stored: StoredConnection) -> some View {
        let state = model.connectionStates[stored.id] ?? .disconnected
        return VStack(alignment: .leading, spacing: 4) {
            Button {
                beginConnect(stored)
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(stored.displayName)
                        Text(stored.scheme.label)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if connectingId == stored.id {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if failedId == stored.id {
                Text(model.connectionError ?? "Connection failed.")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(.vertical, 2)
    }

    /// Advances straight to the browse stage when already connected;
    /// otherwise starts the connect and waits for the state change that
    /// `handleStateChange` picks up.
    private func beginConnect(_ stored: StoredConnection) {
        let state = model.connectionStates[stored.id] ?? .disconnected
        if state == .connected {
            selectConnection(stored)
            return
        }
        failedId = nil
        connectingId = stored.id
        model.engine.connect(connectionId: stored.id)
    }

    private func handleStateChange(
        _ state: ConnectionState, for stored: StoredConnection
    ) {
        guard connectingId == stored.id else { return }
        switch state {
        case .connected:
            connectingId = nil
            selectConnection(stored)
        case .failed:
            connectingId = nil
            failedId = stored.id
        case .connecting, .disconnected:
            break
        }
    }

    /// Enters the browse stage, starting at the last-used destination
    /// for this connection when one was saved, else the connection root.
    private func selectConnection(_ stored: StoredConnection) {
        connection = stored
        if let saved = UserDefaults.standard.string(
            forKey: Self.destinationKey(for: stored.id))
        {
            currentPath = saved
            Task { await loadSavedDestination(saved, fallbackRoot: stored.uri) }
        } else {
            currentPath = stored.uri
            Task { await load(path: stored.uri) }
        }
    }

    // MARK: Browse stage

    private var browseStage: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Button {
                    goUp()
                } label: {
                    Image(systemName: "chevron.up")
                }
                .buttonStyle(.borderless)
                .disabled(OrkaPath.remoteParent(of: currentPath) == nil)
                .help("Go to the parent folder")
                Text(currentPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 8)
            Divider()
            folderList
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    @ViewBuilder
    private var folderList: some View {
        if isLoading {
            VStack {
                Spacer()
                ProgressView()
                Spacer()
            }
        } else if let loadError {
            VStack {
                Spacer()
                VStack(spacing: 8) {
                    Text(loadError)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                    Button("Retry") { Task { await load(path: currentPath) } }
                }
                .padding(.horizontal, 16)
                Spacer()
            }
        } else if folders.isEmpty {
            VStack {
                Spacer()
                Text("No subfolders.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
            }
        } else {
            List(folders, id: \.path) { entry in
                Button {
                    descend(to: entry.path)
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "folder")
                            .foregroundStyle(.secondary)
                        Text(entry.name)
                        Spacer()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            .listStyle(.plain)
        }
    }

    private func descend(to path: String) {
        currentPath = path
        Task { await load(path: path) }
    }

    private func goUp() {
        guard let parent = OrkaPath.remoteParent(of: currentPath) else { return }
        currentPath = parent
        Task { await load(path: parent) }
    }

    /// Loads the saved destination. A remote folder can disappear or a
    /// saved connection can be re-pointed between sessions, so a failure
    /// here falls back to the connection root instead of showing an
    /// error for a path the user never chose this time.
    private func loadSavedDestination(_ path: String, fallbackRoot: String) async {
        loadGeneration += 1
        let gen = loadGeneration
        isLoading = true
        loadError = nil
        let engine = model.engine
        let result = await Task.detached(priority: .userInitiated) {
            Result {
                try engine.listPath(
                    path: path, includeHidden: false, dirsOnly: true)
            }
        }.value
        guard gen == loadGeneration else { return }
        switch result {
        case .success(let entries):
            isLoading = false
            folders = Self.sorted(entries)
        case .failure:
            currentPath = fallbackRoot
            await load(path: fallbackRoot)
        }
    }

    private func load(path: String) async {
        loadGeneration += 1
        let gen = loadGeneration
        isLoading = true
        loadError = nil
        let engine = model.engine
        let result = await Task.detached(priority: .userInitiated) {
            Result {
                try engine.listPath(
                    path: path, includeHidden: false, dirsOnly: true)
            }
        }.value
        guard gen == loadGeneration else { return }
        isLoading = false
        switch result {
        case .success(let entries):
            folders = Self.sorted(entries)
            loadError = nil
        case .failure(let error):
            folders = []
            loadError = DirectoryModel.describe(error)
        }
    }

    private static func sorted(_ entries: [FsEntry]) -> [FsEntry] {
        entries.sorted {
            $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    // MARK: Footer

    private var footer: some View {
        HStack {
            if connection != nil {
                Text("Upload to \(destinationName)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(currentPath)
            }
            Spacer()
            Button("Cancel") { dismiss() }
                // Clear tint keeps macOS glass buttons neutral; a tinted
                // glass button renders with a color wash on macOS.
                .buttonStyle(.glass)
                .tint(.clear)
                .keyboardShortcut(.cancelAction)
            if connection != nil {
                Button("Upload Here") { uploadHere() }
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
                    .help("Upload here")
                    // A folder whose listing failed or has not loaded is
                    // not a confirmed destination.
                    .disabled(isLoading || loadError != nil)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    /// Folder name for the footer. At the connection root the URI's last
    /// component is the connection id, so show the saved display name.
    private var destinationName: String {
        if let split = OrkaPath.splitRemote(currentPath),
            split.path.isEmpty || split.path == "/",
            let connection
        {
            return connection.displayName
        }
        return OrkaPath.displayName(currentPath)
    }

    private func uploadHere() {
        guard let connection else { return }
        UserDefaults.standard.set(
            currentPath, forKey: Self.destinationKey(for: connection.id))
        model.uploadItems(target.sources, to: currentPath)
        dismiss()
    }

    private static func destinationKey(for connectionId: String) -> String {
        "uploadDestination.\(connectionId)"
    }
}
