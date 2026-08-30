import Foundation
import Observation

/// Single source of truth for one directory listing shown in a pane.
@MainActor
@Observable
final class DirectoryModel {
    private(set) var path: String
    private(set) var entries: [FsEntry] = []
    private(set) var isLoading = false
    private(set) var errorMessage: String?
    var selection: Set<String> = []

    /// Increments whenever `entries` is replaced. The AppKit table view
    /// compares stamps to decide when a full reload is necessary.
    private(set) var loadStamp = 0

    /// What the backend behind `path` can do. Recomputed on every reload,
    /// so it always matches the directory currently shown; cheap enough
    /// to call synchronously (a `HashMap` lookup on the Rust side, no I/O).
    private(set) var capabilities = PathCapabilities(
        isLocal: true, canTrash: true, canWatch: true, canRename: true,
        serverSideCopy: false, preservesPermissions: true)

    /// Git status of this directory, when it sits inside a repository.
    private(set) var gitStatus: GitDirStatus?
    /// `gitStatus.entries` keyed by child name, for O(1) lookup per row.
    private(set) var gitStates: [String: GitFileState] = [:]
    /// Increments whenever `gitStatus` is applied. The AppKit table view
    /// compares stamps to decide when the name column needs a reload.
    private(set) var gitStamp = 0

    /// Drops results of superseded loads that finish out of order.
    private var generation = 0

    /// Called with (old, new) when the shown path changes, so the owner
    /// can move the file-system watch.
    var onPathChanged: ((String, String) -> Void)?

    /// Called after a successful load, so the owner can start follow-up
    /// work, such as a folder-size request, for the new listing.
    var onLoaded: (() -> Void)?

    init(path: String) {
        self.path = path
    }

    var displayName: String {
        OrkaPath.displayName(path)
    }

    /// Deep-search results. When non-nil the pane shows these instead of
    /// the directory listing, with the path column visible.
    private(set) var searchResults: [FsEntry]?

    func show(path: String, showHidden: Bool) {
        let old = self.path
        self.path = path
        selection = []
        searchResults = nil
        if old != path {
            onPathChanged?(old, path)
            gitStatus = nil
            gitStates = [:]
            gitStamp += 1
        }
        reload(showHidden: showHidden)
    }

    func showSearchResults(_ entries: [FsEntry]) {
        searchResults = entries
        selection = []
        loadStamp += 1
    }

    func clearSearchResults() {
        guard searchResults != nil else { return }
        searchResults = nil
        selection = []
        loadStamp += 1
    }

    func reload(showHidden: Bool) {
        generation += 1
        let gen = generation
        let target = path
        // The engine call routes remote URIs to their backend; the free
        // listDirectory stays local-only for the sidebar tree.
        let engine = AppModel.shared.engine
        capabilities = engine.pathCapabilities(path: target)
        isLoading = true
        Task.detached(priority: .userInitiated) {
            let result: Result<[FsEntry], Error>
            do {
                result = .success(try engine.listPath(
                    path: target, includeHidden: showHidden, dirsOnly: false))
            } catch {
                result = .failure(error)
            }
            await MainActor.run { [weak self] in
                self?.apply(gen: gen, result: result)
            }
        }
    }

    private func apply(gen: Int, result: Result<[FsEntry], Error>) {
        guard gen == generation else { return }
        isLoading = false
        loadStamp += 1
        switch result {
        case .success(let list):
            entries = list
            errorMessage = nil
            // Keep only selected paths that still exist.
            let alive = Set(list.map(\.path))
            selection = selection.intersection(alive)
            fetchGitStatus(gen: gen)
            onLoaded?()
        case .failure(let error):
            entries = []
            errorMessage = Self.describe(error)
        }
    }

    /// Pulls git status for the current listing. Read-only and pull-based:
    /// no engine event drives this, so a reload is the only trigger.
    private func fetchGitStatus(gen: Int) {
        let target = path
        let engine = AppModel.shared.engine
        Task.detached(priority: .userInitiated) {
            let status = engine.gitStatus(dir: target)
            await MainActor.run { [weak self] in
                self?.applyGitStatus(gen: gen, target: target, status: status)
            }
        }
    }

    private func applyGitStatus(gen: Int, target: String, status: GitDirStatus?) {
        // The pane may have navigated away, or reloaded again, before this
        // call returned; both invalidate the result.
        guard gen == generation, path == target else { return }
        gitStatus = status
        var states: [String: GitFileState] = [:]
        for entry in status?.entries ?? [] {
            states[entry.name] = entry.state
        }
        gitStates = states
        gitStamp += 1
    }

    private static func describe(_ error: Error) -> String {
        if let e = error as? OrkaError {
            switch e {
            case .NotADirectory(let path): return "Not a folder: \(path)"
            case .PermissionDenied(let path): return "Permission denied: \(path)"
            case .NotFound(let path): return "Not found: \(path)"
            case .Io(let message): return message
            }
        }
        return error.localizedDescription
    }
}
