import Foundation
import Observation

/// One node in the lazy folder tree. `children == nil` means not loaded yet.
@MainActor
@Observable
final class SidebarNode: Identifiable {
    let path: String
    let name: String
    var children: [SidebarNode]?
    var isExpanded = false {
        didSet {
            if isExpanded && children == nil {
                loadChildren()
            }
        }
    }
    private var isLoadingChildren = false

    nonisolated var id: String { path }

    init(path: String) {
        self.path = path
        let url = URL(fileURLWithPath: path)
        name = path == "/" ? "Macintosh HD" : url.lastPathComponent
    }

    private func loadChildren() {
        guard !isLoadingChildren else { return }
        isLoadingChildren = true
        let target = path
        Task.detached(priority: .utility) {
            let dirs = (try? listDirectory(
                path: target, includeHidden: false, dirsOnly: true)) ?? []
            await MainActor.run { [weak self] in
                guard let self else { return }
                // Skip .app bundles: they are directories but act as files.
                self.children = dirs
                    .filter { !$0.path.hasSuffix(".app") }
                    .map { SidebarNode(path: $0.path) }
                self.isLoadingChildren = false
            }
        }
    }
}
