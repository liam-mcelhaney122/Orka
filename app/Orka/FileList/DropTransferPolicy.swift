import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Shared move-or-copy policy for the SwiftUI drop targets: tabs, the
/// icon grid, and sidebar folders. The file-list coordinator keeps its
/// own decision because AppKit drags express the Option key through the
/// drag operation mask, not through live modifier flags.
enum DropTransferPolicy {
    /// Filters out no-op and unsafe transfers: dropping into the folder
    /// the item is already in, or a folder into itself or its own
    /// descendant.
    static func transferSources(
        _ sources: [String], destDir: String
    ) -> [String] {
        sources.filter { source in
            let parent = OrkaPath.isLocal(source)
                ? URL(fileURLWithPath: source).deletingLastPathComponent().path
                : OrkaPath.remoteParent(of: source)
            if let parent, samePath(parent, destDir) { return false }
            if samePath(destDir, source) || destDir.hasPrefix(source + "/") {
                return false
            }
            return true
        }
    }

    /// A remote directory can arrive with or without a trailing slash;
    /// `remoteParent` never returns one.
    private static func samePath(_ a: String, _ b: String) -> Bool {
        a == b || trimSlash(a) == trimSlash(b)
    }

    private static func trimSlash(_ path: String) -> Substring {
        path.count > 1 && path.hasSuffix("/") ? path.dropLast() : path[...]
    }

    static func sameVolume(_ a: String, _ b: String) -> Bool {
        func volumeID(_ path: String) -> AnyHashable? {
            let values = try? URL(fileURLWithPath: path)
                .resourceValues(forKeys: [.volumeIdentifierKey])
            return values?.volumeIdentifier as? AnyHashable
        }
        guard let va = volumeID(a), let vb = volumeID(b) else { return false }
        return va == vb
    }

    /// Move only when the copy is not forced, and the transfer stays on
    /// one backend: every endpoint local and on the same volume, or
    /// every endpoint remote on the same connection. A transfer that
    /// crosses volumes, connections, or local/remote always copies.
    static func shouldMove(
        sources: [String], destDir: String, forceCopy: Bool
    ) -> Bool {
        guard !forceCopy else { return false }
        if OrkaPath.isLocal(destDir) {
            guard sources.allSatisfy(OrkaPath.isLocal) else { return false }
            return sources.allSatisfy { sameVolume($0, destDir) }
        }
        guard sources.allSatisfy({ !OrkaPath.isLocal($0) }) else { return false }
        return sources.allSatisfy { OrkaPath.sameConnection($0, destDir) }
    }

    /// Hover proposal: move when the Option key is up and the drag stays
    /// on one side. A local destination moves when every provider vends
    /// a file URL. A remote destination moves when no provider vends
    /// one, which marks an internal drag of remote rows. The drop itself
    /// still copies across volumes or connections; see `shouldMove`.
    @MainActor
    static func proposedOperation(
        providers: [NSItemProvider], destDir: String
    ) -> DropOperation {
        guard !NSEvent.modifierFlags.contains(.option) else { return .copy }
        let vendsFileURL = providers.map {
            $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
        }
        if OrkaPath.isLocal(destDir) {
            return vendsFileURL.allSatisfy { $0 } ? .move : .copy
        }
        return vendsFileURL.contains(true) ? .copy : .move
    }
}
