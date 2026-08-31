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
            if OrkaPath.isLocal(source) {
                let parent = URL(fileURLWithPath: source)
                    .deletingLastPathComponent().path
                if parent == destDir { return false }
            }
            if destDir == source || destDir.hasPrefix(source + "/") {
                return false
            }
            return true
        }
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

    /// Move only when the copy is not forced, every endpoint is local,
    /// and every source shares the destination volume.
    static func shouldMove(
        sources: [String], destDir: String, forceCopy: Bool
    ) -> Bool {
        guard !forceCopy, OrkaPath.isLocal(destDir),
            sources.allSatisfy(OrkaPath.isLocal)
        else { return false }
        return sources.allSatisfy { sameVolume($0, destDir) }
    }

    /// Hover proposal: move when the destination is local, every
    /// provider vends a file URL, and the Option key is up.
    @MainActor
    static func proposedOperation(
        providers: [NSItemProvider], destDir: String
    ) -> DropOperation {
        let allLocal = providers.allSatisfy {
            $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
        }
        return OrkaPath.isLocal(destDir) && allLocal
            && !NSEvent.modifierFlags.contains(.option) ? .move : .copy
    }
}
