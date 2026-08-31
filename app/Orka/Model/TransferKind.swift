import Foundation

/// What one transfer job represents, for the Transfers panel. Derived
/// from source and destination locality, not sent by the engine: the
/// engine only knows move or copy, not which side is remote.
enum TransferKind: Equatable {
    case upload
    case download
    case copy
    case move

    /// Classifies a transfer from its sources and destination. Local
    /// sources with a remote destination upload; remote sources with a
    /// local destination download; an all-local transfer copies or
    /// moves, per `move`. A remote-to-remote transfer never reaches
    /// this: the app has no remote-to-remote path.
    static func derive(
        sources: [String], destDir: String, move: Bool
    ) -> TransferKind {
        let sourcesLocal = sources.allSatisfy(OrkaPath.isLocal)
        let destLocal = OrkaPath.isLocal(destDir)
        if sourcesLocal && !destLocal {
            return .upload
        }
        if !sourcesLocal && destLocal {
            return .download
        }
        return move ? .move : .copy
    }
}
