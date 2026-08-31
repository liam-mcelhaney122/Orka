import Foundation

/// Stages one remote item in a unique temporary directory through an
/// engine copy job. Both drag-out paths use it: the file-list promise
/// delegate and the icon-grid item provider. A unique directory per
/// download keeps concurrent same-named promises apart.
enum RemotePromiseStager {
    private static let directoryPrefix = "orka-promise-"

    /// Downloads `remotePath` into a fresh staging directory. On
    /// success, `completion` receives the staged file URL. The caller
    /// decides when to call `removeStagingDirectory`.
    @MainActor
    static func download(
        remotePath: String,
        model: AppModel,
        completion: @escaping @MainActor (Result<URL, any Error>) -> Void
    ) {
        let name = (remotePath as NSString).lastPathComponent
        let stagingDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                directoryPrefix + UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: stagingDir, withIntermediateDirectories: true)
        } catch {
            completion(.failure(error))
            return
        }
        let jobId = model.engine.copyItems(
            sources: [remotePath], destDir: stagingDir.path)
        model.onJobFinished(jobId: jobId) { state in
            guard state == .done else {
                try? FileManager.default.removeItem(at: stagingDir)
                completion(.failure(OrkaError.Io(
                    message: "Download of \(name) failed")))
                return
            }
            completion(.success(stagingDir.appendingPathComponent(name)))
        }
    }

    /// Removes the staging directory that holds `stagedFile`.
    static func removeStagingDirectory(for stagedFile: URL) {
        try? FileManager.default.removeItem(
            at: stagedFile.deletingLastPathComponent())
    }

    /// Deletes leftover staging directories from earlier runs. The icon
    /// grid cannot remove its directory at hand-off time, and a crash
    /// can strand one, so the app sweeps at launch.
    static func sweepStaleStagingDirectories() {
        Task.detached(priority: .background) {
            let tempDir = FileManager.default.temporaryDirectory
            let entries = (try? FileManager.default.contentsOfDirectory(
                at: tempDir, includingPropertiesForKeys: nil)) ?? []
            for entry in entries
            where entry.lastPathComponent.hasPrefix(directoryPrefix) {
                try? FileManager.default.removeItem(at: entry)
            }
        }
    }
}
