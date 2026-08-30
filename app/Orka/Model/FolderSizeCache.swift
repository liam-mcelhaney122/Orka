import Foundation
import Observation

/// Cache of recursive folder totals from the engine, keyed by path.
/// The Size column reads from here; the engine streams updates in as
/// `FolderSizes` events arrive.
///
/// Totals also persist to a disk file. On launch the stored totals
/// show immediately, but they do not count as fresh: the engine still
/// recomputes them in the background and the display catches up.
@MainActor
@Observable
final class FolderSizeCache {
    private(set) var sizes: [String: (bytes: UInt64, items: UInt64)] = [:]
    /// Bumped on every change. The details table watches this to know when
    /// to reload its Size column without tracking the dictionary itself.
    private(set) var version = 0
    /// Paths the engine computed in this session. A total loaded from
    /// disk is not in this set, so it still triggers a fresh request
    /// while its old value shows.
    @ObservationIgnored private var freshPaths: Set<String> = []
    @ObservationIgnored private var saveTask: Task<Void, Never>?

    init() {
        loadFromDisk()
    }

    func apply(_ incoming: [PathSize]) {
        guard !incoming.isEmpty else { return }
        for size in incoming {
            sizes[size.path] = (bytes: size.bytes, items: size.items)
            freshPaths.insert(size.path)
        }
        version += 1
        scheduleSave()
    }

    /// True when the engine computed this path in this session. Callers
    /// use this check, not a plain cache hit, to skip a request; a
    /// disk-loaded value alone must not skip, or it would never refresh.
    func isFresh(_ path: String) -> Bool {
        freshPaths.contains(path)
    }

    /// Drops cached totals for `prefix`, everything below it, and every
    /// ancestor. A change inside a directory alters the totals of the
    /// whole chain above it; keeping ancestors would pin stale values,
    /// because requests skip paths that are still fresh.
    func invalidate(underPrefix prefix: String) {
        let slashed = prefix.hasSuffix("/") ? prefix : prefix + "/"
        let before = sizes.count
        let keep = { (path: String) in
            path != prefix
                && !path.hasPrefix(slashed)
                && !slashed.hasPrefix(
                    path.hasSuffix("/") ? path : path + "/")
        }
        sizes = sizes.filter { path, _ in keep(path) }
        freshPaths = freshPaths.filter(keep)
        if sizes.count != before {
            version += 1
            scheduleSave()
        }
    }

    // MARK: Disk persistence

    private struct StoredSize: Codable {
        let bytes: UInt64
        let items: UInt64
    }

    /// Upper bound on persisted entries, so years of browsing do not
    /// grow the file without bound.
    private static let maxStoredEntries = 20_000

    private static var fileURL: URL? {
        FileManager.default
            .urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appendingPathComponent("Orka", isDirectory: true)
            .appendingPathComponent("folder-sizes.json")
    }

    private func loadFromDisk() {
        guard let url = Self.fileURL,
            let data = try? Data(contentsOf: url),
            let stored = try? JSONDecoder().decode(
                [String: StoredSize].self, from: data),
            !stored.isEmpty
        else { return }
        for (path, size) in stored {
            sizes[path] = (bytes: size.bytes, items: size.items)
        }
        version += 1
    }

    /// Coalesces bursts of streamed totals into one write, two seconds
    /// after the last change.
    private func scheduleSave() {
        saveTask?.cancel()
        saveTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            self?.saveToDisk()
        }
    }

    private func saveToDisk() {
        guard let url = Self.fileURL else { return }
        var pairs = sizes.map { ($0.key, $0.value) }
        if pairs.count > Self.maxStoredEntries {
            pairs = Array(pairs.prefix(Self.maxStoredEntries))
        }
        let stored = Dictionary(uniqueKeysWithValues: pairs.map {
            ($0.0, StoredSize(bytes: $0.1.bytes, items: $0.1.items))
        })
        guard let data = try? JSONEncoder().encode(stored) else { return }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        try? data.write(to: url, options: .atomic)
    }
}
