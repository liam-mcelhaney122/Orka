import Foundation
import Observation

/// One transfer job's state, as shown in the Transfers panel.
struct TransferRecord: Identifiable {
    let id: UInt64
    let kind: TransferKind
    /// Last path component of a single source, else "N items".
    let displayName: String
    /// "connection: /path" for a remote destination, else the local
    /// destination folder's name.
    let destinationLabel: String
    var state: JobState
    var bytesDone: UInt64
    var bytesTotal: UInt64
    var itemsDone: UInt64
    var itemsTotal: UInt64
    var currentPath: String
    var errors: [JobItemError]
    var bytesPerSecond: Double?
    var finishedAt: Date?
}

/// Tracks every transfer job started by the app, for the Transfers
/// panel. Registers a job when it starts, then applies the engine's
/// progress and completion events by job id.
@MainActor
@Observable
final class TransferManager {
    /// Active records, insertion order.
    private(set) var active: [TransferRecord] = []
    /// Finished records, newest first, capped at 50, session-only.
    private(set) var finished: [TransferRecord] = []

    /// Last progress sample per job, for the bytes-per-second estimate.
    /// A sample only refreshes once a second so the rate does not jitter
    /// on every progress event.
    private var rateSamples: [UInt64: (time: Date, bytesDone: UInt64)] = [:]

    /// Maps a connection id to its display name for destination labels.
    /// AppModel installs a resolver backed by the connection store; the
    /// default keeps the raw id.
    var connectionName: (String) -> String = { $0 }

    private static let finishedCap = 50
    private static let rateInterval: TimeInterval = 1.0

    /// Starts tracking a new job, queued until its first progress event.
    func register(
        jobId: UInt64, sources: [String], destDir: String, move: Bool
    ) {
        let kind = TransferKind.derive(
            sources: sources, destDir: destDir, move: move)
        let displayName = sources.count == 1
            ? OrkaPath.displayName(sources[0])
            : "\(sources.count) items"
        let destinationLabel: String
        if let remote = OrkaPath.splitRemote(destDir) {
            let name = connectionName(remote.connection)
            destinationLabel = remote.path.isEmpty || remote.path == "/"
                ? name
                : "\(name): \(remote.path)"
        } else {
            destinationLabel = (destDir as NSString).lastPathComponent
        }
        let record = TransferRecord(
            id: jobId,
            kind: kind,
            displayName: displayName,
            destinationLabel: destinationLabel,
            state: .queued,
            bytesDone: 0,
            bytesTotal: 0,
            itemsDone: 0,
            itemsTotal: 0,
            currentPath: "",
            errors: [],
            bytesPerSecond: nil,
            finishedAt: nil)
        active.append(record)
    }

    /// Applies one progress event. Returns false when `progress.jobId`
    /// is not a known active record. A record already in a terminal
    /// state ignores further progress: a main-actor hop from a parallel
    /// worker thread can reorder a late `JobProgress` after the
    /// `JobFinished` it followed on the engine side.
    @discardableResult
    func applyProgress(_ progress: JobProgress) -> Bool {
        guard let index = active.firstIndex(where: { $0.id == progress.jobId })
        else { return false }
        guard !active[index].state.isTerminal else { return true }
        active[index].state = progress.state
        active[index].bytesDone = progress.bytesDone
        active[index].bytesTotal = progress.bytesTotal
        active[index].itemsDone = progress.itemsDone
        active[index].itemsTotal = progress.itemsTotal
        active[index].currentPath = progress.currentPath
        if let newRate = rate(jobId: progress.jobId, bytesDone: progress.bytesDone) {
            active[index].bytesPerSecond = newRate
        }
        return true
    }

    /// Bytes per second since the last sample, or nil when less than a
    /// second has passed or bytes have not grown. Always refreshes the
    /// stored sample when bytes grew, so the next call measures from
    /// this point.
    private func rate(jobId: UInt64, bytesDone: UInt64) -> Double? {
        let now = Date()
        guard let previous = rateSamples[jobId] else {
            rateSamples[jobId] = (now, bytesDone)
            return nil
        }
        guard bytesDone > previous.bytesDone else { return nil }
        let elapsed = now.timeIntervalSince(previous.time)
        guard elapsed >= Self.rateInterval else { return nil }
        rateSamples[jobId] = (now, bytesDone)
        return Double(bytesDone - previous.bytesDone) / elapsed
    }

    /// Moves a job to `finished` with its terminal state and errors.
    /// Returns whether the job was known; an unknown id is a no-op so
    /// its errors stay the caller's responsibility.
    @discardableResult
    func applyFinished(
        jobId: UInt64, state: JobState, errors: [JobItemError]
    ) -> Bool {
        guard let index = active.firstIndex(where: { $0.id == jobId })
        else { return false }
        var record = active.remove(at: index)
        record.state = state
        record.errors = errors
        record.finishedAt = Date()
        rateSamples[jobId] = nil
        finished.insert(record, at: 0)
        if finished.count > Self.finishedCap {
            finished.removeLast(finished.count - Self.finishedCap)
        }
        return true
    }

    func record(for jobId: UInt64) -> TransferRecord? {
        active.first { $0.id == jobId } ?? finished.first { $0.id == jobId }
    }

    func clearFinished() {
        finished.removeAll()
    }

    var activeCount: Int { active.count }

    /// Combined progress fraction across every active record that has a
    /// known byte total. Nil when none do, so the caller can hide an
    /// indeterminate aggregate instead of showing a false zero.
    var aggregateFraction: Double? {
        let withTotals = active.filter { $0.bytesTotal > 0 }
        guard !withTotals.isEmpty else { return nil }
        let done = withTotals.reduce(UInt64(0)) { $0 + $1.bytesDone }
        let total = withTotals.reduce(UInt64(0)) { $0 + $1.bytesTotal }
        return total > 0 ? Double(done) / Double(total) : nil
    }
}

extension JobState {
    /// True once the engine will not report further progress for this job.
    fileprivate var isTerminal: Bool {
        switch self {
        case .done, .failed, .cancelled: return true
        case .queued, .preparing, .running: return false
        }
    }
}
