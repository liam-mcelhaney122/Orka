import SwiftUI

struct StatusBarView: View {
    @Bindable var model: AppModel
    var window: WindowState
    @State private var freeSpace: String = ""
    @Environment(\.openWindow) private var openWindow

    private var directory: DirectoryModel { window.activePane.directory }

    var body: some View {
        HStack(spacing: 12) {
            leftText
            Spacer()
            if model.transfers.activeCount > 0 {
                transfersSummary
            } else if let job = model.activeJobs.first(where: {
                model.transfers.record(for: $0.key) == nil
            })?.value {
                // Archive, trash, and Quick Look jobs never register with
                // the transfer manager, so they keep this strip.
                jobView(job)
            } else if OrkaPath.isLocal(directory.path) {
                if !freeSpace.isEmpty || paneFolderSize != nil {
                    HStack(spacing: 8) {
                        if let paneFolderSize {
                            Text(paneFolderSize)
                                .foregroundStyle(.secondary)
                                .help("Folder size")
                        }
                        if !freeSpace.isEmpty {
                            Text("\(freeSpace) available")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } else if let connection = OrkaPath.splitRemote(directory.path)?.connection {
                Text(connection).foregroundStyle(.secondary)
            }
        }
        .font(.caption)
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .frame(height: 24)
        .onChange(of: directory.path, initial: true) { updateFreeSpace() }
    }

    /// Recursive total of the pane directory, while the engine computes
    /// it. Reading `folderSizes.sizes` here keeps the label live as the
    /// result streams in.
    private var paneFolderSize: String? {
        guard let total = model.folderSizes.sizes[directory.path]
        else { return nil }
        return ByteCountFormatter.string(
            fromByteCount: Int64(total.bytes), countStyle: .file)
    }

    @ViewBuilder
    private var leftText: some View {
        HStack(spacing: 6) {
            if directory.gitStatus != nil && !window.isSearching {
                branchSegment
                Text("•").foregroundStyle(.secondary)
            }
            statusText
        }
    }

    /// Branch name, or the short commit hash on a detached HEAD.
    private var branchSegment: some View {
        HStack(spacing: 4) {
            Image(systemName: "arrow.triangle.branch")
            Text(branchLabel)
        }
        .foregroundStyle(.secondary)
    }

    private var branchLabel: String {
        guard let status = directory.gitStatus else { return "" }
        return status.branch ?? status.headShort
    }

    @ViewBuilder
    private var statusText: some View {
        if let error = model.connectionError {
            HStack(spacing: 6) {
                Text(error)
                    .foregroundStyle(.red)
                    .lineLimit(1)
                Button("Dismiss") { model.connectionError = nil }
                    .buttonStyle(.link)
                    .font(.caption)
                    .help("Dismiss this error")
            }
        } else if let error = model.lastJobErrors.first {
            HStack(spacing: 6) {
                Text(error.message)
                    .foregroundStyle(.red)
                    .lineLimit(1)
                Button("Dismiss") { model.lastJobErrors = [] }
                    .buttonStyle(.link)
                    .font(.caption)
                    .help("Dismiss this error")
            }
        } else if let error = directory.errorMessage {
            Text(error).foregroundStyle(.red)
        } else if window.isSearching {
            Text("Searching…").foregroundStyle(.secondary)
        } else if let results = directory.searchResults {
            Text("\(results.count) results")
        } else if directory.selection.isEmpty {
            Text("\(directory.entries.count) items")
        } else {
            Text("\(directory.selection.count) of \(directory.entries.count) selected\(selectionSize)")
        }
    }

    /// Aggregate summary for every upload, download, copy, and move the
    /// transfer manager tracks. Opens the Transfers window on click.
    private var transfersSummary: some View {
        Button {
            openWindow(id: TransfersPanel.windowID)
        } label: {
            HStack(spacing: 6) {
                let count = model.transfers.activeCount
                Text(count == 1 ? "1 transfer" : "\(count) transfers")
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if let fraction = model.transfers.aggregateFraction {
                    ProgressView(value: fraction)
                        .frame(width: 120)
                } else {
                    // Linear style; the default circular spinner clips
                    // inside the 24 pt status bar.
                    ProgressView()
                        .progressViewStyle(.linear)
                        .frame(width: 120)
                }
            }
        }
        .buttonStyle(.borderless)
        .help("Show Transfers")
    }

    private func jobView(_ job: JobProgress) -> some View {
        HStack(spacing: 6) {
            Text(jobLabel(job))
                .foregroundStyle(.secondary)
                .lineLimit(1)
            ProgressView(value: fraction(job))
                .frame(width: 120)
            Button {
                model.cancelJob(job.jobId)
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.plain)
            .help("Cancel")
        }
    }

    private func jobLabel(_ job: JobProgress) -> String {
        switch job.state {
        case .preparing: return "Preparing…"
        default:
            return "\(job.itemsDone) of \(job.itemsTotal)"
        }
    }

    private func fraction(_ job: JobProgress) -> Double {
        if job.bytesTotal > 0 {
            return Double(job.bytesDone) / Double(job.bytesTotal)
        }
        if job.itemsTotal > 0 {
            return Double(job.itemsDone) / Double(job.itemsTotal)
        }
        return 0
    }

    private var selectionSize: String {
        let selected = directory.entries.filter {
            directory.selection.contains($0.path) && !$0.isDir
        }
        let total = selected.reduce(Int64(0)) { $0 + Int64($1.size) }
        guard total > 0 else { return "" }
        return " — " + ByteCountFormatter.string(
            fromByteCount: total, countStyle: .file)
    }

    private func updateFreeSpace() {
        guard OrkaPath.isLocal(directory.path) else {
            // Free space is a local volume statistic; a remote listing
            // has no equivalent, so the connection id shows instead.
            freeSpace = ""
            return
        }
        let url = URL(fileURLWithPath: directory.path)
        let values = try? url.resourceValues(
            forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        if let capacity = values?.volumeAvailableCapacityForImportantUsage {
            freeSpace = ByteCountFormatter.string(
                fromByteCount: capacity, countStyle: .file)
        } else {
            freeSpace = ""
        }
    }
}
