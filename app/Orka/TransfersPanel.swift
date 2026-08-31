import SwiftUI

/// Pop-out window listing every transfer job: active and recently
/// finished. Mirrors the status bar summary at a glance.
struct TransfersPanel: View {
    @Bindable var model: AppModel

    @Environment(\.dismiss) private var dismiss

    /// Scene id for the pop-out window. Shared with OrkaApp.
    static let windowID = "transfers-window"

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            List {
                Section("Active") {
                    ForEach(model.transfers.active) { record in
                        TransferRowView(model: model, record: record)
                    }
                }
                Section("Finished") {
                    ForEach(model.transfers.finished) { record in
                        TransferRowView(model: model, record: record)
                    }
                }
            }
        }
        .frame(minWidth: 480, minHeight: 320)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("Transfers")
                .fontWeight(.medium)
            Spacer()
            Button("Clear Finished") {
                model.transfers.clearFinished()
            }
            .disabled(model.transfers.finished.isEmpty)
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
            }
            .help("Close")
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

/// One row: an icon for the transfer kind, a name and state line, a
/// progress line, and a cancel button while the job is not terminal.
private struct TransferRowView: View {
    @Bindable var model: AppModel
    var record: TransferRecord

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: kindIcon)
                .foregroundStyle(.secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(record.displayName)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    stateTag
                }
                if let detail = detailLine {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                if let progressFraction {
                    ProgressView(value: progressFraction)
                } else if isPreparingOrRunning {
                    ProgressView()
                }
                if record.state == .failed, let firstError = record.errors.first {
                    Text(firstError.message)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .lineLimit(1)
                    if record.errors.count > 1 {
                        DisclosureGroup("\(record.errors.count - 1) more") {
                            // Index identity; several errors can share
                            // one path.
                            ForEach(
                                Array(record.errors.enumerated()).dropFirst(),
                                id: \.offset
                            ) { _, error in
                                Text(error.message)
                                    .font(.caption)
                                    .foregroundStyle(.red)
                            }
                        }
                        .font(.caption)
                    }
                }
            }
            Spacer()
            if !isTerminal {
                Button {
                    model.cancelJob(record.id)
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.plain)
                .help("Cancel")
            }
        }
        .padding(.vertical, 2)
    }

    private var kindIcon: String {
        switch record.kind {
        case .upload: return "arrow.up.circle"
        case .download: return "arrow.down.circle"
        case .copy: return "doc.on.doc"
        case .move: return "folder"
        }
    }

    private var isTerminal: Bool {
        switch record.state {
        case .done, .failed, .cancelled: return true
        case .queued, .preparing, .running: return false
        }
    }

    private var isPreparingOrRunning: Bool {
        switch record.state {
        case .preparing, .running: return true
        case .queued, .done, .failed, .cancelled: return false
        }
    }

    @ViewBuilder
    private var stateTag: some View {
        switch record.state {
        case .queued:
            Text("Waiting").font(.caption).foregroundStyle(.secondary)
        case .preparing:
            Text("Preparing…").font(.caption).foregroundStyle(.secondary)
        case .running:
            EmptyView()
        case .done:
            Image(systemName: "checkmark").foregroundStyle(.secondary)
        case .failed:
            Text("Failed").font(.caption).foregroundStyle(.red)
        case .cancelled:
            Text("Cancelled").font(.caption).foregroundStyle(.secondary)
        }
    }

    /// Fraction for a determinate progress bar. Only the running state
    /// carries live totals; preparing shows an indeterminate spinner.
    private var progressFraction: Double? {
        guard record.state == .running else { return nil }
        if record.bytesTotal > 0 {
            return Double(record.bytesDone) / Double(record.bytesTotal)
        }
        if record.itemsTotal > 0 {
            return Double(record.itemsDone) / Double(record.itemsTotal)
        }
        return nil
    }

    /// The destination while queued or finished; live byte or item
    /// counts while running. A large remote tree past the engine scan
    /// cap reports no byte total, so the count falls back to items;
    /// with neither total, the line is blank rather than stale.
    private var detailLine: String? {
        guard record.state == .running else { return record.destinationLabel }
        if record.bytesTotal > 0 {
            let formatter = ByteCountFormatter()
            let done = formatter.string(fromByteCount: Int64(record.bytesDone))
            let total = formatter.string(fromByteCount: Int64(record.bytesTotal))
            var text = "\(done) of \(total)"
            if let rate = record.bytesPerSecond {
                text += " - \(formatter.string(fromByteCount: Int64(rate)))/s"
            }
            return text
        }
        if record.itemsTotal > 0 {
            return "\(record.itemsDone) of \(record.itemsTotal) items"
        }
        return nil
    }
}
