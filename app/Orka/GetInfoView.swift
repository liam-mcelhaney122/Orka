import SwiftUI
import UniformTypeIdentifiers

/// Get Info sheet (Cmd+I). Reads metadata directly from the URL; the
/// folder size comes from the engine's recursive walk and streams into
/// `AppModel.folderSizes`, so the sheet reads it back from that cache.
struct GetInfoView: View {
    let path: String

    @Environment(\.dismiss) private var dismiss
    private var model: AppModel { AppModel.shared }

    @State private var details: Details

    init(path: String) {
        self.path = path
        if OrkaPath.isLocal(path) {
            _details = State(initialValue: Details(localPath: path))
        } else {
            // `Details` has no access to app state; the lookup happens
            // here and the result is handed in. `focusedPane` is nil
            // when no window has focus; the entry lookup then fails and
            // `Details` falls back to path-derived metadata until the
            // `stat_path` task below fills in the real size and date.
            let entry = AppModel.shared.focusedPane?.directory.entries
                .first { $0.path == path }
            _details = State(initialValue: Details(remotePath: path, entry: entry))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            rows
            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
                    .help("Close the Info window")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(width: 380)
        .task(id: path) {
            guard details.isDir else { return }
            model.requestFolderSize(path: path)
        }
        .task(id: path) {
            // A local stat already ran synchronously in `Details.init`;
            // only a remote path needs the round trip.
            guard !details.isLocal else { return }
            await refreshRemoteStat()
        }
    }

    /// Runs `stat_path` off the main thread and folds the authoritative
    /// size and modified time into `details`. Owner, permissions, and
    /// created stay nil: there is no local stat to source them from.
    private func refreshRemoteStat() async {
        let engine = model.engine
        let target = path
        let stat = await Task.detached(priority: .userInitiated) {
            try? engine.statPath(path: target)
        }.value
        // The view can close during the round trip; its state is gone.
        guard let stat, !Task.isCancelled else { return }
        details.applyRemoteStat(stat)
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(nsImage: details.icon)
                .resizable()
                .frame(width: 48, height: 48)
            VStack(alignment: .leading, spacing: 2) {
                Text(details.name)
                    .font(.headline)
                    .lineLimit(2)
                Text(details.kind)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(16)
    }

    private var rows: some View {
        Grid(alignment: .leadingFirstTextBaseline,
             horizontalSpacing: 12, verticalSpacing: 7) {
            row("Size", sizeText)
            row("Where", details.parent)
            if let created = details.created {
                row("Created", Self.dateFormatter.string(from: created))
            } else if !details.isLocal {
                row("Created", Self.remoteUnavailableCaption)
            }
            if let modified = details.modified {
                row("Modified", Self.dateFormatter.string(from: modified))
            }
            if let target = details.symlinkTarget {
                row("Original", target)
            }
            if let owner = details.owner {
                row("Owner", owner)
            } else if !details.isLocal {
                row("Owner", Self.remoteUnavailableCaption)
            }
            if let permissions = details.permissions {
                row("Permissions", permissions)
            } else if !details.isLocal {
                row("Permissions", Self.remoteUnavailableCaption)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .textSelection(.enabled)
                .lineLimit(3)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.callout)
    }

    private var sizeText: String {
        if details.isDir {
            guard let total = model.folderSizes.sizes[path] else {
                return "Calculating…"
            }
            let bytes = ByteCountFormatter.string(
                fromByteCount: Int64(total.bytes), countStyle: .file)
            return bytes + " for \(total.items) items"
        }
        guard let size = details.fileSize else { return "—" }
        return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
    }

    private static let remoteUnavailableCaption =
        "Not available for remote locations"

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}

/// Metadata snapshot taken when the sheet opens. A local path reads it
/// from disk; a remote path has no disk to read, so it reads the
/// `FsEntry` already fetched for the directory listing instead. `owner`
/// and `permissions` stay nil for remote paths — there is no local
/// stat to source them from — and the view skips those rows.
private struct Details {
    let name: String
    let kind: String
    let parent: String
    let owner: String?
    let permissions: String?
    let created: Date?
    var modified: Date?
    let isDir: Bool
    let isLocal: Bool
    var fileSize: Int64?
    let symlinkTarget: String?
    let icon: NSImage

    init(localPath path: String) {
        let url = URL(fileURLWithPath: path)
        let keys: Set<URLResourceKey> = [
            .localizedTypeDescriptionKey, .isDirectoryKey, .fileSizeKey,
            .creationDateKey, .contentModificationDateKey, .isSymbolicLinkKey,
        ]
        let values = try? url.resourceValues(forKeys: keys)
        let attributes =
            (try? FileManager.default.attributesOfItem(atPath: path)) ?? [:]

        name = url.lastPathComponent
        kind = values?.localizedTypeDescription ?? "Unknown"
        parent = url.deletingLastPathComponent().path
        owner = attributes[.ownerAccountName] as? String
        created = values?.creationDate
        modified = values?.contentModificationDate
        isDir = values?.isDirectory ?? false
        isLocal = true
        fileSize = (values?.fileSize).map(Int64.init)
        icon = NSWorkspace.shared.icon(forFile: path)
        if values?.isSymbolicLink == true {
            symlinkTarget = try? FileManager.default
                .destinationOfSymbolicLink(atPath: path)
        } else {
            symlinkTarget = nil
        }
        permissions = (attributes[.posixPermissions] as? Int)
            .map(Self.describe(posix:))
    }

    /// `entry` is nil when the path names the folder currently browsed
    /// rather than one of its children — it never appears in its own
    /// listing. That leaves only the name and folder kind to show.
    init(remotePath path: String, entry: FsEntry?) {
        let entryName = entry?.name ?? OrkaPath.displayName(path)
        name = entryName
        isDir = entry?.isDir ?? true
        if isDir {
            kind = "Folder"
        } else {
            let ext = (entryName as NSString).pathExtension.lowercased()
            kind = ext.isEmpty
                ? "Document"
                : (UTType(filenameExtension: ext)?.localizedDescription
                    ?? "\(ext.uppercased()) File")
        }
        parent = OrkaPath.remoteParent(of: path) ?? path
        owner = nil
        permissions = nil
        created = nil
        modified = (entry?.modifiedMs).flatMap {
            $0 > 0 ? Date(timeIntervalSince1970: Double($0) / 1000) : nil
        }
        isLocal = false
        fileSize = entry.map { Int64($0.size) }
        symlinkTarget = nil
        if isDir {
            icon = NSWorkspace.shared.icon(for: .folder)
        } else {
            let ext = (entryName as NSString).pathExtension
            let type = ext.isEmpty ? nil : UTType(filenameExtension: ext)
            icon = NSWorkspace.shared.icon(for: type ?? .data)
        }
    }

    /// Folds in the authoritative size and modified time from a
    /// `stat_path` call, once it returns. Owner, permissions, and created
    /// are not part of `FsEntry`, so they stay nil for a remote path.
    mutating func applyRemoteStat(_ stat: FsEntry) {
        fileSize = Int64(stat.size)
        modified = stat.modifiedMs > 0
            ? Date(timeIntervalSince1970: Double(stat.modifiedMs) / 1000) : nil
    }

    private static func describe(posix: Int) -> String {
        let symbols = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]
        let user = symbols[(posix >> 6) & 7]
        let group = symbols[(posix >> 3) & 7]
        let other = symbols[posix & 7]
        return "\(user)\(group)\(other)  (\(String(posix, radix: 8)))"
    }
}
