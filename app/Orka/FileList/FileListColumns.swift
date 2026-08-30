import AppKit

/// Static description of one file-list column.
struct FileColumnSpec {
    let id: String
    let title: String
    let width: CGFloat
    let minWidth: CGFloat
    /// Data columns get a cap so window autoresizing cannot stretch
    /// one of them across the whole window; Name absorbs extra width.
    var maxWidth: CGFloat = 400
    var rightAligned = false
    /// The user can show or hide the column from the header menu.
    /// Name stays always visible; Path follows deep-search state.
    var toggleable = true
    var defaultVisible = false
}

/// The column catalog plus the persisted set of visible columns.
@MainActor
enum FileListColumns {
    static let specs: [FileColumnSpec] = [
        FileColumnSpec(
            id: "name", title: "Name", width: 320, minWidth: 160,
            maxWidth: 100_000, toggleable: false, defaultVisible: true),
        FileColumnSpec(
            id: "modified", title: "Date Modified", width: 160, minWidth: 100,
            maxWidth: 240, defaultVisible: true),
        FileColumnSpec(
            id: "created", title: "Date Created", width: 160, minWidth: 100,
            maxWidth: 240),
        FileColumnSpec(
            id: "added", title: "Date Added", width: 160, minWidth: 100,
            maxWidth: 240),
        FileColumnSpec(
            id: "kind", title: "Kind", width: 150, minWidth: 80,
            defaultVisible: true),
        FileColumnSpec(
            id: "extension", title: "Extension", width: 90, minWidth: 60,
            maxWidth: 160),
        FileColumnSpec(
            id: "size", title: "Size", width: 90, minWidth: 60,
            maxWidth: 160, rightAligned: true, defaultVisible: true),
        FileColumnSpec(
            id: "owner", title: "Owner", width: 110, minWidth: 70,
            maxWidth: 240),
        FileColumnSpec(
            id: "permissions", title: "Permissions", width: 130, minWidth: 90,
            maxWidth: 200),
        FileColumnSpec(
            id: "path", title: "Path", width: 260, minWidth: 120,
            maxWidth: 2000, toggleable: false),
    ]

    private static let defaultsKey = "FileListVisibleColumns"

    /// Ids of the columns the user chose to show. The default set
    /// applies until the first toggle.
    static func visibleIds() -> Set<String> {
        if let saved = UserDefaults.standard.stringArray(forKey: defaultsKey) {
            return Set(saved)
        }
        return Set(specs.filter(\.defaultVisible).map(\.id))
    }

    static func setVisible(_ id: String, _ visible: Bool) {
        var ids = visibleIds()
        if visible { ids.insert(id) } else { ids.remove(id) }
        UserDefaults.standard.set(ids.sorted(), forKey: defaultsKey)
    }
}

/// Metadata for the optional columns that FsEntry does not carry.
/// A local entry reads it from disk on first use. A remote entry has
/// no local stat, so every field stays nil and the cells show "—".
final class FileMetadata {
    let created: Date?
    let added: Date?
    let owner: String?
    let permissions: String?

    init(entry: FsEntry) {
        guard OrkaPath.isLocal(entry.path) else {
            created = nil
            added = nil
            owner = nil
            permissions = nil
            return
        }
        let url = URL(fileURLWithPath: entry.path)
        let values = try? url.resourceValues(
            forKeys: [.creationDateKey, .addedToDirectoryDateKey])
        created = values?.creationDate
        added = values?.addedToDirectoryDate
        let attributes =
            (try? FileManager.default.attributesOfItem(atPath: entry.path))
            ?? [:]
        owner = attributes[.ownerAccountName] as? String
        permissions = (attributes[.posixPermissions] as? Int)
            .map(Self.describe(posix:))
    }

    private static func describe(posix: Int) -> String {
        let symbols = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]
        return symbols[(posix >> 6) & 7] + symbols[(posix >> 3) & 7]
            + symbols[posix & 7]
    }
}

/// Cache for `FileMetadata`, keyed by path and modification time so a
/// changed file re-stats on the next listing.
@MainActor
enum FileMetadataCache {
    private static let cache = NSCache<NSString, FileMetadata>()

    static func metadata(for entry: FsEntry) -> FileMetadata {
        let key = "\(entry.modifiedMs)|\(entry.path)" as NSString
        if let hit = cache.object(forKey: key) { return hit }
        let value = FileMetadata(entry: entry)
        cache.setObject(value, forKey: key)
        return value
    }
}
