import AppKit
import UniformTypeIdentifiers

/// Caches for per-row display data. Both caches are main-thread only.
@MainActor
enum FileKindCache {
    private static let icons = NSCache<NSString, NSImage>()
    private static var kinds: [String: String] = [:]

    static func icon(forPath path: String, size: CGFloat = 16) -> NSImage {
        let key = "\(Int(size)):\(path)" as NSString
        if let cached = icons.object(forKey: key) {
            return cached
        }
        let icon = NSWorkspace.shared.icon(forFile: path)
        icon.size = NSSize(width: size, height: size)
        icons.setObject(icon, forKey: key)
        return icon
    }

    static func kind(for entry: FsEntry) -> String {
        if entry.path.hasSuffix(".app") { return "Application" }
        if entry.isDir { return "Folder" }
        let ext = (entry.name as NSString).pathExtension.lowercased()
        if ext.isEmpty { return "Document" }
        if let cached = kinds[ext] { return cached }
        let kind = UTType(filenameExtension: ext)?.localizedDescription
            ?? "\(ext.uppercased()) File"
        kinds[ext] = kind
        return kind
    }
}
