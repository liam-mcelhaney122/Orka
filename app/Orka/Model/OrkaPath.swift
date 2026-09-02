import Foundation

/// Classifies a path string as local or remote, and derives display and
/// navigation helpers for both kinds. Mirrors `orka_core::vfs::VPath`:
/// a string starting with "/" or "~" is local; everything else is parsed
/// as a "scheme://connection/path" remote URI.
enum OrkaPath {
    static func isLocal(_ path: String) -> Bool {
        path.hasPrefix("/") || path.hasPrefix("~")
    }

    /// A short name for a tab title, window title, or breadcrumb root.
    /// A local path uses its last path component. A remote URI uses its
    /// last path component too, or the connection id at the URI root.
    static func displayName(_ path: String) -> String {
        guard !isLocal(path) else {
            return URL(fileURLWithPath: path).lastPathComponent
        }
        guard let split = splitRemote(path) else { return path }
        let trimmed = split.path.trimmingCharacters(in: slashes)
        return trimmed.isEmpty
            ? split.connection : (trimmed as NSString).lastPathComponent
    }

    /// Splits a remote URI into its connection id and remote-side path.
    /// The path keeps its leading slash, or is empty at the URI root.
    /// Nil when `path` does not parse as "scheme://connection/...".
    static func splitRemote(_ path: String) -> (connection: String, path: String)? {
        guard !isLocal(path), let schemeEnd = path.range(of: "://")
        else { return nil }
        let rest = path[schemeEnd.upperBound...]
        guard let slash = rest.firstIndex(of: "/") else {
            return (String(rest), "")
        }
        return (String(rest[..<slash]), String(rest[slash...]))
    }

    /// The "scheme://connection" prefix of a remote URI, with no path
    /// component. This is both the breadcrumb root segment and the
    /// floor `goUp` never crosses. Nil when `path` is local.
    static func remoteRoot(_ path: String) -> String? {
        guard let schemeEnd = path.range(of: "://") else { return nil }
        let afterScheme = path[schemeEnd.upperBound...]
        let end = afterScheme.firstIndex(of: "/") ?? afterScheme.endIndex
        return String(path[..<end])
    }

    /// The parent of a remote URI, one path component up. Stops at
    /// `remoteRoot`; never returns a path above it. Nil when `path` is
    /// local or already at its root.
    static func remoteParent(of path: String) -> String? {
        guard let root = remoteRoot(path) else { return nil }
        let remainder = path.dropFirst(root.count)
        guard !remainder.isEmpty, remainder != "/" else { return nil }
        let trimmed = remainder.hasSuffix("/")
            ? remainder.dropLast() : remainder[...]
        guard let lastSlash = trimmed.lastIndex(of: "/") else { return root }
        let parentPath = trimmed[..<lastSlash]
        return parentPath.isEmpty ? root : root + parentPath
    }

    /// True when both remote URIs name the same connection. A remote
    /// path has no volume to compare the way two local paths do, so this
    /// is the closest equivalent for deciding whether a remote-to-remote
    /// drag can move instead of copy. False when either path is local.
    static func sameConnection(_ a: String, _ b: String) -> Bool {
        guard let ca = splitRemote(a)?.connection,
            let cb = splitRemote(b)?.connection
        else { return false }
        return ca == cb
    }

    private static let slashes = CharacterSet(charactersIn: "/")
}
