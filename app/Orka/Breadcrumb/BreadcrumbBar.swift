import SwiftUI

/// Explorer-style clickable path bar. Cmd+L or a click on the bar
/// background switches to an editable text path.
struct BreadcrumbBar: View {
    @Bindable var model: AppModel
    var window: WindowState
    @State private var editedPath = ""
    @FocusState private var pathFieldFocused: Bool

    var body: some View {
        Group {
            if window.isEditingPath {
                pathField
            } else {
                crumbs
            }
        }
        .frame(height: 30)
        .onChange(of: window.isEditingPath) {
            if window.isEditingPath {
                editedPath = window.activePane.directory.path
                pathFieldFocused = true
            }
        }
        .onChange(of: pathFieldFocused) {
            // Focus lost without a submit or an Escape means the user
            // clicked elsewhere; leave edit mode so the crumbs come
            // back instead of leaving an orphaned text field.
            if !pathFieldFocused, window.isEditingPath {
                window.isEditingPath = false
            }
        }
    }

    private var pathField: some View {
        TextField("Path", text: $editedPath)
            .textFieldStyle(.roundedBorder)
            .focused($pathFieldFocused)
            .onKeyPress(.tab) {
                completeTab()
                return .handled
            }
            .onSubmit {
                // expandingTildeInPath also collapses "//" runs, which
                // would corrupt a remote URI's scheme separator; only
                // local input goes through it, and only local input is
                // checked against disk.
                let expanded: String
                if OrkaPath.isLocal(editedPath) {
                    expanded = (editedPath as NSString).expandingTildeInPath
                    var isDir: ObjCBool = false
                    let exists = FileManager.default.fileExists(
                        atPath: expanded, isDirectory: &isDir)
                    guard exists, isDir.boolValue else {
                        NSSound.beep()
                        return
                    }
                } else {
                    // A typed remote URI is trusted to the engine, which
                    // reports a listing error in the pane if it is wrong.
                    expanded = editedPath
                }
                window.isEditingPath = false
                window.navigate(to: expanded)
            }
            .onExitCommand { window.isEditingPath = false }
            .padding(.horizontal, 12)
    }

    private var crumbs: some View {
        // Read the path-derived segments here, during body evaluation.
        // The GeometryReader closure runs during layout, outside
        // observation tracking; a read in there never triggers updates,
        // which left the bar stale after navigation.
        let segs = segments
        // The tap catcher lives inside the scroll content, stretched to
        // at least the viewport size. A catcher behind the ScrollView
        // never fires: the AppKit clip view claims those clicks first.
        return GeometryReader { geo in
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(segs, id: \.path) { segment in
                        Button(segment.name) {
                            window.navigate(to: segment.path)
                        }
                        .buttonStyle(.plain)
                        .help(segment.path)
                        .padding(.horizontal, 4)
                        .padding(.vertical, 2)
                        if segment.path != segs.last?.path {
                            Image(systemName: "chevron.right")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                .padding(.horizontal, 12)
                .frame(
                    minWidth: geo.size.width,
                    minHeight: geo.size.height,
                    alignment: .leading)
                .contentShape(Rectangle())
                .onTapGesture { window.isEditingPath = true }
            }
        }
    }

    private var segments: [(name: String, path: String)] {
        let path = window.activePane.directory.path
        guard OrkaPath.isLocal(path) else { return remoteSegments(path) }
        var result: [(String, String)] = [("Macintosh HD", "/")]
        var accumulated = ""
        for component in path.split(separator: "/") {
            accumulated += "/\(component)"
            result.append((String(component), accumulated))
        }
        return result
    }

    /// "sftp://id/a/b" becomes a "sftp://id" root crumb followed by one
    /// crumb per path component, each navigating to its URI prefix.
    private func remoteSegments(_ path: String) -> [(name: String, path: String)] {
        guard let root = OrkaPath.remoteRoot(path) else { return [(path, path)] }
        var result: [(String, String)] = [(root, root)]
        var accumulated = root
        for component in path.dropFirst(root.count).split(separator: "/") {
            accumulated += "/\(component)"
            result.append((String(component), accumulated))
        }
        return result
    }

    // MARK: Tab completion

    /// Completes the last path component against sibling directory names.
    /// A unique match fills the field and appends "/"; several matches
    /// extend to their longest common prefix; no match beeps.
    private func completeTab() {
        let expanded = (editedPath as NSString).expandingTildeInPath
        let ns = expanded as NSString
        let parent: String
        let typed: String
        if expanded.hasSuffix("/") {
            // Dropping the slash from "/" would leave an empty parent.
            let trimmed = String(expanded.dropLast())
            parent = trimmed.isEmpty ? "/" : trimmed
            typed = ""
        } else {
            let dir = ns.deletingLastPathComponent
            parent = dir.isEmpty ? "/" : dir
            typed = ns.lastPathComponent
        }
        guard let dirs = try? listDirectory(
            path: parent, includeHidden: true, dirsOnly: true)
        else {
            NSSound.beep()
            return
        }
        let matches = dirs.map(\.name).filter {
            $0.lowercased().hasPrefix(typed.lowercased())
        }
        switch matches.count {
        case 0:
            NSSound.beep()
        case 1:
            editedPath = joinedPath(parent, matches[0]) + "/"
        default:
            let common = Self.longestCommonPrefix(matches)
            if common.count > typed.count {
                editedPath = joinedPath(parent, common)
            } else {
                NSSound.beep()
            }
        }
    }

    private func joinedPath(_ parent: String, _ name: String) -> String {
        parent.hasSuffix("/") ? parent + name : parent + "/" + name
    }

    private static func longestCommonPrefix(_ strings: [String]) -> String {
        guard var prefix = strings.first else { return "" }
        for s in strings.dropFirst() {
            while !s.lowercased().hasPrefix(prefix.lowercased()) {
                prefix.removeLast()
                if prefix.isEmpty { return "" }
            }
        }
        return prefix
    }
}
