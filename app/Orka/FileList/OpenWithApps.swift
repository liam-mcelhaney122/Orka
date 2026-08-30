import AppKit
import UniformTypeIdentifiers

/// Applications that can open a set of local files, for the
/// "Open With" context menus in the list and grid views.
enum OpenWithApps {
    struct App {
        let url: URL
        let name: String
        let icon: NSImage
        let isDefault: Bool
    }

    /// Applications able to open every path in `paths`. The default
    /// application for the first path sorts first; the rest sort by
    /// name. Returns an empty list when no application opens them all.
    static func apps(for paths: [String]) -> [App] {
        guard let first = paths.first else { return [] }
        let urls = paths.map { URL(fileURLWithPath: $0) }
        var candidates = Set(
            NSWorkspace.shared.urlsForApplications(toOpen: urls[0]))
        for url in urls.dropFirst() {
            candidates.formIntersection(
                NSWorkspace.shared.urlsForApplications(toOpen: url))
        }
        let defaultPath = NSWorkspace.shared
            .urlForApplication(toOpen: URL(fileURLWithPath: first))?
            .standardizedFileURL.path
        let apps = candidates.map { url in
            let icon = NSWorkspace.shared.icon(forFile: url.path)
            icon.size = NSSize(width: 16, height: 16)
            return App(
                url: url,
                name: FileManager.default.displayName(atPath: url.path),
                icon: icon,
                isDefault: url.standardizedFileURL.path == defaultPath)
        }
        return apps.sorted { a, b in
            if a.isDefault != b.isDefault { return a.isDefault }
            return a.name.localizedStandardCompare(b.name)
                == .orderedAscending
        }
    }

    static func open(paths: [String], with appURL: URL) {
        NSWorkspace.shared.open(
            paths.map { URL(fileURLWithPath: $0) },
            withApplicationAt: appURL,
            configuration: NSWorkspace.OpenConfiguration())
    }

    /// "Other…": an application picker rooted at /Applications.
    static func chooseAndOpen(paths: [String]) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.application]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.prompt = "Open"
        panel.message = "Choose an application to open the selection."
        guard panel.runModal() == .OK, let app = panel.url else { return }
        open(paths: paths, with: app)
    }
}
