import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Safari-style tab strip in the window title bar band. Inactive tabs
/// are plain labels with thin separators; the active tab floats as a
/// Liquid Glass capsule on the darker band. Tabs drag like a browser's:
/// within the strip to reorder, onto another window's strip to move,
/// and anywhere else to tear off into a new window.
struct TabBarView: View {
    @Bindable var model: AppModel
    @Bindable var window: WindowState
    @State private var hoveredTabId: UUID?
    /// Tab currently under a file drag, for the drop highlight.
    @State private var dropTargetTabId: UUID?

    /// Drop-side twin of `NSPasteboard.PasteboardType.orkaRemotePath`.
    static let remotePathUTType = UTType(
        exportedAs: "com.orka.remote-path")

    /// Drop-side twin of `NSPasteboard.PasteboardType.orkaTab`.
    static let tabUTType = UTType(exportedAs: "com.orka.tab")

    private let bandHeight: CGFloat = 38
    private let tabHeight: CGFloat = 28
    // Leading inset keeps tabs clear of the traffic lights.
    private let trafficLightInset: CGFloat = 78
    private let maxTabWidth: CGFloat = 220
    private let minTabWidth: CGFloat = 100

    var body: some View {
        // Read observed state during body evaluation. Reads inside the
        // GeometryReader closure run during layout, outside observation
        // tracking, and would leave the strip stale.
        let panes = window.panes
        let activeIndex = window.activePaneIndex
        return GeometryReader { geo in
            let width = tabWidth(bandWidth: geo.size.width, count: panes.count)
            let contentWidth =
                CGFloat(panes.count) * width + plusButtonSpace
            let scrollWidth = max(
                min(contentWidth, geo.size.width - trafficLightInset), 0)
            HStack(spacing: 0) {
                // Drag areas cover only the empty band regions.
                // A band-wide gesture would swallow tab clicks.
                Color.clear
                    .frame(width: trafficLightInset)
                    .contentShape(Rectangle())
                    .windowDragArea()
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 0) {
                        ForEach(
                            Array(panes.enumerated()), id: \.element.id
                        ) { index, pane in
                            HStack(spacing: 0) {
                                separator(
                                    index: index, activeIndex: activeIndex)
                                tab(
                                    index: index, pane: pane, width: width,
                                    isActive: index == activeIndex)
                            }
                        }
                        Button {
                            window.newTab()
                        } label: {
                            Image(systemName: "plus")
                                .font(.system(size: 11, weight: .medium))
                                .padding(7)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)
                        .help("New Tab")
                    }
                    .frame(height: bandHeight)
                }
                .frame(width: scrollWidth)
                Color.clear
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .contentShape(Rectangle())
                    .windowDragArea()
                    // A tab dropped on the empty band lands at the end
                    // of this window's strip.
                    .onDrop(
                        of: [Self.tabUTType],
                        delegate: TabStripEndDropDelegate(window: window))
            }
        }
        .frame(height: bandHeight)
        // The darker band makes the lighter tabs read as raised, the way
        // a browser draws them.
        .background(Color(nsColor: .underPageBackgroundColor))
    }

    private let plusButtonSpace: CGFloat = 30

    /// Tabs shrink from the maximum toward the minimum as the count grows.
    /// Below the minimum the strip scrolls instead.
    private func tabWidth(bandWidth: CGFloat, count: Int) -> CGFloat {
        let available = bandWidth - trafficLightInset - plusButtonSpace
        let fit = available / CGFloat(max(count, 1))
        return min(maxTabWidth, max(minTabWidth, fit))
    }

    /// Glass for the active tab. A pane color tints the glass, the way
    /// Safari tints profile tabs.
    private func activeGlass(for pane: PaneState) -> Glass {
        pane.color == .none
            ? .regular
            : Glass.regular.tint(pane.color.color.opacity(0.35))
    }

    /// Thin divider between adjacent inactive tabs. The active tab's
    /// capsule edges stay clean, like Safari.
    @ViewBuilder
    private func separator(index: Int, activeIndex: Int) -> some View {
        if index > 0, index != activeIndex, index - 1 != activeIndex {
            Rectangle()
                .fill(.secondary.opacity(0.35))
                .frame(width: 1, height: 14)
        }
    }

    private func tab(
        index: Int, pane: PaneState, width: CGFloat, isActive: Bool
    ) -> some View {
        let showClose =
            window.panes.count > 1
            && (isActive || hoveredTabId == pane.id)
        // A Button, not a tap gesture: the title bar drag region
        // swallows plain tap gestures but yields to buttons. The
        // TabDragHandle overlay handles the actual click and drag;
        // the Button remains for styling and accessibility.
        return Button {
            window.selectTab(index)
        } label: {
            // The active title is bold and primary; inactive titles are
            // secondary. The weight contrast marks the active tab even
            // before the capsule reads.
            let title = Text(pane.directory.displayName)
                .lineLimit(1)
                .truncationMode(.tail)
                .font(.caption.weight(isActive ? .semibold : .regular))
                .foregroundStyle(
                    isActive
                        ? AnyShapeStyle(.primary)
                        : AnyShapeStyle(.secondary))
                .padding(.horizontal, showClose ? 24 : 12)
                .frame(width: width, height: tabHeight)
            Group {
                if isActive {
                    // The active tab is a Liquid Glass capsule, like
                    // Safari's. The glass applies to the label itself;
                    // glass placed behind in `.background` composites
                    // over the title and blurs it.
                    title
                        .glassEffect(activeGlass(for: pane), in: .capsule)
                        .overlay(
                            Capsule().strokeBorder(
                                .primary.opacity(0.25), lineWidth: 1))
                        // The shadow lifts the capsule off the band, so
                        // the active tab reads as raised.
                        .shadow(
                            color: .black.opacity(0.25), radius: 3, y: 1)
                } else {
                    title.background {
                        // The pane color stays on inactive tabs so the
                        // color survives tab switches.
                        if pane.color != .none {
                            Capsule().fill(pane.color.color.opacity(0.22))
                        }
                        if hoveredTabId == pane.id {
                            Capsule().fill(.primary.opacity(0.06))
                        }
                    }
                }
            }
            .overlay {
                if dropTargetTabId == pane.id {
                    Capsule().strokeBorder(
                        Color.accentColor, lineWidth: 1.5)
                }
            }
            .padding(.horizontal, 3)
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        // The tab title truncates; the tooltip shows the full path.
        .help(pane.directory.path)
        // The drag layer sits over the whole tab: a click selects, a
        // drag moves the tab or tears it off. It comes before the
        // close overlay so the close button stays clickable on top.
        .overlay {
            TabDragHandle(paneID: pane.id) {
                window.selectTab(index)
            }
        }
        // The close control overlays the tab as a sibling.
        // A nested button inside the tab label would not get clicks.
        .overlay(alignment: .trailing) {
            if showClose {
                Button {
                    window.closeTab(index)
                } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 7, weight: .bold))
                        .padding(4)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .opacity(0.55)
                .help("Close Tab")
                .padding(.trailing, 6)
            }
        }
        .onHover { hovering in
            if hovering {
                hoveredTabId = pane.id
            } else if hoveredTabId == pane.id {
                hoveredTabId = nil
            }
        }
        .contextMenu {
            Button("Move Tab to New Window") {
                // Below the current strip, so the new window is visible
                // next to its source instead of exactly on top of it.
                let origin = window.nsWindow.map {
                    NSPoint(x: $0.frame.minX + 40, y: $0.frame.maxY - 60)
                } ?? NSPoint(x: 200, y: 600)
                model.detachTab(paneID: pane.id, at: origin)
            }
            .disabled(window.panes.count < 2)
            Section("Tab Color") {
                ForEach(TabColor.allCases) { tabColor in
                    Button {
                        pane.color = tabColor
                        // The color is part of the saved session, so a
                        // recolor rewrites it.
                        model.saveSession()
                    } label: {
                        HStack(spacing: 6) {
                            // A real circle view carries its color
                            // into the menu; a tinted SF Symbol can
                            // render monochrome there.
                            Circle()
                                .fill(
                                    tabColor == .none
                                        ? Color.clear : tabColor.color)
                                .overlay(
                                    Circle().strokeBorder(.secondary))
                                .frame(width: 9, height: 9)
                            Text(tabColor.label)
                        }
                    }
                }
            }
        }
        .onDrop(
            of: [.fileURL, Self.remotePathUTType, Self.tabUTType],
            delegate: TabDropDelegate(
                index: index, pane: pane, model: model, window: window,
                dropTarget: $dropTargetTabId))
    }
}

/// Reads a dragged tab's pane UUID from the AppKit drag pasteboard.
/// Synchronous, unlike DropInfo's async item loading, so dropUpdated
/// can decide the operation immediately.
@MainActor
private func draggedTabID() -> UUID? {
    let items = NSPasteboard(name: .drag).pasteboardItems ?? []
    for item in items {
        if let raw = item.string(forType: .orkaTab),
            let id = UUID(uuidString: raw)
        {
            return id
        }
    }
    return nil
}

/// Drop target for the empty band after the tabs: a dragged tab lands
/// at the end of this window's strip.
private struct TabStripEndDropDelegate: DropDelegate {
    let window: WindowState

    func validateDrop(info: DropInfo) -> Bool {
        info.hasItemsConforming(to: [TabBarView.tabUTType])
    }

    func dropUpdated(info: DropInfo) -> DropProposal? {
        DropProposal(operation: .move)
    }

    func performDrop(info: DropInfo) -> Bool {
        guard let id = draggedTabID() else { return false }
        AppModel.shared.moveTab(
            paneID: id, to: window, at: window.panes.count)
        return true
    }
}

/// Handles drops on one tab: files spring-load and transfer into the
/// tab's directory, like a browser; a dragged tab inserts at this
/// tab's position, like a browser reordering or adopting a tab.
private struct TabDropDelegate: DropDelegate {
    /// Hover time before a file drag switches tabs. Long enough that a
    /// drag passing across the strip does not flip through every tab.
    static let springLoadDelay: TimeInterval = 0.35

    let index: Int
    let pane: PaneState
    let model: AppModel
    let window: WindowState
    @Binding var dropTarget: UUID?

    func validateDrop(info: DropInfo) -> Bool {
        info.hasItemsConforming(
            to: [.fileURL, TabBarView.remotePathUTType, TabBarView.tabUTType])
    }

    func dropEntered(info: DropInfo) {
        dropTarget = pane.id
        // A dragged tab must not spring-load: switching tabs mid-drag
        // reads as flicker, and the drop itself sets the active tab.
        guard draggedTabID() == nil else { return }
        let id = pane.id
        DispatchQueue.main.asyncAfter(
            deadline: .now() + Self.springLoadDelay
        ) {
            // The pointer still rests on this tab: open it under the
            // drag so the drop can also land inside the file area.
            if dropTarget == id, window.activePaneIndex != index {
                window.selectTab(index)
            }
        }
    }

    func dropExited(info: DropInfo) {
        if dropTarget == pane.id { dropTarget = nil }
    }

    func dropUpdated(info: DropInfo) -> DropProposal? {
        if let dragged = draggedTabID() {
            // Dropping a tab onto itself is a no-op, not a move.
            return DropProposal(
                operation: dragged == pane.id ? .cancel : .move)
        }
        let destDir = pane.directory.path
        if !remoteSources().isEmpty {
            // Same rule as the file list: remote rows land on a local
            // destination only, and always as a copy.
            return DropProposal(
                operation: OrkaPath.isLocal(destDir) ? .copy : .cancel)
        }
        let sources = transferSources(localSources(), destDir: destDir)
        guard !sources.isEmpty else {
            return DropProposal(operation: .cancel)
        }
        return DropProposal(
            operation: shouldMove(sources, destDir: destDir)
                ? .move : .copy)
    }

    func performDrop(info: DropInfo) -> Bool {
        dropTarget = nil
        if let dragged = draggedTabID() {
            guard dragged != pane.id else { return false }
            AppModel.shared.moveTab(paneID: dragged, to: window, at: index)
            return true
        }
        let destDir = pane.directory.path
        let remote = remoteSources()
        if !remote.isEmpty {
            guard OrkaPath.isLocal(destDir) else { return false }
            model.transfer(sources: remote, to: destDir, move: false)
            window.selectTab(index)
            return true
        }
        let sources = transferSources(localSources(), destDir: destDir)
        guard !sources.isEmpty else { return false }
        model.transfer(
            sources: sources, to: destDir,
            move: shouldMove(sources, destDir: destDir))
        window.selectTab(index)
        return true
    }

    // MARK: Drag pasteboard

    // SwiftUI's DropInfo hands out item data asynchronously. The AppKit
    // drag pasteboard carries the same content synchronously, which
    // keeps the move-or-copy decision in dropUpdated immediate.
    private func localSources() -> [String] {
        let urls = NSPasteboard(name: .drag).readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]) as? [URL]
        return urls?.map(\.path) ?? []
    }

    private func remoteSources() -> [String] {
        let items = NSPasteboard(name: .drag).pasteboardItems ?? []
        return items.compactMap { $0.string(forType: .orkaRemotePath) }
    }

    /// Filters out no-op and unsafe transfers: dropping into the folder
    /// the item is already in, or a folder into itself or its own
    /// descendant. Mirrors the file list's drop filter.
    private func transferSources(
        _ sources: [String], destDir: String
    ) -> [String] {
        sources.filter { source in
            let parent = URL(fileURLWithPath: source)
                .deletingLastPathComponent().path
            if parent == destDir { return false }
            if destDir == source || destDir.hasPrefix(source + "/") {
                return false
            }
            return true
        }
    }

    private func shouldMove(_ sources: [String], destDir: String) -> Bool {
        // Option forces a copy, following macOS convention.
        if NSEvent.modifierFlags.contains(.option) { return false }
        guard let first = sources.first else { return false }
        return sameVolume(first, destDir)
    }

    private func sameVolume(_ a: String, _ b: String) -> Bool {
        func volumeID(_ path: String) -> AnyHashable? {
            let values = try? URL(fileURLWithPath: path)
                .resourceValues(forKeys: [.volumeIdentifierKey])
            return values?.volumeIdentifier as? AnyHashable
        }
        guard let va = volumeID(a), let vb = volumeID(b) else { return false }
        return va == vb
    }
}
