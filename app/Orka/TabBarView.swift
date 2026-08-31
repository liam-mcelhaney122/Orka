import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Safari-style tab strip in the window title bar band. Inactive tabs
/// are plain labels with thin separators; the active tab floats as a
/// Liquid Glass capsule on the darker band. The tab context menu can
/// move a tab into its own window.
struct TabBarView: View {
    @Bindable var model: AppModel
    @Bindable var window: WindowState
    @State private var hoveredTabId: UUID?
    /// Tab currently under a file drag, for the drop highlight.
    @State private var dropTargetTabId: UUID?

    /// Drop-side twin of `NSPasteboard.PasteboardType.orkaRemotePath`.
    static let remotePathUTType = UTType(
        exportedAs: "com.orka.remote-path")

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
        // swallows plain tap gestures but yields to buttons.
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
            of: [.fileURL, Self.remotePathUTType, .orkaSelectedPaths],
            delegate: TabDropDelegate(
                index: index, pane: pane, model: model, window: window,
                dropTarget: $dropTargetTabId))
    }
}

/// Files dragged over a tab spring-load it, like a browser: a short
/// hover switches to the tab, and a drop lands in the tab's directory.
private struct TabDropDelegate: DropDelegate {
    /// Hover time before the drag switches tabs. Long enough that a
    /// drag passing across the strip does not flip through every tab.
    static let springLoadDelay: TimeInterval = 0.35

    let index: Int
    let pane: PaneState
    let model: AppModel
    let window: WindowState
    @Binding var dropTarget: UUID?

    func validateDrop(info: DropInfo) -> Bool {
        info.hasItemsConforming(
            to: [.fileURL, TabBarView.remotePathUTType, .orkaSelectedPaths])
    }

    func dropEntered(info: DropInfo) {
        dropTarget = pane.id
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
        let providers = DropPathLoader.providers(from: info)
        guard !providers.isEmpty else {
            return DropProposal(operation: .cancel)
        }
        return DropProposal(operation: DropTransferPolicy.proposedOperation(
            providers: providers, destDir: pane.directory.path))
    }

    func performDrop(info: DropInfo) -> Bool {
        dropTarget = nil
        let providers = DropPathLoader.providers(from: info)
        guard !providers.isEmpty else { return false }
        let destination = pane.directory.path
        let forceCopy = NSEvent.modifierFlags.contains(.option)
        DropPathLoader.load(providers) { result in
            switch result {
            case .success(let loaded):
                let sources = DropTransferPolicy.transferSources(
                    loaded, destDir: destination)
                guard !sources.isEmpty else { return }
                guard OrkaPath.isLocal(destination)
                    || sources.allSatisfy(OrkaPath.isLocal)
                else { return }
                model.transfer(
                    sources: sources,
                    to: destination,
                    move: DropTransferPolicy.shouldMove(
                        sources: sources,
                        destDir: destination,
                        forceCopy: forceCopy),
                    in: window)
                window.selectTab(index)
            case .failure(let error):
                model.lastJobErrors = [JobItemError(
                    path: destination,
                    message: error.localizedDescription)]
            }
        }
        return true
    }

}
