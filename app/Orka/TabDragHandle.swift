import AppKit
import SwiftUI
import UniformTypeIdentifiers

extension NSPasteboard.PasteboardType {
    /// Carries a dragged tab's pane UUID between tab strips.
    static let orkaTab = NSPasteboard.PasteboardType("com.orka.tab")
}

/// AppKit drag layer over one tab. SwiftUI's onDrag cannot detect a
/// drop that landed nowhere, which is exactly the browser tear-off
/// gesture, so the tab drag runs as a real NSDraggingSession:
/// - a click (no movement) selects the tab
/// - a drop on a tab strip moves the tab there (SwiftUI onDrop)
/// - a drop anywhere else tears the tab off into a new window
struct TabDragHandle: NSViewRepresentable {
    let paneID: UUID
    let onSelect: () -> Void

    func makeNSView(context: Context) -> TabDragNSView {
        let view = TabDragNSView()
        view.paneID = paneID
        view.onSelect = onSelect
        return view
    }

    func updateNSView(_ nsView: TabDragNSView, context: Context) {
        nsView.paneID = paneID
        nsView.onSelect = onSelect
    }
}

final class TabDragNSView: NSView, NSDraggingSource {
    var paneID: UUID?
    var onSelect: (() -> Void)?

    /// Movement below this threshold stays a click.
    private static let dragThreshold: CGFloat = 4

    private var mouseDownEvent: NSEvent?

    override func mouseDown(with event: NSEvent) {
        mouseDownEvent = event
    }

    override func mouseUp(with event: NSEvent) {
        if mouseDownEvent != nil {
            onSelect?()
        }
        mouseDownEvent = nil
    }

    override func mouseDragged(with event: NSEvent) {
        guard let down = mouseDownEvent, let paneID else { return }
        let dx = event.locationInWindow.x - down.locationInWindow.x
        let dy = event.locationInWindow.y - down.locationInWindow.y
        guard dx * dx + dy * dy
            > Self.dragThreshold * Self.dragThreshold
        else { return }
        mouseDownEvent = nil
        let item = NSPasteboardItem()
        item.setString(paneID.uuidString, forType: .orkaTab)
        let dragItem = NSDraggingItem(pasteboardWriter: item)
        dragItem.setDraggingFrame(bounds, contents: tabSnapshot())
        beginDraggingSession(with: [dragItem], event: down, source: self)
    }

    /// Image of the tab under this handle, for the drag preview. The
    /// handle itself is transparent, so the window content below it is
    /// what gets snapshotted.
    private func tabSnapshot() -> NSImage? {
        guard let content = window?.contentView else { return nil }
        let rect = content.convert(bounds, from: self)
        guard let rep = content.bitmapImageRepForCachingDisplay(in: rect)
        else { return nil }
        content.cacheDisplay(in: rect, to: rep)
        let image = NSImage(size: rect.size)
        image.addRepresentation(rep)
        return image
    }

    // MARK: NSDraggingSource

    nonisolated func draggingSession(
        _ session: NSDraggingSession,
        sourceOperationMaskFor context: NSDraggingContext
    ) -> NSDragOperation {
        // A tab means nothing to other apps; keeping the mask empty
        // outside the app makes an outside drop read as "nowhere",
        // which is the tear-off case.
        context == .withinApplication ? .move : []
    }

    nonisolated func draggingSession(
        _ session: NSDraggingSession, endedAt screenPoint: NSPoint,
        operation: NSDragOperation
    ) {
        // A completed move was handled by the receiving tab strip.
        // No operation means the drop landed nowhere: tear off.
        guard operation == [] else { return }
        MainActor.assumeIsolated {
            guard let paneID else { return }
            AppModel.shared.detachTab(paneID: paneID, at: screenPoint)
        }
    }
}
