# Chromium Tab Dragging — Engineering Research Notes

Research into how Chromium (Views toolkit, `chrome/browser/ui/views/tabs/dragging/`) implements tab reordering, cross-window dragging, and tab tear-off, with focus on macOS. All paths are relative to the Chromium `src` tree.

## 1. OS drag-and-drop vs. raw mouse tracking

Chromium's primary mechanism is **not** OS drag-and-drop. `TabDragController` tracks raw mouse events routed through the Views event pipeline (`Tab::OnMouseDragged()` -> `TabDragController::Drag()`) and moves a real `views::Widget`/`NSWindow` itself via a **nested move loop**, not a pasteboard session.

System drag-and-drop is used only as a **fallback** on platforms where the OS does not support client-controlled window dragging, notably Wayland. The gating check is:

```cpp
bool TabDragController::ShouldDragWindowUsingSystemDnD() {
  return !GetAttachedBrowserWidget()->IsMoveLoopSupported();
}
```
(`chrome/browser/ui/views/tabs/dragging/tab_drag_controller.cc`)

**Why:** manual mouse tracking plus direct window movement gives synchronous, precise control over hit-testing other windows and attaching a tab mid-drag. OS DnD is only adopted where the platform leaves no alternative.

## 2. State machine

`TabDragController::DragState` (`tab_drag_controller.h`):

| State | Meaning |
|---|---|
| `kNotStarted` | Mouse pressed but has not moved past the drag threshold |
| `kDraggingTabs` | Dragging tab(s) within `attached_context_` (reorder, or attached to another strip) |
| `kDraggingWindow` | Dragging a whole detached window |
| `kDraggingUsingSystemDnD` | Platform lacks client-controlled window drag |
| `kWaitingToExitRunLoop` | Attached to a new target strip, waiting for the nested move loop to unwind |
| `kWaitingToDragTabs` | Attached to the drag-created window, waiting for the move loop to exit |
| `kWaitingForWindowToShow` | Waiting for the newly detached window to show before the move loop starts |
| `kStopped` | Drag completed or canceled |

**Detach thresholds** — vertical distance the cursor must leave the strip's bounds before a tab detaches:

```cpp
const int TabDragController::kTouchVerticalDetachMagnetism = 50; // touch
const int TabDragController::kVerticalDetachMagnetism = 15;      // mouse
```

The strip rect is expanded by the magnetism value on top and bottom before the containment test.

## 3. Detached-drag visuals and cross-window hand-off

**A torn-off tab is a real, live window — not a drag image.** `DetachIntoNewBrowserAndRunMoveLoop()` creates an actual `Browser` with its own `TabStripModel`, shows its widget, positions it under the cursor, and enters the native move loop.

**Hand-off / attach-on-hover** (not on mouse-up): each drag update calls `GetDragTargetForPoint(point_in_screen)`, which uses `WindowFinder` (`dragging/window_finder.h`) to locate a same-process top-level window under the cursor, then checks whether the point falls inside that window's tab strip (`DoesTabStripContain`). A different target context triggers `DragBrowserToNewTabStrip` -> `DetachAndAttachToNewContext()` **during** the drag. Hovering a detached tab over another window also brings that window to front so its strip is visible.

## 4. macOS specifics

The move loop chain: `views::Widget::RunMoveLoop` -> `NativeWidgetMac::RunMoveLoop` -> `NativeWidgetNSWindowBridge::RunMoveLoop` -> **`CocoaWindowMoveLoop`** (`components/remote_cocoa/app_shim/window_move_loop.mm`):

- Registers a **local NSEvent monitor**: `[NSEvent addLocalMonitorForEventsMatchingMask:(NSEventMaskLeftMouseUp | NSEventMaskLeftMouseDragged | NSEventMaskMouseMoved) handler:handler]`.
- On each drag/move event, repositions the window directly: `[window setFrame:NSOffsetRect(base_frame_, dx, dy) display:NO animate:NO]`.
- Terminates on `NSEventTypeLeftMouseUp`; Escape cancel lives in the drag controller (`EscapeTracker`), not the move loop.
- `NSWindow performWindowDragWithEvent:` is used elsewhere only for ordinary title-bar drags — never for the tab-tear-off path.

Other Mac-only branches in `tab_drag_controller.cc`: PWA/remote windows are non-detachable; the dragged window resizes to fit the target display's work area when crossing monitors; window origin is set *after* `Show()` on Mac ("to avoid child windows being misplaced"); fullscreen is reapplied after the drag when the source window was fullscreen.

## 5. Last tab, Escape, and in-strip reorder animation

**Dragging the last tab of a window** moves the window itself instead of detach-and-recreate (`is_dragging_all_tabs` special case).

**Escape/cancel**: a `KeyEventTracker` watches `VKEY_ESCAPE` and calls `EndDrag(END_DRAG_CANCEL)` -> `RevertDrag()`, which walks the dragged tabs back to their source context at their original indices and restores the pre-drag selection.

**In-strip reorder animation** is delegated to `DraggingTabsSession` (`dragging/dragging_tabs_session.h`): it computes new tab positions from the cursor each update and drives the standard layout system, so neighbors animate through the normal layout path.

---

## Recommended approach for Orka

The Chromium design argues against the NSDraggingSession/SwiftUI `onDrop` route: pasteboard DnD gives no continuous hit-testing, no app-controlled window movement, and coarse drop callbacks instead of hover-driven attach. The plan that maps onto AppKit:

1. **Track the drag with a local event monitor, not `onDrop`.** On mouseDown in the tab strip band, install `NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDragged, .leftMouseUp])` and compute screen-coordinate deltas per event.
2. **Reorder within the strip**: while the cursor stays inside the source strip's rect, reindex the dragged PaneState in the window's `panes` array from the cursor x-position. Let SwiftUI animate the reordered array.
3. **Detach threshold**: tear off once the cursor leaves the strip band by a small vertical margin (Chromium: 15 px mouse).
4. **Detach = move a real window.** Create the destination window on detach and drive its position with `window.setFrameOrigin(_:)` on every event. Do **not** use `NSWindow.performDrag(with:)` — it hands control to AppKit's own machinery and blocks hit-testing.
5. **Hit-test other windows' strips continuously.** Per event, convert each window's tab-band rect to screen coordinates and test the cursor point (the analog of `WindowFinder` + `DoesTabStripContain`). Bring the hovered window to front so its strip is visible.
6. **Attach on hover, not on mouse-up.** When the cursor enters another window's strip, move the PaneState into that window immediately (`AppModel.moveTab`) and switch to reorder mode there. Leaving the strip re-detaches.
7. **Escape**: watch keyCode 53 during the drag; on cancel, restore the tab to its recorded source window and index.
8. **Last tab of a window**: skip window creation and move the existing window in the same loop (`is_dragging_all_tabs` analog; `AppModel.detachTab` already does this).
9. **Mouse-up is cleanup only**: attach already happened live; tear down monitors and settle layout.

Sources: `chrome/browser/ui/views/tabs/dragging/tab_drag_controller.{h,cc}`, `dragging/tab_drag_context.h`, `dragging/window_finder.h`, `dragging/dragging_tabs_session.h`, `ui/views/widget/native_widget_mac.mm`, `components/remote_cocoa/app_shim/native_widget_ns_window_bridge.mm`, `components/remote_cocoa/app_shim/window_move_loop.mm`, and the legacy Cocoa-era design doc at chromium.org/developers/design-documents/tab-strip-mac/.
