import AppKit
import SwiftUI

/// Configures the hosting window so content extends into the title bar,
/// and binds the AppKit window to its WindowState: the state needs the
/// NSWindow to close an emptied window and to place a torn-off tab, and
/// the model tracks which window is key for menu command routing.
struct WindowChromeConfigurator: NSViewRepresentable {
    let windowState: WindowState

    func makeNSView(context: Context) -> ChromeView {
        ChromeView(windowState: windowState)
    }

    func updateNSView(_ nsView: ChromeView, context: Context) {
        nsView.windowState = windowState
    }

    final class ChromeView: NSView {
        var windowState: WindowState
        // The style must apply once; repeated inserts would fight AppKit.
        private var configured = false
        private var observers: [NSObjectProtocol] = []

        init(windowState: WindowState) {
            self.windowState = windowState
            super.init(frame: .zero)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) {
            fatalError("init(coder:) is not supported")
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window, !configured else { return }
            configured = true
            window.titlebarAppearsTransparent = true
            window.titleVisibility = .hidden
            window.styleMask.insert(.fullSizeContentView)
            windowState.nsWindow = window
            if window.isKeyWindow {
                AppModel.shared.keyWindowState = windowState
            }
            let center = NotificationCenter.default
            observers.append(
                center.addObserver(
                    forName: NSWindow.didBecomeKeyNotification,
                    object: window, queue: .main
                ) { [weak self] _ in
                    MainActor.assumeIsolated {
                        guard let self else { return }
                        AppModel.shared.keyWindowState = self.windowState
                    }
                })
            observers.append(
                center.addObserver(
                    forName: NSWindow.willCloseNotification,
                    object: window, queue: .main
                ) { [weak self] _ in
                    MainActor.assumeIsolated {
                        guard let self else { return }
                        AppModel.shared.windowClosed(self.windowState)
                    }
                })
        }

        deinit {
            for observer in observers {
                NotificationCenter.default.removeObserver(observer)
            }
        }
    }
}

extension View {
    /// Lets a drag on this view move the window.
    func windowDragArea() -> some View {
        gesture(WindowDragGesture())
    }
}
