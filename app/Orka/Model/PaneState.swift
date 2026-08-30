import Foundation
import Observation
import SwiftUI

/// Session-scoped color for one tab, styled after browser tab groups.
/// Colors are not persisted to disk in this milestone; they reset on
/// relaunch by design.
enum TabColor: String, CaseIterable, Identifiable {
    case none, red, orange, yellow, green, blue, purple, pink

    var id: String { rawValue }

    var label: String { rawValue.capitalized }

    /// Fixed tag-like hues. The raw RGB values read well on both light
    /// and dark system appearances, so no dynamic colors are needed.
    var color: Color {
        switch self {
        case .none: .clear
        case .red: Color(red: 0.92, green: 0.26, blue: 0.20)
        case .orange: Color(red: 0.98, green: 0.60, blue: 0.11)
        case .yellow: Color(red: 0.95, green: 0.78, blue: 0.18)
        case .green: Color(red: 0.35, green: 0.72, blue: 0.32)
        case .blue: Color(red: 0.24, green: 0.52, blue: 0.96)
        case .purple: Color(red: 0.66, green: 0.45, blue: 0.86)
        case .pink: Color(red: 0.94, green: 0.42, blue: 0.63)
        }
    }
}

/// Navigation state for one pane (one tab, once tabs exist).
@MainActor
@Observable
final class PaneState: Identifiable {
    let id = UUID()
    let directory: DirectoryModel
    private(set) var backStack: [String] = []
    private(set) var forwardStack: [String] = []
    /// Session-scoped group color. Assignment on this @Observable class
    /// propagates to observers without touching AppModel.
    var color: TabColor = .none

    init(path: String) {
        directory = DirectoryModel(path: path)
    }

    var canGoBack: Bool { !backStack.isEmpty }
    var canGoForward: Bool { !forwardStack.isEmpty }

    /// False at the local root and at a remote URI's root; `goUp` has
    /// nowhere left to go in either case.
    var canGoUp: Bool {
        OrkaPath.isLocal(directory.path)
            ? directory.path != "/"
            : OrkaPath.remoteParent(of: directory.path) != nil
    }

    func navigate(to path: String, showHidden: Bool) {
        guard path != directory.path else { return }
        backStack.append(directory.path)
        forwardStack = []
        directory.show(path: path, showHidden: showHidden)
    }

    func goBack(showHidden: Bool) {
        guard let previous = backStack.popLast() else { return }
        forwardStack.append(directory.path)
        directory.show(path: previous, showHidden: showHidden)
    }

    func goForward(showHidden: Bool) {
        guard let next = forwardStack.popLast() else { return }
        backStack.append(directory.path)
        directory.show(path: next, showHidden: showHidden)
    }

    func goUp(showHidden: Bool) {
        let parent: String
        if OrkaPath.isLocal(directory.path) {
            guard directory.path != "/" else { return }
            parent = URL(fileURLWithPath: directory.path)
                .deletingLastPathComponent().path
        } else {
            guard let remoteParent = OrkaPath.remoteParent(of: directory.path)
            else { return }
            parent = remoteParent
        }
        navigate(to: parent, showHidden: showHidden)
    }
}
