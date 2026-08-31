import SwiftUI

final class OrkaAppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) {
        // Joins the Rust worker so no event fires into a dead runtime.
        AppModel.shared.shutdown()
    }
}

@main
struct OrkaApp: App {
    @NSApplicationDelegateAdaptor(OrkaAppDelegate.self) private var delegate

    var body: some Scene {
        // The id lets the tab tear-off and launch restore open more
        // windows of this scene through `openWindow`.
        WindowGroup(id: "main") {
            ContentView()
        }
        .windowStyle(.hiddenTitleBar)
        Window("Git Graph", id: GitGraphPanel.windowID) {
            GitGraphPanel(model: AppModel.shared, inline: false)
        }
        .defaultSize(width: 760, height: 560)
        Window("Transfers", id: TransfersPanel.windowID) {
            TransfersPanel(model: AppModel.shared)
        }
        .defaultSize(width: 520, height: 380)
        .commands {
            CommandGroup(replacing: .undoRedo) {
                let model = AppModel.shared
                Button(model.undoDescription.map { "Undo \($0)" } ?? "Undo") {
                    model.undo()
                }
                .keyboardShortcut("z", modifiers: .command)
                .disabled(model.undoDescription == nil)
                Button(model.redoDescription.map { "Redo \($0)" } ?? "Redo") {
                    model.redo()
                }
                .keyboardShortcut("z", modifiers: [.command, .shift])
                .disabled(model.redoDescription == nil)
            }
            CommandGroup(replacing: .saveItem) {
                Button("Close Tab") {
                    AppModel.shared.closeActiveTab()
                }
                .keyboardShortcut("w", modifiers: .command)
                Button("Close Window") {
                    NSApp.keyWindow?.performClose(nil)
                }
                .keyboardShortcut("w", modifiers: [.command, .shift])
            }
            CommandGroup(after: .newItem) {
                Button("New Tab") {
                    AppModel.shared.newTab()
                }
                .keyboardShortcut("t", modifiers: .command)
                Button("New Folder") {
                    AppModel.shared.newFolder()
                }
                .keyboardShortcut("n", modifiers: [.command, .shift])
                Button("Duplicate") {
                    AppModel.shared.duplicateSelection()
                }
                .keyboardShortcut("d", modifiers: .command)
                Divider()
                Button("Get Info") {
                    AppModel.shared.getInfo()
                }
                .keyboardShortcut("i", modifiers: .command)
                Divider()
                Button("Move to Trash") {
                    AppModel.shared.trashSelection()
                }
                .keyboardShortcut(.delete, modifiers: .command)
                Button("Empty Trash…") {
                    AppModel.shared.requestEmptyTrash()
                }
                .keyboardShortcut(.delete, modifiers: [.command, .shift])
            }
            CommandMenu("Go") {
                Button("Back") {
                    let model = AppModel.shared
                    model.focusedPane?.goBack(showHidden: model.showHidden)
                }
                .keyboardShortcut("[", modifiers: .command)
                Button("Forward") {
                    let model = AppModel.shared
                    model.focusedPane?.goForward(showHidden: model.showHidden)
                }
                .keyboardShortcut("]", modifiers: .command)
                Button("Enclosing Folder") {
                    let model = AppModel.shared
                    model.focusedPane?.goUp(showHidden: model.showHidden)
                }
                .keyboardShortcut(.upArrow, modifiers: .command)
                Divider()
                Button("Home") {
                    AppModel.shared.navigate(
                        to: FileManager.default.homeDirectoryForCurrentUser.path)
                }
                .keyboardShortcut("h", modifiers: [.command, .shift])
                Button("Go to Path…") {
                    AppModel.shared.focusedWindow?.isEditingPath = true
                }
                .keyboardShortcut("l", modifiers: .command)
                Divider()
                Button("Show Next Tab") {
                    AppModel.shared.nextTab()
                }
                .keyboardShortcut("]", modifiers: [.command, .shift])
                Button("Show Previous Tab") {
                    AppModel.shared.previousTab()
                }
                .keyboardShortcut("[", modifiers: [.command, .shift])
            }
            CommandGroup(after: .toolbar) {
                Button("as Icons") {
                    AppModel.shared.viewMode = .icons
                }
                .keyboardShortcut("1", modifiers: .command)
                Button("as List") {
                    AppModel.shared.viewMode = .details
                }
                .keyboardShortcut("2", modifiers: .command)
                Divider()
                Button("Show Hidden Files") {
                    AppModel.shared.showHidden.toggle()
                }
                .keyboardShortcut(".", modifiers: [.command, .shift])
                Divider()
                Button("Refresh") {
                    let model = AppModel.shared
                    model.focusedPane?.directory
                        .reload(showHidden: model.showHidden)
                }
                .keyboardShortcut("r", modifiers: .command)
            }
        }
    }
}
