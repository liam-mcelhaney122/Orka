import SwiftUI

/// Root of one window scene. Each scene claims its own WindowState from
/// the model: a torn-off tab, a saved session from launch restore, or a
/// fresh window. The first scene also opens the other saved windows.
struct ContentView: View {
    @State private var windowState: WindowState?
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            if let windowState {
                MainWindowView(window: windowState)
            } else {
                Color.clear
            }
        }
        .onAppear {
            let model = AppModel.shared
            // AppKit-driven code (the tab tear-off) cannot reach the
            // SwiftUI environment; hand it the openWindow action.
            model.openMainWindow = { openWindow(id: "main") }
            guard windowState == nil else { return }
            windowState = model.makeWindowState()
            if !model.didSpawnRestoredWindows {
                model.didSpawnRestoredWindows = true
                for _ in 0..<model.pendingRestoreCount {
                    openWindow(id: "main")
                }
            }
        }
    }
}

/// One file-manager window: tab band, toolbar, sidebar, file pane, and
/// the optional git panel.
struct MainWindowView: View {
    @Bindable var model = AppModel.shared
    @Bindable var window: WindowState

    /// Panel width when the splitter drag started.
    @State private var dividerDragStart: CGFloat?

    /// Sidebar width, persisted across launches and shared by windows.
    @AppStorage("sidebarWidth") private var sidebarWidth: Double = 230
    /// Sidebar width when its splitter drag started.
    @State private var sidebarDragStart: CGFloat?

    /// Focus drives the search help dropdown.
    @FocusState private var searchFocused: Bool

    private static let minPanelWidth: CGFloat = 340
    private static let minFileWidth: CGFloat = 320
    private static let minSidebarWidth: CGFloat = 180
    private static let maxSidebarWidth: CGFloat = 480

    init(window: WindowState) {
        self.window = window
    }

    private var pane: PaneState { window.activePane }

    private var deleteConfirmTitle: String {
        let count = window.confirmingDelete?.count ?? 0
        return count == 1
            ? "Delete 1 item permanently?"
            : "Delete \(count) items permanently?"
    }

    /// Smallest window width that fits all three panels at their
    /// minimums. The git panel only exists while it is shown, so the
    /// window may shrink further while it is hidden.
    private var windowMinWidth: CGFloat {
        window.showingGitGraph
            ? Self.minSidebarWidth + Self.minFileWidth + Self.minPanelWidth
            : Self.minSidebarWidth + Self.minFileWidth
    }

    var body: some View {
        VStack(spacing: 0) {
            // No divider here: the tab band and the toolbar row read as
            // one continuous chrome surface, like Safari.
            TabBarView(model: model, window: window)
            toolbarRow
                // Above the file pane, so the search help dropdown
                // hangs over the pane instead of under it.
                .zIndex(1)
            Divider()
            // A plain HStack, not a NavigationSplitView. The macOS 26
            // split view insets its sidebar pane at the bottom only,
            // which reads as a glitch under the custom chrome. This
            // Finder-style pane floats with an even inset on every side.
            HStack(spacing: 0) {
                SidebarView(model: model, window: window)
                    .frame(width: CGFloat(sidebarWidth))
                    .padding(.leading, 10)
                    .padding(.vertical, 10)
                sidebarSplitter
                GeometryReader { geo in
                    HStack(spacing: 0) {
                        VStack(spacing: 0) {
                            BreadcrumbBar(model: model, window: window)
                            Divider()
                            if model.viewMode == .icons {
                                IconGridView(model: model, window: window)
                            } else {
                                FileListView(model: model, window: window)
                            }
                            Divider()
                            StatusBarView(model: model, window: window)
                        }
                        .frame(
                            minWidth: Self.minFileWidth, maxWidth: .infinity)
                        // The same floating rounded glass surface as the
                        // sidebar, so the three panes read as one family.
                        .glassEffect(.regular, in: .rect(cornerRadius: 12))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .padding(.vertical, 10)
                        .padding(
                            .trailing, window.showingGitGraph ? 0 : 10)
                        .dropDestination(for: URL.self) { urls, _ in
                            let sources = urls.filter(\.isFileURL).map(\.path)
                            guard !sources.isEmpty else { return false }
                            model.transfer(
                                sources: sources,
                                to: pane.directory.path,
                                move: false,
                                in: window)
                            return true
                        }
                        if window.showingGitGraph {
                            panelDivider(available: geo.size.width)
                            GitGraphPanel(
                                model: model, window: window, inline: true)
                                .frame(width: panelWidth(available: geo.size.width))
                                .glassEffect(
                                    .regular, in: .rect(cornerRadius: 12))
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                                .padding(.vertical, 10)
                                .padding(.trailing, 10)
                                .transition(.move(edge: .trailing))
                        }
                    }
                }
                .animation(
                    .easeInOut(duration: 0.2),
                    value: window.showingGitGraph)
            }
        }
        // The band must occupy the title bar area, not sit below it.
        .ignoresSafeArea(.container, edges: .top)
        .background(WindowChromeConfigurator(windowState: window))
        .sheet(item: $window.infoTarget) { target in
            GetInfoView(path: target.path)
        }
        .sheet(item: $window.editingConnection) { target in
            ConnectionEditorView(target: target)
        }
        .sheet(item: $window.uploadPickerTarget) { target in
            UploadPickerView(model: model, target: target)
        }
        .confirmationDialog(
            deleteConfirmTitle,
            isPresented: Binding(
                get: { window.confirmingDelete != nil },
                set: { if !$0 { model.cancelPermanentDelete(in: window) } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                model.confirmPermanentDelete(in: window)
            }
            Button("Cancel", role: .cancel) {
                model.cancelPermanentDelete(in: window)
            }
        } message: {
            Text("Deleting on a server cannot be undone.")
        }
        .confirmationDialog(
            "Empty the Trash?",
            isPresented: $window.confirmingEmptyTrash,
            titleVisibility: .visible
        ) {
            Button("Empty Trash", role: .destructive) {
                model.confirmEmptyTrash(in: window)
            }
            Button("Cancel", role: .cancel) {
                model.cancelEmptyTrash(in: window)
            }
        } message: {
            Text("Every item in the Trash deletes permanently. There is no undo.")
        }
        .confirmationDialog(
            window.transferConflict.map {
                "An item named \($0.name) already exists."
            } ?? "File conflict",
            isPresented: Binding(
                get: { window.transferConflict != nil },
                set: { if !$0 { window.finishTransferConflict() } }),
            titleVisibility: .visible
        ) {
            Button("Replace", role: .destructive) {
                resolveCurrentConflict(as: .replace)
            }
            Button("Keep Both") {
                resolveCurrentConflict(as: .keepBoth)
            }
            Button("Skip", role: .cancel) {
                window.finishTransferConflict()
            }
        } message: {
            if let conflict = window.transferConflict {
                Text(
                    "Incoming: \(conflict.source)\nExisting: \(conflict.destination)")
            }
        }
        // The gate covers every pane and the chrome, so nothing is
        // clickable until macOS grants Full Disk Access.
        .overlay {
            if !model.hasFullDiskAccess {
                FullDiskAccessGateView(model: model)
            }
        }
        .frame(minWidth: windowMinWidth, minHeight: 440)
        .onAppear {
            pane.directory.reload(showHidden: model.showHidden)
        }
    }

    private func resolveCurrentConflict(as resolution: ConflictResolution) {
        guard let conflict = window.transferConflict else { return }
        model.resolveTransferConflict(conflict, as: resolution)
        window.finishTransferConflict()
    }

    /// Draggable splitter between the sidebar and the file pane.
    /// The gutter is invisible, like Finder's: the floating pane's
    /// edge marks the boundary, so no separator line is drawn.
    private var sidebarSplitter: some View {
        Color.clear
            .frame(width: 10)
            .frame(maxHeight: .infinity)
            .contentShape(Rectangle())
            .onHover { hovering in
                if hovering {
                    NSCursor.resizeLeftRight.push()
                } else {
                    NSCursor.pop()
                }
            }
            .gesture(
                DragGesture(minimumDistance: 1)
                    .onChanged { value in
                        let start = sidebarDragStart ?? CGFloat(sidebarWidth)
                        if sidebarDragStart == nil {
                            sidebarDragStart = start
                        }
                        let wanted = start + value.translation.width
                        sidebarWidth = Double(
                            min(
                                max(wanted, Self.minSidebarWidth),
                                Self.maxSidebarWidth))
                    }
                    .onEnded { _ in sidebarDragStart = nil }
            )
    }

    /// Draggable splitter between the file pane and the git panel.
    /// Invisible, like the sidebar splitter: the gap between the two
    /// floating panes marks the boundary.
    private func panelDivider(available: CGFloat) -> some View {
        Color.clear
            .frame(width: 7)
            .frame(maxHeight: .infinity)
            .contentShape(Rectangle())
            .onHover { hovering in
                if hovering {
                    NSCursor.resizeLeftRight.push()
                } else {
                    NSCursor.pop()
                }
            }
            .gesture(
                DragGesture(minimumDistance: 1)
                    .onChanged { value in
                        let start =
                            dividerDragStart
                            ?? panelWidth(available: available)
                        if dividerDragStart == nil {
                            dividerDragStart = start
                        }
                        let clamped = clampedPanelWidth(
                            start - value.translation.width,
                            available: available)
                        guard available > 0 else { return }
                        window.gitPanelFraction = Double(clamped / available)
                    }
                    .onEnded { _ in dividerDragStart = nil }
            )
    }

    /// Clamps a panel width so both panes keep a usable minimum.
    private func clampedPanelWidth(_ width: CGFloat, available: CGFloat) -> CGFloat {
        let upper = max(Self.minPanelWidth, available - Self.minFileWidth)
        return min(max(width, Self.minPanelWidth), upper)
    }

    /// The panel's share of the split area before any splitter drag.
    private static let defaultPanelFraction: CGFloat = 0.45

    /// The panel width, decided during layout as a share of the
    /// available width, so a window resize grows both panes together.
    /// A splitter drag sets `gitPanelFraction`, and that share wins
    /// from then on. Without one, the panel takes the default share,
    /// grown to the graph's content width when the content is wider.
    /// The clamp protects the file pane's minimum either way.
    private func panelWidth(available: CGFloat) -> CGFloat {
        var wanted: CGFloat
        if let fraction = window.gitPanelFraction {
            wanted = available * CGFloat(fraction)
        } else {
            wanted = available * Self.defaultPanelFraction
            if window.gitPanelIdealWidth > 0 {
                wanted = max(wanted, CGFloat(window.gitPanelIdealWidth))
            }
        }
        return clampedPanelWidth(wanted, available: available)
    }

    /// Custom toolbar row below the tab band.
    /// It replaces the system toolbar, which the hidden title bar removes.
    /// Controls sit in Liquid Glass capsule clusters. One container
    /// gives all clusters a shared sampling region, because glass
    /// cannot sample other glass.
    private var toolbarRow: some View {
        GlassEffectContainer(spacing: 12) {
            HStack(spacing: 12) {
                navigationCluster
                Picker("View", selection: $model.viewMode) {
                    Image(systemName: "list.bullet")
                        .tag(AppModel.ViewMode.details)
                        .help("Details view")
                    Image(systemName: "square.grid.2x2")
                        .tag(AppModel.ViewMode.icons)
                        .help("Icon view")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                actionCluster
                Spacer(minLength: 8)
                searchField
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .background(.bar)
    }

    /// Back, forward, and up share one glass capsule.
    private var navigationCluster: some View {
        HStack(spacing: 2) {
            toolbarIconButton(
                "chevron.left", help: "Back",
                disabled: !pane.canGoBack
            ) { pane.goBack(showHidden: model.showHidden) }
            toolbarIconButton(
                "chevron.right", help: "Forward",
                disabled: !pane.canGoForward
            ) { pane.goForward(showHidden: model.showHidden) }
            toolbarIconButton(
                "arrow.up", help: "Enclosing Folder",
                disabled: !pane.canGoUp
            ) { pane.goUp(showHidden: model.showHidden) }
        }
        .padding(.horizontal, 4)
        .frame(height: 28)
        .glassEffect(.regular, in: .capsule)
    }

    /// Folder actions share a second glass capsule.
    private var actionCluster: some View {
        HStack(spacing: 2) {
            toolbarIconButton(
                "folder.badge.plus", help: "New Folder",
                disabled: !OrkaPath.isLocal(pane.directory.path)
            ) { model.newFolder(in: window) }
            toolbarIconButton(
                "arrow.clockwise", help: "Refresh", disabled: false
            ) { pane.directory.reload(showHidden: model.showHidden) }
            toolbarIconButton(
                "arrow.triangle.branch",
                help: window.showingGitGraph
                    ? "Hide Git Graph" : "Show Git Graph",
                disabled: pane.directory.gitStatus == nil
            ) { window.showingGitGraph.toggle() }
            toolbarIconButton(
                "terminal", help: "Open in Terminal",
                disabled: !OrkaPath.isLocal(pane.directory.path)
            ) { model.openInTerminal(in: window) }
            Toggle(isOn: $model.showHidden) {
                Image(systemName: "eye")
                    .frame(width: 24, height: 24)
                    .contentShape(Rectangle())
            }
            .toggleStyle(.button)
            .help("Show hidden files")
        }
        .padding(.horizontal, 4)
        .frame(height: 28)
        .glassEffect(.regular, in: .capsule)
    }

    /// One icon button for the glass clusters. The fixed frame plus
    /// `contentShape` makes the full slot clickable, not only the glyph.
    private func toolbarIconButton(
        _ symbol: String, help: String, disabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .frame(width: 24, height: 24)
                .contentShape(Rectangle())
        }
        .disabled(disabled)
        .help(help)
    }

    private var searchField: some View {
        HStack(spacing: 5) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            TextField("Search", text: $window.searchText)
                .textFieldStyle(.plain)
                .focused($searchFocused)
                .onSubmit { window.performDeepSearch() }
                .onExitCommand { searchFocused = false }
                .onAppear {
                    // The window hands the first text field key focus at
                    // launch, which pops the help dropdown before any
                    // click. Focus lands after appear, so clear it on
                    // the next runloop turn.
                    DispatchQueue.main.async { searchFocused = false }
                }
        }
        .padding(.horizontal, 10)
        .frame(height: 28)
        .glassEffect(.regular, in: .capsule)
        .frame(width: 300)
        .overlay(alignment: .topLeading) {
            if searchFocused {
                searchHelp
                    // Hangs just below the 28pt capsule.
                    .offset(y: 34)
                    .transition(.opacity)
            }
        }
        .animation(.easeOut(duration: 0.15), value: searchFocused)
    }

    /// Dropdown under the focused search field. It explains the two
    /// search modes and the extension filter the engine parses.
    private var searchHelp: some View {
        VStack(alignment: .leading, spacing: 10) {
            searchHelpRow(
                "line.3.horizontal.decrease",
                "Type to filter the current folder.")
            searchHelpRow(
                "arrow.turn.down.left",
                "Press Return to search all subfolders.")
            searchHelpRow(
                "asterisk",
                "Add *.swift to match only that extension.")
        }
        .font(.caption)
        .padding(12)
        .frame(width: 300, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 12))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func searchHelpRow(
        _ symbol: String, _ text: String
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .frame(width: 14)
            Text(text)
        }
    }
}

/// Full-window blocker shown until macOS grants Full Disk Access.
/// A file manager cannot work while protected locations like the
/// Trash refuse to list, so the whole UI waits behind this screen.
/// The timer polls for the grant; a granted toggle in System Settings
/// lifts the gate without a manual retry. macOS may still ask to
/// relaunch the app, and the gate never returns after that.
struct FullDiskAccessGateView: View {
    var model: AppModel

    private let recheck = Timer.publish(every: 1, on: .main, in: .common)
        .autoconnect()

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.shield")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("Orka needs Full Disk Access")
                .font(.title2.bold())
            Text("""
                macOS protects locations like the Trash. Open System \
                Settings > Privacy & Security > Full Disk Access, click +, \
                add Orka, and turn it on. This screen closes when access \
                arrives; relaunch Orka if macOS asks for it.
                """)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 440)
            HStack(spacing: 10) {
                Button("Reveal Orka in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting(
                        [Bundle.main.bundleURL])
                }
                Button("Open System Settings") {
                    model.openFullDiskAccessSettings()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 6)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.regularMaterial)
        .ignoresSafeArea()
        .onReceive(recheck) { _ in model.checkFullDiskAccess() }
    }
}
