import SwiftUI

/// GitKraken-style branch panel: branches on the left, a commit graph
/// with merge lanes on the right.
struct GitGraphPanel: View {
    @Bindable var model: AppModel

    /// The owning window for the inline panel. Nil for the pop-out.
    var window: WindowState? = nil

    /// False when this instance lives in its own pop-out window.
    var inline = true

    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss

    @State private var graph: GitGraphInfo?
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var selectedBranch: String?
    /// Commit oid to scroll to after a branch click.
    @State private var scrollTarget: String?

    private let rowHeight: CGFloat = 26
    private let laneWidth: CGFloat = 14
    private let nodeRadius: CGFloat = 4
    private let limit: UInt32 = 300

    /// Scene id for the pop-out window. Shared with OrkaApp.
    static let windowID = "git-graph-window"

    /// The window this panel reflects: its own for the inline panel,
    /// the key window for the pop-out.
    private var targetWindow: WindowState? { window ?? model.focusedWindow }

    /// Nil when no window is open; the panel then shows its empty state.
    private var directory: DirectoryModel? { targetWindow?.activePane.directory }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HStack(spacing: 0) {
                branchList
                    .frame(width: 160)
                Divider()
                graphArea
            }
        }
        // The git stamp bumps on every reload, including the ones the
        // watch pipeline triggers, so the panel stays live while open.
        .task(id: directory?.gitStamp) { await load() }
        // The pop-out window sizes itself; the inline panel is sized by
        // ContentView's splitter.
        .frame(
            minWidth: inline ? nil : 640,
            minHeight: inline ? nil : 420)
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "arrow.triangle.branch")
            if let graph {
                Text(graph.repoRoot)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(.secondary)
                if let branch = graph.branch {
                    Text("on \(branch)")
                        .fontWeight(.medium)
                }
            }
            Spacer()
            if let graph, graph.truncated {
                Text("latest \(limit) commits")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Button {
                Task { await load() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Refresh")
            if inline {
                Button {
                    targetWindow?.showingGitGraph = false
                    openWindow(id: Self.windowID)
                } label: {
                    Image(systemName: "macwindow.on.rectangle")
                }
                .help("Pop Out")
                Button {
                    targetWindow?.showingGitGraph = false
                } label: {
                    Image(systemName: "sidebar.trailing")
                }
                .help("Hide Panel")
            } else {
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                }
                .help("Close")
            }
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: Branch list

    private var branchList: some View {
        List(selection: $selectedBranch) {
            Section("Local") {
                branchRows(isLocal: true)
            }
            Section("Remote") {
                branchRows(isLocal: false)
            }
        }
        .listStyle(.sidebar)
        // The panel's glass surface shows through the branch list.
        .scrollContentBackground(.hidden)
        .onChange(of: selectedBranch) { _, name in
            guard let name,
                let branch = graph?.branches.first(where: { $0.name == name }),
                let row = branch.headCommit, let graph,
                Int(row) < graph.commits.count
            else { return }
            scrollTarget = graph.commits[Int(row)].oid
        }
    }

    @ViewBuilder
    private func branchRows(isLocal: Bool) -> some View {
        if let graph {
            ForEach(
                graph.branches.filter { $0.isLocal == isLocal }, id: \.name
            ) { branch in
                HStack(spacing: 6) {
                    Circle()
                        .fill(branchColor(branch, graph: graph))
                        .frame(width: 8, height: 8)
                    Text(branch.name)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    if branch.isHead {
                        Text("HEAD")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundStyle(.secondary)
                    }
                }
                // The tap replaces List's own click selection so it can
                // also open the remote page; keyboard selection still
                // goes through the List binding and only scrolls.
                .contentShape(Rectangle())
                .onTapGesture {
                    selectedBranch = branch.name
                    openBranchOnRemote(branch)
                }
                .help(remoteHelp(for: "branch"))
                .contextMenu {
                    Button("Open on Remote") { openBranchOnRemote(branch) }
                        .disabled(graph.remoteUrl == nil)
                }
                .tag(branch.name)
            }
        }
    }

    private func branchColor(_ branch: GitBranchInfo, graph: GitGraphInfo) -> Color {
        guard let row = branch.headCommit, Int(row) < graph.commits.count
        else { return .gray }
        return Self.color(for: graph.commits[Int(row)].lane)
    }

    // MARK: Graph

    @ViewBuilder
    private var graphArea: some View {
        if isLoading && graph == nil {
            ProgressView()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let graph {
            // The GeometryReader pins the content to the viewport size.
            // Without the floor, a two-axis ScrollView centers content
            // smaller than the viewport, which reads as broken margins
            // in a wide pop-out window.
            GeometryReader { geo in
                ScrollViewReader { proxy in
                    ScrollView([.vertical, .horizontal]) {
                        HStack(spacing: 0) {
                            graphCanvas(graph)
                            commitRows(graph)
                        }
                        .frame(
                            minWidth: geo.size.width,
                            minHeight: geo.size.height,
                            alignment: .topLeading)
                    }
                    .onChange(of: scrollTarget) { _, target in
                        guard let target else { return }
                        withAnimation(.easeInOut(duration: 0.2)) {
                            proxy.scrollTo(target, anchor: .center)
                        }
                    }
                }
            }
        } else {
            Text(errorMessage ?? "Not a git repository")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// The lane-and-node drawing for all rows. Drawn once so lines run
    /// continuously across rows; the text rows align beside it.
    private func graphCanvas(_ graph: GitGraphInfo) -> some View {
        let commits = graph.commits
        let maxLane = commits.map(\.lane).max() ?? 0
        let width = CGFloat(maxLane + 1) * laneWidth + laneWidth

        return Canvas { context, _ in
            func x(_ lane: UInt32) -> CGFloat {
                CGFloat(lane) * laneWidth + laneWidth / 2
            }
            func y(_ row: Int) -> CGFloat {
                CGFloat(row) * rowHeight + rowHeight / 2
            }

            for (row, commit) in commits.enumerated() {
                let color = Self.color(for: commit.lane)
                for parent in commit.parents where Int(parent) < commits.count {
                    let parentCommit = commits[Int(parent)]
                    var path = Path()
                    if parentCommit.lane == commit.lane {
                        path.move(to: CGPoint(x: x(commit.lane), y: y(row) + nodeRadius))
                        path.addLine(
                            to: CGPoint(x: x(commit.lane), y: y(Int(parent)) - nodeRadius))
                    } else {
                        // Elbow at the child row, then straight down the
                        // parent lane to the parent node.
                        let yMid = y(row) + rowHeight * 0.4
                        let yCurve = yMid + rowHeight * 0.2
                        path.move(to: CGPoint(x: x(commit.lane), y: y(row) + nodeRadius))
                        path.addLine(to: CGPoint(x: x(commit.lane), y: yMid))
                        path.addQuadCurve(
                            to: CGPoint(x: x(parentCommit.lane), y: yCurve),
                            control: CGPoint(x: x(commit.lane), y: yCurve))
                        path.addLine(
                            to: CGPoint(x: x(parentCommit.lane), y: y(Int(parent)) - nodeRadius))
                    }
                    context.stroke(path, with: .color(color), lineWidth: 1.5)
                }
            }
            for (row, commit) in commits.enumerated() {
                let center = CGPoint(x: x(commit.lane), y: y(row))
                let rect = CGRect(
                    x: center.x - nodeRadius, y: center.y - nodeRadius,
                    width: nodeRadius * 2, height: nodeRadius * 2)
                let color = Self.color(for: commit.lane)
                if commit.parents.count > 1 {
                    // Merge commits draw as rings, like gitk.
                    context.stroke(
                        Path(ellipseIn: rect), with: .color(color), lineWidth: 2)
                } else {
                    context.fill(Path(ellipseIn: rect), with: .color(color))
                }
                if commit.isHead {
                    let ring = rect.insetBy(dx: -3, dy: -3)
                    context.stroke(
                        Path(ellipseIn: ring), with: .color(.accentColor),
                        lineWidth: 1.5)
                }
            }
        }
        .frame(
            width: width,
            height: CGFloat(commits.count) * rowHeight)
    }

    private func commitRows(_ graph: GitGraphInfo) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(graph.commits, id: \.oid) { commit in
                HStack(spacing: 8) {
                    ForEach(commit.refs, id: \.self) { ref in
                        Text(ref)
                            .font(.system(size: 9, weight: .semibold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(
                                Capsule().fill(Self.color(for: commit.lane).opacity(0.9)))
                            .foregroundStyle(.white)
                    }
                    Text(commit.summary.isEmpty ? "—" : commit.summary)
                        .font(.system(size: 12))
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Spacer(minLength: 20)
                    Text(commit.authorName)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .frame(maxWidth: 140, alignment: .trailing)
                    Text(Self.relativeFormatter.localizedString(
                        for: Date(timeIntervalSince1970: Double(commit.timeMs) / 1000),
                        relativeTo: Date()))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: 80, alignment: .trailing)
                    Text(commit.shortOid)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.tertiary)
                }
                .padding(.horizontal, 10)
                .frame(height: rowHeight)
                // maxWidth lets rows stretch to the viewport floor, so
                // the author/date/oid columns reach the right edge.
                .frame(minWidth: 420, maxWidth: .infinity, alignment: .leading)
                .background(
                    commit.isHead ? Color.accentColor.opacity(0.08) : Color.clear)
                .contentShape(Rectangle())
                .onTapGesture { openCommitOnRemote(commit) }
                .help(remoteHelp(for: "commit"))
                .contextMenu {
                    Button("Open on Remote") { openCommitOnRemote(commit) }
                        .disabled(graph.remoteUrl == nil)
                }
                .id(commit.oid)
            }
        }
    }

    // MARK: Open on remote

    /// Tooltip for clickable rows. Empty when the repo has no remote,
    /// which suppresses the tooltip.
    private func remoteHelp(for kind: String) -> String {
        graph?.remoteUrl == nil ? "" : "Open \(kind) on remote"
    }

    private func openCommitOnRemote(_ commit: GitCommitInfo) {
        guard let remote = graph?.remoteUrl,
            let url = GitRemoteURL.commitURL(remote: remote, oid: commit.oid)
        else { return }
        NSWorkspace.shared.open(url)
    }

    private func openBranchOnRemote(_ branch: GitBranchInfo) {
        guard let remote = graph?.remoteUrl,
            let url = GitRemoteURL.branchURL(
                remote: remote, branch: branch.name, isLocal: branch.isLocal)
        else { return }
        NSWorkspace.shared.open(url)
    }

    // MARK: Load

    private func load() async {
        guard let directory else {
            // No open window: fall back to the empty state.
            graph = nil
            errorMessage = nil
            isLoading = false
            return
        }
        let target = directory.path
        let engine = model.engine
        isLoading = true
        errorMessage = nil
        let result = await Task.detached(priority: .userInitiated) {
            engine.gitGraph(dir: target, limit: limit)
        }.value
        graph = result
        isLoading = false
        if let result {
            // Report how wide the content wants to be so ContentView can
            // route window growth to the truncated pane first.
            let maxLane = result.commits.map(\.lane).max() ?? 0
            let canvasWidth = CGFloat(maxLane + 1) * laneWidth + laneWidth
            targetWindow?.gitPanelIdealWidth = Double(160 + canvasWidth + 420 + 24)
        } else {
            errorMessage = "Not a git repository"
            // No content wants extra width for the error message.
            targetWindow?.gitPanelIdealWidth = 0
        }
    }

    // MARK: Shared styling

    static func color(for lane: UInt32) -> Color {
        palette[Int(lane) % palette.count]
    }

    private static let palette: [Color] = [
        Color(red: 0.32, green: 0.61, blue: 0.94),
        Color(red: 0.40, green: 0.72, blue: 0.40),
        Color(red: 0.93, green: 0.61, blue: 0.25),
        Color(red: 0.70, green: 0.45, blue: 0.85),
        Color(red: 0.25, green: 0.70, blue: 0.75),
        Color(red: 0.85, green: 0.45, blue: 0.62),
        Color(red: 0.55, green: 0.55, blue: 0.35),
        Color(red: 0.50, green: 0.55, blue: 0.65),
    ]

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter
    }()
}
