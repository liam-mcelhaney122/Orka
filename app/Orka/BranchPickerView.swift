import SwiftUI

/// Popover for switching or creating a git branch in the directory's
/// repository. Reached from the branch name in the status bar.
struct BranchPickerView: View {
    let directory: DirectoryModel
    /// Called after a successful checkout so the owner can reload the
    /// pane and refresh the status bar.
    var onSwitched: () -> Void

    @State private var branches: [GitBranchInfo] = []
    @State private var isLoading = true
    @State private var newBranchName = ""
    /// Shorthand the new branch starts from; HEAD means the current
    /// commit, whatever HEAD points at.
    @State private var baseBranch = "HEAD"
    @State private var errorMessage: String?
    @State private var isSwitching = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Switch Branch").font(.headline)
            if isLoading {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Loading branches…").foregroundStyle(.secondary)
                }
            } else if branches.isEmpty {
                Text("No branches found").foregroundStyle(.secondary)
            } else {
                branchList
            }
            Divider()
            newBranchRow
            baseRow
            if let errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .font(.caption)
                    .lineLimit(3)
            }
        }
        .padding(12)
        .frame(width: 280)
        .task { loadBranches() }
    }

    private var branchList: some View {
        List {
            Section("Local") {
                ForEach(localBranches, id: \.name) { branch in
                    Button {
                        switchTo(branch.name, base: nil, create: false)
                    } label: {
                        HStack {
                            Text(branch.name).lineLimit(1)
                            Spacer()
                            if branch.isHead {
                                Image(systemName: "checkmark")
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(isSwitching || branch.isHead)
                }
            }
            if !remoteBranches.isEmpty {
                Section("Remote") {
                    ForEach(remoteBranches, id: \.name) { branch in
                        Button {
                            checkoutRemote(branch.name)
                        } label: {
                            HStack {
                                Text(branch.name).lineLimit(1)
                                Spacer()
                                if hasLocalTrackingBranch(branch.name) {
                                    Image(systemName: "arrow.turn.down.right")
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .buttonStyle(.plain)
                        .disabled(isSwitching)
                        .help("Check out a local branch that tracks this one")
                    }
                }
            }
        }
        .listStyle(.bordered)
        .frame(height: listHeight)
    }

    private var newBranchRow: some View {
        HStack {
            TextField("New branch name", text: $newBranchName)
                .textFieldStyle(.roundedBorder)
                .onSubmit(createAndSwitch)
            Button("Create") { createAndSwitch() }
                .disabled(trimmedName.isEmpty || isSwitching)
        }
    }

    private var baseRow: some View {
        HStack {
            Text("Start from").foregroundStyle(.secondary)
            Spacer()
            Picker("Start from", selection: $baseBranch) {
                Text("Current HEAD").tag("HEAD")
                ForEach(branches, id: \.name) { branch in
                    Text(branch.name).tag(branch.name)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .frame(width: 160)
        }
    }

    private var localBranches: [GitBranchInfo] {
        branches.filter { $0.isLocal }
    }

    private var remoteBranches: [GitBranchInfo] {
        branches.filter { !$0.isLocal }
    }

    private var listHeight: CGFloat {
        let rows = localBranches.count + remoteBranches.count
        return min(CGFloat(rows) * 24 + (remoteBranches.isEmpty ? 8 : 48), 220)
    }

    private var trimmedName: String {
        newBranchName.trimmingCharacters(in: .whitespaces)
    }

    /// Local name for a remote-tracking branch shorthand such as
    /// "origin/main" -> "main".
    private func localName(for remote: String) -> String {
        remote.split(separator: "/", maxSplits: 1)
            .dropFirst()
            .joined(separator: "/")
    }

    private func hasLocalTrackingBranch(_ remote: String) -> Bool {
        let local = localName(for: remote)
        return localBranches.contains { $0.name == local }
    }

    /// Engine calls are synchronous and can block on repo IO, so they
    /// run detached and hop back to the main actor to update state.
    private func loadBranches() {
        let dir = directory.path
        let engine = AppModel.shared.engine
        Task.detached(priority: .userInitiated) {
            let list = engine.gitBranches(dir: dir)
            await MainActor.run {
                branches = list
                isLoading = false
            }
        }
    }

    private func switchTo(_ name: String, base: String?, create: Bool) {
        guard !isSwitching else { return }
        isSwitching = true
        errorMessage = nil
        let dir = directory.path
        let engine = AppModel.shared.engine
        Task.detached(priority: .userInitiated) {
            var failure: String?
            do {
                try engine.gitCheckoutBranch(dir: dir, name: name, base: base, create: create)
            } catch {
                failure = DirectoryModel.describe(error)
            }
            await MainActor.run {
                if let failure {
                    errorMessage = failure
                    isSwitching = false
                } else {
                    dismiss()
                    onSwitched()
                }
            }
        }
    }

    /// Checks out a local branch with the same name that tracks the
    /// remote branch, like `git checkout origin/main`.
    private func checkoutRemote(_ remote: String) {
        let local = localName(for: remote)
        guard !local.isEmpty else { return }
        switchTo(local, base: remote, create: true)
    }

    private func createAndSwitch() {
        let name = trimmedName
        guard !name.isEmpty else { return }
        switchTo(name, base: baseBranch == "HEAD" ? nil : baseBranch, create: true)
    }
}
