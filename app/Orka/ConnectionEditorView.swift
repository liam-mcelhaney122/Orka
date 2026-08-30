import AppKit
import SwiftUI

/// Identifies which connection the editor sheet opens for. A nil
/// `connection` means "new"; the generated id becomes the saved
/// connection's id.
struct ConnectionEditorTarget: Identifiable {
    let id: String
    let connection: StoredConnection?

    init(editing connection: StoredConnection) {
        id = connection.id
        self.connection = connection
    }

    init() {
        id = "new-" + UUID().uuidString
        connection = nil
    }
}

/// Add/edit sheet for one saved connection, opened from the sidebar's
/// Connections section. Fields adapt to the chosen scheme: SFTP and
/// RSync offer Password, SSH Key, and SSH Agent; S3 offers Profile and
/// Access Keys; SMB, NFS, and FTP offer Password only; ADLS offers an
/// account key or an OAuth token; Google Drive and Dropbox use an OAuth
/// token.
struct ConnectionEditorView: View {
    let target: ConnectionEditorTarget

    @Environment(\.dismiss) private var dismiss
    private var model: AppModel { AppModel.shared }

    @State private var displayName: String
    @State private var scheme: StoredScheme
    @State private var host: String
    @State private var port: String
    @State private var username: String
    @State private var initialPath: String
    @State private var authKind: AuthKind
    @State private var keyPath: String
    @State private var profile: String
    @State private var secret: String

    init(target: ConnectionEditorTarget) {
        self.target = target
        let existing = target.connection
        _displayName = State(initialValue: existing?.displayName ?? "")
        _scheme = State(initialValue: existing?.scheme ?? .sftp)
        _host = State(initialValue: existing?.host ?? "")
        _port = State(
            initialValue: existing.map { String($0.port) }
                ?? String(StoredScheme.sftp.defaultPort))
        _username = State(initialValue: existing?.username ?? "")
        _initialPath = State(initialValue: existing?.initialPath ?? "/")
        _authKind = State(initialValue: existing?.auth.kind ?? .password)
        _keyPath = State(initialValue: existing?.auth.keyPath ?? "")
        _profile = State(initialValue: existing?.auth.profile ?? "")
        _secret = State(initialValue: "")
    }

    private var isNew: Bool { target.connection == nil }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            form
            Divider()
            footer
        }
        .frame(width: 420)
        .onChange(of: scheme) { oldValue, newValue in
            if port.isEmpty || port == String(oldValue.defaultPort) {
                port = String(newValue.defaultPort)
            }
            if !availableAuthKinds.contains(authKind) {
                authKind = availableAuthKinds[0]
            }
        }
    }

    private var header: some View {
        Text(isNew ? "New Connection" : "Edit Connection")
            .font(.headline)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
    }

    private var form: some View {
        Form {
            TextField("Name", text: $displayName)
            Picker("Scheme", selection: $scheme) {
                ForEach(availableSchemes, id: \.self) { scheme in
                    Text(scheme.label).tag(scheme)
                }
            }
            TextField("Host", text: $host)
            hostHint
            TextField("Port", text: $port)
            TextField(usernameLabel, text: $username)
            TextField("Initial Path", text: $initialPath)
            Picker("Auth", selection: $authKind) {
                ForEach(availableAuthKinds, id: \.self) { kind in
                    Text(kind.rawValue).tag(kind)
                }
            }
            if scheme == .nfs {
                Text("No sign-in is needed; the mount runs as your user.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            authFields
        }
        .padding(16)
    }

    /// ADLS identifies the container as the username, so the label
    /// must say "Filesystem" even though the value stays in `username`.
    private var usernameLabel: String {
        scheme == .adls ? "Filesystem" : "Username"
    }

    /// One-line format hint under the Host field. Schemes with a plain
    /// hostname get no hint.
    @ViewBuilder
    private var hostHint: some View {
        switch scheme {
        case .smb:
            hintCaption("server/share")
        case .nfs:
            hintCaption("server:/export")
        case .adls:
            hintCaption("account.dfs.core.windows.net")
        case .gdrive:
            hintCaption("drive.google.com")
        case .dropbox:
            hintCaption("dropbox.com")
        case .sftp, .s3, .ftp, .rsync:
            EmptyView()
        }
    }

    private func hintCaption(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    @ViewBuilder
    private var authFields: some View {
        switch authKind {
        case .password, .s3Keys:
            SecureField(
                authKind == .password ? "Password" : "Secret Access Key",
                text: $secret)
            if !isNew {
                Text("Leave blank to keep the saved secret.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .sshKey:
            HStack(spacing: 6) {
                TextField("Key Path", text: $keyPath)
                Button("Choose…") { chooseKeyFile() }
                    .help("Pick the private key file")
            }
            SecureField("Passphrase", text: $secret)
            Text(
                isNew
                    ? "Only needed for an encrypted key. Stored in your keychain."
                    : "Only needed for an encrypted key. Stored in your keychain. "
                        + "Leave blank to keep the saved passphrase."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        case .sshAgent:
            EmptyView()
        case .s3Profile:
            TextField("Profile", text: $profile)
        case .oauthToken:
            SecureField("Access Token", text: $secret)
            Text("Paste an OAuth access token. It is stored in your keychain.")
                .font(.caption)
                .foregroundStyle(.secondary)
        case .sharedKey:
            SecureField("Account Key", text: $secret)
            Text("Paste the base64 storage account key. It is stored in your keychain.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("Cancel") { dismiss() }
                // Clear tint keeps macOS glass buttons neutral; a tinted
                // glass button renders with a color wash on macOS.
                .buttonStyle(.glass)
                .tint(.clear)
                .keyboardShortcut(.cancelAction)
                .help("Discard changes")
            Button("Done") { save() }
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
                .help("Save the connection")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    /// Schemes the picker offers. S3 and FTP have no backend yet, so new
    /// connections hide them. A saved connection keeps its scheme so the
    /// picker selection stays in the list.
    private var availableSchemes: [StoredScheme] {
        StoredScheme.allCases.filter { candidate in
            candidate != .s3 && candidate != .ftp
                || candidate == target.connection?.scheme
        }
    }

    private var availableAuthKinds: [AuthKind] {
        switch scheme {
        case .sftp, .rsync: return [.password, .sshKey, .sshAgent]
        case .s3: return [.s3Profile, .s3Keys]
        case .ftp, .smb, .nfs: return [.password]
        case .adls: return [.sharedKey, .oauthToken]
        case .gdrive, .dropbox: return [.oauthToken]
        }
    }

    /// The port field parsed into the valid TCP range, or nil.
    private var portNumber: UInt32? {
        guard let value = UInt32(port), (1...65535).contains(value) else {
            return nil
        }
        return value
    }

    private var isValid: Bool {
        !displayName.trimmingCharacters(in: .whitespaces).isEmpty
            && !host.trimmingCharacters(in: .whitespaces).isEmpty
            && portNumber != nil
    }

    /// File picker for the private key. Keys live in ~/.ssh, which is
    /// hidden, so the panel starts there and shows hidden files.
    private func chooseKeyFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh")
        if panel.runModal() == .OK, let url = panel.url {
            keyPath = url.path
        }
    }

    private func save() {
        guard let portNumber else { return }
        let auth: StoredAuthMethod
        switch authKind {
        case .password: auth = .password
        case .sshKey: auth = .sshKey(keyPath: keyPath)
        case .sshAgent: auth = .sshAgent
        case .s3Profile: auth = .s3Profile(profile: profile)
        case .s3Keys: auth = .s3Keys
        case .oauthToken: auth = .oauthToken
        case .sharedKey: auth = .sharedKey
        }
        let config = StoredConnection(
            id: target.connection?.id ?? UUID().uuidString,
            displayName: displayName, scheme: scheme, host: host,
            port: portNumber, username: username,
            initialPath: StoredConnection.normalizedInitialPath(initialPath),
            auth: auth)
        model.saveConnection(
            config, secret: secret.isEmpty ? nil : secret)
        dismiss()
    }
}
