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
/// RSync offer Password, SSH Key, and SSH Agent; S3 offers Profile,
/// Access Keys, and No Auth; FTP and FTPS offer Password or No Auth
/// (anonymous login); SMB offers Password, Kerberos, or No Auth
/// (guest); NFS offers No Auth or Kerberos; ADLS offers an account
/// key, a SAS token, a service principal, an interactive sign-in, or a
/// pasted token; Google Drive and Dropbox offer an interactive
/// sign-in, and Google Drive also offers a service-account key file.
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
    /// S3 Access Keys only. Non-empty saves the secret as JSON with the
    /// secret access key, rather than as the plain key string.
    @State private var sessionToken: String
    /// Service Principal and Sign In (OAuth app) auth: the app's
    /// tenant. Empty except for ADLS.
    @State private var tenantIdField: String
    /// Service Principal and Sign In (OAuth app) auth: the app's
    /// client id.
    @State private var clientIdField: String
    /// Google Drive Sign In only. Some OAuth desktop clients (Google's
    /// among them) need the client secret on a token refresh even
    /// though the app is a public installed client. Passed to sign-in
    /// only; never saved on its own.
    @State private var oauthClientSecret: String
    /// Caption under the Sign In button: "Signed in" on success, or the
    /// failure reason. Nil before the first attempt.
    @State private var signInStatus: String?
    @State private var isSigningIn: Bool

    init(target: ConnectionEditorTarget) {
        self.target = target
        let existing = target.connection
        _displayName = State(initialValue: existing?.displayName ?? "")
        let initialScheme = existing?.scheme ?? .sftp
        _scheme = State(initialValue: initialScheme)
        _host = State(initialValue: existing?.host ?? "")
        _port = State(
            initialValue: existing.map { String($0.port) }
                ?? String(StoredScheme.sftp.defaultPort))
        _username = State(initialValue: existing?.username ?? "")
        _initialPath = State(initialValue: existing?.initialPath ?? "/")
        // A saved connection can predate its scheme's current auth
        // options (for example an NFS connection saved back when NFS
        // still offered Password). Clamp here too, not only in
        // onChange(of: scheme), or opening it renders a stale auth
        // kind's fields with no picker to correct them.
        let initialAuthKinds = Self.authKinds(for: initialScheme)
        let savedAuthKind = existing?.auth.kind ?? .password
        _authKind = State(
            initialValue: initialAuthKinds.contains(savedAuthKind)
                ? savedAuthKind : (initialAuthKinds.first ?? .none))
        _keyPath = State(initialValue: existing?.auth.keyPath ?? "")
        _profile = State(initialValue: existing?.auth.profile ?? "")
        _secret = State(initialValue: "")
        _sessionToken = State(initialValue: "")
        _tenantIdField = State(initialValue: existing?.auth.tenantId ?? "")
        _clientIdField = State(initialValue: existing?.auth.clientId ?? "")
        _oauthClientSecret = State(initialValue: "")
        _signInStatus = State(initialValue: nil)
        _isSigningIn = State(initialValue: false)
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
                authKind = availableAuthKinds.first ?? .none
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
            if scheme == .smb {
                hintCaption("DOMAIN;user for a domain account")
            }
            TextField("Initial Path", text: $initialPath)
            if !availableAuthKinds.isEmpty {
                Picker("Auth", selection: $authKind) {
                    ForEach(availableAuthKinds, id: \.self) { kind in
                        Text(kind.rawValue).tag(kind)
                    }
                }
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
        case .sftp, .s3, .ftp, .ftps, .rsync:
            EmptyView()
        }
    }

    private func hintCaption(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    /// "Leave blank to keep the saved secret" applies to every
    /// secret-bearing kind, but only once a saved secret exists.
    @ViewBuilder
    private var keepSecretHint: some View {
        if !isNew {
            Text("Leave blank to keep the saved secret.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var authFields: some View {
        switch authKind {
        case .password, .s3Keys:
            SecureField(
                authKind == .password ? "Password" : "Secret Access Key",
                text: $secret)
            if authKind == .s3Keys {
                SecureField("Session Token (optional)", text: $sessionToken)
            }
            keepSecretHint
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
            keepSecretHint
        case .sharedKey:
            SecureField("Account Key", text: $secret)
            Text("Paste the base64 storage account key. It is stored in your keychain.")
                .font(.caption)
                .foregroundStyle(.secondary)
            keepSecretHint
        case .sasToken:
            SecureField("SAS Token", text: $secret)
            Text("Paste the SAS query string. It is stored in your keychain.")
                .font(.caption)
                .foregroundStyle(.secondary)
            keepSecretHint
        case .servicePrincipal:
            TextField("Tenant ID", text: $tenantIdField)
            TextField("Client ID", text: $clientIdField)
            SecureField("Client Secret", text: $secret)
            keepSecretHint
        case .oauthApp:
            oauthAppFields
        case .serviceAccount:
            serviceAccountFields
        case .kerberos:
            Text("Uses your signed-in user's Kerberos ticket. No credentials are stored.")
                .font(.caption)
                .foregroundStyle(.secondary)
        case .none:
            EmptyView()
        }
    }

    @ViewBuilder
    private var oauthAppFields: some View {
        if scheme == .adls {
            TextField("Tenant ID", text: $tenantIdField)
        }
        TextField("Client ID", text: $clientIdField)
        if scheme == .gdrive {
            SecureField("Client Secret (optional)", text: $oauthClientSecret)
        }
        HStack(spacing: 6) {
            Button(isSigningIn ? "Signing In…" : "Sign In…") {
                Task { await signIn() }
            }
            .disabled(
                isSigningIn
                    || clientIdField.trimmingCharacters(in: .whitespaces).isEmpty)
            if isSigningIn {
                ProgressView().controlSize(.small)
            }
        }
        if let signInStatus {
            Text(signInStatus)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        keepSecretHint
    }

    @ViewBuilder
    private var serviceAccountFields: some View {
        HStack(spacing: 6) {
            Text(secret.isEmpty ? "No file chosen" : "JSON key selected")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Button("Choose JSON key…") { chooseServiceAccountFile() }
        }
        keepSecretHint
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

    /// Schemes the picker offers. Every scheme has a backend now,
    /// except FTPS, whose backend lands separately.
    private var availableSchemes: [StoredScheme] {
        StoredScheme.allCases
    }

    /// Auth kinds offered for the chosen scheme.
    ///
    /// A `static` function (not just this computed property) so `init`
    /// can clamp a saved connection's auth kind against its scheme's
    /// current options before the view ever renders — see the comment
    /// in `init`.
    private static func authKinds(for scheme: StoredScheme) -> [AuthKind] {
        switch scheme {
        case .sftp, .rsync: return [.password, .sshKey, .sshAgent]
        case .s3: return [.s3Profile, .s3Keys, .none]
        case .ftp, .ftps: return [.password, .none]
        case .smb: return [.password, .kerberos, .none]
        case .nfs: return [.none, .kerberos]
        case .adls: return [.sharedKey, .sasToken, .servicePrincipal, .oauthApp, .oauthToken]
        case .gdrive: return [.oauthApp, .serviceAccount, .oauthToken]
        case .dropbox: return [.oauthApp, .oauthToken]
        }
    }

    private var availableAuthKinds: [AuthKind] {
        Self.authKinds(for: scheme)
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

    /// File picker for a Google service-account JSON key. The file's
    /// full content becomes the secret; there is no separate path
    /// field to keep, since the app never re-reads the file.
    private func chooseServiceAccountFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json]
        if panel.runModal() == .OK, let url = panel.url,
            let content = try? String(contentsOf: url, encoding: .utf8)
        {
            secret = content
        }
    }

    /// Runs the interactive OAuth sign-in flow off the main thread and
    /// keeps the returned token-set JSON in `secret` so `save()` stores
    /// it. Tenant id is sent only for ADLS; client secret only for
    /// Google Drive, which some OAuth desktop clients require even for
    /// a public installed client.
    private func signIn() async {
        isSigningIn = true
        signInStatus = nil
        let engineScheme = scheme.toEngine()
        let clientId = clientIdField
        let tenantId = scheme == .adls ? tenantIdField : ""
        let clientSecret =
            (scheme == .gdrive && !oauthClientSecret.isEmpty) ? oauthClientSecret : nil
        let result = await Task.detached(priority: .userInitiated) {
            Result {
                try oauthSignIn(
                    scheme: engineScheme, clientId: clientId,
                    clientSecret: clientSecret, tenantId: tenantId)
            }
        }.value
        isSigningIn = false
        switch result {
        case .success(let json):
            secret = json
            signInStatus = "Signed in"
        case .failure(let error):
            signInStatus = DirectoryModel.describe(error)
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
        case .sasToken: auth = .sasToken
        case .servicePrincipal:
            auth = .servicePrincipal(tenantId: tenantIdField, clientId: clientIdField)
        case .oauthApp:
            auth = .oauthApp(
                clientId: clientIdField, tenantId: scheme == .adls ? tenantIdField : "")
        case .serviceAccount: auth = .serviceAccount
        case .kerberos: auth = .kerberos
        case .none: auth = .none
        }
        let config = StoredConnection(
            id: target.connection?.id ?? UUID().uuidString,
            displayName: displayName, scheme: scheme, host: host,
            port: portNumber, username: username,
            initialPath: StoredConnection.normalizedInitialPath(initialPath),
            auth: auth)
        model.saveConnection(config, secret: resolvedSecret())
        dismiss()
    }

    /// The secret to save. S3 Access Keys with a session token save a
    /// JSON object instead of the plain key, so the backend can tell
    /// the two forms apart (see `SecretFields` in the core crate).
    private func resolvedSecret() -> String? {
        if authKind == .s3Keys, !sessionToken.isEmpty {
            let payload = S3KeysSecret(secretAccessKey: secret, sessionToken: sessionToken)
            if let data = try? JSONEncoder().encode(payload),
                let json = String(data: data, encoding: .utf8)
            {
                return json
            }
        }
        return secret.isEmpty ? nil : secret
    }
}

/// JSON shape for an S3 Access Keys secret that also carries a session
/// token. Mirrors the field names `orka_core::vfs::secret::SecretFields`
/// reads on the backend side.
private struct S3KeysSecret: Codable {
    let secretAccessKey: String
    let sessionToken: String

    enum CodingKeys: String, CodingKey {
        case secretAccessKey = "secret_access_key"
        case sessionToken = "session_token"
    }
}
