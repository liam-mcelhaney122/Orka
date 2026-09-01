import Foundation
import Observation
import Security

/// One saved connection, persisted to disk. Mirrors `ConnectionConfig`
/// from the engine but stays Codable and holds no secret material; the
/// password or key passphrase lives in the keychain, keyed by `id`.
struct StoredConnection: Codable, Identifiable, Hashable {
    var id: String
    var displayName: String
    var scheme: StoredScheme
    var host: String
    var port: UInt32
    var username: String
    var initialPath: String
    var auth: StoredAuthMethod
}

/// Codable mirror of the engine's `Scheme`. The raw value is also the
/// URI scheme string ("sftp://", "s3://", "ftp://", "smb://", and so
/// on). Never remove a case; saved connections.json files decode by
/// raw value.
enum StoredScheme: String, Codable, CaseIterable {
    case sftp
    case s3
    case ftp
    case smb
    case nfs
    case adls
    case gdrive
    case dropbox
    case rsync

    var label: String {
        switch self {
        case .sftp: return "SFTP"
        case .s3: return "S3"
        case .ftp: return "FTP"
        case .smb: return "SMB"
        case .nfs: return "NFS"
        case .adls: return "ADLS Gen2"
        case .gdrive: return "Google Drive"
        case .dropbox: return "Dropbox"
        case .rsync: return "RSync (SSH)"
        }
    }

    var defaultPort: UInt32 {
        switch self {
        case .sftp: return 22
        case .s3: return 443
        case .ftp: return 21
        case .smb: return 445
        case .nfs: return 2049
        case .adls, .gdrive, .dropbox: return 443
        case .rsync: return 22
        }
    }
}

/// Codable mirror of the engine's `AuthMethod`. Carries no secret; the
/// secret text is written to the keychain separately.
enum StoredAuthMethod: Codable, Hashable {
    case password
    case sshKey(keyPath: String)
    case sshAgent
    case s3Profile(profile: String)
    case s3Keys
    case oauthToken
    case sharedKey
    /// No credentials: anonymous FTP, guest SMB, or a mount (NFS) whose
    /// transport has no auth step at all.
    case none
}

/// Which auth fields the editor shows. One per `StoredAuthMethod` case.
enum AuthKind: String, CaseIterable {
    case password = "Password"
    case sshKey = "SSH Key"
    case sshAgent = "SSH Agent"
    case s3Profile = "Profile"
    case s3Keys = "Access Keys"
    case oauthToken = "Token"
    case sharedKey = "Account Key"
    case none = "No Auth"
}

extension StoredAuthMethod {
    var kind: AuthKind {
        switch self {
        case .password: return .password
        case .sshKey: return .sshKey
        case .sshAgent: return .sshAgent
        case .s3Profile: return .s3Profile
        case .s3Keys: return .s3Keys
        case .oauthToken: return .oauthToken
        case .sharedKey: return .sharedKey
        case .none: return .none
        }
    }

    var keyPath: String {
        if case .sshKey(let path) = self { return path }
        return ""
    }

    var profile: String {
        if case .s3Profile(let name) = self { return name }
        return ""
    }

    /// True for auth methods that can keep a secret in the keychain.
    /// An SSH key's secret is an optional passphrase.
    var needsSecret: Bool {
        switch self {
        case .password, .sshKey, .s3Keys, .oauthToken, .sharedKey:
            return true
        case .sshAgent, .s3Profile, .none: return false
        }
    }
}

// MARK: Engine conversion

extension StoredConnection {
    func toEngineConfig() -> ConnectionConfig {
        ConnectionConfig(
            id: id, displayName: displayName, scheme: scheme.toEngine(),
            host: host, port: port, username: username,
            initialPath: initialPath, auth: auth.toEngine())
    }

    /// Remote URI the sidebar navigates to once this connection is live.
    var uri: String { "\(scheme.rawValue)://\(id)\(initialPath)" }

    /// Normalizes an editor-entered initial path. The URI form above
    /// concatenates it after the connection id, so the path must start
    /// with "/". Empty input means the remote root.
    static func normalizedInitialPath(_ path: String) -> String {
        if path.isEmpty { return "/" }
        return path.hasPrefix("/") ? path : "/" + path
    }
}

extension StoredScheme {
    func toEngine() -> Scheme {
        switch self {
        case .sftp: return .sftp
        case .s3: return .s3
        case .ftp: return .ftp
        case .smb: return .smb
        case .nfs: return .nfs
        case .adls: return .adls
        case .gdrive: return .gdrive
        case .dropbox: return .dropbox
        case .rsync: return .rsync
        }
    }
}

extension StoredAuthMethod {
    func toEngine() -> AuthMethod {
        switch self {
        case .password: return .password
        case .sshKey(let keyPath): return .sshKey(keyPath: keyPath)
        case .sshAgent: return .sshAgent
        case .s3Profile(let profile): return .s3Profile(profile: profile)
        case .s3Keys: return .s3Keys
        case .oauthToken: return .oAuthToken
        case .sharedKey: return .sharedKey
        case .none: return .none
        }
    }
}

/// Reads and writes the connection secret in the keychain. Service is
/// "Orka"; the account is the connection id. Matches the service name
/// `TrashDelegate.getSecret` reads on the engine side.
enum KeychainHelper {
    private static func query(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Orka",
            kSecAttrAccount as String: account,
        ]
    }

    /// Saves or replaces the secret for one connection.
    static func save(account: String, secret: String) {
        let base = query(account: account)
        let data = Data(secret.utf8)
        let status = SecItemCopyMatching(base as CFDictionary, nil)
        if status == errSecSuccess {
            SecItemUpdate(
                base as CFDictionary,
                [kSecValueData as String: data] as CFDictionary)
        } else {
            var attributes = base
            attributes[kSecValueData as String] = data
            SecItemAdd(attributes as CFDictionary, nil)
        }
    }

    static func delete(account: String) {
        SecItemDelete(query(account: account) as CFDictionary)
    }
}

/// Saved connections, persisted as JSON. Owned by `AppModel`; every
/// mutation is followed by pushing `toEngine()` to `engine.setConnections`.
@MainActor
@Observable
final class ConnectionStore {
    private(set) var connections: [StoredConnection] = []

    private let fileURL: URL

    init() {
        let support = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!
        let dir = support.appendingPathComponent("Orka", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("connections.json")
        load()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        connections =
            (try? JSONDecoder().decode([StoredConnection].self, from: data))
            ?? []
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(connections) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    /// Appends a new connection.
    func add(_ config: StoredConnection) {
        connections.append(config)
        persist()
    }

    /// Replaces an existing connection by id, or appends it when the id
    /// is not yet known.
    func update(_ config: StoredConnection) {
        guard let index = connections.firstIndex(where: { $0.id == config.id })
        else {
            add(config)
            return
        }
        connections[index] = config
        persist()
    }

    func remove(id: String) {
        connections.removeAll { $0.id == id }
        persist()
    }

    func toEngine() -> [ConnectionConfig] {
        connections.map { $0.toEngineConfig() }
    }
}
