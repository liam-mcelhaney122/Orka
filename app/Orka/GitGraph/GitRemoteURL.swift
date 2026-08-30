import Foundation

/// Builds web page URLs from a configured git remote. Accepts https,
/// ssh, git, and scp-style remote strings. Knows the path layouts of
/// GitHub, GitLab, and Bitbucket; an unknown host gets the GitHub
/// layout, which most forges copy.
enum GitRemoteURL {
    /// The repository home page for a remote URL string, or nil when
    /// the string has no recognizable host.
    static func repoURL(remote: String) -> URL? {
        var s = remote.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasSuffix("/") { s.removeLast() }
        if s.hasSuffix(".git") { s.removeLast(4) }
        if s.hasPrefix("https://") || s.hasPrefix("http://") {
            return URL(string: s)
        }
        if s.hasPrefix("ssh://") || s.hasPrefix("git://") {
            guard let url = URL(string: s), let host = url.host
            else { return nil }
            return URL(string: "https://\(host)\(url.path)")
        }
        // scp-style: [user@]host:path. A slash before the colon means a
        // plain filesystem path, which has no web page.
        guard let colon = s.firstIndex(of: ":") else { return nil }
        let hostPart = String(s[..<colon])
        guard !hostPart.isEmpty, !hostPart.contains("/") else { return nil }
        let host = hostPart.split(separator: "@").last.map(String.init) ?? hostPart
        let path = String(s[s.index(after: colon)...])
        guard !path.isEmpty else { return nil }
        return URL(string: "https://\(host)/\(path)")
    }

    /// The web page of one commit.
    static func commitURL(remote: String, oid: String) -> URL? {
        guard let base = repoURL(remote: remote), let host = base.host
        else { return nil }
        let path: String
        if host.contains("bitbucket") {
            path = "commits/\(oid)"
        } else if host.contains("gitlab") {
            path = "-/commit/\(oid)"
        } else {
            path = "commit/\(oid)"
        }
        return URL(string: base.absoluteString + "/" + path)
    }

    /// The web page of one branch. A remote-tracking name like
    /// "origin/feature" drops its remote prefix, because the forge
    /// names the branch without it.
    static func branchURL(remote: String, branch: String, isLocal: Bool) -> URL? {
        guard let base = repoURL(remote: remote), let host = base.host
        else { return nil }
        var name = branch
        if !isLocal, let slash = name.firstIndex(of: "/") {
            name = String(name[name.index(after: slash)...])
        }
        guard let encoded = name.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed)
        else { return nil }
        let path: String
        if host.contains("bitbucket") {
            path = "branch/\(encoded)"
        } else if host.contains("gitlab") {
            path = "-/tree/\(encoded)"
        } else {
            path = "tree/\(encoded)"
        }
        return URL(string: base.absoluteString + "/" + path)
    }
}
