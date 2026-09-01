import XCTest

/// Codable round-trip tests for `StoredAuthMethod` and `StoredScheme`.
/// A saved `connections.json` decodes by case name, so every case must
/// survive an encode/decode cycle unchanged.
final class ConnectionStoreTests: XCTestCase {

    private func roundTrip(_ auth: StoredAuthMethod) throws -> StoredAuthMethod {
        let data = try JSONEncoder().encode(auth)
        return try JSONDecoder().decode(StoredAuthMethod.self, from: data)
    }

    // MARK: - StoredAuthMethod, existing cases

    func testPasswordRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.password), .password)
    }

    func testSshKeyRoundTrips() throws {
        let auth = StoredAuthMethod.sshKey(keyPath: "/Users/liam/.ssh/id_ed25519")
        XCTAssertEqual(try roundTrip(auth), auth)
    }

    func testSshAgentRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.sshAgent), .sshAgent)
    }

    func testS3ProfileRoundTrips() throws {
        let auth = StoredAuthMethod.s3Profile(profile: "media")
        XCTAssertEqual(try roundTrip(auth), auth)
    }

    func testS3KeysRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.s3Keys), .s3Keys)
    }

    func testOauthTokenRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.oauthToken), .oauthToken)
    }

    func testSharedKeyRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.sharedKey), .sharedKey)
    }

    func testNoneRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.none), .none)
    }

    // MARK: - StoredAuthMethod, new cases

    func testSasTokenRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.sasToken), .sasToken)
    }

    func testServicePrincipalRoundTrips() throws {
        let auth = StoredAuthMethod.servicePrincipal(
            tenantId: "tenant-123", clientId: "client-456")
        XCTAssertEqual(try roundTrip(auth), auth)
    }

    func testOauthAppRoundTrips() throws {
        let auth = StoredAuthMethod.oauthApp(clientId: "client-789", tenantId: "")
        XCTAssertEqual(try roundTrip(auth), auth)
    }

    func testOauthAppWithTenantRoundTrips() throws {
        // ADLS is the one scheme where tenantId is non-empty.
        let auth = StoredAuthMethod.oauthApp(clientId: "client-789", tenantId: "tenant-abc")
        XCTAssertEqual(try roundTrip(auth), auth)
    }

    func testServiceAccountRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.serviceAccount), .serviceAccount)
    }

    func testKerberosRoundTrips() throws {
        XCTAssertEqual(try roundTrip(.kerberos), .kerberos)
    }

    // MARK: - StoredScheme.ftps

    func testFtpsSchemeRoundTrips() throws {
        let data = try JSONEncoder().encode(StoredScheme.ftps)
        let decoded = try JSONDecoder().decode(StoredScheme.self, from: data)
        XCTAssertEqual(decoded, .ftps)
    }

    func testFtpsSchemeRawValueIsStable() {
        // The raw value is also the URI scheme string; changing it would
        // break every saved FTPS connection and every ftps:// URI.
        XCTAssertEqual(StoredScheme.ftps.rawValue, "ftps")
    }

    func testFtpsSchemeDefaultsAndLabel() {
        XCTAssertEqual(StoredScheme.ftps.label, "FTPS")
        XCTAssertEqual(StoredScheme.ftps.defaultPort, 21)
    }

    // MARK: - StoredConnection with a full engine config

    func testFullConnectionWithNewAuthMethodRoundTrips() throws {
        let connection = StoredConnection(
            id: "conn-1", displayName: "My Storage", scheme: .adls,
            host: "myaccount.dfs.core.windows.net", port: 443,
            username: "filesystem",
            initialPath: "/",
            auth: .servicePrincipal(tenantId: "t", clientId: "c"))
        let data = try JSONEncoder().encode(connection)
        let decoded = try JSONDecoder().decode(StoredConnection.self, from: data)
        XCTAssertEqual(decoded, connection)
    }

    // MARK: - StoredAuthMethod field helpers

    func testTenantIdAndClientIdHelpers() {
        let servicePrincipal = StoredAuthMethod.servicePrincipal(
            tenantId: "t1", clientId: "c1")
        XCTAssertEqual(servicePrincipal.tenantId, "t1")
        XCTAssertEqual(servicePrincipal.clientId, "c1")

        let oauthApp = StoredAuthMethod.oauthApp(clientId: "c2", tenantId: "t2")
        XCTAssertEqual(oauthApp.tenantId, "t2")
        XCTAssertEqual(oauthApp.clientId, "c2")

        XCTAssertEqual(StoredAuthMethod.password.tenantId, "")
        XCTAssertEqual(StoredAuthMethod.password.clientId, "")
    }

    func testNeedsSecretForNewAuthMethods() {
        XCTAssertTrue(StoredAuthMethod.sasToken.needsSecret)
        XCTAssertTrue(
            StoredAuthMethod.servicePrincipal(tenantId: "t", clientId: "c").needsSecret)
        XCTAssertTrue(StoredAuthMethod.oauthApp(clientId: "c", tenantId: "").needsSecret)
        XCTAssertTrue(StoredAuthMethod.serviceAccount.needsSecret)
        XCTAssertFalse(StoredAuthMethod.kerberos.needsSecret)
    }

    func testKindMappingForNewAuthMethods() {
        XCTAssertEqual(StoredAuthMethod.sasToken.kind, .sasToken)
        XCTAssertEqual(
            StoredAuthMethod.servicePrincipal(tenantId: "t", clientId: "c").kind,
            .servicePrincipal)
        XCTAssertEqual(
            StoredAuthMethod.oauthApp(clientId: "c", tenantId: "").kind, .oauthApp)
        XCTAssertEqual(StoredAuthMethod.serviceAccount.kind, .serviceAccount)
        XCTAssertEqual(StoredAuthMethod.kerberos.kind, .kerberos)
    }
}
