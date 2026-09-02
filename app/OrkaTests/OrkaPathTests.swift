import XCTest

/// Tests for `OrkaPath`, which classifies a path string as local or
/// remote and derives display and navigation helpers for both kinds.
final class OrkaPathTests: XCTestCase {

    // MARK: - isLocal

    func testIsLocalTrueForAbsolutePath() {
        XCTAssertTrue(OrkaPath.isLocal("/foo/bar"))
    }

    func testIsLocalTrueForHomePath() {
        XCTAssertTrue(OrkaPath.isLocal("~/foo/bar"))
    }

    func testIsLocalTrueForBareTilde() {
        XCTAssertTrue(OrkaPath.isLocal("~"))
    }

    func testIsLocalFalseForRemoteUri() {
        XCTAssertFalse(OrkaPath.isLocal("sftp://myhost/some/dir"))
    }

    // MARK: - displayName

    func testDisplayNameLocalPathUsesLastComponent() {
        XCTAssertEqual(OrkaPath.displayName("/foo/bar/baz.txt"), "baz.txt")
    }

    func testDisplayNameRemotePathUsesLastComponent() {
        XCTAssertEqual(OrkaPath.displayName("sftp://myhost/some/dir"), "dir")
    }

    func testDisplayNameRemoteRootFallsBackToConnectionId() {
        XCTAssertEqual(OrkaPath.displayName("sftp://myhost"), "myhost")
    }

    func testDisplayNameRemoteRootWithTrailingSlashFallsBackToConnectionId() {
        XCTAssertEqual(OrkaPath.displayName("sftp://myhost/"), "myhost")
    }

    func testDisplayNameReturnsRawStringWhenNotRemoteParsable() {
        // No "://" and does not start with "/" or "~", so isLocal is
        // false but splitRemote also fails to parse it.
        XCTAssertEqual(OrkaPath.displayName("not-a-path"), "not-a-path")
    }

    // MARK: - splitRemote

    func testSplitRemoteWithPath() {
        let result = OrkaPath.splitRemote("sftp://myhost/some/dir")
        XCTAssertEqual(result?.connection, "myhost")
        XCTAssertEqual(result?.path, "/some/dir")
    }

    func testSplitRemoteBareConnectionHasEmptyPath() {
        let result = OrkaPath.splitRemote("sftp://myhost")
        XCTAssertEqual(result?.connection, "myhost")
        XCTAssertEqual(result?.path, "")
    }

    func testSplitRemoteTrailingSlashKeepsLeadingSlashInPath() {
        let result = OrkaPath.splitRemote("sftp://myhost/")
        XCTAssertEqual(result?.connection, "myhost")
        XCTAssertEqual(result?.path, "/")
    }

    func testSplitRemoteNilForLocalPath() {
        XCTAssertNil(OrkaPath.splitRemote("/some/local/path"))
    }

    // MARK: - remoteRoot

    func testRemoteRootWithPath() {
        XCTAssertEqual(OrkaPath.remoteRoot("sftp://myhost/some/dir"), "sftp://myhost")
    }

    func testRemoteRootBareConnection() {
        XCTAssertEqual(OrkaPath.remoteRoot("sftp://myhost"), "sftp://myhost")
    }

    func testRemoteRootNilForLocalPath() {
        XCTAssertNil(OrkaPath.remoteRoot("/some/local/path"))
    }

    // MARK: - remoteParent

    func testRemoteParentWalksUpOneComponent() {
        XCTAssertEqual(
            OrkaPath.remoteParent(of: "sftp://myhost/some/dir"),
            "sftp://myhost/some"
        )
    }

    func testRemoteParentOfSingleComponentReturnsRoot() {
        XCTAssertEqual(OrkaPath.remoteParent(of: "sftp://myhost/some"), "sftp://myhost")
    }

    func testRemoteParentTrailingSlashBehavesLikeNoTrailingSlash() {
        XCTAssertEqual(
            OrkaPath.remoteParent(of: "sftp://myhost/some/dir/"),
            "sftp://myhost/some"
        )
    }

    func testRemoteParentNilAtRootWithTrailingSlash() {
        // Already at the root: "myhost/" has nothing beyond the root
        // slash, so remoteParent returns nil rather than climbing above it.
        XCTAssertNil(OrkaPath.remoteParent(of: "sftp://myhost/"))
    }

    func testRemoteParentNilAtBareRoot() {
        // Already at the root with no trailing slash at all.
        XCTAssertNil(OrkaPath.remoteParent(of: "sftp://myhost"))
    }

    func testRemoteParentNilForLocalPath() {
        XCTAssertNil(OrkaPath.remoteParent(of: "/some/local/path"))
    }

    // MARK: - sameConnection

    func testSameConnectionTrueForSameHostDifferentPaths() {
        XCTAssertTrue(OrkaPath.sameConnection(
            "sftp://myhost/some/dir", "sftp://myhost/other/dir"))
    }

    func testSameConnectionFalseForDifferentHosts() {
        XCTAssertFalse(OrkaPath.sameConnection(
            "sftp://hostA/some/dir", "sftp://hostB/some/dir"))
    }

    func testSameConnectionFalseWhenFirstPathIsLocal() {
        XCTAssertFalse(OrkaPath.sameConnection(
            "/local/dir", "sftp://myhost/some/dir"))
    }

    func testSameConnectionFalseWhenSecondPathIsLocal() {
        XCTAssertFalse(OrkaPath.sameConnection(
            "sftp://myhost/some/dir", "/local/dir"))
    }

    func testSameConnectionFalseForTwoLocalPaths() {
        XCTAssertFalse(OrkaPath.sameConnection("/local/a", "/local/b"))
    }
}
