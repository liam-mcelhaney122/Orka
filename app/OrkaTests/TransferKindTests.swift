import XCTest

/// Tests for `TransferKind.derive`, which classifies a transfer from its
/// source and destination locality.
final class TransferKindTests: XCTestCase {

    func testLocalSourceToRemoteDestIsUpload() {
        let kind = TransferKind.derive(
            sources: ["/local/file.txt"],
            destDir: "sftp://myhost/remote/dir",
            move: false)
        XCTAssertEqual(kind, .upload)
    }

    func testRemoteSourceToLocalDestIsDownload() {
        let kind = TransferKind.derive(
            sources: ["sftp://myhost/remote/file.txt"],
            destDir: "/local/dir",
            move: false)
        XCTAssertEqual(kind, .download)
    }

    func testLocalToLocalWithoutMoveIsCopy() {
        let kind = TransferKind.derive(
            sources: ["/local/file.txt"],
            destDir: "/local/dest",
            move: false)
        XCTAssertEqual(kind, .copy)
    }

    func testLocalToLocalWithMoveIsMove() {
        let kind = TransferKind.derive(
            sources: ["/local/file.txt"],
            destDir: "/local/dest",
            move: true)
        XCTAssertEqual(kind, .move)
    }

    func testMultipleLocalSourcesToRemoteDestIsUpload() {
        let kind = TransferKind.derive(
            sources: ["/local/a.txt", "/local/b.txt"],
            destDir: "sftp://myhost/remote/dir",
            move: false)
        XCTAssertEqual(kind, .upload)
    }

    func testMultipleRemoteSourcesToLocalDestIsDownload() {
        let kind = TransferKind.derive(
            sources: [
                "sftp://myhost/remote/a.txt",
                "sftp://myhost/remote/b.txt",
            ],
            destDir: "/local/dir",
            move: false)
        XCTAssertEqual(kind, .download)
    }
}
