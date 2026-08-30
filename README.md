# Orka

A macOS file manager. Rust core, SwiftUI shell.

## Layout

```
crates/orka-core   Filesystem model and directory listing. Pure Rust, no UI.
crates/orka-ffi    Swift-facing API. UniFFI generates the Swift bindings.
app/                 SwiftUI app. XcodeGen generates the Xcode project.
scripts/             Build helpers.
```

## Requirements

- Rust (rustup, stable toolchain)
- Xcode (full install, not only Command Line Tools)
- XcodeGen (`brew install xcodegen`)

## Build

1. Build the Rust core and regenerate the Swift bindings:

   ```sh
   ./scripts/build-rust.sh
   ```

2. Generate the Xcode project and build the app:

   ```sh
   cd app
   xcodegen
   xcodebuild -project Orka.xcodeproj -scheme Orka build
   ```

   If `xcodebuild` reports a Command Line Tools error, prefix the command with
   `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`, or run
   `sudo xcode-select -s /Applications/Xcode.app` once.

3. Open `app/Orka.xcodeproj` in Xcode for normal development. Run
   `./scripts/build-rust.sh` again after each Rust change.

## Test

```sh
cargo test
```

## How the bridge works

- `orka-ffi` builds a static library (`liborka_ffi.a`) that the app links.
- UniFFI generates `app/Generated/orka_ffi.swift` and a C header from the
  same crate. The app imports the header through a bridging header.
- Rust functions marked `#[uniffi::export]` appear in Swift as plain
  functions that `throw` `OrkaError`.

## Current state

- Browse directories, double-click to open folders and files.
- Back and up navigation, hidden-files toggle, size and date columns.
- Sorted directories-first, case-insensitive.
- Git integration: per-file status badges, the current branch in the
  status bar, linked worktree support, and a GitKraken-style branch
  panel with a lane graph of commits and merges.
- The status bar shows the folder's recursive size next to the free
  space, and the toolbar has an "Open in Terminal" button that launches
  the user's default terminal at the current folder.
- Remote file servers: SFTP, S3, FTP, SMB, NFS, ADLS Gen2, Google
  Drive, Dropbox, and RSync over SSH. Saved connections live in the
  sidebar; secrets stay in the keychain. The backends stream transfers
  through the shared operations engine, so progress, cancel, and undo
  work the same as local operations.
- Archive support: compress selected items to zip, tar, or tar.gz and
  extract them again, from the file context menus, with progress and
  undo.
- Chrome-style tabs with per-tab colors.

## Planned

Dual-pane, Quick Look for remote files, tags, and in-app OAuth flows
for the token-based services.
