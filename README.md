<p align="center">
  <img src="logo.png" alt="Orka logo" width="140">
</p>

<h1 align="center">Orka</h1>

<p align="center">
  <strong>A Finder replacement for work across your Mac, remote storage, and Git repositories.</strong>
</p>

<p align="center">
  Orka replaces Finder with browser-style navigation, built-in remote access, and the tools you need to understand and move files.
</p>

<p align="center">
  <a href="https://github.com/liam-mcelhaney122/Orka/actions/workflows/ci.yml"><img src="https://github.com/liam-mcelhaney122/Orka/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/macOS-26-blue" alt="macOS 26">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license">
</p>

<p align="center">
  <a href="https://github.com/liam-mcelhaney122/Orka/releases/latest"><strong>Download the latest release</strong></a>
</p>

---

## Move through files like the web

Open folders in browser-style tabs. Give tabs colors, restore them between sessions, and move any tab into a separate window. Keep multiple independent windows open when one workspace is not enough.

Drag files onto a tab to switch to it and send the files to that folder. You can also drop files directly onto folders in the sidebar.

## One place for every location

Browse local files and remote storage through the same navigation model. Orka connects to:

- SFTP and RSync over SSH (password, SSH key with optional certificate, or SSH agent)
- S3 and S3-compatible storage (AWS profile with SSO, assumed role, or credential process; access keys with optional session token; anonymous)
- FTP and FTPS (password or anonymous)
- SMB (password, Kerberos, or guest)
- NFS (no sign-in or Kerberos)
- Azure Data Lake Storage Gen2 (account key, SAS token, service principal, or in-app sign-in)
- Google Drive (in-app sign-in or service account)
- Dropbox (in-app sign-in)

Save connections beside your favorite folders and mounted volumes. Press Space to use Quick Look with local or remote files.

## See more before you open a file

- **Git context:** See file status in each listing. Open the commit graph in a panel or a separate window.
- **Useful search:** Filter the current folder as you type. Press Return to search recursively. Use patterns such as `*.pdf` to filter by extension.
- **Real folder sizes:** See recursive folder totals in the Size column and status bar. Orka calculates them in the background.
- **Live updates:** See local file changes as they happen. You do not need to refresh the folder.

## File work without losing your place

Copy, move, duplicate, rename, and create folders while Orka tracks active work in the status bar. Long operations run in the background, show progress, and can be canceled.

When names collide, choose Replace, Keep Both, or Skip. Orka creates Finder-style numbered copies when you keep both items.

For local files, create ZIP, TAR, and TAR.GZ archives, or extract archives in place. Use undo and redo for supported file operations.

For faster navigation, use reorderable favorites, direct path entry with Command-L, Open in Terminal, and the hidden-file toggle.

## Why not Finder?

Finder remains the standard macOS file browser. Orka is for workflows that need more context and fewer separate tools.

| Workflow | What Orka adds |
| --- | --- |
| Work across many folders | Colored tabs, session restore, tab-to-window movement, and multiple independent windows |
| Move files between open locations | Drop files onto tabs or sidebar folders |
| Browse remote storage | SFTP, S3, FTP, FTPS, SMB, NFS, Azure Data Lake, Google Drive, and Dropbox beside local files |
| Work in repositories | File-level Git status and a built-in commit graph |
| Inspect large folder trees | Recursive search, extension filters, and calculated folder sizes |
| Manage long file operations | Background progress, cancellation, archive tools, and undo or redo |

## Install

Orka requires macOS 26. Releases are signed with a Developer ID certificate and notarized by Apple.

### Homebrew

```sh
brew install --cask liam-mcelhaney122/tap/orka
```

Update to a new version with:

```sh
brew upgrade --cask orka
```

### Manual download

Download and unzip the [latest release](https://github.com/liam-mcelhaney122/Orka/releases/latest). Move `Orka.app` to `/Applications`.

### First launch

Grant **Full Disk Access** when Orka asks for it. Orka needs this access for protected locations such as Trash. The app opens the correct System Settings page.

## Contribute and build

Development requires macOS 26, a full Xcode installation, the stable Rust toolchain, XcodeGen, and [`just`](https://github.com/casey/just). Build a release and run all tests with:

```sh
just release
just test
```

## License

Orka is available under the [MIT License](LICENSE).
