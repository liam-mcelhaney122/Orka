# TODO

## Done

- File servers with full backends:
  - SSH via RSync (SSH transport, rsync-style server-side copy)
  - ADLS Gen2 (shared-key auth)
  - SMB (mount_smbfs)
  - NFS (mount_nfs)
  - Google Drive (OAuth token)
  - Dropbox (OAuth token)
- Compression and extraction: zip, tar, and tar.gz through context
  menus, with progress, cancel, and undo.
- Chrome-style tabs with angled active-tab feet.
- Colored tab options with a Tab Color context menu.
- Git panel grows to full content width first when the window expands;
  the file pane grows only after the panel fits.

## Remaining

- OAuth flows that mint tokens in-app (Dropbox, Google Drive, ADLS
  OAuth). Connections today paste an access token.
- Proactive cleanup of stale SMB/NFS mounts left by a killed process.
- Tab color persistence across launches.