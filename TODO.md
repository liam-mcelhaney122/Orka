# TODO

## Done

- File servers with full backends:
  - SSH via RSync (SSH transport, rsync-style server-side copy)
  - ADLS Gen2 (shared-key auth)
  - SMB (mount_smbfs, Password or No Auth for guest access)
  - NFS (mount_nfs, no sign-in needed)
  - Google Drive (OAuth token)
  - Dropbox (OAuth token)
  - FTP and FTPS (Password or No Auth for anonymous login; FTPS
    supports implicit TLS on port 990 and explicit `AUTH TLS`
    elsewhere)
  - S3 (AWS profile or access keys; buckets list at the connection root)
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
- Multipart S3 uploads. Uploads today buffer the whole object, so very
  large files may fail.
- An explicit region field for S3 connections. Region comes from the
  host today; a custom endpoint defaults to us-east-1.