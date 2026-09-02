# TODO

## Done

- File servers with full backends:
  - SFTP and RSync over SSH (password with a keyboard-interactive
    fallback, SSH key with an optional OpenSSH certificate, or SSH
    agent; rsync-style server-side copy)
  - ADLS Gen2 (account key, SAS token, service principal, or
    in-app sign-in)
  - SMB (mount_smbfs; Password, Kerberos, or No Auth for guest access)
  - NFS (mount_nfs; no sign-in or Kerberos)
  - Google Drive (in-app sign-in with token refresh, service account,
    or pasted token)
  - Dropbox (in-app sign-in with token refresh or pasted token)
  - FTP and FTPS (Password or No Auth for anonymous login; FTPS
    supports implicit TLS on port 990 and explicit `AUTH TLS`
    elsewhere)
  - S3 (AWS profile with SSO, assumed role, session token, or
    credential process; access keys with an optional session token;
    anonymous access; buckets list at the connection root)
- Compression and extraction: zip, tar, and tar.gz through context
  menus, with progress, cancel, and undo.
- Chrome-style tabs with angled active-tab feet.
- Colored tab options with a Tab Color context menu.
- Git panel grows to full content width first when the window expands;
  the file pane grows only after the panel fits.
- Remote locations: New File, New Folder, Rename, Duplicate, Get Info
  with a server stat, folder sizes, Copy and Cut from a remote pane,
  remote-to-remote drag and drop, and Open in the default app through
  a download to a temporary copy.

## Remaining

- Proactive cleanup of stale SMB/NFS mounts left by a killed process.
- Tab color persistence across launches.
- Multipart S3 uploads. Uploads today buffer the whole object, so very
  large files may fail.
- An explicit region field for S3 connections. Region comes from the
  host today; a custom endpoint defaults to us-east-1.

## Remote locations: future work

The core runs these operations on local paths only. The app shows "not supported on remote locations yet" for them.

- Move to Trash. No backend has a trash. Google Drive and Dropbox have
  a native trash API that could back the `can_trash` capability.
- Compress and Extract. The archive code reads and writes with
  `std::fs`. Remote support needs a stream through the backend, or a
  download, archive, and upload sequence.
- Conflict resolution on a remote transfer. The transfer fails with
  "an item with this name already exists". Replace and Keep Both need
  a resolution parameter and a pre-scan through `stat`.
- Auto-refresh. No backend can push change events. A remote pane
  refreshes only after a job completes. A polling loop keyed on
  `can_watch` would close the gap.
- Deep search. The search engine walks only local trees.
- Owner and permission columns. `Entry` carries no mode or owner.
  SFTP and mounted shares can supply them.
- Symlinks. Only the local, SFTP, and FTP backends report symlinks,
  and transfers skip them.
- Undo. Remote rename, create, duplicate, and delete record no undo
  entry.
- Sidebar tree. The sidebar lists local directories only.

Inherently local: Reveal in Finder, Open in Terminal, free space, Empty
Trash, and every git operation.
