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

## Remaining

- Proactive cleanup of stale SMB/NFS mounts left by a killed process.
- Tab color persistence across launches.
- Multipart S3 uploads. Uploads today buffer the whole object, so very
  large files may fail.
- An explicit region field for S3 connections. Region comes from the
  host today; a custom endpoint defaults to us-east-1.