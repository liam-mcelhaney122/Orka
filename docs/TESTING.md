# Testing Orka

Orka's Rust test suite has three tiers. Each tier trades setup cost
for realism. Run the cheapest tier that answers your question.

| Tier | Command | Needs | Runs in CI |
| --- | --- | --- | --- |
| 1. Unit and offline connector tests | `cargo test --workspace` | Nothing | Every push and pull request (`rust` job) |
| 2. Opt-in daemon bench | `just bench` (after `just bench-up`) | Homebrew `samba`, `vsftpd`, `sudo` for one daemon | Every push and pull request (`bench` job), `continue-on-error: true` |
| 3. Manual live smoke | `just smoke-live` | Real cloud accounts, a Kerberos ticket | Never; run by hand before a release that touches auth |

## Tier 1: unit and offline connector tests

```
cargo test --workspace
```

This is the default tier. Nothing here starts a real system daemon,
opens a real network port outside loopback, or needs a package beyond
what `Cargo.toml` already declares. Two kinds of test live here:

- Ordinary unit tests, next to the code they cover (for example
  `crates/orka-core/src/vfs/mount.rs`'s own `mod tests`).
- Connector benches such as `crates/orka-core/tests/bench_s3.rs`,
  `bench_dropbox.rs`, `bench_gdrive.rs`, `bench_adls.rs`, `bench_ftp.rs`,
  and `bench_oauth.rs`. Despite the `bench_` prefix (kept for a
  consistent file-naming scheme across every connector test), these
  run every time: each one starts its own fake server in-process
  (`orka-bench`'s `fake_http`, `fake_aws`, `fake_dropbox`, `fake_drive`,
  `fake_adls`, `fake_oauth`, `libunftp`, `s3s-fs`, or `russh`) and talks
  to it over loopback. No `#[ignore]`, no external package, no
  variable to set.

### `ORKA_ENDPOINT_*` and `ORKA_EXTRA_CA_FILE`

Every REST-backed connector reads its base URL from an
`ORKA_ENDPOINT_*` variable before falling back to the real cloud
endpoint (see `crates/orka-core/src/vfs/endpoints.rs`). The tier-1
fake-server tests set these once per test binary, pointed at their own
fake server, so a real backend implementation runs against a
same-process fake instead of a hand-rolled stand-in:

- `ORKA_ENDPOINT_STS`, `ORKA_ENDPOINT_SSO_PORTAL` — AWS STS and SSO
  portal, for `AuthMethod::S3Profile`.
- `ORKA_ENDPOINT_GOOGLE_API`, `ORKA_ENDPOINT_GOOGLE_TOKEN`,
  `ORKA_ENDPOINT_GOOGLE_AUTH` — Google Drive and its OAuth endpoints.
- `ORKA_ENDPOINT_DROPBOX_API`, `ORKA_ENDPOINT_DROPBOX_CONTENT`,
  `ORKA_ENDPOINT_DROPBOX_AUTH`, `ORKA_ENDPOINT_DROPBOX_TOKEN` — Dropbox
  and its OAuth endpoints.
- `ORKA_ENDPOINT_AZURE_LOGIN` — Azure AD, for ADLS Gen2 OAuth.

`ORKA_EXTRA_CA_FILE` names a PEM file whose certificates are trusted
in addition to the public Mozilla root set (`webpki-roots`); it backs
every TLS client in `orka-core` (see
`crates/orka-core/src/vfs/http.rs::build_root_store`). Tier 1's fake
HTTPS servers use it to get a real client past a self-signed
certificate; tier 2's implicit-FTPS bench uses it the same way against
`bench/tls/ca.pem`.

You will not normally set any of these by hand: they exist so a test
can point a real client at a fake or bench server, and each test that
needs one sets it itself.

## Tier 2: the opt-in daemon bench

```
just bench-up      # start smbd, vsftpd (if possible), the NFS bench server, and sshd
just bench          # ORKA_BENCH=1 cargo test --workspace -- --include-ignored
just bench-down    # stop every daemon and sweep leftover mounts
```

This tier drives the mounted connectors (SMB, NFS) and implicit-TLS
FTPS against real system mount helpers and real daemons, in
`crates/orka-core/tests/bench_mounts.rs`. Every test in that file is
`#[ignore]` and returns immediately unless `ORKA_BENCH=1` is set, so
`cargo test --workspace` (tier 1) never touches this tier by accident,
and `cargo test -p orka-core --test bench_mounts` still compiles and
lists every test, just as ignored, with nothing installed.

### What `bench-up` starts, and on what port

| Daemon | Port | Package | Config | Optional? |
| --- | --- | --- | --- | --- |
| `smbd` | 4450 | Homebrew `samba` (`brew install samba`) | `bench/smb.conf` | Skipped if not installed |
| `vsftpd` | 990 (implicit TLS) | Homebrew `vsftpd` (`brew install vsftpd`) | `bench/vsftpd.conf` | Skipped if not installed, or if `sudo -n true` needs a password |
| `nfs_bench_server` (`crates/orka-core/examples/nfs_bench_server.rs`) | 23890 | None (built from this repo) | none | Always starts |
| `sshd` | 2222 | Apple's `/usr/sbin/sshd` | `bench/sshd_config` | Skipped if `sshd` is missing; nothing in this repo tests against it yet |

`bench-up` writes one PID file per daemon under `bench/run/`, and one
throwaway certificate authority and server certificate under
`bench/tls/` (generated with `openssl` the first time it runs). Both
directories are gitignored (`bench/.gitignore`) and safe to delete.
`bench-down` reads those PID files to stop exactly what `bench-up`
started, then sweeps anything still mounted under `~/Library/Application
Support/Orka/mounts` in case a bench test panicked mid-mount.

Homebrew's `smbd` is required, not the Apple-supplied `/usr/sbin/smbd`:
Apple's implementation is a different, closed daemon that cannot read
`bench/smb.conf`.

### Why vsftpd needs `sudo`, and NFS cannot use a custom port

Two bench daemons hit the same wall: **Orka's connection config has no
way to carry a non-standard port to certain schemes**, so the bench
server has to run on the standard port instead, which needs root.

- **Implicit-TLS FTPS.** `orka_core::vfs::ftp::is_implicit_tls_port`
  decides implicit-vs-explicit TLS by checking `ConnectionConfig::port
  == 990` exactly, and that same `port` field drives the real TCP dial
  (`connect_session` in that module). There is no way to dial a
  different port while still triggering implicit mode. `bench/vsftpd.conf`
  therefore listens on the real port 990, which needs root to bind, so
  `bench-up` starts it with `sudo` — and only if `sudo -n true` can run
  without a password prompt in the shell `bench-up` runs in.
  Otherwise it prints a skip message and leaves the FTPS bench
  unverified; `ftps_implicit_bench_connects_and_meets_conformance` in
  `bench_mounts.rs` checks the port is reachable and skips itself with
  the same message when it is not.
- **NFS.** A `nfsserve`-based bench server binds one arbitrary high
  port and never registers with a portmapper. `mount_nfs` reaches it
  only when both `port=` and `mountport=` name that port.
  `orka_core::vfs::mount` passes `ConnectionConfig::port` through as
  exactly those options, so `nfs_via_orka_mounts_and_meets_conformance`
  in `bench_mounts.rs` mounts through `MountFactory` and runs the
  shared conformance suite on the mount.
  `nfs_server_meets_conformance_with_the_documented_mount_options`
  mounts the same server by hand with the full option set the
  `nfsserve` README documents for macOS
  (`-o port=N,mountport=N,vers=3,nolocks,tcp`), as a check on the
  bench server itself.

The implicit FTPS limit above is a real limit of today's connection
config, documented here instead of worked around in `ftp`.

### Result of the unprivileged NFS mount experiment on this Mac

Run by hand, outside `cargo test`, to confirm the option set before
writing the bench:

```
$ /sbin/mount_nfs -o nolocks,vers=3,tcp,rsize=131072,actimeo=120,port=23890,mountport=23890 \
    localhost:/ /tmp/nfs_mnt_full
$ echo $?
0
$ mount | grep nfs_mnt_full
localhost:/ on /private/tmp/nfs_mnt_full (nfs, nodev, nosuid, mounted by liammcelhaney)
```

Mounted as a normal, non-root user: no `sudo` needed. Without
`port=`/`mountport=` the same command asks macOS's own on-demand
portmapper, which has no mapping for the bench server's port and
fails quickly with `Connection refused`. That is why `nfs_argv`
passes `ConnectionConfig::port` as both options.

The SMB bench signs in as the current Unix account with the password
`orka-bench`. Samba with `security = user` maps every login to a Unix
account, so `just bench-up` registers `$(id -un)` with `smbpasswd`
and the tests read the same name from `USER`. Set
`ORKA_BENCH_SMB_USER` in both places to use another account.

### Running just the mount bench

```
cargo test -p orka-core --test bench_mounts               # compiles; lists everything as ignored
ORKA_BENCH=1 cargo test -p orka-core --test bench_mounts -- --include-ignored nfs
just bench-up
ORKA_BENCH=1 cargo test -p orka-core --test bench_mounts -- --include-ignored
just bench-down
```

The NFS tests never need `bench-up`: each one starts and stops its own
`nfsserve` instance. The SMB and FTPS tests do need it, and skip
themselves with a clear message if the matching port is not reachable.

## Tier 3: manual live smoke tests

```
just smoke-live
# equivalently:
ORKA_LIVE=1 cargo test --workspace --test smoke_live -- --include-ignored
```

`crates/orka-core/tests/smoke_live.rs` holds `#[ignore]` tests against
real accounts and real servers: nothing here runs in CI, and nothing
here can, since each one needs a human credential step first. Every
test returns immediately, with a skip message, unless `ORKA_LIVE=1` is
set. Once it is set, a missing per-connector variable is a hard
failure with a message naming exactly what to set — at that point a
person asked for this tier on purpose.

| Test | Needs | Variables |
| --- | --- | --- |
| `smb_kerberos_live_smoke` | A Kerberos ticket (`kinit`) and a real SMB share | `ORKA_LIVE_SMB_HOST`, `ORKA_LIVE_SMB_USER` |
| `nfs_kerberos_live_smoke` | A Kerberos ticket and a real `sec=krb5` NFS export | `ORKA_LIVE_NFS_HOST` |
| `google_drive_live_smoke` | A completed Google sign-in (below) | `ORKA_LIVE_GOOGLE_CLIENT_ID`, `ORKA_LIVE_GOOGLE_TOKEN_JSON` |
| `dropbox_live_smoke` | A completed Dropbox sign-in (below) | `ORKA_LIVE_DROPBOX_CLIENT_ID`, `ORKA_LIVE_DROPBOX_TOKEN_JSON` |
| `azure_adls_live_smoke` | A completed Azure sign-in (below) | `ORKA_LIVE_AZURE_ACCOUNT`, `ORKA_LIVE_AZURE_FILESYSTEM`, `ORKA_LIVE_AZURE_TENANT_ID`, `ORKA_LIVE_AZURE_CLIENT_ID`, `ORKA_LIVE_AZURE_TOKEN_JSON` |

### Manual checklist: Kerberos SMB

1. Obtain a Kerberos ticket for an account that can reach the target
   share: `kinit user@REALM`.
2. Confirm the ticket: `klist` must show a non-expired ticket for that
   principal.
3. Set `ORKA_LIVE_SMB_HOST` to `server/share` (for example,
   `fileserver.example.com/homes`) and `ORKA_LIVE_SMB_USER` to the
   matching username, `DOMAIN;user` form included if the realm needs
   it.
4. Run `ORKA_LIVE=1 cargo test --workspace --test smoke_live -- --include-ignored smb_kerberos_live_smoke --nocapture`.
5. **Expected result:** the test connects and lists the share's root
   directory without error. A `mount_smbfs` failure naming "Permission
   denied" or "authentication" usually means the ticket expired or
   does not cover this share; re-run `kinit` and `klist`.

### Manual checklist: Kerberos NFS

1. Obtain a Kerberos ticket as above, for a principal the NFS export's
   `sec=krb5` policy accepts.
2. Set `ORKA_LIVE_NFS_HOST` to `server:/export` (for example,
   `nfs.example.com:/export/home`).
3. Run `ORKA_LIVE=1 cargo test --workspace --test smoke_live -- --include-ignored nfs_kerberos_live_smoke --nocapture`.
4. **Expected result:** the test connects and lists the export's root
   directory without error. `mount_nfs` reporting "not permitted" or a
   Kerberos-specific refusal usually means the ticket does not cover
   this export, or the export is not configured for `sec=krb5`.

### Manual checklist: live OAuth (Google Drive, Dropbox, Azure ADLS)

Each of these needs one interactive sign-in through Orka itself first,
since none of Google's, Dropbox's, or Azure's OAuth flows can be
scripted end to end from a test:

1. Run the Orka app (`just debug` or `just run`) and add a connection
   for the connector under test (Google Drive, Dropbox, or Azure ADLS
   with the OAuth-app auth method), using a real account.
2. Complete the browser sign-in Orka opens. **Expected result:** the
   connection shows as Connected in the app, and its folder listing
   loads.
3. Recover the token set Orka stored for that connection from the
   keychain (Keychain Access.app, or `security find-generic-password`,
   depending on how the app names the keychain item) and copy its JSON
   value into the matching `ORKA_LIVE_*_TOKEN_JSON` variable. Set the
   matching `ORKA_LIVE_*_CLIENT_ID` (and, for Azure,
   `ORKA_LIVE_AZURE_TENANT_ID`, `ORKA_LIVE_AZURE_ACCOUNT`, and
   `ORKA_LIVE_AZURE_FILESYSTEM`) to the values used in step 1.
4. Run `ORKA_LIVE=1 cargo test --workspace --test smoke_live -- --include-ignored google_drive_live_smoke --nocapture`
   (substitute `dropbox_live_smoke` or `azure_adls_live_smoke` for the
   other two).
5. **Expected result:** the test connects with the stored token and
   lists the account's root directory without error. A connect failure
   naming an expired or invalid token means the token needs refreshing
   — repeat step 1's sign-in and step 3's copy.

## Reference: every `ORKA_*` variable

| Variable | Tier | Purpose |
| --- | --- | --- |
| `ORKA_ENDPOINT_STS`, `ORKA_ENDPOINT_SSO_PORTAL` | 1 | Point AWS STS/SSO calls at a fake server |
| `ORKA_ENDPOINT_GOOGLE_API`, `ORKA_ENDPOINT_GOOGLE_TOKEN`, `ORKA_ENDPOINT_GOOGLE_AUTH` | 1 | Point Google Drive calls at a fake server |
| `ORKA_ENDPOINT_DROPBOX_API`, `ORKA_ENDPOINT_DROPBOX_CONTENT`, `ORKA_ENDPOINT_DROPBOX_AUTH`, `ORKA_ENDPOINT_DROPBOX_TOKEN` | 1 | Point Dropbox calls at a fake server |
| `ORKA_ENDPOINT_AZURE_LOGIN` | 1 | Point Azure AD calls at a fake server |
| `ORKA_EXTRA_CA_FILE` | 1, 2 | Trust an extra PEM certificate authority, for a fake or bench TLS server |
| `ORKA_BENCH` | 2 | `1` to run the opt-in daemon bench tests instead of skipping them |
| `ORKA_LIVE` | 3 | `1` to run the manual live smoke tests instead of skipping them |
| `ORKA_LIVE_SMB_HOST`, `ORKA_LIVE_SMB_USER` | 3 | Kerberos SMB target |
| `ORKA_LIVE_NFS_HOST` | 3 | Kerberos NFS target |
| `ORKA_LIVE_GOOGLE_CLIENT_ID`, `ORKA_LIVE_GOOGLE_TOKEN_JSON` | 3 | Google Drive live smoke |
| `ORKA_LIVE_DROPBOX_CLIENT_ID`, `ORKA_LIVE_DROPBOX_TOKEN_JSON` | 3 | Dropbox live smoke |
| `ORKA_LIVE_AZURE_ACCOUNT`, `ORKA_LIVE_AZURE_FILESYSTEM`, `ORKA_LIVE_AZURE_TENANT_ID`, `ORKA_LIVE_AZURE_CLIENT_ID`, `ORKA_LIVE_AZURE_TOKEN_JSON` | 3 | Azure ADLS Gen2 live smoke |
