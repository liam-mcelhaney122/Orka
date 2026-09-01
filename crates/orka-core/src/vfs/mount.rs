//! SMB and NFS backends served through the system mount helpers.
//!
//! A mount connection runs `mount_smbfs` or `mount_nfs` once at connect
//! time and then serves every filesystem call through [`LocalBackend`]
//! on the mounted directory. This reuses the local fast paths and keeps
//! protocol quirks inside the system helpers.
//!
//! Unmounting happens when the backend is dropped: after the router
//! drops the last reference, `Drop` runs `umount -f` (with a
//! `diskutil unmount force` fallback) and removes the mount directory.
//! `FsBackend` has no downcast, so callers cannot unmount explicitly;
//! dropping the backend is the unmount.

use super::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use super::http::url_encode;
use super::{Capabilities, FsBackend, LocalBackend, Scheme, WriteFinish};
use crate::{Entry, ListOptions};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

/// Deadline for one mount command. The helper can hang on an
/// unreachable server; without a deadline the connect worker blocks
/// forever.
const MOUNT_TIMEOUT: Duration = Duration::from_secs(20);
const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(10);

/// Creates SMB and NFS backends by mounting the share with the
/// system's mount helpers. The registry registers one instance per
/// scheme; both schemes route through the same connect path.
pub struct MountFactory;

impl BackendFactory for MountFactory {
    fn connect(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn FsBackend>, String> {
        let dir = mount_root_for(&config.id)?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create mount directory {}: {e}", dir.display()))?;
        // A previous session may have left the share mounted. Reuse it
        // so connect is idempotent.
        if is_mount_point(&dir) {
            return Ok(Arc::new(MountBackend { root: dir }));
        }
        match config.scheme {
            Scheme::Smb => self.connect_smb(config, secrets, dir),
            Scheme::Nfs => self.connect_nfs(config, dir),
            other => Err(format!("mount backend does not serve scheme {other:?}")),
        }
    }
}

impl MountFactory {
    fn connect_smb(
        &self,
        config: &ConnectionConfig,
        secrets: Arc<dyn SecretProvider>,
        dir: PathBuf,
    ) -> Result<Arc<dyn FsBackend>, String> {
        let secret = secrets.get_secret(&config.id);
        let url = build_smb_url(config, secret.as_deref())?;
        let binary = find_binary("mount_smbfs")
            .ok_or_else(|| "mount_smbfs not found on this system".to_string())?;
        let kerberos = config.auth == AuthMethod::Kerberos;
        let mut command = Command::new(binary);
        for arg in smb_argv(&url, &dir, kerberos) {
            command.arg(arg);
        }
        let outcome = run_with_timeout(command, MOUNT_TIMEOUT)?;
        finish_mount("mount_smbfs", outcome, dir, secret.as_deref(), false)
    }

    fn connect_nfs(
        &self,
        config: &ConnectionConfig,
        dir: PathBuf,
    ) -> Result<Arc<dyn FsBackend>, String> {
        validate_nfs_auth(&config.auth)?;
        let target = nfs_target(&config.host)?;
        let binary = find_binary("mount_nfs")
            .ok_or_else(|| "mount_nfs not found on this system".to_string())?;
        let kerberos = config.auth == AuthMethod::Kerberos;
        let mut command = Command::new(binary);
        for arg in nfs_argv(target, &dir, kerberos) {
            command.arg(arg);
        }
        let outcome = run_with_timeout(command, MOUNT_TIMEOUT)?;
        finish_mount("mount_nfs", outcome, dir, None, true)
    }
}

/// Shared tail of both connect paths: report timeouts, treat a failed
/// mount over an already-mounted directory as an idempotent success,
/// verify the mount is readable, and keep secrets out of error text.
fn finish_mount(
    binary: &str,
    outcome: RunOutcome,
    dir: PathBuf,
    secret: Option<&str>,
    admin_hint: bool,
) -> Result<Arc<dyn FsBackend>, String> {
    if outcome.timed_out {
        return Err("mount command timed out".to_string());
    }
    if !outcome.success {
        if is_mount_point(&dir) {
            return Ok(Arc::new(MountBackend { root: dir }));
        }
        let mut message = scrub_secret(&outcome.stderr, secret).trim().to_string();
        if admin_hint && message.to_lowercase().contains("not permitted") {
            message.push_str(" (NFS mounts need administrator rights)");
        }
        return Err(format!("{binary} failed: {message}"));
    }
    if std::fs::read_dir(&dir).is_err() {
        return Err(format!(
            "{binary} reported success but the mount is not readable"
        ));
    }
    Ok(Arc::new(MountBackend { root: dir }))
}

/// Serves one mounted SMB or NFS share. Paths are backend-local
/// strings (`/a/b`) that translate onto the mount directory. When the
/// router drops the last reference to this backend, `Drop` unmounts
/// the share and removes the mount directory.
pub struct MountBackend {
    root: PathBuf,
}

#[cfg(test)]
impl MountBackend {
    pub(crate) fn with_root(root: PathBuf) -> Self {
        Self { root }
    }
}

impl MountBackend {
    /// Maps a backend-local path onto the mount directory. `..` must
    /// never escape the mount root, so any non-normal component is an
    /// error.
    fn translate(&self, path: &str) -> Result<PathBuf, String> {
        let rel = path.strip_prefix('/').unwrap_or(path);
        if rel.is_empty() {
            return Ok(self.root.clone());
        }
        let rel_path = Path::new(rel);
        for component in rel_path.components() {
            match component {
                std::path::Component::Normal(_) | std::path::Component::CurDir => {}
                _ => return Err(format!("path not allowed: {path:?}")),
            }
        }
        Ok(self.root.join(rel_path))
    }

    /// Converts an absolute path inside the mount back to the
    /// backend-local form, so returned entries never leak the real
    /// mount location.
    fn to_local_path(&self, abs: &Path) -> String {
        match abs.strip_prefix(&self.root) {
            Ok(rel) if rel.as_os_str().is_empty() => "/".to_string(),
            Ok(rel) => format!("/{}", rel.to_string_lossy()),
            Err(_) => "/".to_string(),
        }
    }
}

impl FsBackend for MountBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            is_local: false,
            can_trash: false,
            can_watch: false,
            can_rename: true,
            server_side_copy: false,
            // SMB and NFS servers keep basic POSIX mode bits.
            preserves_permissions: true,
        }
    }

    fn list_dir(&self, path: &str, opts: &ListOptions) -> Result<Vec<Entry>, String> {
        let abs = self.translate(path)?;
        let entries = LocalBackend.list_dir(&abs.to_string_lossy(), opts)?;
        Ok(entries
            .into_iter()
            .map(|mut entry| {
                entry.path = self.to_local_path(Path::new(&entry.path));
                entry
            })
            .collect())
    }

    fn stat(&self, path: &str) -> Result<Entry, String> {
        let abs = self.translate(path)?;
        let mut entry = LocalBackend.stat(&abs.to_string_lossy())?;
        entry.path = self.to_local_path(&abs);
        Ok(entry)
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
        let abs = self.translate(path)?;
        LocalBackend.open_read(&abs.to_string_lossy())
    }

    fn create_write(
        &self,
        path: &str,
        size_hint: Option<u64>,
    ) -> Result<Box<dyn WriteFinish>, String> {
        let abs = self.translate(path)?;
        LocalBackend.create_write(&abs.to_string_lossy(), size_hint)
    }

    fn delete(&self, path: &str, recursive: bool) -> Result<(), String> {
        let abs = self.translate(path)?;
        LocalBackend.delete(&abs.to_string_lossy(), recursive)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let from = self.translate(from)?;
        let to = self.translate(to)?;
        LocalBackend.rename(&from.to_string_lossy(), &to.to_string_lossy())
    }

    fn mkdir(&self, path: &str) -> Result<(), String> {
        let abs = self.translate(path)?;
        LocalBackend.mkdir(&abs.to_string_lossy())
    }
}

impl Drop for MountBackend {
    fn drop(&mut self) {
        if !is_mount_point(&self.root) {
            let _ = std::fs::remove_dir(&self.root);
            return;
        }
        if let Some(binary) = find_binary("umount") {
            let mut command = Command::new(binary);
            command.arg("-f").arg(&self.root);
            let _ = run_with_timeout(command, UNMOUNT_TIMEOUT);
        }
        if is_mount_point(&self.root) {
            if let Some(binary) = find_binary("diskutil") {
                let mut command = Command::new(binary);
                command.arg("unmount").arg("force").arg(&self.root);
                let _ = run_with_timeout(command, UNMOUNT_TIMEOUT);
            }
        }
        if !is_mount_point(&self.root) {
            let _ = std::fs::remove_dir(&self.root);
        }
    }
}

/// Builds the `mount_smbfs` URL. The password goes in the URL because
/// mount_smbfs has no stdin or secret-file interface; percent-encoding
/// keeps special characters from splitting the URL. Error text never
/// contains the secret.
///
/// `AuthMethod::None` always builds a guest URL and never looks at
/// `secret`, even if a stale secret is still stored from an earlier
/// `Password` config: switching a saved connection to No Auth must not
/// silently keep authenticating with a leftover credential.
///
/// `AuthMethod::Kerberos` puts the username in the URL with no
/// password, so mount_smbfs authenticates with the caller's existing
/// ticket instead. The username can carry a `DOMAIN;user` form and
/// passes through unchanged.
fn build_smb_url(config: &ConnectionConfig, secret: Option<&str>) -> Result<String, String> {
    if !matches!(
        config.auth,
        AuthMethod::Password | AuthMethod::Kerberos | AuthMethod::None
    ) {
        return Err("wrong auth method for smb".to_string());
    }
    let (server, share) = config
        .host
        .split_once('/')
        .ok_or_else(|| "share name required".to_string())?;
    if share.is_empty() {
        return Err("share name required".to_string());
    }
    if config.auth == AuthMethod::None {
        return Ok(format!("//{server}/{share}"));
    }
    if config.auth == AuthMethod::Kerberos {
        return Ok(format!("//{}@{server}/{share}", config.username));
    }
    match secret {
        Some(password) if !password.is_empty() => Ok(format!(
            "//{}:{}@{server}/{share}",
            config.username,
            url_encode(password)
        )),
        // No stored secret means guest access.
        _ => Ok(format!("//{server}/{share}")),
    }
}

/// Builds the `mount_smbfs` argv (excluding the binary itself). A
/// Kerberos URL carries no password, so without `-N` mount_smbfs
/// would block on an interactive prompt; `-N` makes it fail instead,
/// surfacing a missing ticket as the mount_smbfs error text.
fn smb_argv(url: &str, dir: &Path, kerberos: bool) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = Vec::new();
    if kerberos {
        argv.push("-N".into());
    }
    argv.push(url.into());
    argv.push(dir.as_os_str().to_os_string());
    argv
}

/// Builds the `mount_nfs` argv (excluding the binary itself).
/// `sec=krb5` tells mount_nfs to authenticate the mount with the
/// caller's Kerberos ticket instead of the default `sys` scheme.
fn nfs_argv(target: &str, dir: &Path, kerberos: bool) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = Vec::new();
    if kerberos {
        argv.push("-o".into());
        argv.push("sec=krb5".into());
    }
    argv.push(target.into());
    argv.push(dir.as_os_str().to_os_string());
    argv
}

/// Validates the auth method for an NFS mount. `None` (the default,
/// unauthenticated export) and `Kerberos` (ticket-based `sec=krb5`)
/// are the only kinds mount_nfs supports here.
fn validate_nfs_auth(auth: &AuthMethod) -> Result<(), String> {
    if matches!(auth, AuthMethod::None | AuthMethod::Kerberos) {
        Ok(())
    } else {
        Err("wrong auth method for nfs".to_string())
    }
}

/// Validates the NFS `server:/export` form. `mount_nfs` takes exactly
/// this string, so it passes through unchanged.
fn nfs_target(host: &str) -> Result<&str, String> {
    match host.split_once(':') {
        Some((server, export)) if !server.is_empty() && export.starts_with('/') => Ok(host),
        _ => Err("nfs host must be server:/export".to_string()),
    }
}

/// Mount directories live under the user's application-support area.
/// A `/` in a connection id would escape the mounts directory, so it
/// becomes `_`.
fn mount_dir(home: &str, connection_id: &str) -> PathBuf {
    Path::new(home)
        .join("Library/Application Support/Orka/mounts")
        .join(connection_id.replace('/', "_"))
}

fn mount_root_for(connection_id: &str) -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(mount_dir(&home, connection_id))
}

/// mount_smbfs, mount_nfs, and umount live in /sbin or /usr/sbin,
/// which is often absent from a GUI application's PATH. Look there
/// first, then fall back to PATH.
fn find_binary(name: &str) -> Option<PathBuf> {
    for dir in ["/sbin", "/usr/sbin"] {
        let candidate = Path::new(dir).join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.exists())
}

fn statfs_of(path: &Path) -> Option<libc::statfs> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut info) };
    (rc == 0).then_some(info)
}

/// Detects an existing mount by comparing the statfs mount source of
/// the directory with its parent. A plain empty directory shares its
/// parent's source, so `read_dir` alone cannot tell them apart. The
/// statfs id is unusable here because libc keeps its field private.
fn is_mount_point(dir: &Path) -> bool {
    let Some(dir_fs) = statfs_of(dir) else {
        return false;
    };
    let Some(parent) = dir.parent() else {
        return false;
    };
    let Some(parent_fs) = statfs_of(parent) else {
        return false;
    };
    dir_fs.f_mntfromname != parent_fs.f_mntfromname
}

/// Removes the password from helper output before the text reaches an
/// error message.
fn scrub_secret(text: &str, secret: Option<&str>) -> String {
    match secret {
        Some(password) if !password.is_empty() => text
            .replace(password, "***")
            .replace(&url_encode(password), "***"),
        _ => text.to_string(),
    }
}

struct RunOutcome {
    success: bool,
    stderr: String,
    timed_out: bool,
}

/// Runs a command with a kill deadline. `std::process::Command` has no
/// timeout, so the wait runs on a helper thread and a deadline expiry
/// SIGKILLs the child; the reader thread then sees EOF and reaps it.
fn run_with_timeout(mut command: Command, deadline: Duration) -> Result<RunOutcome, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let program = command.get_program().to_string_lossy().into_owned();
    let child = command
        .spawn()
        .map_err(|e| format!("cannot start {program}: {e}"))?;
    let pid = child.id() as i32;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(deadline) {
        Ok(Ok(output)) => Ok(RunOutcome {
            success: output.status.success(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            timed_out: false,
        }),
        Ok(Err(e)) => Err(format!("cannot wait for {program}: {e}")),
        Err(_) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = receiver.recv();
            Ok(RunOutcome {
                success: false,
                stderr: String::new(),
                timed_out: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn smb_config(host: &str, auth: AuthMethod) -> ConnectionConfig {
        ConnectionConfig {
            id: "test-conn".into(),
            display_name: "Test".into(),
            scheme: Scheme::Smb,
            host: host.into(),
            port: 445,
            username: "liam".into(),
            initial_path: "/".into(),
            auth,
        }
    }

    #[test]
    fn smb_url_with_password_encodes_the_secret() {
        let config = smb_config("server/share", AuthMethod::Password);
        let url = build_smb_url(&config, Some("p@ss w rd")).unwrap();
        assert_eq!(url, "//liam:p%40ss%20w%20rd@server/share");
    }

    #[test]
    fn smb_url_without_secret_is_guest() {
        let config = smb_config("server/share", AuthMethod::Password);
        assert_eq!(build_smb_url(&config, None).unwrap(), "//server/share");
        assert_eq!(build_smb_url(&config, Some("")).unwrap(), "//server/share");
    }

    #[test]
    fn smb_no_auth_is_guest_and_ignores_a_stale_secret() {
        let config = smb_config("server/share", AuthMethod::None);
        // A leftover secret from an earlier Password config must never
        // reach the URL once the connection is set to No Auth.
        assert_eq!(
            build_smb_url(&config, Some("stale-password")).unwrap(),
            "//server/share"
        );
        assert_eq!(build_smb_url(&config, None).unwrap(), "//server/share");
    }

    #[test]
    fn smb_url_passes_port_form_through() {
        let config = smb_config("server:445/share", AuthMethod::Password);
        let url = build_smb_url(&config, Some("pw")).unwrap();
        assert_eq!(url, "//liam:pw@server:445/share");
    }

    #[test]
    fn smb_rejects_wrong_auth() {
        let config = smb_config(
            "server/share",
            AuthMethod::SshKey {
                key_path: "~/.ssh/id_ed25519".into(),
            },
        );
        let err = build_smb_url(&config, Some("pw")).unwrap_err();
        assert_eq!(err, "wrong auth method for smb");
    }

    #[test]
    fn smb_url_for_kerberos_has_no_password() {
        let config = smb_config("server/share", AuthMethod::Kerberos);
        // A stale secret from an earlier Password config must never
        // reach a Kerberos URL either.
        assert_eq!(
            build_smb_url(&config, Some("stale-password")).unwrap(),
            "//liam@server/share"
        );
        assert_eq!(build_smb_url(&config, None).unwrap(), "//liam@server/share");
    }

    #[test]
    fn smb_url_for_kerberos_keeps_a_domain_username() {
        let mut config = smb_config("server/share", AuthMethod::Kerberos);
        config.username = "DOMAIN;user".into();
        assert_eq!(
            build_smb_url(&config, None).unwrap(),
            "//DOMAIN;user@server/share"
        );
    }

    #[test]
    fn smb_rejects_missing_share() {
        for host in ["server", "server/"] {
            let config = smb_config(host, AuthMethod::Password);
            let err = build_smb_url(&config, None).unwrap_err();
            assert_eq!(err, "share name required");
        }
    }

    #[test]
    fn nfs_accepts_server_export_form() {
        assert_eq!(nfs_target("server:/export").unwrap(), "server:/export");
        assert_eq!(
            nfs_target("server:/export/dir").unwrap(),
            "server:/export/dir"
        );
    }

    #[test]
    fn nfs_rejects_invalid_forms() {
        for host in ["server", "server:export", ":/export", ""] {
            let err = nfs_target(host).unwrap_err();
            assert_eq!(err, "nfs host must be server:/export");
        }
    }

    #[test]
    fn smb_argv_adds_no_prompt_flag_only_for_kerberos() {
        let dir = Path::new("/tmp/mnt");
        assert_eq!(
            smb_argv("//server/share", dir, false),
            vec![
                std::ffi::OsString::from("//server/share"),
                std::ffi::OsString::from("/tmp/mnt"),
            ]
        );
        assert_eq!(
            smb_argv("//liam@server/share", dir, true),
            vec![
                std::ffi::OsString::from("-N"),
                std::ffi::OsString::from("//liam@server/share"),
                std::ffi::OsString::from("/tmp/mnt"),
            ]
        );
    }

    #[test]
    fn nfs_argv_adds_sec_krb5_only_for_kerberos() {
        let dir = Path::new("/tmp/mnt");
        assert_eq!(
            nfs_argv("server:/export", dir, false),
            vec![
                std::ffi::OsString::from("server:/export"),
                std::ffi::OsString::from("/tmp/mnt"),
            ]
        );
        assert_eq!(
            nfs_argv("server:/export", dir, true),
            vec![
                std::ffi::OsString::from("-o"),
                std::ffi::OsString::from("sec=krb5"),
                std::ffi::OsString::from("server:/export"),
                std::ffi::OsString::from("/tmp/mnt"),
            ]
        );
    }

    #[test]
    fn nfs_auth_accepts_none_and_kerberos_only() {
        assert!(validate_nfs_auth(&AuthMethod::None).is_ok());
        assert!(validate_nfs_auth(&AuthMethod::Kerberos).is_ok());
        let err = validate_nfs_auth(&AuthMethod::Password).unwrap_err();
        assert_eq!(err, "wrong auth method for nfs");
        let err = validate_nfs_auth(&AuthMethod::SshAgent).unwrap_err();
        assert_eq!(err, "wrong auth method for nfs");
    }

    #[test]
    fn mount_dir_lives_under_application_support() {
        let dir = mount_dir("/Users/x", "abc");
        assert_eq!(
            dir,
            Path::new("/Users/x/Library/Application Support/Orka/mounts/abc")
        );
        assert_eq!(
            mount_dir("/Users/x", "a/b"),
            Path::new("/Users/x/Library/Application Support/Orka/mounts/a_b")
        );
    }

    #[test]
    fn path_translation_joins_and_rejects_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = MountBackend::with_root(tmp.path().to_path_buf());
        assert_eq!(backend.translate("/").unwrap(), tmp.path());
        assert_eq!(backend.translate("/a").unwrap(), tmp.path().join("a"));
        assert_eq!(backend.translate("/a/b").unwrap(), tmp.path().join("a/b"));
        assert!(backend.translate("..").is_err());
        assert!(backend.translate("/a/../b").is_err());
    }

    #[test]
    fn entry_paths_strip_the_root_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = MountBackend::with_root(tmp.path().to_path_buf());
        assert_eq!(backend.to_local_path(&tmp.path().join("a/b")), "/a/b");
        assert_eq!(backend.to_local_path(tmp.path()), "/");
    }

    #[test]
    fn delegation_round_trips_through_the_mount_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();
        let backend = MountBackend::with_root(root);

        let entries = backend.list_dir("/", &ListOptions::default()).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"docs"));
        assert!(entries.iter().all(|e| e.path.starts_with('/')));

        let stat = backend.stat("/a.txt").unwrap();
        assert_eq!(stat.path, "/a.txt");
        assert_eq!(stat.size, 5);
        assert!(!stat.is_dir);

        backend.mkdir("/new").unwrap();
        assert!(tmp.path().join("new").is_dir());

        backend.rename("/new", "/renamed").unwrap();
        assert!(tmp.path().join("renamed").is_dir());

        {
            let mut writer = backend.create_write("/renamed/file.txt", None).unwrap();
            writer.write_all(b"world").unwrap();
            writer.finish().unwrap();
        }
        let mut contents = String::new();
        backend
            .open_read("/renamed/file.txt")
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "world");

        backend.delete("/renamed/file.txt", false).unwrap();
        backend.delete("/renamed", true).unwrap();
        assert!(!tmp.path().join("renamed").exists());

        assert!(backend.translate("..").is_err());
        assert!(backend.open_read("../outside").is_err());
    }

    #[test]
    fn command_timeout_kills_and_reports() {
        let mut command = Command::new("sleep");
        command.arg("5");
        let outcome = run_with_timeout(command, Duration::from_millis(100)).unwrap();
        assert!(outcome.timed_out);
        assert!(!outcome.success);
    }

    #[test]
    fn fast_commands_report_no_timeout() {
        let command = Command::new("true");
        let outcome = run_with_timeout(command, Duration::from_secs(5)).unwrap();
        assert!(!outcome.timed_out);
        assert!(outcome.success);
    }

    #[test]
    fn scrub_removes_raw_and_encoded_secret() {
        let out = scrub_secret("mount failed for //u:pw@h/s", Some("pw"));
        assert!(!out.contains("pw"));
        assert!(out.contains("***"));
        let encoded = scrub_secret("url //u:p%40ss@h/s", Some("p@ss"));
        assert!(!encoded.contains("p%40ss"));
    }
}
