//! A small, disk-backed NFSv3 file system for the mount bench.
//!
//! [`DiskFs`] wraps one real directory with the `nfsserve` crate's
//! `NFSFileSystem` trait, so [`nfsserve::tcp::NFSTcpListener`] can
//! serve it over loopback TCP. Every file system object gets a stable
//! 64-bit id the first time a client sees it (through `lookup`,
//! `readdir`, `create`, or `mkdir`); the id survives for the life of
//! this server process but not across a restart, matching the
//! generation-number contract in [`nfsserve::vfs::NFSFileSystem`].
//!
//! Every operation below does a plain, blocking `std::fs` call inside
//! an `async fn`. That is safe here only because the bench serves one
//! client at a time with small files on local disk; a production NFS
//! server needs real async file I/O instead.

use async_trait::async_trait;
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, sattr3, set_size3, specdata3,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::Metadata;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The root directory's fixed id. `nfsserve` treats id 0 as reserved.
const ROOT_ID: fileid3 = 1;

/// The id and path tables, held behind one lock so a lookup that
/// assigns a fresh id can never race with another assignment for the
/// same path.
struct Inner {
    next_id: fileid3,
    id_to_path: HashMap<fileid3, PathBuf>,
    path_to_id: HashMap<PathBuf, fileid3>,
}

/// An NFSv3 file system backed by one directory on local disk.
pub struct DiskFs {
    root: PathBuf,
    inner: Mutex<Inner>,
}

impl DiskFs {
    /// Serves `root`. `root` must already exist; every path this
    /// server hands out resolves under it.
    pub fn new(root: PathBuf) -> Self {
        let mut id_to_path = HashMap::new();
        let mut path_to_id = HashMap::new();
        id_to_path.insert(ROOT_ID, root.clone());
        path_to_id.insert(root.clone(), ROOT_ID);
        Self {
            root,
            inner: Mutex::new(Inner {
                next_id: ROOT_ID + 1,
                id_to_path,
                path_to_id,
            }),
        }
    }

    fn path_for(&self, id: fileid3) -> Result<PathBuf, nfsstat3> {
        self.inner
            .lock()
            .unwrap()
            .id_to_path
            .get(&id)
            .cloned()
            .ok_or(nfsstat3::NFS3ERR_STALE)
    }

    /// Returns the id for `path`, assigning a fresh one the first time
    /// this path is seen. Callers must already know `path` exists (or
    /// just created it); this never touches disk.
    fn id_for(&self, path: &Path) -> fileid3 {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&id) = inner.path_to_id.get(path) {
            return id;
        }
        let id = inner.next_id;
        inner.next_id += 1;
        inner.id_to_path.insert(id, path.to_path_buf());
        inner.path_to_id.insert(path.to_path_buf(), id);
        id
    }

    /// Drops `path` (and its id) from the tables after a successful
    /// remove. A later use of the freed id reports `NFS3ERR_STALE`,
    /// which is the correct response for a handle that no longer
    /// resolves.
    fn forget(&self, path: &Path) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(id) = inner.path_to_id.remove(path) {
            inner.id_to_path.remove(&id);
        }
    }

    /// After a rename moves `old` to `new` on disk, rewrites every
    /// tracked path under `old` (the entry itself, and, for a
    /// directory, everything below it) onto the matching path under
    /// `new`. Without this, a renamed directory's children would keep
    /// resolving to their old, now-nonexistent location.
    fn rename_prefix(&self, old: &Path, new: &Path) {
        let mut inner = self.inner.lock().unwrap();
        let affected: Vec<(fileid3, PathBuf)> = inner
            .id_to_path
            .iter()
            .filter(|(_, p)| p.starts_with(old))
            .map(|(&id, p)| (id, p.clone()))
            .collect();
        for (id, old_path) in affected {
            let rel = old_path
                .strip_prefix(old)
                .expect("checked by starts_with above");
            let new_path = if rel.as_os_str().is_empty() {
                new.to_path_buf()
            } else {
                new.join(rel)
            };
            inner.path_to_id.remove(&old_path);
            inner.id_to_path.insert(id, new_path.clone());
            inner.path_to_id.insert(new_path, id);
        }
    }
}

/// Converts an NFS wire filename to an `OsStr` for joining onto a
/// `Path`. NFS filenames are opaque bytes, so this goes through raw
/// bytes rather than UTF-8, matching how POSIX file names work.
fn name_to_os(name: &filename3) -> &OsStr {
    OsStr::from_bytes(name.as_ref())
}

/// Converts a directory-entry `OsString` back to the NFS wire form.
fn os_to_name(name: OsString) -> filename3 {
    name.into_vec().into()
}

fn system_time_to_nfstime(time: SystemTime) -> nfsserve::nfs::nfstime3 {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    nfsserve::nfs::nfstime3 {
        seconds: since_epoch.as_secs() as u32,
        nseconds: since_epoch.subsec_nanos(),
    }
}

fn to_fattr3(id: fileid3, meta: &Metadata) -> fattr3 {
    let ftype = if meta.is_dir() {
        ftype3::NF3DIR
    } else if meta.file_type().is_symlink() {
        ftype3::NF3LNK
    } else {
        ftype3::NF3REG
    };
    fattr3 {
        ftype,
        // Mask off the file-type bits POSIX packs into `st_mode`;
        // NFS carries the type separately in `ftype`.
        mode: meta.mode() & 0o7777,
        nlink: meta.nlink().max(1) as u32,
        uid: meta.uid(),
        gid: meta.gid(),
        size: meta.len(),
        used: meta.len(),
        rdev: specdata3::default(),
        fsid: 1,
        fileid: id,
        atime: system_time_to_nfstime(meta.accessed().unwrap_or(UNIX_EPOCH)),
        mtime: system_time_to_nfstime(meta.modified().unwrap_or(UNIX_EPOCH)),
        ctime: system_time_to_nfstime(meta.modified().unwrap_or(UNIX_EPOCH)),
    }
}

fn stat(path: &Path) -> Result<Metadata, nfsstat3> {
    std::fs::symlink_metadata(path).map_err(|_| nfsstat3::NFS3ERR_NOENT)
}

#[async_trait]
impl NFSFileSystem for DiskFs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_ID
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let dir = self.path_for(dirid)?;
        let name = name_to_os(filename);
        if name == "." {
            return Ok(dirid);
        }
        if name == ".." {
            let parent = if dir == self.root {
                self.root.clone()
            } else {
                dir.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| self.root.clone())
            };
            return Ok(self.id_for(&parent));
        }
        let child = dir.join(name);
        if !child.exists() {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        Ok(self.id_for(&child))
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let path = self.path_for(id)?;
        Ok(to_fattr3(id, &stat(&path)?))
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let path = self.path_for(id)?;
        // Only a size change (truncate) is applied; the bench needs
        // SETATTR to round-trip without an error, not to enforce mode,
        // ownership, or timestamp changes.
        if let set_size3::size(size) = setattr.size {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
            file.set_len(size).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        }
        Ok(to_fattr3(id, &stat(&path)?))
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let path = self.path_for(id)?;
        let data = std::fs::read(&path).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(count as usize).min(data.len());
        Ok((data[start..end].to_vec(), end == data.len()))
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        use std::io::{Seek, SeekFrom, Write};
        let path = self.path_for(id)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        file.write_all(data).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        drop(file);
        Ok(to_fattr3(id, &stat(&path)?))
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let dir = self.path_for(dirid)?;
        let path = dir.join(name_to_os(filename));
        std::fs::File::create(&path).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let id = self.id_for(&path);
        Ok((id, to_fattr3(id, &stat(&path)?)))
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        let dir = self.path_for(dirid)?;
        let path = dir.join(name_to_os(filename));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| nfsstat3::NFS3ERR_EXIST)?;
        Ok(self.id_for(&path))
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let dir = self.path_for(dirid)?;
        let path = dir.join(name_to_os(dirname));
        std::fs::create_dir(&path).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let id = self.id_for(&path);
        Ok((id, to_fattr3(id, &stat(&path)?)))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let dir = self.path_for(dirid)?;
        let path = dir.join(name_to_os(filename));
        let meta = stat(&path)?;
        // The NFS REMOVE and RMDIR procedures both land here (see the
        // `nfsserve` dispatch table); tell files and directories apart
        // by their metadata rather than by the request kind.
        let result = if meta.is_dir() {
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        };
        result.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                nfsstat3::NFS3ERR_NOENT
            } else {
                nfsstat3::NFS3ERR_IO
            }
        })?;
        self.forget(&path);
        Ok(())
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let from_dir = self.path_for(from_dirid)?;
        let to_dir = self.path_for(to_dirid)?;
        let from_path = from_dir.join(name_to_os(from_filename));
        let to_path = to_dir.join(name_to_os(to_filename));
        std::fs::rename(&from_path, &to_path).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        self.rename_prefix(&from_path, &to_path);
        Ok(())
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let dir = self.path_for(dirid)?;
        let mut names: Vec<OsString> = std::fs::read_dir(&dir)
            .map_err(|_| nfsstat3::NFS3ERR_NOTDIR)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .collect();
        // Deterministic order, required by the trait's readdir
        // contract: `start_after` only makes sense against a stable
        // ordering across calls.
        names.sort();

        let mut entries = Vec::new();
        let mut started = start_after == 0;
        let mut end = true;
        for name in names {
            let path = dir.join(&name);
            let id = self.id_for(&path);
            if !started {
                if id == start_after {
                    started = true;
                }
                continue;
            }
            if entries.len() >= max_entries {
                end = false;
                break;
            }
            let Ok(meta) = stat(&path) else { continue };
            entries.push(DirEntry {
                fileid: id,
                name: os_to_name(name),
                attr: to_fattr3(id, &meta),
            });
        }
        Ok(ReadDirResult { entries, end })
    }

    async fn symlink(
        &self,
        _dirid: fileid3,
        _linkname: &filename3,
        _symlink: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }

    async fn readlink(&self, _id: fileid3) -> Result<nfspath3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }

    // `fsinfo` and `readdir_simple` keep the trait's default bodies:
    // both only need `getattr` and `readdir` above to work.
}
