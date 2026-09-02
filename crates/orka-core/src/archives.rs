//! Archive creation and extraction: zip, tar, and gzip tarballs.
//!
//! The ops engine drives both directions. Creation walks all sources up
//! front so progress totals stay stable. Extraction confines every member
//! to the destination directory; hostile member names are skipped, not
//! treated as job failures.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
}

/// Picks the archive format from a file extension. Matching is
/// case-insensitive because macOS volumes are usually case-insensitive.
pub fn archive_format_for_path(path: &str) -> Option<ArchiveFormat> {
    let lower = path.to_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        Some(ArchiveFormat::TarGz)
    } else if lower.ends_with(".tar") {
        Some(ArchiveFormat::Tar)
    } else if lower.ends_with(".zip") {
        Some(ArchiveFormat::Zip)
    } else {
        None
    }
}

/// One entry in the pre-walk of a source tree.
struct WalkEntry {
    source: PathBuf,
    /// Member name inside the archive, with "/" separators.
    member: String,
    is_dir: bool,
    size: u64,
}

/// Collects every file and directory below `source`. The member root is
/// the source's file name, so several sources can share one archive.
/// Symlinks are skipped: an archive member that points outside the
/// archive is a security hazard, and remote targets have no meaning.
fn walk_source(
    source: &Path,
    member: &str,
    out: &mut Vec<WalkEntry>,
    cancel: &dyn Fn() -> bool,
) -> Result<(), String> {
    if cancel() {
        return Err("cancelled".to_string());
    }
    let meta = std::fs::symlink_metadata(source).map_err(|e| e.to_string())?;
    if meta.is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        out.push(WalkEntry {
            source: source.to_path_buf(),
            member: member.to_string(),
            is_dir: true,
            size: 0,
        });
        let read = std::fs::read_dir(source).map_err(|e| e.to_string())?;
        let mut children: Vec<_> = read.flatten().collect();
        // Deterministic member order keeps archives reproducible.
        children.sort_by_key(|child| child.file_name());
        for child in children {
            let name = child.file_name().to_string_lossy().into_owned();
            let child_member = format!("{member}/{name}");
            walk_source(&child.path(), &child_member, out, cancel)?;
        }
    } else {
        out.push(WalkEntry {
            source: source.to_path_buf(),
            member: member.to_string(),
            is_dir: false,
            size: meta.len(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

fn mtime_of(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Creates an archive at `dest` from all `sources`.
///
/// Progress reports cumulative file bytes against the pre-walked total,
/// once per member. The cancel check fires between members; a cancelled
/// or failed run leaves the partial file in place for the caller to
/// remove, because only the caller knows the job context.
pub fn create_archive(
    sources: &[PathBuf],
    dest: &Path,
    format: ArchiveFormat,
    progress: &mut dyn FnMut(u64, u64, &str),
    cancel: &dyn Fn() -> bool,
) -> Result<(), String> {
    let mut entries: Vec<WalkEntry> = Vec::new();
    for source in sources {
        let root = source
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or("invalid source path")?;
        walk_source(source, &root, &mut entries, cancel)?;
    }
    let total: u64 = entries.iter().map(|e| e.size).sum();
    let mut done: u64 = 0;

    let file = File::create(dest).map_err(|e| e.to_string())?;
    match format {
        ArchiveFormat::Zip => {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            let mut writer = zip::ZipWriter::new(file);
            for entry in &entries {
                if cancel() {
                    return Err("cancelled".to_string());
                }
                write_zip_member(&mut writer, entry, options)?;
                done += entry.size;
                progress(done, total, &entry.source.display().to_string());
            }
            writer.finish().map_err(|e| e.to_string())?;
        }
        ArchiveFormat::Tar => {
            let tar_entries = write_tar(file, &entries, &mut done, total, progress, cancel)?;
            let _ = tar_entries;
        }
        ArchiveFormat::TarGz => {
            // The gzip trailer is only written by finish(); dropping the
            // encoder mid-way would leave a truncated tarball.
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let encoder = write_tar(encoder, &entries, &mut done, total, progress, cancel)?;
            encoder.finish().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn write_zip_member(
    writer: &mut zip::ZipWriter<File>,
    entry: &WalkEntry,
    options: zip::write::SimpleFileOptions,
) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(&entry.source).map_err(|e| e.to_string())?;
    let options = options.unix_permissions(mode_of(&meta));
    if entry.is_dir {
        writer
            .add_directory(&entry.member, options)
            .map_err(|e| e.to_string())
    } else {
        writer
            .start_file(&entry.member, options)
            .map_err(|e| e.to_string())?;
        let mut file = File::open(&entry.source).map_err(|e| e.to_string())?;
        std::io::copy(&mut file, writer).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Writes tar members and returns the inner writer so a gzip wrapper can
/// flush its trailer.
fn write_tar<W: std::io::Write>(
    out: W,
    entries: &[WalkEntry],
    done: &mut u64,
    total: u64,
    progress: &mut dyn FnMut(u64, u64, &str),
    cancel: &dyn Fn() -> bool,
) -> Result<W, String> {
    let mut builder = tar::Builder::new(out);
    for entry in entries {
        if cancel() {
            return Err("cancelled".to_string());
        }
        let meta = std::fs::symlink_metadata(&entry.source).map_err(|e| e.to_string())?;
        let mut header = tar::Header::new_gnu();
        header.set_mode(mode_of(&meta));
        header.set_mtime(mtime_of(&meta));
        if entry.is_dir {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            builder
                .append_data(&mut header, &entry.member, std::io::empty())
                .map_err(|e| e.to_string())?;
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(entry.size);
            let mut file = File::open(&entry.source).map_err(|e| e.to_string())?;
            builder
                .append_data(&mut header, &entry.member, &mut file)
                .map_err(|e| e.to_string())?;
        }
        *done += entry.size;
        progress(*done, total, &entry.source.display().to_string());
    }
    builder.into_inner().map_err(|e| e.to_string())
}

/// Extracts `archive` into `dest_dir`, which must already exist.
///
/// Returns the top-level items created in `dest_dir` so the caller can
/// record undo actions. Members with absolute paths or ".." components
/// are skipped: one hostile member must not fail a whole job, and it
/// must never write outside `dest_dir`.
pub fn extract(
    archive: &Path,
    dest_dir: &Path,
    progress: &mut dyn FnMut(u64, u64, &str),
    cancel: &dyn Fn() -> bool,
) -> Result<Vec<PathBuf>, String> {
    let format =
        archive_format_for_path(&archive.to_string_lossy()).ok_or("unsupported archive format")?;
    let mut top_level: Vec<PathBuf> = Vec::new();
    match format {
        ArchiveFormat::Zip => extract_zip(archive, dest_dir, &mut top_level, progress, cancel)?,
        ArchiveFormat::Tar | ArchiveFormat::TarGz => {
            extract_tar(archive, dest_dir, format, &mut top_level, progress, cancel)?
        }
    }
    Ok(top_level)
}

fn record_top_level(dest_dir: &Path, rel: &Path, top_level: &mut Vec<PathBuf>) {
    let Some(first) = rel.components().next() else {
        return;
    };
    let item = dest_dir.join(first.as_os_str());
    if !top_level.contains(&item) {
        top_level.push(item);
    }
}

/// Maps an archive member name to a safe relative path. "." components
/// are common in real tarballs and harmless; anything else outside a
/// plain relative name is rejected.
fn safe_member_path(member: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in member.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: Option<u32>) {
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777));
    }
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: Option<u32>) {}

fn extract_zip(
    archive: &Path,
    dest_dir: &Path,
    top_level: &mut Vec<PathBuf>,
    progress: &mut dyn FnMut(u64, u64, &str),
    cancel: &dyn Fn() -> bool,
) -> Result<(), String> {
    let file = File::open(archive).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    // The central directory is already in memory, so the byte total is
    // exact before the first member is written.
    let total: u64 = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|e| e.size()))
        .sum();
    let mut done: u64 = 0;
    for i in 0..zip.len() {
        if cancel() {
            return Err("cancelled".to_string());
        }
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let out = dest_dir.join(&rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        } else {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut out_file = File::create(&out).map_err(|e| e.to_string())?;
            std::io::copy(&mut entry, &mut out_file).map_err(|e| e.to_string())?;
            set_file_mode(&out, entry.unix_mode());
        }
        record_top_level(dest_dir, &rel, top_level);
        done += entry.size();
        progress(done, total, &out.display().to_string());
    }
    Ok(())
}

fn extract_tar(
    archive: &Path,
    dest_dir: &Path,
    format: ArchiveFormat,
    top_level: &mut Vec<PathBuf>,
    progress: &mut dyn FnMut(u64, u64, &str),
    cancel: &dyn Fn() -> bool,
) -> Result<(), String> {
    let file = File::open(archive).map_err(|e| e.to_string())?;
    let reader: Box<dyn std::io::Read> = match format {
        ArchiveFormat::TarGz => Box::new(flate2::read::GzDecoder::new(file)),
        _ => Box::new(file),
    };
    let mut ar = tar::Archive::new(reader);
    // A streamed tar reveals sizes one header at a time, so the total is
    // unknown and stays zero (indeterminate) for progress.
    let total: u64 = 0;
    let mut done: u64 = 0;
    for entry in ar.entries().map_err(|e| e.to_string())? {
        if cancel() {
            return Err("cancelled".to_string());
        }
        let mut entry = entry.map_err(|e| e.to_string())?;
        let raw = entry.path().map_err(|e| e.to_string())?.to_path_buf();
        let Some(rel) = safe_member_path(&raw) else {
            continue;
        };
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                let out = dest_dir.join(&rel);
                std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
                record_top_level(dest_dir, &rel, top_level);
            }
            tar::EntryType::Regular => {
                let out = dest_dir.join(&rel);
                if let Some(parent) = out.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let mut out_file = File::create(&out).map_err(|e| e.to_string())?;
                std::io::copy(&mut entry, &mut out_file).map_err(|e| e.to_string())?;
                set_file_mode(&out, entry.header().mode().ok());
                record_top_level(dest_dir, &rel, top_level);
            }
            // Symlinks, hardlinks, and device nodes are skipped: they
            // carry escape or privilege risks and no user data.
            _ => {}
        }
        done += entry.header().size().unwrap_or(0);
        progress(done, total, &dest_dir.join(&rel).display().to_string());
    }
    Ok(())
}

/// Picks a fresh archive file name in `dest_dir`. A single source names
/// the archive after itself ("Photos" -> "Photos.zip"); several sources
/// fall back to "Archive.zip". Existing names dedupe with " 2", " 3",
/// … like Finder's duplicate naming. Called inside the job so two rapid
/// clicks cannot pick the same name.
pub fn choose_archive_name(dest_dir: &Path, sources: &[PathBuf], format: ArchiveFormat) -> PathBuf {
    let stem = match sources {
        [single] => single.file_name().map(|n| n.to_string_lossy().into_owned()),
        _ => None,
    }
    .unwrap_or_else(|| "Archive".to_string());
    let ext = match format {
        ArchiveFormat::Zip => "zip",
        ArchiveFormat::Tar => "tar",
        ArchiveFormat::TarGz => "tar.gz",
    };
    let mut candidate = dest_dir.join(format!("{stem}.{ext}"));
    let mut counter = 2;
    while candidate.symlink_metadata().is_ok() {
        candidate = dest_dir.join(format!("{stem} {counter}.{ext}"));
        counter += 1;
    }
    candidate
}

/// Picks the extraction directory: a sibling of the archive named after
/// its stem ("photos.tar.gz" -> "photos"), deduped with " 2", " 3", ….
pub fn choose_extract_dir(archive: &Path) -> PathBuf {
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // ".tar.gz" is ASCII, so the byte slice of the original name is safe.
    let lower = name.to_lowercase();
    let stem = match lower.strip_suffix(".tar.gz") {
        Some(base) => name[..base.len()].to_string(),
        None => archive
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or(name),
    };
    let parent = archive.parent().unwrap_or(Path::new("."));
    let mut candidate = parent.join(&stem);
    let mut counter = 2;
    while candidate.symlink_metadata().is_ok() {
        candidate = parent.join(format!("{stem} {counter}"));
        counter += 1;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn no_progress(_: u64, _: u64, _: &str) {}
    fn no_cancel() -> bool {
        false
    }

    fn make_tree(root: &Path) {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.txt"), b"alpha").unwrap();
        std::fs::write(root.join("sub/nested.txt"), b"nested").unwrap();
    }

    #[test]
    fn format_detection() {
        assert_eq!(archive_format_for_path("x.ZIP"), Some(ArchiveFormat::Zip));
        assert_eq!(archive_format_for_path("a.tar"), Some(ArchiveFormat::Tar));
        assert_eq!(
            archive_format_for_path("b.TAR.GZ"),
            Some(ArchiveFormat::TarGz)
        );
        assert_eq!(archive_format_for_path("c.tgz"), Some(ArchiveFormat::TarGz));
        assert_eq!(archive_format_for_path("d.txt"), None);
        assert_eq!(archive_format_for_path("plain"), None);
    }

    #[test]
    fn zip_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("photos");
        make_tree(&src);
        let dest = tmp.path().join("out.zip");
        create_archive(
            std::slice::from_ref(&src),
            &dest,
            ArchiveFormat::Zip,
            &mut no_progress,
            &no_cancel,
        )
        .unwrap();

        let file = File::open(&dest).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        assert!(zip.file_names().any(|n| n == "photos/a.txt"));
        assert!(zip.file_names().any(|n| n == "photos/sub/nested.txt"));
        let mut a = zip.by_name("photos/a.txt").unwrap();
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut a, &mut content).unwrap();
        assert_eq!(content, b"alpha");
    }

    #[test]
    fn tar_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("photos");
        make_tree(&src);
        let dest = tmp.path().join("out.tar");
        create_archive(
            std::slice::from_ref(&src),
            &dest,
            ArchiveFormat::Tar,
            &mut no_progress,
            &no_cancel,
        )
        .unwrap();

        let names = tar_member_names(&dest, false);
        assert!(names.contains(&"photos".to_string()));
        assert!(names.contains(&"photos/a.txt".to_string()));
        assert!(names.contains(&"photos/sub/nested.txt".to_string()));
    }

    #[test]
    fn tar_gz_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("photos");
        make_tree(&src);
        let dest = tmp.path().join("out.tar.gz");
        create_archive(
            std::slice::from_ref(&src),
            &dest,
            ArchiveFormat::TarGz,
            &mut no_progress,
            &no_cancel,
        )
        .unwrap();

        let names = tar_member_names(&dest, true);
        assert!(names.contains(&"photos/a.txt".to_string()));
        assert!(names.contains(&"photos/sub/nested.txt".to_string()));
    }

    fn tar_member_names(dest: &Path, gz: bool) -> Vec<String> {
        let file = File::open(dest).unwrap();
        let reader: Box<dyn std::io::Read> = if gz {
            Box::new(flate2::read::GzDecoder::new(file))
        } else {
            Box::new(file)
        };
        let mut ar = tar::Archive::new(reader);
        ar.entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn extract_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("stuff");
        std::fs::create_dir_all(src.join("deep/nest")).unwrap();
        std::fs::write(src.join("f.txt"), b"hello").unwrap();
        std::fs::write(src.join("deep/nest/g.txt"), b"world").unwrap();
        let archive = tmp.path().join("stuff.zip");
        create_archive(
            &[src],
            &archive,
            ArchiveFormat::Zip,
            &mut no_progress,
            &no_cancel,
        )
        .unwrap();

        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let items = extract(&archive, &out, &mut no_progress, &no_cancel).unwrap();
        assert_eq!(items, vec![out.join("stuff")]);
        assert_eq!(std::fs::read(out.join("stuff/f.txt")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read(out.join("stuff/deep/nest/g.txt")).unwrap(),
            b"world"
        );
    }

    #[test]
    fn hostile_members_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let hostile = tmp.path().join("hostile.zip");
        let file = File::create(&hostile).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("../escape.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"evil").unwrap();
        writer
            .start_file("/absolute.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"evil").unwrap();
        writer
            .start_file("ok.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"fine").unwrap();
        writer.finish().unwrap();

        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let items = extract(&hostile, &out, &mut no_progress, &no_cancel).unwrap();
        assert_eq!(items, vec![out.join("ok.txt")]);
        assert_eq!(std::fs::read(out.join("ok.txt")).unwrap(), b"fine");
        assert!(!tmp.path().join("escape.txt").exists());
    }

    #[test]
    fn choose_archive_name_dedupes() {
        let tmp = tempfile::tempdir().unwrap();
        let many = vec![PathBuf::from("/a/one"), PathBuf::from("/a/two")];
        assert_eq!(
            choose_archive_name(tmp.path(), &many, ArchiveFormat::TarGz),
            tmp.path().join("Archive.tar.gz")
        );
        std::fs::write(tmp.path().join("Archive.zip"), b"").unwrap();
        assert_eq!(
            choose_archive_name(tmp.path(), &many, ArchiveFormat::Zip),
            tmp.path().join("Archive 2.zip")
        );
    }

    #[test]
    fn choose_archive_name_uses_single_source_name() {
        let tmp = tempfile::tempdir().unwrap();
        let single = vec![PathBuf::from("/a/Photos")];
        assert_eq!(
            choose_archive_name(tmp.path(), &single, ArchiveFormat::Zip),
            tmp.path().join("Photos.zip")
        );
        std::fs::write(tmp.path().join("Photos.zip"), b"").unwrap();
        assert_eq!(
            choose_archive_name(tmp.path(), &single, ArchiveFormat::Zip),
            tmp.path().join("Photos 2.zip")
        );
    }

    #[test]
    fn choose_extract_dir_dedupes() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("photos.tar.gz");
        std::fs::write(&archive, b"").unwrap();
        std::fs::create_dir(tmp.path().join("photos")).unwrap();
        assert_eq!(choose_extract_dir(&archive), tmp.path().join("photos 2"));
    }

    #[test]
    fn cancel_mid_write_reports_cancelled() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("tree");
        make_tree(&src);
        let dest = tmp.path().join("out.zip");
        // The cancel flag turns on after the first member, so the failure
        // lands in the write loop and leaves a partial file behind.
        let saw_progress = AtomicBool::new(false);
        let cancel = || saw_progress.load(Ordering::Relaxed);
        let mut progress = |_: u64, _: u64, _: &str| saw_progress.store(true, Ordering::Relaxed);
        let result = create_archive(&[src], &dest, ArchiveFormat::Zip, &mut progress, &cancel);
        assert_eq!(result.unwrap_err(), "cancelled");
        assert!(dest.exists(), "the caller removes the partial archive");
    }
}
