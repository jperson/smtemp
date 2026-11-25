//! Private file and directory creation for the spool and the maildirs.
//!
//! Mail is personal data: everything mailserv stores is created readable
//! by the service user only — files `0600`, directories `0700` — whatever
//! the process umask is. The startup `umask(0o077)` in `main` is defense
//! in depth for anything created elsewhere. The modes only ever remove permissions relative to
//! the umask, never add them.

use std::fs::File;
use std::io;
use std::path::Path;

/// Mode for every directory mailserv creates (owner only).
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Mode for every file mailserv creates (owner read/write).
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Create `path` and any missing parents, like `create_dir_all`, giving
/// each newly created directory [`PRIVATE_DIR_MODE`].
///
/// Existing directories are left as they are (see [`shared_bits`] for
/// detecting ones that are too open).
///
/// # Errors
///
/// Any I/O error from creating a directory.
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(PRIVATE_DIR_MODE);
    }
    builder.create(path)
}

/// Open `path` for writing like `File::create` (create or truncate),
/// giving a newly created file [`PRIVATE_FILE_MODE`]. An existing file
/// keeps its mode.
///
/// Returns the open, write-only file.
///
/// # Errors
///
/// Any I/O error from opening the file.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(PRIVATE_FILE_MODE);
    }
    options.open(path)
}

/// Create `path` and any missing parent directories as private
/// ([`PRIVATE_DIR_MODE`]) directories owned by `uid`:`gid`.
///
/// Used by root just before dropping privileges, so the unprivileged
/// process owns the spool and maildir trees it must write. Directories
/// that already exist are left alone, whoever owns them.
///
/// Ownership is changed through a handle, never by path: each new
/// directory is opened with `O_DIRECTORY | O_NOFOLLOW`, checked to be
/// owned by the current user (the directory just made), and `fchown`ed.
/// A directory swapped for a symlink between the `mkdir` and the `chown`
/// therefore can't make root hand some other file to `uid`.
///
/// # Errors
///
/// Any I/O error from creating, opening or `fchown`ing a directory; a
/// path that is no longer a directory (a symlink: `ELOOP`), or one not
/// owned by the current user, is refused. A directory created
/// concurrently (`AlreadyExists`) is not an error.
#[cfg(unix)]
pub fn create_owned_dir_all(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut missing = Vec::new();
    let mut current = Some(path);
    while let Some(p) = current {
        if p.as_os_str().is_empty() || p.exists() {
            break;
        }
        missing.push(p);
        current = p.parent();
    }
    for dir in missing.into_iter().rev() {
        match std::fs::DirBuilder::new()
            .mode(PRIVATE_DIR_MODE)
            .create(dir)
        {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        hand_over_dir(dir, uid, gid)?;
    }
    Ok(())
}

/// Give the directory just created at `dir` to `uid`:`gid` through an
/// open handle (see [`create_owned_dir_all`]).
///
/// # Errors
///
/// `dir` can't be opened as a directory without following a symlink, or
/// isn't owned by the current user, or `fchown` fails.
#[cfg(unix)]
fn hand_over_dir(dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    // SAFETY: geteuid has no preconditions and can't fail.
    let me = unsafe { libc::geteuid() };
    let meta = handle.metadata()?;
    if !meta.is_dir() || meta.uid() != me {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} changed after it was created; not changing its owner",
                dir.display()
            ),
        ));
    }
    std::os::unix::fs::fchown(&handle, Some(uid), Some(gid))
}

/// Check whether `path` is accessible to group or other users, for the
/// startup warning.
///
/// Returns the group/other permission bits that are set (`mode & 0o077`),
/// or `None` when `path` is private, missing, or the platform is not Unix.
///
/// Existing directories are never changed automatically: an operator may
/// have opened one up deliberately (e.g. for a reader process's group).
pub fn shared_bits(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path).ok()?.permissions().mode();
        let open = mode & 0o077;
        (open != 0).then_some(open)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Returns when the file at `path` last changed, in Unix seconds: its
/// ctime on Unix (updated by rename, write and chmod), its mtime
/// elsewhere. `None` if it can't be read.
pub fn changed_at(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        u64::try_from(meta.ctime()).ok()
    }
    #[cfg(not(unix))]
    {
        meta.modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    }
}

/// Returns the bytes available to unprivileged users on the filesystem
/// holding `path` (`statvfs`: available blocks × fragment size).
///
/// # Errors
///
/// `path` contains a NUL byte or `statvfs` fails (e.g. it doesn't exist).
pub fn free_bytes(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_path` is a valid NUL-terminated string and `stat` is a
    // properly sized, writable `statvfs` the call fills in.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::useless_conversion)] // the field types vary by platform
    Ok(u64::from(stat.f_bavail).saturating_mul(u64::from(stat.f_frsize)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The free space of an existing directory is reported; a missing
    /// path is an error.
    /// New directories, parents included, are created private and handed
    /// over through a handle (to our own ids here, unprivileged); a symlink
    /// standing where a new directory should be is refused, not followed.
    #[cfg(unix)]
    #[test]
    fn owned_dirs_are_handed_over_without_following_symlinks() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let nested = dir.path().join("a/b/c");
        create_owned_dir_all(&nested, uid, gid).unwrap();
        for p in [dir.path().join("a"), dir.path().join("a/b"), nested.clone()] {
            let meta = std::fs::metadata(&p).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (uid, gid));
            assert_eq!(meta.permissions().mode() & 0o777, 0o700, "{}", p.display());
        }
        create_owned_dir_all(&nested, uid, gid).unwrap();

        let target = dir.path().join("precious");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("swapped");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // Refused before anything changes hands; with O_DIRECTORY |
        // O_NOFOLLOW Linux reports ENOTDIR or ELOOP.
        let refused = |e: io::Error| matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR));
        assert!(refused(hand_over_dir(&link, uid, gid).unwrap_err()));
        let dir_link = dir.path().join("swapped-dir");
        std::os::unix::fs::symlink(dir.path().join("a"), &dir_link).unwrap();
        assert!(refused(hand_over_dir(&dir_link, uid, gid).unwrap_err()));
    }

    #[test]
    fn free_bytes_reports_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        assert!(free_bytes(dir.path()).unwrap() > 0);
        assert!(free_bytes(&dir.path().join("missing")).is_err());
    }

    /// Created files and directories are private even under a permissive
    /// umask (the test process's umask is typically 022).
    #[cfg(unix)]
    #[test]
    fn created_paths_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c");
        create_private_dir_all(&nested).unwrap();
        for d in ["a", "a/b", "a/b/c"] {
            let mode = std::fs::metadata(dir.path().join(d))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{d}: {mode:o}");
        }
        let file = nested.join("msg.eml");
        create_private_file(&file).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");

        assert_eq!(shared_bits(&nested), None);
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(shared_bits(&nested), Some(0o055));
    }
}
