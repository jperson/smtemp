//! Private file and directory creation for the spool and the maildirs.
//!
//! Mail is personal data: everything mailserv stores is created readable
//! by the service user only — files `0600`, directories `0700` — whatever
//! the process umask is (D4 in DEPLOYMENT.md; previously the umask
//! decided, which typically meant world-readable `0644`/`0755`). The
//! startup `umask(0o077)` in `main` is defense in depth for anything
//! created elsewhere. The modes only ever remove permissions relative to
//! the umask, never add them.

use std::fs::File;
use std::io;
use std::path::Path;

/// Mode for every directory mailserv creates (owner only).
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Mode for every file mailserv creates (owner read/write).
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// `create_dir_all` with [`PRIVATE_DIR_MODE`] for each directory it
/// creates. Existing directories are left as they are (see
/// [`warn_if_shared`]).
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

/// `File::create` (create or truncate, write-only) with
/// [`PRIVATE_FILE_MODE`] for a newly created file.
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
/// directories owned by `uid:gid`. Used by root just before dropping
/// privileges, so the unprivileged process owns the spool and maildir
/// trees it must write. Directories that already exist are left alone,
/// whoever owns them.
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
        std::os::unix::fs::chown(dir, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// If `path` is a directory that group or other users can access, the
/// permission bits that are too open (for the startup warning). `None`
/// when it is private, missing, or not on Unix.
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

#[cfg(test)]
mod tests {
    use super::*;

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
