//! Storage limits: a quota on each mailbox's stored bytes, and a floor on
//! free disk space for the spool and maildir filesystems. A mailbox's quota
//! comes from the recipient authority (its own `quota-bytes`, or its
//! domain's), falling back to the server's `mailbox-quota-bytes`; the floor
//! is the server's `min-free-disk-bytes`.
//!
//! Both refusals are temporary (`452`), so the sender's server retries
//! (for days) and nothing is bounced by us.

use std::path::PathBuf;

/// `452` for a recipient whose mailbox is over its quota (RFC 3463
/// 4.2.2). Per recipient: the transaction's other recipients are
/// unaffected.
pub(crate) const MAILBOX_FULL: &[u8] = b"452 4.2.2 Mailbox full, try again later\r\n";

/// `452` when the spool or maildir filesystem is below its free-space
/// floor (RFC 3463 4.3.1).
pub(crate) const INSUFFICIENT_STORAGE: &[u8] =
    b"452 4.3.1 Insufficient system storage, try again later\r\n";

/// The storage limits a session enforces.
#[derive(Debug, Clone, Default)]
pub(crate) struct StorageLimits {
    /// The server's default mailbox quota, used when the authority sets
    /// none, or `None` for no default quota.
    pub(crate) mailbox_quota: Option<u64>,
    /// The least free space the filesystems in `watched` must keep, or
    /// `None` for no check.
    pub(crate) min_free_disk: Option<u64>,
    /// Directories whose filesystems must keep `min_free_disk` free (the
    /// spool and the maildir root).
    pub(crate) watched: Vec<PathBuf>,
}

impl StorageLimits {
    /// No limits at all (tests, and a server configured with both set to
    /// 0).
    #[cfg(test)]
    pub(crate) fn unlimited() -> Self {
        Self::default()
    }

    /// Returns the quota that applies to a mailbox whose authority set
    /// `authority` (see [`crate::authority::Recipient::quota_bytes`]): the
    /// authority's value when it set one (`Some(0)` meaning none), else
    /// the server default.
    pub(crate) fn quota_for(&self, authority: Option<u64>) -> Option<u64> {
        match authority {
            Some(0) => None,
            Some(quota) => Some(quota),
            None => self.mailbox_quota,
        }
    }
}

/// Whether a mailbox holding `usage` bytes, under `quota`, may take a
/// message of `incoming` bytes (0 when the size isn't known yet): it must
/// be under its quota, and the message must fit. The check is made at
/// RCPT, before the data, so with an undeclared size a mailbox can end up
/// over its quota by at most one message.
pub(crate) fn has_room(quota: u64, usage: u64, incoming: u64) -> bool {
    usage < quota && usage.saturating_add(incoming) <= quota
}

impl StorageLimits {
    /// Check every watched filesystem against the free-space floor (one
    /// `statvfs` each).
    ///
    /// Returns the first directory below the floor with its free bytes,
    /// or `None` when all have room (or there is no floor). A directory
    /// that can't be measured counts as full: failing closed only defers
    /// mail.
    pub(crate) fn low_disk(&self) -> Option<(PathBuf, u64)> {
        let floor = self.min_free_disk?;
        self.watched.iter().find_map(|dir| {
            let free = crate::fsutil::free_bytes(dir).unwrap_or(0);
            (free < floor).then(|| (dir.clone(), free))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message fits up to and including the quota, but a mailbox at its
    /// quota takes nothing more.
    #[test]
    fn mailbox_quota_boundaries() {
        assert!(has_room(1000, 900, 100));
        assert!(!has_room(1000, 900, 101));
        assert!(!has_room(1000, 1001, 0), "already over");
        assert!(has_room(1000, 0, 0));
        assert!(has_room(1000, 999, 0));
        assert!(!has_room(1000, 1000, 0), "at the quota");
        assert!(!has_room(1000, u64::MAX, 1), "no overflow");
    }

    /// The authority's quota wins (0 meaning none); without one the
    /// server default applies.
    #[test]
    fn authority_quota_overrides_the_default() {
        let limits = StorageLimits {
            mailbox_quota: Some(5000),
            ..StorageLimits::default()
        };
        assert_eq!(limits.quota_for(None), Some(5000));
        assert_eq!(limits.quota_for(Some(9000)), Some(9000));
        assert_eq!(limits.quota_for(Some(0)), None);
        assert_eq!(StorageLimits::unlimited().quota_for(None), None);
        assert_eq!(StorageLimits::unlimited().quota_for(Some(9000)), Some(9000));
    }

    /// A floor above any real disk reports the directory; a floor of one
    /// byte doesn't; a directory that can't be measured counts as full.
    #[test]
    fn free_disk_floor() {
        let dir = tempfile::tempdir().unwrap();
        let mut limits = StorageLimits {
            min_free_disk: Some(u64::MAX),
            watched: vec![dir.path().to_path_buf()],
            ..StorageLimits::default()
        };
        assert_eq!(
            limits.low_disk().map(|(d, _)| d),
            Some(dir.path().to_path_buf())
        );
        limits.min_free_disk = Some(1);
        assert_eq!(limits.low_disk(), None);
        limits.watched.push(dir.path().join("missing"));
        assert!(limits.low_disk().is_some(), "unmeasurable counts as full");
        assert_eq!(StorageLimits::unlimited().low_disk(), None);
    }
}
