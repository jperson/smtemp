//! Dropping root privileges after binding the SMTP port (D4, DEPLOYMENT.md).
//!
//! Port 25 is privileged. mailserv may start as root to bind it, but then
//! switches to an unprivileged user (`--user`, optionally `--group`)
//! **before** it opens the spool, the maildirs or the recipient authority,
//! and before it handles a single connection. Everything an attacker could
//! reach through SMTP runs without root.
//!
//! The rules ([`plan`]):
//! - started as root with `--user`: drop to that user (never to root);
//! - started as root without `--user`: refuse to start;
//! - started as another user: no switch is possible; `--user`, if given,
//!   must name that same user (this is the systemd `CAP_NET_BIND_SERVICE`
//!   setup, and the unprivileged `--port 2525` test setup).
//!
//! [`drop_to`] clears supplementary groups, then sets the gid and the uid
//! (real, effective and saved), and verifies that root can't be regained.
//! glibc and musl apply these calls to every thread of the process, so the
//! async runtime's existing worker threads are switched too.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::CString;

/// The identity to run as after binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// User name as configured (for logs).
    pub user: String,
    /// Numeric user id.
    pub uid: u32,
    /// Numeric group id: `--group`, or the user's primary group.
    pub gid: u32,
}

/// Resolve `--user` (name or numeric uid) and `--group` (name or numeric
/// gid; default: the user's primary group) through the system's user
/// database.
///
/// Returns `Err` if the user or group doesn't exist.
pub fn lookup(user: &str, group: Option<&str>) -> Result<Identity> {
    let (uid, primary_gid) = match user.parse::<u32>() {
        Ok(uid) => passwd_by_uid(uid)?,
        Err(_) => passwd_by_name(user)?,
    }
    .ok_or_else(|| anyhow!("user {user:?} does not exist"))?;
    let gid = match group {
        None => primary_gid,
        Some(g) => match g.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => group_by_name(g)?.ok_or_else(|| anyhow!("group {g:?} does not exist"))?,
        },
    };
    Ok(Identity {
        user: user.to_string(),
        uid,
        gid,
    })
}

/// Decide what to do, given the effective uid at startup and the resolved
/// `--user` identity (if configured). Pure, so the rules are unit-tested.
///
/// Returns `Ok(Some(identity))` to drop to that identity after binding,
/// `Ok(None)` to keep running as the current user, or `Err` to refuse to
/// start.
pub fn plan(euid: u32, target: Option<Identity>) -> Result<Option<Identity>> {
    match (euid, target) {
        (0, None) => bail!(
            "refusing to run as root without --user: set --user (and optionally --group) \
             so privileges are dropped right after binding the port, or run unprivileged \
             with CAP_NET_BIND_SERVICE"
        ),
        (0, Some(id)) if id.uid == 0 => {
            bail!("--user {:?} is root; choose an unprivileged user", id.user)
        }
        (0, Some(id)) => Ok(Some(id)),
        (_, None) => Ok(None),
        (euid, Some(id)) if id.uid == euid => Ok(None),
        (euid, Some(id)) => bail!(
            "cannot switch to user {:?} (uid {}): not running as root (uid {euid})",
            id.user,
            id.uid
        ),
    }
}

/// The current effective uid.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Switch the whole process to `id`, irrevocably: supplementary groups,
/// then gid, then uid (real, effective and saved, since we are root).
///
/// Returns `Err` if any call fails, or if afterwards the process could
/// still regain root or isn't running as `id`. The caller must then exit:
/// continuing would mean serving SMTP with privileges.
pub fn drop_to(id: &Identity) -> Result<()> {
    let gid = id.gid as libc::gid_t;
    // SAFETY: plain syscalls on scalar arguments; `&gid` outlives the call.
    unsafe {
        if libc::setgroups(1, &gid) != 0 {
            return Err(std::io::Error::last_os_error()).context("setgroups failed");
        }
        if libc::setgid(gid) != 0 {
            return Err(std::io::Error::last_os_error()).context("setgid failed");
        }
        if libc::setuid(id.uid as libc::uid_t) != 0 {
            return Err(std::io::Error::last_os_error()).context("setuid failed");
        }
    }
    // Verify: running as the target identity, and root is gone for good.
    // SAFETY: as above; a successful setuid(0) here is the failure we test for.
    let (uid, euid, gid_now, egid, regained) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
            libc::setuid(0) == 0,
        )
    };
    if regained || uid != id.uid || euid != id.uid || gid_now != id.gid || egid != id.gid {
        bail!(
            "privilege drop did not take effect (uid {uid}, euid {euid}, gid {gid_now}, \
             egid {egid}, root regained: {regained})"
        );
    }
    Ok(())
}

/// Set the process umask to `0o077`, so anything created without an
/// explicit mode is private to the service user (defense in depth; the
/// spool and maildirs set their modes explicitly, see `fsutil`).
pub fn restrict_umask() {
    // SAFETY: umask has no preconditions and cannot fail.
    unsafe {
        libc::umask(0o077);
    }
}

/// Run a `get*_r` lookup with a buffer that grows on `ERANGE`.
fn with_buffer<T>(
    mut call: impl FnMut(&mut [libc::c_char]) -> (libc::c_int, Option<T>),
) -> Result<Option<T>> {
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        let (rc, found) = call(&mut buf);
        match rc {
            0 => return Ok(found),
            libc::ERANGE if buf.len() < 1 << 20 => buf.resize(buf.len() * 2, 0),
            rc => {
                return Err(std::io::Error::from_raw_os_error(rc))
                    .context("user database lookup failed")
            }
        }
    }
}

/// `(uid, primary gid)` for a user name.
fn passwd_by_name(name: &str) -> Result<Option<(u32, u32)>> {
    let cname = CString::new(name).context("user name contains NUL")?;
    with_buffer(|buf| {
        // SAFETY: getpwnam_r writes only into `pwd` and `buf` (whose length
        // it is given); `result` is null or points at `pwd`.
        unsafe {
            let mut pwd: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            );
            (rc, (!result.is_null()).then_some((pwd.pw_uid, pwd.pw_gid)))
        }
    })
}

/// `(uid, primary gid)` for a numeric uid.
fn passwd_by_uid(uid: u32) -> Result<Option<(u32, u32)>> {
    with_buffer(|buf| {
        // SAFETY: as in `passwd_by_name`.
        unsafe {
            let mut pwd: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result);
            (rc, (!result.is_null()).then_some((pwd.pw_uid, pwd.pw_gid)))
        }
    })
}

/// The gid for a group name.
fn group_by_name(name: &str) -> Result<Option<u32>> {
    let cname = CString::new(name).context("group name contains NUL")?;
    with_buffer(|buf| {
        // SAFETY: as in `passwd_by_name`, for the group database.
        unsafe {
            let mut grp: libc::group = std::mem::zeroed();
            let mut result: *mut libc::group = std::ptr::null_mut();
            let rc = libc::getgrnam_r(
                cname.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            );
            (rc, (!result.is_null()).then_some(grp.gr_gid))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(user: &str, uid: u32) -> Identity {
        Identity {
            user: user.into(),
            uid,
            gid: uid,
        }
    }

    /// The startup rules: root must drop (and never to root); a non-root
    /// process can't switch, but may name itself.
    #[test]
    fn plan_rules() {
        assert!(plan(0, None).is_err(), "root without --user is refused");
        assert!(plan(0, Some(id("root", 0))).is_err(), "never drop to root");
        assert_eq!(
            plan(0, Some(id("mailserv", 990))).unwrap(),
            Some(id("mailserv", 990))
        );
        assert_eq!(plan(1000, None).unwrap(), None);
        assert_eq!(plan(1000, Some(id("me", 1000))).unwrap(), None);
        let err = plan(1000, Some(id("mailserv", 990)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not running as root"), "{err}");
    }

    /// Lookups work against the real user database: the current user by
    /// uid and by name, and unknown names are errors.
    #[test]
    fn lookup_users_and_groups() {
        let uid = effective_uid();
        let by_uid = lookup(&uid.to_string(), None).unwrap();
        assert_eq!(by_uid.uid, uid);

        // root always exists, by name, with gid 0 for the root group.
        let root = lookup("root", Some("0")).unwrap();
        assert_eq!((root.uid, root.gid), (0, 0));

        assert!(lookup("no-such-user-mailserv-test", None).is_err());
        assert!(lookup("root", Some("no-such-group-mailserv-test")).is_err());
    }

    /// As a non-root user, a drop to someone else must fail (and the
    /// process keeps running as itself); this exercises the syscall path
    /// without root.
    #[test]
    fn drop_without_root_fails() {
        if effective_uid() == 0 {
            return; // would really drop the test runner's privileges
        }
        let other = Identity {
            user: "root".into(),
            uid: 0,
            gid: 0,
        };
        assert!(drop_to(&other).is_err());
    }
}
