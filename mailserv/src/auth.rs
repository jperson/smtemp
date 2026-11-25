//! Authenticated-sender authorization: which `MAIL FROM` / `From:`
//! addresses an AUTH identity may use.
//!
//! AUTH proves *who* the client is. This module answers the separate
//! question of *what that identity may claim*: each login maps to a set of
//! exact addresses and whole domains (`--auth-senders`). The SPF skip and
//! the DMARC-rejection exemption that authenticated sessions get are only
//! safe because every `MAIL FROM` and every `From:` author of an
//! authenticated session is checked against that set first, so being
//! authenticated never means "may use any From".
//!
//! Fail-closed: a login with no grants can authenticate but can't send
//! anything, and the null sender is never allowed for an authenticated
//! session.
//!
//! Credentials come from a file (`--auth-users-file`), never from argv,
//! and the file holds only **argon2id hashes** (PHC strings, made with
//! `mailserv hash-password`), never passwords. Checking a password
//! ([`AuthConfig::check`]) is rate-limited per session (by the caller) and
//! per source IP, bounded in concurrency, and run on the blocking pool;
//! the hash comparison itself is constant-time.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHashString, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::limit::{FailureLimiter, AUTH_FAILURES_PER_IP, AUTH_FAILURE_WINDOW};

/// Hash `password` for the credentials file: argon2id (v19) with the
/// crate's default parameters (19 MiB of memory, 2 passes, 1 lane: the
/// OWASP baseline) and a random 16-byte salt.
///
/// Returns the PHC string, e.g. `$argon2id$v=19$m=19456,t=2,p=1$...`.
///
/// # Errors
///
/// Hashing fails (not expected with the default parameters).
pub fn hash_password(password: &str) -> Result<String> {
    hash_with(Argon2::default(), password)
}

/// Hash `password` with the argon2 context `argon2` and a random salt.
///
/// # Errors
///
/// Hashing fails (invalid parameters).
fn hash_with(argon2: Argon2<'_>, password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hashing failed: {e}"))?
        .to_string())
}

/// Parse `value` as an argon2id PHC string with usable parameters and a
/// hash output.
///
/// # Errors
///
/// Why it isn't one (never echoing `value`, which might be a password).
fn parse_argon2id(value: &str) -> std::result::Result<PasswordHashString, String> {
    let hash = PasswordHashString::new(value).map_err(|_| "not a PHC hash string".to_string())?;
    let parsed = hash.password_hash();
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Err(format!("algorithm is {}, not argon2id", parsed.algorithm));
    }
    Params::try_from(&parsed).map_err(|e| format!("invalid parameters: {e}"))?;
    if parsed.salt.is_none() || parsed.hash.is_none() {
        return Err("missing salt or hash".to_string());
    }
    Ok(hash)
}

/// Below these argon2id costs a hash is weaker than OWASP's minimum
/// recommendations (which trade memory against passes, from 47 MiB × 1 to
/// 7 MiB × 5): at least 7 MiB, and memory × passes of at least 35 MiB.
const MIN_MEMORY_KIB: u32 = 7 * 1024;
/// See [`MIN_MEMORY_KIB`].
const MIN_MEMORY_TIMES_PASSES_KIB: u64 = 35 * 1024;

/// How many failed attempts one session may make before AUTH is refused
/// for the rest of it (without hashing anything).
pub const MAX_FAILURES_PER_SESSION: u32 = 3;

/// The outcome of [`AuthConfig::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCheck {
    /// The password matches the login.
    Accepted,
    /// Unknown login or wrong password (the two are indistinguishable).
    Rejected,
    /// The source IP has used up its failure budget; nothing was checked.
    Blocked,
}

/// One loaded set of logins: the credential store, the dummy hash for
/// unknown logins, and each login's sender grants. Replaced as a whole
/// on reload, so a check never sees half of one file and half of
/// another.
struct Logins {
    /// `user -> argon2id hash`.
    credentials: HashMap<String, PasswordHashString>,
    /// An argon2id hash of a random password with the same parameters as
    /// the first credential, checked for unknown logins so they cost as
    /// much as a wrong password.
    dummy: PasswordHashString,
    /// `user -> addresses/domains` that user may send as.
    senders: SenderGrants,
}

impl Logins {
    /// Build from the contents of a credentials file, `credentials`, and
    /// the `--auth-senders` spec `senders_spec`.
    ///
    /// The credentials format is one `user:hash` per line, where `hash`
    /// is an argon2id PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$
    /// hash`, as printed by `mailserv hash-password`). The user and hash
    /// are trimmed. Blank lines and lines starting with `#` (after leading
    /// whitespace) are ignored. `senders_spec` is the [`SenderGrants`]
    /// spec; `None` or a blank spec means no login has any grants.
    ///
    /// With `strict`, a grant for a login that isn't in the file is an
    /// error (at startup it's almost always a typo, and ignoring it would
    /// leave the intended user unable to send). Otherwise it is ignored
    /// (on reload it means the login was revoked) and listed by
    /// [`Logins::orphaned_grants`].
    ///
    /// One argon2 hash is computed here (the dummy for unknown logins),
    /// with the first credential's parameters.
    ///
    /// # Errors
    ///
    /// A line without a `:`, an empty user, a value that is not an
    /// argon2id PHC string (including a plaintext password), a user listed
    /// twice, no users at all, any [`SenderGrants::parse`] error, or (with
    /// `strict`) a grant for a login that has no credentials. Errors name
    /// the line number, never the value.
    fn parse(credentials: &str, senders_spec: Option<&str>, strict: bool) -> Result<Self> {
        let mut hashes: HashMap<String, PasswordHashString> = HashMap::new();
        let mut first: Option<PasswordHashString> = None;
        for (index, line) in credentials.lines().enumerate() {
            let number = index + 1;
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let Some((user, value)) = line.split_once(':') else {
                bail!("line {number}: expected user:hash");
            };
            let user = user.trim();
            if user.is_empty() {
                bail!("line {number}: empty user name");
            }
            let hash = parse_argon2id(value.trim()).map_err(|why| {
                anyhow!(
                    "line {number}: the value for {user:?} is not an argon2id hash ({why}); \
                     generate one with `mailserv hash-password`"
                )
            })?;
            first.get_or_insert_with(|| hash.clone());
            if hashes.insert(user.to_string(), hash).is_some() {
                bail!("line {number}: {user:?} is listed more than once");
            }
        }
        let Some(first) = first else {
            bail!("no users defined");
        };
        let senders = match senders_spec {
            Some(spec) if !spec.trim().is_empty() => SenderGrants::parse(spec)?,
            _ => SenderGrants::default(),
        };
        if strict {
            for user in senders.by_user.keys() {
                if !hashes.contains_key(user) {
                    bail!("--auth-senders names {user:?}, which has no credentials");
                }
            }
        }

        // The dummy shares the first credential's parameters, so an unknown
        // login costs the same as a typical known one.
        let params = Params::try_from(&first.password_hash())
            .map_err(|e| anyhow!("unusable argon2 parameters: {e}"))?;
        let random_password = SaltString::generate(&mut OsRng);
        let dummy = hash_with(
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
            random_password.as_str(),
        )?;
        let dummy =
            PasswordHashString::new(&dummy).map_err(|e| anyhow!("dummy hash unparseable: {e}"))?;
        Ok(Logins {
            credentials: hashes,
            dummy,
            senders,
        })
    }

    /// Returns the logins named by the grants spec that aren't in the
    /// credentials (so their grants are inert), sorted.
    fn orphaned_grants(&self) -> Vec<String> {
        let mut users: Vec<String> = self
            .senders
            .by_user
            .keys()
            .filter(|u| !self.credentials.contains_key(*u))
            .cloned()
            .collect();
        users.sort_unstable();
        users
    }

    /// Read and parse the credentials file at `path` with the grants spec
    /// `senders_spec`; `strict` as in [`Logins::parse`].
    ///
    /// # Errors
    ///
    /// The file is accessible to other users or can't be read, or
    /// [`Logins::parse`] fails; the message names the file.
    fn load(path: &Path, senders_spec: Option<&str>, strict: bool) -> Result<Self> {
        if let Some(bits) = crate::fsutil::shared_bits(path) {
            if bits & 0o007 != 0 {
                bail!(
                    "credentials file {} is accessible to other users (mode bits {bits:03o}); \
                     chmod o-rwx it",
                    path.display()
                );
            }
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read credentials file {}", path.display()))?;
        Self::parse(&text, senders_spec, strict)
            .with_context(|| format!("invalid credentials file {}", path.display()))
    }
}

/// What a successful [`AuthConfig::reload`] loaded, for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadSummary {
    /// Logins that can authenticate now.
    pub users: usize,
    /// Logins that were removed by this reload, sorted.
    pub removed: Vec<String>,
    /// Logins added by this reload, sorted.
    pub added: Vec<String>,
    /// Logins with `--auth-senders` grants but no credentials (revoked
    /// logins whose grants are now inert), sorted.
    pub orphaned_grants: Vec<String>,
}

/// AUTH configuration: the current set of logins (credentials and sender
/// grants), where it was loaded from, and the shared guards that bound
/// password checking. Grants only exist alongside credentials, so the
/// type rules out a configuration that authorizes senders without AUTH.
///
/// The logins can be replaced at runtime ([`AuthConfig::reload`]); the
/// per-IP failure counts and the check slots carry over.
pub struct AuthConfig {
    /// The current logins.
    logins: RwLock<Arc<Logins>>,
    /// The credentials file, when loaded from one (reload needs it).
    path: Option<PathBuf>,
    /// The `--auth-senders` spec, re-applied to each reloaded file.
    senders_spec: Option<String>,
    /// Failed attempts per source IP.
    failures: FailureLimiter,
    /// Bounds concurrent hash checks to the number of CPUs, so AUTH
    /// attempts can't monopolize the blocking pool.
    checks: tokio::sync::Semaphore,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the hashes.
        let logins = self.current();
        f.debug_struct("AuthConfig")
            .field("path", &self.path)
            .field("users", &logins.credentials.len())
            .field("senders", &logins.senders)
            .finish_non_exhaustive()
    }
}

impl AuthConfig {
    /// Load the credentials file at `path` and combine it with the
    /// `--auth-senders` spec `senders_spec` (see [`Logins::parse`] for both
    /// formats). The path and spec are kept for [`AuthConfig::reload`].
    ///
    /// The file must not be accessible to "other" users. Group access is
    /// allowed: `root:<service group> 0640` lets the service user re-read
    /// it after dropping privileges.
    ///
    /// # Errors
    ///
    /// The file can't be read, is accessible to other users, or fails
    /// [`Logins::parse`] (strictly: a grant must name a login).
    pub fn load(path: &Path, senders_spec: Option<&str>) -> Result<Self> {
        let logins = Logins::load(path, senders_spec, true)?;
        Ok(Self::with_logins(
            logins,
            Some(path.to_path_buf()),
            senders_spec,
        ))
    }

    /// Build from the contents of a credentials file, `credentials`, and
    /// the `--auth-senders` spec `senders_spec` (test helper). Such a
    /// configuration has no file, so it can't be reloaded.
    ///
    /// # Errors
    ///
    /// As [`Logins::parse`], strictly.
    #[cfg(test)]
    pub fn from_credentials(credentials: &str, senders_spec: Option<&str>) -> Result<Self> {
        let logins = Logins::parse(credentials, senders_spec, true)?;
        Ok(Self::with_logins(logins, None, senders_spec))
    }

    /// Wrap `logins`, loaded from `path` with `senders_spec`, with fresh
    /// failure counts and check slots.
    fn with_logins(logins: Logins, path: Option<PathBuf>, senders_spec: Option<&str>) -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        AuthConfig {
            logins: RwLock::new(Arc::new(logins)),
            path,
            senders_spec: senders_spec.map(str::to_string),
            failures: FailureLimiter::new(AUTH_FAILURES_PER_IP, AUTH_FAILURE_WINDOW),
            checks: tokio::sync::Semaphore::new(cpus),
        }
    }

    /// Returns the current logins.
    fn current(&self) -> Arc<Logins> {
        // A poisoned lock still holds a complete snapshot (the writer only
        // swaps an Arc).
        Arc::clone(&self.logins.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Re-read the credentials file and re-apply the `--auth-senders`
    /// spec, replacing the logins at once. Blocking (file I/O and one
    /// argon2 hash); call it from the blocking pool.
    ///
    /// Sessions that already authenticated stay authenticated, but a
    /// removed login can no longer send ([`AuthConfig::permits`]), and new
    /// AUTH attempts use the new file. Failure counts are kept.
    ///
    /// Unlike at startup, a grant for a login that is no longer in the
    /// file is not an error: removing the login is how it is revoked. The
    /// grant is inert and reported in [`ReloadSummary::orphaned_grants`].
    ///
    /// Returns what changed.
    ///
    /// # Errors
    ///
    /// This configuration wasn't loaded from a file, or the file fails
    /// [`AuthConfig::load`]'s other checks. The current logins are then
    /// kept unchanged.
    pub fn reload(&self) -> Result<ReloadSummary> {
        let Some(path) = &self.path else {
            bail!("these credentials were not loaded from a file");
        };
        let new = Logins::load(path, self.senders_spec.as_deref(), false)?;
        let old = self.current();
        let mut removed: Vec<String> = old
            .credentials
            .keys()
            .filter(|u| !new.credentials.contains_key(*u))
            .cloned()
            .collect();
        let mut added: Vec<String> = new
            .credentials
            .keys()
            .filter(|u| !old.credentials.contains_key(*u))
            .cloned()
            .collect();
        removed.sort_unstable();
        added.sort_unstable();
        let users = new.credentials.len();
        let orphaned_grants = new.orphaned_grants();
        *self.logins.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(new);
        Ok(ReloadSummary {
            users,
            removed,
            added,
            orphaned_grants,
        })
    }

    /// Returns the number of logins that can authenticate.
    pub fn user_count(&self) -> usize {
        self.current().credentials.len()
    }

    /// Returns the logins whose hash parameters are below OWASP's minimum
    /// recommendations (see [`MIN_MEMORY_KIB`]), sorted, for a warning.
    /// They still work.
    pub fn weak_hash_users(&self) -> Vec<String> {
        let logins = self.current();
        let mut weak: Vec<String> = logins
            .credentials
            .iter()
            .filter(|(_, hash)| {
                Params::try_from(&hash.password_hash()).map_or(true, |p| {
                    p.m_cost() < MIN_MEMORY_KIB
                        || u64::from(p.m_cost()) * u64::from(p.t_cost())
                            < MIN_MEMORY_TIMES_PASSES_KIB
                })
            })
            .map(|(user, _)| user.clone())
            .collect();
        weak.sort_unstable();
        weak
    }

    /// Check the password `pass` for login `user`, connecting from `ip`.
    ///
    /// Refused at once (no hashing) when `ip` has used up its failure
    /// budget ([`AUTH_FAILURES_PER_IP`] per [`AUTH_FAILURE_WINDOW`]).
    /// Otherwise waits for one of the CPU-count check slots and runs
    /// [`AuthConfig::verify`] on the blocking pool; a failure is counted
    /// against `ip`. The caller enforces [`MAX_FAILURES_PER_SESSION`].
    ///
    /// Returns the outcome; a panicked check counts as [`AuthCheck::Rejected`].
    pub async fn check(self: &Arc<Self>, ip: IpAddr, user: &str, pass: &str) -> AuthCheck {
        if self.failures.is_blocked(ip) {
            return AuthCheck::Blocked;
        }
        let accepted = {
            let Ok(_slot) = self.checks.acquire().await else {
                return AuthCheck::Rejected; // never closed
            };
            let (auth, user, pass) = (Arc::clone(self), user.to_string(), pass.to_string());
            tokio::task::spawn_blocking(move || auth.verify(&user, &pass))
                .await
                .unwrap_or(false)
        };
        if accepted {
            AuthCheck::Accepted
        } else {
            self.failures.record_failure(ip);
            AuthCheck::Rejected
        }
    }

    /// Check the password `pass` for login `user` against the current
    /// logins. Blocking and deliberately slow (one argon2id evaluation);
    /// use [`AuthConfig::check`] from async code.
    ///
    /// Returns `true` only when `user` exists and `pass` matches. The hash
    /// comparison is constant-time, and an unknown login is checked
    /// against a dummy hash with the same parameters, so the time taken
    /// reveals neither how close a guess was nor whether the login exists.
    pub fn verify(&self, user: &str, pass: &str) -> bool {
        let logins = self.current();
        let (hash, known) = match logins.credentials.get(user) {
            Some(hash) => (hash, true),
            None => (&logins.dummy, false),
        };
        let matches = Argon2::default()
            .verify_password(pass.as_bytes(), &hash.password_hash())
            .is_ok();
        matches && known
    }

    /// Whether login `user` may send as `local@domain`: the login must
    /// still exist in the current credentials (so a reload revokes it,
    /// even for a session that authenticated earlier) and hold a grant
    /// for the address (see [`SenderGrants::permits`]).
    pub fn permits(&self, user: &str, local: &str, domain: &str) -> bool {
        let logins = self.current();
        logins.credentials.contains_key(user) && logins.senders.permits(user, local, domain)
    }

    /// Returns the logins that can authenticate but have no sender grants
    /// (so every `MAIL FROM` they send is refused), sorted for stable logs.
    pub fn users_without_grants(&self) -> Vec<String> {
        let logins = self.current();
        let mut users: Vec<String> = logins
            .credentials
            .keys()
            .filter(|u| !logins.senders.by_user.contains_key(*u))
            .cloned()
            .collect();
        users.sort_unstable();
        users
    }
}

/// What one login may send as.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Grant {
    /// Exact addresses, normalized (see [`normalize`]).
    addresses: HashSet<String>,
    /// Whole domains (`@example.org` in the spec), lowercased.
    domains: HashSet<String>,
}

/// Per-login sender grants, from `--auth-senders`.
///
/// Spec: comma-separated `user=grant|grant|...` entries, where a grant is
/// either an exact address (`alice@example.org`) or a whole domain
/// (`@example.org`). Example:
/// `alice=alice@example.org|@example.net,bob=bob@example.org`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SenderGrants {
    /// Login name -> what that login may send as.
    by_user: HashMap<String, Grant>,
}

impl SenderGrants {
    /// Parse an `--auth-senders` `spec` (format above).
    ///
    /// # Errors
    ///
    /// An entry without `=` or with an empty user, a grant that has no
    /// `@` (including an empty grant list), a grant with an implausible
    /// domain, or a login listed twice.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut by_user: HashMap<String, Grant> = HashMap::new();
        for entry in spec.split(',') {
            let entry = entry.trim();
            let Some((user, grants)) = entry.split_once('=') else {
                bail!("--auth-senders entries must be user=address|@domain, got {entry:?}");
            };
            let user = user.trim();
            if user.is_empty() {
                bail!("--auth-senders entry {entry:?} has no user");
            }
            let mut grant = Grant::default();
            for item in grants.split('|').map(str::trim) {
                let Some((local, domain)) = item.rsplit_once('@') else {
                    bail!(
                        "--auth-senders grant {item:?} for {user:?} must be an address or @domain"
                    );
                };
                let Some(domain) = normalize_domain(domain) else {
                    bail!("--auth-senders grant {item:?} for {user:?} has an invalid domain");
                };
                if local.is_empty() {
                    grant.domains.insert(domain);
                } else {
                    grant.addresses.insert(normalize(local, &domain));
                }
            }
            if by_user.insert(user.to_string(), grant).is_some() {
                bail!("--auth-senders lists {user:?} more than once");
            }
        }
        Ok(SenderGrants { by_user })
    }

    /// May login `user` send as `local@domain`?
    ///
    /// Returns `true` when `user` has a grant for the exact address or for
    /// the whole domain; `false` for an unknown login, an empty
    /// local-part, or an implausible domain.
    ///
    /// The domain is compared case-insensitively (DNS names are). The
    /// local-part is compared ASCII-case-insensitively too: RFC 5321
    /// leaves its case to the receiving host, and every hosted mailbox here
    /// is case-insensitive, so `Alice@` is the same mailbox as `alice@`.
    /// Being looser here never grants another user's mailbox.
    pub fn permits(&self, user: &str, local: &str, domain: &str) -> bool {
        let Some(grant) = self.by_user.get(user) else {
            return false;
        };
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };
        if local.is_empty() {
            return false;
        }
        grant.domains.contains(&domain) || grant.addresses.contains(&normalize(local, &domain))
    }
}

/// Returns `local@domain` with `local` ASCII-lowercased. `domain` must
/// already be normalized (see [`normalize_domain`]).
fn normalize(local: &str, domain: &str) -> String {
    format!("{}@{domain}", local.to_ascii_lowercase())
}

/// Normalize `domain` for comparison.
///
/// Returns it trimmed, lowercased and without a trailing dot, or `None`
/// unless it looks like a hostname (non-empty labels of ASCII letters,
/// digits, `-` and `_`).
fn normalize_domain(domain: &str) -> Option<String> {
    let d = domain.trim();
    let d = d.strip_suffix('.').unwrap_or(d);
    let plausible = !d.is_empty()
        && d.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    plausible.then(|| d.to_ascii_lowercase())
}

/// Split an envelope path address `addr` (`local@domain`, brackets
/// already removed) at its last `@`.
///
/// Returns `(local, domain)`, or `None` for the null sender or an address
/// with no `@`, an empty local-part or an empty domain.
pub fn split_address(addr: &str) -> Option<(&str, &str)> {
    let (local, domain) = addr.rsplit_once('@')?;
    (!local.is_empty() && !domain.is_empty()).then_some((local, domain))
}

/// Hash `password` with the cheapest argon2id parameters (8 KiB, 1 pass),
/// so tests stay fast. Verification uses each hash's own parameters, so
/// these work everywhere a real hash does.
#[cfg(test)]
pub(crate) fn test_hash(password: &str) -> String {
    let params = Params::new(8, 1, 1, None).expect("valid test parameters");
    hash_with(
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        password,
    )
    .expect("test hash")
}

/// A credentials file with one `user:hash` line per `(user, password)`
/// pair, hashed with [`test_hash`].
#[cfg(test)]
pub(crate) fn test_credentials(users: &[(&str, &str)]) -> String {
    users
        .iter()
        .map(|(user, pass)| format!("{user}:{}\n", test_hash(pass)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Logins alice, bob and carol (password `pw`) with the grants spec
    /// `senders`.
    fn cfg(senders: &str) -> AuthConfig {
        let creds = test_credentials(&[("alice", "pw"), ("bob", "pw"), ("carol", "pw")]);
        AuthConfig::from_credentials(&creds, Some(senders)).unwrap()
    }

    #[test]
    fn grants_cover_addresses_and_domains() {
        let c = cfg("alice=alice@example.org|@Example.NET.,bob=bob@example.org");
        let g = &c;
        assert!(g.permits("alice", "alice", "example.org"));
        assert!(g.permits("alice", "ALICE", "EXAMPLE.org."));
        assert!(g.permits("alice", "anyone", "example.net"));
        assert!(!g.permits("alice", "bob", "example.org"), "not alice's");
        assert!(
            !g.permits("alice", "x", "sub.example.net"),
            "no subdomain grant"
        );
        assert!(!g.permits("alice", "x", "evil-example.net"));
        assert!(g.permits("bob", "bob", "example.org"));
        assert!(!g.permits("bob", "alice", "example.org"));
        // No grants: fail closed.
        assert!(!g.permits("carol", "carol", "example.org"));
        assert!(!g.permits("mallory", "alice", "example.org"));
        assert!(!g.permits("alice", "", "example.net"), "empty local-part");
        assert_eq!(c.users_without_grants(), vec!["carol"]);
    }

    #[test]
    fn no_senders_spec_means_no_one_may_send() {
        let c = AuthConfig::from_credentials(&test_credentials(&[("alice", "pw")]), None).unwrap();
        assert!(!c.permits("alice", "alice", "example.org"));
        assert_eq!(c.users_without_grants(), vec!["alice"]);
    }

    #[test]
    fn bad_specs_are_startup_errors() {
        let creds = test_credentials(&[("alice", "pw")]);
        for bad in [
            "alice",
            "=alice@example.org",
            "alice=",
            "alice=example.org",
            "alice=alice@",
            "alice=a@bad domain",
            "alice=a@ex..ample",
            "alice=a@example.org,alice=@example.net",
        ] {
            assert!(
                AuthConfig::from_credentials(&creds, Some(bad)).is_err(),
                "{bad:?} should be refused"
            );
        }
        // A grant for a login that can't authenticate is a typo.
        assert!(AuthConfig::from_credentials(&creds, Some("alcie=@example.org")).is_err());
    }

    /// The credentials format: comments, blank lines, CRLF and spaces
    /// around the hash are tolerated; anything that isn't an argon2id hash
    /// (above all a plaintext password) is refused with the line number,
    /// never echoing the value.
    #[test]
    fn credentials_file_format() {
        let (a, b) = (test_hash("s3cr:et "), test_hash("pw"));
        let c = AuthConfig::from_credentials(
            &format!("# logins\r\n\r\n  alice : {a} \r\n\t# indented comment\nbob:{b}\n"),
            None,
        )
        .unwrap();
        assert_eq!(c.user_count(), 2);
        assert!(c.verify("alice", "s3cr:et "), "password kept verbatim");
        assert!(!c.verify("alice", "s3cr:et"));
        assert!(c.verify("bob", "pw"));

        let argon2i = {
            let params = Params::new(8, 1, 1, None).unwrap();
            hash_with(Argon2::new(Algorithm::Argon2i, Version::V0x13, params), "x").unwrap()
        };
        for (bad, why) in [
            (
                "alice".to_string(),
                "line 1: expected user:hash".to_string(),
            ),
            (format!(":{a}"), "line 1: empty user name".into()),
            (
                "alice:hunter2-plaintext".into(),
                "not an argon2id hash (not a PHC".into(),
            ),
            ("alice:".into(), "not an argon2id hash".into()),
            (
                format!("alice:{argon2i}"),
                "algorithm is argon2i, not argon2id".into(),
            ),
            (
                format!("alice:{a}\nalice:{b}"),
                "line 2: \"alice\" is listed more than once".into(),
            ),
            ("# only comments\n\n".into(), "no users defined".into()),
        ] {
            let err = AuthConfig::from_credentials(&bad, None)
                .unwrap_err()
                .to_string();
            assert!(err.contains(&why), "{bad:?}: {err}");
            assert!(!err.contains("hunter2"), "never echoes the value: {err}");
        }
    }

    /// `verify` accepts only the right password for a known login; an
    /// unknown login fails with any password, including one that is valid
    /// for another login.
    #[test]
    fn verify_checks_user_and_password() {
        let creds = test_credentials(&[("alice", "secret"), ("bob", "hunter2")]);
        let c = AuthConfig::from_credentials(&creds, None).unwrap();
        assert!(c.verify("alice", "secret"));
        assert!(!c.verify("alice", "hunter2"), "another user's password");
        assert!(!c.verify("alice", "secre"), "prefix");
        assert!(!c.verify("alice", "secret!"), "longer");
        assert!(!c.verify("alice", ""));
        assert!(!c.verify("mallory", "secret"));
        assert!(!c.verify("mallory", ""));
        assert!(!c.verify("ALICE", "secret"), "logins are case-sensitive");
    }

    /// `hash-password`'s output is a default-strength argon2id hash that
    /// loads and verifies, with a fresh salt each time; cheap test hashes
    /// are flagged as weak, default ones aren't.
    #[test]
    fn default_hashes_round_trip_and_weak_ones_are_flagged() {
        let strong = hash_password("correct horse").unwrap();
        assert!(
            strong.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{strong}"
        );
        assert_ne!(strong, hash_password("correct horse").unwrap(), "salted");
        let c = AuthConfig::from_credentials(
            &format!("strong:{strong}\nweak:{}\n", test_hash("pw")),
            None,
        )
        .unwrap();
        assert!(c.verify("strong", "correct horse"));
        assert_eq!(c.weak_hash_users(), vec!["weak"]);
    }

    /// `check` accepts the right password, counts failures per IP, and
    /// refuses a blocked IP without checking (even the right password);
    /// other IPs are unaffected.
    #[tokio::test]
    async fn check_limits_failures_per_ip() {
        let creds = test_credentials(&[("alice", "secret")]);
        let c = Arc::new(AuthConfig::from_credentials(&creds, None).unwrap());
        let (ip, other): (IpAddr, IpAddr) =
            ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());

        assert_eq!(c.check(ip, "alice", "secret").await, AuthCheck::Accepted);
        for _ in 0..AUTH_FAILURES_PER_IP {
            assert_eq!(c.check(ip, "alice", "wrong").await, AuthCheck::Rejected);
        }
        assert_eq!(c.check(ip, "alice", "secret").await, AuthCheck::Blocked);
        assert_eq!(c.check(other, "alice", "secret").await, AuthCheck::Accepted);
    }

    /// The file must not be readable by other users; group access is
    /// allowed. Missing files are errors.
    #[cfg(unix)]
    #[test]
    fn credentials_file_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users");
        std::fs::write(&path, test_credentials(&[("alice", "pw")])).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AuthConfig::load(&path, None).unwrap().verify("alice", "pw"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            AuthConfig::load(&path, None).is_ok(),
            "group-readable is allowed"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = AuthConfig::load(&path, None).unwrap_err().to_string();
        assert!(err.contains("accessible to other users"), "{err}");

        let missing = dir.path().join("missing");
        let err = format!("{:#}", AuthConfig::load(&missing, None).unwrap_err());
        assert!(err.contains("cannot read credentials file"), "{err}");
    }

    /// `reload` swaps in the edited file: a removed login can no longer
    /// authenticate or send (its grant goes inert and is reported), an
    /// added one can, a changed password applies, and failure counts
    /// carry over. A broken file is refused with the old logins kept, and
    /// a configuration built from a string can't be reloaded.
    #[cfg(unix)]
    #[tokio::test]
    async fn reload_replaces_logins_atomically() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users");
        let write = |text: String| {
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write(test_credentials(&[("alice", "pw"), ("bob", "pw")]));
        let c =
            Arc::new(AuthConfig::load(&path, Some("alice=@example.org,bob=@example.org")).unwrap());
        assert!(c.permits("bob", "b", "example.org"));

        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        for _ in 0..AUTH_FAILURES_PER_IP {
            c.check(ip, "alice", "wrong").await;
        }

        // bob is revoked, carol arrives, alice changes her password.
        write(test_credentials(&[("alice", "new"), ("carol", "pw")]));
        assert_eq!(
            c.reload().unwrap(),
            ReloadSummary {
                users: 2,
                removed: vec!["bob".into()],
                added: vec!["carol".into()],
                orphaned_grants: vec!["bob".into()],
            }
        );
        assert!(!c.verify("bob", "pw"));
        assert!(
            !c.permits("bob", "b", "example.org"),
            "a revoked login can't send, even if its session authenticated earlier"
        );
        assert!(c.verify("carol", "pw"));
        assert!(c.verify("alice", "new") && !c.verify("alice", "pw"));
        assert!(c.permits("alice", "a", "example.org"));
        assert_eq!(
            c.check(ip, "carol", "pw").await,
            AuthCheck::Blocked,
            "failure counts survive a reload"
        );

        // A broken file is refused; the current logins stay.
        write("alice:hunter2\n".to_string());
        let err = format!("{:#}", c.reload().unwrap_err());
        assert!(err.contains("not an argon2id hash"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
        assert!(c.verify("alice", "new"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(c.reload().is_err(), "world-readable is still refused");
        assert_eq!(c.user_count(), 2);

        let fixed = AuthConfig::from_credentials(&test_credentials(&[("a", "pw")]), None).unwrap();
        assert!(fixed.reload().is_err());
    }

    #[test]
    fn split_address_rejects_null_and_empty_parts() {
        assert_eq!(split_address("a@b.example"), Some(("a", "b.example")));
        assert_eq!(
            split_address("\"a@b\"@c.example"),
            Some(("\"a@b\"", "c.example"))
        );
        assert_eq!(split_address(""), None);
        assert_eq!(split_address("@b.example"), None);
        assert_eq!(split_address("a@"), None);
        assert_eq!(split_address("nodomain"), None);
    }
}
