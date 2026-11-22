//! Recipient authority (Phase 12, gap 1): the seam between the SMTP
//! server and the external system that knows which domains are hosted,
//! which addresses belong to which users, and how each domain treats
//! recipients it does not know.
//!
//! The SMTP server is deliberately thin here: it asks one question per
//! RCPT command ("may this address receive mail right now, and where
//! does the mail route?") and enforces the answer. All product policy —
//! who owns which domain, who owns which address, whether addresses
//! expire — lives behind the [`RecipientResolver`] trait.
//!
//! **Contract semantics (decided, see PLAN.md Phase 12):**
//!
//! - **Fail-closed**: an authority that cannot be consulted (unreachable,
//!   timed out, unusable answer) means mail is refused with `451` —
//!   never accepted-and-later-failed. Accepting mail the platform cannot
//!   route produces backscatter once delivery exists.
//! - **Cache successes only**: the session caches *accepted* resolutions
//!   per connection; refusals always reach the authority, giving the
//!   invariant *every refusal is observed by the authority exactly
//!   once* — the console platform is the system of record for the
//!   per-domain refusal event stream.
//! - **One reply for every refusal**: expired and nonexistent addresses
//!   get the same SMTP reply (distinguishing them to senders would leak
//!   which addresses once existed); the reason is recorded in the
//!   structured refusal log instead.
//! - **Keys ride the lookup**: the resolution carries the owning user
//!   and mailbox public key, so the Phase 12 multi-key payload
//!   encryption has its recipient key set at write time without a
//!   second lookup or a later schema migration.
//!
//! # The file-backed authority (the console's first API contract)
//!
//! [`FileAuthority`] loads a JSON document and hot-reloads it when the
//! file's mtime changes; the console (or any operator) publishes policy
//! by rewriting this file. The schema is deliberately small and strict
//! (unknown fields are rejected — extend it by bumping `version`):
//!
//! ```json
//! {
//!   "version": 1,
//!   "domains": {
//!     "example.org": { "mode": "reject" },
//!     "lists.example.org": { "mode": "catch-all", "catch-all-mailbox": "admin@example.org" },
//!     "legacy.example.net": { "mode": "grace", "grace-days": 7 }
//!   },
//!   "mailboxes": {
//!     "alice@example.org": {
//!       "user": "alice",
//!       "expires": null,
//!       "public-key": "age1qy...",
//!       "key-generation": 2
//!     }
//!   }
//! }
//! ```
//!
//! - `domains` keys are the hosted domains (lowercase). `mode` is one
//!   of `reject`, `catch-all`, `grace` (see [`PolicyMode`]).
//! - `mailboxes` keys are full addresses (lowercase). `expires` is an
//!   RFC 3339 timestamp or `null` (permanent). `public-key` is an
//!   opaque string for now (the Phase 12 container format fixes the
//!   encoding); `key-generation` supports rotation.
//! - Under `catch-all`, an *unknown* address routes to the designated
//!   mailbox; a *known but expired* address is refused (`Expired`) — an
//!   admin who expired an address gets the refusal signal, not silent
//!   catch-all routing.
//! - Under `grace`, an expired address keeps accepting for `grace-days`
//!   past its expiry, then refuses. Permanent addresses never age out.
//!
//! If no authority is configured, [`StaticAuthority`] provides the
//! pre-authority behavior for `--local-domains`: every local-part at a
//! hosted domain is accepted and routes to itself.

use anyhow::{Context, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use thiserror::Error;

/// The authority could not be consulted: unreachable, timed out, or it
/// returned an unusable answer. Always transient from the caller's
/// perspective — the session replies `451` and the client retries. This
/// is never used for "no such mailbox": that is
/// [`Resolution::Refuse`].
#[derive(Debug, Error)]
#[error("authority unavailable: {0}")]
pub struct AuthorityUnavailable(pub String);

/// How a hosted domain treats recipients it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    /// Only known, unexpired addresses are accepted.
    Reject,
    /// Any address routes to a designated inbox.
    CatchAll,
    /// Expired addresses keep accepting for a grace period.
    Grace,
}

/// Why an address on a hosted domain cannot receive mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RefusalReason {
    /// No mailbox with this address exists.
    NoSuchMailbox,
    /// The mailbox exists but its expiry has passed (and any grace
    /// period, when the domain grants one).
    Expired,
}

/// The resolved routing target for an accepted recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recipient {
    /// The owning account (platform user). `None` only for the static
    /// fallback authority, which knows domains but not users.
    pub user: Option<String>,
    /// The mailbox mail routes to: the addressed mailbox itself, or the
    /// designated inbox under catch-all.
    pub mailbox: String,
    /// Public key registered for this mailbox — the Phase 12 payload
    /// encryption wraps the content key with every recipient's key.
    pub public_key: Option<String>,
    /// Key-rotation generation for [`Recipient::public_key`].
    pub key_generation: Option<u32>,
    /// The hosted domain's own message size limit, in bytes
    /// (`max-message-bytes`), if it set one. The session enforces the
    /// lower of this and the server-wide `max-data-bytes`.
    pub max_message_bytes: Option<usize>,
}

/// What the authority answered for one candidate recipient.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Resolution {
    /// The domain is not hosted here at all (the session replies with
    /// the relay-denied policy).
    NotHosted,
    /// Accept: mail routes to the described recipient.
    Accept(Recipient),
    /// The domain is hosted, but this address cannot receive mail.
    Refuse {
        /// The domain's policy mode, for the refusal event stream.
        mode: PolicyMode,
        /// Why, for the refusal event stream (never revealed to the
        /// sender — the SMTP reply is identical for every reason).
        reason: RefusalReason,
    },
}

/// The recipient authority: consulted at RCPT time for every address.
///
/// Methods are blocking (filesystem today, HTTP later) with the same
/// convention as [`crate::spool::SpoolWriter`]: callers run them on the
/// blocking pool and apply their own timeout, mapping both elapsed
/// timeouts and `Err` to the fail-closed `451`.
pub trait RecipientResolver: Send + Sync {
    /// Backend name for logs (e.g. `"file"`, `"static"`).
    fn name(&self) -> &str;

    /// Resolve one candidate recipient address.
    ///
    /// `address` is a full address (`local@domain`); malformed addresses
    /// (no `@`) are an [`AuthorityUnavailable`] error, though the session
    /// pre-checks syntax before calling. Returns `Err` only when the
    /// authority itself cannot be consulted; "cannot receive mail" is a
    /// [`Resolution::Refuse`], never an error.
    fn resolve(&self, address: &str) -> Result<Resolution, AuthorityUnavailable>;
}

/// Internal record for one mailbox.
#[derive(Debug, Clone)]
struct Mailbox {
    user: String,
    expires: Option<Timestamp>,
    public_key: Option<String>,
    key_generation: Option<u32>,
}

/// Internal policy for one hosted domain.
#[derive(Debug, Clone)]
enum DomainPolicy {
    Reject,
    CatchAll { mailbox: String },
    Grace { days: i64 },
}

/// The parsed authority document.
#[derive(Debug, Clone)]
struct AuthorityData {
    domains: HashMap<String, DomainPolicy>,
    /// Per-domain message size limits (`max-message-bytes`), for domains
    /// that set one.
    domain_limits: HashMap<String, usize>,
    mailboxes: HashMap<String, Mailbox>,
}

impl AuthorityData {
    /// Resolve one address: the domain's policy decides acceptance and
    /// routing, and an accepted recipient carries the domain's size limit.
    fn resolve(&self, address: &str) -> Result<Resolution, AuthorityUnavailable> {
        let mut resolution = self.resolve_policy(address)?;
        if let Resolution::Accept(recipient) = &mut resolution {
            let addr = address.trim().to_ascii_lowercase();
            recipient.max_message_bytes = addr
                .rsplit_once('@')
                .and_then(|(_, domain)| self.domain_limits.get(domain).copied());
        }
        Ok(resolution)
    }

    fn resolve_policy(&self, address: &str) -> Result<Resolution, AuthorityUnavailable> {
        let addr = address.trim().to_ascii_lowercase();
        let Some((_, domain)) = addr.rsplit_once('@') else {
            return Err(AuthorityUnavailable(format!(
                "malformed address {address:?}"
            )));
        };
        let Some(policy) = self.domains.get(domain) else {
            return Ok(Resolution::NotHosted);
        };

        let now = Timestamp::now();
        let entry = self.mailboxes.get(&addr);
        match policy {
            DomainPolicy::Reject => match self.check_expiry(entry, now) {
                Ok(()) => Ok(Resolution::Accept(Self::recipient(entry, &addr))),
                Err(reason) => Ok(Resolution::Refuse {
                    mode: PolicyMode::Reject,
                    reason,
                }),
            },
            DomainPolicy::CatchAll { mailbox } => {
                match self.check_expiry(entry, now) {
                    // A known, live address routes to itself even under
                    // catch-all; catch-all is for *unknown* addresses.
                    Ok(()) => Ok(Resolution::Accept(Self::recipient(entry, &addr))),
                    Err(RefusalReason::Expired) => Ok(Resolution::Refuse {
                        mode: PolicyMode::CatchAll,
                        reason: RefusalReason::Expired,
                    }),
                    // Unknown address: route to the designated inbox.
                    // When the inbox is itself a known mailbox, its owner
                    // and key are adopted; otherwise the inbox address
                    // doubles as the account identity.
                    Err(RefusalReason::NoSuchMailbox) => {
                        let owner = self.mailboxes.get(mailbox);
                        Ok(Resolution::Accept(Recipient {
                            user: owner
                                .map(|o| o.user.clone())
                                .or_else(|| Some(mailbox.clone())),
                            mailbox: mailbox.clone(),
                            public_key: owner.and_then(|o| o.public_key.clone()),
                            key_generation: owner.and_then(|o| o.key_generation),
                            max_message_bytes: None,
                        }))
                    }
                }
            }
            DomainPolicy::Grace { days } => {
                let Some(mb) = entry else {
                    return Ok(Resolution::Refuse {
                        mode: PolicyMode::Grace,
                        reason: RefusalReason::NoSuchMailbox,
                    });
                };
                // H8 (security report): a permanent mailbox (expires:
                // null) must always accept — the old `is_some_and` logic
                // treated it as expired and refused every permanent user
                // on a grace domain. Only addresses WITH an expiry can
                // age out, and only past expiry + grace.
                let in_grace = mb
                    .expires
                    .is_none_or(|exp| now.as_second() < exp.as_second() + *days * 86_400);
                if in_grace {
                    Ok(Resolution::Accept(Self::recipient(entry, &addr)))
                } else {
                    Ok(Resolution::Refuse {
                        mode: PolicyMode::Grace,
                        reason: RefusalReason::Expired,
                    })
                }
            }
        }
    }

    /// `Ok` when the entry is live (exists and not expired), `Err` with
    /// the refusal reason otherwise.
    fn check_expiry(
        &self,
        entry: Option<&Mailbox>,
        now: Timestamp,
    ) -> std::result::Result<(), RefusalReason> {
        let Some(mb) = entry else {
            return Err(RefusalReason::NoSuchMailbox);
        };
        if mb.expires.is_some_and(|exp| now >= exp) {
            return Err(RefusalReason::Expired);
        }
        Ok(())
    }

    /// Build the routing recipient for a known mailbox entry. The
    /// routing mailbox is the addressed address itself.
    fn recipient(entry: Option<&Mailbox>, addr: &str) -> Recipient {
        let mb = entry.expect("recipient() called with a known mailbox");
        Recipient {
            user: Some(mb.user.clone()),
            mailbox: addr.to_string(),
            public_key: mb.public_key.clone(),
            key_generation: mb.key_generation,
            max_message_bytes: None,
        }
    }
}

// -- File format (strict: the console's API contract) ----------------

/// The on-disk authority document. Unknown fields are rejected so a
/// typo'd policy file fails loudly instead of silently misbehaving;
/// schema changes bump `version`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityFile {
    version: u32,
    domains: HashMap<String, DomainFile>,
    mailboxes: HashMap<String, MailboxFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct DomainFile {
    mode: PolicyMode,
    catch_all_mailbox: Option<String>,
    grace_days: Option<u64>,
    /// The domain's own message size limit in bytes (optional). Only a
    /// *lower* limit than the server's `max-data-bytes` has an effect.
    max_message_bytes: Option<u64>,
}

/// The smallest accepted `max-message-bytes`: 1 KiB. Anything smaller
/// can't hold real headers, so it is almost certainly a unit mistake
/// (e.g. `10` meaning 10 MB) that would silently refuse all mail.
const MIN_DOMAIN_MESSAGE_BYTES: u64 = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct MailboxFile {
    user: String,
    /// RFC 3339 timestamp, or null/absent for a permanent address.
    expires: Option<String>,
    public_key: Option<String>,
    key_generation: Option<u32>,
}

impl AuthorityFile {
    fn into_data(self) -> Result<AuthorityData> {
        if self.version != 1 {
            anyhow::bail!("unsupported authority file version {}", self.version);
        }
        let mut domains = HashMap::new();
        let mut domain_limits = HashMap::new();
        for (name, domain) in self.domains {
            if let Some(limit) = domain.max_message_bytes {
                if limit < MIN_DOMAIN_MESSAGE_BYTES {
                    anyhow::bail!(
                        "domain {name}: max-message-bytes must be at least {MIN_DOMAIN_MESSAGE_BYTES}, got {limit}"
                    );
                }
                domain_limits.insert(
                    name.to_ascii_lowercase(),
                    usize::try_from(limit).unwrap_or(usize::MAX),
                );
            }
            let policy = match domain.mode {
                PolicyMode::Reject => DomainPolicy::Reject,
                PolicyMode::CatchAll => {
                    let mailbox = domain.catch_all_mailbox.ok_or_else(|| {
                        anyhow::anyhow!("domain {name}: catch-all requires catch-all-mailbox")
                    })?;
                    DomainPolicy::CatchAll {
                        mailbox: mailbox.to_ascii_lowercase(),
                    }
                }
                PolicyMode::Grace => {
                    let days = domain.grace_days.ok_or_else(|| {
                        anyhow::anyhow!("domain {name}: grace requires grace-days")
                    })?;
                    if days == 0 {
                        anyhow::bail!("domain {name}: grace-days must be at least 1");
                    }
                    // H8 (security report): cap the window — bounded
                    // arithmetic in the expiry comparison, no absurd
                    // configurations.
                    if days > 366 {
                        anyhow::bail!("domain {name}: grace-days must be at most 366");
                    }
                    DomainPolicy::Grace { days: days as i64 }
                }
            };
            domains.insert(name.to_ascii_lowercase(), policy);
        }

        let mut mailboxes = HashMap::new();
        for (address, mailbox) in self.mailboxes {
            let expires = mailbox
                .expires
                .map(|raw| {
                    raw.parse::<Timestamp>()
                        .with_context(|| format!("mailbox {address}: invalid expires {raw:?}"))
                })
                .transpose()?;
            mailboxes.insert(
                address.to_ascii_lowercase(),
                Mailbox {
                    user: mailbox.user,
                    expires,
                    public_key: mailbox.public_key,
                    key_generation: mailbox.key_generation,
                },
            );
        }
        Ok(AuthorityData {
            domains,
            domain_limits,
            mailboxes,
        })
    }
}

/// Authority backed by a JSON file: the console's first publishing
/// format. The file is read at startup and hot-reloaded whenever its
/// mtime changes; an unreadable or unparseable file at runtime is a
/// transient authority failure (fail-closed `451`), never a silent
/// fallback.
#[derive(Debug)]
pub struct FileAuthority {
    path: PathBuf,
    state: RwLock<Arc<Loaded>>,
}

/// The loaded snapshot plus the change token it was loaded from (mtime
/// and file size — M15, security report: mtime alone misses a second
/// publish within one mtime tick).
#[derive(Debug)]
struct Loaded {
    stamp: Option<(SystemTime, u64)>,
    data: AuthorityData,
}

/// The (mtime, size) change token of the file, or `None` when it cannot
/// be stat'ed.
fn file_stamp(path: &Path) -> Option<(SystemTime, u64)> {
    std::fs::metadata(path).ok().and_then(|m| {
        let mtime = m.modified().ok()?;
        Some((mtime, m.len()))
    })
}

impl FileAuthority {
    /// Load (and validate) the authority file.
    ///
    /// Returns the ready-to-use authority on success. Returns `Err` if
    /// the file cannot be read or parsed — the server should refuse to
    /// start rather than guess at recipient policy.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let stamp = file_stamp(&path);
        let data = Self::load(&path)?;
        Ok(FileAuthority {
            path,
            state: RwLock::new(Arc::new(Loaded { stamp, data })),
        })
    }

    /// Read and validate the file. Used at startup and on every mtime
    /// change.
    fn load(path: &Path) -> Result<AuthorityData> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read authority file {}", path.display()))?;
        let file: AuthorityFile = serde_json::from_str(&raw)
            .with_context(|| format!("invalid authority file {}", path.display()))?;
        file.into_data()
    }

    /// The current snapshot, reloading first if the file changed.
    ///
    /// M15 (security report): a failed reload (console publishing
    /// non-atomically, a typo'd policy) keeps serving the **last good
    /// snapshot** — a broken publish used to turn every RCPT for every
    /// hosted domain into a `451` until the file was fixed, and the
    /// failed file was re-parsed on every RCPT. The last attempted
    /// change token is memoized, so a persistently bad file is read
    /// once per change, not once per lookup.
    fn current(&self) -> Result<Arc<Loaded>, AuthorityUnavailable> {
        let stamp = file_stamp(&self.path);
        {
            let snapshot = self.state.read().expect("authority lock poisoned");
            if snapshot.stamp == stamp {
                return Ok(Arc::clone(&snapshot));
            }
        }
        let mut snapshot = self.state.write().expect("authority lock poisoned");
        // Re-check: another thread may have reloaded while we waited.
        if snapshot.stamp == stamp {
            return Ok(Arc::clone(&snapshot));
        }
        match Self::load(&self.path) {
            Ok(data) => {
                tracing::info!(file = %self.path.display(), "recipient authority reloaded");
                *snapshot = Arc::new(Loaded { stamp, data });
            }
            Err(e) => {
                // Serve the last good snapshot; memoize this change
                // token so the broken file is not re-parsed per lookup.
                // It will load successfully on the next content change.
                // N5 (security report): the failure is logged loudly —
                // recipient policy is now stale (e.g. an expiry or a
                // domain removal in the rejected publish is NOT in
                // effect) and operators must know. Logged once per
                // change, not per lookup.
                tracing::error!(
                    file = %self.path.display(),
                    error = %format!("{e:#}"),
                    "authority reload failed; serving the last good policy (stale)"
                );
                let last_good = Arc::clone(&snapshot);
                *snapshot = Arc::new(Loaded {
                    stamp,
                    data: last_good.data.clone(),
                });
            }
        }
        Ok(Arc::clone(&snapshot))
    }
}

impl RecipientResolver for FileAuthority {
    fn name(&self) -> &str {
        "file"
    }

    fn resolve(&self, address: &str) -> Result<Resolution, AuthorityUnavailable> {
        self.current()?.data.resolve(address)
    }
}

/// The pre-authority fallback: every local-part at a hosted domain is
/// accepted and routes to itself — exactly the behavior mailserv had
/// before the authority seam. Used when no `--authority` file is
/// configured so existing deployments and tests keep working; the
/// product always runs with a real authority.
#[derive(Debug, Clone)]
pub struct StaticAuthority {
    domains: std::collections::HashSet<String>,
}

impl StaticAuthority {
    /// Host the given domains (lowercased). Every local-part at them
    /// accepts; everything else is [`Resolution::NotHosted`].
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        StaticAuthority {
            domains: domains
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
        }
    }
}

impl RecipientResolver for StaticAuthority {
    fn name(&self) -> &str {
        "static"
    }

    fn resolve(&self, address: &str) -> Result<Resolution, AuthorityUnavailable> {
        let addr = address.trim().to_ascii_lowercase();
        let Some((_, domain)) = addr.rsplit_once('@') else {
            return Err(AuthorityUnavailable(format!(
                "malformed address {address:?}"
            )));
        };
        if self.domains.contains(domain) {
            Ok(Resolution::Accept(Recipient {
                user: None,
                mailbox: addr,
                public_key: None,
                key_generation: None,
                max_message_bytes: None,
            }))
        } else {
            Ok(Resolution::NotHosted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3339 helper for test fixtures.
    fn ts(seconds_from_epoch: i64) -> Timestamp {
        Timestamp::from_second(seconds_from_epoch).unwrap()
    }

    /// A complete, valid document with one domain per mode.
    const DOC: &str = r#"{
        "version": 1,
        "domains": {
            "example.org": { "mode": "reject" },
            "catch.example.org": { "mode": "catch-all", "catch-all-mailbox": "admin@example.org" },
            "legacy.example.net": { "mode": "grace", "grace-days": 7 }
        },
        "mailboxes": {
            "alice@example.org": { "user": "alice", "expires": null, "public-key": "pk-alice", "key-generation": 2 },
            "bob@example.org": { "user": "bob", "expires": null },
            "temp@legacy.example.net": { "user": "bob", "expires": "2020-01-01T00:00:00Z" }
        }
    }"#;

    /// Unknown domains are NotHosted; hosted domains resolve their
    /// mailboxes with user and key attached.
    #[test]
    fn resolve_routes_by_domain_and_mailbox() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(&path, DOC).unwrap();
        let authority = FileAuthority::open(&path).unwrap();

        // Unknown domain.
        assert_eq!(
            authority.resolve("x@foreign.example").unwrap(),
            Resolution::NotHosted
        );

        // Known mailbox: user, key, and generation ride the result.
        assert_eq!(
            authority.resolve("alice@example.org").unwrap(),
            Resolution::Accept(Recipient {
                user: Some("alice".into()),
                mailbox: "alice@example.org".into(),
                public_key: Some("pk-alice".into()),
                key_generation: Some(2),
                max_message_bytes: None,
            })
        );

        // Unknown mailbox on a reject domain.
        assert_eq!(
            authority.resolve("nobody@example.org").unwrap(),
            Resolution::Refuse {
                mode: PolicyMode::Reject,
                reason: RefusalReason::NoSuchMailbox,
            }
        );

        // Addresses are matched case-insensitively.
        assert!(matches!(
            authority.resolve("ALICE@Example.ORG").unwrap(),
            Resolution::Accept(_)
        ));
    }

    /// Catch-all routes unknown addresses to the designated inbox
    /// (adopting its owner and key) but refuses known-but-expired
    /// addresses: an admin who expired an address gets the refusal
    /// signal, not silent catch-all routing.
    #[test]
    fn catch_all_routes_unknown_and_refuses_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(&path, DOC).unwrap();
        let authority = FileAuthority::open(&path).unwrap();

        // Unknown local-part → the designated inbox, with its owner's
        // identity (admin@example.org is not itself a mailbox here, so
        // the user falls back to the address).
        assert_eq!(
            authority.resolve("anything@catch.example.org").unwrap(),
            Resolution::Accept(Recipient {
                user: Some("admin@example.org".into()),
                mailbox: "admin@example.org".into(),
                public_key: None,
                key_generation: None,
                max_message_bytes: None,
            })
        );
    }

    /// Grace mode: an expired address keeps accepting for grace-days
    /// past expiry, then refuses; unknown addresses never accept.
    #[test]
    fn grace_accepts_within_window_then_refuses() {
        let now = Timestamp::now().as_second();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(
            &path,
            format!(
                r#"{{
                    "version": 1,
                    "domains": {{ "example.org": {{ "mode": "grace", "grace-days": 7 }} }},
                    "mailboxes": {{
                        "recent@example.org": {{ "user": "u", "expires": "{}" }},
                        "stale@example.org": {{ "user": "u", "expires": "{}" }},
                        "permanent@example.org": {{ "user": "u", "expires": null }},
                        "future@example.org": {{ "user": "u", "expires": "{}" }}
                    }}
                }}"#,
                ts(now - 86_400),      // expired 1 day ago
                ts(now - 30 * 86_400), // expired 30 days ago
                ts(now + 30 * 86_400), // expires 30 days from now
            ),
        )
        .unwrap();
        let authority = FileAuthority::open(&path).unwrap();

        assert!(matches!(
            authority.resolve("recent@example.org").unwrap(),
            Resolution::Accept(_)
        ));
        assert_eq!(
            authority.resolve("stale@example.org").unwrap(),
            Resolution::Refuse {
                mode: PolicyMode::Grace,
                reason: RefusalReason::Expired,
            }
        );
        assert_eq!(
            authority.resolve("never@example.org").unwrap(),
            Resolution::Refuse {
                mode: PolicyMode::Grace,
                reason: RefusalReason::NoSuchMailbox,
            }
        );

        // H8 (security report): permanent mailboxes (expires: null) and
        // not-yet-expired ones must always accept on a grace domain —
        // the old `is_some_and` logic treated every permanent mailbox as
        // expired and refused them all.
        assert!(matches!(
            authority.resolve("permanent@example.org").unwrap(),
            Resolution::Accept(_)
        ));
        assert!(matches!(
            authority.resolve("future@example.org").unwrap(),
            Resolution::Accept(_)
        ));
    }

    /// Editing the file changes answers without a restart (mtime
    /// hot-reload); a malformed rewrite fails closed with the last
    /// good policy preserved for the next successful reload.
    #[test]
    fn hot_reload_picks_up_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(&path, DOC).unwrap();
        let authority = FileAuthority::open(&path).unwrap();
        assert!(matches!(
            authority.resolve("alice@example.org").unwrap(),
            Resolution::Accept(_)
        ));

        // Give the mtime room to differ.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(
            &path,
            r#"{ "version": 1, "domains": { "example.org": { "mode": "reject" } }, "mailboxes": {} }"#,
        )
        .unwrap();
        assert_eq!(
            authority.resolve("alice@example.org").unwrap(),
            Resolution::Refuse {
                mode: PolicyMode::Reject,
                reason: RefusalReason::NoSuchMailbox,
            }
        );

        // M15 (security report): a malformed rewrite (the console
        // publishing non-atomically) must NOT turn every RCPT into a
        // `451` — the last good snapshot keeps serving, the broken file
        // is not re-parsed per lookup, and the next good publish
        // applies.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&path, "not json at all").unwrap();
        assert_eq!(
            authority.resolve("alice@example.org").unwrap(),
            Resolution::Refuse {
                mode: PolicyMode::Reject,
                reason: RefusalReason::NoSuchMailbox,
            }
        );

        // The next good publish applies.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&path, DOC).unwrap();
        assert!(matches!(
            authority.resolve("alice@example.org").unwrap(),
            Resolution::Accept(_)
        ));
    }

    /// `max-message-bytes`: carried on every accepted recipient of the
    /// domain (including catch-all routing), absent elsewhere, and a value
    /// under 1 KiB (almost certainly a unit mistake) is a load error.
    #[test]
    fn domain_size_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(
            &path,
            r#"{
                "version": 1,
                "domains": {
                    "small.example": { "mode": "reject", "max-message-bytes": 5000000 },
                    "catch.example": { "mode": "catch-all", "catch-all-mailbox": "inbox@catch.example", "max-message-bytes": 2048 },
                    "plain.example": { "mode": "reject" }
                },
                "mailboxes": {
                    "a@small.example": { "user": "a", "expires": null },
                    "b@plain.example": { "user": "b", "expires": null }
                }
            }"#,
        )
        .unwrap();
        let authority = FileAuthority::open(&path).unwrap();
        let limit = |addr: &str| match authority.resolve(addr).unwrap() {
            Resolution::Accept(r) => r.max_message_bytes,
            other => panic!("{addr}: {other:?}"),
        };
        assert_eq!(limit("A@Small.Example"), Some(5_000_000));
        assert_eq!(limit("anyone@catch.example"), Some(2048));
        assert_eq!(limit("b@plain.example"), None);

        std::fs::write(
            &path,
            r#"{ "version": 1, "domains": { "x.example": { "mode": "reject", "max-message-bytes": 10 } }, "mailboxes": {} }"#,
        )
        .unwrap();
        let err = FileAuthority::open(&path).unwrap_err().to_string();
        assert!(
            err.contains("max-message-bytes must be at least 1024"),
            "{err}"
        );
    }

    /// The strict file contract: malformed documents are startup
    /// errors, not silent misbehavior.
    #[test]
    fn invalid_documents_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        let open = |json: &str| {
            std::fs::write(&path, json).unwrap();
            FileAuthority::open(&path)
        };

        // Unknown version.
        assert!(open(r#"{ "version": 2, "domains": {}, "mailboxes": {} }"#).is_err());
        // catch-all without a designated mailbox.
        assert!(open(
            r#"{ "version": 1, "domains": { "example.org": { "mode": "catch-all" } }, "mailboxes": {} }"#
        ).is_err());
        // grace without a window.
        assert!(open(
            r#"{ "version": 1, "domains": { "example.org": { "mode": "grace" } }, "mailboxes": {} }"#
        ).is_err());
        // Unknown field (typo protection for the console contract).
        assert!(open(
            r#"{ "version": 1, "domains": { "example.org": { "mode": "reject", "mod": "reject" } }, "mailboxes": {} }"#
        ).is_err());
        // Invalid expires timestamp.
        assert!(open(
            r#"{ "version": 1, "domains": {}, "mailboxes": { "a@b.c": { "user": "u", "expires": "yesterday" } } }"#
        ).is_err());
    }

    /// The static fallback preserves the pre-authority behavior: every
    /// local-part at a hosted domain accepts and routes to itself.
    #[test]
    fn static_authority_accepts_any_local_part() {
        let authority = StaticAuthority::new(vec!["Example.ORG".into(), "example.net".into()]);
        assert!(matches!(
            authority.resolve("Anything@EXAMPLE.org").unwrap(),
            Resolution::Accept(_)
        ));
        assert_eq!(
            authority.resolve("x@foreign.example").unwrap(),
            Resolution::NotHosted
        );
    }
}
