//! Recipient authority: the seam between the SMTP server and the external
//! system that knows which domains are hosted, which addresses belong to
//! which users, and how each domain treats recipients it does not know.
//!
//! The SMTP server is deliberately thin here: it asks one question per
//! RCPT command ("may this address receive mail right now, and where
//! does the mail route?") and enforces the answer. All product policy —
//! who owns which domain, who owns which address, whether addresses
//! expire — lives behind the [`RecipientResolver`] trait.
//!
//! **Contract semantics:**
//!
//! - **Fail-closed**: an authority that cannot be consulted (unreachable,
//!   timed out, unusable answer) means mail is refused with `451` —
//!   never accepted-and-later-failed. Accepting mail the platform can't
//!   route would mean bouncing it later (backscatter).
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
//!   and mailbox public key, so payload encryption (not implemented yet)
//!   can have its recipient key set at write time without a second lookup.
//!
//! # The file-backed authority (the console's first API contract)
//!
//! [`FileAuthority`] loads a JSON document and hot-reloads it when the
//! file's mtime or size changes; the console (or any operator) publishes
//! policy by rewriting this file. A rewrite that fails to load is logged
//! and the last good policy keeps serving. The schema is deliberately small and strict
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
//!   opaque string (its encoding isn't fixed yet); `key-generation`
//!   supports rotation. Both are carried, not used.
//! - Under `catch-all`, an *unknown* address routes to the designated
//!   mailbox; a *known but expired* address is refused (`Expired`) — an
//!   admin who expired an address gets the refusal signal, not silent
//!   catch-all routing.
//! - Under `grace`, an expired address keeps accepting for `grace-days`
//!   past its expiry, then refuses. Permanent addresses never age out.
//!
//! If no authority is configured, [`StaticAuthority`] serves
//! `--local-domains`: every local-part at a hosted domain is accepted and
//! routes to itself. Footgun: that accepts any address, so never use it on
//! an internet-facing server.

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
    /// Public key registered for this mailbox. Carried, not used yet.
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
    /// Returns the backend name for logs (e.g. `"file"`, `"static"`).
    fn name(&self) -> &str;

    /// Resolve one candidate recipient `address`, a full address
    /// (`local@domain`), matched case-insensitively.
    ///
    /// Returns the authority's [`Resolution`]; "cannot receive mail" is a
    /// [`Resolution::Refuse`], never an error.
    ///
    /// # Errors
    ///
    /// [`AuthorityUnavailable`] when the authority itself cannot be
    /// consulted, or for a malformed address (no `@`), though the session
    /// pre-checks syntax before calling.
    fn resolve(&self, address: &str) -> Result<Resolution, AuthorityUnavailable>;
}

/// Internal record for one mailbox.
#[derive(Debug, Clone)]
struct Mailbox {
    /// Owning account.
    user: String,
    /// When the address stops accepting; `None` for a permanent address.
    expires: Option<Timestamp>,
    /// Registered public key, carried through to the recipient.
    public_key: Option<String>,
    /// Key-rotation generation for `public_key`.
    key_generation: Option<u32>,
}

/// Internal policy for one hosted domain (the validated [`PolicyMode`]).
#[derive(Debug, Clone)]
enum DomainPolicy {
    /// Only known, unexpired addresses are accepted.
    Reject,
    /// Unknown addresses route to `mailbox` (lowercased).
    CatchAll { mailbox: String },
    /// Expired addresses keep accepting for `days` (1–366) past expiry.
    Grace { days: i64 },
}

/// The parsed authority document. All keys are lowercased.
#[derive(Debug, Clone)]
struct AuthorityData {
    /// Hosted domain -> its policy.
    domains: HashMap<String, DomainPolicy>,
    /// Per-domain message size limits (`max-message-bytes`), for domains
    /// that set one.
    domain_limits: HashMap<String, usize>,
    /// Full address -> mailbox record.
    mailboxes: HashMap<String, Mailbox>,
}

impl AuthorityData {
    /// Resolve `address`: the domain's policy decides acceptance and
    /// routing (see [`AuthorityData::resolve_policy`]), and an accepted
    /// recipient carries the domain's size limit.
    ///
    /// # Errors
    ///
    /// [`AuthorityUnavailable`] for an address without `@`.
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

    /// Apply the hosted domain's policy to `address` (trimmed and
    /// lowercased) at the current time, without the size limit.
    ///
    /// Returns [`Resolution::NotHosted`] for an unknown domain, otherwise
    /// the accept/refuse decision of the domain's [`PolicyMode`].
    ///
    /// # Errors
    ///
    /// [`AuthorityUnavailable`] for an address without `@`.
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
                // A permanent mailbox (`expires: null`) always accepts. Only
                // addresses WITH an expiry can age out, and only past
                // expiry + grace. Footgun: `is_some_and` here would treat
                // `null` as expired and refuse every permanent mailbox.
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

    /// Check whether mailbox `entry` is live at `now`.
    ///
    /// Returns `Ok` when the entry exists and has not expired, otherwise
    /// `Err` with the refusal reason ([`RefusalReason::NoSuchMailbox`] for
    /// `None`, [`RefusalReason::Expired`] at or past its expiry).
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

    /// Build the routing recipient for the known mailbox `entry` at
    /// address `addr`. The routing mailbox is `addr` itself; the size
    /// limit is left for [`AuthorityData::resolve`] to fill in.
    ///
    /// # Panics
    ///
    /// If `entry` is `None`; callers pass an entry they have already
    /// checked.
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
    /// Schema version; only `1` is supported.
    version: u32,
    /// Hosted domain -> its policy.
    domains: HashMap<String, DomainFile>,
    /// Full address -> mailbox record.
    mailboxes: HashMap<String, MailboxFile>,
}

/// One entry of the document's `domains` map.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct DomainFile {
    /// How the domain treats unknown recipients.
    mode: PolicyMode,
    /// The designated inbox; required for `catch-all`.
    catch_all_mailbox: Option<String>,
    /// The grace window in days (1–366); required for `grace`.
    grace_days: Option<u64>,
    /// The domain's own message size limit in bytes (optional). Only a
    /// *lower* limit than the server's `max-data-bytes` has an effect.
    max_message_bytes: Option<u64>,
}

/// The smallest accepted `max-message-bytes`: 1 KiB. Anything smaller
/// can't hold real headers, so it is almost certainly a unit mistake
/// (e.g. `10` meaning 10 MB) that would silently refuse all mail.
const MIN_DOMAIN_MESSAGE_BYTES: u64 = 1024;

/// One entry of the document's `mailboxes` map.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct MailboxFile {
    /// Owning account.
    user: String,
    /// RFC 3339 timestamp, or null/absent for a permanent address.
    expires: Option<String>,
    /// Opaque public key string.
    public_key: Option<String>,
    /// Key-rotation generation for `public_key`.
    key_generation: Option<u32>,
}

impl AuthorityFile {
    /// Validate the document and convert it to lookup form, lowercasing
    /// every domain, address and catch-all mailbox.
    ///
    /// # Errors
    ///
    /// An unsupported `version`; a `max-message-bytes` below
    /// [`MIN_DOMAIN_MESSAGE_BYTES`]; a `catch-all` domain without
    /// `catch-all-mailbox`; a `grace` domain without `grace-days` or with
    /// a value outside 1–366; or an unparseable `expires` timestamp.
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
                    // Cap the window, so the expiry arithmetic stays bounded.
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
/// format. The file must load at startup, and is hot-reloaded whenever
/// its mtime or size changes. A reload that fails at runtime (unreadable
/// or invalid file) is logged at `error` and the last good policy keeps
/// serving until the next change loads.
#[derive(Debug)]
pub struct FileAuthority {
    /// The authority document.
    path: PathBuf,
    /// The snapshot currently served.
    state: RwLock<Arc<Loaded>>,
}

/// The loaded snapshot plus the change token it was loaded from: mtime
/// and file size, because mtime alone misses a second publish within one
/// mtime tick.
#[derive(Debug)]
struct Loaded {
    /// The file's change token when last loaded (or last attempted).
    stamp: Option<(SystemTime, u64)>,
    /// The policy being served.
    data: AuthorityData,
}

/// Returns the (mtime, size) change token of the file at `path`, or
/// `None` when it cannot be stat'ed.
fn file_stamp(path: &Path) -> Option<(SystemTime, u64)> {
    std::fs::metadata(path).ok().and_then(|m| {
        let mtime = m.modified().ok()?;
        Some((mtime, m.len()))
    })
}

impl FileAuthority {
    /// Load (and validate) the authority file at `path`.
    ///
    /// Returns the ready-to-use authority.
    ///
    /// # Errors
    ///
    /// The file cannot be read, parsed or validated (see
    /// [`FileAuthority::load`]) — the server should refuse to start
    /// rather than guess at recipient policy.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let stamp = file_stamp(&path);
        let data = Self::load(&path)?;
        Ok(FileAuthority {
            path,
            state: RwLock::new(Arc::new(Loaded { stamp, data })),
        })
    }

    /// Read and validate the file at `path`. Used at startup and on every
    /// change-token change.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is not a valid document (malformed JSON,
    /// unknown or missing fields), or fails validation.
    fn load(path: &Path) -> Result<AuthorityData> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read authority file {}", path.display()))?;
        let file: AuthorityFile = serde_json::from_str(&raw)
            .with_context(|| format!("invalid authority file {}", path.display()))?;
        file.into_data()
    }

    /// Returns the current snapshot, reloading first if the file's change
    /// token differs from the snapshot's.
    ///
    /// A failed reload (a non-atomic publish, a typo'd policy) keeps
    /// serving the **last good snapshot**, so a broken publish never turns
    /// every RCPT into a `451`. The last attempted change token is
    /// memoized, so a persistently bad file is read once per change, not
    /// once per lookup. This never returns `Err` today; the signature
    /// matches [`RecipientResolver::resolve`].
    ///
    /// # Panics
    ///
    /// If the snapshot lock is poisoned.
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
                // Serve the last good snapshot under this change token, so
                // the broken file is not re-parsed (or re-logged) per
                // lookup; the next change gets a fresh attempt. Logged
                // loudly: recipient policy is now stale (e.g. an expiry or
                // a domain removal in the rejected publish is NOT in
                // effect) and operators must know.
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

/// The fallback authority: every local-part at a hosted domain is
/// accepted and routes to itself, with no user or key. Used when no
/// `--authority` file is configured (development and tests); production
/// runs with a real authority (see the module docs for why).
#[derive(Debug, Clone)]
pub struct StaticAuthority {
    /// Hosted domains, lowercased.
    domains: std::collections::HashSet<String>,
}

impl StaticAuthority {
    /// Host `domains` (lowercased). Every local-part at them accepts;
    /// everything else is [`Resolution::NotHosted`].
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

    /// The timestamp `seconds_from_epoch`; its `Display` is the RFC 3339
    /// form the fixtures need.
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

    /// Catch-all routes unknown addresses to the designated inbox (adopting
    /// its owner and key when it is a known mailbox; otherwise its address
    /// doubles as the user), routes known live addresses to themselves,
    /// and refuses known-but-expired addresses: an admin who expired an
    /// address gets the refusal signal, not silent catch-all routing.
    #[test]
    fn catch_all_routes_unknown_and_refuses_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(&path, DOC).unwrap();
        let authority = FileAuthority::open(&path).unwrap();

        // Unknown local-part → the designated inbox (admin@example.org is
        // not itself a mailbox here, so the user falls back to the
        // address).
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

        // A catch-all domain with known mailboxes: one live, one expired,
        // and the designated inbox itself.
        std::fs::write(
            &path,
            r#"{
                "version": 1,
                "domains": {
                    "catch.example.org": { "mode": "catch-all", "catch-all-mailbox": "inbox@catch.example.org" }
                },
                "mailboxes": {
                    "inbox@catch.example.org": { "user": "owner", "public-key": "pk-owner", "key-generation": 4 },
                    "live@catch.example.org": { "user": "carol", "expires": null },
                    "gone@catch.example.org": { "user": "dave", "expires": "2020-01-01T00:00:00Z" }
                }
            }"#,
        )
        .unwrap();
        let authority = FileAuthority::open(&path).unwrap();

        // Known-but-expired: refused, never silently caught.
        assert_eq!(
            authority.resolve("gone@catch.example.org").unwrap(),
            Resolution::Refuse {
                mode: PolicyMode::CatchAll,
                reason: RefusalReason::Expired,
            }
        );
        // Known and live: routes to itself, not to the inbox.
        assert_eq!(
            authority.resolve("live@catch.example.org").unwrap(),
            Resolution::Accept(Recipient {
                user: Some("carol".into()),
                mailbox: "live@catch.example.org".into(),
                public_key: None,
                key_generation: None,
                max_message_bytes: None,
            })
        );
        // Unknown: the inbox, adopting its owner and key.
        assert_eq!(
            authority.resolve("whoever@catch.example.org").unwrap(),
            Resolution::Accept(Recipient {
                user: Some("owner".into()),
                mailbox: "inbox@catch.example.org".into(),
                public_key: Some("pk-owner".into()),
                key_generation: Some(4),
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

        // Permanent mailboxes (`expires: null`) and not-yet-expired ones
        // always accept on a grace domain.
        assert!(matches!(
            authority.resolve("permanent@example.org").unwrap(),
            Resolution::Accept(_)
        ));
        assert!(matches!(
            authority.resolve("future@example.org").unwrap(),
            Resolution::Accept(_)
        ));
    }

    /// Editing the file changes answers without a restart (hot reload);
    /// a malformed rewrite keeps serving the last good policy until the
    /// next good publish.
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

        // A malformed rewrite (a non-atomic publish) must NOT turn every
        // RCPT into a `451`: the last good snapshot keeps serving.
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

    /// The static fallback: every local-part at a hosted domain accepts,
    /// case-insensitively; other domains are not hosted.
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
