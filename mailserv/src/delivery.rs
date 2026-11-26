//! Local delivery: the trace headers added at acceptance, the
//! `DeliverySink` seam and its maildir implementation, and the
//! drain/retry loop.
//!
//! - [`with_trace_headers`] — at end-of-data, before the spool write,
//!   the message gets `Return-Path:` (RFC 5321 §4.5.2) and a `Received:`
//!   trace header (RFC 5321 §4.4). They are the same for every recipient
//!   (no `for` clause), so the stored payload is the final message for
//!   all of them and can be sealed as a whole. Each copy's envelope
//!   address is delivery metadata, never part of the message.
//! - [`DeliverySink`] — where mail goes. `MaildirSink` writes one copy per
//!   envelope recipient into the routing mailbox's maildir
//!   (`{root}/{domain}/{local}/new`). Implementations MUST be idempotent
//!   per (envelope address, queue_id): the session attempts immediate delivery
//!   for low latency, and the drain loop re-attempts queued messages
//!   periodically — both paths may race, and a retry after partial
//!   failure must never duplicate mail.
//! - [`drain_once`] — the retry engine. Scans the committed spool,
//!   delivers each stored payload verbatim to each recipient, removes
//!   fully delivered messages, retries failures with exponential backoff,
//!   and dead-letters messages still undeliverable after
//!   `MAX_QUEUE_LIFETIME` (5 days).

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::spool::{SpoolMeta, SpoolQueue, SpoolRcpt};

/// Where accepted mail goes. Blocking methods (filesystem, and later
/// object storage); callers run them on a blocking thread pool.
pub trait DeliverySink: Send + Sync {
    /// Returns the backend name for logs (e.g. `"maildir"`).
    fn name(&self) -> &str;

    /// Deliver one copy of `message` (the stored payload, delivered
    /// verbatim) for the envelope recipient `rcpt` of the queued message
    /// `queue_id`: into `rcpt.mailbox`, recording `rcpt.address` as the
    /// copy's delivery metadata.
    ///
    /// Idempotency contract: for a given (envelope address, queue_id)
    /// pair this MUST deliver at most once — calling again after success
    /// (or racing a concurrent attempt) returns `Ok` without duplicating
    /// mail. Two envelope addresses routed to one mailbox (catch-all) are
    /// two copies.
    ///
    /// # Errors
    ///
    /// Delivery failed; the message stays queued and the drain loop
    /// retries.
    fn deliver(&self, rcpt: &SpoolRcpt, queue_id: &str, message: &[u8]) -> Result<()>;

    /// Returns the bytes stored for the routing mailbox `mailbox`, for the
    /// quota check at RCPT (0 for a mailbox with nothing stored yet). May
    /// come from a short-lived cache, so it can lag deletions slightly.
    /// Blocking (it may scan storage).
    ///
    /// # Errors
    ///
    /// The mailbox name is unusable or its storage can't be measured.
    fn usage(&self, mailbox: &str) -> Result<u64>;

    /// Remove crash debris from the store: partial copies a delivery
    /// started but never committed, older than `min_age` at `now` (Unix
    /// seconds). Blocking, and possibly slow (it may walk every mailbox),
    /// so it runs less often than the drain (see [`sweep_sink_debris`]).
    ///
    /// Returns what was removed, for the log.
    ///
    /// # Errors
    ///
    /// The store can't be listed or a file can't be removed.
    fn sweep_debris(&self, now: u64, min_age: Duration) -> Result<Vec<String>>;
}

/// How long a measured mailbox size is trusted before the maildir is
/// scanned again. Deliveries through the sink update the cached value, so
/// the lag only affects mail removed from (or added to) the maildir by
/// something else.
const USAGE_CACHE_TTL: Duration = Duration::from_secs(60);

/// The most mailboxes whose sizes are cached; past this, expired entries
/// are dropped (and, if still full, all of them).
const USAGE_CACHE_ENTRIES: usize = 10_000;

/// Maildir delivery: one maildir per routing mailbox, under
/// `{root}/{domain}/{local}/` (both lowercased). Each copy is written to
/// `tmp/`, fsynced, and hard-linked into `new/` as
/// `{queue_id}.{envelope-address tag}.eml` (see [`address_tag`]), so the file name
/// records which address the copy was for; the sink creates `tmp/` and
/// `new/` on first delivery.
#[derive(Debug, Clone)]
pub struct MaildirSink {
    /// Directory holding the per-domain maildir trees.
    root: PathBuf,
    /// Measured mailbox sizes: maildir path → (when measured, bytes).
    usage: Arc<Mutex<HashMap<PathBuf, (Instant, u64)>>>,
}

impl MaildirSink {
    /// Open (creating if needed) the maildir root directory `root`.
    ///
    /// Returns the ready-to-use sink.
    ///
    /// # Errors
    ///
    /// The root cannot be created; the server should refuse to start
    /// rather than accept mail it cannot deliver.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        crate::fsutil::create_private_dir_all(&root)
            .with_context(|| format!("cannot create maildir root {}", root.display()))?;
        Ok(MaildirSink {
            root,
            usage: Arc::default(),
        })
    }

    /// Returns the bytes in the `new/` and `cur/` files of `maildir`
    /// (0 for a maildir that doesn't exist yet).
    ///
    /// # Errors
    ///
    /// A directory or file can't be read.
    fn scan(maildir: &Path) -> Result<u64> {
        let mut total = 0u64;
        for sub in ["new", "cur"] {
            let dir = maildir.join(sub);
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
            };
            for entry in entries {
                let meta = entry
                    .and_then(|e| e.metadata())
                    .with_context(|| format!("cannot measure {}", dir.display()))?;
                if meta.is_file() {
                    total = total.saturating_add(meta.len());
                }
            }
        }
        Ok(total)
    }
}

impl DeliverySink for MaildirSink {
    fn name(&self) -> &str {
        "maildir"
    }

    fn deliver(&self, rcpt: &SpoolRcpt, queue_id: &str, message: &[u8]) -> Result<()> {
        let mailbox = &rcpt.mailbox;
        let (local, domain) = split_recipient(mailbox)
            .with_context(|| format!("cannot deliver to malformed mailbox {mailbox:?}"))?;
        let maildir = self.root.join(&domain).join(&local);
        let tmp = maildir.join("tmp");
        let new = maildir.join("new");
        crate::fsutil::create_private_dir_all(&tmp)
            .with_context(|| format!("cannot create maildir {}", maildir.display()))?;
        crate::fsutil::create_private_dir_all(&new)
            .with_context(|| format!("cannot create maildir {}", maildir.display()))?;

        // Idempotency is per (envelope address, queue_id), case-insensitive
        // like recipient lookup, so the tag is the lowercased envelope
        // address. Under catch-all that differs from the mailbox, and each
        // address gets its own copy: the tag is injective, so two
        // addresses never share a file name.
        let filename = format!(
            "{queue_id}.{}.eml",
            address_tag(&rcpt.address.to_ascii_lowercase())
        );
        let target = new.join(&filename);

        // An existing delivery of this pair is success, not an error — the
        // drain loop and the inline fast path may both attempt the same
        // copy.
        if target.exists() {
            return Ok(());
        }

        // A staging name of this attempt's own, so two attempts racing
        // past the check above never write the same `tmp/` file. The
        // commit is a hard link (the maildir convention), which fails
        // with `EEXIST` instead of replacing: exactly one attempt creates
        // the target, and only that one counts the copy in the cached
        // size. The other found the copy already delivered (identical
        // bytes), which is success, as above.
        let staged = tmp.join(format!("{filename}.{}", uuid::Uuid::new_v4().simple()));
        if let Err(e) = write_durable(&staged, message) {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
        let created = match std::fs::hard_link(&staged, &target) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => {
                let _ = std::fs::remove_file(&staged);
                return Err(e)
                    .with_context(|| format!("cannot commit delivery to {}", target.display()));
            }
        };
        // The staged name is only a second link to the delivered file (or
        // an unused copy); a leftover is swept as debris.
        let _ = std::fs::remove_file(&staged);
        // Make the link itself durable: without this a power cut can lose
        // the new directory entry after the message was dequeued. Done on
        // both paths, so an attempt that lost the race doesn't report
        // success before the winner's entry is durable. A failure is a
        // failed delivery: the message stays queued, and the retry finds
        // the file if it did survive (idempotent).
        std::fs::File::open(&new)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("cannot sync maildir {}", new.display()))?;
        // Keep a cached size current, so a burst of deliveries is counted
        // before the next scan; only by the attempt that created the copy.
        if created {
            let mut cache = self.usage.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((_, bytes)) = cache.get_mut(&maildir) {
                *bytes = bytes.saturating_add(message.len() as u64);
            }
        }
        Ok(())
    }

    fn sweep_debris(&self, now: u64, min_age: Duration) -> Result<Vec<String>> {
        // {root}/{domain}/{local}/tmp/*: a file there is a copy whose
        // link into new/ never happened (or a staged name left beside a
        // delivered copy, which removing leaves in place). Live deliveries are seconds
        // old; `min_age` keeps them safe.
        let mut removed = Vec::new();
        let list = |dir: &Path| -> Result<Vec<PathBuf>> {
            match std::fs::read_dir(dir) {
                Ok(entries) => entries
                    .map(|e| e.map(|e| e.path()))
                    .collect::<std::io::Result<Vec<_>>>()
                    .with_context(|| format!("cannot list {}", dir.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(e) => Err(e).with_context(|| format!("cannot list {}", dir.display())),
            }
        };
        for domain in list(&self.root)?.into_iter().filter(|p| p.is_dir()) {
            for mailbox in list(&domain)?.into_iter().filter(|p| p.is_dir()) {
                for file in list(&mailbox.join("tmp"))? {
                    let old = crate::fsutil::changed_at(&file)
                        .is_some_and(|at| now.saturating_sub(at) >= min_age.as_secs());
                    if !old || !file.is_file() {
                        continue;
                    }
                    match std::fs::remove_file(&file) {
                        Ok(()) => removed.push(file.display().to_string()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            return Err(e)
                                .with_context(|| format!("cannot remove {}", file.display()))
                        }
                    }
                }
            }
        }
        Ok(removed)
    }

    fn usage(&self, mailbox: &str) -> Result<u64> {
        let (local, domain) = split_recipient(mailbox)
            .with_context(|| format!("cannot measure malformed mailbox {mailbox:?}"))?;
        let maildir = self.root.join(&domain).join(&local);
        let now = Instant::now();
        {
            let cache = self.usage.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(&(at, bytes)) = cache.get(&maildir) {
                if now.duration_since(at) < USAGE_CACHE_TTL {
                    return Ok(bytes);
                }
            }
        }
        // Scan without holding the lock; a delivery racing the scan is
        // counted by the next one.
        let bytes = Self::scan(&maildir)?;
        let mut cache = self.usage.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= USAGE_CACHE_ENTRIES {
            cache.retain(|_, (at, _)| now.duration_since(*at) < USAGE_CACHE_TTL);
            if cache.len() >= USAGE_CACHE_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(maildir, (now, bytes));
        Ok(bytes)
    }
}

/// Split `recipient` at its last `@` into `(local-part, domain)`, both
/// ASCII-lowercased, and validate both as filesystem-safe path
/// components.
///
/// The components become maildir directory names under the sink root,
/// so each must be a single safe component: non-empty, at most 128
/// bytes, no leading dot, no `..` run, and only dot-atom characters
/// other than `/`.
///
/// # Errors
///
/// No `@`, or a component that fails the checks above (anything that
/// could escape the maildir root). The caller treats that as a failed
/// delivery (the message stays queued), never as a path to honor.
fn split_recipient(recipient: &str) -> Result<(String, String)> {
    let (local, domain) = recipient
        .rsplit_once('@')
        .ok_or_else(|| anyhow::anyhow!("no '@' in recipient {recipient:?}"))?;
    let local = local.to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();
    // Both components must be a single path segment: never empty, no
    // leading dot (so never `.` or `..`), no `..` run, and only the
    // mailbox-safe set the session enforces for local-parts at RCPT time
    // (`address::is_mailbox_safe`, the one definition of it).
    let safe = crate::address::is_mailbox_safe;
    for component in [&local, &domain] {
        if component.is_empty()
            || component.len() > 128
            || component.starts_with('.')
            || component.contains("..")
            || !component.bytes().all(safe)
        {
            return Err(anyhow::anyhow!(
                "unsafe mailbox path component in {recipient:?}"
            ));
        }
    }
    Ok((local, domain))
}

/// The longest [`address_tag`] before it falls back to a hash, so that
/// `{queue id}.{tag}.eml` stays well under a file name's 255 bytes.
const MAX_TAG_LEN: usize = 160;

/// Returns a filesystem-safe tag for the (lowercased) envelope address
/// `recipient` in maildir file names. It is injective: distinct addresses
/// always get distinct tags, or two copies of a message would share one
/// file and all but one would be lost.
///
/// ASCII letters, digits, `.` and `-` are kept, the `@` becomes `_`, and
/// every other byte (`_` and `%` included) becomes `%XX`. So
/// `user@example.org` is `user_example.org`, as it always was, while
/// `a+b@x` (`a%2bb_x`) and `a_b@x` (`a%5fb_x`) no longer collide. A tag
/// that would be longer than [`MAX_TAG_LEN`] is cut and ends in `~` and
/// a SHA-256 prefix of the whole address instead (`~` is always escaped
/// otherwise, so the two forms can't meet).
fn address_tag(recipient: &str) -> String {
    use std::fmt::Write as _;
    let (local, domain) = recipient.rsplit_once('@').unwrap_or((recipient, ""));
    let mut tag = String::with_capacity(recipient.len());
    let escape = |part: &str, tag: &mut String| {
        for b in part.bytes() {
            if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
                tag.push(b as char);
            } else {
                let _ = write!(tag, "%{b:02x}");
            }
        }
    };
    escape(local, &mut tag);
    if recipient.contains('@') {
        tag.push('_');
        escape(domain, &mut tag);
    }
    if tag.len() <= MAX_TAG_LEN {
        return tag;
    }
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(recipient.as_bytes());
    let mut cut = MAX_TAG_LEN - 33;
    while !tag.is_char_boundary(cut) {
        cut -= 1;
    }
    tag.truncate(cut);
    tag.push('~');
    for b in &digest[..16] {
        let _ = write!(tag, "{b:02x}");
    }
    tag
}

/// Write `bytes` to a new private file at `path` (truncating any
/// existing file) and fsync before returning: callers can rely on the
/// bytes surviving a crash once this returns `Ok`.
///
/// # Errors
///
/// The file cannot be created, written, or fsynced; the error message
/// names the path.
fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = crate::fsutil::create_private_file(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("cannot fsync {}", path.display()))?;
    Ok(())
}

/// Format `ts` (in UTC) as an RFC 5322 date-time for the `Received:`
/// header.
///
/// Returns the RFC 2822/5322 form, or the RFC 3339 form if the strict
/// formatting fails (still machine-parseable).
fn rfc5322_date(ts: jiff::Timestamp) -> String {
    let zoned = ts.to_zoned(jiff::tz::TimeZone::UTC);
    jiff::fmt::rfc2822::to_string(&zoned).unwrap_or_else(|_| ts.to_string())
}

/// Prepend the trace headers to the message `raw` as received, for the
/// accepted message described by `meta` (whose `queue_id` must already be
/// set). Called once, before the spool write.
///
/// Returns the final message, the same for every recipient:
/// `Return-Path:` (the envelope sender in `<>`, `<>` for the null
/// sender), then a `Received:` header (from the HELO and peer IP, by
/// `meta.server_domain`, with `ESMTP`, plus `S` for TLS and `A` for an
/// authenticated submission per RFC 3848, and the queue ID), then this
/// server's `Authentication-Results:` (see [`authentication_results`]),
/// then an `X-Display-Name-Warning:` when `meta.display_name_claims` isn't
/// empty, then `raw` verbatim (the caller has removed forged copies of
/// those two headers). There is no `for` clause (RFC 5321 §4.4 makes it optional):
/// one message shared by all recipients can't name one without disclosing
/// it to the others. An unparseable `meta.received_at` is dated at the
/// Unix epoch.
pub fn with_trace_headers(meta: &SpoolMeta, raw: &[u8]) -> Vec<u8> {
    let sender = match meta.mail_from.as_deref() {
        Some(addr) if !addr.is_empty() => format!("<{addr}>"),
        _ => "<>".to_string(),
    };
    // The peer is recorded as "ip:port"; the trace header convention is
    // the address in parentheses.
    let peer_ip = meta
        .peer
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(&meta.peer);
    let protocol = match (meta.tls_active, meta.authenticated.is_some()) {
        (false, false) => "ESMTP",
        (true, false) => "ESMTPS",
        (false, true) => "ESMTPA",
        (true, true) => "ESMTPSA",
    };
    // HELO is validated at the SMTP layer; this is defense in depth
    // against whatever the spooled metadata holds. Anything but printable
    // ASCII becomes `?`, so no CR/LF can split the header.
    let helo: String = meta
        .helo
        .as_deref()
        .unwrap_or("unknown")
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect();
    let date = rfc5322_date(
        meta.received_at
            .parse()
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH),
    );

    let mut out = Vec::with_capacity(raw.len() + 512);
    out.extend_from_slice(format!("Return-Path: {sender}\r\n").as_bytes());
    out.extend_from_slice(
        format!(
            "Received: from {helo} ({peer_ip})\r\n\tby {} ({}) with {protocol} id {};\r\n\t{date}\r\n",
            meta.server_domain,
            env!("CARGO_PKG_NAME"),
            meta.queue_id,
        )
        .as_bytes(),
    );
    out.extend_from_slice(authentication_results(meta).as_bytes());
    if !meta.display_name_claims.is_empty() {
        let claims: Vec<String> = meta
            .display_name_claims
            .iter()
            .map(|d| header_token(d))
            .collect();
        // A cut list says so: the domains left out may include the one
        // that matters, and that many claims is itself the signal.
        let truncated = match meta.display_name_claims_truncated {
            Some(addresses) => format!(
                " (truncated: {} of the {addresses} addresses at other domains shown)",
                claims.len()
            ),
            None => String::new(),
        };
        out.extend_from_slice(
            format!(
                "X-Display-Name-Warning: the From display name names {}, which is not the sender{truncated}\r\n",
                claims.join(", ")
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(raw);
    out
}

/// Returns this server's `Authentication-Results:` header (RFC 8601) for
/// the message described by `meta`, with `meta.server_domain` as the
/// authserv-id and one result per method:
///
/// - `auth=pass smtp.auth=<login>` for an authenticated submission;
/// - `spf=<result>` with `smtp.mailfrom=<domain>`, or `smtp.helo=<name>`
///   for the null sender (whose SPF identity is the HELO name); omitted
///   when SPF wasn't evaluated (authenticated submissions);
/// - one `dkim=pass|fail header.d=<d> header.s=<s>` per evaluated
///   signature, or `dkim=none`;
/// - `dmarc=pass|fail header.from=<domain>`, or `dmarc=none` when the
///   From domain publishes no policy.
///
/// Every value is reduced to header-safe characters ([`header_token`]),
/// since signature tags and names come from the sender.
pub fn authentication_results(meta: &SpoolMeta) -> String {
    let mut results: Vec<String> = Vec::new();
    if let Some(user) = &meta.authenticated {
        results.push(format!("auth=pass smtp.auth={}", header_token(user)));
    }
    if let Some(spf) = &meta.spf_result {
        let result = spf.as_str();
        let identity = match meta.mail_from.as_deref() {
            Some(addr) if !addr.is_empty() => addr
                .rsplit_once('@')
                .map(|(_, d)| format!("smtp.mailfrom={}", header_token(d))),
            _ => meta
                .helo
                .as_deref()
                .map(|h| format!("smtp.helo={}", header_token(h))),
        };
        results.push(match identity {
            Some(identity) => format!("spf={} {identity}", header_token(result)),
            None => format!("spf={}", header_token(result)),
        });
    }
    if meta.dkim.is_empty() {
        results.push("dkim=none".to_string());
    }
    for dkim in &meta.dkim {
        results.push(format!(
            "dkim={} header.d={} header.s={}",
            if dkim.verified { "pass" } else { "fail" },
            header_token(&dkim.domain),
            header_token(&dkim.selector),
        ));
    }
    results.push(match &meta.dmarc {
        Some(dmarc) => format!(
            "dmarc={} header.from={}",
            if dmarc.pass { "pass" } else { "fail" },
            header_token(&dmarc.from_domain)
        ),
        None => "dmarc=none".to_string(),
    });
    format!(
        "Authentication-Results: {};\r\n\t{}\r\n",
        header_token(&meta.server_domain),
        results.join(";\r\n\t")
    )
}

/// The longest value [`header_token`] writes: a full DNS name, or an
/// address with its local-part.
const MAX_HEADER_TOKEN_LEN: usize = 320;

/// Returns `value` with every character outside letters, digits and
/// `.-_+@` replaced by `_`, so a sender-chosen value (a DKIM selector, a
/// HELO name) can't break or extend a header, cut to
/// [`MAX_HEADER_TOKEN_LEN`] bytes (plus a `...` marking the cut).
fn header_token(value: &str) -> String {
    // Bounded too: an over-long value (a `From:` domain has no length
    // limit of its own) is cut and marked with `...`.
    crate::verdict::truncated(value, MAX_HEADER_TOKEN_LEN)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// What one drain pass did, for logging.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainStats {
    /// Messages fully delivered to every recipient and removed from the
    /// queue.
    pub delivered: usize,
    /// Messages still queued after failed (or partially failed)
    /// delivery attempts.
    pub retrying: usize,
    /// Messages moved to the dead-letter directory after failing for
    /// [`MAX_QUEUE_LIFETIME`].
    pub dead_lettered: usize,
    /// Messages left untouched because their next retry is not due yet.
    pub deferred: usize,
    /// Uncommitted crash-debris files removed by the sweep (see
    /// [`SpoolQueue::sweep_debris`]).
    pub debris_removed: usize,
}

/// How old an uncommitted spool file must be before the drain removes it
/// as crash debris. A write takes seconds, so an hour leaves a wide margin
/// (and covers an operator mid-way through the requeue procedure).
pub const DEBRIS_MIN_AGE: Duration = Duration::from_secs(60 * 60);

/// The first retry interval after a failed delivery attempt. Each further
/// failure doubles it, up to [`RETRY_MAX`].
pub const RETRY_BASE: Duration = Duration::from_secs(60);

/// The longest interval between retries.
pub const RETRY_MAX: Duration = Duration::from_secs(60 * 60);

/// How long a message keeps being retried, counted from its first failed
/// delivery attempt, before it is dead-lettered. Five days is the usual MTA
/// queue lifetime (Postfix's `maximal_queue_lifetime`; RFC 5321 §4.5.4.1
/// suggests 4–5 days). Mail that got a `250` must survive any realistic
/// outage of the delivery backend.
pub const MAX_QUEUE_LIFETIME: Duration = Duration::from_secs(5 * 24 * 60 * 60);

/// Returns the wait before the next attempt after `attempts` failed
/// ones: 1, 2, 4, 8 … minutes (1 minute for 0 or 1), capped at
/// [`RETRY_MAX`].
pub fn retry_delay(attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(16);
    RETRY_BASE.saturating_mul(1u32 << doublings).min(RETRY_MAX)
}

/// Returns the current time in seconds since the Unix epoch (0 if the
/// clock is before the epoch).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Run one pass of the queue drain over `spool` into `sink` at the
/// current time. See [`drain_at`] for the behavior, return value and
/// errors.
/// Sweep crash debris older than [`DEBRIS_MIN_AGE`] from `sink` at `now`
/// (Unix seconds; see [`DeliverySink::sweep_debris`]), logging each
/// removal at `warn` and a failure without propagating it. Blocking.
///
/// Returns how many files were removed.
pub fn sweep_sink_debris(sink: &dyn DeliverySink, now: u64) -> usize {
    match sink.sweep_debris(now, DEBRIS_MIN_AGE) {
        Ok(removed) => {
            for item in &removed {
                tracing::warn!(file = %item, "removed uncommitted delivery file (crash debris)");
            }
            removed.len()
        }
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "delivery debris sweep failed");
            0
        }
    }
}

/// [`sweep_sink_debris`] now.
pub fn sweep_sink_debris_now(sink: &dyn DeliverySink) -> usize {
    sweep_sink_debris(sink, unix_now())
}

pub fn drain_once(spool: &dyn SpoolQueue, sink: &dyn DeliverySink) -> Result<DrainStats> {
    drain_at(spool, sink, unix_now())
}

/// Run one pass of the queue drain over `spool` into `sink` at `now`
/// (Unix seconds).
///
/// First, crash debris older than [`DEBRIS_MIN_AGE`] is swept (see
/// [`SpoolQueue::sweep_debris`]); each removed item is logged at `warn`,
/// and a sweep failure is logged without failing the pass.
///
/// Then, for each committed message:
/// - not yet due (its last failure was less than [`retry_delay`] ago):
///   skipped, and its payload is not read;
/// - payload unreadable (removed by a concurrent fast-path dequeue, or
///   damaged): logged and skipped for this pass;
/// - due: the stored payload is delivered verbatim to every recipient
///   (idempotent per recipient, so recipients that already have their
///   copy are not duplicated). A message delivered to every recipient is
///   dequeued.
/// - otherwise a failed attempt is recorded. If the message has been
///   failing for [`MAX_QUEUE_LIFETIME`], it is dead-lettered and logged
///   at `error`.
///
/// Blocking; callers run it on a blocking thread pool. Delivery failures
/// are logged and leave the message queued; they never fail the pass.
///
/// Returns what the pass did.
///
/// # Errors
///
/// Spool I/O fails: listing the queue, removing a delivered message,
/// recording an attempt, or dead-lettering. The pass stops at that
/// message; the caller logs the error and the next pass retries.
pub fn drain_at(spool: &dyn SpoolQueue, sink: &dyn DeliverySink, now: u64) -> Result<DrainStats> {
    let mut stats = DrainStats::default();
    match spool.sweep_debris(now, DEBRIS_MIN_AGE) {
        Ok(removed) => {
            for item in &removed {
                tracing::warn!(file = %item, "removed uncommitted spool file (crash debris)");
            }
            stats.debris_removed = removed.len();
        }
        // Debris only costs disk space; never let it stop deliveries.
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "spool debris sweep failed"),
    }
    for queued in spool.list()? {
        let meta = &queued.meta;
        if let Some(last) = queued.last_failure {
            if now < last.saturating_add(retry_delay(queued.attempts).as_secs()) {
                stats.deferred += 1;
                continue;
            }
        }
        // Loaded only now, for a message that is due.
        let payload = match spool.load_payload(&queued) {
            Ok(payload) => payload,
            Err(e) => {
                // Removed by a concurrent fast-path dequeue, or damaged.
                // Either way there is nothing to deliver this pass.
                tracing::warn!(queue_id = %meta.queue_id, error = %e, "queued payload unreadable; skipped");
                continue;
            }
        };
        let mut all_delivered = true;
        for rcpt in &meta.rcpt_to {
            // The stored payload is the final message (trace headers
            // included): deliver it as is.
            if let Err(e) = sink.deliver(rcpt, &meta.queue_id, &payload) {
                all_delivered = false;
                tracing::warn!(
                    queue_id = %meta.queue_id,
                    recipient = %rcpt.address,
                    mailbox = %rcpt.mailbox,
                    error = %e,
                    "delivery failed; message stays queued"
                );
            }
        }

        if all_delivered {
            spool.dequeue(&queued)?;
            stats.delivered += 1;
            tracing::info!(queue_id = %meta.queue_id, "message delivered and dequeued");
            continue;
        }

        let record = spool.record_attempt(&queued, now)?;
        let failing_for = now.saturating_sub(record.first_failure.unwrap_or(now));
        if failing_for >= MAX_QUEUE_LIFETIME.as_secs() {
            spool.dead_letter(&queued)?;
            stats.dead_lettered += 1;
            // Accepted mail is leaving the queue undelivered: an operator
            // must see this (alert on it) and can requeue it once the cause
            // is fixed (move `.eml`, then `.json`, back to `new/` and delete
            // `.attempts`).
            tracing::error!(
                queue_id = %meta.queue_id,
                attempts = record.attempts,
                failing_for_secs = failing_for,
                recipients = meta.rcpt_to.len(),
                "accepted message undeliverable for the queue lifetime; dead-lettered"
            );
        } else {
            stats.retrying += 1;
            tracing::info!(
                queue_id = %meta.queue_id,
                attempts = record.attempts,
                next_attempt_in_secs = retry_delay(record.attempts).as_secs(),
                "delivery deferred"
            );
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::{DiskSpool, SpoolMeta, SpoolRcpt, SpoolWriter as _};

    /// An envelope recipient `address` routed to `mailbox`.
    fn rcpt(address: &str, mailbox: &str) -> SpoolRcpt {
        SpoolRcpt {
            address: address.into(),
            mailbox: mailbox.into(),
            user: None,
            public_key: None,
            key_generation: None,
        }
    }

    /// A metadata record with plausible values; tests override the
    /// fields they care about via struct update syntax.
    fn sample_meta() -> SpoolMeta {
        SpoolMeta {
            queue_id: "0000000064f1.0123456789abcdef".into(),
            session_id: "session-1".into(),
            server_domain: "mail.test".into(),
            received_at: jiff::Timestamp::now().to_string(),
            peer: "127.0.0.1:40000".into(),
            helo: Some("client.test".into()),
            mail_from: Some("sender@example.test".into()),
            rcpt_to: vec![SpoolRcpt {
                address: "user@example.org".into(),
                mailbox: "user@example.org".into(),
                user: Some("alice".into()),
                public_key: None,
                key_generation: None,
            }],
            spf_result: Some(spf::SpfResult::Pass),
            spf_helo: None,
            dkim: Vec::new(),
            dmarc: None,
            authenticated: None,
            tls_active: false,
            message_size: 0,
            encryption: None,
            display_name_claims: Vec::new(),
            display_name_claims_truncated: None,
        }
    }

    /// with_trace_headers prepends Return-Path and Received, keeps the raw
    /// bytes verbatim, names no recipient (the message is shared by all of
    /// them), and marks TLS and authentication in the protocol token.
    #[test]
    fn trace_headers_are_message_level() {
        let raw = b"Subject: hi\r\n\r\nbody\r\n".to_vec();
        let meta = sample_meta();
        let text = String::from_utf8(with_trace_headers(&meta, &raw)).unwrap();

        assert!(text.starts_with("Return-Path: <sender@example.test>\r\n"));
        assert!(text.contains("Received: from client.test (127.0.0.1)\r\n"));
        assert!(text.contains(&format!(
            "\tby mail.test (mailserv) with ESMTP id {};\r\n\t",
            meta.queue_id
        )));
        assert!(!text.contains("for <"), "no recipient is named: {text}");
        assert!(!text.contains("user@example.org"));
        // Raw message follows verbatim after the trace headers.
        assert!(text.ends_with("\r\nSubject: hi\r\n\r\nbody\r\n"));

        // Null sender renders as the empty path.
        let mut null = sample_meta();
        null.mail_from = Some(String::new());
        assert!(with_trace_headers(&null, &raw).starts_with(b"Return-Path: <>\r\n"));

        // RFC 3848 protocol tokens.
        for (tls, user, token) in [
            (true, None, " with ESMTPS id "),
            (false, Some("alice"), " with ESMTPA id "),
            (true, Some("alice"), " with ESMTPSA id "),
        ] {
            let mut m = sample_meta();
            m.tls_active = tls;
            m.authenticated = user.map(String::from);
            let text = String::from_utf8(with_trace_headers(&m, &raw)).unwrap();
            assert!(text.contains(token), "{token}: {text}");
        }
    }

    /// Sender-chosen values in our headers are bounded in length, and the
    /// cut is marked.
    #[test]
    fn header_tokens_are_bounded() {
        assert_eq!(header_token("a.example"), "a.example");
        let long = header_token(&"d.".repeat(50_000));
        assert_eq!(long.len(), MAX_HEADER_TOKEN_LEN + 3);
        assert!(long.ends_with("..."));
        // The trace headers stay small whatever the From domain.
        let mut meta = sample_meta();
        meta.dmarc = Some(crate::verdict::DmarcSummary {
            from_domain: "x".repeat(100_000),
            policy: dmarc::DmarcPolicy::None,
            spf_aligned: false,
            dkim_aligned: false,
            pass: false,
            action: dmarc::Action::Pass,
        });
        assert!(authentication_results(&meta).len() < 1024);
    }

    /// Authentication-Results names our authserv-id and each method's
    /// result: SPF with the MAIL FROM domain (the HELO name for a bounce),
    /// every DKIM signature, DMARC with the From domain, AUTH for a
    /// submission; sender-chosen values are reduced to safe characters.
    #[test]
    fn authentication_results_reports_each_method() {
        use crate::verdict::{DkimSummary, DmarcSummary};
        let mut meta = sample_meta();
        meta.dkim = vec![
            DkimSummary {
                domain: "example.test".into(),
                selector: "s1".into(),
                body_hash_ok: true,
                signature_ok: true,
                verified: true,
                error: None,
                temporary: false,
            },
            DkimSummary {
                domain: "evil.example".into(),
                selector: "x;dmarc=pass\r\nX-Injected: 1".into(),
                body_hash_ok: false,
                signature_ok: false,
                verified: false,
                error: Some("bad".into()),
                temporary: false,
            },
        ];
        meta.dmarc = Some(DmarcSummary {
            from_domain: "example.test".into(),
            policy: dmarc::DmarcPolicy::Reject,
            spf_aligned: true,
            dkim_aligned: true,
            pass: true,
            action: dmarc::Action::Pass,
        });
        assert_eq!(
            authentication_results(&meta),
            "Authentication-Results: mail.test;\r\n\
             \tspf=pass smtp.mailfrom=example.test;\r\n\
             \tdkim=pass header.d=example.test header.s=s1;\r\n\
             \tdkim=fail header.d=evil.example header.s=x_dmarc_pass__X-Injected__1;\r\n\
             \tdmarc=pass header.from=example.test\r\n"
        );

        // A bounce: SPF's identity is the HELO name; no signatures, no policy.
        let mut bounce = sample_meta();
        bounce.mail_from = Some(String::new());
        bounce.spf_result = Some(spf::SpfResult::SoftFail);
        assert_eq!(
            authentication_results(&bounce),
            "Authentication-Results: mail.test;\r\n\
             \tspf=softfail smtp.helo=client.test;\r\n\tdkim=none;\r\n\tdmarc=none\r\n"
        );

        // A submission: AUTH, no SPF.
        let mut submitted = sample_meta();
        submitted.authenticated = Some("alice".into());
        submitted.spf_result = None;
        assert!(authentication_results(&submitted).starts_with(
            "Authentication-Results: mail.test;\r\n\tauth=pass smtp.auth=alice;\r\n\tdkim=none"
        ));
    }

    /// The message gets our Authentication-Results after the Received
    /// header, and a display-name warning only when there are claims.
    #[test]
    fn trace_headers_carry_the_verdicts() {
        let mut meta = sample_meta();
        let text =
            String::from_utf8(with_trace_headers(&meta, b"Subject: x\r\n\r\nbody\r\n")).unwrap();
        assert!(
            text.contains("\r\nAuthentication-Results: mail.test;\r\n\tspf=pass"),
            "{text}"
        );
        assert!(!text.contains("X-Display-Name-Warning"));

        meta.display_name_claims = vec!["victim.example".into()];
        let text =
            String::from_utf8(with_trace_headers(&meta, b"Subject: x\r\n\r\nbody\r\n")).unwrap();
        assert!(text.contains(
            "X-Display-Name-Warning: the From display name names victim.example, which is not the sender\r\nSubject: x"
        ), "{text}");
    }

    /// A cut claim list is marked in the warning, with how many of the
    /// addresses found at other domains are shown.
    #[test]
    fn trace_headers_mark_a_cut_claim_list() {
        let meta = SpoolMeta {
            display_name_claims: vec!["a0.com".into(), "a1.com".into()],
            display_name_claims_truncated: Some(2400),
            ..sample_meta()
        };
        let text =
            String::from_utf8(with_trace_headers(&meta, b"Subject: x\r\n\r\nbody\r\n")).unwrap();
        assert!(text.contains(
            "X-Display-Name-Warning: the From display name names a0.com, a1.com, which is not the sender (truncated: 2 of the 2400 addresses at other domains shown)\r\nSubject: x"
        ), "{text}");
    }

    /// Defence in depth: a stored HELO containing a bare CR can't inject a
    /// header into the message.
    #[test]
    fn trace_headers_neutralise_control_characters_in_helo() {
        let mut meta = sample_meta();
        meta.helo = Some("evil.example\rX-Injected: yes".into());
        let text = String::from_utf8(with_trace_headers(&meta, b"\r\nbody\r\n")).unwrap();
        assert!(text.contains("Received: from evil.example?X-Injected:?yes (127.0.0.1)\r\n"));
        assert_eq!(text.matches('\r').count(), text.matches("\r\n").count());
    }

    /// The maildir sink writes one copy per envelope address into the
    /// routing mailbox's {root}/{domain}/{local}/new, named after the
    /// address; redelivery of the same (address, queue_id) is idempotent,
    /// case-insensitively, and the bytes are stored verbatim.
    #[tokio::test]
    async fn maildir_delivery_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();

        let message = b"Return-Path: <s@x.test>\r\nReceived: ...\r\nSubject: hi\r\n".to_vec();
        let user = rcpt("User@Example.ORG", "User@Example.ORG");
        sink.deliver(&user, "q-1", &message).unwrap();

        let delivered = dir
            .path()
            .join("example.org/user/new/q-1.user_example.org.eml");
        assert_eq!(std::fs::read(&delivered).unwrap(), message);

        // Redelivery (crash recovery, drain race) does not duplicate.
        let lower = rcpt("user@example.org", "user@example.org");
        sink.deliver(&lower, "q-1", &message).unwrap();
        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(delivered.parent().unwrap())
            .await
            .unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec!["q-1.user_example.org.eml"]);
    }

    /// Two catch-all addresses routed to one inbox get one copy each,
    /// told apart by the envelope address in the file name.
    #[tokio::test]
    async fn catch_all_addresses_get_separate_copies() {
        catch_all_copies().await;
    }

    /// `usage` measures a mailbox's `new/` and `cur/` files (0 before the
    /// first delivery), serves the cached value while fresh, counts
    /// deliveries through the sink right away, and refuses a malformed
    /// mailbox name.
    #[test]
    fn maildir_usage_is_measured_and_tracked() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();
        let mailbox = "user@example.org";
        assert_eq!(sink.usage(mailbox).unwrap(), 0);

        sink.deliver(&rcpt(mailbox, mailbox), "q-1", &[b'x'; 100])
            .unwrap();
        assert_eq!(
            sink.usage(mailbox).unwrap(),
            100,
            "counted through the cache"
        );

        // A file added behind the sink's back (another tool, cur/) is
        // seen once the cached value expires, not before.
        let cur = dir.path().join("example.org/user/cur");
        std::fs::create_dir_all(&cur).unwrap();
        std::fs::write(cur.join("read.eml"), [b'y'; 50]).unwrap();
        assert_eq!(sink.usage(mailbox).unwrap(), 100, "cached");
        let fresh = MaildirSink::open(dir.path()).unwrap();
        assert_eq!(
            fresh.usage(mailbox).unwrap(),
            150,
            "a scan sees new/ and cur/"
        );

        assert!(sink.usage("../etc@example.org").is_err());
    }

    /// The maildir sweep removes `tmp/` files old enough to be crash
    /// leftovers, and nothing else: not a fresh `tmp/` file (a delivery in
    /// progress), not delivered mail in `new/`.
    #[test]
    fn maildir_sweep_removes_only_old_tmp_files() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();
        sink.deliver(
            &rcpt("user@example.org", "user@example.org"),
            "q-1",
            b"mail",
        )
        .unwrap();
        let tmp = dir.path().join("example.org/user/tmp");
        std::fs::write(tmp.join("q-2.partial.eml"), b"half").unwrap();
        let now = unix_now();

        assert!(
            sink.sweep_debris(now, DEBRIS_MIN_AGE).unwrap().is_empty(),
            "too fresh"
        );
        let removed = sink.sweep_debris(now + 2 * 3600, DEBRIS_MIN_AGE).unwrap();
        assert_eq!(removed.len(), 1, "{removed:?}");
        assert!(removed[0].ends_with("q-2.partial.eml"));
        assert!(dir
            .path()
            .join("example.org/user/new/q-1.user_example.org.eml")
            .exists());

        let empty = MaildirSink::open(dir.path().join("nothing-yet")).unwrap();
        assert!(empty.sweep_debris(now, DEBRIS_MIN_AGE).unwrap().is_empty());
    }

    /// Envelope addresses that differ only in punctuation get their own
    /// copies in one catch-all inbox (a lossy tag mapped `a+b`, `a_b`,
    /// `a*b`, `a=b` and `a~b` to one file, and four copies were lost).
    #[test]
    fn punctuation_variants_get_separate_copies() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();
        let addresses = [
            "a+b@catch.example",
            "a_b@catch.example",
            "a*b@catch.example",
            "a=b@catch.example",
            "a~b@catch.example",
            "a%5fb@catch.example",
            "a%b@catch.example",
        ];
        for address in addresses {
            sink.deliver(
                &rcpt(address, "inbox@catch.example"),
                "q-1",
                address.as_bytes(),
            )
            .unwrap();
        }
        let new = dir.path().join("catch.example/inbox/new");
        let names: Vec<_> = std::fs::read_dir(&new).unwrap().collect();
        assert_eq!(names.len(), addresses.len());
        for address in addresses {
            let file = new.join(format!("q-1.{}.eml", address_tag(address)));
            assert_eq!(std::fs::read(file).unwrap(), address.as_bytes());
        }
    }

    /// The tag keeps plain addresses as they always were, escapes the
    /// rest injectively, and stays short for the longest addresses.
    #[test]
    fn address_tags() {
        assert_eq!(address_tag("user@example.org"), "user_example.org");
        assert_eq!(address_tag("a+b@x"), "a%2bb_x");
        assert_eq!(address_tag("a_b@x"), "a%5fb_x");
        assert_eq!(address_tag("a%5fb@x"), "a%255fb_x");
        assert_eq!(address_tag("a~b@x"), "a%7eb_x");
        let long_a = format!("{}@{}.example", "a".repeat(64), "d".repeat(200));
        let long_b = format!("{}@{}.example", "a".repeat(64), "d".repeat(201));
        let (ta, tb) = (address_tag(&long_a), address_tag(&long_b));
        assert!(ta.len() <= MAX_TAG_LEN && tb.len() <= MAX_TAG_LEN);
        assert_ne!(ta, tb);
        assert!(ta.contains('~'));
        // The escaped form is at its longest for a 64-octet local-part of
        // escaped bytes; it still fits a file name with the queue ID.
        let escaped = format!("{}@x.example", "+".repeat(64));
        assert!(address_tag(&escaped).len() <= MAX_TAG_LEN);
    }

    /// The fast path and the drain delivering the same copy at once both
    /// succeed and leave exactly one file, with nothing left in `tmp/`.
    #[test]
    fn racing_deliveries_of_one_copy() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();
        let message = vec![b'm'; 256 * 1024];
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        sink.deliver(&rcpt("u@example.org", "u@example.org"), "q-1", &message)
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });
        let mailbox = dir.path().join("example.org/u");
        assert_eq!(std::fs::read_dir(mailbox.join("new")).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(mailbox.join("tmp")).unwrap().count(), 0);
        assert_eq!(
            std::fs::read(mailbox.join("new/q-1.u_example.org.eml")).unwrap(),
            message
        );
    }

    /// Racing attempts of one copy both succeed (see above), but the cached
    /// mailbox size must count the copy once: every attempt that renamed its
    /// staging file adds `message.len()` to the cache, so a burst inflates
    /// the reading and the next quota check can defer a message that fits.
    #[test]
    fn racing_deliveries_count_the_copy_once() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();
        let mailbox = "u@example.org";
        let message = vec![b'm'; 256 * 1024];
        // A quota check populates the cache; deliveries keep it current.
        let before = sink.usage(mailbox).unwrap();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        sink.deliver(&rcpt("u@example.org", mailbox), "q-1", &message)
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });
        let new = dir.path().join("example.org/u/new");
        let on_disk: u64 = std::fs::read_dir(&new)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert_eq!(on_disk, message.len() as u64);
        assert_eq!(
            sink.usage(mailbox).unwrap(),
            before + on_disk,
            "the cached size counts the copy once, not once per attempt"
        );
    }

    async fn catch_all_copies() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();
        for address in ["a@catch.example", "b@catch.example"] {
            sink.deliver(&rcpt(address, "inbox@catch.example"), "q-1", b"msg")
                .unwrap();
        }
        let mut names: Vec<String> = std::fs::read_dir(dir.path().join("catch.example/inbox/new"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["q-1.a_catch.example.eml", "q-1.b_catch.example.eml"]
        );
    }

    /// drain_once delivers every recipient copy of a queued message and
    /// removes it from the spool; a second pass finds nothing.
    #[tokio::test]
    async fn drain_delivers_and_dequeues() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path().join("spool"), None).unwrap();
        let sink = MaildirSink::open(dir.path().join("maildir")).unwrap();

        let raw = b"Subject: hi\r\n\r\nbody\r\n".to_vec();
        spool
            .write(
                SpoolMeta {
                    rcpt_to: vec![
                        SpoolRcpt {
                            address: "a@example.org".into(),
                            mailbox: "a@example.org".into(),
                            user: Some("alice".into()),
                            public_key: None,
                            key_generation: None,
                        },
                        SpoolRcpt {
                            address: "b@example.org".into(),
                            mailbox: "b@example.org".into(),
                            user: Some("bob".into()),
                            public_key: None,
                            key_generation: None,
                        },
                    ],
                    ..sample_meta()
                },
                raw.clone(),
            )
            .unwrap();

        let stats = drain_once(&spool, &sink).unwrap();
        assert_eq!(
            stats,
            DrainStats {
                delivered: 1,
                ..DrainStats::default()
            }
        );

        // Both copies exist, each exactly the stored payload (the drain
        // adds nothing); the queue is empty.
        for rcpt in ["a", "b"] {
            let path = dir.path().join(format!("maildir/example.org/{rcpt}/new"));
            let mut rd = tokio::fs::read_dir(&path).await.unwrap();
            let mut names = Vec::new();
            while let Some(e) = rd.next_entry().await.unwrap() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
            assert_eq!(names.len(), 1, "{path:?}: {names:?}");
            let bytes = std::fs::read(path.join(&names[0])).unwrap();
            assert_eq!(bytes, raw, "delivered verbatim");
        }
        assert!(spool.list().unwrap().is_empty());

        // Second pass is a no-op.
        let stats = drain_once(&spool, &sink).unwrap();
        assert_eq!(stats, DrainStats::default());
    }

    /// A sink that fails while `failing` is set, then delivers.
    struct FlakySink {
        /// Whether `deliver` currently fails.
        failing: std::sync::atomic::AtomicBool,
        /// Number of `deliver` calls so far.
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FlakySink {
        /// A sink that starts out failing.
        fn failing() -> Self {
            FlakySink {
                failing: true.into(),
                calls: 0.into(),
            }
        }

        /// Returns the number of `deliver` calls so far.
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DeliverySink for FlakySink {
        fn name(&self) -> &str {
            "flaky"
        }

        fn deliver(&self, _r: &SpoolRcpt, _q: &str, _m: &[u8]) -> Result<()> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                Err(anyhow::anyhow!("disk on fire"))
            } else {
                Ok(())
            }
        }

        fn usage(&self, _mailbox: &str) -> Result<u64> {
            Ok(0)
        }

        fn sweep_debris(&self, _now: u64, _min_age: Duration) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    /// The retry interval doubles per failure and stops at `RETRY_MAX`.
    #[test]
    fn retry_schedule_backs_off_to_the_cap() {
        let mins = |a| retry_delay(a).as_secs() / 60;
        assert_eq!([1, 2, 3, 4, 5, 6, 7].map(mins), [1, 2, 4, 8, 16, 32, 60]);
        assert_eq!(retry_delay(10_000), RETRY_MAX, "no overflow");
    }

    /// A day-long delivery outage loses nothing. Retries back off (a
    /// message isn't touched before it is due), and the message is
    /// delivered once the sink recovers, a day later.
    #[tokio::test]
    async fn long_outage_is_retried_with_backoff_then_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path().join("spool"), None).unwrap();
        let sink = FlakySink::failing();
        spool.write(sample_meta(), b"payload".to_vec()).unwrap();
        let t0: u64 = 1_700_000_000;

        // First failure, then nothing is attempted until the backoff ends.
        let stats = drain_at(&spool, &sink, t0).unwrap();
        assert_eq!((stats.retrying, stats.deferred), (1, 0));
        let calls = sink.calls();
        let stats = drain_at(&spool, &sink, t0 + 59).unwrap();
        assert_eq!((stats.retrying, stats.deferred), (0, 1));
        assert_eq!(sink.calls(), calls, "not due: no delivery attempt");

        // Keep failing for a day, one pass per minute: far fewer attempts
        // than passes (backoff), and never dead-lettered.
        let day = 24 * 60 * 60;
        let mut now = t0;
        while now < t0 + day {
            now += 60;
            let stats = drain_at(&spool, &sink, now).unwrap();
            assert_eq!(stats.dead_lettered, 0);
        }
        let queued = &spool.list().unwrap()[0];
        assert!(
            queued.attempts < 40,
            "backoff: {} attempts in a day",
            queued.attempts
        );
        assert_eq!(queued.first_failure, Some(t0));

        // The backend recovers: the next due pass delivers and dequeues.
        sink.failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let due = queued.last_failure.unwrap() + retry_delay(queued.attempts).as_secs();
        let stats = drain_at(&spool, &sink, due).unwrap();
        assert_eq!(stats.delivered, 1);
        assert!(spool.list().unwrap().is_empty());
    }

    /// A message still failing after MAX_QUEUE_LIFETIME is dead-lettered
    /// with all three files preserved, so it can be inspected and requeued.
    #[tokio::test]
    async fn dead_letters_only_after_the_queue_lifetime() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path().join("spool"), None).unwrap();
        let sink = FlakySink::failing();
        let queue_id = spool
            .write(sample_meta(), b"payload".to_vec())
            .unwrap()
            .queue_id;
        let t0: u64 = 1_700_000_000;
        let lifetime = MAX_QUEUE_LIFETIME.as_secs();

        drain_at(&spool, &sink, t0).unwrap();
        // Due, still failing, just inside the lifetime: kept.
        let stats = drain_at(&spool, &sink, t0 + lifetime - 1).unwrap();
        assert_eq!((stats.retrying, stats.dead_lettered), (1, 0));
        // Due again past the lifetime: dead-lettered.
        let stats = drain_at(&spool, &sink, t0 + lifetime + RETRY_MAX.as_secs()).unwrap();
        assert_eq!(
            stats,
            DrainStats {
                dead_lettered: 1,
                ..DrainStats::default()
            }
        );
        assert!(spool.list().unwrap().is_empty());

        let dead = dir.path().join("spool/dead-letter");
        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(&dead).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        assert_eq!(
            names,
            vec![
                format!("{queue_id}.attempts"),
                format!("{queue_id}.eml"),
                format!("{queue_id}.json"),
            ]
        );

        // The requeue procedure: move .eml then .json back to new/ and
        // delete .attempts. The message is due at once, with a fresh
        // lifetime.
        let new = dir.path().join("spool/new");
        for ext in ["eml", "json"] {
            std::fs::rename(
                dead.join(format!("{queue_id}.{ext}")),
                new.join(format!("{queue_id}.{ext}")),
            )
            .unwrap();
        }
        std::fs::remove_file(dead.join(format!("{queue_id}.attempts"))).unwrap();
        sink.failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let stats = drain_at(&spool, &sink, t0 + 2 * lifetime).unwrap();
        assert_eq!(stats.delivered, 1);
    }

    /// Sidecars round-trip, and a count-only sidecar still loads (the
    /// message is due now and its lifetime clock starts at the next failure).
    #[test]
    fn attempt_record_formats() {
        use crate::spool::AttemptRecord;
        let r = AttemptRecord {
            attempts: 3,
            first_failure: Some(10),
            last_failure: Some(20),
        };
        assert_eq!(r.to_string(), "3 10 20");
        assert_eq!(AttemptRecord::parse("3 10 20\n"), r);
        assert_eq!(
            AttemptRecord::parse("5"),
            AttemptRecord {
                attempts: 5,
                ..AttemptRecord::default()
            }
        );
        assert_eq!(AttemptRecord::parse("garbage"), AttemptRecord::default());
    }
}
