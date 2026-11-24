//! Local delivery: the `DeliverySink` seam and the maildir
//! implementation, plus the message fixing (trace headers) applied when
//! a message leaves the queue and the drain/retry loop.
//!
//! Two layers:
//!
//! - [`DeliverySink`] — where mail goes. `MaildirSink` writes one
//!   message copy per recipient into a per-recipient maildir
//!   (`{root}/{domain}/{local}/new`). Implementations MUST be
//!   idempotent per (recipient, queue_id): the session attempts
//!   immediate delivery for low latency, and the drain loop re-attempts
//!   queued messages periodically — both paths may race, and a retry
//!   after partial failure must never duplicate mail.
//! - [`drain_once`] — the retry engine. Scans the committed spool,
//!   delivers each message to each recipient, removes fully delivered
//!   messages, retries failures with exponential backoff, and dead-letters
//!   messages still undeliverable after `MAX_QUEUE_LIFETIME` (5 days).
//!
//! Message fixing happens in [`prepare_for_delivery`]: the final MTA
//! prepends `Return-Path` (RFC 5321 §4.5.2) and a `Received:` trace
//! header (RFC 5321 §4.4). The `for <rcpt>` clause names only the
//! recipient of this copy, so other envelope recipients stay private.

use anyhow::{Context, Result};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::spool::{DiskSpool, SpoolMeta};

/// Where accepted mail goes. Blocking methods (filesystem, and later
/// object storage); callers run them on a blocking thread pool.
pub trait DeliverySink: Send + Sync {
    /// Returns the backend name for logs (e.g. `"maildir"`).
    fn name(&self) -> &str;

    /// Deliver one copy of `message` (the final bytes, trace headers
    /// included) to the routing mailbox `recipient`, for the queued
    /// message `queue_id`.
    ///
    /// Idempotency contract: for a given (recipient, queue_id) pair this
    /// MUST deliver at most once — calling again after success (or
    /// racing a concurrent attempt) returns `Ok` without duplicating
    /// mail.
    ///
    /// # Errors
    ///
    /// Delivery failed; the message stays queued and the drain loop
    /// retries.
    fn deliver(&self, recipient: &str, queue_id: &str, message: &[u8]) -> Result<()>;
}

/// Maildir delivery: one maildir per recipient address, under
/// `{root}/{domain}/{local}/` (both lowercased). Each copy is written to
/// `tmp/`, fsynced, and renamed into `new/` as
/// `{queue_id}.{sanitized-recipient}.eml`; the sink creates `tmp/` and
/// `new/` on first delivery.
#[derive(Debug, Clone)]
pub struct MaildirSink {
    /// Directory holding the per-domain maildir trees.
    root: PathBuf,
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
        Ok(MaildirSink { root })
    }
}

impl DeliverySink for MaildirSink {
    fn name(&self) -> &str {
        "maildir"
    }

    fn deliver(&self, recipient: &str, queue_id: &str, message: &[u8]) -> Result<()> {
        let (local, domain) = split_recipient(recipient)
            .with_context(|| format!("cannot deliver to malformed recipient {recipient:?}"))?;
        let maildir = self.root.join(&domain).join(&local);
        let tmp = maildir.join("tmp");
        let new = maildir.join("new");
        crate::fsutil::create_private_dir_all(&tmp)
            .with_context(|| format!("cannot create maildir {}", maildir.display()))?;
        crate::fsutil::create_private_dir_all(&new)
            .with_context(|| format!("cannot create maildir {}", maildir.display()))?;

        // Idempotency is per (recipient, queue_id) as *addresses* — case
        // variants of the same address must map to the same file, so the
        // tag is built from the normalized address.
        let normalized = format!("{local}@{domain}");
        let filename = format!("{queue_id}.{}.eml", sanitize(&normalized));
        let target = new.join(&filename);

        // Idempotency: an existing delivery of this (recipient, queue_id)
        // pair is success, not an error — the drain loop and the inline
        // fast path may both attempt the same copy.
        if target.exists() {
            return Ok(());
        }

        let staged = tmp.join(&filename);
        write_durable(&staged, message)?;
        std::fs::rename(&staged, &target)
            .with_context(|| format!("cannot commit delivery to {}", target.display()))?;
        Ok(())
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
    // leading dot (so never `.` or `..`), no `..` run, and only RFC 5321
    // dot-atom characters minus `/` (the set the session enforces for
    // local-parts at RCPT time; `\` and control characters are not atext).
    let safe = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'='
                    | b'?'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
            )
    };
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

/// Returns a filesystem-safe tag for `recipient` in maildir filenames:
/// ASCII alphanumerics, `.`, `_` and `-` are kept, everything else
/// becomes `_`.
fn sanitize(recipient: &str) -> String {
    recipient
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
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

/// Prepend the final-delivery trace headers to the raw message `raw`.
///
/// Returns one recipient's delivery copy: `Return-Path:` (the envelope
/// sender from `meta` in `<>`, `<>` for the null sender), then a
/// `Received:` header (from the HELO and peer IP, by
/// `meta.server_domain`, with ESMTP or ESMTPS, the queue ID, and `for
/// <recipient>`), then `raw` verbatim. RFC 5321 §4.4 allows exactly one
/// path in `for`; naming only this copy's `recipient` keeps the other
/// envelope recipients private. An unparseable `meta.received_at` is
/// dated at the Unix epoch.
pub fn prepare_for_delivery(meta: &SpoolMeta, recipient: &str, raw: &[u8]) -> Vec<u8> {
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
    let protocol = if meta.tls_active { "ESMTPS" } else { "ESMTP" };
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
            "Received: from {helo} ({peer_ip})\r\n\tby {} ({}) with {protocol} id {}\r\n\tfor <{recipient}>; {date}\r\n",
            meta.server_domain,
            env!("CARGO_PKG_NAME"),
            meta.queue_id,
        )
        .as_bytes(),
    );
    out.extend_from_slice(raw);
    out
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
}

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
pub fn drain_once(spool: &DiskSpool, sink: &dyn DeliverySink) -> Result<DrainStats> {
    drain_at(spool, sink, unix_now())
}

/// Run one pass of the queue drain over `spool` into `sink` at `now`
/// (Unix seconds).
///
/// For each committed message:
/// - not yet due (its last failure was less than [`retry_delay`] ago):
///   skipped, and its payload is not read;
/// - payload unreadable (removed by a concurrent fast-path dequeue, or
///   damaged): logged and skipped for this pass;
/// - due: delivery is attempted to every recipient (idempotent per
///   recipient, so recipients that already have their copy are not
///   duplicated). A message delivered to every recipient is dequeued.
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
pub fn drain_at(spool: &DiskSpool, sink: &dyn DeliverySink, now: u64) -> Result<DrainStats> {
    let mut stats = DrainStats::default();
    for queued in spool.list()? {
        let meta = &queued.meta;
        if let Some(last) = queued.last_failure {
            if now < last.saturating_add(retry_delay(queued.attempts).as_secs()) {
                stats.deferred += 1;
                continue;
            }
        }
        // Loaded only now, for a message that is due.
        let payload = match queued.load_payload() {
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
            // The trace headers name the envelope address; the copy goes
            // to the authority-resolved routing mailbox (which differs
            // from the address only under catch-all).
            let message = prepare_for_delivery(meta, &rcpt.address, &payload);
            if let Err(e) = sink.deliver(&rcpt.mailbox, &meta.queue_id, &message) {
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
            spool.remove(&queued)?;
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
    use crate::spool::{SpoolMeta, SpoolRcpt, SpoolWriter as _};

    /// A metadata record with plausible values; tests override the
    /// fields they care about via struct update syntax.
    fn sample_meta() -> SpoolMeta {
        SpoolMeta {
            queue_id: "00006b01.test.queue".into(),
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
            spf_result: Some("Pass".into()),
            spf_helo: None,
            dkim: Vec::new(),
            dmarc: None,
            authenticated: None,
            tls_active: false,
            message_size: 0,
            encryption: None,
        }
    }

    /// prepare_for_delivery prepends Return-Path and Received, keeps the
    /// raw bytes verbatim, and puts the per-copy recipient in the `for`
    /// clause only.
    #[test]
    fn delivery_copy_carries_trace_headers() {
        let raw = b"Subject: hi\r\n\r\nbody\r\n".to_vec();
        let meta = sample_meta();
        let copy = prepare_for_delivery(&meta, "user@example.org", &raw);
        let text = String::from_utf8(copy.clone()).unwrap();

        assert!(text.starts_with("Return-Path: <sender@example.test>\r\n"));
        assert!(text.contains("Received: from client.test (127.0.0.1)\r\n"));
        assert!(text.contains("\tby mail.test (mailserv) with ESMTP id "));
        assert!(text.contains("\tfor <user@example.org>; "));
        assert!(text.contains(&meta.queue_id));
        // Raw message follows verbatim after the trace headers.
        assert!(text.ends_with("Subject: hi\r\n\r\nbody\r\n"));

        // Null sender renders as the empty path.
        let mut null = sample_meta();
        null.mail_from = Some(String::new());
        let copy = prepare_for_delivery(&null, "user@example.org", &raw);
        assert!(String::from_utf8(copy)
            .unwrap()
            .starts_with("Return-Path: <>\r\n"));

        // TLS upgrades the protocol token.
        let mut tls = sample_meta();
        tls.tls_active = true;
        let copy = prepare_for_delivery(&tls, "user@example.org", &raw);
        assert!(String::from_utf8(copy)
            .unwrap()
            .contains(" with ESMTPS id "));
    }

    /// Defence in depth: a stored HELO containing a bare CR can't inject a
    /// header into the delivered copy.
    #[test]
    fn delivery_copy_neutralises_control_characters_in_helo() {
        let mut meta = sample_meta();
        meta.helo = Some("evil.example\rX-Injected: yes".into());
        let copy = prepare_for_delivery(&meta, "user@example.org", b"\r\nbody\r\n");
        let text = String::from_utf8(copy).unwrap();
        assert!(text.contains("Received: from evil.example?X-Injected:?yes (127.0.0.1)\r\n"));
        assert_eq!(text.matches('\r').count(), text.matches("\r\n").count());
    }

    /// The maildir sink writes one copy per recipient under
    /// {root}/{domain}/{local}/new, and redelivery of the same
    /// (recipient, queue_id) is idempotent.
    #[tokio::test]
    async fn maildir_delivery_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();

        let message = b"Return-Path: <s@x.test>\r\nReceived: ...\r\nSubject: hi\r\n".to_vec();
        sink.deliver("User@Example.ORG", "q-1", &message).unwrap();

        // Address is lowercased; file lands in new/ with a name built
        // from the normalized address, so case variants share one file.
        let delivered = dir
            .path()
            .join("example.org/user/new/q-1.user_example.org.eml");
        assert_eq!(std::fs::read(&delivered).unwrap(), message);

        // Redelivery (crash recovery, drain race) does not duplicate.
        sink.deliver("user@example.org", "q-1", &message).unwrap();
        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(delivered.parent().unwrap())
            .await
            .unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec!["q-1.user_example.org.eml"]);
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
                &raw,
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

        // Both copies exist with trace headers; the queue is empty.
        for rcpt in ["a", "b"] {
            let path = dir.path().join(format!("maildir/example.org/{rcpt}/new"));
            let mut rd = tokio::fs::read_dir(&path).await.unwrap();
            let mut names = Vec::new();
            while let Some(e) = rd.next_entry().await.unwrap() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
            assert_eq!(names.len(), 1, "{path:?}: {names:?}");
            let bytes = std::fs::read(path.join(&names[0])).unwrap();
            assert!(bytes.starts_with(b"Return-Path: <sender@example.test>\r\n"));
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

        fn deliver(&self, _r: &str, _q: &str, _m: &[u8]) -> Result<()> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                Err(anyhow::anyhow!("disk on fire"))
            } else {
                Ok(())
            }
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
        spool.write(sample_meta(), b"payload").unwrap();
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
        let queue_id = spool.write(sample_meta(), b"payload").unwrap();
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
